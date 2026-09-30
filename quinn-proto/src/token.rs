use std::{
    fmt,
    mem::size_of,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use bytes::{Buf, BufMut, Bytes};
use rand::{Rng, RngExt};

use crate::{
    Duration, RESET_TOKEN_SIZE, ServerConfig, SystemTime, UNIX_EPOCH,
    coding::{BufExt, BufMutExt},
    crypto::{HandshakeTokenKey, HmacKey},
    packet::InitialHeader,
    shared::ConnectionId,
};

/// Responsible for limiting clients' ability to reuse validation tokens
///
/// [_RFC 9000 § 8.1.4:_](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.4)
///
/// > Attackers could replay tokens to use servers as amplifiers in DDoS attacks. To protect
/// > against such attacks, servers MUST ensure that replay of tokens is prevented or limited.
/// > Servers SHOULD ensure that tokens sent in Retry packets are only accepted for a short time,
/// > as they are returned immediately by clients. Tokens that are provided in NEW_TOKEN frames
/// > (Section 19.7) need to be valid for longer but SHOULD NOT be accepted multiple times.
/// > Servers are encouraged to allow tokens to be used only once, if possible; tokens MAY include
/// > additional information about clients to further narrow applicability or reuse.
///
/// `TokenLog` pertains only to tokens provided in NEW_TOKEN frames.
pub trait TokenLog: Send + Sync {
    /// Record that the token was used and, ideally, return a token reuse error if the token may
    /// have been already used previously
    ///
    /// False negatives and false positives are both permissible. Called when a client uses an
    /// address validation token.
    ///
    /// Parameters:
    /// - `nonce`: A server-generated random unique value for the token.
    /// - `issued`: The time the server issued the token.
    /// - `lifetime`: The expiration time of address validation tokens sent via NEW_TOKEN frames,
    ///   as configured by [`ServerValidationTokenConfig::lifetime`][1].
    ///
    /// [1]: crate::ValidationTokenConfig::lifetime
    ///
    /// ## Security & Performance
    ///
    /// To the extent that it is possible to repeatedly trigger false negatives (returning `Ok` for
    /// a token which has been reused), an attacker could use the server to perform [amplification
    /// attacks][2]. The QUIC specification requires that this be limited, if not prevented fully.
    ///
    /// A false positive (returning `Err` for a token which has never been used) is not a security
    /// vulnerability; it is permissible for a `TokenLog` to always return `Err`. A false positive
    /// causes the token to be ignored, which may cause the transmission of some 0.5-RTT data to be
    /// delayed until the handshake completes, if a sufficient amount of 0.5-RTT data it sent.
    ///
    /// [2]: https://en.wikipedia.org/wiki/Denial-of-service_attack#Amplification
    fn check_and_insert(
        &self,
        nonce: u128,
        issued: SystemTime,
        lifetime: Duration,
    ) -> Result<(), TokenReuseError>;
}

/// Error for when a validation token may have been reused
pub struct TokenReuseError;

/// Null implementation of [`TokenLog`], which never accepts tokens
pub struct NoneTokenLog;

impl TokenLog for NoneTokenLog {
    fn check_and_insert(&self, _: u128, _: SystemTime, _: Duration) -> Result<(), TokenReuseError> {
        Err(TokenReuseError)
    }
}

/// Responsible for storing validation tokens received from servers and retrieving them for use in
/// subsequent connections
pub trait TokenStore: Send + Sync {
    /// Potentially store a token for later one-time use
    ///
    /// Called when a NEW_TOKEN frame is received from the server.
    fn insert(&self, server_name: &str, token: Bytes);

    /// Try to find and take a token that was stored with the given server name
    ///
    /// The same token must never be returned from `take` twice, as doing so can be used to
    /// de-anonymize a client's traffic.
    ///
    /// Called when trying to connect to a server. It is always ok for this to return `None`.
    fn take(&self, server_name: &str) -> Option<Bytes>;
}

/// Null implementation of [`TokenStore`], which does not store any tokens
pub struct NoneTokenStore;

impl TokenStore for NoneTokenStore {
    fn insert(&self, _: &str, _: Bytes) {}
    fn take(&self, _: &str) -> Option<Bytes> {
        None
    }
}

/// State in an `Incoming` determined by a token or lack thereof
#[derive(Debug)]
pub(crate) struct IncomingToken {
    pub(crate) retry_src_cid: Option<ConnectionId>,
    pub(crate) orig_dst_cid: ConnectionId,
    pub(crate) validated: bool,
}

impl IncomingToken {
    /// Construct for an `Incoming` given the first packet header, or error if the connection
    /// cannot be established
    pub(crate) fn from_header(
        header: &InitialHeader,
        server_config: &ServerConfig,
        remote_address: SocketAddr,
    ) -> Result<Self, InvalidRetryTokenError> {
        let unvalidated = Self {
            retry_src_cid: None,
            orig_dst_cid: header.dst_cid,
            validated: false,
        };

        // Decode token or short-circuit
        if header.token.is_empty() {
            return Ok(unvalidated);
        }

        // In cases where a token cannot be decrypted/decoded, we must allow for the possibility
        // that this is caused not by client malfeasance, but by the token having been generated by
        // an incompatible endpoint, e.g. a different version or a neighbor behind the same load
        // balancer. In such cases we proceed as if there was no token.
        //
        // [_RFC 9000 § 8.1.3:_](https://www.rfc-editor.org/rfc/rfc9000.html#section-8.1.3-10)
        //
        // > If the token is invalid, then the server SHOULD proceed as if the client did not have
        // > a validated address, including potentially sending a Retry packet.
        let Some(retry) = server_config
            .token_key
            .decode(&header.token, remote_address)
        else {
            return Ok(unvalidated);
        };

        // Validate token, then convert into Self
        match retry.payload {
            TokenPayload::Retry {
                address,
                orig_dst_cid,
                retry_src_cid,
                issued,
            } => {
                if address != remote_address {
                    return Err(InvalidRetryTokenError);
                }
                if retry_src_cid.is_some_and(|cid| cid != header.dst_cid) {
                    return Err(InvalidRetryTokenError);
                }
                if issued
                    .checked_add(server_config.retry_token_lifetime)
                    .is_none_or(|expires| expires < server_config.time_source.now())
                {
                    return Err(InvalidRetryTokenError);
                }

                Ok(Self {
                    retry_src_cid: Some(header.dst_cid),
                    orig_dst_cid,
                    validated: true,
                })
            }
            TokenPayload::Validation { ip, issued } => {
                if ip != remote_address.ip() {
                    return Ok(unvalidated);
                }
                if issued + server_config.validation_token.lifetime
                    < server_config.time_source.now()
                {
                    return Ok(unvalidated);
                }
                if server_config
                    .validation_token
                    .log
                    .check_and_insert(retry.nonce, issued, server_config.validation_token.lifetime)
                    .is_err()
                {
                    return Ok(unvalidated);
                }

                Ok(Self {
                    retry_src_cid: None,
                    orig_dst_cid: header.dst_cid,
                    validated: true,
                })
            }
        }
    }
}

/// Error for a token being unambiguously from a Retry packet, and not valid
///
/// The connection cannot be established.
pub(crate) struct InvalidRetryTokenError;

/// Token encryption key and optional authentication key prepared when configuring the server
#[derive(Clone)]
pub(crate) struct TokenKey {
    encryption: Arc<dyn HandshakeTokenKey>,
    authentication: Option<Arc<dyn HmacKey>>,
}

impl TokenKey {
    pub(crate) fn new(encryption: Arc<dyn HandshakeTokenKey>) -> Self {
        let authentication = encryption.token_authentication_key().map(|key| {
            assert_eq!(key.signature_len(), TOKEN_TAG_LEN);
            Arc::from(key)
        });
        Self {
            encryption,
            authentication,
        }
    }

    pub(crate) fn encode(&self, payload: TokenPayload, rng: &mut impl Rng) -> Vec<u8> {
        let Some(key) = &self.authentication else {
            return Token::new(payload, rng).encode(&*self.encryption);
        };

        let mut token = Vec::with_capacity(128);
        token.put_u8(TOKEN_VERSION);
        let (kind, address) = match payload {
            TokenPayload::Retry {
                address,
                orig_dst_cid,
                retry_src_cid,
                issued,
            } => {
                token.put_u8(TokenType::Retry as u8);
                orig_dst_cid.encode_long(&mut token);
                // All Retry issuers know the source CID. Legacy decoded tokens have no such CID,
                // but are never re-encoded as new Retry tokens.
                retry_src_cid
                    .expect("Retry source CID required when issuing a token")
                    .encode_long(&mut token);
                // Milliseconds allow short lifetimes without the whole-second rounding of legacy
                // tokens. This timestamp is local data, not supplied by a peer.
                token.put_u64(
                    issued
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis()
                        .try_into()
                        .expect("token issuance time fits in u64 milliseconds"),
                );
                (TokenType::Retry, address)
            }
            TokenPayload::Validation { ip, .. } => {
                token.put_u8(TokenType::Validation as u8);
                // Preserve NEW_TOKEN confidentiality, uniqueness and the replay-log nonce. The
                // outer MAC makes forged tokens cheap to reject before per-token key derivation.
                token.extend_from_slice(&Token::new(payload, rng).encode(&*self.encryption));
                (TokenType::Validation, SocketAddr::new(ip, 0))
            }
        };
        assert!(token.len() + TOKEN_TAG_LEN <= MAX_TOKEN_LEN);
        let (input, len) = Self::authentication_data(&token, kind, address);
        let mut tag = [0; TOKEN_TAG_LEN];
        key.sign(&input[..len], &mut tag);
        token.extend_from_slice(&tag);
        token
    }

    fn decode(&self, token: &[u8], address: SocketAddr) -> Option<Token> {
        let Some(key) = &self.authentication else {
            return Token::decode(&*self.encryption, token);
        };

        // Never fall back to legacy decryption in this mode: a forged format marker would then
        // bypass the cheap MAC check. Unknown/old tokens leave the peer unvalidated instead.
        if !(2 + TOKEN_TAG_LEN..=MAX_TOKEN_LEN).contains(&token.len()) || token[0] != TOKEN_VERSION
        {
            return None;
        }
        let kind = TokenType::from_byte(token[1])?;
        // Two CID lengths, at most two MAX_CID_SIZE-byte CIDs, and an eight-byte timestamp.
        if matches!(kind, TokenType::Retry)
            && !(12 + TOKEN_TAG_LEN..=12 + 2 * crate::MAX_CID_SIZE + TOKEN_TAG_LEN)
                .contains(&token.len())
        {
            return None;
        }
        let (body, tag) = token.split_at(token.len() - TOKEN_TAG_LEN);
        let (input, len) = Self::authentication_data(body, kind, address);
        key.verify(&input[..len], tag).ok()?;

        let mut reader = &body[2..];
        match kind {
            TokenType::Retry => {
                let orig_dst_cid = ConnectionId::decode_long(&mut reader)?;
                let retry_src_cid = ConnectionId::decode_long(&mut reader)?;
                let issued = UNIX_EPOCH
                    .checked_add(Duration::from_millis((&mut reader).get::<u64>().ok()?))?;
                if !reader.is_empty() {
                    return None;
                }
                Some(Token {
                    payload: TokenPayload::Retry {
                        address,
                        orig_dst_cid,
                        retry_src_cid: Some(retry_src_cid),
                        issued,
                    },
                    nonce: 0,
                })
            }
            TokenType::Validation => {
                let token = Token::decode(&*self.encryption, reader)?;
                // Do not accept an encrypted Retry wrapped as a NEW_TOKEN.
                matches!(token.payload, TokenPayload::Validation { .. }).then_some(token)
            }
        }
    }

    fn authentication_data(
        body: &[u8],
        kind: TokenType,
        address: SocketAddr,
    ) -> ([u8; MAX_TOKEN_LEN + 64], usize) {
        let mut input = [0; MAX_TOKEN_LEN + 64];
        let mut buf = &mut input[..];
        buf.put_slice(b"quinn-token-v1");
        buf.put_u8(kind as u8);
        encode_ip(&mut buf, address.ip());
        if matches!(kind, TokenType::Retry) {
            buf.put_u16(address.port());
        }
        buf.put_slice(body);
        let len = MAX_TOKEN_LEN + 64 - buf.len();
        (input, len)
    }
}

const TOKEN_VERSION: u8 = 1;
const TOKEN_TAG_LEN: usize = 32;
const MAX_TOKEN_LEN: usize = 1024;

/// Decoded token, or a token to be encoded in the legacy encrypted format
pub(crate) struct Token {
    /// Content recovered after authentication
    pub(crate) payload: TokenPayload,
    /// Unique nonce for encrypted tokens; unused (zero) for MAC-only Retry tokens
    nonce: u128,
}

impl Token {
    /// Construct with newly sampled randomness
    pub(crate) fn new(payload: TokenPayload, rng: &mut impl Rng) -> Self {
        Self {
            nonce: rng.random(),
            payload,
        }
    }

    /// Encode and encrypt
    pub(crate) fn encode(&self, key: &dyn HandshakeTokenKey) -> Vec<u8> {
        let mut buf = Vec::new();

        // Encode payload
        match self.payload {
            TokenPayload::Retry {
                address,
                orig_dst_cid,
                issued,
                ..
            } => {
                buf.put_u8(TokenType::Retry as u8);
                encode_addr(&mut buf, address);
                orig_dst_cid.encode_long(&mut buf);
                encode_unix_secs(&mut buf, issued);
            }
            TokenPayload::Validation { ip, issued } => {
                buf.put_u8(TokenType::Validation as u8);
                encode_ip(&mut buf, ip);
                encode_unix_secs(&mut buf, issued);
            }
        }

        // Encrypt
        let aead_key = key.aead_from_hkdf(&self.nonce.to_le_bytes());
        aead_key.seal(&mut buf, &[]).unwrap();
        buf.extend(&self.nonce.to_le_bytes());

        buf
    }

    /// Decode and decrypt
    fn decode(key: &dyn HandshakeTokenKey, raw_token_bytes: &[u8]) -> Option<Self> {
        // Decrypt

        let nonce_slice_start = raw_token_bytes.len().checked_sub(size_of::<u128>())?;
        let (sealed_token, nonce_bytes) = raw_token_bytes.split_at_checked(nonce_slice_start)?;

        let nonce = u128::from_le_bytes(nonce_bytes.try_into().unwrap());

        let aead_key = key.aead_from_hkdf(nonce_bytes);
        let mut sealed_token = sealed_token.to_vec();
        let data = aead_key.open(&mut sealed_token, &[]).ok()?;

        // Decode payload
        let mut reader = &data[..];
        let payload = match TokenType::from_byte((&mut reader).get::<u8>().ok()?)? {
            TokenType::Retry => TokenPayload::Retry {
                address: decode_addr(&mut reader)?,
                orig_dst_cid: ConnectionId::decode_long(&mut reader)?,
                retry_src_cid: None,
                issued: decode_unix_secs(&mut reader)?,
            },
            TokenType::Validation => TokenPayload::Validation {
                ip: decode_ip(&mut reader)?,
                issued: decode_unix_secs(&mut reader)?,
            },
        };

        if !reader.is_empty() {
            // Consider extra bytes a decoding error (it may be from an incompatible endpoint)
            return None;
        }

        Some(Self { nonce, payload })
    }
}

/// Content of a [`Token`]
pub(crate) enum TokenPayload {
    /// Token originating from a Retry packet
    Retry {
        /// The client's address
        address: SocketAddr,
        /// The destination connection ID set in the very first packet from the client
        orig_dst_cid: ConnectionId,
        /// The source CID of the Retry packet, absent in legacy encrypted tokens
        retry_src_cid: Option<ConnectionId>,
        /// The time at which this token was issued
        issued: SystemTime,
    },
    /// Token originating from a NEW_TOKEN frame
    Validation {
        /// The client's IP address (its port is likely to change between sessions)
        ip: IpAddr,
        /// The time at which this token was issued
        issued: SystemTime,
    },
}

/// Variant tag for a [`TokenPayload`]
#[derive(Copy, Clone)]
#[repr(u8)]
enum TokenType {
    Retry = 0,
    Validation = 1,
}

impl TokenType {
    fn from_byte(n: u8) -> Option<Self> {
        use TokenType::*;
        [Retry, Validation].into_iter().find(|ty| *ty as u8 == n)
    }
}

fn encode_addr(buf: &mut Vec<u8>, address: SocketAddr) {
    encode_ip(buf, address.ip());
    buf.put_u16(address.port());
}

fn decode_addr<B: Buf>(buf: &mut B) -> Option<SocketAddr> {
    let ip = decode_ip(buf)?;
    let port = buf.get().ok()?;
    Some(SocketAddr::new(ip, port))
}

fn encode_ip(buf: &mut impl BufMut, ip: IpAddr) {
    match ip {
        IpAddr::V4(x) => {
            buf.put_u8(0);
            buf.put_slice(&x.octets());
        }
        IpAddr::V6(x) => {
            buf.put_u8(1);
            buf.put_slice(&x.octets());
        }
    }
}

fn decode_ip<B: Buf>(buf: &mut B) -> Option<IpAddr> {
    match buf.get::<u8>().ok()? {
        0 => buf.get().ok().map(IpAddr::V4),
        1 => buf.get().ok().map(IpAddr::V6),
        _ => None,
    }
}

fn encode_unix_secs(buf: &mut Vec<u8>, time: SystemTime) {
    buf.write::<u64>(
        time.duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    );
}

fn decode_unix_secs<B: Buf>(buf: &mut B) -> Option<SystemTime> {
    Some(UNIX_EPOCH + Duration::from_secs(buf.get::<u64>().ok()?))
}

/// Stateless reset token
///
/// Used for an endpoint to securely communicate that it has lost state for a connection.
#[allow(clippy::derived_hash_with_manual_eq)] // Custom PartialEq impl matches derived semantics
#[derive(Debug, Copy, Clone, Hash)]
pub(crate) struct ResetToken([u8; RESET_TOKEN_SIZE]);

impl ResetToken {
    pub(crate) fn new(key: &dyn HmacKey, id: ConnectionId) -> Self {
        let mut signature = vec![0; key.signature_len()];
        key.sign(&id, &mut signature);
        // TODO: Server ID??
        let mut result = [0; RESET_TOKEN_SIZE];
        result.copy_from_slice(&signature[..RESET_TOKEN_SIZE]);
        result.into()
    }
}

impl PartialEq for ResetToken {
    fn eq(&self, other: &Self) -> bool {
        crate::constant_time::eq(&self.0, &other.0)
    }
}

impl Eq for ResetToken {}

impl From<[u8; RESET_TOKEN_SIZE]> for ResetToken {
    fn from(x: [u8; RESET_TOKEN_SIZE]) -> Self {
        Self(x)
    }
}

impl std::ops::Deref for ResetToken {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for ResetToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.iter() {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(all(test, any(feature = "aws-lc-rs", feature = "ring")))]
mod test {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    #[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
    use aws_lc_rs::hkdf;
    #[cfg(feature = "ring")]
    use ring::hkdf;

    fn token_round_trip(payload: TokenPayload) -> TokenPayload {
        let rng = &mut rand::rng();
        let token = Token::new(payload, rng);
        let mut master_key = [0; 64];
        rng.fill_bytes(&mut master_key);
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(&master_key);
        let encoded = token.encode(&prk);
        let decoded = Token::decode(&prk, &encoded).expect("token didn't decrypt / decode");
        assert_eq!(token.nonce, decoded.nonce);
        decoded.payload
    }

    #[test]
    fn retry_token_sanity() {
        use crate::MAX_CID_SIZE;
        use crate::cid_generator::{ConnectionIdGenerator, RandomConnectionIdGenerator};
        use crate::{Duration, UNIX_EPOCH};

        use std::net::Ipv6Addr;

        let address_1 = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433);
        let orig_dst_cid_1 = RandomConnectionIdGenerator::new(MAX_CID_SIZE).generate_cid();
        let issued_1 = UNIX_EPOCH + Duration::from_secs(42); // Fractional seconds would be lost
        let payload_1 = TokenPayload::Retry {
            address: address_1,
            orig_dst_cid: orig_dst_cid_1,
            retry_src_cid: None,
            issued: issued_1,
        };
        let TokenPayload::Retry {
            address: address_2,
            orig_dst_cid: orig_dst_cid_2,
            issued: issued_2,
            ..
        } = token_round_trip(payload_1)
        else {
            panic!("token decoded as wrong variant");
        };

        assert_eq!(address_1, address_2);
        assert_eq!(orig_dst_cid_1, orig_dst_cid_2);
        assert_eq!(issued_1, issued_2);
    }

    #[test]
    fn validation_token_sanity() {
        use crate::{Duration, UNIX_EPOCH};

        use std::net::Ipv6Addr;

        let ip_1 = Ipv6Addr::LOCALHOST.into();
        let issued_1 = UNIX_EPOCH + Duration::from_secs(42); // Fractional seconds would be lost

        let payload_1 = TokenPayload::Validation {
            ip: ip_1,
            issued: issued_1,
        };
        let TokenPayload::Validation {
            ip: ip_2,
            issued: issued_2,
        } = token_round_trip(payload_1)
        else {
            panic!("token decoded as wrong variant");
        };

        assert_eq!(ip_1, ip_2);
        assert_eq!(issued_1, issued_2);
    }

    #[test]
    fn invalid_token_returns_err() {
        let rng = &mut rand::rng();

        let mut master_key = [0; 64];
        rng.fill_bytes(&mut master_key);

        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(&master_key);

        let mut invalid_token = Vec::new();

        let mut random_data = [0; 32];
        rand::rng().fill_bytes(&mut random_data);
        invalid_token.put_slice(&random_data);

        // Assert: garbage sealed data returns err
        assert!(Token::decode(&prk, &invalid_token).is_none());
    }

    struct CountingKey {
        inner: hkdf::Prk,
        aead_calls: AtomicUsize,
        authentication_calls: AtomicUsize,
    }

    impl CountingKey {
        fn new(seed: u8) -> Arc<Self> {
            Arc::new(Self {
                inner: hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(&[seed; 32]),
                aead_calls: AtomicUsize::new(0),
                authentication_calls: AtomicUsize::new(0),
            })
        }
    }

    impl HandshakeTokenKey for CountingKey {
        fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Box<dyn crate::crypto::AeadKey> {
            self.aead_calls.fetch_add(1, Ordering::Relaxed);
            self.inner.aead_from_hkdf(random_bytes)
        }

        fn token_authentication_key(&self) -> Option<Box<dyn HmacKey>> {
            self.authentication_calls.fetch_add(1, Ordering::Relaxed);
            self.inner.token_authentication_key()
        }
    }

    fn retry_payload(address: SocketAddr) -> TokenPayload {
        TokenPayload::Retry {
            address,
            orig_dst_cid: ConnectionId::new(&[1; 20]),
            retry_src_cid: Some(ConnectionId::new(&[2; 8])),
            issued: UNIX_EPOCH + Duration::from_millis(42_123),
        }
    }

    #[test]
    fn mac_retry_round_trip_without_aead() {
        let provider = CountingKey::new(42);
        let key = TokenKey::new(provider.clone());
        for address in ["127.0.0.1:4433", "[::1]:4433"] {
            let address = address.parse().unwrap();
            let encoded = key.encode(retry_payload(address), &mut rand::rng());
            assert_eq!(encoded.len(), 72);
            // Cloning the configuration shares the prepared key rather than re-deriving it.
            let decoded = key.clone().decode(&encoded, address).unwrap();
            let TokenPayload::Retry {
                orig_dst_cid,
                retry_src_cid,
                issued,
                ..
            } = decoded.payload
            else {
                panic!("wrong token kind");
            };
            assert_eq!(orig_dst_cid, ConnectionId::new(&[1; 20]));
            assert_eq!(retry_src_cid, Some(ConnectionId::new(&[2; 8])));
            assert_eq!(issued, UNIX_EPOCH + Duration::from_millis(42_123));

            let mut changed_port = address;
            changed_port.set_port(4434);
            assert!(key.decode(&encoded, changed_port).is_none());
            assert!(
                key.decode(&encoded, "192.0.2.1:4433".parse().unwrap())
                    .is_none()
            );
        }
        assert_eq!(provider.authentication_calls.load(Ordering::Relaxed), 1);
        assert_eq!(provider.aead_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn forged_tokens_never_reach_aead() {
        let provider = CountingKey::new(42);
        let key = TokenKey::new(provider.clone());
        let address = "127.0.0.1:4433".parse().unwrap();
        for payload in [
            retry_payload(address),
            TokenPayload::Validation {
                ip: address.ip(),
                issued: UNIX_EPOCH,
            },
        ] {
            let encoded = key.encode(payload, &mut rand::rng());
            let calls = provider.aead_calls.load(Ordering::Relaxed);
            for i in 0..encoded.len() {
                let mut forged = encoded.clone();
                forged[i] ^= 1;
                assert!(key.decode(&forged, address).is_none());
                assert!(key.decode(&encoded[..i], address).is_none());
            }
            let mut extended = encoded;
            extended.push(0);
            assert!(key.decode(&extended, address).is_none());
            assert_eq!(provider.aead_calls.load(Ordering::Relaxed), calls);
        }

        let calls = provider.aead_calls.load(Ordering::Relaxed);
        for len in 0..=MAX_TOKEN_LEN + 1 {
            for kind in [0, 1, 255] {
                let mut forged = vec![0; len];
                if len >= 2 {
                    forged[..2].copy_from_slice(&[TOKEN_VERSION, kind]);
                }
                assert!(key.decode(&forged, address).is_none());
            }
        }
        // Old tokens and unrecognized format bytes cannot select a fallback decryptor.
        let legacy = Token::new(retry_payload(address), &mut rand::rng()).encode(&provider.inner);
        assert!(key.decode(&legacy, address).is_none());
        assert_eq!(provider.aead_calls.load(Ordering::Relaxed), calls);
    }

    #[test]
    fn validation_mac_preserves_nonce_and_allows_port_change() {
        let provider = CountingKey::new(42);
        let key = TokenKey::new(provider.clone());
        for (address, expected_len) in [("127.0.0.1:4433", 80), ("[::1]:4433", 92)] {
            let address: SocketAddr = address.parse().unwrap();
            let payload = TokenPayload::Validation {
                ip: address.ip(),
                issued: UNIX_EPOCH + Duration::from_secs(42),
            };
            let encoded = key.encode(payload, &mut rand::rng());
            assert_eq!(encoded.len(), expected_len);
            let decoded = key.decode(&encoded, address).unwrap();
            assert!(
                matches!(decoded.payload, TokenPayload::Validation { ip, .. } if ip == address.ip())
            );
            let mut new_port = address;
            new_port.set_port(4434);
            assert_eq!(key.decode(&encoded, new_port).unwrap().nonce, decoded.nonce);
            let calls = provider.aead_calls.load(Ordering::Relaxed);
            assert!(
                key.decode(&encoded, "192.0.2.1:4433".parse().unwrap())
                    .is_none()
            );
            assert_eq!(provider.aead_calls.load(Ordering::Relaxed), calls);
        }
    }

    #[test]
    fn mac_keys_are_reproducible_and_key_changes_invalidate_tokens() {
        let key = TokenKey::new(CountingKey::new(42));
        let same = TokenKey::new(CountingKey::new(42));
        let other = TokenKey::new(CountingKey::new(43));
        let address = "127.0.0.1:4433".parse().unwrap();
        let encoded = key.encode(retry_payload(address), &mut rand::rng());
        assert!(same.decode(&encoded, address).is_some());
        assert!(other.decode(&encoded, address).is_none());
    }

    #[test]
    fn custom_provider_can_retain_legacy_format() {
        struct LegacyKey(hkdf::Prk);
        impl HandshakeTokenKey for LegacyKey {
            fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Box<dyn crate::crypto::AeadKey> {
                self.0.aead_from_hkdf(random_bytes)
            }
        }
        let key = TokenKey::new(Arc::new(LegacyKey(
            hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(&[42; 32]),
        )));
        let address = "127.0.0.1:4433".parse().unwrap();
        let encoded = key.encode(retry_payload(address), &mut rand::rng());
        assert_eq!(encoded.len(), 69);
        assert!(matches!(
            key.decode(&encoded, address).unwrap().payload,
            TokenPayload::Retry {
                retry_src_cid: None,
                ..
            }
        ));
    }
}

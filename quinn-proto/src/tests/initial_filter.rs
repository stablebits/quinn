//! Admission ordering regressions
use super::*;
use crate::{
    crypto::{HandshakeTokenKey, Keys, UnsupportedVersion},
    token::{Token, TokenPayload},
};
#[cfg(all(feature = "aws-lc-rs", not(feature = "ring")))]
use aws_lc_rs::hkdf;
#[cfg(feature = "ring")]
use ring::hkdf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// `InitialFilter` with a switchable admission gate and a fixed verdict, recording what it saw
struct Policy {
    allow: AtomicBool,
    verdict: InitialDecision,
    seen: Mutex<Vec<InitialContext>>,
    admitted: AtomicUsize,
}

impl Policy {
    fn new(verdict: InitialDecision) -> Arc<Self> {
        Arc::new(Self {
            allow: AtomicBool::new(true),
            verdict,
            seen: Mutex::new(Vec::new()),
            admitted: AtomicUsize::new(0),
        })
    }

    fn seen(&self) -> Vec<InitialContext> {
        self.seen.lock().expect("policy mutex poisoned").clone()
    }
}

impl InitialFilter for Policy {
    fn allow_initial(&self, meta: &InitialMetadata) -> bool {
        assert!(
            meta.datagram_len() >= usize::from(MIN_INITIAL_SIZE),
            "short datagrams must be dropped before the admission gate"
        );
        self.admitted.fetch_add(1, Ordering::Relaxed);
        self.allow.load(Ordering::Relaxed)
    }

    fn decide(&self, context: &InitialContext) -> InitialDecision {
        self.seen
            .lock()
            .expect("policy mutex poisoned")
            .push(*context);
        self.verdict
    }
}

/// Number of expensive operations performed by the server
#[derive(Default)]
struct Counts {
    initial_keys: AtomicUsize,
    retry_tags: AtomicUsize,
    token_aeads: AtomicUsize,
    token_log: AtomicUsize,
}

impl Counts {
    /// `[initial_keys, retry_tags, token_aeads, token_log]`
    fn values(&self) -> [usize; 4] {
        [
            &self.initial_keys,
            &self.retry_tags,
            &self.token_aeads,
            &self.token_log,
        ]
        .map(|v| v.load(Ordering::Relaxed))
    }
}

/// Crypto provider counting expensive operations, optionally rejecting every version
struct SpyCrypto {
    inner: Arc<dyn crypto::ServerConfig>,
    counts: Arc<Counts>,
    reject: bool,
}

impl crypto::ServerConfig for SpyCrypto {
    fn initial_keys(&self, version: u32, cid: ConnectionId) -> Result<Keys, UnsupportedVersion> {
        self.counts.initial_keys.fetch_add(1, Ordering::Relaxed);
        if self.reject {
            return Err(UnsupportedVersion);
        }
        self.inner.initial_keys(version, cid)
    }

    fn retry_tag(&self, version: u32, cid: ConnectionId, packet: &[u8]) -> [u8; 16] {
        assert!(
            !self.reject,
            "retry_tag called for a version the provider rejected"
        );
        self.counts.retry_tags.fetch_add(1, Ordering::Relaxed);
        self.inner.retry_tag(version, cid, packet)
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        self.inner.clone().start_session(version, params)
    }
}

/// Fixed handshake token key material, so tokens issued before instrumentation stay valid
fn token_key() -> hkdf::Prk {
    hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(&[42; 32])
}

/// `keyed_server_config()` using [`token_key`]
fn keyed_server_config() -> ServerConfig {
    let mut config = server_config();
    config.token_key(Arc::new(token_key()));
    config
}

/// Token key counting expensive operations
struct SpyToken {
    inner: hkdf::Prk,
    counts: Arc<Counts>,
}

impl HandshakeTokenKey for SpyToken {
    fn aead_from_hkdf(&self, random: &[u8]) -> Box<dyn crypto::AeadKey> {
        self.counts.token_aeads.fetch_add(1, Ordering::Relaxed);
        self.inner.aead_from_hkdf(random)
    }
}

struct SpyLog(Arc<Counts>);

impl TokenLog for SpyLog {
    fn check_and_insert(&self, _: u128, _: SystemTime, _: Duration) -> Result<(), TokenReuseError> {
        self.0.token_log.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

/// Count expensive operations of a [`keyed_server_config`]
fn instrument(config: &mut ServerConfig, reject_versions: bool) -> Arc<Counts> {
    let counts = Arc::new(Counts::default());
    config.crypto = Arc::new(SpyCrypto {
        inner: config.crypto.clone(),
        counts: counts.clone(),
        reject: reject_versions,
    });
    config.token_key(Arc::new(SpyToken {
        inner: token_key(),
        counts: counts.clone(),
    }));
    config.validation_token.log = Arc::new(SpyLog(counts.clone()));
    counts
}

/// Encode a protected, padded client Initial with the given DCID and token
fn initial_packet(config: &ServerConfig, dst_cid: ConnectionId, token: &[u8]) -> BytesMut {
    let mut buf = Vec::new();
    let encode = Header::Initial(InitialHeader {
        dst_cid,
        src_cid: ConnectionId::new(&[2; 8]),
        token: token.to_vec().into(),
        number: PacketNumber::U8(0),
        version: 1,
    })
    .encode(&mut buf);
    buf.resize(MIN_INITIAL_SIZE.into(), 0);
    let keys = config
        .crypto
        .initial_keys(1, dst_cid)
        .expect("QUIC v1 is supported");
    encode.finish(
        &mut buf,
        &*keys.header.remote,
        Some((0, &*keys.packet.remote)),
    );
    buf.as_slice().into()
}

fn server_endpoint(config: ServerConfig) -> Endpoint {
    Endpoint::new(Default::default(), Some(Arc::new(config)), true)
}

/// Issue a NEW_TOKEN (`validation`) or Retry token for `addr`
fn issue_token(config: &ServerConfig, addr: SocketAddr, validation: bool) -> Vec<u8> {
    let payload = if validation {
        TokenPayload::Validation {
            ip: addr.ip(),
            issued: config.time_source.now(),
        }
    } else {
        TokenPayload::Retry {
            address: addr,
            orig_dst_cid: ConnectionId::new(&[1; 8]),
            issued: config.time_source.now(),
        }
    };
    Token::new(payload, &mut rand::rng()).encode(&*config.token_key)
}

/// An encrypted Retry token for `addr`, issued at `issued`
fn retry_token(config: &ServerConfig, addr: SocketAddr, issued: SystemTime) -> Vec<u8> {
    let payload = TokenPayload::Retry {
        address: addr,
        orig_dst_cid: ConnectionId::new(&[1; 8]),
        issued,
    };
    Token::new(payload, &mut rand::rng()).encode(&*config.token_key)
}

fn is_retry(datagram: &[u8]) -> bool {
    datagram.first().is_some_and(|byte| byte & 0xf0 == 0xf0)
}

#[test]
fn admission_rejects_all_tokens_before_crypto_and_replay_log() {
    let addr = "[::1]:4433".parse().unwrap();
    let mut config = keyed_server_config();
    let policy = Policy::new(InitialDecision::Proceed);
    policy.allow.store(false, Ordering::Relaxed);
    let validation = true;
    let dst_cid = ConnectionId::new(&[1; 8]);
    let tokens = [
        vec![],
        vec![7; 80],
        vec![7; 1000],
        issue_token(&config, addr, !validation),
        issue_token(&config, addr, validation),
    ];
    let packets: Vec<_> = tokens
        .iter()
        .map(|token| initial_packet(&config, dst_cid, token))
        .collect();
    let reject_versions = false;
    let counts = instrument(&mut config, reject_versions);
    config.initial_filter(policy.clone());
    let mut endpoint = server_endpoint(config);
    for data in &packets {
        let mut out = Vec::new();
        let event = endpoint.handle(Instant::now(), addr, None, None, data.clone(), &mut out);
        assert!(event.is_none(), "gate-rejected initial produced an event");
        assert!(out.is_empty(), "gate-rejected initial drew a response");
        assert_eq!(
            endpoint.open_connections(),
            0,
            "gate rejection opened state"
        );
        assert_eq!(
            endpoint.incoming_buffer_bytes(),
            0,
            "gate rejection buffered data"
        );
    }
    assert_eq!(
        counts.values(),
        [0; 4],
        "gate rejection must precede all crypto and replay-log work"
    );
    assert!(
        policy.seen().is_empty(),
        "decide must not run for gate-rejected initials"
    );

    // A gate-rejected NEW_TOKEN was not consumed; it remains valid when admitted.
    policy.allow.store(true, Ordering::Relaxed);
    let Some(DatagramEvent::NewConnection(incoming)) = endpoint.handle(
        Instant::now(),
        addr,
        None,
        None,
        packets[4].clone(),
        &mut Vec::new(),
    ) else {
        panic!("expected an Incoming for the admitted NEW_TOKEN initial")
    };
    assert!(incoming.remote_address_validated(), "NEW_TOKEN not honored");
    assert!(incoming.may_retry(), "NEW_TOKEN peer may still be retried");
    endpoint.ignore(incoming);
    assert_eq!(
        counts.values(),
        [1, 0, 1, 1],
        "Proceed must not decode the token a second time"
    );
}

#[test]
fn filtered_handshake_proceed() {
    let policy = Policy::new(InitialDecision::Proceed);
    let mut config = keyed_server_config();
    config.initial_filter(policy.clone());
    let mut pair = Pair::new(Default::default(), config);
    pair.connect();
    let seen = policy.seen();
    assert_eq!(seen.len(), 1, "Proceed must consult the filter once");
    assert!(
        !seen[0].remote_address_validated(),
        "first flight carries no token"
    );
    assert!(seen[0].may_retry(), "first flight may be retried");
    assert_eq!(seen[0].remote_address(), pair.client.addr);
}

/// An `Ignore` verdict drops the datagram outright: no state is allocated, nothing is sent back,
/// and the client times out rather than learning it was refused.
#[test]
fn filtered_handshake_ignore() {
    let _guard = subscribe();
    let policy = Policy::new(InitialDecision::Ignore);
    let mut config = keyed_server_config();
    config.initial_filter(policy.clone());
    let mut pair = Pair::new(Default::default(), config);
    let client_addr = pair.client.addr;

    let client_ch = pair.begin_connect(client_config());
    pair.drive();
    pair.server.assert_no_accept();
    assert!(
        pair.server.outbound.is_empty(),
        "an ignored initial must not draw any response"
    );

    // `drive()` stops once the client's only remaining timer is its idle timeout; advance past it
    // so the unanswered attempt gives up.
    pair.time += Duration::from_secs(60);
    pair.drive();
    assert_matches!(
        pair.client_conn_mut(client_ch).poll(),
        Some(Event::ConnectionLost {
            reason: ConnectionError::TimedOut,
        })
    );

    let seen = policy.seen();
    assert!(
        !seen.is_empty(),
        "the filter should have been consulted at least once"
    );
    assert!(
        seen.iter()
            .all(|ctx| !ctx.remote_address_validated() && ctx.remote_address() == client_addr),
        "a dropped initial issues no token, so every retransmit stays unvalidated: {seen:?}"
    );
}

#[test]
fn post_token_ignore_pays_token_cost_only() {
    let addr = "[::1]:4433".parse().unwrap();
    for validation in [false, true] {
        let mut config = keyed_server_config();
        let token = if validation {
            issue_token(&config, addr, validation)
        } else {
            vec![7; 80]
        };
        let data = initial_packet(&config, ConnectionId::new(&[1; 8]), &token);
        let reject_versions = false;
        let counts = instrument(&mut config, reject_versions);
        config.initial_filter(Policy::new(InitialDecision::Ignore));
        let mut endpoint = server_endpoint(config);
        let event = endpoint.handle(Instant::now(), addr, None, None, data, &mut Vec::new());
        assert!(event.is_none(), "Ignore must not produce an event");
        assert_eq!(
            counts.values(),
            [0, 0, 1, usize::from(validation)],
            "Ignore must pay only token decoding (validation token: {validation})"
        );
    }
}

#[test]
fn malformed_initial_is_budgeted_and_no_filter_retains_close() {
    let addr = "[::1]:4433".parse().unwrap();
    let mut data = BytesMut::from(hex!("c4 00000001 00 00 00 3f").as_ref());
    data.resize(MIN_INITIAL_SIZE.into(), 0);
    for allow in [false, true] {
        let mut config = keyed_server_config();
        let reject_versions = false;
        let counts = instrument(&mut config, reject_versions);
        let policy = Policy::new(InitialDecision::Ignore);
        policy.allow.store(allow, Ordering::Relaxed);
        config.initial_filter(policy);
        let result = server_endpoint(config).handle(
            Instant::now(),
            addr,
            None,
            None,
            data.clone(),
            &mut Vec::new(),
        );
        assert_eq!(
            result.is_some(),
            allow,
            "malformed initial answered only when admitted (allow: {allow})"
        );
        assert_eq!(
            counts.values(),
            [usize::from(allow), 0, 0, 0],
            "malformed initial must derive keys only when admitted (allow: {allow})"
        );
    }
    let event = server_endpoint(keyed_server_config()).handle(
        Instant::now(),
        addr,
        None,
        None,
        data,
        &mut Vec::new(),
    );
    assert!(
        matches!(event, Some(DatagramEvent::Response(_))),
        "expected a response datagram"
    );
}

/// An authenticated Retry token bound to another address draws INVALID_TOKEN, bypassing the filter,
/// exactly like the no-filter path.
#[test]
fn authenticated_invalid_retry_retains_error_response() {
    let addr = "[::1]:4433".parse().unwrap();
    let mut config = keyed_server_config();
    let validation = false;
    let token = issue_token(&config, "[::1]:4434".parse().unwrap(), validation);
    let data = initial_packet(&config, ConnectionId::new(&[1; 8]), &token);
    let policy = Policy::new(InitialDecision::Ignore);
    config.initial_filter(policy.clone());
    let mut out = Vec::new();
    let event = server_endpoint(config).handle(Instant::now(), addr, None, None, data, &mut out);
    assert!(
        matches!(event, Some(DatagramEvent::Response(_))),
        "expected a response datagram"
    );
    assert!(
        !is_retry(&out),
        "a Retry token bound to another address draws CONNECTION_CLOSE, not Retry"
    );
    assert!(
        policy.seen().is_empty(),
        "decide must not run for an invalid Retry token"
    );
}

#[test]
fn no_filter_validates_reserved_bits_before_consuming_token() {
    let addr = "[::1]:4433".parse().unwrap();
    let mut config = keyed_server_config();
    let validation = true;
    let token = issue_token(&config, addr, validation);
    let mut data = initial_packet(&config, ConnectionId::new(&[1; 8]), &token);
    // Flip a protected reserved bit without changing the header protection sample.
    data[0] ^= 0x04;
    let reject_versions = false;
    let counts = instrument(&mut config, reject_versions);
    let event =
        server_endpoint(config).handle(Instant::now(), addr, None, None, data, &mut Vec::new());
    assert!(event.is_none(), "reserved bits violation must be dropped");
    assert_eq!(
        counts.values(),
        [1, 0, 0, 0],
        "without a filter, the token must not be decoded before header validation"
    );
}

/// Retry tokens that decrypt but are invalid for the packet skip `decide` and draw INVALID_TOKEN,
/// costing Initial keys and a response, so only the admission gate bounds them.
#[test]
fn invalid_retry_tokens_skip_decide_but_not_the_gate() {
    let addr: SocketAddr = "[::1]:4433".parse().unwrap();
    for allow in [false, true] {
        let mut config = keyed_server_config();
        let now = config.time_source.now();
        let packets: Vec<_> = [
            retry_token(&config, "[::1]:4434".parse().unwrap(), now),
            retry_token(&config, addr, now - Duration::from_secs(3600)),
        ]
        .iter()
        .map(|token| initial_packet(&config, ConnectionId::new(&[1; 8]), token))
        .collect();
        let reject_versions = false;
        let counts = instrument(&mut config, reject_versions);
        let policy = Policy::new(InitialDecision::Ignore);
        policy.allow.store(allow, Ordering::Relaxed);
        config.initial_filter(policy.clone());
        let mut endpoint = server_endpoint(config);
        for data in packets {
            let mut out = Vec::new();
            let event = endpoint.handle(Instant::now(), addr, None, None, data, &mut out);
            assert_eq!(
                event.is_some(),
                allow,
                "invalid Retry token answered only when admitted (allow: {allow})"
            );
            assert!(
                !is_retry(&out),
                "an invalid Retry token must not draw Retry"
            );
        }
        assert!(
            policy.seen().is_empty(),
            "decide must not run for invalid Retry tokens"
        );
        let n = usize::from(allow);
        assert_eq!(
            counts.values(),
            [2 * n, 0, 2 * n, 0],
            "each admitted invalid Retry token costs Initial keys and token decryption (allow: {allow})"
        );
    }
}

#[test]
fn existing_connection_bypasses_exhausted_admission() {
    let mut config = keyed_server_config();
    let policy = Policy::new(InitialDecision::Proceed);
    config.initial_filter(policy.clone());
    let mut pair = Pair::new(Default::default(), config);
    let (client, _) = pair.connect();
    let admitted = policy.admitted.load(Ordering::Relaxed);
    policy.allow.store(false, Ordering::Relaxed);
    let before = pair.client_conn_mut(client).stats().frame_rx.acks;
    pair.client_conn_mut(client).ping();
    pair.drive();
    assert!(
        pair.client_conn_mut(client).stats().frame_rx.acks > before,
        "established connection must keep working with the gate closed"
    );
    assert_eq!(
        policy.admitted.load(Ordering::Relaxed),
        admitted,
        "established connection traffic must not reach the gate"
    );
}

#[test]
fn global_budget_bounds_new_cids_addresses_and_valid_token_replays() {
    /// Admits a fixed number of initials in total
    struct Budget(AtomicUsize);
    impl InitialFilter for Budget {
        fn allow_initial(&self, _: &InitialMetadata) -> bool {
            self.0
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                .is_ok()
        }
        fn decide(&self, _: &InitialContext) -> InitialDecision {
            InitialDecision::Ignore
        }
    }
    let mut config = keyed_server_config();
    let packets: Vec<_> = (0u16..100)
        .map(|i| {
            let addr: SocketAddr = format!("[::1]:{}", 4433 + i).parse().unwrap();
            let dst_cid = ConnectionId::new(&u64::from(i).to_be_bytes());
            let token = match i % 3 {
                0 => vec![7; 80],
                1 => issue_token(&config, addr, false),
                _ => issue_token(&config, addr, true),
            };
            (addr, initial_packet(&config, dst_cid, &token))
        })
        .collect();
    let reject_versions = false;
    let counts = instrument(&mut config, reject_versions);
    let budget = 6;
    config.initial_filter(Arc::new(Budget(AtomicUsize::new(budget))));
    let mut endpoint = server_endpoint(config);
    for (addr, data) in packets.iter().cycle().take(300) {
        let event = endpoint.handle(
            Instant::now(),
            *addr,
            None,
            None,
            data.clone(),
            &mut Vec::new(),
        );
        assert!(event.is_none(), "budget policy only ever ignores");
    }
    assert_eq!(
        counts.values(),
        [0, 0, budget, 2],
        "only the {budget} admitted initials may pay token costs"
    );
}

//! Admission ordering and fast Retry regressions, based on Alex Pyattaev's filter tests.
use super::*;
use crate::{
    crypto::{HandshakeTokenKey, Keys, UnsupportedVersion},
    token::{Token, TokenPayload},
};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

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
}
impl InitialFilter for Policy {
    fn allow_initial(&self, meta: &InitialMetadata) -> bool {
        assert!(meta.datagram_len() >= 1200);
        self.admitted.fetch_add(1, Ordering::Relaxed);
        self.allow.load(Ordering::Relaxed)
    }
    fn decide(&self, context: &InitialContext) -> InitialDecision {
        self.seen.lock().unwrap().push(*context);
        self.verdict
    }
}

#[derive(Default)]
struct Counts {
    keys: AtomicUsize,
    tags: AtomicUsize,
    tokens: AtomicUsize,
    log: AtomicUsize,
}
impl Counts {
    fn values(&self) -> [usize; 4] {
        [&self.keys, &self.tags, &self.tokens, &self.log].map(|v| v.load(Ordering::Relaxed))
    }
}
struct SpyCrypto {
    inner: Arc<dyn crypto::ServerConfig>,
    counts: Arc<Counts>,
    reject: bool,
}
// Intentionally uses the default supports_version, exercising custom-provider compatibility.
impl crypto::ServerConfig for SpyCrypto {
    fn initial_keys(&self, version: u32, cid: ConnectionId) -> Result<Keys, UnsupportedVersion> {
        self.counts.keys.fetch_add(1, Ordering::Relaxed);
        if self.reject {
            return Err(UnsupportedVersion);
        }
        self.inner.initial_keys(version, cid)
    }
    fn retry_tag(&self, version: u32, cid: ConnectionId, packet: &[u8]) -> [u8; 16] {
        assert!(!self.reject);
        self.counts.tags.fetch_add(1, Ordering::Relaxed);
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
struct SpyToken {
    inner: Arc<dyn HandshakeTokenKey>,
    counts: Arc<Counts>,
}
impl HandshakeTokenKey for SpyToken {
    fn aead_from_hkdf(&self, random: &[u8]) -> Box<dyn crypto::AeadKey> {
        self.counts.tokens.fetch_add(1, Ordering::Relaxed);
        self.inner.aead_from_hkdf(random)
    }
}
struct SpyLog(Arc<Counts>);
impl TokenLog for SpyLog {
    fn check_and_insert(&self, _: u128, _: SystemTime, _: Duration) -> Result<(), TokenReuseError> {
        self.0.log.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}
fn instrument(config: &mut ServerConfig, reject: bool) -> Arc<Counts> {
    let counts = Arc::new(Counts::default());
    config.crypto = Arc::new(SpyCrypto {
        inner: config.crypto.clone(),
        counts: counts.clone(),
        reject,
    });
    config.token_key = Arc::new(SpyToken {
        inner: config.token_key.clone(),
        counts: counts.clone(),
    });
    config.validation_token.log = Arc::new(SpyLog(counts.clone()));
    counts
}
fn packet(config: &ServerConfig, cid: ConnectionId, token: &[u8]) -> BytesMut {
    let mut buf = Vec::new();
    let encode = Header::Initial(InitialHeader {
        dst_cid: cid,
        src_cid: ConnectionId::new(&[2; 8]),
        token: token.to_vec().into(),
        number: PacketNumber::U8(0),
        version: 1,
    })
    .encode(&mut buf);
    buf.resize(1200, 0);
    let keys = config.crypto.initial_keys(1, cid).unwrap();
    encode.finish(
        &mut buf,
        &*keys.header.remote,
        Some((0, &*keys.packet.remote)),
    );
    buf.as_slice().into()
}
fn endpoint(config: ServerConfig) -> Endpoint {
    Endpoint::new(Default::default(), Some(Arc::new(config)), true)
}
fn token(config: &ServerConfig, addr: SocketAddr, validation: bool) -> Vec<u8> {
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

#[test]
fn admission_rejects_all_tokens_before_crypto_and_replay_log() {
    let addr = "[::1]:4433".parse().unwrap();
    let mut config = server_config();
    let policy = Policy::new(InitialDecision::Proceed);
    policy.allow.store(false, Ordering::Relaxed);
    let tokens = [
        vec![],
        vec![7; 80],
        vec![7; 1000],
        token(&config, addr, false),
        token(&config, addr, true),
    ];
    let packets: Vec<_> = tokens
        .iter()
        .map(|t| packet(&config, ConnectionId::new(&[1; 8]), t))
        .collect();
    let counts = instrument(&mut config, false);
    config.initial_filter(policy.clone());
    let mut ep = endpoint(config);
    for data in &packets {
        let mut out = Vec::new();
        assert!(
            ep.handle(Instant::now(), addr, None, None, data.clone(), &mut out)
                .is_none()
        );
        assert!(out.is_empty());
        assert_eq!(ep.open_connections(), 0);
        assert_eq!(ep.incoming_buffer_bytes(), 0);
    }
    assert_eq!(counts.values(), [0; 4]);
    assert!(policy.seen.lock().unwrap().is_empty());
    // A gate-rejected NEW_TOKEN was not consumed; it remains valid when admitted.
    policy.allow.store(true, Ordering::Relaxed);
    let Some(DatagramEvent::NewConnection(incoming)) = ep.handle(
        Instant::now(),
        addr,
        None,
        None,
        packets[4].clone(),
        &mut Vec::new(),
    ) else {
        panic!("expected incoming")
    };
    assert!(incoming.remote_address_validated());
    assert!(incoming.may_retry());
    ep.ignore(incoming);
    assert_eq!(counts.values(), [1, 0, 1, 1]); // no double token decoding on Proceed
}

#[test]
fn filtered_handshake_proceed_and_retry() {
    for verdict in [InitialDecision::Proceed, InitialDecision::Retry] {
        let policy = Policy::new(verdict);
        let mut config = server_config();
        config.initial_filter(policy.clone());
        let mut pair = Pair::new(Default::default(), config);
        pair.connect();
        let seen = policy.seen.lock().unwrap();
        assert!(!seen[0].remote_address_validated());
        assert!(seen[0].may_retry());
        assert_eq!(seen[0].remote_address(), pair.client.addr);
        if verdict == InitialDecision::Retry {
            assert_eq!(seen.len(), 2);
            assert!(seen[1].remote_address_validated());
            assert!(!seen[1].may_retry());
        } else {
            assert_eq!(seen.len(), 1);
        }
    }
}

#[test]
fn post_token_ignore_pays_token_cost_only() {
    let addr = "[::1]:4433".parse().unwrap();
    for validation in [false, true] {
        let mut config = server_config();
        let t = if validation {
            token(&config, addr, true)
        } else {
            vec![7; 80]
        };
        let data = packet(&config, ConnectionId::new(&[1; 8]), &t);
        let counts = instrument(&mut config, false);
        config.initial_filter(Policy::new(InitialDecision::Ignore));
        let mut ep = endpoint(config);
        assert!(
            ep.handle(Instant::now(), addr, None, None, data, &mut Vec::new())
                .is_none()
        );
        assert_eq!(counts.values(), [0, 0, 1, usize::from(validation)]);
    }
}

#[test]
fn fast_retry_provider_fallback_and_replacement() {
    let addr = "[::1]:4433".parse().unwrap();
    let mut config = server_config();
    let data = packet(&config, ConnectionId::new(&[1; 8]), &[]);
    let counts = instrument(&mut config, false);
    config.initial_filter(Policy::new(InitialDecision::Retry));
    let mut ep = endpoint(config);
    for _ in 0..3 {
        let mut out = Vec::new();
        assert!(matches!(
            ep.handle(Instant::now(), addr, None, None, data.clone(), &mut out),
            Some(DatagramEvent::Response(_))
        ));
        assert_eq!(out[0] & 0xf0, 0xf0);
        assert_eq!(ep.open_connections(), 0);
    }
    assert_eq!(counts.values(), [3, 3, 3, 0]); // default capability check derives keys
    let mut replacement = server_config();
    replacement.initial_filter(Policy::new(InitialDecision::Retry));
    let counts = instrument(&mut replacement, true);
    ep.set_server_config(Some(Arc::new(replacement)));
    assert!(
        ep.handle(Instant::now(), addr, None, None, data, &mut Vec::new())
            .is_none()
    );
    assert_eq!(counts.values(), [1, 0, 0, 0]); // unsupported provider never reaches retry_tag
}

#[test]
fn malformed_initial_is_budgeted_and_no_filter_retains_close() {
    let addr = "[::1]:4433".parse().unwrap();
    let mut data = BytesMut::from(hex!("c4 00000001 00 00 00 3f").as_ref());
    data.resize(1200, 0);
    for allow in [false, true] {
        let mut config = server_config();
        let counts = instrument(&mut config, false);
        let policy = Policy::new(InitialDecision::Retry);
        policy.allow.store(allow, Ordering::Relaxed);
        config.initial_filter(policy);
        let result = endpoint(config).handle(
            Instant::now(),
            addr,
            None,
            None,
            data.clone(),
            &mut Vec::new(),
        );
        assert_eq!(result.is_some(), allow);
        assert_eq!(counts.values(), [usize::from(allow), 0, 0, 0]);
    }
    assert!(matches!(
        endpoint(server_config()).handle(Instant::now(), addr, None, None, data, &mut Vec::new()),
        Some(DatagramEvent::Response(_))
    ));
}

#[test]
fn authenticated_invalid_retry_retains_error_response() {
    let addr = "[::1]:4433".parse().unwrap();
    let mut config = server_config();
    let t = token(&config, "[::1]:4434".parse().unwrap(), false);
    let data = packet(&config, ConnectionId::new(&[1; 8]), &t);
    let policy = Policy::new(InitialDecision::Retry);
    config.initial_filter(policy.clone());
    let mut out = Vec::new();
    assert!(matches!(
        endpoint(config).handle(Instant::now(), addr, None, None, data, &mut out),
        Some(DatagramEvent::Response(_))
    ));
    assert_ne!(out[0] & 0xf0, 0xf0);
    assert!(policy.seen.lock().unwrap().is_empty());
}

// A cheap-capability provider that panics if the fast path derives Initial keys.
struct NoInitialKeys(Arc<dyn crypto::ServerConfig>);
impl crypto::ServerConfig for NoInitialKeys {
    fn supports_version(&self, version: u32) -> bool {
        self.0.supports_version(version)
    }
    fn initial_keys(&self, _: u32, _: ConnectionId) -> Result<Keys, UnsupportedVersion> {
        panic!("fast Retry derived Initial keys")
    }
    fn retry_tag(&self, version: u32, cid: ConnectionId, packet: &[u8]) -> [u8; 16] {
        self.0.retry_tag(version, cid, packet)
    }
    fn start_session(self: Arc<Self>, _: u32, _: &TransportParameters) -> Box<dyn crypto::Session> {
        panic!("fast Retry started TLS")
    }
}

#[test]
fn built_in_fast_retry_skips_initial_keys_and_retains_no_route() {
    let addr = "[::1]:4433".parse().unwrap();
    let mut config = server_config();
    let data = packet(&config, ConnectionId::new(&[1; 8]), &[7; 80]);
    config.crypto = Arc::new(NoInitialKeys(config.crypto.clone()));
    config.max_incoming = 1;
    config.initial_filter(Policy::new(InitialDecision::Retry));
    let mut ep = endpoint(config);
    for _ in 0..3 {
        let mut out = Vec::new();
        assert!(matches!(
            ep.handle(Instant::now(), addr, None, None, data.clone(), &mut out),
            Some(DatagramEvent::Response(_))
        ));
        assert_eq!(out[0] & 0xf0, 0xf0);
        assert_eq!(ep.known_connections(), 0);
        assert_eq!(ep.known_cids(), 0);
    }
}

#[test]
fn no_filter_validates_reserved_bits_before_consuming_token() {
    let addr = "[::1]:4433".parse().unwrap();
    let mut config = server_config();
    let t = token(&config, addr, true);
    let mut data = packet(&config, ConnectionId::new(&[1; 8]), &t);
    data[0] ^= 0x04; // protected reserved bit, without changing the HP sample
    let counts = instrument(&mut config, false);
    assert!(
        endpoint(config)
            .handle(Instant::now(), addr, None, None, data, &mut Vec::new())
            .is_none()
    );
    assert_eq!(counts.values(), [1, 0, 0, 0]);
}

#[test]
fn existing_connection_bypasses_exhausted_admission() {
    let mut config = server_config();
    let policy = Policy::new(InitialDecision::Retry);
    config.initial_filter(policy.clone());
    let mut pair = Pair::new(Default::default(), config);
    let (client, _) = pair.connect();
    let admitted = policy.admitted.load(Ordering::Relaxed);
    policy.allow.store(false, Ordering::Relaxed);
    let before = pair.client_conn_mut(client).stats().frame_rx.acks;
    pair.client_conn_mut(client).ping();
    pair.drive();
    assert!(pair.client_conn_mut(client).stats().frame_rx.acks > before);
    assert_eq!(policy.admitted.load(Ordering::Relaxed), admitted);
}

#[test]
fn endpoint_version_list_cannot_force_unsupported_retry_crypto() {
    let addr = "[::1]:4433".parse().unwrap();
    let unknown: u32 = 0x12345678;
    let mut config = server_config();
    let mut data = packet(&config, ConnectionId::new(&[1; 8]), &[]);
    data[1..5].copy_from_slice(&unknown.to_be_bytes());
    config.initial_filter(Policy::new(InitialDecision::Retry));
    let mut endpoint_config = EndpointConfig::default();
    endpoint_config.supported_versions(vec![1, unknown]);
    let mut ep = Endpoint::new(Arc::new(endpoint_config), Some(Arc::new(config)), true);
    let mut out = Vec::new();
    assert!(
        ep.handle(Instant::now(), addr, None, None, data, &mut out)
            .is_none()
    );
    assert!(out.is_empty());
}

#[test]
fn default_admission_hook_allows_simple_retry_policy() {
    struct Retry;
    impl InitialFilter for Retry {
        fn decide(&self, _: &InitialContext) -> InitialDecision {
            InitialDecision::Retry
        }
    }
    let mut config = server_config();
    config.initial_filter(Arc::new(Retry));
    Pair::new(Default::default(), config).connect();
}

#[test]
fn global_budget_bounds_new_cids_addresses_and_valid_token_replays() {
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
    let mut config = server_config();
    let packets: Vec<_> = (0u16..100)
        .map(|n| {
            let addr: SocketAddr = format!("[::1]:{}", 4433 + n).parse().unwrap();
            let t = match n % 3 {
                0 => vec![7; 80],
                1 => token(&config, addr, false),
                _ => token(&config, addr, true),
            };
            (
                addr,
                packet(&config, ConnectionId::new(&u64::from(n).to_be_bytes()), &t),
            )
        })
        .collect();
    let counts = instrument(&mut config, false);
    config.initial_filter(Arc::new(Budget(AtomicUsize::new(6))));
    let mut ep = endpoint(config);
    for (addr, data) in packets.iter().cycle().take(300) {
        assert!(
            ep.handle(
                Instant::now(),
                *addr,
                None,
                None,
                data.clone(),
                &mut Vec::new()
            )
            .is_none()
        );
    }
    assert_eq!(counts.values(), [0, 0, 6, 2]);
}

#[test]
fn coalesced_initials_generate_one_retry() {
    let mut config = server_config();
    let mut data = packet(&config, ConnectionId::new(&[1; 8]), &[]);
    data.extend_from_slice(&data.clone());
    let policy = Policy::new(InitialDecision::Retry);
    config.initial_filter(policy.clone());
    let mut out = Vec::new();
    assert!(matches!(
        endpoint(config).handle(
            Instant::now(),
            "[::1]:4433".parse().unwrap(),
            None,
            None,
            data,
            &mut out
        ),
        Some(DatagramEvent::Response(_))
    ));
    assert_eq!(policy.admitted.load(Ordering::Relaxed), 1);
    assert_eq!(policy.seen.lock().unwrap().len(), 1);
    assert_eq!(out[0] & 0xf0, 0xf0);
}

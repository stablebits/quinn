//! Budget new Initials before token work, then Retry unvalidated peers.
use quinn::{
    Endpoint, InitialContext, InitialDecision, InitialFilter, InitialMetadata, ServerConfig,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::{
    error::Error,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
mod common;

/// Fixed one-second windows with a bounded count and no per-source state.
/// A boundary can admit two windows' budgets close together. This limits work,
/// not legitimate-client starvation during a sustained flood.
struct AdmissionPolicy {
    epoch: Instant,
    limit: u32,
    // Upper bits: window; lower bits: count. One CAS attempt bounds contention work.
    state: AtomicU64,
}
impl AdmissionPolicy {
    fn new(epoch: Instant, limit: u32) -> Self {
        Self {
            epoch,
            limit,
            state: AtomicU64::new(0),
        }
    }
    fn allow_at(&self, now: Instant) -> bool {
        let window = now.saturating_duration_since(self.epoch).as_secs();
        if window > u32::MAX as u64 {
            return false;
        }
        let old = self.state.load(Ordering::Relaxed);
        let previous = old >> 32;
        if window < previous {
            return false;
        }
        let used = if window == previous { old as u32 } else { 0 };
        if used >= self.limit {
            return false;
        }
        self.state
            .compare_exchange(
                old,
                (window << 32) | u64::from(used + 1),
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_ok()
    }
}
impl InitialFilter for AdmissionPolicy {
    fn allow_initial(&self, meta: &InitialMetadata) -> bool {
        self.allow_at(meta.received_at())
    }
    fn decide(&self, ctx: &InitialContext) -> InitialDecision {
        if ctx.remote_address_validated() {
            InitialDecision::Proceed
        } else {
            InitialDecision::Retry
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let der = CertificateDer::from(cert.cert);
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let mut config = ServerConfig::with_single_cert(vec![der.clone()], key.into())?;
    // Counts Initials, not handshakes: both first flight and Retry return need budget.
    config.initial_filter(Arc::new(AdmissionPolicy::new(Instant::now(), 100)));
    let server = Endpoint::server(config, "127.0.0.1:0".parse()?)?;
    let client = common::make_client_endpoint("127.0.0.1:0".parse()?, &[der.as_ref()])?;
    let connect = client.connect(server.local_addr()?, "localhost")?;
    let (client_conn, server_conn) = tokio::try_join!(
        async {
            connect
                .await
                .map_err(|e| -> Box<dyn Error + Send + Sync> { e.into() })
        },
        async { Ok::<_, Box<dyn Error + Send + Sync>>(server.accept().await.unwrap().await?) },
    )?;
    println!(
        "Retried handshake completed with {}",
        server_conn.remote_address()
    );
    client_conn.close(0u32.into(), b"done");
    server_conn.closed().await;
    client.wait_idle().await;
    Ok(())
}

#[test]
fn budget_rejects_and_refills_deterministically() {
    let now = Instant::now();
    let policy = AdmissionPolicy::new(now, 2);
    assert!(policy.allow_at(now));
    assert!(policy.allow_at(now)); // Retry return consumes another slot
    assert!(!policy.allow_at(now));
    let later = now + std::time::Duration::from_secs(1);
    assert!(policy.allow_at(later));
    assert!(!policy.allow_at(now)); // stale timestamp cannot reopen an old window
    assert!(policy.allow_at(later));
    assert!(!policy.allow_at(later));
    assert!(!AdmissionPolicy::new(now, 0).allow_at(now));
}

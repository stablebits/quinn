use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

use anyhow::Result;
use bench::{configure_tracing_subscriber, contention, drain_stream, mt_rt};
use clap::Parser;
use tokio::sync::Semaphore;
use tracing::{info, warn};

/// Cumulative timing of the accept path, reported to stdout every 1000 accepts.
/// `sched` is the delay between spawning the accept task and it starting to run;
/// `sync` is the synchronous CPU-heavy section (`Incoming::accept`).
#[derive(Default)]
struct AcceptTiming {
    accepts: AtomicU64,
    sched_total_ns: AtomicU64,
    sync_total_ns: AtomicU64,
    sync_max_ns: AtomicU64,
}

impl AcceptTiming {
    fn record(&self, sched_ns: u64, sync_ns: u64) {
        self.sched_total_ns.fetch_add(sched_ns, Ordering::Relaxed);
        self.sync_total_ns.fetch_add(sync_ns, Ordering::Relaxed);
        self.sync_max_ns.fetch_max(sync_ns, Ordering::Relaxed);
        let accepts = self.accepts.fetch_add(1, Ordering::Relaxed) + 1;
        if accepts % 1000 == 0 {
            println!(
                "accept_timing accepts={} sched_avg_us={} sync_avg_us={} sync_max_us={}",
                accepts,
                self.sched_total_ns.load(Ordering::Relaxed) / accepts / 1000,
                self.sync_total_ns.load(Ordering::Relaxed) / accepts / 1000,
                self.sync_max_ns.load(Ordering::Relaxed) / 1000,
            );
        }
    }
}

fn main() -> Result<()> {
    let opt = Opt::parse();
    configure_tracing_subscriber();

    let runtime = mt_rt(opt.worker_threads);
    let data_handle = runtime.handle().clone();
    let endpoint = contention::server_endpoint(
        data_handle.clone(),
        opt.listen,
        opt.initial_mtu,
        opt.max_concurrent_uni_streams,
    )?;
    info!("listening on {}", endpoint.local_addr()?);

    // Bounds in-flight handshakes (the CPU-heavy TLS work in `incoming.await`). When all
    // permits are taken, the accept loop stalls and further attempts queue in the endpoint
    // as cheap un-accepted `Incoming`s (bounded by `ServerConfig::max_incoming`), leaving
    // CPU headroom for established connections.
    let handshake_limiter = (opt.max_concurrent_handshakes > 0)
        .then(|| Arc::new(Semaphore::new(opt.max_concurrent_handshakes)));

    let timing = Arc::new(AcceptTiming::default());

    let accept_loop = async move {
        while let Some(incoming) = endpoint.accept().await {
            let read_unordered = opt.read_unordered;
            let timing = timing.clone();
            let data_handle = data_handle.clone();
            let permit = match &handshake_limiter {
                Some(limiter) => Some(limiter.clone().acquire_owned().await.unwrap()),
                None => None,
            };
            let spawned_at = Instant::now();
            tokio::spawn(async move {
                let sched_ns = spawned_at.elapsed().as_nanos() as u64;
                // `Incoming::accept` runs the CPU-heavy part (TLS session creation plus
                // first-packet handshake processing) synchronously; the permit covers
                // exactly that section. The rest of the handshake is driven by the
                // connection driver and awaited without holding a permit, so the cap
                // bounds handshake CPU concurrency rather than handshake RTTs in flight.
                let sync_start = Instant::now();
                let connecting = match incoming.accept() {
                    Ok(connecting) => connecting,
                    Err(error) => {
                        warn!("accept failed: {error}");
                        return;
                    }
                };
                drop(permit);
                timing.record(sched_ns, sync_start.elapsed().as_nanos() as u64);
                let connection = match connecting.await {
                    Ok(connection) => connection,
                    Err(error) => {
                        warn!("handshake failed: {error}");
                        return;
                    }
                };

                // Stream handling is data-plane work: spawn it (and, transitively, the
                // per-stream drain tasks) onto the data runtime. With a dedicated
                // handshake runtime this task itself runs there, so a bare spawn would
                // drag all stream processing onto the handshake threads.
                data_handle.spawn(async move {
                    while let Ok(mut stream) = connection.accept_uni().await {
                        tokio::spawn(async move {
                            let _ = drain_stream(&mut stream, read_unordered).await;
                        });
                    }
                });
            });
        }
    };

    if opt.handshake_threads > 0 {
        // Dedicated control runtime: the accept loop and the synchronous TLS sections run
        // on its threads, so its size is the handshake CPU budget. quinn's endpoint and
        // connection drivers stay pinned to the data runtime (see `PinnedRuntime`).
        let control = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(opt.handshake_threads)
            .thread_name("handshake")
            .enable_all()
            .build()?;
        control.block_on(accept_loop);
    } else {
        runtime.block_on(accept_loop);
    }

    Ok(())
}

#[derive(Debug, Parser, Clone, Copy)]
#[command(name = "server")]
struct Opt {
    #[arg(long, default_value = "[::1]:4433")]
    listen: SocketAddr,
    #[arg(long, default_value = "4")]
    worker_threads: usize,
    #[arg(long, default_value = "1200")]
    initial_mtu: u16,
    #[arg(long, default_value = "131072")]
    max_concurrent_uni_streams: u64,
    /// Maximum handshakes processed concurrently (0 = unlimited)
    #[arg(long, default_value = "0")]
    max_concurrent_handshakes: usize,
    /// Run the accept loop and synchronous handshake sections on a dedicated runtime
    /// with this many threads (0 = use the shared data runtime)
    #[arg(long, default_value = "0")]
    handshake_threads: usize,
    #[arg(long)]
    read_unordered: bool,
}

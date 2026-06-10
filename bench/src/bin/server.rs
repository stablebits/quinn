use std::{net::SocketAddr, sync::Arc};

use anyhow::Result;
use bench::{configure_tracing_subscriber, contention, drain_stream, mt_rt};
use clap::Parser;
use tokio::sync::Semaphore;
use tracing::{info, warn};

fn main() -> Result<()> {
    let opt = Opt::parse();
    configure_tracing_subscriber();

    let runtime = mt_rt(opt.worker_threads);
    let endpoint = contention::server_endpoint(
        &runtime,
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

    runtime.block_on(async move {
        while let Some(incoming) = endpoint.accept().await {
            let read_unordered = opt.read_unordered;
            let permit = match &handshake_limiter {
                Some(limiter) => Some(limiter.clone().acquire_owned().await.unwrap()),
                None => None,
            };
            tokio::spawn(async move {
                let connection = match incoming.await {
                    Ok(connection) => connection,
                    Err(error) => {
                        warn!("handshake failed: {error}");
                        return;
                    }
                };
                drop(permit);

                while let Ok(mut stream) = connection.accept_uni().await {
                    tokio::spawn(async move {
                        let _ = drain_stream(&mut stream, read_unordered).await;
                    });
                }
            });
        }
    });

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
    #[arg(long)]
    read_unordered: bool,
}

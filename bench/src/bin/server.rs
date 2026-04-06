use std::net::SocketAddr;

use anyhow::Result;
use bench::{configure_tracing_subscriber, contention, drain_stream, mt_rt};
use clap::Parser;
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

    runtime.block_on(async move {
        while let Some(incoming) = endpoint.accept().await {
            let read_unordered = opt.read_unordered;
            tokio::spawn(async move {
                let connection = match incoming.await {
                    Ok(connection) => connection,
                    Err(error) => {
                        warn!("handshake failed: {error}");
                        return;
                    }
                };

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
    #[arg(long)]
    read_unordered: bool,
}

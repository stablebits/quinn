use std::{
    net::SocketAddr,
    sync::{Arc, Barrier},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use bench::{configure_tracing_subscriber, contention, rt};
use clap::Parser;

fn main() -> Result<()> {
    let opt = Opt::parse();
    configure_tracing_subscriber();

    if opt.connections_per_second == 0 || opt.workers == 0 {
        println!("duration_secs={}", opt.duration_secs);
        println!(
            "target_connections_per_second={}",
            opt.connections_per_second
        );
        println!("workers={}", opt.workers);
        println!("connections=0");
        println!("achieved_connections_per_second=0.00");
        return Ok(());
    }

    let barrier = Arc::new(Barrier::new(opt.workers));
    let mut threads = Vec::with_capacity(opt.workers);
    for worker_index in 0..opt.workers {
        let barrier = barrier.clone();
        let opt = opt.clone();
        threads.push(std::thread::spawn(move || {
            run_worker(opt, barrier, worker_index)
        }));
    }

    let mut connections = 0_u64;
    let mut latencies = Vec::new();
    for thread in threads {
        let worker_latencies = thread.join().expect("new-client thread")?;
        connections += worker_latencies.len() as u64;
        latencies.extend(worker_latencies);
    }
    latencies.sort_unstable();

    let duration = Duration::from_secs(opt.duration_secs);
    let achieved = connections as f64 / duration.as_secs_f64();

    println!("duration_secs={}", opt.duration_secs);
    println!(
        "target_connections_per_second={}",
        opt.connections_per_second
    );
    println!("workers={}", opt.workers);
    println!("connections={}", connections);
    println!("achieved_connections_per_second={achieved:.2}");
    println!(
        "connect_latency_p50_ms={:.3}",
        percentile(&latencies, 0.50).as_secs_f64() * 1000.0
    );
    println!(
        "connect_latency_p90_ms={:.3}",
        percentile(&latencies, 0.90).as_secs_f64() * 1000.0
    );
    println!(
        "connect_latency_p99_ms={:.3}",
        percentile(&latencies, 0.99).as_secs_f64() * 1000.0
    );
    println!(
        "connect_latency_max_ms={:.3}",
        latencies.last().copied().unwrap_or_default().as_secs_f64() * 1000.0
    );

    Ok(())
}

fn percentile(sorted: &[Duration], q: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let idx = ((sorted.len() - 1) as f64 * q).round() as usize;
    sorted[idx]
}

fn run_worker(opt: Opt, barrier: Arc<Barrier>, worker_index: usize) -> Result<Vec<Duration>> {
    let rate = opt.connections_per_second as f64 / opt.workers as f64;
    if rate == 0.0 {
        return Ok(Vec::new());
    }

    let runtime = rt();
    let endpoint = contention::client_endpoint(&runtime, opt.connect)?;
    let client_config = contention::insecure_client_config(opt.initial_mtu, 16)?;
    runtime.block_on(async move {
        let interval = Duration::from_secs_f64(1.0 / rate);

        barrier.wait();

        let start = Instant::now();
        let stop_at = start + Duration::from_secs(opt.duration_secs);
        let mut next_attempt = start
            + Duration::from_nanos(
                ((interval.as_nanos() / opt.workers as u128) * worker_index as u128) as u64,
            );
        let mut latencies = Vec::new();

        while next_attempt < stop_at {
            let now = Instant::now();
            if next_attempt > now {
                std::thread::sleep(next_attempt - now);
            }

            let connect_start = Instant::now();
            let connection = endpoint
                .connect_with(client_config.clone(), opt.connect, "localhost")
                .unwrap()
                .await
                .context("unable to connect churn client")?;
            latencies.push(connect_start.elapsed());
            connection.close(0u32.into(), b"churn");
            next_attempt += interval;
        }

        endpoint.wait_idle().await;
        Ok(latencies)
    })
}

#[derive(Debug, Parser, Clone, Copy)]
#[command(name = "new-conn-client")]
struct Opt {
    #[arg(long)]
    connect: SocketAddr,
    #[arg(long, default_value = "10")]
    duration_secs: u64,
    #[arg(long, default_value = "2500")]
    connections_per_second: u64,
    #[arg(long, default_value = "16")]
    workers: usize,
    #[arg(long, default_value = "1200")]
    initial_mtu: u16,
}

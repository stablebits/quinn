use std::sync::Arc;

use clap::{Parser, Subcommand};
#[cfg(not(feature = "split-runtimes"))]
use quinn::TokioRuntime;
#[cfg(feature = "split-runtimes")]
use quinn::{EndpointRuntimeConfig, TokioRuntimeHandle};
use tokio::runtime::{Builder, Runtime};
use tracing::error;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

use perf::{client, server, RuntimeConfig};

fn main() {
    let opt = Cli::parse();
    let runtime = build_runtime(opt.command.workers());

    #[cfg(feature = "split-runtimes")]
    let endpoint_runtime = build_runtime(opt.command.endpoint_workers());
    #[cfg(feature = "split-runtimes")]
    let runtimes: RuntimeConfig = EndpointRuntimeConfig::new(
        Arc::new(TokioRuntimeHandle::new(endpoint_runtime.handle().clone())),
        Arc::new(TokioRuntimeHandle::new(runtime.handle().clone())),
    );
    #[cfg(not(feature = "split-runtimes"))]
    let runtimes: RuntimeConfig = Arc::new(TokioRuntime);

    runtime.block_on(run(opt, runtimes));
}

fn build_runtime(workers: Option<usize>) -> Runtime {
    let mut runtime = Builder::new_multi_thread();
    runtime.enable_all();
    if let Some(workers) = workers {
        runtime.worker_threads(workers);
    }
    runtime.build().unwrap()
}

async fn run(opt: Cli, runtimes: RuntimeConfig) {
    let registry = tracing_subscriber::registry();
    #[cfg(feature = "tokio-console")]
    let registry = registry.with(console_subscriber::spawn());
    registry
        .with(
            fmt::layer().with_filter(
                EnvFilter::try_from_default_env()
                    .or_else(|_| EnvFilter::try_new("warn"))
                    .unwrap(),
            ),
        )
        .init();

    let r = match opt.command {
        Commands::Server(opt) => server::run(opt, runtimes).await,
        Commands::Client(opt) => client::run(opt, runtimes).await,
    };
    if let Err(e) = r {
        error!("{:#}", e);
    }
}

#[derive(Parser)]
#[clap(long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run as a perf server
    Server(server::Opt),
    /// Run as a perf client
    Client(client::Opt),
}

impl Commands {
    fn workers(&self) -> Option<usize> {
        match self {
            Self::Server(opt) => opt.workers(),
            Self::Client(opt) => opt.workers(),
        }
    }

    #[cfg(feature = "split-runtimes")]
    fn endpoint_workers(&self) -> Option<usize> {
        match self {
            Self::Server(opt) => opt.endpoint_workers(),
            Self::Client(opt) => opt.endpoint_workers(),
        }
    }
}

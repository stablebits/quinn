use clap::{Parser, Subcommand};
use tokio::runtime::Builder;
use tracing::error;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

use perf::{client, server};

fn main() {
    let opt = Cli::parse();
    let workers = opt.command.workers();

    let mut runtime = Builder::new_multi_thread();
    runtime.enable_all();
    if let Some(workers) = workers {
        runtime.worker_threads(workers);
    }
    runtime.build().unwrap().block_on(run(opt));
}

async fn run(opt: Cli) {
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
        Commands::Server(opt) => server::run(opt).await,
        Commands::Client(opt) => client::run(opt).await,
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
}

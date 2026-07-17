mod cli;
mod crypto;
mod fs;
mod pqfs;

use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let args = cli::Args::parse();

    info!(
        "pqfs starting: backend={}, mountpoint={}",
        args.backend.display(),
        args.mountpoint.display()
    );

    pqfs::Pqfs::mount(args)
}

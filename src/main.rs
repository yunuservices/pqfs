mod cli;
mod crypto;
mod fs;

use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let mut args = cli::Args::parse();
    args.resolve_password()?;

    info!(
        "pqfs starting: backend={}, mountpoint={}",
        args.backend.display(),
        args.mountpoint.display()
    );

    fs::Pqfs::mount(args)
}

mod cli;
mod commands;
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

    match cli::Cli::parse().command {
        cli::Command::Mount(mut args) => {
            args.credential.resolve()?;
            info!(
                "pqfs starting: backend={}, mountpoint={}",
                args.backend.display(),
                args.mountpoint.display()
            );
            fs::Pqfs::mount(args)
        }
        cli::Command::Keygen(args) => commands::keygen(args),
        cli::Command::Slots(args) => commands::slots(args),
        cli::Command::Share(args) => commands::share(args),
        cli::Command::Revoke(args) => commands::revoke(args),
        cli::Command::Passwd(args) => commands::passwd(args),
    }
}

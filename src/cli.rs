use std::io::IsTerminal;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "pqfs",
    about = "pqfs / hybrid post-quantum FUSE filesystem",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Mount a volume.
    Mount(MountArgs),
}

#[derive(Parser, Debug)]
pub struct MountArgs {
    /// Directory used to store encrypted files and metadata.
    pub backend: PathBuf,

    /// Directory where the filesystem will be mounted.
    pub mountpoint: PathBuf,

    /// Password used to unlock the volume.
    ///
    /// Falls back to the `PQFS_PASSWORD` environment variable. If neither is
    /// supplied and stdin is a TTY, you will be prompted securely.
    #[arg(short, long, env = "PQFS_PASSWORD", hide_env_values = true)]
    pub password: Option<String>,

    /// Create a new volume if one does not already exist.
    ///
    /// Without this flag, mounting a backend that has no `pqfs.header` fails
    /// so that an existing volume is not accidentally overwritten.
    #[arg(long)]
    pub init: bool,

    /// Extra mount options passed to FUSE.
    #[arg(short = 'o', long = "option")]
    pub options: Vec<String>,
}

impl MountArgs {
    /// Resolve the password from CLI arg, env var, or interactive prompt.
    pub fn resolve_password(&mut self) -> Result<()> {
        if self.password.as_ref().is_some_and(|pw| !pw.is_empty()) {
            return Ok(());
        }
        self.password = Some(prompt_password("Volume password: ")?);
        Ok(())
    }
}

pub fn prompt_password(prompt: &str) -> Result<String> {
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "password is required (use --password, set PQFS_PASSWORD, or run interactively)"
        );
    }
    rpassword::prompt_password(prompt).context("failed to read password")
}

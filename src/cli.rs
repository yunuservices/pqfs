use std::io::IsTerminal;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "pqfs",
    about = "pqfs / hybrid post-quantum FUSE filesystem",
    version
)]
pub struct Args {
    /// Directory used to store encrypted files and metadata.
    pub backend: PathBuf,

    /// Directory where the filesystem will be mounted.
    pub mountpoint: PathBuf,

    /// Password used to derive the master key.
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

impl Args {
    /// Resolve the password from CLI arg, env var, or interactive prompt.
    pub fn resolve_password(&mut self) -> Result<()> {
        if let Some(pw) = &self.password {
            if !pw.is_empty() {
                return Ok(());
            }
        }

        if std::io::stdin().is_terminal() {
            let pw = rpassword::prompt_password("Volume password: ")
                .context("failed to read password")?;
            self.password = Some(pw);
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "password is required (use --password, set PQFS_PASSWORD, or run interactively)"
            ))
        }
    }
}

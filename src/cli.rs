use std::io::IsTerminal;
use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::crypto::{Identity, Unlock};
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

    /// Generate an ML-KEM identity for receiving shared volumes.
    Keygen(KeygenArgs),

    /// List the key slots of a volume.
    Slots(VolumeArgs),

    /// Give a recipient their own key slot on a volume.
    Share(ShareArgs),

    /// Remove a key slot from a volume.
    Revoke(RevokeArgs),

    /// Replace the password slot of a volume.
    Passwd(PasswdArgs),

    /// Retire the current master key so revoked slots cannot open copies.
    Rekey(PasswdArgs),
}

#[derive(Parser, Debug)]
pub struct PasswdArgs {
    /// Directory holding the encrypted volume.
    pub backend: PathBuf,

    #[command(flatten)]
    pub credential: CredentialArgs,
}

#[derive(Parser, Debug)]
pub struct KeygenArgs {
    /// Path of the private identity file. The public half is written
    /// alongside it with a .pub suffix.
    #[arg(short, long)]
    pub out: PathBuf,
}

#[derive(Parser, Debug)]
pub struct VolumeArgs {
    /// Directory holding the encrypted volume.
    pub backend: PathBuf,
}

#[derive(Parser, Debug)]
pub struct ShareArgs {
    /// Directory holding the encrypted volume.
    pub backend: PathBuf,

    /// Public identity file of the recipient.
    #[arg(long)]
    pub to: PathBuf,

    /// Name recorded on the new slot.
    #[arg(long)]
    pub label: Option<String>,

    #[command(flatten)]
    pub credential: CredentialArgs,
}

#[derive(Parser, Debug)]
pub struct RevokeArgs {
    /// Directory holding the encrypted volume.
    pub backend: PathBuf,

    /// Index of the slot to remove, as shown by `pqfs slots`.
    #[arg(long)]
    pub slot: usize,

    #[command(flatten)]
    pub credential: CredentialArgs,
}

#[derive(Parser, Debug)]
pub struct CredentialArgs {
    /// Password of an existing password slot.
    #[arg(short, long, env = "PQFS_PASSWORD", hide_env_values = true)]
    pub password: Option<String>,

    /// Private identity file of an existing recipient slot.
    #[arg(long)]
    pub identity: Option<PathBuf>,
}

#[derive(Parser, Debug)]
pub struct MountArgs {
    /// Directory used to store encrypted files and metadata.
    pub backend: PathBuf,

    /// Directory where the filesystem will be mounted.
    pub mountpoint: PathBuf,

    #[command(flatten)]
    pub credential: CredentialArgs,

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

impl CredentialArgs {
    pub fn resolve(&mut self) -> Result<()> {
        if self.identity.is_some() || self.password.as_ref().is_some_and(|pw| !pw.is_empty()) {
            return Ok(());
        }
        self.password = Some(prompt_password("Volume password: ")?);
        Ok(())
    }

    pub fn identity_file(&self) -> Result<Option<Identity>> {
        match &self.identity {
            Some(path) => Identity::load(path).map(Some),
            None => Ok(None),
        }
    }

    pub fn unlock<'a>(&'a self, identity: &'a Option<Identity>) -> Result<Unlock<'a>> {
        if let Some(identity) = identity {
            return Ok(Unlock::Identity(identity));
        }
        Ok(Unlock::Password(self.require_password()?))
    }

    pub fn require_password(&self) -> Result<&str> {
        match self.password.as_deref() {
            Some(password) if !password.is_empty() => Ok(password),
            _ => anyhow::bail!("a password is required"),
        }
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

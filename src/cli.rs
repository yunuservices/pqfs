use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "pqfs", about = "pqfs / hybrid post-quantum FUSE filesystem")]
pub struct Args {
    /// Directory used to store encrypted files and metadata.
    pub backend: PathBuf,

    /// Directory where the filesystem will be mounted.
    pub mountpoint: PathBuf,

    /// Password used to derive the master key.
    #[arg(short, long)]
    pub password: String,

    /// Extra mount options passed to FUSE.
    #[arg(short = 'o', long = "option")]
    pub options: Vec<String>,
}

impl Args {
    pub fn run(self) -> anyhow::Result<()> {
        crate::fs::mount_fs(self)
    }
}

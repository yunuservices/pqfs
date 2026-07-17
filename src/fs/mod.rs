mod entry;
mod inner;
mod ops;
mod wrapper;

use std::time::Duration;

pub(crate) use entry::{Entry, EntryKind};
pub(crate) use inner::PqfsInner;
pub use wrapper::Pqfs;

pub(crate) const INDEX_FILE: &str = "pqfs.index";
pub(crate) const TTL: Duration = Duration::from_secs(1);
pub(crate) const BLOCK_SIZE: u64 = 512;

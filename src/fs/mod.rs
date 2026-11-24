mod blocks;
mod entry;
pub(crate) mod inner;
mod ops;
mod wrapper;

use std::time::Duration;

pub(crate) use inner::rekey_index;
pub use wrapper::Pqfs;

pub(crate) const INDEX_FILE: &str = "pqfs.index";
pub(crate) const INDEX_TMP: &str = "pqfs.index.tmp";
pub(crate) const ROOT_INO: u64 = fuser::INodeNo::ROOT.0;
pub(crate) const TTL: Duration = Duration::from_secs(1);
pub(crate) const BLOCK_SIZE: u64 = 512;
pub(crate) const MAX_NAME_LEN: u16 = 255;

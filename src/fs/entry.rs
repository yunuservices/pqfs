use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) enum EntryKind {
    File,
    Dir,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct Entry {
    pub(crate) ino: u64,
    pub(crate) parent: u64,
    pub(crate) name_hash: [u8; 32],
    pub(crate) name_encrypted: Vec<u8>,
    // encrypted per-file key (empty for directories)
    pub(crate) content_key: Vec<u8>,
    pub(crate) kind: EntryKind,
    pub(crate) size: u64,
    pub(crate) perm: u16,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

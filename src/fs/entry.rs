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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_bincode_roundtrip() {
        let entry = Entry {
            ino: 42,
            parent: 1,
            name_hash: [0u8; 32],
            name_encrypted: vec![1, 2, 3],
            content_key: vec![4, 5, 6],
            kind: EntryKind::File,
            size: 123,
            perm: 0o644,
            uid: 1000,
            gid: 1000,
        };
        let bytes = bincode::serialize(&entry).unwrap();
        let decoded: Entry = bincode::deserialize(&bytes).unwrap();
        assert_eq!(entry.ino, decoded.ino);
        assert_eq!(entry.size, decoded.size);
        assert!(matches!(decoded.kind, EntryKind::File));
    }
}

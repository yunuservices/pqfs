use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) enum EntryKind {
    File,
    Dir,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub(crate) struct Timestamps {
    pub(crate) atime: u64,
    pub(crate) mtime: u64,
    pub(crate) ctime: u64,
    pub(crate) crtime: u64,
}

impl Timestamps {
    pub(crate) fn now() -> Self {
        let now = now_nanos();
        Self {
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
        }
    }

    pub(crate) fn touch_modified(&mut self) {
        let now = now_nanos();
        self.mtime = now;
        self.ctime = now;
    }
}

pub(crate) fn now_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

pub(crate) fn to_system_time(nanos: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_nanos(nanos)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct Entry {
    pub(crate) ino: u64,
    pub(crate) parent: u64,
    pub(crate) name_hash: [u8; 32],
    pub(crate) name_encrypted: Vec<u8>,
    pub(crate) content_key: Vec<u8>,
    pub(crate) kind: EntryKind,
    pub(crate) size: u64,
    pub(crate) perm: u16,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) times: Timestamps,
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
            times: Timestamps::now(),
        };
        let bytes = bincode::serialize(&entry).unwrap();
        let decoded: Entry = bincode::deserialize(&bytes).unwrap();
        assert_eq!(entry.ino, decoded.ino);
        assert_eq!(entry.size, decoded.size);
        assert!(matches!(decoded.kind, EntryKind::File));
    }
}

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::{Context, Result};
use fuser::{FUSE_ROOT_ID, FileAttr, FileType};

use super::entry::{Entry, EntryKind};
use super::{BLOCK_SIZE, INDEX_FILE};
use crate::crypto::Crypto;

/// The actual filesystem state. Mutated under an `Arc<Mutex<...>>` so that
/// long-running I/O operations can be offloaded to worker threads without
/// blocking the FUSE dispatch loop.
pub(crate) struct PqfsInner {
    pub(crate) backend: PathBuf,
    pub(crate) crypto: Crypto,
    pub(crate) entries: BTreeMap<u64, Entry>,
    pub(crate) next_ino: u64,
}

impl PqfsInner {
    pub(crate) fn load(backend: PathBuf, crypto: Crypto) -> Result<Self> {
        fs::create_dir_all(&backend)?;
        fs::create_dir_all(backend.join("data"))?;

        let index_path = backend.join(INDEX_FILE);
        let (entries, next_ino) = if index_path.exists() {
            let data = fs::read(&index_path)
                .with_context(|| format!("failed to read {}", index_path.display()))?;
            let plaintext = crypto.decrypt(&data).context("failed to decrypt index")?;
            let map: BTreeMap<u64, Entry> = bincode::deserialize(&plaintext)?;
            let next_ino = map.keys().next_back().copied().unwrap_or(FUSE_ROOT_ID) + 1;
            (map, next_ino)
        } else {
            let mut map = BTreeMap::new();
            let root_hash = crypto.hash_filename("");
            let root_name = crypto
                .encrypt_filename("")
                .context("failed to encrypt root name")?;
            map.insert(
                FUSE_ROOT_ID,
                Entry {
                    ino: FUSE_ROOT_ID,
                    parent: FUSE_ROOT_ID,
                    name_hash: root_hash,
                    name_encrypted: root_name,
                    content_key: Vec::new(),
                    kind: EntryKind::Dir,
                    size: 0,
                    perm: 0o755,
                    uid: unsafe { libc::getuid() },
                    gid: unsafe { libc::getgid() },
                },
            );
            (map, FUSE_ROOT_ID + 1)
        };

        Ok(Self {
            backend,
            crypto,
            entries,
            next_ino,
        })
    }

    pub(crate) fn save_index(&mut self) -> Result<()> {
        let plaintext = bincode::serialize(&self.entries)?;
        let ciphertext = self.crypto.encrypt(&plaintext)?;
        let index_path = self.backend.join(INDEX_FILE);
        let tmp = index_path.with_extension("tmp");
        fs::write(&tmp, ciphertext)?;
        fs::rename(&tmp, &index_path)?;
        Ok(())
    }

    pub(crate) fn attr_for(&self, entry: &Entry) -> FileAttr {
        let now = SystemTime::now();
        FileAttr {
            ino: entry.ino,
            size: entry.size,
            blocks: (entry.size + BLOCK_SIZE - 1) / BLOCK_SIZE,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind: match entry.kind {
                EntryKind::File => FileType::RegularFile,
                EntryKind::Dir => FileType::Directory,
            },
            perm: entry.perm,
            nlink: 1,
            uid: entry.uid,
            gid: entry.gid,
            rdev: 0,
            flags: 0,
            blksize: 4096,
        }
    }

    pub(crate) fn data_path(&self, ino: u64) -> PathBuf {
        self.backend.join("data").join(format!("{}", ino))
    }

    pub(crate) fn find_child(&self, parent: u64, name: &OsStr) -> Option<&Entry> {
        let name = name.to_string_lossy();
        let hash = self.crypto.hash_filename(&name);
        let crypto = &self.crypto;
        self.entries.values().find(|e| {
            if e.parent != parent || e.name_hash != hash {
                return false;
            }
            // Verify with decryption to rule out hash collisions.
            crypto
                .decrypt_filename(&e.name_encrypted)
                .map(|decrypted| decrypted == name.as_ref())
                .unwrap_or(false)
        })
    }

    pub(crate) fn allocate_ino(&mut self) -> u64 {
        let ino = self.next_ino;
        self.next_ino += 1;
        ino
    }
}

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use fuser::{FUSE_ROOT_ID, FileAttr};

use super::entry::{Entry, EntryKind, Timestamps, file_type, to_system_time};
use super::{BLOCK_SIZE, INDEX_FILE};
use crate::crypto::Crypto;

/// The actual filesystem metadata state. It is decoupled from `Crypto` so
/// long-running I/O and crypto work does not have to hold the metadata lock.
pub(crate) struct PqfsInner {
    pub(crate) backend: PathBuf,
    pub(crate) entries: BTreeMap<u64, Entry>,
    pub(crate) next_ino: u64,
    children: HashMap<(u64, [u8; 32]), u64>,
    by_parent: HashMap<u64, BTreeSet<u64>>,
    dirty: bool,
}

impl PqfsInner {
    pub(crate) fn load(backend: PathBuf, crypto: &Crypto) -> Result<Self> {
        fs::create_dir_all(&backend)?;
        fs::create_dir_all(backend.join("data"))?;

        let index_path = backend.join(INDEX_FILE);
        let (entries, next_ino) = if index_path.exists() {
            let data = fs::read(&index_path)
                .with_context(|| format!("failed to read {}", index_path.display()))?;
            let plaintext = crypto.decrypt(&data).context(
                "failed to decrypt index (the volume may have been rekeyed since this header was written)",
            )?;
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
                    times: Timestamps::now(),
                    link_target: Vec::new(),
                },
            );
            (map, FUSE_ROOT_ID + 1)
        };

        let mut this = Self {
            backend,
            entries,
            next_ino,
            children: HashMap::new(),
            by_parent: HashMap::new(),
            dirty: false,
        };
        this.rebuild_indexes();
        Ok(this)
    }

    fn rebuild_indexes(&mut self) {
        self.children.clear();
        self.by_parent.clear();
        let links: Vec<(u64, u64, [u8; 32])> = self
            .entries
            .values()
            .filter(|e| e.ino != FUSE_ROOT_ID)
            .map(|e| (e.ino, e.parent, e.name_hash))
            .collect();
        for (ino, parent, name_hash) in links {
            self.link(ino, parent, name_hash);
        }
    }

    fn link(&mut self, ino: u64, parent: u64, name_hash: [u8; 32]) {
        self.children.insert((parent, name_hash), ino);
        self.by_parent.entry(parent).or_default().insert(ino);
    }

    fn unlink_index(&mut self, ino: u64, parent: u64, name_hash: [u8; 32]) {
        if self.children.get(&(parent, name_hash)) == Some(&ino) {
            self.children.remove(&(parent, name_hash));
        }
        if let Some(set) = self.by_parent.get_mut(&parent) {
            set.remove(&ino);
            if set.is_empty() {
                self.by_parent.remove(&parent);
            }
        }
    }

    pub(crate) fn insert_entry(&mut self, entry: Entry) {
        if let Some(previous) = self.entries.get(&entry.ino) {
            let (parent, name_hash) = (previous.parent, previous.name_hash);
            self.unlink_index(entry.ino, parent, name_hash);
        }
        if entry.ino != FUSE_ROOT_ID {
            self.link(entry.ino, entry.parent, entry.name_hash);
        }
        self.entries.insert(entry.ino, entry);
    }

    pub(crate) fn remove_entry(&mut self, ino: u64) -> Option<Entry> {
        let entry = self.entries.remove(&ino)?;
        self.unlink_index(ino, entry.parent, entry.name_hash);
        Some(entry)
    }

    pub(crate) fn relink(
        &mut self,
        ino: u64,
        new_parent: u64,
        new_name_hash: [u8; 32],
        new_name_encrypted: Vec<u8>,
    ) {
        let Some(entry) = self.entries.get(&ino) else {
            return;
        };
        let (parent, name_hash) = (entry.parent, entry.name_hash);
        self.unlink_index(ino, parent, name_hash);

        if let Some(entry) = self.entries.get_mut(&ino) {
            entry.parent = new_parent;
            entry.name_hash = new_name_hash;
            entry.name_encrypted = new_name_encrypted;
            entry.times.touch_changed();
        }
        self.link(ino, new_parent, new_name_hash);
    }

    pub(crate) fn child_inodes(&self, parent: u64) -> impl Iterator<Item = &Entry> {
        self.by_parent
            .get(&parent)
            .into_iter()
            .flatten()
            .filter_map(|ino| self.entries.get(ino))
    }

    pub(crate) fn has_children(&self, parent: u64) -> bool {
        self.by_parent.get(&parent).is_some_and(|s| !s.is_empty())
    }

    pub(crate) fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    pub(crate) fn flush_index(&mut self, crypto: &Crypto) -> Result<()> {
        if !self.dirty {
            return Ok(());
        }
        self.save_index(crypto)
    }

    pub(crate) fn save_index(&mut self, crypto: &Crypto) -> Result<()> {
        let plaintext = bincode::serialize(&self.entries)?;
        let ciphertext = crypto.encrypt(&plaintext)?;
        let index_path = self.backend.join(INDEX_FILE);
        let tmp = index_path.with_extension("tmp");

        let mut file = fs::File::create(&tmp)
            .with_context(|| format!("failed to create {}", tmp.display()))?;
        file.write_all(&ciphertext)?;
        file.sync_all()?;
        drop(file);

        fs::rename(&tmp, &index_path)?;
        fs::File::open(&self.backend)?.sync_all()?;
        self.dirty = false;
        Ok(())
    }

    pub(crate) fn attr_for(&self, entry: &Entry) -> FileAttr {
        FileAttr {
            ino: entry.ino,
            size: entry.size,
            blocks: entry.size.div_ceil(BLOCK_SIZE),
            atime: to_system_time(entry.times.atime),
            mtime: to_system_time(entry.times.mtime),
            ctime: to_system_time(entry.times.ctime),
            crtime: to_system_time(entry.times.crtime),
            kind: file_type(&entry.kind),
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

    pub(crate) fn find_child(&self, crypto: &Crypto, parent: u64, name: &OsStr) -> Option<&Entry> {
        let name = name.to_string_lossy();
        let hash = crypto.hash_filename(&name);
        let entry = self.entries.get(self.children.get(&(parent, hash))?)?;
        crypto
            .decrypt_filename(&entry.name_encrypted)
            .ok()
            .filter(|decrypted| decrypted == name.as_ref())
            .map(|_| entry)
    }

    pub(crate) fn allocate_ino(&mut self) -> u64 {
        let ino = self.next_ino;
        self.next_ino += 1;
        ino
    }
}

/// Re-encrypt the directory index under a new master key. File contents are
/// left untouched: only the wrapped per-file keys and the encrypted names are
/// rewritten, so the cost is proportional to the number of entries.
pub(crate) fn rekey_index(backend: &Path, old: &Crypto, new: &Crypto) -> Result<Vec<u8>> {
    let index_path = backend.join(INDEX_FILE);
    let mut entries: BTreeMap<u64, Entry> = if index_path.exists() {
        let data = fs::read(&index_path)
            .with_context(|| format!("failed to read {}", index_path.display()))?;
        let plaintext = old.decrypt(&data).context("failed to decrypt index")?;
        bincode::deserialize(&plaintext)?
    } else {
        BTreeMap::new()
    };

    for entry in entries.values_mut() {
        if !entry.content_key.is_empty() {
            let content_key = old
                .decrypt(&entry.content_key)
                .with_context(|| format!("failed to unwrap the key of inode {}", entry.ino))?;
            entry.content_key = new.encrypt(&content_key)?;
        }

        if !entry.name_encrypted.is_empty() {
            let name = old
                .decrypt_filename(&entry.name_encrypted)
                .with_context(|| format!("failed to decrypt the name of inode {}", entry.ino))?;
            entry.name_encrypted = new.encrypt_filename(&name)?;
            entry.name_hash = new.hash_filename(&name);
        }

        if !entry.link_target.is_empty() {
            let target = old.decrypt_filename(&entry.link_target).with_context(|| {
                format!("failed to decrypt the link target of inode {}", entry.ino)
            })?;
            entry.link_target = new.encrypt_filename(&target)?;
        }
    }

    new.encrypt(&bincode::serialize(&entries)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Crypto;

    fn setup() -> (tempfile::TempDir, Crypto) {
        let dir = tempfile::tempdir().unwrap();
        let crypto = Crypto::init_for_tests("test-password", dir.path()).unwrap();
        (dir, crypto)
    }

    #[test]
    fn load_creates_root_entry() {
        let (dir, crypto) = setup();
        let inner = PqfsInner::load(dir.path().to_path_buf(), &crypto).unwrap();
        assert!(inner.entries.contains_key(&FUSE_ROOT_ID));
        assert_eq!(inner.next_ino, FUSE_ROOT_ID + 1);
    }

    #[test]
    fn save_index_creates_file() {
        let (dir, crypto) = setup();
        let mut inner = PqfsInner::load(dir.path().to_path_buf(), &crypto).unwrap();
        inner.save_index(&crypto).unwrap();
        assert!(dir.path().join(INDEX_FILE).exists());
    }

    #[test]
    fn save_index_leaves_no_temporary_file() {
        let (dir, crypto) = setup();
        let mut inner = PqfsInner::load(dir.path().to_path_buf(), &crypto).unwrap();
        inner.save_index(&crypto).unwrap();
        inner.save_index(&crypto).unwrap();
        assert!(dir.path().join(INDEX_FILE).exists());
        assert!(!dir.path().join("pqfs.tmp").exists());
    }

    #[test]
    fn save_and_reload_preserves_entries() {
        let (dir, crypto) = setup();
        let mut inner = PqfsInner::load(dir.path().to_path_buf(), &crypto).unwrap();
        let first = inner.allocate_ino();
        assert_eq!(first, FUSE_ROOT_ID + 1);

        inner.insert_entry(Entry {
            ino: first,
            parent: FUSE_ROOT_ID,
            name_hash: [0u8; 32],
            name_encrypted: Vec::new(),
            content_key: Vec::new(),
            kind: EntryKind::File,
            size: 0,
            perm: 0o644,
            uid: 0,
            gid: 0,
            times: Timestamps::now(),
            link_target: Vec::new(),
        });

        inner.save_index(&crypto).unwrap();
        let reloaded = PqfsInner::load(dir.path().to_path_buf(), &crypto).unwrap();
        assert!(reloaded.entries.contains_key(&FUSE_ROOT_ID));
        assert!(reloaded.entries.contains_key(&first));
        assert_eq!(reloaded.next_ino, inner.next_ino);
    }

    #[test]
    fn attr_reports_stored_timestamps() {
        let (dir, crypto) = setup();
        let mut inner = PqfsInner::load(dir.path().to_path_buf(), &crypto).unwrap();
        let ino = inner.allocate_ino();
        let mut times = Timestamps::now();
        times.mtime = 1_700_000_000_000_000_000;
        times.crtime = 1_600_000_000_000_000_000;
        inner.insert_entry(Entry {
            ino,
            parent: FUSE_ROOT_ID,
            name_hash: [0u8; 32],
            name_encrypted: Vec::new(),
            content_key: Vec::new(),
            kind: EntryKind::File,
            size: 0,
            perm: 0o644,
            uid: 0,
            gid: 0,
            link_target: Vec::new(),
            times,
        });

        let attr = inner.attr_for(inner.entries.get(&ino).unwrap());
        assert_eq!(attr.mtime, to_system_time(times.mtime));
        assert_eq!(attr.crtime, to_system_time(times.crtime));
        assert_ne!(attr.mtime, attr.crtime);
    }

    #[test]
    fn timestamps_survive_an_index_reload() {
        let (dir, crypto) = setup();
        let mut inner = PqfsInner::load(dir.path().to_path_buf(), &crypto).unwrap();
        let before = inner.entries.get(&FUSE_ROOT_ID).unwrap().times;
        inner.save_index(&crypto).unwrap();

        let reloaded = PqfsInner::load(dir.path().to_path_buf(), &crypto).unwrap();
        let after = reloaded.entries.get(&FUSE_ROOT_ID).unwrap().times;
        assert_eq!(before.crtime, after.crtime);
        assert_eq!(before.mtime, after.mtime);
    }

    #[test]
    fn is_descendant_detects_a_cycle_target() {
        let (dir, crypto) = setup();
        let mut inner = PqfsInner::load(dir.path().to_path_buf(), &crypto).unwrap();

        let a = inner.allocate_ino();
        let b = inner.allocate_ino();
        for (ino, parent) in [(a, FUSE_ROOT_ID), (b, a)] {
            inner.insert_entry(Entry {
                ino,
                parent,
                name_hash: [0u8; 32],
                name_encrypted: Vec::new(),
                content_key: Vec::new(),
                kind: EntryKind::Dir,
                size: 0,
                perm: 0o755,
                uid: 0,
                gid: 0,
                times: Timestamps::now(),
                link_target: Vec::new(),
            });
        }

        assert!(inner.is_descendant_of(b, a));
        assert!(!inner.is_descendant_of(a, b));
        assert!(!inner.is_descendant_of(FUSE_ROOT_ID, a));
    }

    #[test]
    fn child_index_survives_a_reload() {
        let (dir, crypto) = setup();
        let mut inner = PqfsInner::load(dir.path().to_path_buf(), &crypto).unwrap();

        let ino = inner.allocate_ino();
        let name = "belge.txt";
        inner.insert_entry(Entry {
            ino,
            parent: FUSE_ROOT_ID,
            name_hash: crypto.hash_filename(name),
            name_encrypted: crypto.encrypt_filename(name).unwrap(),
            content_key: Vec::new(),
            kind: EntryKind::File,
            size: 0,
            perm: 0o644,
            uid: 0,
            gid: 0,
            times: Timestamps::now(),
            link_target: Vec::new(),
        });
        inner.save_index(&crypto).unwrap();

        let reloaded = PqfsInner::load(dir.path().to_path_buf(), &crypto).unwrap();
        let found = reloaded
            .find_child(&crypto, FUSE_ROOT_ID, std::ffi::OsStr::new(name))
            .unwrap();
        assert_eq!(found.ino, ino);
        assert_eq!(reloaded.child_inodes(FUSE_ROOT_ID).count(), 1);
        assert!(reloaded.has_children(FUSE_ROOT_ID));
        assert!(!reloaded.has_children(ino));
    }

    #[test]
    fn relink_moves_the_child_index_entry() {
        let (dir, crypto) = setup();
        let mut inner = PqfsInner::load(dir.path().to_path_buf(), &crypto).unwrap();

        let target_dir = inner.allocate_ino();
        inner.insert_entry(Entry {
            ino: target_dir,
            parent: FUSE_ROOT_ID,
            name_hash: crypto.hash_filename("d"),
            name_encrypted: crypto.encrypt_filename("d").unwrap(),
            content_key: Vec::new(),
            kind: EntryKind::Dir,
            size: 0,
            perm: 0o755,
            uid: 0,
            gid: 0,
            times: Timestamps::now(),
            link_target: Vec::new(),
        });

        let ino = inner.allocate_ino();
        inner.insert_entry(Entry {
            ino,
            parent: FUSE_ROOT_ID,
            name_hash: crypto.hash_filename("eski"),
            name_encrypted: crypto.encrypt_filename("eski").unwrap(),
            content_key: Vec::new(),
            kind: EntryKind::File,
            size: 0,
            perm: 0o644,
            uid: 0,
            gid: 0,
            times: Timestamps::now(),
            link_target: Vec::new(),
        });

        inner.relink(
            ino,
            target_dir,
            crypto.hash_filename("yeni"),
            crypto.encrypt_filename("yeni").unwrap(),
        );

        assert!(
            inner
                .find_child(&crypto, FUSE_ROOT_ID, std::ffi::OsStr::new("eski"))
                .is_none()
        );
        let moved = inner
            .find_child(&crypto, target_dir, std::ffi::OsStr::new("yeni"))
            .unwrap();
        assert_eq!(moved.ino, ino);
        assert_eq!(inner.child_inodes(target_dir).count(), 1);
    }

    #[test]
    fn remove_entry_clears_the_child_index() {
        let (dir, crypto) = setup();
        let mut inner = PqfsInner::load(dir.path().to_path_buf(), &crypto).unwrap();

        let ino = inner.allocate_ino();
        inner.insert_entry(Entry {
            ino,
            parent: FUSE_ROOT_ID,
            name_hash: crypto.hash_filename("x"),
            name_encrypted: crypto.encrypt_filename("x").unwrap(),
            content_key: Vec::new(),
            kind: EntryKind::File,
            size: 0,
            perm: 0o644,
            uid: 0,
            gid: 0,
            times: Timestamps::now(),
            link_target: Vec::new(),
        });
        assert!(inner.has_children(FUSE_ROOT_ID));

        inner.remove_entry(ino).unwrap();
        assert!(!inner.has_children(FUSE_ROOT_ID));
        assert!(
            inner
                .find_child(&crypto, FUSE_ROOT_ID, std::ffi::OsStr::new("x"))
                .is_none()
        );
    }

    #[test]
    fn flush_index_only_writes_when_dirty() {
        let (dir, crypto) = setup();
        let mut inner = PqfsInner::load(dir.path().to_path_buf(), &crypto).unwrap();
        inner.save_index(&crypto).unwrap();

        let path = dir.path().join(INDEX_FILE);
        let before = std::fs::metadata(&path).unwrap().len();
        let first = std::fs::read(&path).unwrap();

        inner.flush_index(&crypto).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), first);

        inner.mark_dirty();
        inner.flush_index(&crypto).unwrap();
        assert_ne!(std::fs::read(&path).unwrap(), first);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), before);
    }

    #[test]
    fn rekey_rewraps_keys_names_and_link_targets() {
        let dir = tempfile::tempdir().unwrap();
        let old = Crypto::init_for_tests("pw", dir.path()).unwrap();
        let mut inner = PqfsInner::load(dir.path().to_path_buf(), &old).unwrap();

        let file = inner.allocate_ino();
        inner.insert_entry(Entry {
            ino: file,
            parent: FUSE_ROOT_ID,
            name_hash: old.hash_filename("belge.txt"),
            name_encrypted: old.encrypt_filename("belge.txt").unwrap(),
            content_key: old.encrypt(old.random_key().as_slice()).unwrap(),
            kind: EntryKind::File,
            size: 0,
            perm: 0o644,
            uid: 0,
            gid: 0,
            times: Timestamps::now(),
            link_target: Vec::new(),
        });

        let link = inner.allocate_ino();
        inner.insert_entry(Entry {
            ino: link,
            parent: FUSE_ROOT_ID,
            name_hash: old.hash_filename("link"),
            name_encrypted: old.encrypt_filename("link").unwrap(),
            content_key: Vec::new(),
            kind: EntryKind::Symlink,
            size: 9,
            perm: 0o777,
            uid: 0,
            gid: 0,
            times: Timestamps::now(),
            link_target: old.encrypt_filename("belge.txt").unwrap(),
        });
        let old_content_key = inner.entries.get(&file).unwrap().content_key.clone();
        inner.save_index(&old).unwrap();

        let new = Crypto::init_for_tests("pw2", &dir.path().join("other")).unwrap();
        let index = rekey_index(dir.path(), &old, &new).unwrap();
        std::fs::write(dir.path().join(INDEX_FILE), index).unwrap();

        let reloaded = PqfsInner::load(dir.path().to_path_buf(), &new).unwrap();
        let file_entry = reloaded.entries.get(&file).unwrap();
        assert_ne!(file_entry.content_key, old_content_key);
        assert_eq!(
            new.decrypt(&file_entry.content_key).unwrap(),
            old.decrypt(&old_content_key).unwrap()
        );
        assert!(
            reloaded
                .find_child(&new, FUSE_ROOT_ID, std::ffi::OsStr::new("belge.txt"))
                .is_some()
        );

        let link_entry = reloaded.entries.get(&link).unwrap();
        assert_eq!(
            new.decrypt_filename(&link_entry.link_target).unwrap(),
            "belge.txt"
        );
        assert!(old.decrypt_filename(&link_entry.link_target).is_err());
    }
}

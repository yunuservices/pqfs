use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::PathBuf;

use fuser::{
    FileType, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen,
    ReplyWrite,
};
use libc::{EEXIST, EIO, ENOENT, ENOTDIR, ENOTEMPTY};
use tracing::{error, warn};
use zeroize::Zeroizing;

use super::TTL;
use super::entry::{Entry, EntryKind};
use super::inner::PqfsInner;
use crate::crypto::Crypto;

impl PqfsInner {
    pub(crate) fn lookup(&self, crypto: &Crypto, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if let Some(entry) = self.find_child(crypto, parent, name).cloned() {
            reply.entry(&TTL, &self.attr_for(&entry), 0);
        } else {
            reply.error(ENOENT);
        }
    }

    pub(crate) fn getattr(&self, _crypto: &Crypto, ino: u64, reply: ReplyAttr) {
        if let Some(entry) = self.entries.get(&ino).cloned() {
            reply.attr(&TTL, &self.attr_for(&entry));
        } else {
            reply.error(ENOENT);
        }
    }

    /// Synchronous counterpart of `Filesystem::read`, callable from worker
    /// threads. No `&self` is required because the caller already extracted the
    /// entry snapshot and data path while holding only a brief read lock.
    pub(crate) fn do_read(
        crypto: &Crypto,
        entry: &Entry,
        data_path: PathBuf,
        offset: i64,
        size: u32,
        reply: ReplyData,
    ) {
        let ciphertext = match fs::read(&data_path) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                reply.data(&[]);
                return;
            }
            Err(e) => {
                error!("read error for {}: {}", data_path.display(), e);
                reply.error(EIO);
                return;
            }
        };

        let plaintext = match decrypt_file_content(crypto, entry, &ciphertext) {
            Ok(v) => v,
            Err(code) => {
                reply.error(code);
                return;
            }
        };

        let (start, end) = clamp_read_range(plaintext.len(), offset, size);
        reply.data(&plaintext[start..end]);
    }

    /// Read the existing plaintext for a file write. Performed outside the
    /// metadata lock so that long-running I/O and crypto do not block other
    /// operations.
    pub(crate) fn read_existing_plaintext(
        crypto: &Crypto,
        entry: &Entry,
        data_path: PathBuf,
    ) -> Result<Vec<u8>, i32> {
        if !data_path.exists() {
            return Ok(Vec::new());
        }
        let ciphertext = match fs::read(&data_path) {
            Ok(v) => v,
            Err(e) => {
                error!("read error on write for {}: {}", data_path.display(), e);
                return Err(EIO);
            }
        };
        decrypt_file_content(crypto, entry, &ciphertext)
    }

    /// Encrypt and write the plaintext for a file write. Returns the
    /// (possibly new) encrypted per-file content key and the final size so the
    /// caller can update metadata under a short write lock.
    pub(crate) fn do_write_data(
        crypto: &Crypto,
        entry: &Entry,
        data_path: PathBuf,
        offset: i64,
        data: &[u8],
    ) -> Result<(Vec<u8>, u64), i32> {
        let mut plaintext = Self::read_existing_plaintext(crypto, entry, data_path.clone())?;

        // Ensure this file has its own per-file key.
        let content_key_enc = if entry.content_key.is_empty() {
            match crypto.encrypt(crypto.random_key().as_slice()) {
                Ok(v) => v,
                Err(e) => {
                    error!("content key encrypt error for inode {}: {}", entry.ino, e);
                    return Err(EIO);
                }
            }
        } else {
            entry.content_key.clone()
        };

        let content_key = decrypt_content_key(crypto, &content_key_enc, entry.ino)?;

        let offset = offset as usize;
        if offset > plaintext.len() {
            plaintext.resize(offset, 0);
        }
        let end = offset + data.len();
        if end > plaintext.len() {
            plaintext.resize(end, 0);
        }
        plaintext[offset..end].copy_from_slice(data);

        let ciphertext = match crypto.encrypt_with_key(&content_key, &plaintext) {
            Ok(v) => v,
            Err(e) => {
                error!("encrypt error for {}: {}", data_path.display(), e);
                return Err(EIO);
            }
        };

        if let Err(e) = fs::write(&data_path, ciphertext) {
            error!("write error for {}: {}", data_path.display(), e);
            return Err(EIO);
        }

        Ok((content_key_enc, plaintext.len() as u64))
    }

    pub(crate) fn readdir(
        &self,
        crypto: &Crypto,
        ino: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let Some(parent) = self.entries.get(&ino).cloned() else {
            reply.error(ENOENT);
            return;
        };
        if !matches!(parent.kind, EntryKind::Dir) {
            reply.error(ENOTDIR);
            return;
        }

        let mut entries: Vec<(u64, FileType, String)> = vec![
            (ino, FileType::Directory, ".".to_string()),
            (parent.parent, FileType::Directory, "..".to_string()),
        ];
        for child in self.entries.values().filter(|e| e.parent == ino) {
            let name = match crypto.decrypt_filename(&child.name_encrypted) {
                Ok(n) => n,
                Err(e) => {
                    error!("filename decryption error for inode {}: {}", child.ino, e);
                    reply.error(EIO);
                    return;
                }
            };
            entries.push((
                child.ino,
                match child.kind {
                    EntryKind::File => FileType::RegularFile,
                    EntryKind::Dir => FileType::Directory,
                },
                name,
            ));
        }

        for (i, (ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(ino, (i + 1) as i64, kind, &name) {
                break;
            }
        }
        reply.ok();
    }

    pub(crate) fn create(
        &mut self,
        crypto: &Crypto,
        parent: u64,
        name: &OsStr,
        mode: u32,
        reply: ReplyCreate,
    ) {
        if self.find_child(crypto, parent, name).is_some() {
            reply.error(EEXIST);
            return;
        }

        let ino = self.allocate_ino();
        let name = name.to_string_lossy().to_string();
        let name_hash = crypto.hash_filename(&name);
        let name_encrypted = match crypto.encrypt_filename(&name) {
            Ok(v) => v,
            Err(e) => {
                error!("filename encryption error: {}", e);
                reply.error(EIO);
                return;
            }
        };
        let content_key = match crypto.encrypt(crypto.random_key().as_slice()) {
            Ok(v) => v,
            Err(e) => {
                error!("content key encryption error: {}", e);
                reply.error(EIO);
                return;
            }
        };
        let entry = Entry {
            ino,
            parent,
            name_hash,
            name_encrypted,
            content_key,
            kind: EntryKind::File,
            size: 0,
            perm: (mode as u16) & 0o777,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        };

        self.entries.insert(ino, entry.clone());
        if let Err(e) = self.save_index(crypto) {
            error!("index save error: {}", e);
            reply.error(EIO);
            return;
        }

        reply.created(&TTL, &self.attr_for(&entry), 0, 0, 0);
    }

    pub(crate) fn mkdir(
        &mut self,
        crypto: &Crypto,
        parent: u64,
        name: &OsStr,
        mode: u32,
        reply: ReplyEntry,
    ) {
        if self.find_child(crypto, parent, name).is_some() {
            reply.error(EEXIST);
            return;
        }

        let ino = self.allocate_ino();
        let name = name.to_string_lossy().to_string();
        let name_hash = crypto.hash_filename(&name);
        let name_encrypted = match crypto.encrypt_filename(&name) {
            Ok(v) => v,
            Err(e) => {
                error!("filename encryption error: {}", e);
                reply.error(EIO);
                return;
            }
        };
        let entry = Entry {
            ino,
            parent,
            name_hash,
            name_encrypted,
            content_key: Vec::new(),
            kind: EntryKind::Dir,
            size: 0,
            perm: (mode as u16) & 0o777,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
        };

        self.entries.insert(ino, entry.clone());
        if let Err(e) = self.save_index(crypto) {
            error!("index save error: {}", e);
            reply.error(EIO);
            return;
        }

        reply.entry(&TTL, &self.attr_for(&entry), 0);
    }

    pub(crate) fn unlink(&mut self, crypto: &Crypto, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(entry) = self.find_child(crypto, parent, name).cloned() else {
            reply.error(ENOENT);
            return;
        };

        self.entries.remove(&entry.ino);
        let data_path = self.data_path(entry.ino);
        if data_path.exists()
            && let Err(e) = fs::remove_file(&data_path)
        {
            warn!("failed to remove data file {}: {}", data_path.display(), e);
        }
        if let Err(e) = self.save_index(crypto) {
            error!("index save error: {}", e);
            reply.error(EIO);
            return;
        }
        reply.ok();
    }

    pub(crate) fn rmdir(&mut self, crypto: &Crypto, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(entry) = self.find_child(crypto, parent, name).cloned() else {
            reply.error(ENOENT);
            return;
        };
        if !matches!(entry.kind, EntryKind::Dir) {
            reply.error(ENOTDIR);
            return;
        }
        if self.entries.values().any(|e| e.parent == entry.ino) {
            reply.error(ENOTEMPTY);
            return;
        }

        self.entries.remove(&entry.ino);
        if let Err(e) = self.save_index(crypto) {
            error!("index save error: {}", e);
            reply.error(EIO);
            return;
        }
        reply.ok();
    }

    pub(crate) fn open(&self, ino: u64, reply: ReplyOpen) {
        if self.entries.contains_key(&ino) {
            reply.opened(0, 0);
        } else {
            reply.error(ENOENT);
        }
    }

    pub(crate) fn release(reply: ReplyEmpty) {
        reply.ok();
    }

    /// Update the metadata after a write has completed on disk.
    pub(crate) fn commit_write(
        &mut self,
        crypto: &Crypto,
        ino: u64,
        content_key_enc: Vec<u8>,
        size: u64,
        reply: ReplyWrite,
        written: u32,
    ) {
        if let Some(e) = self.entries.get_mut(&ino) {
            e.content_key = content_key_enc;
            e.size = size;
        } else {
            // Entry was removed while the write was in flight. The data file
            // is already on disk; report success because the write completed.
            warn!(
                "inode {} removed during write; orphan data file may remain",
                ino
            );
        }
        if let Err(e) = self.save_index(crypto) {
            error!("index save error: {}", e);
            reply.error(EIO);
            return;
        }
        reply.written(written);
    }
}

fn decrypt_content_key(
    crypto: &Crypto,
    content_key_enc: &[u8],
    ino: u64,
) -> Result<Zeroizing<Vec<u8>>, i32> {
    match crypto.decrypt(content_key_enc) {
        Ok(v) => {
            if v.len() != 32 {
                error!("bad per-file key length for inode {}: {}", ino, v.len());
                Err(EIO)
            } else {
                Ok(Zeroizing::new(v))
            }
        }
        Err(e) => {
            error!("content key decrypt error for inode {}: {}", ino, e);
            Err(EIO)
        }
    }
}

fn decrypt_file_content(crypto: &Crypto, entry: &Entry, ciphertext: &[u8]) -> Result<Vec<u8>, i32> {
    if entry.content_key.is_empty() {
        // Legacy file: content encrypted directly with the master key.
        match crypto.decrypt(ciphertext) {
            Ok(v) => Ok(v),
            Err(e) => {
                error!("decrypt error for inode {}: {}", entry.ino, e);
                Err(EIO)
            }
        }
    } else {
        let content_key = decrypt_content_key(crypto, &entry.content_key, entry.ino)?;
        match crypto.decrypt_with_key(&content_key, ciphertext) {
            Ok(v) => Ok(v),
            Err(e) => {
                error!("decrypt error for inode {}: {}", entry.ino, e);
                Err(EIO)
            }
        }
    }
}

fn clamp_read_range(len: usize, offset: i64, size: u32) -> (usize, usize) {
    let start = usize::try_from(offset).unwrap_or(0).min(len);
    let end = start.saturating_add(size as usize).min(len);
    (start, end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::entry::{Entry, EntryKind};
    use crate::fs::inner::PqfsInner;
    use std::sync::{Arc, RwLock};

    #[test]
    fn read_range_past_eof_is_empty() {
        assert_eq!(clamp_read_range(5, 10, 4096), (5, 5));
        assert_eq!(clamp_read_range(5, 5, 4096), (5, 5));
        assert_eq!(clamp_read_range(0, 0, 4096), (0, 0));
    }

    #[test]
    fn read_range_is_truncated_at_eof() {
        assert_eq!(clamp_read_range(5, 0, 4096), (0, 5));
        assert_eq!(clamp_read_range(5, 2, 2), (2, 4));
        assert_eq!(clamp_read_range(5, 2, 100), (2, 5));
    }

    #[test]
    fn read_range_rejects_negative_offset() {
        assert_eq!(clamp_read_range(5, -1, 4096), (0, 5));
    }

    #[test]
    fn read_range_does_not_overflow() {
        assert_eq!(clamp_read_range(5, i64::MAX, u32::MAX), (5, 5));
    }

    #[test]
    fn concurrent_writes_to_one_inode_do_not_lose_data() {
        for _ in 0..8 {
            let dir = tempfile::tempdir().unwrap();
            let crypto = Arc::new(Crypto::init_for_tests("pw", dir.path()).unwrap());
            let mut inner = PqfsInner::load(dir.path().to_path_buf(), &crypto).unwrap();
            let ino = inner.allocate_ino();
            inner.entries.insert(
                ino,
                Entry {
                    ino,
                    parent: 1,
                    name_hash: [0u8; 32],
                    name_encrypted: Vec::new(),
                    content_key: Vec::new(),
                    kind: EntryKind::File,
                    size: 0,
                    perm: 0o644,
                    uid: 0,
                    gid: 0,
                },
            );
            let data_path = inner.data_path(ino);
            let inner = Arc::new(RwLock::new(inner));
            let lock = Arc::new(RwLock::new(()));

            let handles: Vec<_> = [(0i64, b'A'), (4096i64, b'B')]
                .into_iter()
                .map(|(offset, byte)| {
                    let inner = Arc::clone(&inner);
                    let crypto = Arc::clone(&crypto);
                    let lock = Arc::clone(&lock);
                    let data_path = data_path.clone();
                    std::thread::spawn(move || {
                        let _guard = lock.write().unwrap();
                        let entry = inner.read().unwrap().entries.get(&ino).cloned().unwrap();
                        let (key, size) = PqfsInner::do_write_data(
                            crypto.as_ref(),
                            &entry,
                            data_path,
                            offset,
                            &[byte; 1024],
                        )
                        .unwrap();
                        let mut guard = inner.write().unwrap();
                        let e = guard.entries.get_mut(&ino).unwrap();
                        e.content_key = key;
                        e.size = e.size.max(size);
                    })
                })
                .collect();
            for h in handles {
                h.join().unwrap();
            }

            let guard = inner.read().unwrap();
            let entry = guard.entries.get(&ino).unwrap();
            let ciphertext = std::fs::read(guard.data_path(ino)).unwrap();
            let plaintext = decrypt_file_content(crypto.as_ref(), entry, &ciphertext).unwrap();

            assert_eq!(plaintext.len(), 4096 + 1024);
            assert!(plaintext[0..1024].iter().all(|b| *b == b'A'));
            assert!(plaintext[4096..5120].iter().all(|b| *b == b'B'));
        }
    }
}

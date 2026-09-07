use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;

use fuser::{
    FUSE_ROOT_ID, FileType, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyWrite, TimeOrNow,
};
use libc::{EEXIST, EINVAL, EIO, EISDIR, ENOENT, ENOTDIR, ENOTEMPTY};
use tracing::{error, warn};
use zeroize::Zeroizing;

use super::TTL;
use super::blocks;
use super::entry::{Entry, EntryKind, Timestamps};
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
        if !data_path.exists() {
            reply.data(&[]);
            return;
        }

        let content_key = match decrypt_content_key(crypto, &entry.content_key, entry.ino) {
            Ok(v) => v,
            Err(code) => {
                reply.error(code);
                return;
            }
        };

        let offset = u64::try_from(offset).unwrap_or(0);
        match blocks::read_range(
            crypto,
            content_key.as_slice(),
            &data_path,
            entry.size,
            offset,
            size as usize,
        ) {
            Ok(data) => reply.data(&data),
            Err(e) => {
                error!("read error for inode {}: {}", entry.ino, e);
                reply.error(EIO);
            }
        }
    }

    pub(crate) fn do_write_data(
        crypto: &Crypto,
        entry: &Entry,
        data_path: PathBuf,
        offset: i64,
        data: &[u8],
    ) -> Result<(Vec<u8>, u64), i32> {
        let content_key_enc = ensure_content_key(crypto, entry)?;
        let content_key = decrypt_content_key(crypto, &content_key_enc, entry.ino)?;
        let offset = u64::try_from(offset).unwrap_or(0);

        match blocks::write_range(
            crypto,
            content_key.as_slice(),
            &data_path,
            entry.size,
            offset,
            data,
        ) {
            Ok(size) => Ok((content_key_enc, size)),
            Err(e) => {
                error!("write error for inode {}: {}", entry.ino, e);
                Err(EIO)
            }
        }
    }

    pub(crate) fn do_truncate(
        crypto: &Crypto,
        entry: &Entry,
        data_path: PathBuf,
        size: u64,
    ) -> Result<(Vec<u8>, u64), i32> {
        let content_key_enc = ensure_content_key(crypto, entry)?;
        let content_key = decrypt_content_key(crypto, &content_key_enc, entry.ino)?;

        match blocks::truncate(crypto, content_key.as_slice(), &data_path, entry.size, size) {
            Ok(()) => Ok((content_key_enc, size)),
            Err(e) => {
                error!("truncate error for inode {}: {}", entry.ino, e);
                Err(EIO)
            }
        }
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
        for child in self.child_inodes(ino) {
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
            times: Timestamps::now(),
        };

        self.insert_entry(entry.clone());
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
            times: Timestamps::now(),
        };

        self.insert_entry(entry.clone());
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

        if matches!(entry.kind, EntryKind::Dir) {
            reply.error(EISDIR);
            return;
        }

        self.remove_entry(entry.ino);
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
        if self.has_children(entry.ino) {
            reply.error(ENOTEMPTY);
            return;
        }

        self.remove_entry(entry.ino);
        if let Err(e) = self.save_index(crypto) {
            error!("index save error: {}", e);
            reply.error(EIO);
            return;
        }
        reply.ok();
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn apply_setattr(
        &mut self,
        crypto: &Crypto,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        truncated: Option<(Vec<u8>, u64)>,
        reply: ReplyAttr,
    ) {
        let Some(entry) = self.entries.get_mut(&ino) else {
            reply.error(ENOENT);
            return;
        };

        if let Some(mode) = mode {
            entry.perm = (mode as u16) & 0o777;
        }
        if let Some(uid) = uid {
            entry.uid = uid;
        }
        if let Some(gid) = gid {
            entry.gid = gid;
        }
        if let Some(atime) = atime {
            entry.times.atime = time_or_now_nanos(atime);
        }
        if let Some(mtime) = mtime {
            entry.times.mtime = time_or_now_nanos(mtime);
        }
        if let Some((content_key, size)) = truncated {
            entry.content_key = content_key;
            entry.size = size;
            entry.times.touch_modified();
        }
        entry.times.touch_changed();

        let entry = entry.clone();
        if let Err(e) = self.save_index(crypto) {
            error!("index save error: {}", e);
            reply.error(EIO);
            return;
        }
        reply.attr(&TTL, &self.attr_for(&entry));
    }

    pub(crate) fn is_descendant_of(&self, mut ino: u64, ancestor: u64) -> bool {
        let mut hops = 0;
        while ino != FUSE_ROOT_ID && hops < self.entries.len() + 1 {
            if ino == ancestor {
                return true;
            }
            match self.entries.get(&ino) {
                Some(entry) => ino = entry.parent,
                None => return false,
            }
            hops += 1;
        }
        ino == ancestor
    }

    pub(crate) fn rename(
        &mut self,
        crypto: &Crypto,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        reply: ReplyEmpty,
    ) {
        let Some(source) = self.find_child(crypto, parent, name).cloned() else {
            reply.error(ENOENT);
            return;
        };

        match self.entries.get(&newparent) {
            Some(entry) if matches!(entry.kind, EntryKind::Dir) => {}
            Some(_) => {
                reply.error(ENOTDIR);
                return;
            }
            None => {
                reply.error(ENOENT);
                return;
            }
        }

        if matches!(source.kind, EntryKind::Dir) && self.is_descendant_of(newparent, source.ino) {
            reply.error(EINVAL);
            return;
        }

        if let Some(existing) = self.find_child(crypto, newparent, newname).cloned()
            && existing.ino != source.ino
        {
            match (&source.kind, &existing.kind) {
                (EntryKind::Dir, EntryKind::Dir) => {
                    if self.has_children(existing.ino) {
                        reply.error(ENOTEMPTY);
                        return;
                    }
                }
                (EntryKind::Dir, EntryKind::File) => {
                    reply.error(ENOTDIR);
                    return;
                }
                (EntryKind::File, EntryKind::Dir) => {
                    reply.error(EISDIR);
                    return;
                }
                (EntryKind::File, EntryKind::File) => {}
            }

            self.remove_entry(existing.ino);
            let data_path = self.data_path(existing.ino);
            if data_path.exists()
                && let Err(e) = fs::remove_file(&data_path)
            {
                warn!("failed to remove data file {}: {}", data_path.display(), e);
            }
        }

        let newname = newname.to_string_lossy().to_string();
        let name_hash = crypto.hash_filename(&newname);
        let name_encrypted = match crypto.encrypt_filename(&newname) {
            Ok(v) => v,
            Err(e) => {
                error!("filename encryption error: {}", e);
                reply.error(EIO);
                return;
            }
        };

        self.relink(source.ino, newparent, name_hash, name_encrypted);

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
            e.times.touch_modified();
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

fn ensure_content_key(crypto: &Crypto, entry: &Entry) -> Result<Vec<u8>, i32> {
    if !entry.content_key.is_empty() {
        return Ok(entry.content_key.clone());
    }
    crypto.encrypt(crypto.random_key().as_slice()).map_err(|e| {
        error!("content key encrypt error for inode {}: {}", entry.ino, e);
        EIO
    })
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

fn time_or_now_nanos(value: TimeOrNow) -> u64 {
    match value {
        TimeOrNow::SpecificTime(time) => time
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
        TimeOrNow::Now => crate::fs::entry::now_nanos(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::entry::{Entry, EntryKind};
    use crate::fs::inner::PqfsInner;
    use std::sync::{Arc, RwLock};

    #[test]
    fn concurrent_writes_to_one_inode_do_not_lose_data() {
        for _ in 0..8 {
            let dir = tempfile::tempdir().unwrap();
            let crypto = Arc::new(Crypto::init_for_tests("pw", dir.path()).unwrap());
            let mut inner = PqfsInner::load(dir.path().to_path_buf(), &crypto).unwrap();
            let ino = inner.allocate_ino();
            inner.insert_entry(Entry {
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
                times: Timestamps::now(),
            });
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
            let content_key =
                decrypt_content_key(crypto.as_ref(), &entry.content_key, entry.ino).unwrap();
            let plaintext = blocks::read_range(
                crypto.as_ref(),
                content_key.as_slice(),
                &guard.data_path(ino),
                entry.size,
                0,
                entry.size as usize,
            )
            .unwrap();

            assert_eq!(entry.size, 4096 + 1024);
            assert_eq!(plaintext.len(), 4096 + 1024);
            assert!(plaintext[0..1024].iter().all(|b| *b == b'A'));
            assert!(plaintext[4096..5120].iter().all(|b| *b == b'B'));
        }
    }

    #[test]
    fn root_is_not_listed_as_its_own_child() {
        let dir = tempfile::tempdir().unwrap();
        let crypto = Crypto::init_for_tests("pw", dir.path()).unwrap();
        let inner = PqfsInner::load(dir.path().to_path_buf(), &crypto).unwrap();

        let root = inner.entries.get(&fuser::FUSE_ROOT_ID).unwrap();
        assert_eq!(root.parent, fuser::FUSE_ROOT_ID);

        let children: Vec<_> = inner
            .entries
            .values()
            .filter(|e| e.parent == fuser::FUSE_ROOT_ID && e.ino != fuser::FUSE_ROOT_ID)
            .collect();
        assert!(children.is_empty());
    }
}

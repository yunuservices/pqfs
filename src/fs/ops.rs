use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use fuser::{
    Errno, FileHandle, FileType, FopenFlags, Generation, INodeNo, Owner, ReplyAttr, ReplyCreate,
    ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, TimeOrNow,
};
use libc::{EEXIST, EINVAL, EIO, ENOENT, ENOTDIR};
use tracing::{error, warn};
use zeroize::Zeroizing;

use super::blocks;
use super::entry::{Entry, EntryKind, Timestamps, file_type};
use super::inner::PqfsInner;
use super::{ROOT_INO, TTL};
use crate::crypto::Crypto;

impl PqfsInner {
    pub(crate) fn lookup(&self, crypto: &Crypto, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if let Some(entry) = self.find_child(crypto, parent, name).cloned() {
            reply.entry(&TTL, &self.attr_for(&entry), Generation(0));
        } else {
            reply.error(Errno::ENOENT);
        }
    }

    pub(crate) fn getattr(&self, _crypto: &Crypto, ino: u64, reply: ReplyAttr) {
        if let Some(entry) = self.entries.get(&ino).cloned() {
            reply.attr(&TTL, &self.attr_for(&entry));
        } else {
            reply.error(Errno::ENOENT);
        }
    }

    /// Synchronous counterpart of `Filesystem::read`, callable from worker
    /// threads. No `&self` is required because the caller already extracted the
    /// entry snapshot and data path while holding only a brief read lock.
    pub(crate) fn do_read(
        crypto: &Crypto,
        entry: &Entry,
        data_path: PathBuf,
        offset: u64,
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
                reply.error(Errno::from_i32(code));
                return;
            }
        };

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
                reply.error(Errno::EIO);
            }
        }
    }

    pub(crate) fn do_write_data(
        crypto: &Crypto,
        entry: &Entry,
        data_path: PathBuf,
        offset: u64,
        data: &[u8],
    ) -> Result<(Vec<u8>, u64), i32> {
        let content_key_enc = ensure_content_key(crypto, entry)?;
        let content_key = decrypt_content_key(crypto, &content_key_enc, entry.ino)?;

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
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let page = self.readdir_page(crypto, ino, offset, |ino, cookie, kind, name| {
            reply.add(INodeNo(ino), cookie, kind, name)
        });
        match page {
            Ok(()) => reply.ok(),
            Err(code) => reply.error(Errno::from_i32(code)),
        }
    }

    pub(crate) fn readdir_page(
        &self,
        crypto: &Crypto,
        ino: u64,
        offset: u64,
        mut add: impl FnMut(u64, u64, FileType, &str) -> bool,
    ) -> Result<(), i32> {
        let Some(dir) = self.entries.get(&ino) else {
            return Err(ENOENT);
        };
        if !matches!(dir.kind, EntryKind::Dir) {
            return Err(ENOTDIR);
        }

        for (cookie, dot_ino, name) in [(1, ino, "."), (2, dir.parent, "..")] {
            if cookie > offset && add(dot_ino, cookie, FileType::Directory, name) {
                return Ok(());
            }
        }

        for child in self.child_inodes_after(ino, offset.saturating_sub(DOT_ENTRIES)) {
            let name = crypto
                .decrypt_filename(&child.name_encrypted)
                .map_err(|e| {
                    error!("filename decryption error for inode {}: {}", child.ino, e);
                    EIO
                })?;
            if add(
                child.ino,
                child.ino + DOT_ENTRIES,
                file_type(&child.kind),
                &name,
            ) {
                break;
            }
        }
        Ok(())
    }

    pub(crate) fn create(
        &mut self,
        crypto: &Crypto,
        parent: u64,
        name: &OsStr,
        mode: u32,
        owner: Owner,
        reply: ReplyCreate,
    ) {
        if self.find_child(crypto, parent, name).is_some() {
            reply.error(Errno::EEXIST);
            return;
        }

        let ino = self.allocate_ino();
        let name = name.to_string_lossy().to_string();
        let name_hash = crypto.hash_filename(&name);
        let name_encrypted = match crypto.encrypt_filename(&name) {
            Ok(v) => v,
            Err(e) => {
                error!("filename encryption error: {}", e);
                reply.error(Errno::EIO);
                return;
            }
        };
        let content_key = match crypto.encrypt(crypto.random_key().as_slice()) {
            Ok(v) => v,
            Err(e) => {
                error!("content key encryption error: {}", e);
                reply.error(Errno::EIO);
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
            uid: owner.uid,
            gid: owner.gid,
            times: Timestamps::now(),
            link_target: Vec::new(),
        };

        self.insert_entry(entry.clone());
        if let Err(e) = self.save_index(crypto) {
            error!("index save error: {}", e);
            reply.error(Errno::EIO);
            return;
        }

        reply.created(
            &TTL,
            &self.attr_for(&entry),
            Generation(0),
            FileHandle(0),
            FopenFlags::empty(),
        );
    }

    pub(crate) fn mkdir(
        &mut self,
        crypto: &Crypto,
        parent: u64,
        name: &OsStr,
        mode: u32,
        owner: Owner,
        reply: ReplyEntry,
    ) {
        if self.find_child(crypto, parent, name).is_some() {
            reply.error(Errno::EEXIST);
            return;
        }

        let ino = self.allocate_ino();
        let name = name.to_string_lossy().to_string();
        let name_hash = crypto.hash_filename(&name);
        let name_encrypted = match crypto.encrypt_filename(&name) {
            Ok(v) => v,
            Err(e) => {
                error!("filename encryption error: {}", e);
                reply.error(Errno::EIO);
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
            uid: owner.uid,
            gid: owner.gid,
            times: Timestamps::now(),
            link_target: Vec::new(),
        };

        self.insert_entry(entry.clone());
        if let Err(e) = self.save_index(crypto) {
            error!("index save error: {}", e);
            reply.error(Errno::EIO);
            return;
        }

        reply.entry(&TTL, &self.attr_for(&entry), Generation(0));
    }

    pub(crate) fn symlink(
        &mut self,
        crypto: &Crypto,
        parent: u64,
        name: &OsStr,
        target: &Path,
        owner: Owner,
        reply: ReplyEntry,
    ) {
        if self.find_child(crypto, parent, name).is_some() {
            reply.error(Errno::EEXIST);
            return;
        }

        let target = target.to_string_lossy().to_string();
        let link_target = match crypto.encrypt_filename(&target) {
            Ok(v) => v,
            Err(e) => {
                error!("link target encryption error: {}", e);
                reply.error(Errno::EIO);
                return;
            }
        };

        let ino = self.allocate_ino();
        let name = name.to_string_lossy().to_string();
        let name_hash = crypto.hash_filename(&name);
        let name_encrypted = match crypto.encrypt_filename(&name) {
            Ok(v) => v,
            Err(e) => {
                error!("filename encryption error: {}", e);
                reply.error(Errno::EIO);
                return;
            }
        };

        let entry = Entry {
            ino,
            parent,
            name_hash,
            name_encrypted,
            content_key: Vec::new(),
            kind: EntryKind::Symlink,
            size: target.len() as u64,
            perm: 0o777,
            uid: owner.uid,
            gid: owner.gid,
            times: Timestamps::now(),
            link_target,
        };

        self.insert_entry(entry.clone());
        if let Err(e) = self.save_index(crypto) {
            error!("index save error: {}", e);
            reply.error(Errno::EIO);
            return;
        }

        reply.entry(&TTL, &self.attr_for(&entry), Generation(0));
    }

    pub(crate) fn readlink(&self, crypto: &Crypto, ino: u64, reply: ReplyData) {
        let Some(entry) = self.entries.get(&ino) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if !matches!(entry.kind, EntryKind::Symlink) {
            reply.error(Errno::EINVAL);
            return;
        }
        match crypto.decrypt_filename(&entry.link_target) {
            Ok(target) => reply.data(target.as_bytes()),
            Err(e) => {
                error!("link target decryption error for inode {}: {}", ino, e);
                reply.error(Errno::EIO);
            }
        }
    }

    pub(crate) fn unlink(&mut self, crypto: &Crypto, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(entry) = self.find_child(crypto, parent, name).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };

        if matches!(entry.kind, EntryKind::Dir) {
            reply.error(Errno::EISDIR);
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
            reply.error(Errno::EIO);
            return;
        }
        reply.ok();
    }

    pub(crate) fn rmdir(&mut self, crypto: &Crypto, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(entry) = self.find_child(crypto, parent, name).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };
        if !matches!(entry.kind, EntryKind::Dir) {
            reply.error(Errno::ENOTDIR);
            return;
        }
        if self.has_children(entry.ino) {
            reply.error(Errno::ENOTEMPTY);
            return;
        }

        self.remove_entry(entry.ino);
        if let Err(e) = self.save_index(crypto) {
            error!("index save error: {}", e);
            reply.error(Errno::EIO);
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
            reply.error(Errno::ENOENT);
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
            reply.error(Errno::EIO);
            return;
        }
        reply.attr(&TTL, &self.attr_for(&entry));
    }

    pub(crate) fn is_descendant_of(&self, mut ino: u64, ancestor: u64) -> bool {
        let mut hops = 0;
        while ino != ROOT_INO && hops < self.entries.len() + 1 {
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

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn rename(
        &mut self,
        crypto: &Crypto,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        flags: u32,
        reply: ReplyEmpty,
    ) {
        let Some(source) = self.find_child(crypto, parent, name).cloned() else {
            reply.error(Errno::ENOENT);
            return;
        };

        let target_exists = self.find_child(crypto, newparent, newname).is_some();
        if let Some(code) = rename_flags_error(flags, target_exists) {
            reply.error(Errno::from_i32(code));
            return;
        }

        match self.entries.get(&newparent) {
            Some(entry) if matches!(entry.kind, EntryKind::Dir) => {}
            Some(_) => {
                reply.error(Errno::ENOTDIR);
                return;
            }
            None => {
                reply.error(Errno::ENOENT);
                return;
            }
        }

        if matches!(source.kind, EntryKind::Dir) && self.is_descendant_of(newparent, source.ino) {
            reply.error(Errno::EINVAL);
            return;
        }

        if let Some(existing) = self.find_child(crypto, newparent, newname).cloned()
            && existing.ino != source.ino
        {
            match (
                matches!(source.kind, EntryKind::Dir),
                matches!(existing.kind, EntryKind::Dir),
            ) {
                (true, true) => {
                    if self.has_children(existing.ino) {
                        reply.error(Errno::ENOTEMPTY);
                        return;
                    }
                }
                (true, false) => {
                    reply.error(Errno::ENOTDIR);
                    return;
                }
                (false, true) => {
                    reply.error(Errno::EISDIR);
                    return;
                }
                (false, false) => {}
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
                reply.error(Errno::EIO);
                return;
            }
        };

        self.relink(source.ino, newparent, name_hash, name_encrypted);

        if let Err(e) = self.save_index(crypto) {
            error!("index save error: {}", e);
            reply.error(Errno::EIO);
            return;
        }
        reply.ok();
    }

    pub(crate) fn open(&self, ino: u64, reply: ReplyOpen) {
        if self.entries.contains_key(&ino) {
            reply.opened(FileHandle(0), FopenFlags::empty());
        } else {
            reply.error(Errno::ENOENT);
        }
    }

    pub(crate) fn release(reply: ReplyEmpty) {
        reply.ok();
    }

    /// Update the metadata after a write has completed on disk.
    pub(crate) fn commit_write(
        &mut self,
        ino: u64,
        content_key_enc: Vec<u8>,
        size: u64,
        reply: ReplyWrite,
        written: u32,
    ) {
        let updated = if let Some(e) = self.entries.get_mut(&ino) {
            e.content_key = content_key_enc;
            e.size = size;
            e.times.touch_modified();
            true
        } else {
            // Entry was removed while the write was in flight. The data file
            // is already on disk; report success because the write completed.
            warn!(
                "inode {} removed during write; orphan data file may remain",
                ino
            );
            false
        };

        if updated {
            self.mark_dirty();
        }
        reply.written(written);
    }
}

const DOT_ENTRIES: u64 = 2;

fn rename_flags_error(flags: u32, target_exists: bool) -> Option<i32> {
    if flags & !libc::RENAME_NOREPLACE != 0 {
        return Some(EINVAL);
    }
    if flags & libc::RENAME_NOREPLACE != 0 && target_exists {
        return Some(EEXIST);
    }
    None
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
                link_target: Vec::new(),
            });
            let data_path = inner.data_path(ino);
            let inner = Arc::new(RwLock::new(inner));
            let lock = Arc::new(RwLock::new(()));

            let handles: Vec<_> = [(0u64, b'A'), (4096u64, b'B')]
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

    fn named_file(inner: &mut PqfsInner, crypto: &Crypto, name: &str) -> u64 {
        let ino = inner.allocate_ino();
        inner.insert_entry(Entry {
            ino,
            parent: ROOT_INO,
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
        ino
    }

    fn readdir_page(
        inner: &PqfsInner,
        crypto: &Crypto,
        offset: u64,
        limit: usize,
    ) -> Vec<(u64, String)> {
        let mut out = Vec::new();
        inner
            .readdir_page(crypto, ROOT_INO, offset, |_, cookie, _, name| {
                if out.len() == limit {
                    return true;
                }
                out.push((cookie, name.to_string()));
                false
            })
            .unwrap();
        out
    }

    fn names(page: &[(u64, String)]) -> Vec<&str> {
        page.iter().map(|(_, name)| name.as_str()).collect()
    }

    #[test]
    fn readdir_resumes_after_entries_are_removed() {
        let dir = tempfile::tempdir().unwrap();
        let crypto = Crypto::init_for_tests("pw", dir.path()).unwrap();
        let mut inner = PqfsInner::load(dir.path().to_path_buf(), &crypto).unwrap();
        let inodes: Vec<u64> = ["a", "b", "c", "d", "e"]
            .iter()
            .map(|name| named_file(&mut inner, &crypto, name))
            .collect();

        let first = readdir_page(&inner, &crypto, 0, 3);
        assert_eq!(names(&first), [".", "..", "a"]);

        inner.remove_entry(inodes[0]);
        inner.remove_entry(inodes[1]);
        let rest = readdir_page(&inner, &crypto, first.last().unwrap().0, 100);
        assert_eq!(names(&rest), ["c", "d", "e"]);
    }

    #[test]
    fn readdir_pages_list_every_entry_once() {
        let dir = tempfile::tempdir().unwrap();
        let crypto = Crypto::init_for_tests("pw", dir.path()).unwrap();
        let mut inner = PqfsInner::load(dir.path().to_path_buf(), &crypto).unwrap();
        for name in ["a", "b", "c"] {
            named_file(&mut inner, &crypto, name);
        }

        let mut listed = Vec::new();
        let mut offset = 0;
        loop {
            let page = readdir_page(&inner, &crypto, offset, 1);
            let Some((cookie, _)) = page.last() else {
                break;
            };
            offset = *cookie;
            listed.extend(page);
        }
        assert_eq!(names(&listed), [".", "..", "a", "b", "c"]);
    }

    #[test]
    fn rename_flags_are_honoured() {
        assert_eq!(rename_flags_error(0, true), None);
        assert_eq!(rename_flags_error(libc::RENAME_NOREPLACE, false), None);
        assert_eq!(
            rename_flags_error(libc::RENAME_NOREPLACE, true),
            Some(EEXIST)
        );
        assert_eq!(
            rename_flags_error(libc::RENAME_EXCHANGE, false),
            Some(EINVAL)
        );
        assert_eq!(
            rename_flags_error(libc::RENAME_WHITEOUT, false),
            Some(EINVAL)
        );
    }

    #[test]
    fn root_is_not_listed_as_its_own_child() {
        let dir = tempfile::tempdir().unwrap();
        let crypto = Crypto::init_for_tests("pw", dir.path()).unwrap();
        let inner = PqfsInner::load(dir.path().to_path_buf(), &crypto).unwrap();

        let root = inner.entries.get(&ROOT_INO).unwrap();
        assert_eq!(root.parent, ROOT_INO);

        let children: Vec<_> = inner
            .entries
            .values()
            .filter(|e| e.parent == ROOT_INO && e.ino != ROOT_INO)
            .collect();
        assert!(children.is_empty());
    }
}

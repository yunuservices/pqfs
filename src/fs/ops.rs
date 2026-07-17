use std::ffi::OsStr;
use std::fs;
use std::io;

use fuser::{
    FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyWrite, Request,
};
use libc::{EEXIST, EIO, EISDIR, ENOENT, ENOTDIR, ENOTEMPTY};
use tracing::{error, warn};

use super::TTL;
use super::entry::{Entry, EntryKind};
use super::inner::PqfsInner;

impl PqfsInner {
    pub(crate) fn lookup(&mut self, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if let Some(entry) = self.find_child(parent, name).cloned() {
            reply.entry(&TTL, &self.attr_for(&entry), 0);
        } else {
            reply.error(ENOENT);
        }
    }

    pub(crate) fn getattr(&mut self, ino: u64, reply: ReplyAttr) {
        if let Some(entry) = self.entries.get(&ino).cloned() {
            reply.attr(&TTL, &self.attr_for(&entry));
        } else {
            reply.error(ENOENT);
        }
    }

    /// Synchronous counterpart of `Filesystem::read`, callable from worker
    /// threads that do not hold a `fuser::Request` reference.
    pub(crate) fn do_read(&mut self, ino: u64, offset: i64, size: u32, reply: ReplyData) {
        let Some(entry) = self.entries.get(&ino).cloned() else {
            reply.error(ENOENT);
            return;
        };
        if !matches!(entry.kind, EntryKind::File) {
            reply.error(EISDIR);
            return;
        }

        let data_path = self.data_path(ino);
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

        let plaintext = if entry.content_key.is_empty() {
            // Legacy file: content encrypted directly with the master key.
            match self.crypto.decrypt(&ciphertext) {
                Ok(v) => v,
                Err(e) => {
                    error!("decrypt error for inode {}: {}", ino, e);
                    reply.error(EIO);
                    return;
                }
            }
        } else {
            let content_key = match self.crypto.decrypt(&entry.content_key) {
                Ok(v) => {
                    if v.len() != 32 {
                        error!("bad per-file key length for inode {}: {}", ino, v.len());
                        reply.error(EIO);
                        return;
                    }
                    v
                }
                Err(e) => {
                    error!("content key decrypt error for inode {}: {}", ino, e);
                    reply.error(EIO);
                    return;
                }
            };
            match self.crypto.decrypt_with_key(&content_key, &ciphertext) {
                Ok(v) => v,
                Err(e) => {
                    error!("decrypt error for inode {}: {}", ino, e);
                    reply.error(EIO);
                    return;
                }
            }
        };

        let offset = offset as usize;
        let end = plaintext.len().min(offset + size as usize);
        reply.data(&plaintext[offset..end]);
    }

    /// Synchronous counterpart of `Filesystem::write`, callable from worker
    /// threads that do not hold a `fuser::Request` reference.
    pub(crate) fn do_write(&mut self, ino: u64, offset: i64, data: &[u8], reply: ReplyWrite) {
        let mut entry = match self.entries.get(&ino).cloned() {
            Some(e) if matches!(e.kind, EntryKind::File) => e,
            Some(_) => {
                reply.error(EISDIR);
                return;
            }
            None => {
                reply.error(ENOENT);
                return;
            }
        };

        let data_path = self.data_path(ino);
        let mut plaintext = if data_path.exists() {
            match fs::read(&data_path) {
                Ok(ct) => {
                    if entry.content_key.is_empty() {
                        // Legacy file: decrypt with the master key and convert below.
                        match self.crypto.decrypt(&ct) {
                            Ok(pt) => pt,
                            Err(e) => {
                                error!("decrypt error on write for {}: {}", data_path.display(), e);
                                reply.error(EIO);
                                return;
                            }
                        }
                    } else {
                        let content_key = match self.crypto.decrypt(&entry.content_key) {
                            Ok(v) => {
                                if v.len() != 32 {
                                    error!("bad per-file key length for inode {}", ino);
                                    reply.error(EIO);
                                    return;
                                }
                                v
                            }
                            Err(e) => {
                                error!("content key decrypt error for inode {}: {}", ino, e);
                                reply.error(EIO);
                                return;
                            }
                        };
                        match self.crypto.decrypt_with_key(&content_key, &ct) {
                            Ok(pt) => pt,
                            Err(e) => {
                                error!("decrypt error on write for {}: {}", data_path.display(), e);
                                reply.error(EIO);
                                return;
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("read error on write for {}: {}", data_path.display(), e);
                    reply.error(EIO);
                    return;
                }
            }
        } else {
            Vec::new()
        };

        // Ensure this file has its own per-file key.
        if entry.content_key.is_empty() {
            let key = self.crypto.random_key();
            match self.crypto.encrypt(&key) {
                Ok(v) => entry.content_key = v,
                Err(e) => {
                    error!("content key encrypt error for inode {}: {}", ino, e);
                    reply.error(EIO);
                    return;
                }
            }
            if let Some(e) = self.entries.get_mut(&ino) {
                e.content_key = entry.content_key.clone();
            }
        }

        let content_key = match self.crypto.decrypt(&entry.content_key) {
            Ok(v) => {
                if v.len() != 32 {
                    error!("bad per-file key length for inode {}", ino);
                    reply.error(EIO);
                    return;
                }
                v
            }
            Err(e) => {
                error!("content key decrypt error for inode {}: {}", ino, e);
                reply.error(EIO);
                return;
            }
        };

        let offset = offset as usize;
        if offset > plaintext.len() {
            plaintext.resize(offset, 0);
        }
        let end = offset + data.len();
        if end > plaintext.len() {
            plaintext.resize(end, 0);
        }
        plaintext[offset..end].copy_from_slice(data);

        let ciphertext = match self.crypto.encrypt_with_key(&content_key, &plaintext) {
            Ok(v) => v,
            Err(e) => {
                error!("encrypt error for {}: {}", data_path.display(), e);
                reply.error(EIO);
                return;
            }
        };

        if let Err(e) = fs::write(&data_path, ciphertext) {
            error!("write error for {}: {}", data_path.display(), e);
            reply.error(EIO);
            return;
        }

        if let Some(e) = self.entries.get_mut(&ino) {
            e.size = plaintext.len() as u64;
        }
        if let Err(e) = self.save_index() {
            error!("index save error: {}", e);
            reply.error(EIO);
            return;
        }

        reply.written(data.len() as u32);
    }

    pub(crate) fn readdir(&mut self, ino: u64, offset: i64, mut reply: ReplyDirectory) {
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
        let crypto = &self.crypto;
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

    pub(crate) fn create(&mut self, parent: u64, name: &OsStr, mode: u32, reply: ReplyCreate) {
        if self.find_child(parent, name).is_some() {
            reply.error(EEXIST);
            return;
        }

        let ino = self.allocate_ino();
        let name = name.to_string_lossy().to_string();
        let name_hash = self.crypto.hash_filename(&name);
        let name_encrypted = match self.crypto.encrypt_filename(&name) {
            Ok(v) => v,
            Err(e) => {
                error!("filename encryption error: {}", e);
                reply.error(EIO);
                return;
            }
        };
        let content_key = match self.crypto.encrypt(&self.crypto.random_key()) {
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
        if let Err(e) = self.save_index() {
            error!("index save error: {}", e);
            reply.error(EIO);
            return;
        }

        reply.created(&TTL, &self.attr_for(&entry), 0, 0, 0);
    }

    pub(crate) fn mkdir(&mut self, parent: u64, name: &OsStr, mode: u32, reply: ReplyEntry) {
        if self.find_child(parent, name).is_some() {
            reply.error(EEXIST);
            return;
        }

        let ino = self.allocate_ino();
        let name = name.to_string_lossy().to_string();
        let name_hash = self.crypto.hash_filename(&name);
        let name_encrypted = match self.crypto.encrypt_filename(&name) {
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
        if let Err(e) = self.save_index() {
            error!("index save error: {}", e);
            reply.error(EIO);
            return;
        }

        reply.entry(&TTL, &self.attr_for(&entry), 0);
    }

    pub(crate) fn unlink(&mut self, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(entry) = self.find_child(parent, name).cloned() else {
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
        if let Err(e) = self.save_index() {
            error!("index save error: {}", e);
            reply.error(EIO);
            return;
        }
        reply.ok();
    }

    pub(crate) fn rmdir(&mut self, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(entry) = self.find_child(parent, name).cloned() else {
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
        if let Err(e) = self.save_index() {
            error!("index save error: {}", e);
            reply.error(EIO);
            return;
        }
        reply.ok();
    }

    pub(crate) fn open(&mut self, ino: u64, reply: ReplyOpen) {
        if self.entries.contains_key(&ino) {
            reply.opened(0, 0);
        } else {
            reply.error(ENOENT);
        }
    }

    pub(crate) fn release(&mut self, reply: ReplyEmpty) {
        reply.ok();
    }
}

impl Filesystem for PqfsInner {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        self.lookup(parent, name, reply);
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        self.getattr(ino, reply);
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        self.do_read(ino, offset, size, reply);
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        self.do_write(ino, offset, data, reply);
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        reply: ReplyDirectory,
    ) {
        self.readdir(ino, offset, reply);
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        self.create(parent, name, mode, reply);
    }

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        self.mkdir(parent, name, mode, reply);
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        self.unlink(parent, name, reply);
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        self.rmdir(parent, name, reply);
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        self.open(ino, reply);
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.release(reply);
    }
}

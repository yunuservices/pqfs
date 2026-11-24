use std::collections::HashMap;
use std::ffi::CString;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock, mpsc};
use std::thread::{self, JoinHandle};

use anyhow::{Context, Result, bail};
use fuser::{
    BsdFileFlags, Config, Errno, FileHandle, Filesystem, INodeNo, LockOwner, MountOption,
    OpenFlags, Owner, RenameFlags, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request, SessionACL, TimeOrNow, WriteFlags,
};
use std::time::SystemTime;
use tracing::{debug, error};

use super::MAX_NAME_LEN;
use super::blocks;
use super::entry::EntryKind;
use super::inner::PqfsInner;
use crate::cli::MountArgs;
use crate::crypto::Crypto;

/// Thread-pool wrapper around `PqfsInner`. `Crypto` is shared via an `Arc`, and
/// the metadata lock is held only for short metadata operations. I/O and
/// crypto work for read/write is offloaded to worker threads so multiple I/O
/// requests can run concurrently.
pub struct Pqfs {
    inner: Arc<RwLock<PqfsInner>>,
    crypto: Arc<Crypto>,
    job_tx: Option<mpsc::Sender<Box<dyn FnOnce() + Send>>>,
    inode_locks: Arc<Mutex<HashMap<u64, Arc<RwLock<()>>>>>,
    workers: Vec<JoinHandle<()>>,
}

impl Pqfs {
    fn new(inner: PqfsInner, crypto: Arc<Crypto>) -> Self {
        let inner = Arc::new(RwLock::new(inner));
        let (tx, rx) = mpsc::channel::<Box<dyn FnOnce() + Send>>();
        let rx = Arc::new(Mutex::new(rx));

        let thread_count = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2)
            .max(2);
        let mut workers = Vec::with_capacity(thread_count);
        for _ in 0..thread_count {
            let rx = Arc::clone(&rx);
            workers.push(thread::spawn(move || {
                loop {
                    let job = {
                        let rx = rx.lock().unwrap_or_else(|e| e.into_inner());
                        rx.recv()
                    };
                    match job {
                        Ok(job) => job(),
                        Err(_) => break,
                    }
                }
            }));
        }

        Self {
            inner,
            crypto,
            job_tx: Some(tx),
            inode_locks: Arc::new(Mutex::new(HashMap::new())),
            workers,
        }
    }

    pub fn mount(args: MountArgs) -> Result<()> {
        let header_exists = args.backend.join("pqfs.header").exists();
        let identity = args.credential.identity_file()?;
        let crypto = if header_exists {
            Crypto::unlock(&args.backend, args.credential.unlock(&identity)?)?
        } else if args.init {
            Crypto::init(args.credential.require_password()?, &args.backend)?
        } else {
            bail!(
                "no volume found at {}; use --init to create one",
                args.backend.display()
            );
        };
        let crypto = Arc::new(crypto);

        let inner = PqfsInner::load(args.backend.clone(), &crypto)?;
        let fs = Self::new(inner, Arc::clone(&crypto));

        debug!("pqfs mounted at {}", args.mountpoint.display());
        fuser::mount(fs, &args.mountpoint, &mount_config(&args.options))
            .with_context(|| format!("failed to mount at {}", args.mountpoint.display()))?;
        Ok(())
    }

    fn read_inner(&self) -> std::sync::RwLockReadGuard<'_, PqfsInner> {
        self.inner.read().unwrap_or_else(|e| e.into_inner())
    }

    fn write_inner(&self) -> std::sync::RwLockWriteGuard<'_, PqfsInner> {
        self.inner.write().unwrap_or_else(|e| e.into_inner())
    }

    fn inode_lock(&self, ino: u64) -> Arc<RwLock<()>> {
        let mut locks = self.inode_locks.lock().unwrap_or_else(|e| e.into_inner());
        Arc::clone(locks.entry(ino).or_default())
    }

    fn spawn_job<F>(&self, job: F)
    where
        F: FnOnce() + Send + 'static,
    {
        if let Some(tx) = &self.job_tx {
            let _ = tx.send(Box::new(job));
        }
    }
}

impl Drop for Pqfs {
    fn drop(&mut self) {
        if let Err(e) = self
            .inner
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .flush_index(self.crypto.as_ref())
        {
            error!("failed to flush the index on unmount: {}", e);
        }

        // Close the job queue so workers exit after draining pending jobs.
        self.job_tx = None;
        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }
    }
}

impl Filesystem for Pqfs {
    fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let parent = parent.0;
        let crypto = self.crypto.as_ref();
        self.read_inner().lookup(crypto, parent, name, reply);
    }

    fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        let ino = ino.0;
        let crypto = self.crypto.as_ref();
        self.read_inner().getattr(crypto, ino, reply);
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let ino = ino.0;
        let inner = Arc::clone(&self.inner);
        let crypto = Arc::clone(&self.crypto);
        let lock = self.inode_lock(ino);

        let (kind, data_path) = {
            let inner = self.read_inner();
            let kind = inner.entries.get(&ino).map(|e| e.kind.clone());
            let data_path = inner.data_path(ino);
            (kind, data_path)
        };

        match kind {
            Some(EntryKind::File) => {
                self.spawn_job(move || {
                    let _guard = lock.read().unwrap_or_else(|e| e.into_inner());

                    let entry = {
                        let inner = inner.read().unwrap_or_else(|e| e.into_inner());
                        match inner.entries.get(&ino) {
                            Some(entry) => entry.clone(),
                            None => {
                                reply.error(Errno::ENOENT);
                                return;
                            }
                        }
                    };

                    PqfsInner::do_read(crypto.as_ref(), &entry, data_path, offset, size, reply);
                });
            }
            Some(_) => reply.error(Errno::EISDIR),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let ino = ino.0;
        let data = data.to_vec();
        let inner = Arc::clone(&self.inner);
        let crypto = Arc::clone(&self.crypto);
        let lock = self.inode_lock(ino);

        let (kind, data_path) = {
            let inner = self.read_inner();
            let kind = inner.entries.get(&ino).map(|e| e.kind.clone());
            let data_path = inner.data_path(ino);
            (kind, data_path)
        };

        match kind {
            Some(EntryKind::File) => {
                self.spawn_job(move || {
                    let _guard = lock.write().unwrap_or_else(|e| e.into_inner());

                    let entry = {
                        let inner = inner.read().unwrap_or_else(|e| e.into_inner());
                        match inner.entries.get(&ino) {
                            Some(entry) => entry.clone(),
                            None => {
                                reply.error(Errno::ENOENT);
                                return;
                            }
                        }
                    };

                    let (content_key_enc, size) = match PqfsInner::do_write_data(
                        crypto.as_ref(),
                        &entry,
                        data_path,
                        offset,
                        &data,
                    ) {
                        Ok(v) => v,
                        Err(code) => {
                            reply.error(Errno::from_i32(code));
                            return;
                        }
                    };
                    let written = data.len() as u32;
                    let mut inner = inner.write().unwrap_or_else(|e| e.into_inner());
                    inner.commit_write(ino, content_key_enc, size, reply, written);
                });
            }
            Some(EntryKind::Dir) => reply.error(Errno::EISDIR),
            Some(EntryKind::Symlink) => reply.error(Errno::EINVAL),
            None => reply.error(Errno::ENOENT),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &self,
        _req: &Request,
        ino: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        _kill_suid_gid: bool,
        reply: ReplyAttr,
    ) {
        let ino = ino.0;
        let inner = Arc::clone(&self.inner);
        let crypto = Arc::clone(&self.crypto);
        let lock = self.inode_lock(ino);

        let (entry, data_path) = {
            let guard = self.read_inner();
            (guard.entries.get(&ino).cloned(), guard.data_path(ino))
        };

        let Some(entry) = entry else {
            reply.error(Errno::ENOENT);
            return;
        };

        let Some(size) = size else {
            self.write_inner().apply_setattr(
                crypto.as_ref(),
                ino,
                mode,
                uid,
                gid,
                atime,
                mtime,
                None,
                reply,
            );
            return;
        };

        if !matches!(entry.kind, EntryKind::File) {
            reply.error(Errno::EISDIR);
            return;
        }

        self.spawn_job(move || {
            let _guard = lock.write().unwrap_or_else(|e| e.into_inner());

            let entry = {
                let guard = inner.read().unwrap_or_else(|e| e.into_inner());
                match guard.entries.get(&ino) {
                    Some(entry) => entry.clone(),
                    None => {
                        reply.error(Errno::ENOENT);
                        return;
                    }
                }
            };

            let truncated = match PqfsInner::do_truncate(crypto.as_ref(), &entry, data_path, size) {
                Ok(v) => v,
                Err(code) => {
                    reply.error(Errno::from_i32(code));
                    return;
                }
            };

            let mut guard = inner.write().unwrap_or_else(|e| e.into_inner());
            guard.apply_setattr(
                crypto.as_ref(),
                ino,
                mode,
                uid,
                gid,
                atime,
                mtime,
                Some(truncated),
                reply,
            );
        });
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        _owner: Option<Owner>,
        reply: ReplyEmpty,
    ) {
        let crypto = Arc::clone(&self.crypto);
        self.write_inner().rename(
            crypto.as_ref(),
            parent.0,
            name,
            newparent.0,
            newname,
            flags.bits(),
            reply,
        );
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        reply: ReplyDirectory,
    ) {
        let ino = ino.0;
        let crypto = self.crypto.as_ref();
        self.read_inner().readdir(crypto, ino, offset, reply);
    }

    fn create(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        _kill_suid_gid: bool,
        _owner: Owner,
        reply: ReplyCreate,
    ) {
        let parent = parent.0;
        let crypto = self.crypto.as_ref();
        self.write_inner().create(crypto, parent, name, mode, reply);
    }

    fn mkdir(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _owner: Owner,
        reply: ReplyEntry,
    ) {
        let parent = parent.0;
        let crypto = self.crypto.as_ref();
        self.write_inner().mkdir(crypto, parent, name, mode, reply);
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let parent = parent.0;
        let crypto = self.crypto.as_ref();
        self.write_inner().unlink(crypto, parent, name, reply);
    }

    fn rmdir(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let parent = parent.0;
        let crypto = self.crypto.as_ref();
        self.write_inner().rmdir(crypto, parent, name, reply);
    }

    fn open(
        &self,
        _req: &Request,
        ino: INodeNo,
        _flags: OpenFlags,
        _kill_suid_gid: bool,
        reply: ReplyOpen,
    ) {
        let ino = ino.0;
        self.read_inner().open(ino, reply);
    }

    fn symlink(
        &self,
        _req: &Request,
        parent: INodeNo,
        link_name: &OsStr,
        target: &Path,
        _owner: Owner,
        reply: ReplyEntry,
    ) {
        let parent = parent.0;
        let crypto = Arc::clone(&self.crypto);
        self.write_inner()
            .symlink(crypto.as_ref(), parent, link_name, target, reply);
    }

    fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
        let ino = ino.0;
        let crypto = Arc::clone(&self.crypto);
        self.read_inner().readlink(crypto.as_ref(), ino, reply);
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        let inner = self.read_inner();
        let stats = match backing_store_stats(&inner.backend) {
            Ok(stats) => stats,
            Err(e) => {
                error!("statfs error: {}", e);
                reply.error(Errno::EIO);
                return;
            }
        };
        reply.statfs(
            stats.blocks,
            stats.blocks_free,
            stats.blocks_available,
            inner.entries.len() as u64 + stats.files_free,
            stats.files_free,
            stats.block_size,
            u32::from(MAX_NAME_LEN),
            stats.fragment_size,
        );
    }

    fn fsync(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        let ino = ino.0;
        let crypto = Arc::clone(&self.crypto);
        let lock = self.inode_lock(ino);
        let _guard = lock.read().unwrap_or_else(|e| e.into_inner());

        let mut inner = self.write_inner();
        if let Err(e) = blocks::sync(&inner.data_path(ino)) {
            error!("fsync error for inode {}: {}", ino, e);
            reply.error(Errno::EIO);
            return;
        }
        if let Err(e) = inner.flush_index(crypto.as_ref()) {
            error!("index save error: {}", e);
            reply.error(Errno::EIO);
            return;
        }
        reply.ok();
    }

    fn fsyncdir(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        let crypto = Arc::clone(&self.crypto);
        if let Err(e) = self.write_inner().flush_index(crypto.as_ref()) {
            error!("index save error: {}", e);
            reply.error(Errno::EIO);
            return;
        }
        reply.ok();
    }

    fn flush(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        let ino = ino.0;
        let crypto = Arc::clone(&self.crypto);
        let lock = self.inode_lock(ino);
        let _guard = lock.read().unwrap_or_else(|e| e.into_inner());

        let mut inner = self.write_inner();
        if let Err(e) = blocks::sync(&inner.data_path(ino)) {
            error!("flush error for inode {}: {}", ino, e);
            reply.error(Errno::EIO);
            return;
        }
        if let Err(e) = inner.flush_index(crypto.as_ref()) {
            error!("index save error: {}", e);
            reply.error(Errno::EIO);
            return;
        }
        reply.ok();
    }

    fn release(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        PqfsInner::release(reply);
    }
}

fn mount_config(options: &[String]) -> Config {
    let mut config = Config::default();
    config.mount_options = vec![
        MountOption::FSName("pqfs".to_string()),
        MountOption::Subtype("pqfs".to_string()),
        MountOption::NoAtime,
    ];

    if options.iter().any(|o| o == "ro") {
        config.mount_options.push(MountOption::RO);
    } else {
        config.mount_options.push(MountOption::RW);
    }

    for opt in options {
        match opt.as_str() {
            "ro" | "rw" => {}
            "allow_other" => config.acl = SessionACL::All,
            "allow_root" => config.acl = SessionACL::RootAndOwner,
            _ => config.mount_options.push(MountOption::CUSTOM(opt.clone())),
        }
    }
    config
}

struct BackingStoreStats {
    blocks: u64,
    blocks_free: u64,
    blocks_available: u64,
    files_free: u64,
    block_size: u32,
    fragment_size: u32,
}

fn backing_store_stats(backend: &Path) -> std::io::Result<BackingStoreStats> {
    let path = CString::new(backend.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("backend path contains a nul byte"))?;

    let mut raw = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(path.as_ptr(), raw.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let raw = unsafe { raw.assume_init() };

    Ok(BackingStoreStats {
        blocks: raw.f_blocks,
        blocks_free: raw.f_bfree,
        blocks_available: raw.f_bavail,
        files_free: raw.f_ffree,
        block_size: raw.f_bsize as u32,
        fragment_size: raw.f_frsize as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(list: &[&str]) -> Vec<String> {
        list.iter().map(|o| o.to_string()).collect()
    }

    #[test]
    fn allow_other_and_allow_root_set_the_session_acl() {
        assert_eq!(mount_config(&[]).acl, SessionACL::Owner);
        assert_eq!(
            mount_config(&options(&["allow_other"])).acl,
            SessionACL::All
        );
        assert_eq!(
            mount_config(&options(&["allow_root"])).acl,
            SessionACL::RootAndOwner
        );
    }

    #[test]
    fn acl_options_are_not_passed_through_as_custom_options() {
        let config = mount_config(&options(&["allow_other", "allow_root", "ro", "fsname=x"]));
        let custom: Vec<_> = config
            .mount_options
            .iter()
            .filter_map(|o| match o {
                MountOption::CUSTOM(value) => Some(value.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(custom, ["fsname=x"]);
        assert!(config.mount_options.contains(&MountOption::RO));
        assert!(!config.mount_options.contains(&MountOption::RW));
    }
}

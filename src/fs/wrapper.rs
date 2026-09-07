use std::collections::HashMap;
use std::ffi::OsStr;
use std::sync::{Arc, Mutex, RwLock, mpsc};
use std::thread::{self, JoinHandle};

use anyhow::{Context, Result, bail};
use fuser::{
    Filesystem, MountOption, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow,
};
use libc::{EIO, EISDIR, ENOENT};
use std::time::SystemTime;
use tracing::{debug, error};

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

        let mut mount_options = vec![
            MountOption::FSName("pqfs".to_string()),
            MountOption::Subtype("pqfs".to_string()),
            MountOption::NoAtime,
        ];

        if args.options.iter().any(|o| o == "ro") {
            mount_options.push(MountOption::RO);
        } else {
            mount_options.push(MountOption::RW);
        }

        for opt in &args.options {
            if opt == "ro" || opt == "rw" {
                continue;
            }
            mount_options.push(MountOption::CUSTOM(opt.clone()));
        }

        debug!("pqfs mounted at {}", args.mountpoint.display());
        fuser::mount2(fs, &args.mountpoint, &mount_options)
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
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let crypto = self.crypto.as_ref();
        self.read_inner().lookup(crypto, parent, name, reply);
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        let crypto = self.crypto.as_ref();
        self.read_inner().getattr(crypto, ino, reply);
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
        let crypto = Arc::clone(&self.crypto);
        let lock = self.inode_lock(ino);

        let (entry, data_path) = {
            let inner = self.read_inner();
            let entry = inner.entries.get(&ino).cloned();
            let data_path = inner.data_path(ino);
            (entry, data_path)
        };

        match entry {
            Some(entry) if matches!(entry.kind, EntryKind::File) => {
                self.spawn_job(move || {
                    let _guard = lock.read().unwrap_or_else(|e| e.into_inner());
                    PqfsInner::do_read(crypto.as_ref(), &entry, data_path, offset, size, reply);
                });
            }
            Some(_) => reply.error(EISDIR),
            None => reply.error(ENOENT),
        }
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
                                reply.error(ENOENT);
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
                            reply.error(code);
                            return;
                        }
                    };
                    let written = data.len() as u32;
                    let mut inner = inner.write().unwrap_or_else(|e| e.into_inner());
                    inner.commit_write(ino, content_key_enc, size, reply, written);
                });
            }
            Some(EntryKind::Dir) => reply.error(EISDIR),
            None => reply.error(ENOENT),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let inner = Arc::clone(&self.inner);
        let crypto = Arc::clone(&self.crypto);
        let lock = self.inode_lock(ino);

        let (entry, data_path) = {
            let guard = self.read_inner();
            (guard.entries.get(&ino).cloned(), guard.data_path(ino))
        };

        let Some(entry) = entry else {
            reply.error(ENOENT);
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
            reply.error(EISDIR);
            return;
        }

        self.spawn_job(move || {
            let _guard = lock.write().unwrap_or_else(|e| e.into_inner());

            let entry = {
                let guard = inner.read().unwrap_or_else(|e| e.into_inner());
                match guard.entries.get(&ino) {
                    Some(entry) => entry.clone(),
                    None => {
                        reply.error(ENOENT);
                        return;
                    }
                }
            };

            let truncated = match PqfsInner::do_truncate(crypto.as_ref(), &entry, data_path, size) {
                Ok(v) => v,
                Err(code) => {
                    reply.error(code);
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
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let crypto = Arc::clone(&self.crypto);
        self.write_inner()
            .rename(crypto.as_ref(), parent, name, newparent, newname, reply);
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        reply: ReplyDirectory,
    ) {
        let crypto = self.crypto.as_ref();
        self.read_inner().readdir(crypto, ino, offset, reply);
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
        let crypto = self.crypto.as_ref();
        self.write_inner().create(crypto, parent, name, mode, reply);
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
        let crypto = self.crypto.as_ref();
        self.write_inner().mkdir(crypto, parent, name, mode, reply);
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let crypto = self.crypto.as_ref();
        self.write_inner().unlink(crypto, parent, name, reply);
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let crypto = self.crypto.as_ref();
        self.write_inner().rmdir(crypto, parent, name, reply);
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        self.read_inner().open(ino, reply);
    }

    fn fsync(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        let crypto = Arc::clone(&self.crypto);
        let lock = self.inode_lock(ino);
        let _guard = lock.read().unwrap_or_else(|e| e.into_inner());

        let mut inner = self.write_inner();
        if let Err(e) = blocks::sync(&inner.data_path(ino)) {
            error!("fsync error for inode {}: {}", ino, e);
            reply.error(EIO);
            return;
        }
        if let Err(e) = inner.flush_index(crypto.as_ref()) {
            error!("index save error: {}", e);
            reply.error(EIO);
            return;
        }
        reply.ok();
    }

    fn fsyncdir(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        let crypto = Arc::clone(&self.crypto);
        if let Err(e) = self.write_inner().flush_index(crypto.as_ref()) {
            error!("index save error: {}", e);
            reply.error(EIO);
            return;
        }
        reply.ok();
    }

    fn flush(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        _lock_owner: u64,
        reply: ReplyEmpty,
    ) {
        let crypto = Arc::clone(&self.crypto);
        let lock = self.inode_lock(ino);
        let _guard = lock.read().unwrap_or_else(|e| e.into_inner());

        let mut inner = self.write_inner();
        if let Err(e) = blocks::sync(&inner.data_path(ino)) {
            error!("flush error for inode {}: {}", ino, e);
            reply.error(EIO);
            return;
        }
        if let Err(e) = inner.flush_index(crypto.as_ref()) {
            error!("index save error: {}", e);
            reply.error(EIO);
            return;
        }
        reply.ok();
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
        PqfsInner::release(reply);
    }
}

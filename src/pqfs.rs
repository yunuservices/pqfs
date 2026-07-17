use std::ffi::OsStr;
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};

use anyhow::{Context, Result};
use fuser::{
    Filesystem, MountOption, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyWrite, Request,
};
use tracing::debug;

use crate::cli::Args;
use crate::crypto::Crypto;
use crate::fs::PqfsInner;

/// Thread-pool wrapper around `PqfsInner`. Metadata operations are handled
/// synchronously; read/write work is offloaded to worker threads so the FUSE
/// dispatch loop does not block on I/O or crypto.
pub struct Pqfs {
    inner: Arc<Mutex<PqfsInner>>,
    job_tx: Option<mpsc::Sender<Box<dyn FnOnce() + Send>>>,
    workers: Vec<JoinHandle<()>>,
}

impl Pqfs {
    fn new(inner: PqfsInner) -> Self {
        let inner = Arc::new(Mutex::new(inner));
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
            job_tx: Some(tx),
            workers,
        }
    }

    pub fn mount(args: Args) -> Result<()> {
        let crypto = if args.backend.join("pqfs.header").exists() {
            Crypto::load(&args.password, &args.backend)?
        } else {
            Crypto::init(&args.password, &args.backend)?
        };

        let inner = PqfsInner::load(args.backend.clone(), crypto)?;
        let fs = Self::new(inner);

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

    fn lock_inner(&self) -> std::sync::MutexGuard<PqfsInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn spawn_job<F>(&self, job: F)
    where
        F: FnOnce(&mut PqfsInner) + Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        let boxed: Box<dyn FnOnce() + Send> = Box::new(move || {
            let mut guard = inner.lock().unwrap_or_else(|e| e.into_inner());
            job(&mut guard);
        });
        if let Some(tx) = &self.job_tx {
            let _ = tx.send(boxed);
        }
    }
}

impl Drop for Pqfs {
    fn drop(&mut self) {
        // Close the job queue so workers exit after draining pending jobs.
        self.job_tx = None;
        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }
    }
}

impl Filesystem for Pqfs {
    fn lookup(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        <PqfsInner as Filesystem>::lookup(&mut *self.lock_inner(), req, parent, name, reply);
    }

    fn getattr(&mut self, req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        <PqfsInner as Filesystem>::getattr(&mut *self.lock_inner(), req, ino, reply);
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
        self.spawn_job(move |inner| {
            inner.do_read(ino, offset, size, reply);
        });
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
        self.spawn_job(move |inner| {
            inner.do_write(ino, offset, &data, reply);
        });
    }

    fn readdir(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        reply: ReplyDirectory,
    ) {
        <PqfsInner as Filesystem>::readdir(&mut *self.lock_inner(), req, ino, 0, offset, reply);
    }

    fn create(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        <PqfsInner as Filesystem>::create(
            &mut *self.lock_inner(),
            req,
            parent,
            name,
            mode,
            umask,
            flags,
            reply,
        );
    }

    fn mkdir(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        <PqfsInner as Filesystem>::mkdir(
            &mut *self.lock_inner(),
            req,
            parent,
            name,
            mode,
            umask,
            reply,
        );
    }

    fn unlink(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        <PqfsInner as Filesystem>::unlink(&mut *self.lock_inner(), req, parent, name, reply);
    }

    fn rmdir(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        <PqfsInner as Filesystem>::rmdir(&mut *self.lock_inner(), req, parent, name, reply);
    }

    fn open(&mut self, req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        <PqfsInner as Filesystem>::open(&mut *self.lock_inner(), req, ino, flags, reply);
    }

    fn release(
        &mut self,
        req: &Request<'_>,
        ino: u64,
        fh: u64,
        flags: i32,
        lock_owner: Option<u64>,
        flush: bool,
        reply: ReplyEmpty,
    ) {
        <PqfsInner as Filesystem>::release(
            &mut *self.lock_inner(),
            req,
            ino,
            fh,
            flags,
            lock_owner,
            flush,
            reply,
        );
    }
}

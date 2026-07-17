use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use fuser::{
    FUSE_ROOT_ID, FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request,
};
use libc::{EEXIST, EIO, EISDIR, ENOENT, ENOTDIR, ENOTEMPTY};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, warn};

use crate::cli::Args;
use crate::crypto::Crypto;

const INDEX_FILE: &str = "pqfs.index";
const TTL: Duration = Duration::from_secs(1);
const BLOCK_SIZE: u64 = 512;

#[derive(Serialize, Deserialize, Clone, Debug)]
enum EntryKind {
    File,
    Dir,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Entry {
    ino: u64,
    parent: u64,
    name: String,
    kind: EntryKind,
    size: u64,
    perm: u16,
    uid: u32,
    gid: u32,
}

pub struct Pqfs {
    backend: PathBuf,
    crypto: Crypto,
    entries: BTreeMap<u64, Entry>,
    next_ino: u64,
}

impl Pqfs {
    pub fn mount(args: Args) -> Result<()> {
        let crypto = if args.backend.join("pqfs.header").exists() {
            Crypto::load(&args.password, &args.backend)?
        } else {
            Crypto::init(&args.password, &args.backend)?
        };

        let fs = Self::load(args.backend.clone(), crypto)?;

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

    fn load(backend: PathBuf, crypto: Crypto) -> Result<Self> {
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
            map.insert(
                FUSE_ROOT_ID,
                Entry {
                    ino: FUSE_ROOT_ID,
                    parent: FUSE_ROOT_ID,
                    name: "".to_string(),
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

    fn save_index(&mut self) -> Result<()> {
        let plaintext = bincode::serialize(&self.entries)?;
        let ciphertext = self.crypto.encrypt(&plaintext)?;
        let index_path = self.backend.join(INDEX_FILE);
        let tmp = index_path.with_extension("tmp");
        fs::write(&tmp, ciphertext)?;
        fs::rename(&tmp, &index_path)?;
        Ok(())
    }

    fn attr_for(&self, entry: &Entry) -> FileAttr {
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

    fn data_path(&self, ino: u64) -> PathBuf {
        self.backend.join("data").join(format!("{}", ino))
    }

    fn find_child(&self, parent: u64, name: &OsStr) -> Option<&Entry> {
        let name = name.to_string_lossy();
        self.entries
            .values()
            .find(|e| e.parent == parent && e.name == name.as_ref())
    }

    fn allocate_ino(&mut self) -> u64 {
        let ino = self.next_ino;
        self.next_ino += 1;
        ino
    }
}

impl Filesystem for Pqfs {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if let Some(entry) = self.find_child(parent, name).cloned() {
            reply.entry(&TTL, &self.attr_for(&entry), 0);
        } else {
            reply.error(ENOENT);
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        if let Some(entry) = self.entries.get(&ino).cloned() {
            reply.attr(&TTL, &self.attr_for(&entry));
        } else {
            reply.error(ENOENT);
        }
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
        let Some(entry) = self.entries.get(&ino) else {
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

        let plaintext = match self.crypto.decrypt(&ciphertext) {
            Ok(v) => v,
            Err(e) => {
                error!("decrypt error for inode {}: {}", ino, e);
                reply.error(EIO);
                return;
            }
        };

        let offset = offset as usize;
        let end = plaintext.len().min(offset + size as usize);
        reply.data(&plaintext[offset..end]);
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
        let Some(entry) = self.entries.get_mut(&ino) else {
            reply.error(ENOENT);
            return;
        };
        if !matches!(entry.kind, EntryKind::File) {
            reply.error(EISDIR);
            return;
        }

        let data_path = self.data_path(ino);
        let mut plaintext = if data_path.exists() {
            match fs::read(&data_path) {
                Ok(ct) => match self.crypto.decrypt(&ct) {
                    Ok(pt) => pt,
                    Err(e) => {
                        error!("decrypt error on write for {}: {}", data_path.display(), e);
                        reply.error(EIO);
                        return;
                    }
                },
                Err(e) => {
                    error!("read error on write for {}: {}", data_path.display(), e);
                    reply.error(EIO);
                    return;
                }
            }
        } else {
            Vec::new()
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

        let ciphertext = match self.crypto.encrypt(&plaintext) {
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

        entry.size = plaintext.len() as u64;
        if let Err(e) = self.save_index() {
            error!("index save error: {}", e);
            reply.error(EIO);
            return;
        }

        reply.written(data.len() as u32);
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
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
            entries.push((
                child.ino,
                match child.kind {
                    EntryKind::File => FileType::RegularFile,
                    EntryKind::Dir => FileType::Directory,
                },
                child.name.clone(),
            ));
        }

        for (i, (ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(ino, (i + 1) as i64, kind, &name) {
                break;
            }
        }
        reply.ok();
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyCreate,
    ) {
        if self.find_child(parent, name).is_some() {
            reply.error(EEXIST);
            return;
        }

        let ino = self.allocate_ino();
        let name = name.to_string_lossy().to_string();
        let entry = Entry {
            ino,
            parent,
            name,
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

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        if self.find_child(parent, name).is_some() {
            reply.error(EEXIST);
            return;
        }

        let ino = self.allocate_ino();
        let entry = Entry {
            ino,
            parent,
            name: name.to_string_lossy().to_string(),
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

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(entry) = self.find_child(parent, name).cloned() else {
            reply.error(ENOENT);
            return;
        };

        self.entries.remove(&entry.ino);
        let data_path = self.data_path(entry.ino);
        if data_path.exists() {
            if let Err(e) = fs::remove_file(&data_path) {
                warn!("failed to remove data file {}: {}", data_path.display(), e);
            }
        }
        if let Err(e) = self.save_index() {
            error!("index save error: {}", e);
            reply.error(EIO);
            return;
        }
        reply.ok();
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
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

    fn open(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        if self.entries.contains_key(&ino) {
            reply.opened(0, 0);
        } else {
            reply.error(ENOENT);
        }
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
        reply.ok();
    }
}

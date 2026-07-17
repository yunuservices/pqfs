# pqfs

A hybrid post-quantum FUSE filesystem written in Rust.

> [!CAUTION]
> **Research prototype / not audited.** DO NOT use pqfs for real or sensitive
> data. It is intended for learning and experimentation.

`pqfs` mounts a userspace filesystem on top of an encrypted backend directory.
Files, directories, and file names are authenticated and encrypted with
**XChaCha20Poly1305**. The master key is derived from your password and an
**ML-KEM** shared secret (default **ML-KEM-768**), combining classical and
post-quantum protection.

## Why?

“Harvest now, decrypt later” protection: a password + ML-KEM hybrid key makes
stolen ciphertext harder to decrypt with future quantum computers.

## Features

- FUSE userspace filesystem in Rust (`fuser`)
- Hybrid key derivation: Argon2(password) + ML-KEM shared secret
  (ML-KEM-512 / 768 / 1024 selectable at compile time)
- Authenticated encryption for file contents, directory index, and file names
  (XChaCha20Poly1305)
- Per-file content keys wrapped by the master key
- File-name encryption via HMAC-based lookup + XChaCha20Poly1305
- Concurrent reads: metadata is protected by an `RwLock` and long-running I/O
  and crypto work is offloaded to a worker thread pool
- Small, modular codebase suitable for learning and extending
- CLI with hidden password prompt and `PQFS_PASSWORD` environment-variable support
- Custom FUSE mount options via `-o`

## Stack

| Layer | Crate |
|-------|-------|
| FUSE | `fuser` |
| Post-quantum KEM | `ml-kem` |
| AEAD | `chacha20poly1305` |
| Password hashing | `argon2` |
| Key derivation | `hkdf` + `sha2` |
| CLI | `clap` |

## Build

Linux or WSL is required. `fuser` links against libfuse3.

```bash
# Debian/Ubuntu dependencies
sudo apt-get install -y libfuse3-dev pkg-config

# Default: ML-KEM-768
cargo build --release

# Alternative ML-KEM parameter sets
cargo build --release --no-default-features --features ml-kem-512
cargo build --release --no-default-features --features ml-kem-1024
```

## Quick start

```bash
# 1. Create backend and mountpoint directories
mkdir -p ~/pqfs-backend ~/pqfs-mnt

# 2. Create a new volume and mount it
./target/release/pqfs ~/pqfs-backend ~/pqfs-mnt --password "super secret" --init

# In another terminal:
cd ~/pqfs-mnt
echo "hello quantum world" > test.txt
cat test.txt
ls -la

# Unmount
fusermount3 -u ~/pqfs-mnt
```

Mount an existing volume by omitting `--init`:

```bash
./target/release/pqfs ~/pqfs-backend ~/pqfs-mnt --password "super secret"
```

Use the environment variable to avoid leaking the password in shell history:

```bash
PQFS_PASSWORD="super secret" ./target/release/pqfs ~/pqfs-backend ~/pqfs-mnt
```

### Docker quick-start

```bash
# Build image and keep a container running for manual testing
docker compose up -d pqfs

# Create and mount a volume inside the container
docker compose exec pqfs pqfs /data /mnt/pqfs --password smoke-test --init
docker compose exec pqfs pqfs /data /mnt/pqfs --password smoke-test

# Or run the one-shot smoke test (creates, writes, reads, unmounts)
docker compose --profile test run --rm smoke-test
```

### On-disk layout

After initialization, the encrypted backend (`~/pqfs-backend`) contains:

- `pqfs.header` — encrypted ML-KEM seed, public key, ciphertext, and salt
- `pqfs.index` — encrypted directory index
- `data/` — per-inode encrypted file contents

## Threat model

### What pqfs tries to protect against

- **Offline backend theft.** If an attacker steals the backend directory, the
  files, directory index, and file names are encrypted. The ML-KEM secret seed
  is also stored in the backend, but it is encrypted with a key derived from
  the password, so the attacker needs both the backend and the password.
- **Harvest-now-decrypt-later.** The master key combines a classical password
  derivation (Argon2) with an ML-KEM shared secret. Even if a future quantum
  computer breaks the password-derived classical component, recovering the
  key still requires breaking ML-KEM.
- **Accidental metadata leakage.** File names are hashed for lookups and
  encrypted for storage, so plain file names do not appear on disk.

### What pqfs does *not* protect against

- **A compromised running system.** Once the filesystem is mounted, plaintext
  data lives in process memory and is visible to anything with access to the
  mountpoint or the kernel.
- **Weak passwords.** Argon2 slows guessing, but a short or guessable password
  can still be brute-forced.
- **Active attackers on the host.** A malicious kernel module, root user, or
  another process with sufficient privileges can observe or modify data while
  the filesystem is mounted.
- **Rollback / snapshot attacks.** The backend has no versioning or integrity
  log; an attacker with write access can replay an older `pqfs.index` or data
  file.
- **Multi-user access control.** `pqfs` does not implement its own user model;
  access is governed by the UNIX permissions of the FUSE mountpoint.
- **Side channels and Denial of Service.** File sizes, directory structure,
  access timing, and write patterns leak information and are not hidden.

## Architecture

```text
┌─────────────────────────────────────┐
│  FUSE mountpoint (pqfs)             │
│  ls, cat, cp, rm, mkdir, ...        │
└──────────────┬──────────────────────┘
               │ Filesystem trait
┌──────────────▼──────────────────────┐
│  Pqfs (src/fs/wrapper.rs)           │
│  - worker thread pool               │
│  - shared Crypto + RwLock metadata  │
├──────────────┬──────────────────────┤
│  PqfsInner (src/fs/inner.rs)        │
│  - directory index (BTreeMap)       │
│  - per-inode encrypted data files   │
├──────────────┼──────────────────────┤
│  Ops (src/fs/ops.rs)                │
│  Entry (src/fs/entry.rs)            │
└──────────────┬──────────────────────┘
               │ encrypt / decrypt
┌──────────────▼──────────────────────┐
│  Crypto (src/crypto/)               │
│  - volume.rs (init/load)            │
│  - aead.rs (XChaCha20Poly1305)      │
│  - filename.rs (name HMAC/encrypt)  │
│  - keys.rs (Argon2/HKDF)            │
│  - kem.rs (ML-KEM parameter set)    │
└─────────────────────────────────────┘
```

## Roadmap / ideas

- [x] File-name encryption
- [x] Per-file keys instead of one master key
- [x] Async / multi-threaded FUSE
- [ ] Benchmark vs. ext4 / LUKS
- [ ] Switchable AES-256-GCM vs. ChaCha20-Poly1305
- [x] ML-KEM-1024 / ML-KEM-512 parameter option

## License

Distributed under the MIT License. See `LICENSE` for details.

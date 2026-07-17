# pqfs

A hybrid post-quantum FUSE filesystem written in Rust.

> **Research prototype.** Not audited. Do not use for real data.

`pqfs` mounts a user-space filesystem on top of an encrypted backend directory. Every file and the directory index are encrypted with **XChaCha20Poly1305**. The master key is derived from a password and the shared secret of a selected **ML-KEM** parameter-set encapsulation (default **ML-KEM-768**), giving a hybrid classical + post-quantum key establishment.

## Why?

"Harvest now, decrypt later" is a real threat: encrypted data stolen today could be decrypted by future quantum computers. `pqfs` is a small proof-of-concept that experiments with protecting long-lived data using a hybrid key encapsulation mechanism (password + ML-KEM).

## Features

- FUSE userspace filesystem in Rust (`fuser`)
- Hybrid key derivation: Argon2(password) + ML-KEM shared secret (ML-KEM-512 / 768 / 1024 selectable at compile time)
- Authenticated encryption for file contents, directory index, and file names (XChaCha20Poly1305)
- Per-file content keys wrapped by the master key
- File-name encryption via HMAC-based lookup + XChaCha20Poly1305
- Async read/write dispatch to a worker thread pool so the FUSE loop does not block on I/O or crypto
- Small, modular codebase suitable for learning and extending
- CLI with mount options

## Stack

| Layer | Crate |
|-------|-------|
| FUSE | `fuser` |
| Post-quantum KEM | `ml-kem` (ML-KEM-512 / 768 / 1024) |
| AEAD | `chacha20poly1305` |
| Password hashing | `argon2` |
| Key derivation | `hkdf` + `sha2` |
| CLI | `clap` |

## Build

Linux or WSL is required. `fuser` links against libfuse.

```bash
# Debian/Ubuntu dependencies
sudo apt-get install -y libfuse-dev pkg-config

# Default: ML-KEM-768
cargo build --release

# Alternative ML-KEM parameter sets
cargo build --release --no-default-features --features ml-kem-512
cargo build --release --no-default-features --features ml-kem-1024
```

## Usage

```bash
# Create a new encrypted volume and mount it
mkdir -p ~/pqfs-backend ~/pqfs-mnt
./target/release/pqfs ~/pqfs-backend ~/pqfs-mnt --password "super secret" --init

# Mount an existing volume (omit --init to avoid accidental creation)
./target/release/pqfs ~/pqfs-backend ~/pqfs-mnt --password "super secret"

# Or use the environment variable (avoids shell history leakage)
PQFS_PASSWORD="super secret" ./target/release/pqfs ~/pqfs-backend ~/pqfs-mnt
```

# In another terminal
cd ~/pqfs-mnt
echo "hello quantum world" > test.txt
cat test.txt
ls -la

# Unmount
fusermount -u ~/pqfs-mnt
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

The encrypted backend (`~/pqfs-backend`) will contain:

- `pqfs.header` — encrypted ML-KEM seed, public key, ciphertext, and salt
- `pqfs.index` — encrypted directory index
- `data/` — per-inode encrypted file contents

## Security Notes

- This is a **proof of concept** for educational purposes.
- No formal audit has been performed.
- The ML-KEM secret seed is stored in the backend, encrypted with a key derived from your password. An attacker needs both the backend and the password to recover it.
- FUSE userspace filesystems are not as fast as kernel-native encrypted filesystems (e.g., dm-crypt / LUKS).

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
├──────────────┬──────────────────────┤
│  PqfsInner (src/fs/inner.rs)        │
│  - directory index (BTreeMap)     │
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

## Roadmap / Ideas

- [x] File-name encryption
- [x] Per-file keys instead of one master key
- [x] Async / multi-threaded FUSE
- [ ] Benchmark vs. ext4 / LUKS
- [ ] Switchable AES-256-GCM vs. ChaCha20-Poly1305
- [x] ML-KEM-1024 / ML-KEM-512 parameter option

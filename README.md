# pqfs

A hybrid post-quantum FUSE filesystem written in Rust.

> **Research prototype.** Not audited. Do not use for real data.

`pqfs` mounts a user-space filesystem on top of an encrypted backend directory. Every file and the directory index are encrypted with **XChaCha20Poly1305**. The master key is derived from a password and the shared secret of an **ML-KEM-768** encapsulation, giving a hybrid classical + post-quantum key establishment.

## Why?

"Harvest now, decrypt later" is a real threat: encrypted data stolen today could be decrypted by future quantum computers. `pqfs` is a small proof-of-concept that experiments with protecting long-lived data using a hybrid key encapsulation mechanism (password + ML-KEM).

## Features

- FUSE userspace filesystem in Rust (`fuser`)
- Hybrid key derivation: Argon2(password) + ML-KEM-768 shared secret
- Authenticated encryption for file contents, directory index, and file names (XChaCha20Poly1305)
- Small, modular codebase suitable for learning and extending
- CLI with mount options

## Stack

| Layer | Crate |
|-------|-------|
| FUSE | `fuser` |
| Post-quantum KEM | `ml-kem` (ML-KEM-768) |
| AEAD | `chacha20poly1305` |
| Password hashing | `argon2` |
| Key derivation | `hkdf` + `sha2` |
| CLI | `clap` |

## Build

Linux or WSL is required. `fuser` links against libfuse.

```bash
# Debian/Ubuntu dependencies
sudo apt-get install -y libfuse-dev pkg-config

# Build
cargo build --release
```

## Usage

```bash
# Create a new encrypted volume and mount it
mkdir -p ~/pqfs-backend ~/pqfs-mnt
./target/release/pqfs ~/pqfs-backend ~/pqfs-mnt --password "super secret"

# In another terminal
cd ~/pqfs-mnt
echo "hello quantum world" > test.txt
cat test.txt
ls -la

# Unmount
fusermount -u ~/pqfs-mnt
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
│  Pqfs (src/fs.rs)                   │
│  - directory index (BTreeMap)       │
│  - per-inode encrypted data files   │
└──────────────┬──────────────────────┘
               │ encrypt / decrypt
┌──────────────▼──────────────────────┐
│  Crypto (src/crypto.rs)             │
│  - Argon2(password)                 │
│  - ML-KEM-768 hybrid KEM            │
│  - XChaCha20Poly1305                │
└─────────────────────────────────────┘
```

## Roadmap / Ideas

- [x] File-name encryption
- [ ] Per-file keys instead of one master key
- [ ] Async / multi-threaded FUSE
- [ ] Benchmark vs. ext4 / LUKS
- [ ] Switchable AES-256-GCM vs. ChaCha20-Poly1305
- [ ] ML-KEM-1024 / ML-KEM-512 parameter option

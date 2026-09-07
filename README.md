# pqfs

A hybrid post-quantum FUSE filesystem written in Rust.

> [!CAUTION]
> **Research prototype / not audited.** DO NOT use pqfs for real or sensitive
> data. It is intended for learning and experimentation.

`pqfs` mounts a userspace filesystem on top of an encrypted backend directory.
Files, directories, and file names are authenticated and encrypted with
**XChaCha20Poly1305** under a random master key. That master key never leaves
the volume in the clear: it is wrapped into independent **key slots**, one per
credential. A slot is unlocked either by a password (Argon2id) or by an
**ML-KEM** identity (default **ML-KEM-768**).

## Why?

Because the master key is wrapped per recipient rather than derived from a
password, a volume can be handed to someone else without sharing a secret you
both already know. Each recipient gets their own slot, encapsulated to their
public key, and that slot can be revoked without re-encrypting the volume.

That is also where the post-quantum part earns its place. Shared ciphertext
sits somewhere an attacker can copy it today and try to open it in twenty
years. Wrapping the master key with ML-KEM instead of a classical KEM is what
makes "harvest now, decrypt later" a losing strategy against a shared volume.

## Features

- FUSE userspace filesystem in Rust (`fuser`)
- Random master key wrapped into key slots; password slots use Argon2id with
  parameters recorded in the volume header, recipient slots use ML-KEM
  (ML-KEM-512 / 768 / 1024 selectable at compile time)
- Share a volume with a recipient's public key and revoke that access later
- Change the password without re-encrypting the volume
- Authenticated encryption for file contents, directory index, and file names
  (XChaCha20Poly1305)
- Block-based file encryption: reads and writes touch only the blocks they
  need, and each block is bound to its index so blocks cannot be reordered
- Per-file content keys wrapped by the master key
- File-name encryption via HMAC-based lookup + XChaCha20Poly1305
- Authenticated volume header: slots cannot be added, removed or transplanted
  between volumes without detection
- Concurrent reads: metadata is protected by an `RwLock`, writes are
  serialised per inode, and long-running I/O and crypto work is offloaded to a
  worker thread pool
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

## Command line

```text
pqfs mount <BACKEND> <MOUNTPOINT>   mount a volume
pqfs keygen --out <FILE>            create an ML-KEM identity
pqfs slots <BACKEND>                list the key slots of a volume
pqfs share <BACKEND> --to <PUBFILE> give a recipient their own slot
pqfs revoke <BACKEND> --slot <N>    remove a slot
pqfs passwd <BACKEND>               replace the password slot
pqfs rekey <BACKEND>                retire the current master key
```

Every command that opens a volume takes the same credential flags:

| Flag | Meaning |
| --- | --- |
| `-p`, `--password <PASSWORD>` | unlock through a password slot |
| `--identity <FILE>` | unlock through a recipient slot |
| *(neither)* | prompt for the password on the terminal |

`PQFS_PASSWORD` is read when `--password` is absent, so the password never has
to appear in shell history.

### Quick start

```bash
mkdir -p ~/pqfs-backend ~/pqfs-mnt

# Create a new volume and mount it
pqfs mount ~/pqfs-backend ~/pqfs-mnt --init --password "super secret"

# In another terminal
cd ~/pqfs-mnt
echo "hello quantum world" > test.txt
cat test.txt

fusermount3 -u ~/pqfs-mnt
```

Mount an existing volume by omitting `--init`:

```bash
PQFS_PASSWORD="super secret" pqfs mount ~/pqfs-backend ~/pqfs-mnt
```

Extra FUSE options are passed through with `-o`, and `-o ro` mounts read-only.

### Sharing a volume

The recipient generates an identity and sends you only the public half:

```bash
pqfs keygen --out ~/.pqfs/alice.key
# writes ~/.pqfs/alice.key      (private, mode 0600 — never share this)
#        ~/.pqfs/alice.key.pub  (public, this is what you send)
```

You add a slot for that public key:

```bash
pqfs share ~/pqfs-backend --to alice.key.pub --label alice
pqfs slots ~/pqfs-backend
# 0	password
# 1	recipient	alice
```

The recipient now mounts the volume with their key and no password at all:

```bash
pqfs mount ~/pqfs-backend ~/pqfs-mnt --identity ~/.pqfs/alice.key
```

Revoking a slot removes that credential from the live volume:

```bash
pqfs revoke ~/pqfs-backend --slot 1
```

Revocation on its own is not enough. A revoked recipient who kept a copy of
the old header still holds a slot wrapping the master key, and that key still
protects the volume — pairing the retained header with a later copy of the
data reads everything written *after* the revocation. `pqfs rekey` closes
that by retiring the master key:

```bash
pqfs rekey ~/pqfs-backend
```

Rekeying draws a new master key, rewraps every remaining slot, rewraps the
per-file keys, and re-encrypts the file names and the index. File contents are
never re-encrypted, so the cost scales with the number of files rather than
their size. The swap is committed atomically: if the process dies partway, the
next command completes it.

What rekeying cannot do is take back what was already handed over. A copy the
recipient made while their slot was valid stays readable — revocation and
rekeying stop future access, never past disclosure. Rekey after every
revocation you actually care about.

`pqfs slots` is the only command that does not need a credential; slot labels
and kinds are stored in the clear so you can see who has access before
unlocking.

### Changing the password

```bash
pqfs passwd ~/pqfs-backend
```

This unwraps the master key with your current credential and rewraps it under
a new password. File contents are untouched, so it is instant regardless of
volume size. It also works with `--identity`, which is how a recipient can
set a password on a volume they were given.

A volume always keeps at least one slot; `pqfs revoke` refuses to remove the
last one.

### Docker quick-start

```bash
# Build image and keep a container running for manual testing
docker compose up -d pqfs

# Create and mount a volume inside the container
docker compose exec pqfs pqfs mount /data /mnt/pqfs --password smoke-test --init
docker compose exec pqfs pqfs mount /data /mnt/pqfs --password smoke-test

# Or run the one-shot smoke test (creates, writes, reads, unmounts)
docker compose --profile test run --rm smoke-test
```

### On-disk layout

After initialization, the encrypted backend (`~/pqfs-backend`) contains:

- `pqfs.header` — volume id, key slots, and the header MAC. Each slot holds a
  copy of the master key wrapped to one credential; nothing in the header is
  usable without one of them.
- `pqfs.index` — encrypted directory index
- `pqfs.rekey`, `pqfs.header.new`, `pqfs.index.new` — present only while a
  rekey is committing; the next command finishes the swap
- `data/` — per-inode encrypted file contents, stored as independently
  encrypted blocks

## Threat model

### What pqfs tries to protect against

- **Offline backend theft.** If an attacker steals the backend directory, the
  files, directory index, and file names are encrypted. The master key is
  random and only exists on disk wrapped inside key slots, so the attacker
  needs a password or a recipient private key as well as the backend.
- **Harvest-now-decrypt-later on a shared volume.** A recipient slot wraps the
  master key with ML-KEM. Ciphertext copied today cannot be opened later by a
  quantum computer the way a classical key encapsulation would allow.
- **Header tampering.** The header is authenticated with a MAC derived from the
  master key, so slots cannot be added, removed, reordered or transplanted from
  another volume without detection.
- **Block reordering.** Each file block is bound to its index, so blocks cannot
  be swapped within a file.
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
- **Data a recipient already copied.** Revoking a slot and rekeying stop future
  access, but a copy taken while the slot was valid stays readable. Nothing in
  the design can undo a disclosure that already happened.
- **Revocation without rekeying.** If you revoke a slot but do not run
  `pqfs rekey`, a recipient who kept the old header can still derive the master
  key and read data written after the revocation.
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
│  Blocks (src/fs/blocks.rs)          │
│  Entry (src/fs/entry.rs)            │
└──────────────┬──────────────────────┘
               │ encrypt / decrypt
┌──────────────▼──────────────────────┐
│  Crypto (src/crypto/)               │
│  - volume.rs (key slots, header)    │
│  - identity.rs (ML-KEM identities)  │
│  - aead.rs (XChaCha20Poly1305)      │
│  - filename.rs (name HMAC/encrypt)  │
│  - keys.rs (Argon2/HKDF/key wrap)   │
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
- [x] Key slots, volume sharing, and revocation
- [x] Block-based file encryption
- [ ] Hardware-backed identities (TPM / PKCS#11)
- [x] Re-key a volume so revocation also retires the master key

## License

Distributed under the MIT License. See `LICENSE` for details.

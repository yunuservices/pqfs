use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result};

use crate::crypto::{Crypto, NONCE_LEN};

pub(crate) const BLOCK_PLAINTEXT: usize = 65536;
const TAG_LEN: usize = 16;
const FULL_RECORD: u64 = (NONCE_LEN + BLOCK_PLAINTEXT + TAG_LEN) as u64;

pub(crate) fn block_count(size: u64) -> u64 {
    size.div_ceil(BLOCK_PLAINTEXT as u64)
}

fn plaintext_len(size: u64, index: u64) -> usize {
    let start = index * BLOCK_PLAINTEXT as u64;
    if start >= size {
        return 0;
    }
    ((size - start).min(BLOCK_PLAINTEXT as u64)) as usize
}

fn record_len(size: u64, index: u64) -> usize {
    NONCE_LEN + plaintext_len(size, index) + TAG_LEN
}

fn record_offset(index: u64) -> u64 {
    index * FULL_RECORD
}

fn read_block(
    file: &mut File,
    crypto: &Crypto,
    key: &[u8],
    size: u64,
    index: u64,
) -> Result<Vec<u8>> {
    let len = record_len(size, index);
    let mut buf = vec![0u8; len];
    file.seek(SeekFrom::Start(record_offset(index)))?;
    file.read_exact(&mut buf)
        .with_context(|| format!("failed to read block {index}"))?;
    crypto.decrypt_block(key, index, &buf)
}

fn write_block(
    file: &mut File,
    crypto: &Crypto,
    key: &[u8],
    index: u64,
    plaintext: &[u8],
) -> Result<()> {
    let record = crypto.encrypt_block(key, index, plaintext)?;
    file.seek(SeekFrom::Start(record_offset(index)))?;
    file.write_all(&record)
        .with_context(|| format!("failed to write block {index}"))?;
    Ok(())
}

fn open_rw(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("failed to open {}", path.display()))
}

pub(crate) fn read_range(
    crypto: &Crypto,
    key: &[u8],
    path: &Path,
    size: u64,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>> {
    if offset >= size || len == 0 {
        return Ok(Vec::new());
    }
    let end = (offset + len as u64).min(size);
    let first = offset / BLOCK_PLAINTEXT as u64;
    let last = (end - 1) / BLOCK_PLAINTEXT as u64;

    let mut file =
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut out = Vec::with_capacity((end - offset) as usize);
    for index in first..=last {
        let block = read_block(&mut file, crypto, key, size, index)?;
        let block_start = index * BLOCK_PLAINTEXT as u64;
        let from = offset.saturating_sub(block_start) as usize;
        let to = ((end - block_start) as usize).min(block.len());
        if from < to {
            out.extend_from_slice(&block[from..to]);
        }
    }
    Ok(out)
}

pub(crate) fn write_range(
    crypto: &Crypto,
    key: &[u8],
    path: &Path,
    size: u64,
    offset: u64,
    data: &[u8],
) -> Result<u64> {
    let new_size = size.max(offset + data.len() as u64);
    let old_blocks = block_count(size);
    let new_blocks = block_count(new_size);
    if new_blocks == 0 {
        return Ok(new_size);
    }

    let touched_from = (offset / BLOCK_PLAINTEXT as u64).min(old_blocks.saturating_sub(1));
    let mut file = open_rw(path)?;

    for index in touched_from..new_blocks {
        let target = plaintext_len(new_size, index);
        let mut buf = if index < old_blocks {
            read_block(&mut file, crypto, key, size, index)?
        } else {
            Vec::new()
        };
        buf.resize(target, 0);

        let block_start = index * BLOCK_PLAINTEXT as u64;
        let block_end = block_start + target as u64;
        let write_start = offset.max(block_start);
        let write_end = (offset + data.len() as u64).min(block_end);
        if write_start < write_end {
            let dst = (write_start - block_start) as usize..(write_end - block_start) as usize;
            let src = (write_start - offset) as usize..(write_end - offset) as usize;
            buf[dst].copy_from_slice(&data[src]);
        }

        write_block(&mut file, crypto, key, index, &buf)?;
    }

    file.set_len(record_offset(new_blocks - 1) + record_len(new_size, new_blocks - 1) as u64)?;
    Ok(new_size)
}

pub(crate) fn truncate(
    crypto: &Crypto,
    key: &[u8],
    path: &Path,
    size: u64,
    new_size: u64,
) -> Result<()> {
    if new_size > size {
        write_range(crypto, key, path, size, new_size, &[])?;
        return Ok(());
    }
    if new_size == size {
        return Ok(());
    }

    let new_blocks = block_count(new_size);
    if new_blocks == 0 {
        let file = open_rw(path)?;
        file.set_len(0)?;
        return Ok(());
    }

    let mut file = open_rw(path)?;
    let last = new_blocks - 1;
    let target = plaintext_len(new_size, last);
    let mut buf = read_block(&mut file, crypto, key, size, last)?;
    buf.truncate(target);
    write_block(&mut file, crypto, key, last, &buf)?;
    file.set_len(record_offset(last) + record_len(new_size, last) as u64)?;
    Ok(())
}

pub(crate) fn sync(path: &Path) -> Result<()> {
    match File::open(path) {
        Ok(file) => file
            .sync_all()
            .with_context(|| format!("failed to sync {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("failed to open {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Crypto;

    fn setup() -> (tempfile::TempDir, Crypto, Vec<u8>) {
        let dir = tempfile::tempdir().unwrap();
        let crypto = Crypto::init_for_tests("pw", dir.path()).unwrap();
        let key = crypto.random_key().to_vec();
        (dir, crypto, key)
    }

    #[test]
    fn read_past_eof_returns_empty() {
        let (dir, crypto, key) = setup();
        let path = dir.path().join("f");
        let size = write_range(&crypto, &key, &path, 0, 0, b"hello").unwrap();
        assert_eq!(size, 5);

        assert!(
            read_range(&crypto, &key, &path, size, 5, 4096)
                .unwrap()
                .is_empty()
        );
        assert!(
            read_range(&crypto, &key, &path, size, 100_000, 4096)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            read_range(&crypto, &key, &path, size, 2, 4096).unwrap(),
            b"llo"
        );
    }

    #[test]
    fn writes_spanning_blocks_round_trip() {
        let (dir, crypto, key) = setup();
        let path = dir.path().join("f");
        let payload: Vec<u8> = (0..BLOCK_PLAINTEXT * 2 + 1234)
            .map(|i| (i % 251) as u8)
            .collect();

        let size = write_range(&crypto, &key, &path, 0, 0, &payload).unwrap();
        assert_eq!(size as usize, payload.len());
        assert_eq!(block_count(size), 3);

        let read = read_range(&crypto, &key, &path, size, 0, payload.len()).unwrap();
        assert_eq!(read, payload);

        let mid = read_range(&crypto, &key, &path, size, BLOCK_PLAINTEXT as u64 - 10, 20).unwrap();
        assert_eq!(mid, &payload[BLOCK_PLAINTEXT - 10..BLOCK_PLAINTEXT + 10]);
    }

    #[test]
    fn partial_overwrite_leaves_the_rest_intact() {
        let (dir, crypto, key) = setup();
        let path = dir.path().join("f");
        let payload = vec![b'a'; BLOCK_PLAINTEXT + 500];
        let size = write_range(&crypto, &key, &path, 0, 0, &payload).unwrap();

        let size = write_range(&crypto, &key, &path, size, 10, b"ZZZZ").unwrap();
        let read = read_range(&crypto, &key, &path, size, 0, size as usize).unwrap();
        assert_eq!(&read[0..10], &payload[0..10]);
        assert_eq!(&read[10..14], b"ZZZZ");
        assert_eq!(&read[14..], &payload[14..]);
    }

    #[test]
    fn sparse_write_zero_fills_the_gap() {
        let (dir, crypto, key) = setup();
        let path = dir.path().join("f");
        let size = write_range(&crypto, &key, &path, 0, 0, b"ab").unwrap();

        let size = write_range(
            &crypto,
            &key,
            &path,
            size,
            BLOCK_PLAINTEXT as u64 + 5,
            b"cd",
        )
        .unwrap();
        assert_eq!(size as usize, BLOCK_PLAINTEXT + 7);

        let read = read_range(&crypto, &key, &path, size, 0, size as usize).unwrap();
        assert_eq!(&read[0..2], b"ab");
        assert!(read[2..BLOCK_PLAINTEXT + 5].iter().all(|b| *b == 0));
        assert_eq!(&read[BLOCK_PLAINTEXT + 5..], b"cd");
    }

    #[test]
    fn truncate_shrinks_and_grows() {
        let (dir, crypto, key) = setup();
        let path = dir.path().join("f");
        let payload = vec![b'x'; BLOCK_PLAINTEXT * 2];
        let size = write_range(&crypto, &key, &path, 0, 0, &payload).unwrap();

        truncate(&crypto, &key, &path, size, 100).unwrap();
        let read = read_range(&crypto, &key, &path, 100, 0, 4096).unwrap();
        assert_eq!(read.len(), 100);
        assert!(read.iter().all(|b| *b == b'x'));

        truncate(&crypto, &key, &path, 100, 0).unwrap();
        assert!(
            read_range(&crypto, &key, &path, 0, 0, 4096)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_block_cannot_be_replayed_at_another_index() {
        let (dir, crypto, key) = setup();
        let path = dir.path().join("f");
        let mut payload = vec![b'a'; BLOCK_PLAINTEXT];
        payload.extend_from_slice(&[b'b'; BLOCK_PLAINTEXT]);
        let size = write_range(&crypto, &key, &path, 0, 0, &payload).unwrap();

        let raw = std::fs::read(&path).unwrap();
        let record = NONCE_LEN + BLOCK_PLAINTEXT + 16;
        let mut swapped = raw.clone();
        let (first, second) = raw.split_at(record);
        swapped[..record].copy_from_slice(&second[..record]);
        swapped[record..record * 2].copy_from_slice(first);
        std::fs::write(&path, &swapped).unwrap();

        assert!(read_range(&crypto, &key, &path, size, 0, 16).is_err());
    }
}

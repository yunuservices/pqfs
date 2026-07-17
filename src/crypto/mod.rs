use chacha20poly1305::XChaCha20Poly1305;

mod aead;
mod filename;
mod header;
mod kem;
mod keys;
mod volume;

pub(crate) use header::VolumeHeader;
pub(crate) use kem::{SELECTED_KEM_PARAM, SelectedKem};

pub(crate) const KEY_LEN: usize = 32;
pub(crate) const SALT_LEN: usize = 16;
pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const SEED_LEN: usize = 64;

/// Hybrid crypto engine: classical password + ML-KEM selected-parameter-set shared secret.
pub struct Crypto {
    pub(crate) cipher: XChaCha20Poly1305,
    pub(crate) header: VolumeHeader,
    pub(crate) filename_cipher: XChaCha20Poly1305,
    pub(crate) filename_hash_key: [u8; KEY_LEN],
}

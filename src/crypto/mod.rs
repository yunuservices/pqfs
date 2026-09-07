use chacha20poly1305::XChaCha20Poly1305;

mod aead;
mod filename;
mod header;
mod identity;
mod kem;
mod keys;
pub(crate) mod volume;

pub(crate) use header::{HEADER_VERSION, KdfParams, KeySlot, VolumeHeader};
pub(crate) use identity::{Identity, PublicIdentity};
pub(crate) use kem::{SELECTED_KEM_PARAM, SelectedKem};
pub(crate) use volume::Unlock;

pub(crate) const KEY_LEN: usize = 32;
pub(crate) const SALT_LEN: usize = 16;
pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const SEED_LEN: usize = 64;
pub(crate) const MAC_LEN: usize = 32;
pub(crate) const VOLUME_ID_LEN: usize = 16;
pub(crate) const MAX_HEADER_BYTES: u64 = 256 * 1024;

/// Hybrid crypto engine: classical password + ML-KEM selected-parameter-set shared secret.
pub struct Crypto {
    pub(crate) cipher: XChaCha20Poly1305,
    pub(crate) header: VolumeHeader,
    pub(crate) filename_cipher: XChaCha20Poly1305,
    pub(crate) filename_hash_key: keys::SecretKey,
}

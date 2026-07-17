use anyhow::{Context, Result, bail};
use argon2::Argon2;
use chacha20poly1305::aead::KeyInit;
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;

use super::{Crypto, KEY_LEN, NONCE_LEN, SALT_LEN, VolumeHeader};

pub(crate) fn random_nonce() -> XNonce {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    XNonce::try_from(nonce.as_slice()).expect("nonce length is correct")
}

pub(crate) fn build_cipher(key: &[u8]) -> Result<XChaCha20Poly1305> {
    let k = Key::try_from(key).map_err(|_| anyhow::anyhow!("invalid cipher key length"))?;
    Ok(XChaCha20Poly1305::new(&k))
}

pub(crate) fn derive_password_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    if salt.len() != SALT_LEN {
        bail!("invalid salt length");
    }
    let argon2 = Argon2::default();
    let mut out = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| anyhow::anyhow!("Argon2 key derivation failed: {}", e))?;
    Ok(out)
}

pub(crate) fn derive_master_key(
    password_key: &[u8],
    shared_secret: &[u8],
) -> Result<[u8; KEY_LEN]> {
    let mut ikm = Vec::with_capacity(password_key.len() + shared_secret.len());
    ikm.extend_from_slice(password_key);
    ikm.extend_from_slice(shared_secret);
    let hkdf = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; KEY_LEN];
    hkdf.expand(b"pqfs-hybrid-master-key", &mut okm)
        .map_err(|e| anyhow::anyhow!("HKDF expand failed: {}", e))?;
    Ok(okm)
}

pub(crate) fn derive_filename_keys(master_key: &[u8]) -> Result<([u8; KEY_LEN], [u8; KEY_LEN])> {
    let hkdf = Hkdf::<Sha256>::new(None, master_key);
    let mut filename_key = [0u8; KEY_LEN];
    let mut filename_hash_key = [0u8; KEY_LEN];
    hkdf.expand(b"pqfs-filename-key", &mut filename_key)
        .map_err(|e| anyhow::anyhow!("HKDF filename key expand failed: {}", e))?;
    hkdf.expand(b"pqfs-filename-hash-key", &mut filename_hash_key)
        .map_err(|e| anyhow::anyhow!("HKDF filename hash key expand failed: {}", e))?;
    Ok((filename_key, filename_hash_key))
}

impl Crypto {
    pub(crate) fn from_master_key(master_key: &[u8], header: VolumeHeader) -> Result<Self> {
        let (filename_key, filename_hash_key) = derive_filename_keys(master_key)?;
        let cipher = build_cipher(master_key)?;
        let filename_cipher = build_cipher(&filename_key)?;
        Ok(Self {
            cipher,
            header,
            filename_cipher,
            filename_hash_key,
        })
    }

    pub(crate) fn random_key(&self) -> [u8; KEY_LEN] {
        let mut key = [0u8; KEY_LEN];
        rand::rng().fill_bytes(&mut key);
        key
    }
}

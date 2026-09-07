use anyhow::{Result, bail};
use argon2::{Algorithm, Argon2, Params, Version as ArgonVersion};
use chacha20poly1305::aead::KeyInit;
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;

use zeroize::Zeroizing;

use super::{Crypto, KEY_LEN, KdfParams, MAC_LEN, NONCE_LEN, SALT_LEN, VolumeHeader};

pub(crate) type SecretKey = Zeroizing<[u8; KEY_LEN]>;

pub(crate) fn random_nonce() -> XNonce {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    XNonce::try_from(nonce.as_slice()).expect("nonce length is correct")
}

pub(crate) fn build_cipher(key: &[u8]) -> Result<XChaCha20Poly1305> {
    let k = Key::try_from(key).map_err(|_| anyhow::anyhow!("invalid cipher key length"))?;
    Ok(XChaCha20Poly1305::new(&k))
}

pub(crate) fn derive_password_key(
    password: &str,
    salt: &[u8],
    kdf: KdfParams,
) -> Result<SecretKey> {
    if salt.len() != SALT_LEN {
        bail!("invalid salt length");
    }
    let params = Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(KEY_LEN))
        .map_err(|e| anyhow::anyhow!("invalid Argon2 parameters: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, ArgonVersion::V0x13, params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(password.as_bytes(), salt, out.as_mut_slice())
        .map_err(|e| anyhow::anyhow!("Argon2 key derivation failed: {}", e))?;
    Ok(out)
}

pub(crate) fn derive_master_key(password_key: &[u8], shared_secret: &[u8]) -> Result<SecretKey> {
    let mut ikm = Vec::with_capacity(password_key.len() + shared_secret.len());
    ikm.extend_from_slice(password_key);
    ikm.extend_from_slice(shared_secret);
    let hkdf = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(b"pqfs-hybrid-master-key", okm.as_mut_slice())
        .map_err(|e| anyhow::anyhow!("HKDF expand failed: {}", e))?;
    Ok(okm)
}

pub(crate) fn derive_header_mac_key(password_key: &[u8]) -> Result<SecretKey> {
    let hkdf = Hkdf::<Sha256>::new(None, password_key);
    let mut okm = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(b"pqfs-header-mac-key", okm.as_mut_slice())
        .map_err(|e| anyhow::anyhow!("HKDF header mac key expand failed: {}", e))?;
    Ok(okm)
}

pub(crate) fn header_mac(mac_key: &[u8], header: &VolumeHeader) -> Result<[u8; MAC_LEN]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(mac_key)
        .map_err(|e| anyhow::anyhow!("invalid header mac key: {}", e))?;
    mac.update(&header.authenticated_bytes()?);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub(crate) fn verify_header_mac(mac_key: &[u8], header: &VolumeHeader) -> Result<()> {
    let mut mac = Hmac::<Sha256>::new_from_slice(mac_key)
        .map_err(|e| anyhow::anyhow!("invalid header mac key: {}", e))?;
    mac.update(&header.authenticated_bytes()?);
    mac.verify_slice(&header.mac)
        .map_err(|_| anyhow::anyhow!("password incorrect or volume header has been modified"))
}

pub(crate) fn derive_filename_keys(master_key: &[u8]) -> Result<(SecretKey, SecretKey)> {
    let hkdf = Hkdf::<Sha256>::new(None, master_key);
    let mut filename_key = Zeroizing::new([0u8; KEY_LEN]);
    let mut filename_hash_key = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(b"pqfs-filename-key", filename_key.as_mut_slice())
        .map_err(|e| anyhow::anyhow!("HKDF filename key expand failed: {}", e))?;
    hkdf.expand(b"pqfs-filename-hash-key", filename_hash_key.as_mut_slice())
        .map_err(|e| anyhow::anyhow!("HKDF filename hash key expand failed: {}", e))?;
    Ok((filename_key, filename_hash_key))
}

impl Crypto {
    pub(crate) fn from_master_key(master_key: &[u8], header: VolumeHeader) -> Result<Self> {
        let (filename_key, filename_hash_key) = derive_filename_keys(master_key)?;
        let cipher = build_cipher(master_key)?;
        let filename_cipher = build_cipher(filename_key.as_slice())?;
        Ok(Self {
            cipher,
            header,
            filename_cipher,
            filename_hash_key,
        })
    }

    pub(crate) fn random_key(&self) -> SecretKey {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        rand::rng().fill_bytes(key.as_mut_slice());
        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KDF: KdfParams = KdfParams {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
    };

    #[test]
    fn random_nonce_has_correct_length() {
        assert_eq!(random_nonce().len(), NONCE_LEN);
    }

    #[test]
    fn derive_password_key_produces_32_bytes() {
        let salt = [0u8; SALT_LEN];
        let key = derive_password_key("password", &salt, TEST_KDF).unwrap();
        assert_eq!(key.len(), KEY_LEN);
    }

    #[test]
    fn derive_password_key_is_deterministic() {
        let salt = [1u8; SALT_LEN];
        let a = derive_password_key("same", &salt, TEST_KDF).unwrap();
        let b = derive_password_key("same", &salt, TEST_KDF).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn derive_master_key_is_32_bytes_and_sensitive_to_input() {
        let pw = derive_password_key("pw", &[0u8; SALT_LEN], TEST_KDF).unwrap();
        let ss = [0u8; 64];
        let key_a = derive_master_key(pw.as_slice(), &ss).unwrap();
        assert_eq!(key_a.len(), KEY_LEN);

        let mut ss2 = ss;
        ss2[0] ^= 1;
        let key_b = derive_master_key(pw.as_slice(), &ss2).unwrap();
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn derive_filename_keys_are_independent() {
        let master = [7u8; KEY_LEN];
        let (a, b) = derive_filename_keys(&master).unwrap();
        assert_eq!(a.len(), KEY_LEN);
        assert_eq!(b.len(), KEY_LEN);
        assert_ne!(a, b);
    }
}

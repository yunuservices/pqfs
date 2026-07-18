use anyhow::{Context, Result, bail};
use chacha20poly1305::XNonce;
use chacha20poly1305::aead::Aead;

use super::keys::{build_cipher, random_nonce};
use super::{Crypto, NONCE_LEN};

impl Crypto {
    /// Encrypt arbitrary plaintext. Format: [24-byte nonce || ciphertext || tag].
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = random_nonce();
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .context("encryption failed")?;
        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(nonce.as_ref());
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt a blob produced by `encrypt`.
    pub fn decrypt(&self, blob: &[u8]) -> Result<Vec<u8>> {
        if blob.len() < NONCE_LEN + 16 {
            bail!("ciphertext too short");
        }
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        let nonce = XNonce::try_from(nonce).map_err(|_| anyhow::anyhow!("invalid nonce length"))?;
        self.cipher
            .decrypt(&nonce, ct)
            .context("decryption failed (corrupted or tampered data)")
    }

    pub fn encrypt_with_key(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = build_cipher(key)?;
        let nonce = random_nonce();
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .context("per-file key encryption failed")?;
        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(nonce.as_ref());
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn decrypt_with_key(&self, key: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
        if blob.len() < NONCE_LEN + 16 {
            bail!("per-file ciphertext too short");
        }
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        let nonce = XNonce::try_from(nonce)
            .map_err(|_| anyhow::anyhow!("invalid per-file nonce length"))?;
        let cipher = build_cipher(key)?;
        cipher
            .decrypt(&nonce, ct)
            .context("per-file key decryption failed")
    }
}

#[cfg(test)]
mod tests {
    use super::super::Crypto;

    fn crypto() -> Crypto {
        let dir = tempfile::tempdir().unwrap();
        Crypto::init("test-password", dir.path()).unwrap()
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let crypto = crypto();
        let plaintext = b"hello quantum world";
        let ciphertext = crypto.encrypt(plaintext).unwrap();
        let decrypted = crypto.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypt_decrypt_with_per_file_key_roundtrip() {
        let crypto = crypto();
        let content_key = crypto.random_key();
        let plaintext = b"per-file secret";
        let ciphertext = crypto.encrypt_with_key(&content_key, plaintext).unwrap();
        let decrypted = crypto.decrypt_with_key(&content_key, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let crypto = crypto();
        let mut ciphertext = crypto.encrypt(b"secret").unwrap();
        ciphertext[ciphertext.len() - 1] ^= 1;
        assert!(crypto.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn decrypt_rejects_short_ciphertext() {
        let crypto = crypto();
        assert!(crypto.decrypt(&[0u8; 10]).is_err());
    }
}

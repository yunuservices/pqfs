use anyhow::{Context, Result, bail};
use chacha20poly1305::XNonce;
use chacha20poly1305::aead::{Aead, KeyInit};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::keys::random_nonce;
use super::{Crypto, KEY_LEN, NONCE_LEN};

impl Crypto {
    pub fn hash_filename(&self, name: &str) -> [u8; KEY_LEN] {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.filename_hash_key).expect("valid HMAC key size");
        mac.update(name.as_bytes());
        let bytes = mac.finalize().into_bytes();
        let mut out = [0u8; KEY_LEN];
        out.copy_from_slice(&bytes);
        out
    }

    pub fn encrypt_filename(&self, name: &str) -> Result<Vec<u8>> {
        let nonce = random_nonce();
        let ciphertext = self
            .filename_cipher
            .encrypt(&nonce, name.as_bytes())
            .context("filename encryption failed")?;
        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(nonce.as_ref());
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn decrypt_filename(&self, blob: &[u8]) -> Result<String> {
        if blob.len() < NONCE_LEN + 16 {
            bail!("encrypted filename too short");
        }
        let (nonce, ct) = blob.split_at(NONCE_LEN);
        let nonce = XNonce::try_from(nonce)
            .map_err(|_| anyhow::anyhow!("invalid filename nonce length"))?;
        let plaintext = self
            .filename_cipher
            .decrypt(&nonce, ct)
            .context("filename decryption failed")?;
        String::from_utf8(plaintext).context("filename is not valid UTF-8")
    }
}

#[cfg(test)]
mod tests {
    use super::super::Crypto;

    fn crypto() -> Crypto {
        let dir = tempfile::tempdir().unwrap();
        Crypto::init_for_tests("test-password", dir.path()).unwrap()
    }

    #[test]
    fn encrypt_decrypt_filename_roundtrip() {
        let crypto = crypto();
        let name = "my secret document.txt";
        let encrypted = crypto.encrypt_filename(name).unwrap();
        let decrypted = crypto.decrypt_filename(&encrypted).unwrap();
        assert_eq!(decrypted, name);
    }

    #[test]
    fn hash_filename_is_deterministic() {
        let crypto = crypto();
        let name = "document.txt";
        assert_eq!(crypto.hash_filename(name), crypto.hash_filename(name));
    }

    #[test]
    fn hash_filename_differs_for_different_names() {
        let crypto = crypto();
        assert_ne!(crypto.hash_filename("a"), crypto.hash_filename("b"));
    }

    #[test]
    fn decrypt_filename_rejects_short_blob() {
        let crypto = crypto();
        assert!(crypto.decrypt_filename(&[0u8; 10]).is_err());
    }
}

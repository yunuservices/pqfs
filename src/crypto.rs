use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ml_kem::kem::{Ciphertext, Decapsulate, Encapsulate, Kem, KeyExport};
use ml_kem::{MlKem768, Seed};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const SEED_LEN: usize = 64;

/// On-disk header stored in the backend root.
#[derive(Serialize, Deserialize, Debug)]
pub struct VolumeHeader {
    pub salt: [u8; SALT_LEN],
    pub kem_ciphertext: Vec<u8>,
    pub kem_public_key: Vec<u8>,
    pub encrypted_seed: Vec<u8>,
}

/// Hybrid crypto engine: classical password + ML-KEM-768 shared secret.
pub struct Crypto {
    cipher: XChaCha20Poly1305,
    header: VolumeHeader,
    filename_cipher: XChaCha20Poly1305,
    filename_hash_key: [u8; KEY_LEN],
}

impl Crypto {
    const HEADER_FILE: &'static str = "pqfs.header";

    /// Create a new volume. Generates an ML-KEM-768 keypair, derives a hybrid
    /// master key from the password and the KEM shared secret, and stores the
    /// encrypted seed in the backend.
    pub fn init(password: &str, backend: &Path) -> Result<Self> {
        fs::create_dir_all(backend)?;
        let header_path = backend.join(Self::HEADER_FILE);
        if header_path.exists() {
            bail!("volume already exists at {}", backend.display());
        }

        let mut salt = [0u8; SALT_LEN];
        rand::rng().fill_bytes(&mut salt);

        let password_key = Self::derive_password_key(password, &salt)?;
        let pw_key = Key::try_from(password_key.as_slice())
            .map_err(|_| anyhow::anyhow!("invalid password key length"))?;
        let pw_cipher = XChaCha20Poly1305::new(&pw_key);

        let (dk, ek) = MlKem768::generate_keypair();
        let (ct, shared_secret) = ek.encapsulate();

        let seed = dk.to_seed().context("failed to extract ML-KEM seed")?;
        let seed_bytes: Vec<u8> = AsRef::<[u8]>::as_ref(&seed).to_vec();
        let sk_nonce = Self::random_nonce();
        let encrypted_seed = pw_cipher
            .encrypt(&sk_nonce, seed_bytes.as_ref())
            .context("failed to encrypt ML-KEM seed")?;

        // Prepend nonce to encrypted seed blob.
        let mut encrypted_seed_blob = Vec::with_capacity(NONCE_LEN + encrypted_seed.len());
        encrypted_seed_blob.extend_from_slice(sk_nonce.as_ref());
        encrypted_seed_blob.extend_from_slice(&encrypted_seed);

        let master_key =
            Self::derive_master_key(&password_key, AsRef::<[u8]>::as_ref(&shared_secret))?;

        let header = VolumeHeader {
            salt,
            kem_ciphertext: AsRef::<[u8]>::as_ref(&ct).to_vec(),
            kem_public_key: AsRef::<[u8]>::as_ref(&ek.to_bytes()).to_vec(),
            encrypted_seed: encrypted_seed_blob,
        };

        let this = Self::from_master_key(&master_key, header)?;
        this.save(backend)?;
        Ok(this)
    }

    /// Load an existing volume.
    pub fn load(password: &str, backend: &Path) -> Result<Self> {
        let header_path = backend.join(Self::HEADER_FILE);
        let data = fs::read(&header_path)
            .with_context(|| format!("failed to read {}", header_path.display()))?;
        let header: VolumeHeader = bincode::deserialize(&data)?;

        let password_key = Self::derive_password_key(password, &header.salt)?;
        let pw_key = Key::try_from(password_key.as_slice())
            .map_err(|_| anyhow::anyhow!("invalid password key length"))?;
        let pw_cipher = XChaCha20Poly1305::new(&pw_key);

        if header.encrypted_seed.len() < NONCE_LEN + 16 {
            bail!("corrupted encrypted seed");
        }
        let (nonce, ct) = header.encrypted_seed.split_at(NONCE_LEN);
        let nonce =
            XNonce::try_from(nonce).map_err(|_| anyhow::anyhow!("invalid seed nonce length"))?;
        let seed_bytes = pw_cipher
            .decrypt(&nonce, ct)
            .context("password incorrect or corrupted volume")?;

        if seed_bytes.len() != SEED_LEN {
            bail!("invalid ML-KEM seed length");
        }
        let seed = Seed::try_from(seed_bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("invalid ML-KEM seed"))?;
        let dk = <MlKem768 as Kem>::DecapsulationKey::from_seed(seed);

        let ct_array = Ciphertext::<MlKem768>::try_from(header.kem_ciphertext.as_slice())
            .map_err(|_| anyhow::anyhow!("invalid ML-KEM ciphertext"))?;
        let shared_secret = dk.decapsulate(&ct_array);

        let master_key =
            Self::derive_master_key(&password_key, AsRef::<[u8]>::as_ref(&shared_secret))?;

        Ok(Self::from_master_key(&master_key, header)?)
    }

    /// Encrypt arbitrary plaintext. Format: [24-byte nonce || ciphertext || tag].
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Self::random_nonce();
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

    fn save(&self, backend: &Path) -> Result<()> {
        let header_path = backend.join(Self::HEADER_FILE);
        let data = bincode::serialize(&self.header)?;
        fs::write(&header_path, data)?;
        Ok(())
    }

    fn derive_password_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN]> {
        let argon2 = Argon2::default();
        let mut out = [0u8; KEY_LEN];
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut out)
            .map_err(|e| anyhow::anyhow!("Argon2 key derivation failed: {}", e))?;
        Ok(out)
    }

    fn derive_master_key(password_key: &[u8], shared_secret: &[u8]) -> Result<[u8; KEY_LEN]> {
        let mut ikm = Vec::with_capacity(password_key.len() + shared_secret.len());
        ikm.extend_from_slice(password_key);
        ikm.extend_from_slice(shared_secret);
        let hkdf = Hkdf::<Sha256>::new(None, &ikm);
        let mut okm = [0u8; KEY_LEN];
        hkdf.expand(b"pqfs-hybrid-master-key", &mut okm)
            .map_err(|e| anyhow::anyhow!("HKDF expand failed: {}", e))?;
        Ok(okm)
    }

    fn from_master_key(master_key: &[u8], header: VolumeHeader) -> Result<Self> {
        let (filename_key, filename_hash_key) = Self::derive_filename_keys(master_key)?;
        let cipher = Self::build_cipher(master_key)?;
        let filename_cipher = Self::build_cipher(&filename_key)?;
        Ok(Self {
            cipher,
            header,
            filename_cipher,
            filename_hash_key,
        })
    }

    fn build_cipher(key: &[u8]) -> Result<XChaCha20Poly1305> {
        let k = Key::try_from(key).map_err(|_| anyhow::anyhow!("invalid cipher key length"))?;
        Ok(XChaCha20Poly1305::new(&k))
    }

    fn derive_filename_keys(master_key: &[u8]) -> Result<([u8; KEY_LEN], [u8; KEY_LEN])> {
        let hkdf = Hkdf::<Sha256>::new(None, master_key);
        let mut filename_key = [0u8; KEY_LEN];
        let mut filename_hash_key = [0u8; KEY_LEN];
        hkdf.expand(b"pqfs-filename-key", &mut filename_key)
            .map_err(|e| anyhow::anyhow!("HKDF filename key expand failed: {}", e))?;
        hkdf.expand(b"pqfs-filename-hash-key", &mut filename_hash_key)
            .map_err(|e| anyhow::anyhow!("HKDF filename hash key expand failed: {}", e))?;
        Ok((filename_key, filename_hash_key))
    }

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
        let nonce = Self::random_nonce();
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

    pub fn random_key(&self) -> [u8; KEY_LEN] {
        let mut key = [0u8; KEY_LEN];
        rand::rng().fill_bytes(&mut key);
        key
    }

    pub fn encrypt_with_key(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Self::build_cipher(key)?;
        let nonce = Self::random_nonce();
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
        let cipher = Self::build_cipher(key)?;
        cipher
            .decrypt(&nonce, ct)
            .context("per-file key decryption failed")
    }

    fn random_nonce() -> XNonce {
        let mut nonce = [0u8; NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce);
        XNonce::try_from(nonce.as_slice()).expect("nonce length is correct")
    }
}

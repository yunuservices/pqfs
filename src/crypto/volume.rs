use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use ml_kem::Seed;
use ml_kem::kem::{Ciphertext, Decapsulate, Encapsulate, Kem, KeyExport};
use rand::Rng;

use super::keys::{derive_master_key, derive_password_key, random_nonce};
use super::{Crypto, NONCE_LEN, SALT_LEN, SEED_LEN, SELECTED_KEM_PARAM, SelectedKem, VolumeHeader};

impl Crypto {
    const HEADER_FILE: &'static str = "pqfs.header";

    /// Create a new volume. Generates an ML-KEM keypair for the selected
    /// parameter set, derives a hybrid master key from the password and the KEM
    /// shared secret, and stores the encrypted seed in the backend.
    pub fn init(password: &str, backend: &Path) -> Result<Self> {
        fs::create_dir_all(backend)?;
        let header_path = backend.join(Self::HEADER_FILE);
        if header_path.exists() {
            bail!("volume already exists at {}", backend.display());
        }

        let mut salt = [0u8; SALT_LEN];
        rand::rng().fill_bytes(&mut salt);

        let password_key = derive_password_key(password, &salt)?;
        let pw_key = Key::try_from(password_key.as_slice())
            .map_err(|_| anyhow::anyhow!("invalid password key length"))?;
        let pw_cipher = XChaCha20Poly1305::new(&pw_key);

        let (dk, ek) = <SelectedKem as Kem>::generate_keypair();
        let (ct, shared_secret) = ek.encapsulate();

        let seed = dk.to_seed().context("failed to extract ML-KEM seed")?;
        let seed_bytes: Vec<u8> = AsRef::<[u8]>::as_ref(&seed).to_vec();
        let sk_nonce = random_nonce();
        let encrypted_seed = pw_cipher
            .encrypt(&sk_nonce, seed_bytes.as_ref())
            .context("failed to encrypt ML-KEM seed")?;

        // Prepend nonce to encrypted seed blob.
        let mut encrypted_seed_blob = Vec::with_capacity(NONCE_LEN + encrypted_seed.len());
        encrypted_seed_blob.extend_from_slice(sk_nonce.as_ref());
        encrypted_seed_blob.extend_from_slice(&encrypted_seed);

        let master_key = derive_master_key(&password_key, AsRef::<[u8]>::as_ref(&shared_secret))?;

        let header = VolumeHeader {
            salt,
            kem_param: SELECTED_KEM_PARAM,
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

        if header.kem_param != SELECTED_KEM_PARAM {
            bail!(
                "volume uses ML-KEM-{} but this binary is built for ML-KEM-{}",
                header.kem_param,
                SELECTED_KEM_PARAM
            );
        }

        let password_key = derive_password_key(password, &header.salt)?;
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
        let dk = <SelectedKem as Kem>::DecapsulationKey::from_seed(seed);

        let ct_array = Ciphertext::<SelectedKem>::try_from(header.kem_ciphertext.as_slice())
            .map_err(|_| anyhow::anyhow!("invalid ML-KEM ciphertext"))?;
        let shared_secret = dk.decapsulate(&ct_array);

        let master_key = derive_master_key(&password_key, AsRef::<[u8]>::as_ref(&shared_secret))?;

        Ok(Self::from_master_key(&master_key, header)?)
    }

    fn save(&self, backend: &Path) -> Result<()> {
        let header_path = backend.join(Self::HEADER_FILE);
        let data = bincode::serialize(&self.header)?;
        fs::write(&header_path, data)?;
        Ok(())
    }
}

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use bincode::Options;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use ml_kem::Seed;
use ml_kem::kem::{Ciphertext, Decapsulate, Encapsulate, Kem, KeyExport};
use rand::Rng;

use super::keys::{
    derive_header_mac_key, derive_master_key, derive_password_key, header_mac, random_nonce,
    verify_header_mac,
};
use super::{
    Crypto, HEADER_VERSION, KdfParams, MAC_LEN, MAX_HEADER_BYTES, NONCE_LEN, SALT_LEN, SEED_LEN,
    SELECTED_KEM_PARAM, SelectedKem, VolumeHeader,
};

impl Crypto {
    const HEADER_FILE: &'static str = "pqfs.header";

    /// Create a new volume. Generates an ML-KEM keypair for the selected
    /// parameter set, derives a hybrid master key from the password and the KEM
    /// shared secret, and stores the encrypted seed in the backend.
    pub fn init(password: &str, backend: &Path) -> Result<Self> {
        Self::init_with_params(password, backend, KdfParams::default())
    }

    pub(crate) fn init_with_params(password: &str, backend: &Path, kdf: KdfParams) -> Result<Self> {
        fs::create_dir_all(backend)?;
        let header_path = backend.join(Self::HEADER_FILE);
        if header_path.exists() {
            bail!("volume already exists at {}", backend.display());
        }

        let mut salt = [0u8; SALT_LEN];
        rand::rng().fill_bytes(&mut salt);

        let password_key = derive_password_key(password, &salt, kdf)?;
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

        let mut encrypted_seed_blob = Vec::with_capacity(NONCE_LEN + encrypted_seed.len());
        encrypted_seed_blob.extend_from_slice(sk_nonce.as_ref());
        encrypted_seed_blob.extend_from_slice(&encrypted_seed);

        let master_key = derive_master_key(&password_key, AsRef::<[u8]>::as_ref(&shared_secret))?;

        let mut header = VolumeHeader {
            version: HEADER_VERSION,
            salt,
            kdf,
            kem_param: SELECTED_KEM_PARAM,
            kem_ciphertext: AsRef::<[u8]>::as_ref(&ct).to_vec(),
            kem_public_key: AsRef::<[u8]>::as_ref(&ek.to_bytes()).to_vec(),
            encrypted_seed: encrypted_seed_blob,
            mac: [0u8; MAC_LEN],
        };

        let mac_key = derive_header_mac_key(&password_key)?;
        header.mac = header_mac(&mac_key, &header)?;

        let this = Self::from_master_key(&master_key, header)?;
        this.save(backend)?;
        Ok(this)
    }

    #[cfg(test)]
    pub(crate) fn init_for_tests(password: &str, backend: &Path) -> Result<Self> {
        Self::init_with_params(
            password,
            backend,
            KdfParams {
                m_cost: 8,
                t_cost: 1,
                p_cost: 1,
            },
        )
    }

    /// Load an existing volume.
    pub fn load(password: &str, backend: &Path) -> Result<Self> {
        let header_path = backend.join(Self::HEADER_FILE);
        let data = fs::read(&header_path)
            .with_context(|| format!("failed to read {}", header_path.display()))?;
        if data.len() as u64 > MAX_HEADER_BYTES {
            bail!("volume header is implausibly large");
        }
        let header: VolumeHeader = bincode::DefaultOptions::new()
            .with_limit(MAX_HEADER_BYTES)
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .deserialize(&data)
            .context("failed to parse volume header")?;

        if header.version != HEADER_VERSION {
            bail!(
                "volume uses header version {} but this binary supports version {}",
                header.version,
                HEADER_VERSION
            );
        }

        if header.kem_param != SELECTED_KEM_PARAM {
            bail!(
                "volume uses ML-KEM-{} but this binary is built for ML-KEM-{}",
                header.kem_param,
                SELECTED_KEM_PARAM
            );
        }

        let password_key = derive_password_key(password, &header.salt, header.kdf)?;

        let mac_key = derive_header_mac_key(&password_key)?;
        verify_header_mac(&mac_key, &header)?;

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

        Self::from_master_key(&master_key, header)
    }

    fn save(&self, backend: &Path) -> Result<()> {
        let header_path = backend.join(Self::HEADER_FILE);
        let data = bincode::serialize(&self.header)?;
        fs::write(&header_path, data)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_creates_volume_header() {
        let dir = tempfile::tempdir().unwrap();
        let _ = Crypto::init_for_tests("pw", dir.path()).unwrap();
        assert!(dir.path().join("pqfs.header").exists());
    }

    #[test]
    fn init_refuses_existing_volume() {
        let dir = tempfile::tempdir().unwrap();
        let _ = Crypto::init_for_tests("pw", dir.path()).unwrap();
        assert!(Crypto::init_for_tests("pw", dir.path()).is_err());
    }

    #[test]
    fn load_roundtrip_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let crypto = Crypto::init_for_tests("my-password", dir.path()).unwrap();
        let ciphertext = crypto.encrypt(b"payload").unwrap();

        let loaded = Crypto::load("my-password", dir.path()).unwrap();
        let decrypted = loaded.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, b"payload");
    }

    #[test]
    fn load_with_wrong_password_fails() {
        let dir = tempfile::tempdir().unwrap();
        let _ = Crypto::init_for_tests("right-password", dir.path()).unwrap();
        assert!(Crypto::load("wrong-password", dir.path()).is_err());
    }

    #[test]
    fn header_records_kdf_params_and_version() {
        let dir = tempfile::tempdir().unwrap();
        let kdf = KdfParams {
            m_cost: 16,
            t_cost: 2,
            p_cost: 1,
        };
        let crypto = Crypto::init_with_params("pw", dir.path(), kdf).unwrap();
        assert_eq!(crypto.header.version, HEADER_VERSION);
        assert_eq!(crypto.header.kdf, kdf);

        let loaded = Crypto::load("pw", dir.path()).unwrap();
        assert_eq!(loaded.header.kdf, kdf);
    }

    #[test]
    fn load_rejects_a_tampered_kem_ciphertext() {
        let dir = tempfile::tempdir().unwrap();
        let crypto = Crypto::init_for_tests("pw", dir.path()).unwrap();

        let mut header = crypto.header.clone();
        header.kem_ciphertext[0] ^= 1;
        std::fs::write(
            dir.path().join("pqfs.header"),
            bincode::serialize(&header).unwrap(),
        )
        .unwrap();

        assert!(Crypto::load("pw", dir.path()).is_err());
    }

    #[test]
    fn load_rejects_a_tampered_kdf_params() {
        let dir = tempfile::tempdir().unwrap();
        let crypto = Crypto::init_for_tests("pw", dir.path()).unwrap();

        let mut header = crypto.header.clone();
        header.kdf.t_cost += 1;
        std::fs::write(
            dir.path().join("pqfs.header"),
            bincode::serialize(&header).unwrap(),
        )
        .unwrap();

        assert!(Crypto::load("pw", dir.path()).is_err());
    }

    #[test]
    fn load_rejects_an_oversized_header() {
        let dir = tempfile::tempdir().unwrap();
        let _ = Crypto::init_for_tests("pw", dir.path()).unwrap();
        std::fs::write(
            dir.path().join("pqfs.header"),
            vec![0u8; (MAX_HEADER_BYTES + 1) as usize],
        )
        .unwrap();

        assert!(Crypto::load("pw", dir.path()).is_err());
    }
}

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport};
use ml_kem::{EncapsulationKey, Seed};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::keys::{SecretKey, derive_recipient_kek};
use super::{SEED_LEN, SELECTED_KEM_PARAM, SelectedKem};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct PublicIdentity {
    pub(crate) kem_param: u16,
    pub(crate) kem_public_key: Vec<u8>,
}

pub(crate) struct Identity {
    seed: Zeroizing<Vec<u8>>,
}

impl Identity {
    pub(crate) fn generate() -> Result<Self> {
        let (dk, _) = <SelectedKem as Kem>::generate_keypair();
        let seed = dk.to_seed().context("failed to extract ML-KEM seed")?;
        Ok(Self {
            seed: Zeroizing::new(AsRef::<[u8]>::as_ref(&seed).to_vec()),
        })
    }

    fn decapsulation_key(&self) -> Result<<SelectedKem as Kem>::DecapsulationKey> {
        let seed = Seed::try_from(self.seed.as_slice())
            .map_err(|_| anyhow::anyhow!("invalid ML-KEM seed"))?;
        Ok(<SelectedKem as Kem>::DecapsulationKey::from_seed(seed))
    }

    pub(crate) fn public(&self) -> Result<PublicIdentity> {
        let ek = self.decapsulation_key()?.encapsulation_key().clone();
        Ok(PublicIdentity {
            kem_param: SELECTED_KEM_PARAM,
            kem_public_key: AsRef::<[u8]>::as_ref(&ek.to_bytes()).to_vec(),
        })
    }

    pub(crate) fn recover_kek(&self, kem_ciphertext: &[u8]) -> Result<SecretKey> {
        let ct = ml_kem::kem::Ciphertext::<SelectedKem>::try_from(kem_ciphertext)
            .map_err(|_| anyhow::anyhow!("invalid ML-KEM ciphertext"))?;
        let shared_secret = self.decapsulation_key()?.decapsulate(&ct);
        derive_recipient_kek(AsRef::<[u8]>::as_ref(&shared_secret))
    }

    pub(crate) fn save(&self, path: &Path) -> Result<()> {
        write_private(path, self.seed.as_slice())
            .with_context(|| format!("failed to write {}", path.display()))
    }

    pub(crate) fn load(path: &Path) -> Result<Self> {
        let seed = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        if seed.len() != SEED_LEN {
            bail!("{} is not a pqfs identity", path.display());
        }
        Ok(Self {
            seed: Zeroizing::new(seed),
        })
    }
}

impl PublicIdentity {
    pub(crate) fn encapsulate(&self) -> Result<(Vec<u8>, SecretKey)> {
        if self.kem_param != SELECTED_KEM_PARAM {
            bail!(
                "recipient uses ML-KEM-{} but this binary is built for ML-KEM-{}",
                self.kem_param,
                SELECTED_KEM_PARAM
            );
        }
        let bytes = ml_kem::array::Array::try_from(self.kem_public_key.as_slice())
            .map_err(|_| anyhow::anyhow!("invalid ML-KEM public key length"))?;
        let ek = EncapsulationKey::<SelectedKem>::new(&bytes)
            .map_err(|_| anyhow::anyhow!("invalid ML-KEM public key"))?;
        let (ct, shared_secret) = ek.encapsulate();
        Ok((
            AsRef::<[u8]>::as_ref(&ct).to_vec(),
            derive_recipient_kek(AsRef::<[u8]>::as_ref(&shared_secret))?,
        ))
    }

    pub(crate) fn save(&self, path: &Path) -> Result<()> {
        let data = bincode::serialize(self)?;
        fs::write(path, data).with_context(|| format!("failed to write {}", path.display()))
    }

    pub(crate) fn load(path: &Path) -> Result<Self> {
        let data = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
        bincode::deserialize(&data)
            .with_context(|| format!("{} is not a pqfs public identity", path.display()))
    }
}

#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    fs::write(path, data)
}

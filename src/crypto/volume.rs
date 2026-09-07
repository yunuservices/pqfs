use std::fs;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result, bail};
use bincode::Options;
use rand::Rng;
use zeroize::Zeroizing;

use super::keys::{
    SecretKey, derive_header_mac_key, derive_password_key, header_mac, unwrap_master_key,
    verify_header_mac, wrap_master_key,
};
use super::{
    Crypto, HEADER_VERSION, Identity, KEY_LEN, KdfParams, KeySlot, MAC_LEN, MAX_HEADER_BYTES,
    PublicIdentity, SALT_LEN, VOLUME_ID_LEN, VolumeHeader,
};

pub(crate) enum Unlock<'a> {
    Password(&'a str),
    Identity(&'a Identity),
}

impl Crypto {
    pub(crate) const HEADER_FILE: &'static str = "pqfs.header";

    pub fn init(password: &str, backend: &Path) -> Result<Self> {
        Self::init_with_params(password, backend, KdfParams::default())
    }

    pub(crate) fn init_with_params(password: &str, backend: &Path, kdf: KdfParams) -> Result<Self> {
        fs::create_dir_all(backend)?;
        let header_path = backend.join(Self::HEADER_FILE);
        if header_path.exists() {
            bail!("volume already exists at {}", backend.display());
        }

        let mut master_key = Zeroizing::new([0u8; KEY_LEN]);
        rand::rng().fill_bytes(master_key.as_mut_slice());

        let mut volume_id = [0u8; VOLUME_ID_LEN];
        rand::rng().fill_bytes(&mut volume_id);

        let slot = password_slot(password, &volume_id, master_key.as_slice(), kdf)?;

        let mut header = VolumeHeader {
            version: HEADER_VERSION,
            volume_id,
            slots: vec![slot],
            mac: [0u8; MAC_LEN],
        };
        seal_header(&mut header, master_key.as_slice())?;

        let this = Self::from_master_key(master_key.as_slice(), header)?;
        this.save(backend)?;
        Ok(this)
    }

    #[cfg(test)]
    pub(crate) fn init_for_tests(password: &str, backend: &Path) -> Result<Self> {
        Self::init_with_params(password, backend, test_kdf())
    }

    /// Load an existing volume.
    #[cfg(test)]
    pub fn load(password: &str, backend: &Path) -> Result<Self> {
        Self::unlock(backend, Unlock::Password(password))
    }

    pub(crate) fn unlock(backend: &Path, credential: Unlock<'_>) -> Result<Self> {
        let header = read_header(backend)?;
        let master_key = open_master_key(&header, &credential)?;
        verify_header_mac(
            derive_header_mac_key(master_key.as_slice())?.as_slice(),
            &header,
        )?;
        Self::from_master_key(master_key.as_slice(), header)
    }

    pub(crate) fn save(&self, backend: &Path) -> Result<()> {
        let header_path = backend.join(Self::HEADER_FILE);
        let data = bincode::serialize(&self.header)?;
        fs::write(&header_path, data)?;
        Ok(())
    }
}

pub(crate) fn read_header(backend: &Path) -> Result<VolumeHeader> {
    let header_path = backend.join(Crypto::HEADER_FILE);
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
    Ok(header)
}

pub(crate) fn open_master_key(header: &VolumeHeader, credential: &Unlock<'_>) -> Result<SecretKey> {
    for slot in &header.slots {
        if let Some(master_key) = try_slot(header, slot, credential)? {
            return Ok(master_key);
        }
    }
    bail!("no key slot accepted the supplied credential")
}

fn try_slot(
    header: &VolumeHeader,
    slot: &KeySlot,
    credential: &Unlock<'_>,
) -> Result<Option<SecretKey>> {
    match (slot, credential) {
        (
            KeySlot::Password {
                salt,
                kdf,
                wrapped_master_key,
            },
            Unlock::Password(password),
        ) => {
            let kek = derive_password_key(password, salt, *kdf)?;
            Ok(unwrap_master_key(kek.as_slice(), &header.volume_id, wrapped_master_key).ok())
        }
        (
            KeySlot::Recipient {
                kem_ciphertext,
                wrapped_master_key,
                ..
            },
            Unlock::Identity(identity),
        ) => {
            let Ok(kek) = identity.recover_kek(kem_ciphertext) else {
                return Ok(None);
            };
            Ok(unwrap_master_key(kek.as_slice(), &header.volume_id, wrapped_master_key).ok())
        }
        _ => Ok(None),
    }
}

pub(crate) fn recipient_slot(
    recipient: &PublicIdentity,
    label: &str,
    volume_id: &[u8],
    master_key: &[u8],
) -> Result<KeySlot> {
    let (kem_ciphertext, kek) = recipient.encapsulate()?;
    Ok(KeySlot::Recipient {
        label: label.to_string(),
        kem_param: recipient.kem_param,
        kem_public_key: recipient.kem_public_key.clone(),
        kem_ciphertext,
        wrapped_master_key: wrap_master_key(kek.as_slice(), volume_id, master_key)?,
    })
}

pub(crate) fn password_slot(
    password: &str,
    volume_id: &[u8],
    master_key: &[u8],
    kdf: KdfParams,
) -> Result<KeySlot> {
    let mut salt = [0u8; SALT_LEN];
    rand::rng().fill_bytes(&mut salt);
    let kek = derive_password_key(password, &salt, kdf)?;
    Ok(KeySlot::Password {
        salt,
        kdf,
        wrapped_master_key: wrap_master_key(kek.as_slice(), volume_id, master_key)?,
    })
}

pub(crate) fn write_header(
    backend: &Path,
    header: &mut VolumeHeader,
    master_key: &[u8],
) -> Result<()> {
    seal_header(header, master_key)?;
    let path = backend.join(Crypto::HEADER_FILE);
    let tmp = path.with_extension("tmp");
    let data = bincode::serialize(header)?;

    let mut file =
        fs::File::create(&tmp).with_context(|| format!("failed to create {}", tmp.display()))?;
    file.write_all(&data)?;
    file.sync_all()?;
    drop(file);

    fs::rename(&tmp, &path)?;
    fs::File::open(backend)?.sync_all()?;
    Ok(())
}

pub(crate) fn seal_header(header: &mut VolumeHeader, master_key: &[u8]) -> Result<()> {
    header.mac = [0u8; MAC_LEN];
    let mac_key = derive_header_mac_key(master_key)?;
    header.mac = header_mac(mac_key.as_slice(), header)?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn test_kdf() -> KdfParams {
    KdfParams {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn volume(dir: &Path) -> Crypto {
        Crypto::init_for_tests("pw", dir).unwrap()
    }

    #[test]
    fn init_creates_a_single_password_slot() {
        let dir = tempfile::tempdir().unwrap();
        let crypto = volume(dir.path());
        assert_eq!(crypto.header.version, HEADER_VERSION);
        assert_eq!(crypto.header.slots.len(), 1);
        assert_eq!(crypto.header.slots[0].kind(), "password");
    }

    #[test]
    fn init_refuses_an_existing_volume() {
        let dir = tempfile::tempdir().unwrap();
        let _ = volume(dir.path());
        assert!(Crypto::init_for_tests("pw", dir.path()).is_err());
    }

    #[test]
    fn the_password_opens_the_volume_and_a_wrong_one_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let crypto = volume(dir.path());
        let ciphertext = crypto.encrypt(b"payload").unwrap();

        let loaded = Crypto::load("pw", dir.path()).unwrap();
        assert_eq!(loaded.decrypt(&ciphertext).unwrap(), b"payload");
        assert!(Crypto::load("wrong", dir.path()).is_err());
    }

    #[test]
    fn a_recipient_slot_opens_the_same_master_key() {
        let dir = tempfile::tempdir().unwrap();
        let crypto = volume(dir.path());
        let ciphertext = crypto.encrypt(b"payload").unwrap();

        let identity = Identity::generate().unwrap();
        let mut header = read_header(dir.path()).unwrap();
        let master_key = open_master_key(&header, &Unlock::Password("pw")).unwrap();
        header.slots.push(
            recipient_slot(
                &identity.public().unwrap(),
                "alice",
                &header.volume_id,
                master_key.as_slice(),
            )
            .unwrap(),
        );
        write_header(dir.path(), &mut header, master_key.as_slice()).unwrap();

        let opened = Crypto::unlock(dir.path(), Unlock::Identity(&identity)).unwrap();
        assert_eq!(opened.decrypt(&ciphertext).unwrap(), b"payload");
    }

    #[test]
    fn a_stranger_identity_does_not_open_the_volume() {
        let dir = tempfile::tempdir().unwrap();
        let crypto = volume(dir.path());

        let holder = Identity::generate().unwrap();
        let stranger = Identity::generate().unwrap();
        let mut header = read_header(dir.path()).unwrap();
        let master_key = open_master_key(&header, &Unlock::Password("pw")).unwrap();
        header.slots.push(
            recipient_slot(
                &holder.public().unwrap(),
                "holder",
                &header.volume_id,
                master_key.as_slice(),
            )
            .unwrap(),
        );
        write_header(dir.path(), &mut header, master_key.as_slice()).unwrap();

        assert!(Crypto::unlock(dir.path(), Unlock::Identity(&stranger)).is_err());
        drop(crypto);
    }

    #[test]
    fn a_slot_cannot_be_transplanted_into_another_volume() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let _ = volume(a.path());
        let _ = volume(b.path());

        let mut target = read_header(b.path()).unwrap();
        let source = read_header(a.path()).unwrap();
        target.slots.push(source.slots[0].clone());

        let master_key = open_master_key(&target, &Unlock::Password("pw")).unwrap();
        write_header(b.path(), &mut target, master_key.as_slice()).unwrap();

        let reloaded = read_header(b.path()).unwrap();
        assert!(
            try_slot(&reloaded, &reloaded.slots[1], &Unlock::Password("pw"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn load_rejects_a_tampered_slot_list() {
        let dir = tempfile::tempdir().unwrap();
        let crypto = volume(dir.path());

        let mut header = crypto.header.clone();
        header.slots.push(header.slots[0].clone());
        fs::write(
            dir.path().join(Crypto::HEADER_FILE),
            bincode::serialize(&header).unwrap(),
        )
        .unwrap();

        assert!(Crypto::load("pw", dir.path()).is_err());
    }

    #[test]
    fn load_rejects_an_oversized_header() {
        let dir = tempfile::tempdir().unwrap();
        let _ = volume(dir.path());
        fs::write(
            dir.path().join(Crypto::HEADER_FILE),
            vec![0u8; (MAX_HEADER_BYTES + 1) as usize],
        )
        .unwrap();

        assert!(Crypto::load("pw", dir.path()).is_err());
    }

    #[test]
    fn kdf_params_are_recorded_and_reused() {
        let dir = tempfile::tempdir().unwrap();
        let kdf = KdfParams {
            m_cost: 16,
            t_cost: 2,
            p_cost: 1,
        };
        let crypto = Crypto::init_with_params("pw", dir.path(), kdf).unwrap();
        match &crypto.header.slots[0] {
            KeySlot::Password { kdf: stored, .. } => assert_eq!(*stored, kdf),
            other => panic!("unexpected slot {other:?}"),
        }
        assert!(Crypto::load("pw", dir.path()).is_ok());
    }
}

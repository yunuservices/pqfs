use serde::{Deserialize, Serialize};

use super::{MAC_LEN, SALT_LEN, VOLUME_ID_LEN};

pub(crate) const HEADER_VERSION: u32 = 3;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KdfParams {
    pub(crate) m_cost: u32,
    pub(crate) t_cost: u32,
    pub(crate) p_cost: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m_cost: 131_072,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) enum KeySlot {
    Password {
        salt: [u8; SALT_LEN],
        kdf: KdfParams,
        wrapped_master_key: Vec<u8>,
    },
    Recipient {
        label: String,
        kem_param: u16,
        kem_public_key: Vec<u8>,
        kem_ciphertext: Vec<u8>,
        wrapped_master_key: Vec<u8>,
    },
}

impl KeySlot {
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            KeySlot::Password { .. } => "password",
            KeySlot::Recipient { .. } => "recipient",
        }
    }

    pub(crate) fn label(&self) -> &str {
        match self {
            KeySlot::Password { .. } => "",
            KeySlot::Recipient { label, .. } => label,
        }
    }
}

/// On-disk header stored in the backend root.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct VolumeHeader {
    pub(crate) version: u32,
    pub(crate) volume_id: [u8; VOLUME_ID_LEN],
    pub(crate) slots: Vec<KeySlot>,
    pub(crate) mac: [u8; MAC_LEN],
}

impl VolumeHeader {
    pub(crate) fn authenticated_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut unsigned = self.clone();
        unsigned.mac = [0u8; MAC_LEN];
        Ok(bincode::serialize(&unsigned)?)
    }
}

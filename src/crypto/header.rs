use serde::{Deserialize, Serialize};

use super::SALT_LEN;

/// On-disk header stored in the backend root.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct VolumeHeader {
    pub(crate) salt: [u8; SALT_LEN],
    pub(crate) kem_param: u16,
    pub(crate) kem_ciphertext: Vec<u8>,
    pub(crate) kem_public_key: Vec<u8>,
    pub(crate) encrypted_seed: Vec<u8>,
}

use serde::{Deserialize, Serialize};
use std::hash::Hash;

use crate::lwe::Ciphertext64;

pub const TAG_BYTES: usize = 128 / 8;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(pub u128);

impl SessionId {
    pub fn new(ciphertext: &Ciphertext64) -> anyhow::Result<SessionId> {
        let mut serialized_data = Vec::new();
        bincode::serialize_into(&mut serialized_data, &ciphertext)?;
        let digest = Self::hash_array(serialized_data);
        Ok(Self::digest_to_id(digest))
    }

    fn hash_array(to_hash: Vec<u8>) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(to_hash.as_slice());
        hasher.finalize()
    }

    fn digest_to_id(digest: blake3::Hash) -> SessionId {
        let mut array: [u8; TAG_BYTES] = [0; TAG_BYTES];
        array[..TAG_BYTES].copy_from_slice(&digest.as_bytes()[..TAG_BYTES]);
        SessionId(u128::from_le_bytes(array))
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)?;
        Ok(())
    }
}

impl From<u128> for SessionId {
    fn from(id: u128) -> Self {
        SessionId(id)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        computation::SessionId,
        lwe::Ciphertext64,
        tests::{helper::tests::generate_cipher, test_data_setup::tests::TEST_KEY_PATH},
    };

    #[test]
    fn sunshine() {
        let ct = generate_cipher(TEST_KEY_PATH, 0);
        // Validate that session ID is sufficiently large
        assert!(SessionId::new(&ct).unwrap().0 > 2_u128.pow(100));
    }

    #[test]
    fn determinism() {
        let ct_base = generate_cipher(TEST_KEY_PATH, 0);
        let base = SessionId::new(&ct_base);
        let ct_other: Ciphertext64 = generate_cipher(TEST_KEY_PATH, 0);
        // validate that the same input gives the same result
        assert_eq!(base.unwrap(), SessionId::new(&ct_other).unwrap());
    }

    #[test]
    fn uniqueness() {
        let ct_base: Ciphertext64 = generate_cipher(TEST_KEY_PATH, 0);
        let base = SessionId::new(&ct_base);
        let ct_other: Ciphertext64 = generate_cipher(TEST_KEY_PATH, 1);
        let other = SessionId::new(&ct_other);
        // Validate that a bit change results in a difference in session id
        assert_ne!(base.unwrap(), other.unwrap());
    }
}

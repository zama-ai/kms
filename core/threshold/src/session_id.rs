use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha3::{digest::ExtendableOutput, Shake128};

use crate::execution::endpoints::decryption::RadixOrBoolCiphertext;

pub const SESSION_ID_BYTES: usize = 128 / 8;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(pub u128);

impl SessionId {
    /// NOTE: this function is deprecated since the session IDs
    /// are always derived from request IDs.
    pub fn new(ciphertext: &RadixOrBoolCiphertext) -> anyhow::Result<SessionId> {
        let serialized_ct = bincode::serialize(ciphertext)?;

        // hash the serialized ct data into a 128-bit (SESSION_ID_BYTES) digest and convert to u128
        let mut hash = [0_u8; SESSION_ID_BYTES];
        Shake128::digest_xof(serialized_ct, &mut hash);
        Ok(SessionId(u128::from_le_bytes(hash)))
    }
}

impl FromStr for SessionId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut hash = [0_u8; SESSION_ID_BYTES];
        Shake128::digest_xof(s, &mut hash);
        Ok(SessionId(u128::from_le_bytes(hash)))
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
    use tfhe::{prelude::FheEncrypt, FheUint8};

    use crate::{
        execution::{
            constants::SMALL_TEST_KEY_PATH, endpoints::decryption::RadixOrBoolCiphertext,
            tfhe_internals::test_feature::KeySet,
        },
        file_handling::read_element,
        session_id::SessionId,
    };

    /// Indeterministic cipher generation.
    /// Encrypts a small message with deterministic randomness
    fn generate_cipher(_key_name: &str, message: u8) -> RadixOrBoolCiphertext {
        let keys: KeySet = read_element(SMALL_TEST_KEY_PATH).unwrap();
        let (ct, _id, _tag) = FheUint8::encrypt(message, &keys.client_key).into_raw_parts();
        RadixOrBoolCiphertext::Radix(ct)
    }

    #[test]
    fn sunshine() {
        let ct = generate_cipher(SMALL_TEST_KEY_PATH, 0);
        // Validate that session ID is sufficiently large
        assert!(SessionId::new(&ct).unwrap().0 > 2_u128.pow(100));
    }

    #[test]
    fn indeterminism() {
        let ct_base = generate_cipher(SMALL_TEST_KEY_PATH, 0);
        let base = SessionId::new(&ct_base);
        let ct_other = generate_cipher(SMALL_TEST_KEY_PATH, 0);
        // validate that the same input gives a different result
        assert_ne!(base.unwrap(), SessionId::new(&ct_other).unwrap());
    }

    #[test]
    fn uniqueness() {
        let ct_base = generate_cipher(SMALL_TEST_KEY_PATH, 0);
        let base = SessionId::new(&ct_base);
        let ct_other = generate_cipher(SMALL_TEST_KEY_PATH, 1);
        let other = SessionId::new(&ct_other);
        // Validate that a bit change results in a difference in session id
        assert_ne!(base.unwrap(), other.unwrap());
    }
}

use std::str::FromStr;

use serde::{Deserialize, Serialize};

use hashing::{serialize_hash_element, DomainSep};

pub const DSEP_SESSION_ID: DomainSep = *b"SESSN_ID";

pub const SESSION_ID_BYTES: usize = 128 / 8;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(u128);

impl SessionId {
    pub fn new(ciphertext: &impl Serialize) -> anyhow::Result<SessionId> {
        // hash the serialized ct data into a 128-bit (SESSION_ID_BYTES) digest and convert to u128
        let hash = serialize_hash_element(&DSEP_SESSION_ID, ciphertext)?;
        let mut hash_arr = [0_u8; SESSION_ID_BYTES];
        hash_arr.copy_from_slice(&hash[..SESSION_ID_BYTES]);
        Ok(SessionId(u128::from_le_bytes(hash_arr)))
    }

    pub fn to_le_bytes(&self) -> [u8; SESSION_ID_BYTES] {
        self.0.to_le_bytes()
    }

    pub fn to_be_bytes(&self) -> [u8; SESSION_ID_BYTES] {
        self.0.to_be_bytes()
    }
}

impl FromStr for SessionId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hash = serialize_hash_element(&DSEP_SESSION_ID, &s.to_string())?;
        let mut hash_arr = [0_u8; SESSION_ID_BYTES];
        hash_arr.copy_from_slice(&hash[..SESSION_ID_BYTES]);
        Ok(SessionId(u128::from_le_bytes(hash_arr)))
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

impl From<SessionId> for u128 {
    fn from(value: SessionId) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use tfhe::{prelude::FheEncrypt, FheUint8};

    use crate::SessionId;
    use execution::{
        constants::SMALL_TEST_KEY_PATH, endpoints::decryption::RadixOrBoolCiphertext,
        tfhe_internals::test_feature::KeySet,
    };
    use test_utils::read_element;

    // Indeterministic cipher generation.
    // Encrypts a small message with deterministic randomness
    fn generate_cipher(message: u8) -> RadixOrBoolCiphertext {
        let keys: KeySet = read_element(SMALL_TEST_KEY_PATH).unwrap();
        let (ct, _id, _tag, _rerand_metadata) =
            FheUint8::encrypt(message, &keys.client_key).into_raw_parts();
        RadixOrBoolCiphertext::Radix(ct)
    }

    #[test]
    fn indeterminism() {
        let ct_base = generate_cipher(0);
        let base = SessionId::new(&ct_base);
        let ct_other = generate_cipher(0);
        // validate that the same input gives a different result
        assert_ne!(base.unwrap(), SessionId::new(&ct_other).unwrap());
    }

    #[test]
    fn uniqueness() {
        let ct_base = generate_cipher(0);
        let base = SessionId::new(&ct_base);
        let ct_other = generate_cipher(1);
        let other = SessionId::new(&ct_other);
        // Validate that a bit change results in a difference in session id
        assert_ne!(base.unwrap(), other.unwrap());
    }

    #[test]
    fn sunshine() {
        let ct = generate_cipher(0);
        // Validate that session ID is sufficiently large
        assert!(SessionId::new(&ct).unwrap().0 > 2_u128.pow(100));
    }
}

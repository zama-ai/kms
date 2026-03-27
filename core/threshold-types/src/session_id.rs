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
    use super::SessionId;

    #[test]
    fn determinism() {
        // Same input must always produce the same session id.
        let dummy_ciphertext: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let a = SessionId::new(&dummy_ciphertext).unwrap();
        let b = SessionId::new(&dummy_ciphertext).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn uniqueness() {
        let ciphertext_a: Vec<u8> = vec![0x00; 64];
        let mut ciphertext_b: Vec<u8> = vec![0x00; 64];
        ciphertext_b[0] = 0x01;
        // Validate that a bit change results in a difference in session id
        assert_ne!(
            SessionId::new(&ciphertext_a).unwrap(),
            SessionId::new(&ciphertext_b).unwrap()
        );
    }

    #[test]
    fn sunshine() {
        let data: &[u8] = br#"{"ciphertext":"CAFEBABE","tag":"test-vector-sunshine"}"#;

        // Session id should use most of the 128-bit space.
        assert!(SessionId::new(&data).unwrap().0 > 2_u128.pow(100));
    }

    #[test]
    fn check_against_known_answer() {
        let data: &[u8] = br#"known-answer-test-vector"#;
        let id = SessionId::new(&data).unwrap();
        // If this breaks, the hashing logic or domain separator changed.
        assert_eq!(id.0, 144183619070594751274649460517890251705);
    }
}

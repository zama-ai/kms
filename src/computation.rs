use ndarray::Array1;
use serde::{Deserialize, Serialize};
use std::hash::Hash;

use crate::{lwe::Ciphertext, Z128};

pub const TAG_BYTES: usize = 128 / 8;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(pub u128);

impl SessionId {
    pub fn new(ciphertext: &Ciphertext) -> SessionId {
        let mut hasher = blake3::Hasher::new();
        // Hash each part of the ciphertext individually to avoid risk collisions
        // in case the a and b parts have *variable* and *distinct* sizes
        hasher.update(Self::hash_array(&ciphertext.a).as_bytes());
        hasher.update(Self::hash_array(&ciphertext.b).as_bytes());
        let digest = hasher.finalize();
        Self::digest_to_id(digest)
    }

    fn hash_array(to_hash: &Array1<Z128>) -> blake3::Hash {
        let mut hasher = blake3::Hasher::new();
        let bytes_to_hash = Self::to_byte_vec(to_hash);
        hasher.update(bytes_to_hash.as_slice());
        hasher.finalize()
    }

    fn to_byte_vec(input: &Array1<Z128>) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::with_capacity(TAG_BYTES * input.len());
        for elem in input.iter() {
            for cur_byte in elem.0.to_be_bytes() {
                res.push(cur_byte);
            }
        }
        res
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
    use ndarray::Array1;

    use crate::{computation::SessionId, lwe::Ciphertext, Z128};

    #[test]
    fn sunshine() {
        let a = Array1::<Z128>::zeros(16);
        let b = Array1::<Z128>::zeros(16);
        let ct = Ciphertext { a, b };
        // reference check, should be updated if semantics change
        assert_eq!(
            SessionId(105015842660904496297637409066838404456),
            SessionId::new(&ct)
        );
    }

    #[test]
    fn determinism() {
        let a = Array1::<Z128>::zeros(16);
        let b = Array1::<Z128>::zeros(16);
        let ct_base: Ciphertext = Ciphertext {
            a: a.clone(),
            b: b.clone(),
        };
        let base = SessionId::new(&ct_base);
        let ct_other: Ciphertext = Ciphertext { a, b };
        // validate that the same input gives the same result
        assert_eq!(base, SessionId::new(&ct_other));
    }

    #[test]
    fn uniqueness() {
        let mut a = Array1::<Z128>::zeros(16);
        let mut b = Array1::<Z128>::zeros(16);
        let ct_base: Ciphertext = Ciphertext {
            a: a.clone(),
            b: b.clone(),
        };
        let base = SessionId::new(&ct_base);
        b[0] += 1;
        let ct_other: Ciphertext = Ciphertext {
            a: a.clone(),
            b: b.clone(),
        };
        a[0] += 1;
        let ct_third: Ciphertext = Ciphertext { a, b };
        // Validate that a bit change results in a difference in session id
        assert_ne!(base, SessionId::new(&ct_other));
        assert_ne!(SessionId::new(&ct_third), SessionId::new(&ct_other));
        assert_ne!(base, SessionId::new(&ct_third));
    }
}

use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use sha3::{
    digest::ExtendableOutput,
    digest::{Update, XofReader},
    Shake256,
};

/// Byte size of a typical key or opening value (currently 16 byte = 128 bit)
pub(crate) const KEY_BYTE_LEN: usize = 16;

/// Byte size of a commitment value - twice the size of the opening value (currently 32 byte = 256 bit)
pub(crate) const COMMITMENT_BYTE_LEN: usize = 2 * KEY_BYTE_LEN;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Hash, Eq)]
pub struct Commitment(pub [u8; COMMITMENT_BYTE_LEN]);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Hash, Eq)]
pub struct Opening(pub [u8; KEY_BYTE_LEN]);

/// hash the given message and opening to compute the 256-bit commitment in the ROM
fn commitment_inner_hash(msg: &[u8], o: &Opening) -> Commitment {
    let mut com = [0u8; COMMITMENT_BYTE_LEN];
    let mut hasher = Shake256::default();
    hasher.update(&o.0);
    hasher.update(msg);
    let mut or = hasher.finalize_xof();
    or.read(&mut com);
    Commitment(com)
}

/// commit to msg and return a 256-bit commitment and 128-bit opening value
pub fn commit<R: Rng + CryptoRng>(msg: &[u8], rng: &mut R) -> (Commitment, Opening) {
    let mut opening = [0u8; KEY_BYTE_LEN];
    rng.fill_bytes(&mut opening);

    let o = Opening(opening);
    let com = commitment_inner_hash(msg, &o);
    (com, o)
}

/// verify that commitment c can be opened with o to retrieve msg
pub fn verify(msg: &[u8], com_to_check: &Commitment, o: &Opening) -> bool {
    let computed_commitment = commitment_inner_hash(msg, o);
    computed_commitment == *com_to_check
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_prng::AesRng;
    use rand::SeedableRng;

    #[test]
    fn test_commit_verify() {
        let msg = b"Let's commit to this message!";
        let mut rng = AesRng::seed_from_u64(0);
        let (com, opening) = commit(msg, &mut rng);
        assert!(verify(msg, &com, &opening));
    }

    #[test]
    fn test_commit_verify_fail() {
        let msg = b"Now commit to this other message";
        let mut rng = AesRng::seed_from_u64(1);
        let (com, opening) = commit(msg, &mut rng);

        assert!(verify(msg, &com, &opening));

        // check that verification fails for wrong values.
        let msg2 = b"wrong message here...";
        let com2 = Commitment(*b"00000000000000001111111111111111");
        let op2 = Opening(*b"0000000000000000");

        assert!(!verify(msg2, &com, &opening));
        assert!(!verify(msg, &com2, &opening));
        assert!(!verify(msg, &com, &op2));
    }
}

use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Byte size of a typical key or opening value (currently 16 byte = 128 bit)
pub(crate) const KEY_BYTE_LEN: usize = 16;

/// Byte size of a commitment value - twice the size of the opening value (currently 32 byte = 256 bit)
pub(crate) const COMMITMENT_BYTE_LEN: usize = 2 * KEY_BYTE_LEN;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Hash, Eq)]
pub struct Commitment(pub [u8; COMMITMENT_BYTE_LEN]);

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Hash, Eq)]
pub struct Opening(pub [u8; KEY_BYTE_LEN]);

/// Domain separator for commitments.
pub(crate) const DSEP_COMM: &[u8; 4] = b"COMM";

/// hash the given message and opening to compute the 256-bit commitment in the ROM
fn commitment_inner_hash(msg: &[u8], o: &Opening) -> Commitment {
    let mut hasher = Sha3_256::new();
    hasher.update(DSEP_COMM);
    hasher.update(msg);
    hasher.update(o.0);
    let digest = hasher.finalize();

    // the try_into should never fail because our tests will guarantee the lengths are correct
    let com: [u8; COMMITMENT_BYTE_LEN] = digest
        .as_slice()
        .try_into()
        .expect("wrong length in commmitment hash");
    Commitment(com)
}

//NIST: Level Zero Operation
/// commit to msg and return a 256-bit commitment and 128-bit opening value
pub fn commit<R: Rng + CryptoRng>(msg: &[u8], rng: &mut R) -> (Commitment, Opening) {
    let mut opening = [0u8; KEY_BYTE_LEN];
    rng.fill_bytes(&mut opening);

    let o = Opening(opening);
    let com = commitment_inner_hash(msg, &o);
    (com, o)
}

/// verify that commitment c can be opened with o and that it matches msg
pub fn verify(msg: &[u8], com_to_check: &Commitment, o: &Opening) -> anyhow::Result<()> {
    let computed_commitment = commitment_inner_hash(msg, o);
    if computed_commitment == *com_to_check {
        Ok(())
    } else {
        Err(anyhow::anyhow!("Commitment verification failed!"))
    }
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
        assert!(verify(msg, &com, &opening).is_ok());
    }

    #[test]
    fn test_commit_verify_fail() {
        let msg = b"Now commit to this other message";
        let mut rng = AesRng::seed_from_u64(1);
        let (com, opening) = commit(msg, &mut rng);

        assert!(verify(msg, &com, &opening).is_ok());

        // check that verification fails for wrong values.
        let msg_wrong = b"Wrong message here...";
        let com_wrong = Commitment([42u8; COMMITMENT_BYTE_LEN]);
        let opening_wrong = Opening([23u8; KEY_BYTE_LEN]);

        assert!(verify(msg_wrong, &com, &opening).is_err());
        assert!(verify(msg, &com_wrong, &opening).is_err());
        assert!(verify(msg, &com, &opening_wrong).is_err());
    }
}

//! EdDSA over ed25519 signing backend.

use super::SigningScheme;
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer, SigningKey as Ed25519SigningKey,
    VerifyingKey as Ed25519VerifyingKey,
};
use hashing::DomainSep;

/// The fixed encoded length of an ed25519 signature (`R‖s`), in bytes.
pub const SIG_SIZE: usize = 64;

/// The number of seed bytes consumed to build an ed25519 signing key.
pub const SEED_LEN: usize = 32;

/// Build an ed25519 signing key deterministically from a 32-byte seed.
pub fn keygen_from_seed(seed: &[u8; SEED_LEN]) -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(seed)
}

/// Marker type for the EdDSA/ed25519 signature scheme.
pub struct Ed25519;

impl SigningScheme for Ed25519 {
    type SigningKey = Ed25519SigningKey;
    type VerificationKey = Ed25519VerifyingKey;

    fn sign(dsep: &DomainSep, msg: &[u8], sk: &Ed25519SigningKey) -> anyhow::Result<Vec<u8>> {
        let signed = [&dsep[..], msg].concat();
        let sig: Ed25519Signature = sk.try_sign(&signed)?;
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(
        dsep: &DomainSep,
        msg: &[u8],
        sig: &[u8],
        vk: &Ed25519VerifyingKey,
    ) -> anyhow::Result<()> {
        let bytes: [u8; SIG_SIZE] = sig.try_into().map_err(|_| {
            anyhow::anyhow!(
                "expected {SIG_SIZE}-byte ed25519 signature, got {}",
                sig.len()
            )
        })?;
        let ed_sig = Ed25519Signature::from_bytes(&bytes);
        let signed = [&dsep[..], msg].concat();
        // `verify_strict` (not `verify`) rejects non-canonical `s` and
        // small-order / mixed-order public keys, so ed25519 signatures are
        // non-malleable here — matching the low-`s` normalization the ECDSA
        // backend enforces via `check_normalized`.
        vk.verify_strict(&signed, &ed_sig)
            .map_err(|e| anyhow::anyhow!("ed25519 verification failed: {e}"))
    }

    fn verifying_key(sk: &Ed25519SigningKey) -> anyhow::Result<Ed25519VerifyingKey> {
        Ok(sk.verifying_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_prng::AesRng;
    use rand::{RngCore, SeedableRng};

    const DSEP: &DomainSep = b"EDDSATST";

    fn seed<R: RngCore>(rng: &mut R) -> [u8; SEED_LEN] {
        let mut s = [0u8; SEED_LEN];
        rng.fill_bytes(&mut s);
        s
    }

    #[test]
    fn round_trip() {
        let mut rng = AesRng::seed_from_u64(1);
        let sk = keygen_from_seed(&seed(&mut rng));
        let vk = Ed25519::verifying_key(&sk).unwrap();
        let sig = Ed25519::sign(DSEP, b"hello", &sk).unwrap();
        assert_eq!(sig.len(), SIG_SIZE);
        Ed25519::verify(DSEP, b"hello", &sig, &vk).unwrap();
    }

    /// A signature of the wrong byte length is rejected before any curve work.
    #[test]
    fn rejects_wrong_length_signature() {
        let mut rng = AesRng::seed_from_u64(2);
        let sk = keygen_from_seed(&seed(&mut rng));
        let vk = Ed25519::verifying_key(&sk).unwrap();

        let err = Ed25519::verify(DSEP, b"hello", &[0u8; SIG_SIZE - 1], &vk).unwrap_err();
        assert!(err.to_string().contains("ed25519 signature"));
        assert!(Ed25519::verify(DSEP, b"hello", &[0u8; SIG_SIZE + 1], &vk).is_err());
    }

    /// A tampered message, a tampered signature, and a wrong domain separator all reject.
    #[test]
    fn rejects_tampering() {
        let mut rng = AesRng::seed_from_u64(3);
        let sk = keygen_from_seed(&seed(&mut rng));
        let vk = Ed25519::verifying_key(&sk).unwrap();
        let sig = Ed25519::sign(DSEP, b"hello", &sk).unwrap();

        assert!(Ed25519::verify(DSEP, b"HELLO", &sig, &vk).is_err());
        assert!(Ed25519::verify(b"OTHERDSP", b"hello", &sig, &vk).is_err());

        let mut bad = sig.clone();
        bad[0] ^= 0x01;
        assert!(Ed25519::verify(DSEP, b"hello", &bad, &vk).is_err());
    }
}

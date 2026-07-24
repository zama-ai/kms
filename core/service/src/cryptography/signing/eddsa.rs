//! EdDSA over ed25519 signing backend.

use super::SigningScheme;
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer, SigningKey as Ed25519SigningKey, Verifier,
    VerifyingKey as Ed25519VerifyingKey,
};
use hashing::DomainSep;

/// The fixed encoded length of an ed25519 signature (`R‖s`), in bytes.
pub const SIG_LEN: usize = 64;

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
        let bytes: [u8; SIG_LEN] = sig.try_into().map_err(|_| {
            anyhow::anyhow!(
                "expected {SIG_LEN}-byte ed25519 signature, got {}",
                sig.len()
            )
        })?;
        let ed_sig = Ed25519Signature::from_bytes(&bytes);
        let signed = [&dsep[..], msg].concat();
        vk.verify(&signed, &ed_sig)
            .map_err(|e| anyhow::anyhow!("ed25519 verification failed: {e}"))
    }

    fn verifying_key(sk: &Ed25519SigningKey) -> anyhow::Result<Ed25519VerifyingKey> {
        Ok(sk.verifying_key())
    }
}

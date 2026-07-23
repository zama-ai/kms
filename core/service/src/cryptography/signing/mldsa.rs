//! ML-DSA (FIPS 204) signing backend, generic over the parameter set.
//!
//! ML-DSA implements the `signature` v3 `Signer`/`Verifier` traits (imported
//! here directly from `ml_dsa`), distinct from the v2.2 traits used by the
//! ECDSA and ed25519 backends.

use hashing::DomainSep;
use ml_dsa::{
    B32, MlDsaParams, Signature as MlDsaSignature, SignatureEncoding, Signer,
    SigningKey as MlDsaSigningKey, Verifier, VerifyingKey as MlDsaVerifyingKey,
};

/// The number of seed bytes consumed to build an ML-DSA signing key.
pub const SEED_LEN: usize = 32;

/// Build an ML-DSA signing key deterministically from a 32-byte seed.
pub fn keygen_from_seed<P: MlDsaParams>(seed: &[u8; SEED_LEN]) -> MlDsaSigningKey<P> {
    let seed = B32::try_from(&seed[..]).expect("seed is exactly SEED_LEN bytes");
    MlDsaSigningKey::<P>::from_seed(&seed)
}

/// Derive the ML-DSA verification key from the signing key.
pub fn verifying_key<P: MlDsaParams>(sk: &MlDsaSigningKey<P>) -> MlDsaVerifyingKey<P> {
    sk.verifying_key()
}

/// Sign `dsep ‖ msg`, returning the FIPS 204 signature encoding for `P`.
pub fn sign<P: MlDsaParams>(
    dsep: &DomainSep,
    msg: &[u8],
    sk: &MlDsaSigningKey<P>,
) -> anyhow::Result<Vec<u8>> {
    let signed = [&dsep[..], msg].concat();
    let sig: MlDsaSignature<P> = sk
        .try_sign(&signed)
        .map_err(|e| anyhow::anyhow!("ML-DSA signing failed: {e}"))?;
    Ok(sig.to_vec())
}

/// Verify an ML-DSA signature over `dsep ‖ msg`.
pub fn verify<P: MlDsaParams>(
    dsep: &DomainSep,
    msg: &[u8],
    sig: &[u8],
    vk: &MlDsaVerifyingKey<P>,
) -> anyhow::Result<()> {
    let sig = MlDsaSignature::<P>::try_from(sig)
        .map_err(|e| anyhow::anyhow!("could not decode ML-DSA signature: {e}"))?;
    let signed = [&dsep[..], msg].concat();
    vk.verify(&signed, &sig)
        .map_err(|e| anyhow::anyhow!("ML-DSA verification failed: {e}"))
}

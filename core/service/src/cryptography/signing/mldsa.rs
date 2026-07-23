//! ML-DSA (FIPS 204) signing backend, generic over the parameter set.

use super::SigningScheme;
use core::marker::PhantomData;
use hashing::DomainSep;
use ml_dsa::{
    B32, Keypair, MlDsaParams, Signature as MlDsaSignature, SignatureEncoding, Signer,
    SigningKey as MlDsaSigningKey, Verifier, VerifyingKey as MlDsaVerifyingKey,
};

/// The number of seed bytes consumed to build an ML-DSA signing key.
pub const SEED_LEN: usize = 32;

/// Build an ML-DSA signing key deterministically from a 32-byte seed.
pub fn keygen_from_seed<P: MlDsaParams>(seed: &[u8; SEED_LEN]) -> MlDsaSigningKey<P> {
    let seed = B32::try_from(&seed[..]).expect("seed is exactly SEED_LEN bytes");
    MlDsaSigningKey::<P>::from_seed(&seed)
}

/// Marker type for the ML-DSA signature scheme with parameter set `P`.
pub struct MlDsa<P>(PhantomData<P>);

impl<P: MlDsaParams> SigningScheme for MlDsa<P> {
    type SigningKey = MlDsaSigningKey<P>;
    type VerificationKey = MlDsaVerifyingKey<P>;

    fn sign(dsep: &DomainSep, msg: &[u8], sk: &MlDsaSigningKey<P>) -> anyhow::Result<Vec<u8>> {
        let signed = [&dsep[..], msg].concat();
        let sig: MlDsaSignature<P> = sk
            .try_sign(&signed)
            .map_err(|e| anyhow::anyhow!("ML-DSA signing failed: {e}"))?;
        Ok(sig.to_vec())
    }

    fn verify(
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

    fn verifying_key(sk: &MlDsaSigningKey<P>) -> anyhow::Result<MlDsaVerifyingKey<P>> {
        Ok(sk.verifying_key())
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use aes_prng::AesRng;
    use ml_dsa::{MlDsa44, MlDsa65, MlDsa87};
    use rand::{RngCore, SeedableRng};

    const DSEP: &DomainSep = b"MLDSATST";

    fn seed<R: RngCore>(rng: &mut R) -> [u8; SEED_LEN] {
        let mut s = [0u8; SEED_LEN];
        rng.fill_bytes(&mut s);
        s
    }

    /// Round-trips, and rejects a tampered message, a wrong domain separator,
    /// a tampered signature, and a malformed (too short) signature.
    fn exercise<P: MlDsaParams>(seed_u64: u64) {
        let mut rng = AesRng::seed_from_u64(seed_u64);
        let sk = keygen_from_seed::<P>(&seed(&mut rng));
        let vk = MlDsa::<P>::verifying_key(&sk).unwrap();

        let sig = MlDsa::<P>::sign(DSEP, b"hello", &sk).unwrap();
        MlDsa::<P>::verify(DSEP, b"hello", &sig, &vk).unwrap();

        assert!(MlDsa::<P>::verify(DSEP, b"HELLO", &sig, &vk).is_err());
        assert!(MlDsa::<P>::verify(b"OTHERDSP", b"hello", &sig, &vk).is_err());

        let mut bad = sig.clone();
        bad[0] ^= 0x01;
        assert!(MlDsa::<P>::verify(DSEP, b"hello", &bad, &vk).is_err());

        let err = MlDsa::<P>::verify(DSEP, b"hello", &[0u8; 10], &vk).unwrap_err();
        assert!(err.to_string().contains("decode ML-DSA signature"));
    }

    #[test]
    fn all_param_sets() {
        exercise::<MlDsa44>(1);
        exercise::<MlDsa65>(2);
        exercise::<MlDsa87>(3);
    }
}

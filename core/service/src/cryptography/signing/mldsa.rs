//! ML-DSA (FIPS 204) signing backend, generic over the parameter set.

use super::{DSEP_SIGKEY_DIGEST, SigningError, SigningScheme, SigningSchemeType};
use core::marker::PhantomData;
use hashing::{DIGEST_BYTES, DomainSep, unsafe_hash_list_w_size};
use ml_dsa::{
    B32, KeyExport, Keypair, MlDsaParams, Signature as MlDsaSignature, SignatureEncoding, Signer,
    SigningKey as MlDsaSigningKey, Verifier, VerifyingKey as MlDsaVerifyingKey,
};

/// The number of seed bytes consumed to build an ML-DSA signing key.
pub const SEED_LEN: usize = 32;

/// Marker type for the ML-DSA signature scheme with parameter set `P`.
pub struct MlDsa<P>(PhantomData<P>);

impl<P: MlDsaParams> SigningScheme for MlDsa<P> {
    type SigningKey = MlDsaSigningKey<P>;
    type VerificationKey = MlDsaVerifyingKey<P>;

    fn sign(
        dsep: &DomainSep,
        msg: &[u8],
        sk: &MlDsaSigningKey<P>,
    ) -> Result<Vec<u8>, SigningError> {
        let signed = [&dsep[..], msg].concat();
        let sig: MlDsaSignature<P> = sk
            .try_sign(&signed)
            .map_err(|e| SigningError::Sign(e.to_string()))?;
        Ok(sig.to_vec())
    }

    fn verify(
        dsep: &DomainSep,
        msg: &[u8],
        sig: &[u8],
        vk: &MlDsaVerifyingKey<P>,
    ) -> Result<(), SigningError> {
        let sig = MlDsaSignature::<P>::try_from(sig)
            .map_err(|e| SigningError::MalformedSignature(e.to_string()))?;
        let signed = [&dsep[..], msg].concat();
        vk.verify(&signed, &sig)
            .map_err(|e| SigningError::Verify(e.to_string()))
    }

    fn verifying_key(sk: &MlDsaSigningKey<P>) -> Result<MlDsaVerifyingKey<P>, SigningError> {
        Ok(sk.verifying_key())
    }
}

impl<P: MlDsaParams> MlDsa<P> {
    /// Deterministically derive the signing key from a 32-byte seed.
    pub fn keygen_from_seed(seed: &[u8; SEED_LEN]) -> MlDsaSigningKey<P> {
        MlDsaSigningKey::<P>::from_seed(&B32::from(*seed))
    }

    /// The identifier of `vk`; a [`DIGEST_BYTES`] digest of the scheme's tag, concatenated with the key's bytes.
    pub fn digest(scheme: SigningSchemeType, vk: &MlDsaVerifyingKey<P>) -> Vec<u8> {
        let bytes = vk.to_bytes();
        unsafe_hash_list_w_size(
            &DSEP_SIGKEY_DIGEST,
            &[&scheme.tag()[..], bytes.as_ref()],
            DIGEST_BYTES,
        )
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
        let sk = MlDsa::<P>::keygen_from_seed(&seed(&mut rng));
        let vk = MlDsa::<P>::verifying_key(&sk).unwrap();

        let sig = MlDsa::<P>::sign(DSEP, b"hello", &sk).unwrap();
        MlDsa::<P>::verify(DSEP, b"hello", &sig, &vk).unwrap();

        assert!(MlDsa::<P>::verify(DSEP, b"HELLO", &sig, &vk).is_err());
        assert!(MlDsa::<P>::verify(b"OTHERDSP", b"hello", &sig, &vk).is_err());

        let mut bad = sig.clone();
        bad[0] ^= 0x01;
        assert!(MlDsa::<P>::verify(DSEP, b"hello", &bad, &vk).is_err());

        let err = MlDsa::<P>::verify(DSEP, b"hello", &[0u8; 10], &vk).unwrap_err();
        assert!(matches!(err, SigningError::MalformedSignature(_)));
    }

    #[test]
    fn all_param_sets() {
        exercise::<MlDsa44>(1);
        exercise::<MlDsa65>(2);
        exercise::<MlDsa87>(3);
    }
}

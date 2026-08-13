//! ML-DSA (FIPS 204) signing backend, generic over the parameter set.

use super::{DSEP_SIGKEY_DIGEST, SigningError, SigningScheme, SigningSchemeType};
use core::marker::PhantomData;
use hashing::{DIGEST_BYTES, DomainSep, unsafe_hash_list_w_size};
use ml_dsa::{
    B32, EncodedVerifyingKey, KeyExport, Keypair, MlDsaParams, Signature as MlDsaSignature,
    SignatureEncoding, Signer, SigningKey as MlDsaSigningKey, Verifier,
    VerifyingKey as MlDsaVerifyingKey,
};
use serde::{Deserialize, Serialize, de::Visitor};
use tfhe::named::Named;
use tfhe_versionable::{NotVersioned, Unversionize, Versionize, VersionizeOwned};

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

/// Persistable wrapper around an ML-DSA verifying key, generic over the
/// parameter set `P`.
///
/// Serializes as the fixed-size FIPS-204 `pkEncode` byte string (the same
/// encoding [`MlDsa::digest`] hashes). This is the object persisted for the ML-DSA
/// schemes, so a consumer needs only the FIPS-204 encoding — not the
/// [`super::UnifiedPublicSigKey`] tagged union — to read a node's published ML-DSA
/// identity.
pub struct MlDsaVerfKey<P: MlDsaParams>(pub(crate) MlDsaVerifyingKey<P>);

impl<P: MlDsaParams> Clone for MlDsaVerfKey<P> {
    fn clone(&self) -> Self {
        MlDsaVerfKey(self.0.clone())
    }
}

impl<P: MlDsaParams> std::fmt::Debug for MlDsaVerfKey<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("MlDsaVerfKey")
            .field(&self.0.encode())
            .finish()
    }
}

impl<P: MlDsaParams> PartialEq for MlDsaVerfKey<P> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<P: MlDsaParams> Named for MlDsaVerfKey<P> {
    const NAME: &'static str = "MlDsaVerfKey";
}

impl<P: MlDsaParams> Serialize for MlDsaVerfKey<P> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.0.encode().as_ref())
    }
}

impl<'de, P: MlDsaParams> Deserialize<'de> for MlDsaVerfKey<P> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_bytes(MlDsaVerfKeyVisitor(PhantomData))
    }
}

struct MlDsaVerfKeyVisitor<P: MlDsaParams>(PhantomData<P>);
impl<P: MlDsaParams> Visitor<'_> for MlDsaVerfKeyVisitor<P> {
    type Value = MlDsaVerfKey<P>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "an ML-DSA verifying key (pkEncode byte string)")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        // `try_from` enforces the exact `pkEncode` length; `decode` is then
        // infallible for a correctly sized encoding (FIPS-204 Algorithm 23).
        let enc =
            EncodedVerifyingKey::<P>::try_from(v).map_err(|_| E::invalid_length(v.len(), &self))?;
        Ok(MlDsaVerfKey(MlDsaVerifyingKey::<P>::decode(&enc)))
    }
}

impl<P: MlDsaParams> Versionize for MlDsaVerfKey<P> {
    type Versioned<'vers>
        = &'vers MlDsaVerfKey<P>
    where
        P: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        self
    }
}

impl<P: MlDsaParams> VersionizeOwned for MlDsaVerfKey<P> {
    type VersionedOwned = MlDsaVerfKey<P>;
    fn versionize_owned(self) -> Self::VersionedOwned {
        self
    }
}

impl<P: MlDsaParams> Unversionize for MlDsaVerfKey<P> {
    fn unversionize(
        versioned: Self::VersionedOwned,
    ) -> Result<Self, tfhe_versionable::UnversionizeError> {
        Ok(versioned)
    }
}

impl<P: MlDsaParams> NotVersioned for MlDsaVerfKey<P> {}

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

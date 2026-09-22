//! A signature made under several schemes at once.
//!
//! A composite signature is worth no more than the guarantee that *every* one of
//! its parts is present. Dropping the post-quantum half of an ECDSA+ML-DSA pair
//! must not leave something a verifier accepts, or the hedge the composite was
//! built for is gone.
//!
//! What makes that hold is that the scheme set is inside the bytes each
//! signature covers. A signature produced under `{A, B}` attests to that set, so
//! it cannot be re-presented as a complete signature under `{A}`.≠

use super::identity::NodeSigningIdentity;
use super::scheme_set::SigningSchemeSet;
use super::verf_key_set::VerfKeySet;
use super::{Signature, SigningError, unified_verify};
use hashing::DomainSep;
use serde::{Deserialize, Serialize};
use tfhe_versionable::{Versionize, VersionsDispatch};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, VersionsDispatch)]
pub enum CompositeSignatureVersions {
    V0(CompositeSignature),
}

/// One signature per scheme, over a message that commits to the scheme set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(CompositeSignatureVersions)]
pub struct CompositeSignature {
    schemes: SigningSchemeSet,
    signatures: Vec<Vec<u8>>,
}

impl CompositeSignature {
    /// The bytes every constituent signature is made over.
    pub fn preimage(schemes: &SigningSchemeSet, msg: &[u8]) -> Vec<u8> {
        // Note that the scheme should comes first and is length-prefixed
        [schemes.canonical_bytes().as_slice(), msg].concat()
    }

    /// Sign `msg` under every scheme in `schemes`.
    #[cfg(feature = "non-wasm")]
    pub fn sign(
        identity: &NodeSigningIdentity,
        schemes: &SigningSchemeSet,
        dsep: &DomainSep,
        msg: &[u8],
    ) -> Result<Self, SigningError> {
        identity.ensure_supported(schemes.as_slice())?;
        let preimage = Self::preimage(schemes, msg);
        let signatures = schemes
            .iter()
            .map(|scheme| {
                identity
                    .unified_sign_with(scheme, dsep, &preimage)
                    .map(|signature| signature.to_bytes())
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            schemes: schemes.clone(),
            signatures,
        })
    }

    /// Check every signature against `keys`, having first checked that this
    /// signature was made under exactly `expected`.
    ///
    /// Every signature must verify.
    pub fn verify(
        &self,
        keys: &VerfKeySet,
        expected: &SigningSchemeSet,
        dsep: &DomainSep,
        msg: &[u8],
    ) -> Result<(), SigningError> {
        // The scheme-set comparison happens before any cryptography,
        // so a composite signature presented with one of its parts removed is
        // rejected for being the wrong shape
        if self.schemes != *expected {
            return Err(SigningError::UnexpectedSchemeSet {
                expected: expected.to_string(),
                actual: self.schemes.to_string(),
            });
        }
        if self.schemes.len() != self.signatures.len() {
            return Err(SigningError::SignatureCountMismatch {
                schemes: self.schemes.len(),
                signatures: self.signatures.len(),
            });
        }
        let preimage = Self::preimage(&self.schemes, msg);
        // Note that we have just ensured `schemes` and `signatures` have same cardinality.
        for (scheme, bytes) in self.schemes.iter().zip(&self.signatures) {
            let signature = Signature::new(scheme, bytes.clone());
            unified_verify(dsep, &preimage, &signature, keys.require(scheme)?)?;
        }
        Ok(())
    }

    /// The schemes this signature was made under.
    pub fn schemes(&self) -> &SigningSchemeSet {
        &self.schemes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::signatures::{SigningSchemeType, gen_sig_keys};
    use crate::cryptography::signing::test_support::seeded_identity;
    use aes_prng::AesRng;
    use rand::SeedableRng;

    const DSEP: &DomainSep = b"COMPSIGT";
    const MSG: &[u8] = b"a message signed under several schemes at once";

    fn pair() -> SigningSchemeSet {
        SigningSchemeSet::new([SigningSchemeType::Ecdsa256k1, SigningSchemeType::MlDsa87]).unwrap()
    }

    fn setup(seed: u64) -> (NodeSigningIdentity, VerfKeySet, SigningSchemeSet) {
        let mut rng = AesRng::seed_from_u64(seed);
        let identity = seeded_identity(&mut rng);
        let schemes = pair();
        let keys = VerfKeySet::from_identity(&identity, &schemes).unwrap();
        (identity, keys, schemes)
    }

    #[test]
    fn round_trip_sunshine() {
        let (identity, keys, schemes) = setup(1);
        let sig = CompositeSignature::sign(&identity, &schemes, DSEP, MSG).unwrap();
        assert_eq!(sig.schemes(), &schemes);
        sig.verify(&keys, &schemes, DSEP, MSG).unwrap();
    }

    /// Removing a signature must not leave something that verifies under the remaining scheme.
    #[test]
    fn a_stripped_signature_is_rejected() {
        let (identity, keys, schemes) = setup(2);
        let sig = CompositeSignature::sign(&identity, &schemes, DSEP, MSG).unwrap();

        // Drop the ML-DSA half and relabel the set as ECDSA-only
        let stripped = CompositeSignature {
            schemes: SigningSchemeSet::single(SigningSchemeType::Ecdsa256k1),
            signatures: vec![sig.signatures[0].clone()],
        };

        // Against the original policy it is the wrong scheme set...
        assert!(matches!(
            stripped.verify(&keys, &schemes, DSEP, MSG),
            Err(SigningError::UnexpectedSchemeSet { .. })
        ));

        // ...and even if a verifier were talked into asking only for ECDSA, the
        // surviving signature covers a preimage naming the *pair*, so it does
        // not verify against the single-scheme preimage either.
        let ecdsa_only = SigningSchemeSet::single(SigningSchemeType::Ecdsa256k1);
        assert!(stripped.verify(&keys, &ecdsa_only, DSEP, MSG).is_err());
    }

    /// A signature list that disagrees with the scheme set in length is refused
    /// before any verification happens.
    #[test]
    fn a_signature_count_mismatch_is_rejected() {
        let (identity, keys, schemes) = setup(3);
        let sig = CompositeSignature::sign(&identity, &schemes, DSEP, MSG).unwrap();

        let mut short = sig.clone();
        short.signatures.pop();
        assert!(matches!(
            short.verify(&keys, &schemes, DSEP, MSG),
            Err(SigningError::SignatureCountMismatch { .. })
        ));

        let mut long = sig;
        long.signatures.push(vec![0u8; 64]);
        assert!(matches!(
            long.verify(&keys, &schemes, DSEP, MSG),
            Err(SigningError::SignatureCountMismatch { .. })
        ));
    }

    /// Every constituent signature has to verify; one bad one fails the whole.
    #[test]
    fn one_tampered_signature_fails_the_composite() {
        let (identity, keys, schemes) = setup(4);
        let base = CompositeSignature::sign(&identity, &schemes, DSEP, MSG).unwrap();

        for index in 0..base.signatures.len() {
            let mut tampered = base.clone();
            tampered.signatures[index][0] ^= 0x01;
            assert!(
                tampered.verify(&keys, &schemes, DSEP, MSG).is_err(),
                "tampering with signature {index} was not detected"
            );
        }
    }

    #[test]
    fn a_tampered_message_or_dsep_fails() {
        let (identity, keys, schemes) = setup(5);
        let sig = CompositeSignature::sign(&identity, &schemes, DSEP, MSG).unwrap();
        assert!(
            sig.verify(&keys, &schemes, DSEP, b"a different message")
                .is_err()
        );
        assert!(sig.verify(&keys, &schemes, b"OTHERDSP", MSG).is_err());
    }

    /// Signatures are checked against the key set presented, so another party's
    /// keys do not verify them.
    #[test]
    fn another_partys_keys_do_not_verify() {
        let (identity, keys, schemes) = setup(6);
        let (_, other_keys, _) = setup(7);
        let sig = CompositeSignature::sign(&identity, &schemes, DSEP, MSG).unwrap();

        sig.verify(&keys, &schemes, DSEP, MSG).unwrap();
        assert!(sig.verify(&other_keys, &schemes, DSEP, MSG).is_err());
    }

    /// A key set missing one of the schemes cannot verify, rather than skipping
    /// the scheme it has no key for.
    #[test]
    fn a_key_set_missing_a_scheme_is_rejected() {
        let (identity, _keys, schemes) = setup(8);
        let sig = CompositeSignature::sign(&identity, &schemes, DSEP, MSG).unwrap();

        let ecdsa_only = VerfKeySet::from_identity(
            &identity,
            &SigningSchemeSet::single(SigningSchemeType::Ecdsa256k1),
        )
        .unwrap();
        assert!(matches!(
            sig.verify(&ecdsa_only, &schemes, DSEP, MSG),
            Err(SigningError::NoVerificationKey(_))
        ));
    }

    /// An identity with no root seed can only do ECDSA, so asking it for the
    /// composite pair fails rather than producing a one-scheme signature.
    #[test]
    fn a_seedless_identity_cannot_sign_the_composite() {
        let mut rng = AesRng::seed_from_u64(9);
        let identity = NodeSigningIdentity::ecdsa_only(gen_sig_keys(&mut rng).1);
        assert!(matches!(
            CompositeSignature::sign(&identity, &pair(), DSEP, MSG),
            Err(SigningError::MissingRootSeed(_))
        ));
    }

    /// Distinct scheme sets give distinct preimages, which is what stops a
    /// signature crossing between them.
    #[test]
    fn preimages_separate_scheme_sets() {
        let single = SigningSchemeSet::single(SigningSchemeType::Ecdsa256k1);
        assert_ne!(
            CompositeSignature::preimage(&single, MSG),
            CompositeSignature::preimage(&pair(), MSG)
        );
    }
}

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
use super::typed_signature::StoredTypedSignature;
use super::verf_key_set::VerfKeySet;
use super::{Signature, SigningError, SigningSchemeType, unified_verify};
use hashing::DomainSep;
use serde::{Deserialize, Serialize};
use tfhe_versionable::{Versionize, VersionsDispatch};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, VersionsDispatch)]
pub enum CompositeSignatureVersions {
    V0(CompositeSignature),
}

/// One signature per scheme, over a message that commits to the scheme set.
///
/// Entries are ordered by scheme and carry no duplicate scheme.
///
/// The [`Deserialize`] impl *rejects* a non-canonical list rather than sorting it:
/// a value arriving from storage or the wire is attacker-chosen, and silently
/// reordering it would give one signature more than one encoding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Versionize)]
#[versionize(CompositeSignatureVersions)]
#[serde(transparent)]
pub struct CompositeSignature(Vec<StoredTypedSignature>);

impl<'de> Deserialize<'de> for CompositeSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let entries = Vec::<StoredTypedSignature>::deserialize(deserializer)?;
        Self::from_canonical(entries).map_err(serde::de::Error::custom)
    }
}

impl CompositeSignature {
    /// Accept `entries` only if they are already ordered by scheme, carry no
    /// duplicate scheme, and are non-empty.
    pub fn from_canonical(entries: Vec<StoredTypedSignature>) -> Result<Self, SigningError> {
        let schemes =
            SigningSchemeSet::from_canonical(entries.iter().map(|entry| entry.scheme).collect())?;
        debug_assert_eq!(schemes.len(), entries.len());
        Ok(Self(entries))
    }

    /// The entries, ordered by scheme.
    pub fn entries(&self) -> &[StoredTypedSignature] {
        &self.0
    }
    /// The bytes every constituent signature is made over.
    pub fn preimage(schemes: &SigningSchemeSet, msg: &[u8]) -> Vec<u8> {
        // Note that the scheme should comes first and is length-prefixed
        [schemes.canonical_bytes().as_slice(), msg].concat()
    }

    /// Sign `msg` under every scheme in `schemes`, each over the same bytes.
    #[cfg(feature = "non-wasm")]
    pub fn sign_uniform(
        identity: &NodeSigningIdentity,
        schemes: &SigningSchemeSet,
        dsep: &DomainSep,
        msg: &[u8],
    ) -> Result<Self, SigningError> {
        identity.ensure_supported(schemes.as_slice())?;
        let preimage = Self::preimage(schemes, msg);
        let entries = schemes
            .iter()
            .map(|scheme| {
                identity
                    .unified_sign_with(scheme, dsep, &preimage)
                    .map(|signature| StoredTypedSignature {
                        scheme,
                        signature: signature.to_bytes(),
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        // `schemes` is canonical, so the entries built from it are too.
        Ok(Self(entries))
    }

    /// Check every signature against `keys`, having first checked that this
    /// signature was made under exactly `expected`.
    ///
    /// Every signature must verify.
    pub fn verify_uniform(
        &self,
        keys: &VerfKeySet,
        expected: &SigningSchemeSet,
        dsep: &DomainSep,
        msg: &[u8],
    ) -> Result<(), SigningError> {
        // The scheme-set comparison happens before any cryptography,
        // so a composite signature presented with one of its parts removed is
        // rejected for being the wrong shape
        let schemes = self.schemes()?;
        if schemes != *expected {
            return Err(SigningError::UnexpectedSchemeSet {
                expected: expected.to_string(),
                actual: schemes.to_string(),
            });
        }
        let preimage = Self::preimage(&schemes, msg);
        for entry in &self.0 {
            let signature = Signature::new(entry.scheme, entry.signature.clone());
            unified_verify(dsep, &preimage, &signature, keys.require(entry.scheme)?)?;
        }
        Ok(())
    }

    /// The schemes this signature was made under, derived from its entries.
    pub fn schemes(&self) -> Result<SigningSchemeSet, SigningError> {
        SigningSchemeSet::new(self.0.iter().map(|entry| entry.scheme))
    }
}

/// The bytes a non-ECDSA result signature covers: the payload, prefixed by the
/// canonical scheme set.
///
/// `schemes` is canonicalised here, so callers may pass it in any order and
/// still agree on the bytes.
pub fn result_signed_bytes(
    schemes: &[SigningSchemeType],
    payload_bytes: &[u8],
) -> Result<Vec<u8>, SigningError> {
    let schemes = SigningSchemeSet::new(schemes.iter().copied())?;
    Ok(CompositeSignature::preimage(&schemes, payload_bytes))
}

/// The per-scheme signatures of a *result*: a keygen, CRS, preprocessing or
/// decryption response.
///
/// ECDSA signs `eip712_hash` recoverably, producing the signature the fhevm
/// contracts verify on chain. Every other scheme signs `dsep ‖ payload_bytes`.
///
/// Returns the entries rather than a [`CompositeSignature`] because a result may
/// legitimately request no schemes at all, which that type refuses to represent.
///
/// WARNING: the non-ECDSA entries here are *not* yet bound to the scheme set, so a
/// verifier must still check the schemes it receives against the ones it asked
/// for!
#[cfg(feature = "non-wasm")]
pub fn sign_result_entries(
    identity: &NodeSigningIdentity,
    schemes: &[SigningSchemeType],
    dsep: &DomainSep,
    eip712_hash: &[u8],
    payload_bytes: &[u8],
) -> Result<Vec<StoredTypedSignature>, SigningError> {
    if schemes.is_empty() {
        return Ok(Vec::new());
    }
    // Every non-ECDSA entry commits to the scheme set, so one cannot be lifted
    // out of a larger response and presented as a complete smaller one.
    let signed = result_signed_bytes(schemes, payload_bytes)?;
    schemes
        .iter()
        .map(|&scheme| {
            let signature = match scheme {
                SigningSchemeType::Ecdsa256k1 => {
                    let hash = alloy_primitives::B256::try_from(eip712_hash).map_err(|_| {
                        SigningError::Sign(format!(
                            "EIP-712 signing hash must be 32 bytes, got {}",
                            eip712_hash.len()
                        ))
                    })?;
                    crate::cryptography::signing::ecdsa::eip712_sign_hash(identity.ecdsa(), &hash)
                        .map_err(|e| SigningError::Sign(e.to_string()))?
                }
                _ => identity
                    .unified_sign_with(scheme, dsep, &signed)?
                    .to_bytes(),
            };
            Ok(StoredTypedSignature { scheme, signature })
        })
        .collect()
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
        let sig = CompositeSignature::sign_uniform(&identity, &schemes, DSEP, MSG).unwrap();
        assert_eq!(sig.schemes().unwrap(), schemes);
        sig.verify_uniform(&keys, &schemes, DSEP, MSG).unwrap();
    }

    /// Removing a signature must not leave something that verifies under the remaining scheme.
    #[test]
    fn a_stripped_signature_is_rejected() {
        let (identity, keys, schemes) = setup(2);
        let sig = CompositeSignature::sign_uniform(&identity, &schemes, DSEP, MSG).unwrap();

        // Drop the ML-DSA half and relabel the set as ECDSA-only
        let stripped = CompositeSignature::from_canonical(vec![sig.entries()[0].clone()]).unwrap();

        // Against the original policy it is the wrong scheme set...
        assert!(matches!(
            stripped.verify_uniform(&keys, &schemes, DSEP, MSG),
            Err(SigningError::UnexpectedSchemeSet { .. })
        ));

        // ...and even if a verifier were talked into asking only for ECDSA, the
        // surviving signature covers a preimage naming the *pair*, so it does
        // not verify against the single-scheme preimage either.
        let ecdsa_only = SigningSchemeSet::single(SigningSchemeType::Ecdsa256k1);
        assert!(
            stripped
                .verify_uniform(&keys, &ecdsa_only, DSEP, MSG)
                .is_err()
        );
    }

    /// A list that is not ordered by scheme, or repeats one, is refused on
    /// deserialization rather than normalised.
    #[test]
    fn a_non_canonical_entry_list_is_rejected() {
        let (identity, _keys, schemes) = setup(3);
        let sig = CompositeSignature::sign_uniform(&identity, &schemes, DSEP, MSG).unwrap();
        let entries = sig.entries().to_vec();

        let mut reversed = entries.clone();
        reversed.reverse();
        assert!(CompositeSignature::from_canonical(reversed).is_err());

        let duplicated = vec![entries[0].clone(), entries[0].clone()];
        assert!(CompositeSignature::from_canonical(duplicated).is_err());

        assert!(CompositeSignature::from_canonical(Vec::new()).is_err());
    }

    /// Every constituent signature has to verify; one bad one fails the whole.
    #[test]
    fn one_tampered_signature_fails_the_composite() {
        let (identity, keys, schemes) = setup(4);
        let base = CompositeSignature::sign_uniform(&identity, &schemes, DSEP, MSG).unwrap();

        for index in 0..base.entries().len() {
            let mut entries = base.entries().to_vec();
            entries[index].signature[0] ^= 0x01;
            let tampered = CompositeSignature::from_canonical(entries).unwrap();
            assert!(
                tampered.verify_uniform(&keys, &schemes, DSEP, MSG).is_err(),
                "tampering with signature {index} was not detected"
            );
        }
    }

    #[test]
    fn a_tampered_message_or_dsep_fails() {
        let (identity, keys, schemes) = setup(5);
        let sig = CompositeSignature::sign_uniform(&identity, &schemes, DSEP, MSG).unwrap();
        assert!(
            sig.verify_uniform(&keys, &schemes, DSEP, b"a different message")
                .is_err()
        );
        assert!(
            sig.verify_uniform(&keys, &schemes, b"OTHERDSP", MSG)
                .is_err()
        );
    }

    /// Signatures are checked against the key set presented, so another party's
    /// keys do not verify them.
    #[test]
    fn another_partys_keys_do_not_verify() {
        let (identity, keys, schemes) = setup(6);
        let (_, other_keys, _) = setup(7);
        let sig = CompositeSignature::sign_uniform(&identity, &schemes, DSEP, MSG).unwrap();

        sig.verify_uniform(&keys, &schemes, DSEP, MSG).unwrap();
        assert!(
            sig.verify_uniform(&other_keys, &schemes, DSEP, MSG)
                .is_err()
        );
    }

    /// A key set missing one of the schemes cannot verify, rather than skipping
    /// the scheme it has no key for.
    #[test]
    fn a_key_set_missing_a_scheme_is_rejected() {
        let (identity, _keys, schemes) = setup(8);
        let sig = CompositeSignature::sign_uniform(&identity, &schemes, DSEP, MSG).unwrap();

        let ecdsa_only = VerfKeySet::from_identity(
            &identity,
            &SigningSchemeSet::single(SigningSchemeType::Ecdsa256k1),
        )
        .unwrap();
        assert!(matches!(
            sig.verify_uniform(&ecdsa_only, &schemes, DSEP, MSG),
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
            CompositeSignature::sign_uniform(&identity, &pair(), DSEP, MSG),
            Err(SigningError::MissingRootSeed(_))
        ));
    }

    /// The result shape splits by scheme: ECDSA signs the EIP-712 hash, every
    /// other scheme signs the payload.
    #[test]
    fn result_entries_split_ecdsa_from_the_rest() {
        let mut rng = AesRng::seed_from_u64(20);
        let identity = seeded_identity(&mut rng);
        let schemes = [
            SigningSchemeType::Ecdsa256k1,
            SigningSchemeType::Ed25519,
            SigningSchemeType::MlDsa65,
        ];
        let eip712_hash = [0x11u8; 32];
        let payload = b"the serialized result payload";

        let entries =
            sign_result_entries(&identity, &schemes, DSEP, &eip712_hash, payload).unwrap();
        assert_eq!(entries.len(), 3);

        for entry in &entries {
            if entry.scheme == SigningSchemeType::Ecdsa256k1 {
                // Recoverable EIP-712 signature: 65 bytes, and not a signature
                // over the payload.
                assert_eq!(entry.signature.len(), 65);
                continue;
            }
            let vk = identity.unified_verifying_key(entry.scheme).unwrap();
            let sig = Signature::new(entry.scheme, entry.signature.clone());
            unified_verify(DSEP, payload, &sig, &vk)
                .unwrap_or_else(|e| panic!("{:?} should sign the payload: {e}", entry.scheme));
            // ...and not the EIP-712 hash.
            assert!(unified_verify(DSEP, &eip712_hash, &sig, &vk).is_err());
        }
    }

    /// No schemes requested means no per-scheme entries, which is why this
    /// returns a plain list rather than a `CompositeSignature`.
    #[test]
    fn result_entries_tolerate_an_empty_request() {
        let mut rng = AesRng::seed_from_u64(21);
        let identity = seeded_identity(&mut rng);
        assert!(
            sign_result_entries(&identity, &[], DSEP, &[0u8; 32], b"payload")
                .unwrap()
                .is_empty()
        );
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

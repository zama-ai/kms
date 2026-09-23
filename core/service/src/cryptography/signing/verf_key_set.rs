//! The verification keys one party publishes, one per signature scheme.

use super::identity::NodeSigningIdentity;
use super::{SigningError, SigningSchemeType, UnifiedPublicSigKey};
use hashing::{DomainSep, hash_element};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Domain separator for the digest that identifies a whole verification-key set.
const DSEP_VERF_KEY_SET: DomainSep = *b"VKEYSET_";

/// One party's verification keys, keyed by the scheme each belongs to.
///
/// The counterpart of [`NodeSigningIdentity`] on the verifying side: an identity
/// signs under several schemes, so a verifier needs several keys, and needs them
/// to travel together.
///
/// Not versioned since this is an in-memory only structure.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VerfKeySet {
    keys: BTreeMap<SigningSchemeType, UnifiedPublicSigKey>,
}

impl VerfKeySet {
    /// A non-empty key set from `keys`, checking that each key belongs to the
    /// scheme it is filed under.
    pub fn new(
        keys: BTreeMap<SigningSchemeType, UnifiedPublicSigKey>,
    ) -> Result<Self, SigningError> {
        if keys.is_empty() {
            return Err(SigningError::EmptySchemeSet);
        }
        for (scheme, key) in &keys {
            let actual = key.signing_scheme_type();
            if actual != *scheme {
                return Err(SigningError::SchemeMismatch {
                    signature: *scheme,
                    key: actual,
                });
            }
        }
        Ok(Self { keys })
    }

    /// The key set `identity` publishes for `schemes`.
    pub fn from_identity(
        identity: &NodeSigningIdentity,
        schemes: &[SigningSchemeType],
    ) -> Result<Self, SigningError> {
        let mut keys = BTreeMap::new();
        for &scheme in schemes {
            keys.insert(scheme, identity.unified_verifying_key(scheme)?);
        }
        Self::new(keys)
    }

    /// The schemes this set holds keys for, in canonical order.
    pub fn schemes(&self) -> Vec<SigningSchemeType> {
        // Canonical order is based on the underlying BTreeMap order
        self.keys.keys().copied().collect()
    }

    /// The key for `scheme`, if the set holds one.
    pub fn get(&self, scheme: SigningSchemeType) -> Option<&UnifiedPublicSigKey> {
        self.keys.get(&scheme)
    }

    /// The key for `scheme`, or an error naming the scheme that is missing.
    pub fn require(&self, scheme: SigningSchemeType) -> Result<&UnifiedPublicSigKey, SigningError> {
        self.get(scheme)
            .ok_or(SigningError::NoVerificationKey(scheme))
    }

    /// The identifier of this key set.
    ///
    /// A digest over every member key, so changing, adding or removing one
    /// changes the identity.
    pub fn id(&self) -> Result<Vec<u8>, SigningError> {
        Ok(hash_element(&DSEP_VERF_KEY_SET, &self.canonical_bytes()?))
    }

    /// The unambiguous byte encoding of this key set, for use inside a digest.
    fn canonical_bytes(&self) -> Result<Vec<u8>, SigningError> {
        let mut out = Vec::new();
        // Bounded by the number of known schemes, so the cast cannot truncate.
        out.extend_from_slice(&(self.keys.len() as u32).to_le_bytes());
        // Note that this is deterministic based on the `Ord` implementation of SigningSchemeType.
        for (scheme, key) in &self.keys {
            out.extend_from_slice(&scheme.tag());
            let bytes = key.digest();
            out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            out.extend_from_slice(&bytes);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::signing::test_support::seeded_identity;
    use aes_prng::AesRng;
    use rand::SeedableRng;
    use strum::IntoEnumIterator;

    #[test]
    fn from_identity_covers_every_requested_scheme() {
        let mut rng = AesRng::seed_from_u64(1);
        let identity = seeded_identity(&mut rng);
        let schemes: Vec<_> = SigningSchemeType::iter().collect();
        let set = VerfKeySet::from_identity(&identity, &schemes).unwrap();

        assert_eq!(set.schemes(), schemes);
        for &scheme in &schemes {
            let key = set.require(scheme).unwrap();
            assert_eq!(key.signing_scheme_type(), scheme);
            assert_eq!(key, &identity.unified_verifying_key(scheme).unwrap());
        }
    }

    /// A seedless identity can only do ECDSA, so asking it for more must fail
    /// rather than yield a smaller set than requested.
    #[test]
    fn from_identity_fails_without_a_root_seed() {
        let mut rng = AesRng::seed_from_u64(2);
        let (_pk, sk) = crate::cryptography::signatures::gen_sig_keys(&mut rng);
        let identity = NodeSigningIdentity::ecdsa_only(sk);

        VerfKeySet::from_identity(&identity, &[SigningSchemeType::Ecdsa256k1]).unwrap();

        let all: Vec<_> = SigningSchemeType::iter().collect();
        assert!(matches!(
            VerfKeySet::from_identity(&identity, &all),
            Err(SigningError::MissingRootSeed(_))
        ));
    }

    #[test]
    fn a_key_filed_under_the_wrong_scheme_is_rejected() {
        let mut rng = AesRng::seed_from_u64(3);
        let identity = seeded_identity(&mut rng);
        let ecdsa = identity
            .unified_verifying_key(SigningSchemeType::Ecdsa256k1)
            .unwrap();

        let mut keys = BTreeMap::new();
        keys.insert(SigningSchemeType::MlDsa87, ecdsa);
        assert!(matches!(
            VerfKeySet::new(keys),
            Err(SigningError::SchemeMismatch { .. })
        ));

        assert!(matches!(
            VerfKeySet::new(BTreeMap::new()),
            Err(SigningError::EmptySchemeSet)
        ));
    }

    /// The id names the whole set: swapping any single member key changes it.
    #[test]
    fn id_changes_when_any_member_key_changes() {
        let mut rng = AesRng::seed_from_u64(4);
        let identity = seeded_identity(&mut rng);
        let other_identity = seeded_identity(&mut rng);
        let schemes: Vec<_> = SigningSchemeType::iter().collect();

        let base = VerfKeySet::from_identity(&identity, &schemes).unwrap();
        let base_id = base.id().unwrap();
        assert_eq!(base_id, base.id().unwrap(), "the id is not deterministic");

        for &scheme in &schemes {
            let mut swapped = base.keys.clone();
            swapped.insert(
                scheme,
                other_identity.unified_verifying_key(scheme).unwrap(),
            );
            let swapped = VerfKeySet::new(swapped).unwrap();
            assert_ne!(
                base_id,
                swapped.id().unwrap(),
                "swapping the {scheme} key left the set id unchanged"
            );
        }

        // Dropping a scheme is also a different identity, not a weaker form of
        // the same one.
        let mut fewer = base.keys.clone();
        fewer.remove(&SigningSchemeType::MlDsa87);
        let fewer = VerfKeySet::new(fewer).unwrap();
        assert_ne!(base_id, fewer.id().unwrap());
    }
}

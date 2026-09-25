//! The verification keys one party publishes, one per signature scheme.

use super::identity::NodeSigningIdentity;
use super::{HasSigningScheme, SigningError, SigningSchemeType, UnifiedPublicSigKey};
use hashing::{DomainSep, hash_element};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;
use tfhe::named::Named;
use tfhe_versionable::{Versionize, VersionsDispatch};

/// Domain separator for the digest that identifies a whole verification-key set.
const DSEP_VERF_KEY_SET: DomainSep = *b"VKEYSET_";

/// One party's verification keys, keyed by the scheme each belongs to.
///
/// The counterpart of [`NodeSigningIdentity`] on the verifying side: an identity
/// signs under several schemes, so a verifier needs several keys, and needs them
/// to travel together.
///
/// The set is persisted, so it is versioned. Its own shape is tagged by
/// [`VerfKeySetVersions`], and the scheme tags and keys inside it each carry
/// their own dispatch, so a later change to [`UnifiedPublicSigKey`] is handled
/// by `UnifiedPublicSigKeyVersions` without a new version here.
///
/// # Invariants
///
/// The set is non-empty, and every key is filed under the scheme it actually
/// belongs to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Versionize)]
#[serde(transparent)]
#[versionize(try_convert = "VerfKeySetRepr")]
pub struct VerfKeySet {
    keys: BTreeMap<SigningSchemeType, UnifiedPublicSigKey>,
}

impl Named for VerfKeySet {
    const NAME: &'static str = "VerfKeySet";
}

/// The unvalidated mirror of [`VerfKeySet`] that carries the version dispatch.
/// way back from a versioned artifact, so both paths check the same invariants.
///
/// The mirror is a newtype over the map, so the stored bytes hold the versioned
/// map and no extra field.
#[derive(Versionize)]
#[versionize(VerfKeySetVersions)]
pub struct VerfKeySetRepr(BTreeMap<SigningSchemeType, UnifiedPublicSigKey>);

#[derive(VersionsDispatch)]
pub enum VerfKeySetVersions {
    V0(VerfKeySetRepr),
}

impl From<VerfKeySet> for VerfKeySetRepr {
    fn from(value: VerfKeySet) -> Self {
        Self(value.keys)
    }
}

/// Reading a set back re-establishes the invariants.
impl TryFrom<VerfKeySetRepr> for VerfKeySet {
    type Error = SigningError;

    fn try_from(versioned: VerfKeySetRepr) -> Result<Self, Self::Error> {
        Self::new(versioned.0)
    }
}

impl<'de> Deserialize<'de> for VerfKeySet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let keys = BTreeMap::<SigningSchemeType, UnifiedPublicSigKey>::deserialize(deserializer)?;
        Self::new(keys).map_err(serde::de::Error::custom)
    }
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
    use tfhe_versionable::{Unversionize, UnversionizeError, VersionizeOwned};

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

    /// A misfiled key and an empty set are both refused, by the constructor and
    /// on deserialization alike.
    #[test]
    fn the_invariants_hold_for_a_built_and_a_deserialized_set() {
        let mut rng = AesRng::seed_from_u64(3);
        let identity = seeded_identity(&mut rng);
        let ecdsa = identity
            .unified_verifying_key(SigningSchemeType::Ecdsa256k1)
            .unwrap();

        // A well-formed set survives the round trip.
        let good = VerfKeySet::new(BTreeMap::from([(
            SigningSchemeType::Ecdsa256k1,
            ecdsa.clone(),
        )]))
        .unwrap();
        let bytes = bc2wrap::serialize(&good).unwrap();
        assert_eq!(
            bc2wrap::deserialize_slice::<VerfKeySet>(&bytes).unwrap(),
            good
        );

        // A key filed under a scheme it does not belong to.
        let misfiled = BTreeMap::from([(SigningSchemeType::MlDsa87, ecdsa)]);
        assert!(matches!(
            VerfKeySet::new(misfiled.clone()),
            Err(SigningError::SchemeMismatch { .. })
        ));
        let bytes = bc2wrap::serialize(&misfiled).unwrap();
        assert!(bc2wrap::deserialize_slice::<VerfKeySet>(&bytes).is_err());

        // The empty set, which would make `verify_composite` accept a signature
        // list having checked nothing.
        let empty = BTreeMap::<SigningSchemeType, UnifiedPublicSigKey>::new();
        assert!(matches!(
            VerfKeySet::new(empty.clone()),
            Err(SigningError::EmptySchemeSet)
        ));
        let bytes = bc2wrap::serialize(&empty).unwrap();
        assert!(bc2wrap::deserialize_slice::<VerfKeySet>(&bytes).is_err());

        // The versioned path re-checks both invariants as well.
        assert_eq!(
            VerfKeySet::unversionize(good.clone().versionize_owned()).unwrap(),
            good
        );
        for bad in [misfiled, empty] {
            let smuggled = VerfKeySetRepr(bad).versionize_owned();
            assert!(matches!(
                VerfKeySet::unversionize(smuggled),
                Err(UnversionizeError::Conversion { .. })
            ));
        }
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

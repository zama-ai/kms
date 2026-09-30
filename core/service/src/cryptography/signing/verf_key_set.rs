//! The verification keys one party publishes, one per signature scheme.

use super::ecdsa::PublicSigKey;
use super::identity::NodeSigningIdentity;
use super::{
    HasSigningScheme, SigningError, SigningSchemeType, UnifiedPublicSigKey, canonical_schemes,
};
use hashing::{DomainSep, hash_element};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;
use tfhe::named::Named;
use tfhe_versionable::{Versionize, VersionsDispatch};

/// Domain separator for the digest that identifies the keys a signature is made with.
const DSEP_VERF_KEY_SET: DomainSep = *b"VKEYSET_";

/// One party's verification keys, keyed by the scheme each belongs to.
///
/// The counterpart of [`NodeSigningIdentity`] on the verifying side: an identity
/// signs under several schemes, so a verifier needs several keys, and needs them
/// to travel together.
///
/// # Invariants
///
/// The set is non-empty, and every key is filed under the scheme it actually
/// belongs to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Versionize)]
#[serde(transparent)]
#[versionize(try_convert = "VerfKeySetRepr")]
pub struct VerfKeySet {
    pub(crate) keys: BTreeMap<SigningSchemeType, UnifiedPublicSigKey>,
}

impl Named for VerfKeySet {
    const NAME: &'static str = "VerfKeySet";
}

/// The unvalidated mirror of [`VerfKeySet`] that carries the version dispatch.
///
/// `try_convert` versions the target type, not `VerfKeySet` itself, so the
/// dispatch enum is named after this type rather than after the validated one.
#[derive(Versionize)]
#[versionize(VerfKeySetReprVersions)]
pub struct VerfKeySetRepr(BTreeMap<SigningSchemeType, UnifiedPublicSigKey>);

#[derive(VersionsDispatch)]
pub enum VerfKeySetReprVersions {
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

    /// The set holding nothing but the ECDSA key `key`.
    pub fn ecdsa_only(key: PublicSigKey) -> Self {
        // Non-empty and correctly filed, so the invariants hold without `new`.
        Self {
            keys: BTreeMap::from([(
                SigningSchemeType::Ecdsa256k1,
                UnifiedPublicSigKey::Ecdsa256k1(key),
            )]),
        }
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

    /// The ECDSA member of this set.
    /// Purely a convenience helper method
    pub fn ecdsa(&self) -> Result<&PublicSigKey, SigningError> {
        match self.require(SigningSchemeType::Ecdsa256k1)? {
            UnifiedPublicSigKey::Ecdsa256k1(key) => Ok(key),
            // `new` files every key under the scheme it reports, so the ECDSA slot holds an ECDSA
            // key.
            other => Err(SigningError::SchemeMismatch {
                signature: SigningSchemeType::Ecdsa256k1,
                key: other.signing_scheme_type(),
            }),
        }
    }

    /// The key for `scheme`, or an error naming the scheme that is missing.
    pub fn require(&self, scheme: SigningSchemeType) -> Result<&UnifiedPublicSigKey, SigningError> {
        self.get(scheme)
            .ok_or(SigningError::NoVerificationKey(scheme))
    }

    /// The ECDSA key of the set, or an error if it holds none.
    pub fn ecdsa(&self) -> Result<&PublicSigKey, SigningError> {
        match self.require(SigningSchemeType::Ecdsa256k1)? {
            UnifiedPublicSigKey::Ecdsa256k1(key) => Ok(key),
            // Unreachable: `new` files every key under its own scheme.
            _ => Err(SigningError::NoVerificationKey(
                SigningSchemeType::Ecdsa256k1,
            )),
        }
    }

    /// The identifier of the keys a signature under `schemes` is made with.
    pub fn id(&self, schemes: &[SigningSchemeType]) -> Result<Vec<u8>, SigningError> {
        let schemes = canonical_schemes(schemes)?;
        Ok(hash_element(
            &DSEP_VERF_KEY_SET,
            &self.canonical_bytes(&schemes)?,
        ))
    }

    /// The unambiguous byte encoding of the keys for the canonical `schemes`,
    /// for use inside a digest.
    fn canonical_bytes(&self, schemes: &[SigningSchemeType]) -> Result<Vec<u8>, SigningError> {
        let mut out = Vec::new();
        // Bounded by the number of known schemes, so the cast cannot truncate.
        out.extend_from_slice(&(schemes.len() as u32).to_le_bytes());
        for &scheme in schemes {
            out.extend_from_slice(&scheme.tag());
            let bytes = self.require(scheme)?.digest();
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

    /// An ECDSA-only set holds and returns exactly its key, and a set without an
    /// ECDSA key says so.
    #[test]
    fn an_ecdsa_only_set_holds_and_returns_its_key() {
        let mut rng = AesRng::seed_from_u64(6);
        let (pk, _sk) = crate::cryptography::signatures::gen_sig_keys(&mut rng);
        let set = VerfKeySet::ecdsa_only(pk.clone());
        assert_eq!(set.schemes(), vec![SigningSchemeType::Ecdsa256k1]);
        assert_eq!(set.ecdsa().unwrap(), &pk);

        let identity = seeded_identity(&mut rng);
        let no_ecdsa = VerfKeySet::from_identity(&identity, &[SigningSchemeType::MlDsa65]).unwrap();
        assert!(matches!(
            no_ecdsa.ecdsa(),
            Err(SigningError::NoVerificationKey(
                SigningSchemeType::Ecdsa256k1
            ))
        ));
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

        // The empty set, which publishes nothing any signature could be checked
        // against.
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

    /// The id names the selected keys: swapping a selected key, or changing the
    /// selection, changes it, while a key outside the selection does not.
    #[test]
    fn id_names_exactly_the_selected_keys() {
        let mut rng = AesRng::seed_from_u64(4);
        let identity = seeded_identity(&mut rng);
        let other_identity = seeded_identity(&mut rng);
        let every_scheme: Vec<_> = SigningSchemeType::iter().collect();
        let selected = [SigningSchemeType::Ecdsa256k1, SigningSchemeType::MlDsa87];

        let base = VerfKeySet::from_identity(&identity, &every_scheme).unwrap();
        let base_id = base.id(&selected).unwrap();

        for &scheme in &every_scheme {
            let mut swapped = base.keys.clone();
            swapped.insert(
                scheme,
                other_identity.unified_verifying_key(scheme).unwrap(),
            );
            let swapped_id = VerfKeySet::new(swapped).unwrap().id(&selected).unwrap();
            assert_eq!(
                base_id == swapped_id,
                !selected.contains(&scheme),
                "swapping the {scheme} key had the wrong effect on the id"
            );
        }

        assert_ne!(base_id, base.id(&[SigningSchemeType::Ecdsa256k1]).unwrap());
        assert_ne!(base_id, base.id(&every_scheme).unwrap());
    }
}

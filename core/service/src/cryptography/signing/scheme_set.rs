//! The set of signature schemes a composite signature is made under.
//!
//! A composite signature is only as strong as the *guarantee that every one of
//! its constituent signatures is present* hence this type needs to be persisted
//! as part of the signature or request, to avoid malleability attacks cutting
//! out one or more of the composite signature elements.

use super::{SigningError, SigningSchemeType};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use tfhe_versionable::{Versionize, VersionsDispatch};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, VersionsDispatch)]
pub enum SigningSchemeSetVersions {
    V0(SigningSchemeSet),
}

/// A non-empty, ascending, duplicate-free set of signature schemes.
///
/// # Canonical form
///
/// The schemes are ordered by their wire discriminant and carry no duplicates.
/// The set is never empty.
///
/// Ordering by wire discriminant is the same as ordering by the derived [`Ord`]
/// on [`SigningSchemeType`], which follows declaration order.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Versionize)]
#[versionize(SigningSchemeSetVersions)]
#[serde(transparent)]
pub struct SigningSchemeSet(Vec<SigningSchemeType>);

impl SigningSchemeSet {
    /// Creates a canonical set of `schemes`, sorting and de-duplicating the input.
    ///
    /// Errors when `schemes` is empty.
    pub fn new<I>(schemes: I) -> Result<Self, SigningError>
    where
        I: IntoIterator<Item = SigningSchemeType>,
    {
        let mut schemes: Vec<SigningSchemeType> = schemes.into_iter().collect();
        schemes.sort_unstable();
        schemes.dedup();
        if schemes.is_empty() {
            return Err(SigningError::EmptySchemeSet);
        }
        Ok(Self(schemes))
    }

    /// The set containing `scheme` alone.
    pub fn single(scheme: SigningSchemeType) -> Self {
        Self(vec![scheme])
    }

    /// Accept `schemes` only if it is already in canonical form.
    pub fn from_canonical(schemes: Vec<SigningSchemeType>) -> Result<Self, SigningError> {
        if schemes.is_empty() {
            return Err(SigningError::EmptySchemeSet);
        }
        let canonical = Self::new(schemes.iter().copied())?;
        if canonical.0 != schemes {
            return Err(SigningError::NonCanonicalSchemeSet(format!(
                "expected {canonical}, got {}",
                Self::render(&schemes)
            )));
        }
        Ok(canonical)
    }

    /// The schemes, in canonical order.
    pub fn as_slice(&self) -> &[SigningSchemeType] {
        &self.0
    }

    /// The schemes, in canonical order.
    pub fn iter(&self) -> impl Iterator<Item = SigningSchemeType> + '_ {
        self.0.iter().copied()
    }

    /// How many schemes the set holds; never zero.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether `scheme` is in the set.
    pub fn contains(&self, scheme: SigningSchemeType) -> bool {
        self.0.contains(&scheme)
    }

    /// The single scheme this set holds, or `None` if it holds several.
    pub fn sole(&self) -> Option<SigningSchemeType> {
        match self.0.as_slice() {
            [scheme] => Some(*scheme),
            _ => None,
        }
    }

    /// The unambiguous byte encoding of this set, for use inside a signature's
    /// or a digest's preimage.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 4 * self.0.len());
        // The set is non-empty and bounded by the number of known schemes, so
        // the cast cannot truncate.
        out.extend_from_slice(&(self.0.len() as u32).to_le_bytes());
        for scheme in &self.0 {
            out.extend_from_slice(&scheme.tag());
        }
        out
    }

    fn render(schemes: &[SigningSchemeType]) -> String {
        schemes
            .iter()
            .map(|scheme| scheme.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl fmt::Display for SigningSchemeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{{}}}", Self::render(&self.0))
    }
}

impl<'de> Deserialize<'de> for SigningSchemeSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let schemes = Vec::<SigningSchemeType>::deserialize(deserializer)?;
        Self::from_canonical(schemes).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;

    /// The set every pre-composite signature carries.
    const ECDSA: SigningSchemeType = SigningSchemeType::Ecdsa256k1;

    #[test]
    fn new_sorts_and_dedups() {
        let set = SigningSchemeSet::new([
            SigningSchemeType::MlDsa87,
            ECDSA,
            SigningSchemeType::MlDsa87,
            SigningSchemeType::Ed25519,
        ])
        .unwrap();
        assert_eq!(
            set.as_slice(),
            [
                ECDSA,
                SigningSchemeType::Ed25519,
                SigningSchemeType::MlDsa87,
            ]
            .as_slice()
        );
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn empty_is_rejected() {
        assert!(matches!(
            SigningSchemeSet::new(std::iter::empty()),
            Err(SigningError::EmptySchemeSet)
        ));
        assert!(matches!(
            SigningSchemeSet::from_canonical(vec![]),
            Err(SigningError::EmptySchemeSet)
        ));
    }

    /// Canonical order is the only accepted encoding.
    #[test]
    fn from_canonical_rejects_non_canonical() {
        let reordered = vec![SigningSchemeType::MlDsa87, ECDSA];
        assert!(matches!(
            SigningSchemeSet::from_canonical(reordered),
            Err(SigningError::NonCanonicalSchemeSet(_))
        ));

        let duplicated = vec![ECDSA, ECDSA];
        assert!(matches!(
            SigningSchemeSet::from_canonical(duplicated),
            Err(SigningError::NonCanonicalSchemeSet(_))
        ));

        // ...and the canonica order is accepted.
        SigningSchemeSet::from_canonical(vec![ECDSA, SigningSchemeType::MlDsa87]).unwrap();
    }

    /// A non-canonical set must not survive a serialization round-trip, because
    /// that is the path an attacker-supplied encoding takes.
    #[test]
    fn deserialization_rejects_non_canonical() {
        let canonical = SigningSchemeSet::new([ECDSA, SigningSchemeType::MlDsa87]).unwrap();
        let bytes = bc2wrap::serialize(&canonical).unwrap();
        let back: SigningSchemeSet = bc2wrap::deserialize_slice(&bytes).unwrap();
        assert_eq!(canonical, back);

        // Serialize the reversed list directly; it must not deserialize back.
        let reversed = vec![SigningSchemeType::MlDsa87, ECDSA];
        let bytes = bc2wrap::serialize(&reversed).unwrap();
        assert!(bc2wrap::deserialize_slice::<SigningSchemeSet>(&bytes).is_err());
    }

    #[test]
    fn sole_is_none_for_a_composite_set() {
        assert_eq!(SigningSchemeSet::single(ECDSA).sole(), Some(ECDSA));
        assert_eq!(
            SigningSchemeSet::new([ECDSA, SigningSchemeType::MlDsa87])
                .unwrap()
                .sole(),
            None
        );
    }

    /// Distinct sets must not share a preimage, including the case where one is
    /// a prefix of another — that is the collision a bare concatenation would
    /// admit.
    #[test]
    fn canonical_bytes_separate_distinct_sets() {
        let mut seen = std::collections::HashSet::new();
        for scheme in SigningSchemeType::iter() {
            assert!(
                seen.insert(SigningSchemeSet::single(scheme).canonical_bytes()),
                "{scheme} shares a preimage with another set"
            );
        }
        let pair = SigningSchemeSet::new([ECDSA, SigningSchemeType::MlDsa87]).unwrap();
        assert!(seen.insert(pair.canonical_bytes()));

        // The length prefix is what separates a set from a longer one that
        // starts with it.
        let single = SigningSchemeSet::single(ECDSA);
        assert!(
            !pair
                .canonical_bytes()
                .starts_with(&single.canonical_bytes())
        );
    }

    /// Locks the serialized form of a [`SigningSchemeSet`].
    ///
    /// The freeze-and-replay harness covers this type too
    /// (`SigningSchemeSetTest`), but that catches a break only when the stored
    /// fixtures are pulled and replayed. This runs in the unit suite and names
    /// the exact bytes, so an encoding change is reported where it is made. The
    /// same pairing exists for `SigncryptionPayload`, which has both a fixture
    /// and `test_signcryption_payload_v0_serialization_locked`.
    ///
    /// The expected bytes follow `bc2wrap`'s bincode-v1 rules: a sequence length
    /// as a little-endian `u64`, then each enum variant as a little-endian
    /// `u32` discriminant.
    ///
    /// A change here breaks every signcryption already written under a
    /// composite scheme set, so it must come with a new version of the
    /// containing type rather than with an update to these bytes.
    #[test]
    fn versioned_encoding_is_locked() {
        // One scheme: length 1, then discriminant 0 (Ecdsa256k1).
        assert_eq!(
            bc2wrap::serialize(&SigningSchemeSet::single(ECDSA)).unwrap(),
            vec![
                1, 0, 0, 0, 0, 0, 0, 0, // sequence length
                0, 0, 0, 0, // Ecdsa256k1
            ],
            "LOCKED: the singleton encoding changed"
        );

        // Two schemes, in canonical order: discriminants 0 and 4. This is the
        // pair the backward-compatibility fixture freezes.
        assert_eq!(
            bc2wrap::serialize(
                &SigningSchemeSet::new([ECDSA, SigningSchemeType::MlDsa87]).unwrap()
            )
            .unwrap(),
            vec![
                2, 0, 0, 0, 0, 0, 0, 0, // sequence length
                0, 0, 0, 0, // Ecdsa256k1
                4, 0, 0, 0, // MlDsa87
            ],
            "LOCKED: the composite encoding changed"
        );

        // The discriminants are the wire values, so the stored encoding cannot
        // drift from what a peer of another release expects.
        for scheme in SigningSchemeType::iter() {
            let bytes = bc2wrap::serialize(&SigningSchemeSet::single(scheme)).unwrap();
            assert_eq!(
                bytes[8..],
                (scheme.as_wire() as u32).to_le_bytes(),
                "{scheme} is not encoded as its wire discriminant"
            );
        }
    }

    #[test]
    fn every_scheme_round_trips_as_a_singleton() {
        for scheme in SigningSchemeType::iter() {
            let set = SigningSchemeSet::single(scheme);
            assert_eq!(set.sole(), Some(scheme));
            assert!(set.contains(scheme));
            let bytes = bc2wrap::serialize(&set).unwrap();
            let back: SigningSchemeSet = bc2wrap::deserialize_slice(&bytes).unwrap();
            assert_eq!(set, back);
        }
    }
}

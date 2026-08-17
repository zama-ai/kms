//! The root secret a KMS node's per-scheme signing keys are derived from.
//!
//! Every non-ECDSA signing key descends from a [`RootSigningSeed`] drawn from the
//! rng. This is deliberately *not* derived from the node's ECDSA signing key:
//! the post-quantum keys exist to outlive secp256k1, so recovering the ECDSA
//! scalar must not reveal them.
//!
//! Long term the ECDSA key will enventually be derived from the seed too.

use super::cache::DerivedKeyCache;
use super::ecdsa::PrivateSigKey;
use super::eddsa::Ed25519;
use super::mldsa::MlDsa;
use super::{
    DSEP_SIGKEY_DERIVE, SIGKEY_DERIVATION_VERSION, SigningError, SigningSchemeType,
    UnifiedPrivateSigKey, UnifiedPublicSigKey,
};
use crate::cryptography::signing::HasSigningScheme;
use crate::impl_generic_versionize;
use hashing::{DIGEST_BYTES, hash_element};
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87};
use serde::{Deserialize, Serialize, de::Visitor};
use tfhe::named::Named;
use tfhe_versionable::{Versionize, VersionsDispatch};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// The number of bytes in a root signing seed.
pub const ROOT_SEED_LEN: usize = 32;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Zeroize, VersionsDispatch)]
pub enum RootSigningSeedVersions {
    V0(RootSigningSeed),
}

/// A KMS node's root signing secret.
///
/// Persisted on its own (as `PrivDataType::SigningSeed`) rather than inside
/// [`PrivateSigKey`], so that adding it to an existing node is a purely additive
/// write that the ordinary backup pass picks up, and so the `#[wasm_bindgen]`
/// [`PrivateSigKey`] byte format is untouched.
///
/// **Losing this seed loses every non-ECDSA identity of the node**: they are
/// derived from it and stored nowhere else. It must be in the backup set.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Zeroize, Versionize)]
#[versionize(RootSigningSeedVersions)]
pub struct RootSigningSeed {
    seed: WrappedSeed,
    /// Memoized per-scheme signing keys derived from `seed`.
    /// Skipped from (de)serialization and versioning: it is pure cache, so only
    /// the root secret is persisted and it deserializes with a cold cache.
    #[serde(skip)]
    #[versionize(skip)]
    cache: DerivedKeyCache,
}

impl Named for RootSigningSeed {
    const NAME: &'static str = "RootSigningSeed";
}

// Marker only: the `seed: WrappedSeed` field is `ZeroizeOnDrop`, so dropping a
// `RootSigningSeed` wipes the root secret, and dropping `cache` wipes every key
// derived from it (`UnifiedPrivateSigKey: ZeroizeOnDrop`). Not derived because
// that would generate a `Drop` impl, which conflicts with the other macros on
// this type — the same reason the zeroizing `Drop` lives on a newtype for
// [`PrivateSigKey`].
impl ZeroizeOnDrop for RootSigningSeed {}

impl RootSigningSeed {
    /// A fresh root seed drawn from `rng`.
    ///
    /// The seed is generated independently of all other key material — in
    /// particular it is never derived from the ECDSA signing key. That
    /// independence is the entire point of this type.
    pub fn random<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> Self {
        let mut seed = [0u8; ROOT_SEED_LEN];
        rng.fill_bytes(&mut seed);
        let root = Self {
            seed: WrappedSeed(seed),
            cache: DerivedKeyCache::default(),
        };
        // Wipe the copy of the secret that was moved into `root`.
        seed.zeroize();
        root
    }

    /// The memoized signing key this root derives for `scheme`.
    ///
    /// # ECDSA is derived here, but is not the node's identity
    ///
    /// This covers *every* scheme, ECDSA included — the seed is the root of the
    /// whole key hierarchy. The ECDSA arm exists for two callers: generating the
    /// key of a *fresh* node, and, later, rotating an existing node onto its
    /// seed-derived key.
    ///
    /// It is **not** the current ECDSA identity of an upgraded node, whose
    /// identity is the separately persisted [`PrivateSigKey`] — which is why
    /// [`PrivateSigKey::unified_verifying_key`] answers ECDSA from itself and
    /// only delegates the other schemes here. Signing with, publishing, or
    /// validating against the ECDSA key derived here would use the wrong
    /// identity for such a node. Use [`Self::derive_ecdsa_signing_key`] at the
    /// two call sites that legitimately want it, so the intent is explicit and
    /// auditable.
    pub(crate) fn derive_signing_key(
        &self,
        scheme: SigningSchemeType,
    ) -> Result<&UnifiedPrivateSigKey, SigningError> {
        let slot = self.cache.slot(scheme);
        if let Some(key) = slot.get() {
            return Ok(key);
        }
        // Cache miss: derive once and memoize.
        let derived = self.expand_signing_key(scheme)?;
        let _ = slot.set(derived);
        Ok(slot
            .get()
            .expect("cache slot was populated by this call or a concurrent one"))
    }

    /// The ECDSA signing key this root derives.
    ///
    /// Only two callers are correct: key generation on a fresh node (which has
    /// no prior identity, so this *becomes* its identity and is persisted as
    /// such), and the future rotation of an existing node. Everything else must
    /// use the persisted [`PrivateSigKey`] — see [`Self::derive_signing_key`].
    pub(crate) fn derive_ecdsa_signing_key(&self) -> Result<PrivateSigKey, SigningError> {
        match self.derive_signing_key(SigningSchemeType::Ecdsa256k1)? {
            UnifiedPrivateSigKey::Ecdsa256k1(sk) => Ok(sk.clone()),
            other => Err(SigningError::KeyDerivation(format!(
                "expected an ECDSA signing key, got {:?}",
                other.signing_scheme_type()
            ))),
        }
    }

    /// The verification key that signatures made with [`Self::derive_signing_key`]
    /// under `scheme` verify against.
    ///
    /// Carries the same ECDSA caveat as [`Self::derive_signing_key`]: for an
    /// upgraded node the ECDSA verification key returned here is the
    /// *post-rotation* one, not the identity it currently signs with.
    pub fn unified_verifying_key(
        &self,
        scheme: SigningSchemeType,
    ) -> Result<UnifiedPublicSigKey, SigningError> {
        self.derive_signing_key(scheme)?.verifying_key()
    }

    /// Run the KDF and the scheme's key expansion, bypassing the cache.
    fn expand_signing_key(
        &self,
        scheme: SigningSchemeType,
    ) -> Result<UnifiedPrivateSigKey, SigningError> {
        Ok(match scheme {
            SigningSchemeType::Ecdsa256k1 => UnifiedPrivateSigKey::Ecdsa256k1(
                // Fallible: a derived seed that is zero or `>= n` is not a valid
                // secp256k1 scalar. That happens with probability ~2^-128, so in
                // practice this only ever returns `Ok`, but it is an error rather
                // than a panic so a caller can regenerate instead of crashing.
                PrivateSigKey::keygen_from_seed(&self.derived_seed(scheme))?,
            ),
            SigningSchemeType::Ed25519 => {
                UnifiedPrivateSigKey::Ed25519(Ed25519::keygen_from_seed(&self.derived_seed(scheme)))
            }
            SigningSchemeType::MlDsa44 => UnifiedPrivateSigKey::MlDsa44(Box::new(
                MlDsa::<MlDsa44>::keygen_from_seed(&self.derived_seed(scheme)),
            )),
            SigningSchemeType::MlDsa65 => UnifiedPrivateSigKey::MlDsa65(Box::new(
                MlDsa::<MlDsa65>::keygen_from_seed(&self.derived_seed(scheme)),
            )),
            SigningSchemeType::MlDsa87 => UnifiedPrivateSigKey::MlDsa87(Box::new(
                MlDsa::<MlDsa87>::keygen_from_seed(&self.derived_seed(scheme)),
            )),
        })
    }

    /// Derive a deterministic 32-byte seed for `scheme` from this root seed.
    ///
    /// The derived seed is
    /// `SHAKE256(DSEP_SIGKEY_DERIVE ‖ scheme_tag ‖ version ‖ root_seed)`, where
    /// `scheme_tag` is [`SigningSchemeType::tag`] and `version` is
    /// [`SIGKEY_DERIVATION_VERSION`]. Every input is fixed-length, so the
    /// concatenation is unambiguous.
    fn derived_seed(&self, scheme: SigningSchemeType) -> Zeroizing<[u8; DIGEST_BYTES]> {
        // Use Zeroizing to ensure the assembled KDF input gets wiped at dropping
        let mut msg = Zeroizing::new(Vec::with_capacity(4 + 1 + ROOT_SEED_LEN));
        msg.extend_from_slice(&scheme.tag());
        msg.push(SIGKEY_DERIVATION_VERSION);
        msg.extend_from_slice(&self.seed.0);
        // Use Zeroizing to ensure the digest gets wiped at dropping
        let digest = Zeroizing::new(hash_element(&DSEP_SIGKEY_DERIVE, msg.as_slice()));

        Zeroizing::new(
            digest
                .as_slice()
                .try_into()
                .expect("SHAKE256 output is exactly DIGEST_BYTES bytes"),
        )
    }
}

/// The raw root secret, in a newtype that wipes itself on drop.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
struct WrappedSeed([u8; ROOT_SEED_LEN]);
impl_generic_versionize!(WrappedSeed);

// Never render the root secret.
impl std::fmt::Debug for WrappedSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WrappedSeed(..)")
    }
}

/// Serialize as the raw seed bytes, so the persisted object is exactly the
/// secret and nothing else.
impl Serialize for WrappedSeed {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for WrappedSeed {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_bytes(WrappedSeedVisitor)
    }
}

struct WrappedSeedVisitor;
impl Visitor<'_> for WrappedSeedVisitor {
    type Value = WrappedSeed;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(formatter, "a {ROOT_SEED_LEN}-byte root signing seed")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let bytes: [u8; ROOT_SEED_LEN] = v
            .try_into()
            .map_err(|_| E::invalid_length(v.len(), &self))?;
        Ok(WrappedSeed(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::SAFE_SER_SIZE_LIMIT;
    use crate::cryptography::signing::{HasSigningScheme, unified_sign, unified_verify};
    use aes_prng::AesRng;
    use hashing::DomainSep;
    use rand::SeedableRng;
    use strum::IntoEnumIterator;
    use tfhe::safe_serialization::{safe_deserialize, safe_serialize};

    const DSEP: &DomainSep = b"SEEDTEST";

    /// A root seed with fixed contents, for tests that need reproducibility.
    fn fixed_root(bytes: [u8; ROOT_SEED_LEN]) -> RootSigningSeed {
        RootSigningSeed {
            seed: WrappedSeed(bytes),
            cache: DerivedKeyCache::default(),
        }
    }

    /// A cold copy of `root`: same secret, empty cache. A plain `clone()` would
    /// share the warmed cache, so it cannot show that re-derivation is stable.
    fn cold_copy(root: &RootSigningSeed) -> RootSigningSeed {
        let mut buf = Vec::new();
        safe_serialize(root, &mut buf, SAFE_SER_SIZE_LIMIT).unwrap();
        safe_deserialize(std::io::Cursor::new(&buf), SAFE_SER_SIZE_LIMIT).unwrap()
    }

    /// Every scheme derived from the root signs and verifies; a tampered message
    /// fails.
    #[test]
    fn every_scheme_signs_and_verifies() {
        let mut rng = AesRng::seed_from_u64(1);
        let root = RootSigningSeed::random(&mut rng);
        let msg = b"a message signed under a seed-derived key";

        for scheme in SigningSchemeType::iter() {
            let sk = root.derive_signing_key(scheme).unwrap();
            let vk = root.unified_verifying_key(scheme).unwrap();
            assert_eq!(sk.signing_scheme_type(), scheme);
            assert_eq!(vk.signing_scheme_type(), scheme);

            let sig = unified_sign(DSEP, msg, sk).unwrap();
            unified_verify(DSEP, msg, &sig, &vk)
                .unwrap_or_else(|e| panic!("{scheme:?} seed-derived key should verify: {e}"));
            assert!(unified_verify(DSEP, b"tampered", &sig, &vk).is_err());
        }
    }

    /// The root survives the safe-serialization round-trip used to persist it,
    /// and the cold copy re-derives byte-identical keys for every scheme.
    #[test]
    fn round_trip_re_derives_the_same_keys() {
        let mut rng = AesRng::seed_from_u64(2);
        let root = RootSigningSeed::random(&mut rng);
        let restored = cold_copy(&root);

        assert_eq!(root, restored, "root seed did not survive the round-trip");
        for scheme in SigningSchemeType::iter() {
            assert_eq!(
                root.unified_verifying_key(scheme).unwrap(),
                restored.unified_verifying_key(scheme).unwrap(),
                "{scheme:?} was not re-derived identically"
            );
        }
    }

    /// Two independently generated roots share no derived key. This is the
    /// property the whole type exists for: the key hierarchy hangs off the seed
    /// and nothing else.
    #[test]
    fn distinct_roots_give_distinct_keys() {
        let mut rng = AesRng::seed_from_u64(3);
        let first = RootSigningSeed::random(&mut rng);
        let second = RootSigningSeed::random(&mut rng);
        assert_ne!(first, second, "two random roots collided");

        for scheme in SigningSchemeType::iter() {
            assert_ne!(
                first.unified_verifying_key(scheme).unwrap(),
                second.unified_verifying_key(scheme).unwrap(),
                "{scheme:?} keys of two distinct roots collided"
            );
        }
    }

    /// Distinct schemes derive distinct seeds from the same root (the scheme tag
    /// is bound into the KDF), so the per-scheme keys never share seed material.
    #[test]
    fn distinct_schemes_have_distinct_seeds() {
        let mut rng = AesRng::seed_from_u64(4);
        let root = RootSigningSeed::random(&mut rng);

        let schemes: Vec<_> = SigningSchemeType::iter().collect();
        let seeds: Vec<_> = schemes.iter().map(|s| root.derived_seed(*s)).collect();
        for i in 0..seeds.len() {
            for j in (i + 1)..seeds.len() {
                assert_ne!(
                    *seeds[i], *seeds[j],
                    "{:?} and {:?} share a derived seed",
                    schemes[i], schemes[j]
                );
            }
        }
    }

    /// `derive_signing_key` memoizes: repeated calls return the same cached
    /// instance, and a (warm) clone shares that cache rather than re-deriving.
    /// Unlike the [`PrivateSigKey`] cache, the ECDSA slot is live here.
    #[test]
    fn derived_keys_are_cached_and_shared_across_clones() {
        let mut rng = AesRng::seed_from_u64(5);
        let root = RootSigningSeed::random(&mut rng);

        for scheme in SigningSchemeType::iter() {
            let first = root.derive_signing_key(scheme).unwrap();
            let second = root.derive_signing_key(scheme).unwrap();
            assert!(
                std::ptr::eq(first, second),
                "{scheme:?} was re-derived instead of served from the cache"
            );

            let clone = root.clone();
            let from_clone = clone.derive_signing_key(scheme).unwrap();
            assert!(
                std::ptr::eq(first, from_clone),
                "{scheme:?} clone did not share the warmed cache"
            );
        }
    }

    /// The ECDSA key derived from the root is a fully usable signing key, and
    /// `derive_ecdsa_signing_key` hands back that same key.
    #[test]
    fn ecdsa_key_is_derivable_and_usable() {
        let mut rng = AesRng::seed_from_u64(6);
        let root = RootSigningSeed::random(&mut rng);

        let sk = root.derive_ecdsa_signing_key().unwrap();
        let vk = root
            .unified_verifying_key(SigningSchemeType::Ecdsa256k1)
            .unwrap();
        match &vk {
            UnifiedPublicSigKey::Ecdsa256k1(pk) => assert_eq!(*pk, sk.verf_key()),
            other => panic!("expected ECDSA, got {:?}", other.signing_scheme_type()),
        }

        let msg = b"signed by the seed-derived ECDSA key";
        let sig = unified_sign(DSEP, msg, &UnifiedPrivateSigKey::Ecdsa256k1(sk)).unwrap();
        unified_verify(DSEP, msg, &sig, &vk).unwrap();
    }

    /// `zeroize` wipes the root: keys derived afterwards differ from the ones
    /// derived before.
    #[test]
    fn zeroize_wipes_the_root() {
        let mut rng = AesRng::seed_from_u64(7);
        let mut root = RootSigningSeed::random(&mut rng);

        let before: Vec<_> = SigningSchemeType::iter()
            .map(|s| root.unified_verifying_key(s).unwrap())
            .collect();
        root.zeroize();
        for (scheme, old) in SigningSchemeType::iter().zip(before) {
            assert_ne!(
                root.unified_verifying_key(scheme).unwrap(),
                old,
                "{scheme:?} key survived zeroize"
            );
        }
    }

    /// Frozen derivation vector: for a fixed root seed the derived per-scheme
    /// seeds are stable across releases. A change here means the KDF (domain
    /// separator, version, tag encoding, or hash) changed and every derived key
    /// rotated — which, once a deployment holds published per-scheme material,
    /// is a breaking change.
    #[test]
    fn frozen_derivation_vector() {
        let root = fixed_root(std::array::from_fn(|i| i as u8));

        assert_eq!(
            hex::encode(root.derived_seed(SigningSchemeType::Ecdsa256k1)),
            "c14f3f09325877e1d6b679399ca655ab833ee867ba403592d51685652f3843b8",
        );
        assert_eq!(
            hex::encode(root.derived_seed(SigningSchemeType::Ed25519)),
            "7934c51d7f696eeaf47257d54c3cec3f87e8c0f79d13e3cd1493ff14dde50638",
        );
        assert_eq!(
            hex::encode(root.derived_seed(SigningSchemeType::MlDsa44)),
            "dd5b8daf355f927d357ebe1f908314926504b0f8e0e5ded86f9279f0360f270a",
        );
        assert_eq!(
            hex::encode(root.derived_seed(SigningSchemeType::MlDsa65)),
            "054eed4c52f8d4e090e88f7db93370d52df0821a03b4bdf2e655c78b0fa46ac2",
        );
        assert_eq!(
            hex::encode(root.derived_seed(SigningSchemeType::MlDsa87)),
            "b2263620e75c55e8a93e929232307b4b236605af9856e9b7124f2d555361b2bd",
        );
    }

    /// The root serializes as exactly its raw secret bytes, so the persisted
    /// object cannot silently grow a second copy of the secret.
    #[test]
    fn serializes_as_raw_bytes() {
        let bytes: [u8; ROOT_SEED_LEN] = std::array::from_fn(|i| (i as u8).wrapping_mul(7));
        let root = fixed_root(bytes);
        let encoded = bc2wrap::serialize(&root).unwrap();
        assert!(
            encoded.windows(ROOT_SEED_LEN).any(|w| w == bytes),
            "the serialized root does not contain the seed bytes"
        );
        let decoded: RootSigningSeed = bc2wrap::deserialize_slice(&encoded).unwrap();
        assert_eq!(root, decoded);
    }
}

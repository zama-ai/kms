//! The signing identity of a KMS node.

use super::ecdsa::{Ecdsa256k1, PrivateSigKey, PublicSigKey};
use super::seed::RootSigningSeed;
use super::{
    Signature, SigningError, SigningScheme, SigningSchemeType, UnifiedPublicSigKey, unified_sign,
};
use hashing::DomainSep;
use std::sync::Arc;
use zeroize::ZeroizeOnDrop;

/// Everything a KMS node signs with: its ECDSA key, and the root seed the keys of
/// the other schemes are derived from.
///
/// The two halves are persisted separately, as `PrivDataType::SigningKey` and
/// `PrivDataType::SigningSeed`, and assembled here by the loader that reads them.
/// This type is therefore never serialized itself.
///
/// # Which key each scheme uses
///
/// - **ECDSA** uses the node's own [`PrivateSigKey`]. That is a property of the
///   transition rather than of the design. A node generated from scratch derives
///   that key from the seed, so for it both roots already coincide.
/// - **Every other scheme** uses a key derived from the [`RootSigningSeed`], and
///   fails with [`SigningError::MissingRootSeed`] when the node has none.
///
/// A legacy node, without a seed, only works for ECDSA.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeSigningIdentity {
    ecdsa: Arc<PrivateSigKey>,
    seed: Option<RootSigningSeed>,
}

// Marker only: every secret this type holds wipes itself when it drops.
// `RootSigningSeed` is `ZeroizeOnDrop`, so the seed goes with the identity, and
// the ECDSA key goes when the last handle to it drops.
impl ZeroizeOnDrop for NodeSigningIdentity {}

impl NodeSigningIdentity {
    /// A node identity whose non-ECDSA keys descend from `seed`.
    pub fn new(ecdsa: PrivateSigKey, seed: RootSigningSeed) -> Self {
        Self {
            ecdsa: Arc::new(ecdsa),
            seed: Some(seed),
        }
    }

    /// A node identity limited to ECDSA, for a node that holds no root seed.
    pub fn ecdsa_only(ecdsa: PrivateSigKey) -> Self {
        Self {
            ecdsa: Arc::new(ecdsa),
            seed: None,
        }
    }

    /// The node's ECDSA signing key.
    pub fn ecdsa(&self) -> &PrivateSigKey {
        &self.ecdsa
    }

    /// The node's ECDSA verification key, which is its identity in an MPC
    /// context.
    pub fn verf_key(&self) -> PublicSigKey {
        self.ecdsa.verf_key()
    }

    /// Whether a root seed is attached, and hence whether this identity can sign
    /// under anything but ECDSA.
    pub fn has_root_seed(&self) -> bool {
        self.seed.is_some()
    }

    /// Sign `msg` (domain-separated by `dsep`) under `scheme`.
    #[cfg(feature = "non-wasm")]
    pub(crate) fn unified_sign_with(
        &self,
        scheme: SigningSchemeType,
        dsep: &DomainSep,
        msg: &[u8],
    ) -> Result<Signature, SigningError> {
        match scheme {
            SigningSchemeType::Ecdsa256k1 => Ok(Signature::new(
                scheme,
                Ecdsa256k1::sign(dsep, msg, self.ecdsa())?,
            )),
            _ => {
                let seed = self.require_root_seed(scheme)?;
                unified_sign(dsep, msg, seed.derive_signing_key(scheme)?)
            }
        }
    }

    /// The verification key that [`Self::unified_sign_with`] signatures under
    /// `scheme` verify against.
    pub fn unified_verifying_key(
        &self,
        scheme: SigningSchemeType,
    ) -> Result<UnifiedPublicSigKey, SigningError> {
        match scheme {
            SigningSchemeType::Ecdsa256k1 => {
                Ok(UnifiedPublicSigKey::Ecdsa256k1(self.ecdsa.verf_key()))
            }
            _ => self
                .require_root_seed(scheme)?
                .unified_verifying_key(scheme),
        }
    }

    /// The attached root seed, or an error naming the scheme that needs it.
    fn require_root_seed(
        &self,
        scheme: SigningSchemeType,
    ) -> Result<&RootSigningSeed, SigningError> {
        self.seed
            .as_ref()
            .ok_or(SigningError::MissingRootSeed(scheme))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::signatures::gen_sig_keys;
    use crate::cryptography::signing::{HasSigningScheme, unified_verify};
    use aes_prng::AesRng;
    use rand::SeedableRng;
    use strum::IntoEnumIterator;

    const DSEP: &DomainSep = b"IDNTTEST";

    /// A complete node identity: an ECDSA key and a root seed.
    fn seeded_identity<R: rand::CryptoRng + rand::RngCore>(rng: &mut R) -> NodeSigningIdentity {
        let (_pk, sk) = gen_sig_keys(rng);
        NodeSigningIdentity::new(sk, RootSigningSeed::random(rng))
    }

    /// Extract the Ethereum address from an ECDSA unified verification key,
    /// panicking on any other scheme.
    fn ecdsa_address(vk: UnifiedPublicSigKey) -> alloy_primitives::Address {
        match vk {
            UnifiedPublicSigKey::Ecdsa256k1(pk) => pk.address(),
            other => panic!(
                "expected an ECDSA verification key, got {:?}",
                other.signing_scheme_type()
            ),
        }
    }

    /// Every scheme signs and verifies through the identity, and a tampered
    /// message fails.
    #[test]
    fn every_scheme_signs_and_verifies() {
        let mut rng = AesRng::seed_from_u64(101);
        let identity = seeded_identity(&mut rng);
        let msg = b"a message signed under a derived scheme key";

        for scheme in SigningSchemeType::iter() {
            let vk = identity.unified_verifying_key(scheme).unwrap();
            assert_eq!(vk.signing_scheme_type(), scheme);

            let sig = identity.unified_sign_with(scheme, DSEP, msg).unwrap();
            assert_eq!(sig.scheme(), scheme);
            unified_verify(DSEP, msg, &sig, &vk)
                .unwrap_or_else(|e| panic!("{scheme:?} derived key should verify: {e}"));
            assert!(unified_verify(DSEP, b"tampered", &sig, &vk).is_err());
        }
    }

    /// Deriving the same scheme from the same identity twice yields identical
    /// keys.
    #[test]
    fn derivation_is_deterministic() {
        let mut rng = AesRng::seed_from_u64(202);
        let identity = seeded_identity(&mut rng);
        let msg = b"deriving twice must give the same key";

        for scheme in SigningSchemeType::iter() {
            let sig = identity.unified_sign_with(scheme, DSEP, msg).unwrap();
            let vk = identity.clone().unified_verifying_key(scheme).unwrap();
            unified_verify(DSEP, msg, &sig, &vk)
                .unwrap_or_else(|e| panic!("{scheme:?} derivation was not deterministic: {e}"));
        }
    }

    /// The transition invariant: the ECDSA identity is the node's own key, and
    /// attaching a root seed does not move it.
    #[test]
    fn ecdsa_identity_is_never_the_seed_derived_key() {
        let mut rng = AesRng::seed_from_u64(305);
        let (pk, sk) = gen_sig_keys(&mut rng);
        let identity = NodeSigningIdentity::new(sk, RootSigningSeed::random(&mut rng));

        // What the identity publishes is the node's own key...
        let vk = identity
            .unified_verifying_key(SigningSchemeType::Ecdsa256k1)
            .unwrap();
        assert_eq!(ecdsa_address(vk.clone()), pk.address());
        assert_eq!(identity.verf_key(), pk);

        // ...and what it signs with verifies against exactly that key.
        let msg = b"signed by the node's ECDSA identity";
        let sig = identity
            .unified_sign_with(SigningSchemeType::Ecdsa256k1, DSEP, msg)
            .unwrap();
        unified_verify(DSEP, msg, &sig, &vk).unwrap();
    }

    /// Without a root seed an identity can still do everything ECDSA, and fails
    /// loudly for every other scheme.
    #[test]
    fn non_ecdsa_requires_a_root_seed() {
        let mut rng = AesRng::seed_from_u64(707);
        let (_pk, sk) = gen_sig_keys(&mut rng);
        let identity = NodeSigningIdentity::ecdsa_only(sk);
        assert!(!identity.has_root_seed());
        let msg = b"a seedless identity is ECDSA-only";

        let vk = identity
            .unified_verifying_key(SigningSchemeType::Ecdsa256k1)
            .unwrap();
        let sig = identity
            .unified_sign_with(SigningSchemeType::Ecdsa256k1, DSEP, msg)
            .unwrap();
        unified_verify(DSEP, msg, &sig, &vk).unwrap();

        for scheme in SigningSchemeType::iter().filter(|s| *s != SigningSchemeType::Ecdsa256k1) {
            assert!(matches!(
                identity.unified_verifying_key(scheme),
                Err(SigningError::MissingRootSeed(s)) if s == scheme
            ));
            assert!(matches!(
                identity.unified_sign_with(scheme, DSEP, msg),
                Err(SigningError::MissingRootSeed(s)) if s == scheme
            ));
        }
    }

    /// Two identities that share an ECDSA key but hold different seeds derive
    /// different keys for every other scheme.
    #[test]
    fn the_seed_alone_determines_the_derived_keys() {
        let mut rng = AesRng::seed_from_u64(3078);
        let (_pk, sk) = gen_sig_keys(&mut rng);
        let one = NodeSigningIdentity::new(sk.clone(), RootSigningSeed::random(&mut rng));
        let other = NodeSigningIdentity::new(sk, RootSigningSeed::random(&mut rng));

        assert_ne!(one, other);
        assert_eq!(
            one.unified_verifying_key(SigningSchemeType::Ecdsa256k1)
                .unwrap(),
            other
                .unified_verifying_key(SigningSchemeType::Ecdsa256k1)
                .unwrap(),
            "the shared ECDSA key was not the identity of both"
        );
        for scheme in SigningSchemeType::iter().filter(|s| *s != SigningSchemeType::Ecdsa256k1) {
            assert_ne!(
                one.unified_verifying_key(scheme).unwrap(),
                other.unified_verifying_key(scheme).unwrap(),
                "{scheme:?} was determined by the ECDSA key rather than by the seed"
            );
        }
    }
}

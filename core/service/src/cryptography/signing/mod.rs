//! Multi-scheme signing support (issue #3078).
//!
//! Every backend signs `dsep ‖ msg` and applies its own normalization/encoding
//! internally.

pub mod ecdsa;
mod eddsa;
pub mod identity;
mod mldsa;
pub mod seed;

use alloy_primitives::Address;
use ecdsa::Ecdsa256k1;
use ecdsa::{PrivateSigKey, PublicSigKey};
use ed25519_dalek::{PUBLIC_KEY_LENGTH, SigningKey as Ed25519SigningKey};
use eddsa::Ed25519;
pub use eddsa::Ed25519VerfKey;
use hashing::{DIGEST_BYTES, DomainSep};
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, SigningKey as MlDsaSigningKey};
use mldsa::MlDsa;
pub use mldsa::MlDsaVerfKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use strum::{EnumCount, EnumIter, VariantNames as _};
use strum_macros::{Display, EnumString, VariantNames};
use tfhe::named::Named;
use tfhe_versionable::{Versionize, VersionsDispatch};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Domain separator for deriving per-scheme signing keys from a
/// [`seed::RootSigningSeed`].
const DSEP_SIGKEY_DERIVE: DomainSep = *b"SIGKDERV";

/// Domain separator for the digests that identify a verification key.
const DSEP_SIGKEY_DIGEST: DomainSep = *b"SIGKDGST";

/// Version of the per-scheme key-derivation scheme.
const SIGKEY_DERIVATION_VERSION: u8 = 1;

/// Errors produced by the multi-scheme signing API.
#[derive(Debug, Error)]
pub enum SigningError {
    /// A signature was verified against a key of a different scheme.
    #[error("signature scheme {signature:?} does not match verification key scheme {key:?}")]
    SchemeMismatch {
        /// The scheme the signature claims to have been produced under.
        signature: SigningSchemeType,
        /// The scheme of the verification key it was checked against.
        key: SigningSchemeType,
    },
    /// The signature byte length is wrong for its scheme.
    #[error("invalid signature length: expected {expected} bytes, got {actual}")]
    InvalidSignatureLength {
        /// The length the scheme requires.
        expected: usize,
        /// The length that was actually supplied.
        actual: usize,
    },
    /// The signature bytes could not be decoded into the scheme's signature type.
    #[error("malformed signature: {0}")]
    MalformedSignature(String),
    /// An ECDSA signature was not in low-`s` (BIP-0062) normalized form.
    #[error("signature is not normalized (low-s): {0}")]
    NotNormalized(String),
    /// The backend failed to produce a signature.
    #[error("signing failed: {0}")]
    Sign(String),
    /// Signature verification failed (cryptographically invalid or tampered).
    #[error("verification failed: {0}")]
    Verify(String),
    /// Deriving a verification key from a signing key failed.
    #[error("could not derive verification key: {0}")]
    KeyDerivation(String),
    /// A key that has to be derived from the root seed was requested, but the
    /// signing key carries none.
    #[error("no root signing seed is attached to this signing key, so no {0} key can be derived")]
    MissingRootSeed(SigningSchemeType),
    /// An integer discriminant did not correspond to any known signing scheme.
    #[error("unsupported signing scheme discriminant: {0}")]
    UnknownScheme(i32),
    /// A string did not name any known signing scheme.
    #[error(
        "unknown signing scheme {0:?}, expected one of: {expected}",
        expected = SigningSchemeType::VARIANTS.join(", ")
    )]
    UnknownSchemeName(String),
}

/// Trait for any value that is tied to a concrete signature scheme.
pub trait HasSigningScheme {
    fn signing_scheme_type(&self) -> SigningSchemeType;
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum SigningSchemeTypeVersions {
    V0(SigningSchemeType),
}

/// A signature profile: a key type together with the message convention it signs
/// under.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
    Display,
    EnumIter,
    EnumCount,
    EnumString,
    VariantNames,
    Versionize,
)]
#[versionize(SigningSchemeTypeVersions)]
#[strum(ascii_case_insensitive)]
pub enum SigningSchemeType {
    // WARNING: Do not reorder or remove variants; only append.
    Ecdsa256k1,
    Ed25519,
    MlDsa44, // NIST level 2
    MlDsa65, // NIST level 3
    MlDsa87, // NIST level 5
}

impl SigningSchemeType {
    /// The expected length of the digest for this scheme.
    pub fn expected_digest_len(self) -> usize {
        match self {
            // The Ethereum address of the key.
            SigningSchemeType::Ecdsa256k1 => Address::len_bytes(),
            // The full public key.
            SigningSchemeType::Ed25519 => PUBLIC_KEY_LENGTH,
            // A Shake256 digest of the public key, since an ML-DSA public key is far too large
            // to serve as an identifier itself.
            SigningSchemeType::MlDsa44
            | SigningSchemeType::MlDsa65
            | SigningSchemeType::MlDsa87 => DIGEST_BYTES,
        }
    }

    /// The schemes a request asks its response to be signed under.
    ///
    /// An explicit list is honoured as given, so a caller that wants only
    /// [`SigningSchemeType::Ed25519`] gets exactly that. An empty list resolves to
    /// [`SigningSchemeType::Ecdsa256k1`].
    pub fn resolve_requested(requested: &[i32]) -> Result<Vec<Self>, SigningError> {
        if requested.is_empty() {
            return Ok(vec![SigningSchemeType::Ecdsa256k1]);
        }
        let mut resolved = Vec::with_capacity(SigningSchemeType::COUNT);
        for &raw in requested {
            let scheme = SigningSchemeType::try_from(raw)?;
            if !resolved.contains(&scheme) {
                resolved.push(scheme);
            }
        }
        Ok(resolved)
    }

    /// The schemes named by `requested`, for command-line and config input.
    ///
    /// An unrecognised name is an error that lists the accepted spellings.
    ///
    /// Only the parsing lives here: the resolution itself is
    /// [`Self::resolve_requested`], so the two forms cannot drift apart.
    pub fn parse_requested<S: AsRef<str>>(requested: &[S]) -> Result<Vec<Self>, SigningError> {
        let mut raw = Vec::with_capacity(requested.len());
        for name in requested {
            let name = name.as_ref().trim();
            let scheme = SigningSchemeType::from_str(name)
                .map_err(|_| SigningError::UnknownSchemeName(name.to_owned()))?;
            raw.push(scheme.as_wire());
        }
        Self::resolve_requested(&raw)
    }

    /// The discriminant this scheme travels as on the wire, as the gRPC
    /// `SigningSchemeType` field holds it.
    pub fn as_wire(self) -> i32 {
        kms_grpc::kms::v1::SigningSchemeType::from(self) as i32
    }

    /// The scheme's stable 4-byte tag, for binding a scheme into a hash input.
    fn tag(self) -> [u8; 4] {
        self.as_wire().to_le_bytes()
    }
}

impl From<kms_grpc::kms::v1::SigningSchemeType> for SigningSchemeType {
    fn from(value: kms_grpc::kms::v1::SigningSchemeType) -> Self {
        match value {
            kms_grpc::kms::v1::SigningSchemeType::Ecdsa256k1 => SigningSchemeType::Ecdsa256k1,
            kms_grpc::kms::v1::SigningSchemeType::Ed25519 => SigningSchemeType::Ed25519,
            kms_grpc::kms::v1::SigningSchemeType::Mldsa44 => SigningSchemeType::MlDsa44,
            kms_grpc::kms::v1::SigningSchemeType::Mldsa65 => SigningSchemeType::MlDsa65,
            kms_grpc::kms::v1::SigningSchemeType::Mldsa87 => SigningSchemeType::MlDsa87,
        }
    }
}

impl From<SigningSchemeType> for kms_grpc::kms::v1::SigningSchemeType {
    fn from(value: SigningSchemeType) -> Self {
        match value {
            SigningSchemeType::Ecdsa256k1 => kms_grpc::kms::v1::SigningSchemeType::Ecdsa256k1,
            SigningSchemeType::Ed25519 => kms_grpc::kms::v1::SigningSchemeType::Ed25519,
            SigningSchemeType::MlDsa44 => kms_grpc::kms::v1::SigningSchemeType::Mldsa44,
            SigningSchemeType::MlDsa65 => kms_grpc::kms::v1::SigningSchemeType::Mldsa65,
            SigningSchemeType::MlDsa87 => kms_grpc::kms::v1::SigningSchemeType::Mldsa87,
        }
    }
}

impl TryFrom<i32> for SigningSchemeType {
    type Error = SigningError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        kms_grpc::kms::v1::SigningSchemeType::try_from(value)
            .map(SigningSchemeType::from)
            .map_err(|_| SigningError::UnknownScheme(value))
    }
}

/// A signature scheme, implemented on a zero-sized marker type per scheme.
///
/// Every implementation signs `dsep ‖ msg` and applies any scheme-specific
/// normalization/encoding, returning the scheme's standard signature bytes.
pub trait SigningScheme {
    type SigningKey;
    type VerificationKey;

    /// Sign `dsep ‖ msg`, returning the scheme's standard signature encoding.
    #[cfg(feature = "non-wasm")]
    fn sign(dsep: &DomainSep, msg: &[u8], sk: &Self::SigningKey) -> Result<Vec<u8>, SigningError>;

    /// Verify a signature over `dsep ‖ msg`.
    fn verify(
        dsep: &DomainSep,
        msg: &[u8],
        sig: &[u8],
        vk: &Self::VerificationKey,
    ) -> Result<(), SigningError>;

    /// Derive the verification key from the signing key if possible, otherwise return an error.
    fn verifying_key(sk: &Self::SigningKey) -> Result<Self::VerificationKey, SigningError>;
}

/// A digital signature together with the scheme that produced it.
///
/// Not `Versionize`: a `Signature` is never persisted or `safe_serialize`d — it
/// only ever crosses the wire as its raw, scheme-specific bytes (see
/// [`Signature::to_bytes`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub(crate) scheme: SigningSchemeType,
    pub(crate) sig: Vec<u8>,
}

impl Signature {
    /// Construct from a scheme tag and raw scheme-specific bytes.
    ///
    /// No validation of `sig` against `scheme` happens here.
    pub fn new(scheme: SigningSchemeType, sig: Vec<u8>) -> Self {
        Self { scheme, sig }
    }

    /// The signature scheme that produced this signature.
    pub fn scheme(&self) -> SigningSchemeType {
        self.scheme
    }

    /// The raw, scheme-specific signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.sig
    }

    /// A copy of the raw, scheme-specific signature bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.sig.clone()
    }
}

impl HasSigningScheme for Signature {
    fn signing_scheme_type(&self) -> SigningSchemeType {
        self.scheme
    }
}

/// A signing key tagged with the scheme it belongs to.
/// Large types are boxed so the enum remains small to move.
#[allow(clippy::large_enum_variant)]
pub enum UnifiedPrivateSigKey {
    Ecdsa256k1(PrivateSigKey),
    Ed25519(Ed25519SigningKey),
    MlDsa44(Box<MlDsaSigningKey<MlDsa44>>),
    MlDsa65(Box<MlDsaSigningKey<MlDsa65>>),
    MlDsa87(Box<MlDsaSigningKey<MlDsa87>>),
}

impl HasSigningScheme for UnifiedPrivateSigKey {
    fn signing_scheme_type(&self) -> SigningSchemeType {
        match self {
            UnifiedPrivateSigKey::Ecdsa256k1(_) => SigningSchemeType::Ecdsa256k1,
            UnifiedPrivateSigKey::Ed25519(_) => SigningSchemeType::Ed25519,
            UnifiedPrivateSigKey::MlDsa44(_) => SigningSchemeType::MlDsa44,
            UnifiedPrivateSigKey::MlDsa65(_) => SigningSchemeType::MlDsa65,
            UnifiedPrivateSigKey::MlDsa87(_) => SigningSchemeType::MlDsa87,
        }
    }
}

impl UnifiedPrivateSigKey {
    /// Derive the matching public verification key, when the scheme supports it.
    ///
    /// Currently always `Ok` (every supported scheme can derive it); fallible so
    /// a future scheme that cannot may error rather than panic.
    pub fn verifying_key(&self) -> Result<UnifiedPublicSigKey, SigningError> {
        Ok(match self {
            UnifiedPrivateSigKey::Ecdsa256k1(sk) => {
                UnifiedPublicSigKey::Ecdsa256k1(Ecdsa256k1::verifying_key(sk)?)
            }
            UnifiedPrivateSigKey::Ed25519(sk) => {
                UnifiedPublicSigKey::Ed25519(Ed25519VerfKey(Ed25519::verifying_key(sk)?))
            }
            UnifiedPrivateSigKey::MlDsa44(sk) => UnifiedPublicSigKey::MlDsa44(Box::new(
                MlDsaVerfKey(MlDsa::<MlDsa44>::verifying_key(sk)?),
            )),
            UnifiedPrivateSigKey::MlDsa65(sk) => UnifiedPublicSigKey::MlDsa65(Box::new(
                MlDsaVerfKey(MlDsa::<MlDsa65>::verifying_key(sk)?),
            )),
            UnifiedPrivateSigKey::MlDsa87(sk) => UnifiedPublicSigKey::MlDsa87(Box::new(
                MlDsaVerfKey(MlDsa::<MlDsa87>::verifying_key(sk)?),
            )),
        })
    }
}

impl Zeroize for UnifiedPrivateSigKey {
    fn zeroize(&mut self) {
        match self {
            // `PrivateSigKey` wipes its inner key material in place.
            UnifiedPrivateSigKey::Ecdsa256k1(sk) => sk.zeroize(),
            // The ed25519 and ML-DSA signing keys expose no in-place `zeroize`;
            // they only wipe through their zeroizing `Drop`. Overwriting the key
            // with a fresh dummy drops — and thereby wipes — the real secret in
            // place.
            UnifiedPrivateSigKey::Ed25519(sk) => {
                *sk = Ed25519::keygen_from_seed(&[0u8; eddsa::SEED_LEN])
            }
            UnifiedPrivateSigKey::MlDsa44(sk) => {
                **sk = MlDsa::<MlDsa44>::keygen_from_seed(&[0u8; mldsa::SEED_LEN])
            }
            UnifiedPrivateSigKey::MlDsa65(sk) => {
                **sk = MlDsa::<MlDsa65>::keygen_from_seed(&[0u8; mldsa::SEED_LEN])
            }
            UnifiedPrivateSigKey::MlDsa87(sk) => {
                **sk = MlDsa::<MlDsa87>::keygen_from_seed(&[0u8; mldsa::SEED_LEN])
            }
        }
    }
}

// Marker only, not derived: `Box<MlDsaSigningKey<_>>` implements neither
// `Zeroize` nor `ZeroizeOnDrop` — the `zeroize` crate covers `Box<[T]>`, not
// `Box<T>` — even though the *inner* `MlDsaSigningKey<_>` implements both, so
// the derive macro cannot prove the bound. The invariant holds regardless:
// every variant's key material wipes itself when dropped — ECDSA via its
// `WrappedSigningKey: ZeroizeOnDrop` field, ed25519 and ML-DSA via their own
// zeroizing `Drop`, reached through the box's drop glue, which runs
// `drop_in_place` on the heap contents before deallocating. So dropping the
// enum zeroizes the secret.
impl ZeroizeOnDrop for UnifiedPrivateSigKey {}
// Deliberately no `Drop for UnifiedPrivateSigKey` calling `zeroize()`: the
// `Zeroize` impl above wipes *by* triggering the leaf types' `Drop`, which is
// exactly what a plain drop already does, so routing through it adds no
// guarantee — it only pays for a throwaway key (a full ML-DSA keygen) that is
// then itself dropped and wiped. It would also forbid moving out of the
// variants.

// The marker above is an assertion the compiler cannot check for us, and it
// rests on the *optional* `zeroize` features of `ml-dsa` and `ed25519-dalek`:
// both crates gate their entire zeroizing `Drop` behind `#[cfg(feature =
// "zeroize")]`. Were a dependency bump, a `default-features` change, or
// feature unification ever to drop either feature, the wiping would silently
// vanish and this marker would become a lie — with no compile error and no
// failing test. These bounds turn that into a build failure.
//
// Assert on the leaf key types rather than on `UnifiedPrivateSigKey` itself:
// its own `ZeroizeOnDrop` is the hand-written impl above, so asserting it
// would merely restate the claim under test.
const _: () = {
    const fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    // Wipes via `WrappedSigningKey`'s derived, compiler-checked `Drop`.
    assert_zeroize_on_drop::<PrivateSigKey>();
    // Requires `ed25519-dalek/zeroize`.
    assert_zeroize_on_drop::<Ed25519SigningKey>();
    // Require `ml-dsa/zeroize`.
    assert_zeroize_on_drop::<MlDsaSigningKey<MlDsa44>>();
    assert_zeroize_on_drop::<MlDsaSigningKey<MlDsa65>>();
    assert_zeroize_on_drop::<MlDsaSigningKey<MlDsa87>>();
};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, VersionsDispatch)]
pub enum UnifiedPublicSigKeyVersions {
    V0(UnifiedPublicSigKey),
}

/// A verification key tagged with the scheme it belongs to.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(UnifiedPublicSigKeyVersions)]
#[allow(clippy::large_enum_variant)]
pub enum UnifiedPublicSigKey {
    Ecdsa256k1(PublicSigKey),
    Ed25519(Ed25519VerfKey),
    MlDsa44(Box<MlDsaVerfKey<MlDsa44>>),
    MlDsa65(Box<MlDsaVerfKey<MlDsa65>>),
    MlDsa87(Box<MlDsaVerfKey<MlDsa87>>),
}

impl Named for UnifiedPublicSigKey {
    const NAME: &'static str = "UnifiedPublicSigKey";
}

impl UnifiedPublicSigKey {
    /// The identifier of this verification key, used to identify its operator in an MPC context.
    /// The encoding is scheme specific; see [`SigningSchemeType::expected_digest_len`] for the
    /// length each one has.
    pub fn digest(&self) -> Vec<u8> {
        match self {
            UnifiedPublicSigKey::Ecdsa256k1(vk) => vk.verf_key_id(),
            // The raw public key, which is also its Solana address.
            UnifiedPublicSigKey::Ed25519(vk) => vk.0.as_bytes().to_vec(),
            UnifiedPublicSigKey::MlDsa44(vk) => MlDsa::digest(SigningSchemeType::MlDsa44, &vk.0),
            UnifiedPublicSigKey::MlDsa65(vk) => MlDsa::digest(SigningSchemeType::MlDsa65, &vk.0),
            UnifiedPublicSigKey::MlDsa87(vk) => MlDsa::digest(SigningSchemeType::MlDsa87, &vk.0),
        }
    }

    /// The text form of [`Self::digest`], as stored under `TypedVerfAddress`:
    /// `0x`-prefixed hex.
    pub fn address_text(&self) -> String {
        match self {
            UnifiedPublicSigKey::Ecdsa256k1(vk) => vk.address().to_string(), // Already includes `0x`
            other => format!("0x{}", hex::encode(other.digest())),
        }
    }
}

impl HasSigningScheme for UnifiedPublicSigKey {
    fn signing_scheme_type(&self) -> SigningSchemeType {
        match self {
            UnifiedPublicSigKey::Ecdsa256k1(_) => SigningSchemeType::Ecdsa256k1,
            UnifiedPublicSigKey::Ed25519(_) => SigningSchemeType::Ed25519,
            UnifiedPublicSigKey::MlDsa44(_) => SigningSchemeType::MlDsa44,
            UnifiedPublicSigKey::MlDsa65(_) => SigningSchemeType::MlDsa65,
            UnifiedPublicSigKey::MlDsa87(_) => SigningSchemeType::MlDsa87,
        }
    }
}

/// The verification keys a client or validator holds for its peers: per party
/// id, one key per scheme that party has published.
pub type SchemeVerfKeys = HashMap<u32, HashMap<SigningSchemeType, UnifiedPublicSigKey>>;

/// The verification key `party_id` published for `scheme`, if it published one.
pub fn verf_key_for(
    keys: &SchemeVerfKeys,
    party_id: u32,
    scheme: SigningSchemeType,
) -> Option<&UnifiedPublicSigKey> {
    keys.get(&party_id).and_then(|keys| keys.get(&scheme))
}

/// Sign `msg` (domain-separated by `dsep`) under the scheme of `sk`.
#[cfg(feature = "non-wasm")]
pub fn unified_sign(
    dsep: &DomainSep,
    msg: &[u8],
    sk: &UnifiedPrivateSigKey,
) -> Result<Signature, SigningError> {
    let scheme = sk.signing_scheme_type();
    let sig = match sk {
        UnifiedPrivateSigKey::Ecdsa256k1(sk) => Ecdsa256k1::sign(dsep, msg, sk)?,
        UnifiedPrivateSigKey::Ed25519(sk) => Ed25519::sign(dsep, msg, sk)?,
        UnifiedPrivateSigKey::MlDsa44(sk) => MlDsa::<MlDsa44>::sign(dsep, msg, sk)?,
        UnifiedPrivateSigKey::MlDsa65(sk) => MlDsa::<MlDsa65>::sign(dsep, msg, sk)?,
        UnifiedPrivateSigKey::MlDsa87(sk) => MlDsa::<MlDsa87>::sign(dsep, msg, sk)?,
    };
    Ok(Signature::new(scheme, sig))
}

/// Verify `sig` over `msg` (domain-separated by `dsep`) against `vk`.
///
/// Errors if the signature's scheme does not match the verification key, if the
/// bytes are malformed for that scheme, or if verification fails.
pub fn unified_verify(
    dsep: &DomainSep,
    msg: &[u8],
    sig: &Signature,
    vk: &UnifiedPublicSigKey,
) -> Result<(), SigningError> {
    let key_scheme = vk.signing_scheme_type();
    if sig.scheme != key_scheme {
        return Err(SigningError::SchemeMismatch {
            signature: sig.scheme,
            key: key_scheme,
        });
    }
    let bytes = sig.as_bytes();
    match vk {
        UnifiedPublicSigKey::Ecdsa256k1(vk) => Ecdsa256k1::verify(dsep, msg, bytes, vk),
        UnifiedPublicSigKey::Ed25519(vk) => Ed25519::verify(dsep, msg, bytes, &vk.0),
        UnifiedPublicSigKey::MlDsa44(vk) => MlDsa::<MlDsa44>::verify(dsep, msg, bytes, &vk.0),
        UnifiedPublicSigKey::MlDsa65(vk) => MlDsa::<MlDsa65>::verify(dsep, msg, bytes, &vk.0),
        UnifiedPublicSigKey::MlDsa87(vk) => MlDsa::<MlDsa87>::verify(dsep, msg, bytes, &vk.0),
    }
}

/// Scaffolding shared by the test modules of this module and its backends.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::cryptography::signatures::gen_sig_keys;
    use crate::cryptography::signing::identity::NodeSigningIdentity;
    use crate::cryptography::signing::seed::RootSigningSeed;
    use rand::RngCore;

    pub(crate) fn random_seed<R: RngCore>(rng: &mut R) -> [u8; 32] {
        let mut s = [0u8; 32];
        rng.fill_bytes(&mut s);
        s
    }

    /// A complete node signing identity: an ECDSA key with a root seed attached.
    pub(crate) fn seeded_identity<R: rand::CryptoRng + RngCore>(
        rng: &mut R,
    ) -> NodeSigningIdentity {
        let (_pk, sk) = gen_sig_keys(rng);
        NodeSigningIdentity::new(sk, RootSigningSeed::random(rng))
    }

    /// The contract every [`SigningScheme`] backend owes, checked in one place so that a new
    /// backend gets the same coverage by writing a single call.
    ///
    /// A freshly produced signature verifies, and a tampered message, a different domain
    /// separator, a tampered signature and a truncated signature all reject. Key generation is
    /// not part of the trait, so the caller supplies the signing key.
    pub(crate) fn exercise_backend<S: SigningScheme>(dsep: &DomainSep, sk: &S::SigningKey) {
        let vk = S::verifying_key(sk).expect("the backend must derive its verification key");
        let sig = S::sign(dsep, b"hello", sk).expect("the backend must sign");
        S::verify(dsep, b"hello", &sig, &vk).expect("a fresh signature must verify");

        assert!(
            S::verify(dsep, b"HELLO", &sig, &vk).is_err(),
            "a tampered message verified"
        );
        assert!(
            S::verify(b"OTHERDSP", b"hello", &sig, &vk).is_err(),
            "a different domain separator verified"
        );

        let mut tampered = sig.clone();
        tampered[0] ^= 0x01;
        assert!(
            S::verify(dsep, b"hello", &tampered, &vk).is_err(),
            "a tampered signature verified"
        );

        assert!(
            S::verify(dsep, b"hello", &[0u8; 10], &vk).is_err(),
            "a truncated signature verified"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{random_seed, seeded_identity};
    use super::*;
    use crate::consts::SAFE_SER_SIZE_LIMIT;
    use crate::cryptography::signatures::gen_sig_keys;
    use aes_prng::AesRng;
    use rand::{RngCore, SeedableRng};
    use strum::IntoEnumIterator;
    use tfhe::safe_serialization::{safe_deserialize, safe_serialize};

    const DSEP: &DomainSep = b"SCHMTEST";

    fn all_private_keys<R: rand::CryptoRng + RngCore>(rng: &mut R) -> Vec<UnifiedPrivateSigKey> {
        let keys = vec![
            UnifiedPrivateSigKey::Ecdsa256k1(gen_sig_keys(rng).1),
            UnifiedPrivateSigKey::Ed25519(Ed25519::keygen_from_seed(&random_seed(rng))),
            UnifiedPrivateSigKey::MlDsa44(Box::new(MlDsa::<MlDsa44>::keygen_from_seed(
                &random_seed(rng),
            ))),
            UnifiedPrivateSigKey::MlDsa65(Box::new(MlDsa::<MlDsa65>::keygen_from_seed(
                &random_seed(rng),
            ))),
            UnifiedPrivateSigKey::MlDsa87(Box::new(MlDsa::<MlDsa87>::keygen_from_seed(
                &random_seed(rng),
            ))),
        ];
        // This list is written out by hand, so pin it to the enum: a scheme added without a key
        // here would be skipped in silence by every test below rather than failing one.
        assert_eq!(
            keys.len(),
            SigningSchemeType::iter().count(),
            "all_private_keys does not cover every SigningSchemeType"
        );
        keys
    }

    /// Every scheme round-trips; a tampered message fails.
    #[test]
    fn round_trip_all_schemes() {
        let mut rng = AesRng::seed_from_u64(1);
        let keys = all_private_keys(&mut rng);

        let msg = b"a message signed under several schemes at once";
        for sk in &keys {
            let vk = sk.verifying_key().unwrap();
            assert_eq!(sk.signing_scheme_type(), vk.signing_scheme_type());

            let sig = unified_sign(DSEP, msg, sk).unwrap();
            assert_eq!(sig.scheme(), sk.signing_scheme_type());
            unified_verify(DSEP, msg, &sig, &vk)
                .unwrap_or_else(|e| panic!("{:?} should verify: {e}", sig.scheme()));

            let bad = unified_verify(DSEP, b"a different message", &sig, &vk);
            assert!(
                bad.is_err(),
                "{:?} verified a tampered message",
                sig.scheme()
            );
        }
    }

    /// Spans a classic and a post-quantum scheme: mismatched keys/tags reject.
    #[test]
    fn cross_scheme_rejection() {
        let mut rng = AesRng::seed_from_u64(7);
        let ecdsa_key = UnifiedPrivateSigKey::Ecdsa256k1(gen_sig_keys(&mut rng).1);
        let mldsa_key = UnifiedPrivateSigKey::MlDsa65(Box::new(
            MlDsa::<MlDsa65>::keygen_from_seed(&random_seed(&mut rng)),
        ));
        let msg = b"hybrid classic + post-quantum message";

        let ecdsa_sig = unified_sign(DSEP, msg, &ecdsa_key).unwrap();
        let mldsa_sig = unified_sign(DSEP, msg, &mldsa_key).unwrap();

        unified_verify(DSEP, msg, &ecdsa_sig, &ecdsa_key.verifying_key().unwrap()).unwrap();
        unified_verify(DSEP, msg, &mldsa_sig, &mldsa_key.verifying_key().unwrap()).unwrap();

        assert!(
            unified_verify(DSEP, msg, &ecdsa_sig, &mldsa_key.verifying_key().unwrap()).is_err()
        );
        assert!(
            unified_verify(DSEP, msg, &mldsa_sig, &ecdsa_key.verifying_key().unwrap()).is_err()
        );
    }

    /// `zeroize` wipes the key material of every scheme: signing after it
    /// produces a different signature than before (the secret has changed).
    #[test]
    fn zeroize_wipes_every_scheme() {
        let mut rng = AesRng::seed_from_u64(11);
        let msg = b"zeroize must overwrite the signing key";
        for mut sk in all_private_keys(&mut rng) {
            let scheme = sk.signing_scheme_type();
            let before = unified_sign(DSEP, msg, &sk).unwrap();
            sk.zeroize();
            let after = unified_sign(DSEP, msg, &sk).unwrap();
            assert_ne!(before, after, "{scheme:?} key was not wiped by zeroize");
        }
    }

    /// Every scheme's unified verification key survives a safe-serialization
    /// round-trip (the persisted form used for `VerfKey`), keeping equality,
    /// scheme tag and digest — exercising the hand-written `Versionize`/serde
    /// impls for the ed25519 and ML-DSA wrappers.
    #[test]
    fn unified_public_sig_key_safe_serialization_round_trip() {
        let mut rng = AesRng::seed_from_u64(4242);
        let sk = seeded_identity(&mut rng);

        for scheme in SigningSchemeType::iter() {
            let vk = sk.unified_verifying_key(scheme).unwrap();

            let mut buf = Vec::new();
            safe_serialize(&vk, &mut buf, SAFE_SER_SIZE_LIMIT).unwrap();
            let back: UnifiedPublicSigKey =
                safe_deserialize(std::io::Cursor::new(&buf), SAFE_SER_SIZE_LIMIT).unwrap();

            assert_eq!(vk, back, "{scheme:?} verf key did not survive round-trip");
            assert_eq!(back.signing_scheme_type(), scheme);
            assert_eq!(vk.digest(), back.digest(), "{scheme:?} digest changed");
        }
    }

    /// The ECDSA arm must produce the same bytes as the legacy `internal_sign`.
    #[test]
    fn ecdsa_bytes_match_legacy_path() {
        let mut rng = AesRng::seed_from_u64(42);
        let (_pk, sk) = gen_sig_keys(&mut rng);
        let msg = b"bytes must be identical to the pre-existing ECDSA encoding";

        let legacy = ecdsa::internal_sign(DSEP, msg, &sk).unwrap();
        let unified = unified_sign(DSEP, msg, &UnifiedPrivateSigKey::Ecdsa256k1(sk)).unwrap();

        assert_eq!(unified.scheme(), SigningSchemeType::Ecdsa256k1);
        assert_eq!(unified.as_bytes(), legacy.as_bytes());
        assert_eq!(unified.as_bytes().len(), ecdsa::SIG_SIZE);
    }

    /// The internal and gRPC scheme enums must stay in lock-step.
    #[test]
    fn consistent_signing_scheme_conversion() {
        for scheme in SigningSchemeType::iter() {
            let wire = scheme as i32;
            let grpc = kms_grpc::kms::v1::SigningSchemeType::try_from(wire).unwrap();
            assert_eq!(
                SigningSchemeType::from(grpc),
                scheme,
                "{scheme} does not round-trip through kms_grpc"
            );
        }

        // The gRPC enum must not carry variants the internal enum is missing.
        let past_last = SigningSchemeType::iter().count() as i32;
        assert!(
            kms_grpc::kms::v1::SigningSchemeType::try_from(past_last).is_err(),
            "kms_grpc has a scheme with discriminant {past_last} that SigningSchemeType lacks"
        );
    }

    #[test]
    fn unified_verf_digest() {
        let mut rng = AesRng::seed_from_u64(505);
        let keys = all_private_keys(&mut rng);

        for sk in &keys {
            let vk = sk.verifying_key().unwrap();
            let digest = vk.digest();
            let expected_len = vk.signing_scheme_type().expected_digest_len();
            assert_eq!(
                digest.len(),
                expected_len,
                "{} should have a {} byte digest",
                vk.signing_scheme_type(),
                expected_len
            );
        }
    }

    /// An empty request resolves to ECDSA, an explicit list is honoured as given and
    /// de-duplicated, and an unknown scheme is an error.
    #[test]
    fn resolve_requested_defaults_to_ecdsa_and_dedups() {
        // Empty ⇒ ECDSA: a client that predates the field sends nothing and
        // expects the ECDSA signature it always got.
        assert_eq!(
            SigningSchemeType::resolve_requested(&[]).unwrap(),
            vec![SigningSchemeType::Ecdsa256k1]
        );

        // An explicit list is honoured as given; ECDSA is not added to it.
        let ed25519 = kms_grpc::kms::v1::SigningSchemeType::Ed25519 as i32;
        assert_eq!(
            SigningSchemeType::resolve_requested(&[ed25519]).unwrap(),
            vec![SigningSchemeType::Ed25519]
        );

        // Known schemes map through, preserving order.
        let ecdsa = kms_grpc::kms::v1::SigningSchemeType::Ecdsa256k1 as i32;
        let mldsa65 = kms_grpc::kms::v1::SigningSchemeType::Mldsa65 as i32;
        assert_eq!(
            SigningSchemeType::resolve_requested(&[ecdsa, mldsa65]).unwrap(),
            vec![SigningSchemeType::Ecdsa256k1, SigningSchemeType::MlDsa65]
        );

        // Duplicates are removed while preserving first-seen order.
        assert_eq!(
            SigningSchemeType::resolve_requested(&[mldsa65, ecdsa, mldsa65]).unwrap(),
            vec![SigningSchemeType::MlDsa65, SigningSchemeType::Ecdsa256k1]
        );

        // An unknown scheme is an error.
        assert!(SigningSchemeType::resolve_requested(&[9999]).is_err());
    }

    /// The string form a command line supplies follows the same rules as the
    /// gRPC form, and every scheme name round-trips through it.
    #[test]
    fn parse_requested_matches_resolve_requested() {
        // Naming nothing asks for ECDSA, exactly as an empty gRPC field does.
        assert_eq!(
            SigningSchemeType::parse_requested::<&str>(&[]).unwrap(),
            SigningSchemeType::resolve_requested(&[]).unwrap()
        );

        // Every scheme's own name parses back to it, whatever the casing, and
        // surrounding whitespace from a config value is ignored.
        for scheme in SigningSchemeType::iter() {
            let name = scheme.to_string();
            for spelling in [
                name.clone(),
                name.to_lowercase(),
                name.to_uppercase(),
                format!("  {name} "),
            ] {
                assert_eq!(
                    SigningSchemeType::parse_requested(&[spelling]).unwrap(),
                    vec![scheme],
                    "Spelling did not parse as {scheme}"
                );
            }
        }

        // Order is kept and duplicates are dropped, as in the gRPC form.
        assert_eq!(
            SigningSchemeType::parse_requested(&["mldsa65", "ecdsa256k1", "MlDsa65"]).unwrap(),
            vec![SigningSchemeType::MlDsa65, SigningSchemeType::Ecdsa256k1]
        );

        // A name that is not a scheme is an error naming the accepted spellings.
        let err = SigningSchemeType::parse_requested(&["rsa"])
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("rsa"),
            "the error does not quote the input: {err}"
        );
        for scheme in SigningSchemeType::iter() {
            assert!(
                err.contains(&scheme.to_string()),
                "the error does not list {scheme}: {err}"
            );
        }
    }
}

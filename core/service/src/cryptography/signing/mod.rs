//! Multi-scheme signing support (issue #3078).
//!
//! Every backend signs `dsep ‖ msg` and applies its own normalization/encoding
//! internally.

// The module is `pub(crate)` and its callers have not landed yet, so every
// scheme's API currently looks dead to the crate.
// TODO(#3078): remove this once the unified signing API is used by the KMS and other consumers.
#![allow(dead_code)]

pub mod ecdsa;
mod eddsa;
mod mldsa;

use ecdsa::Ecdsa256k1;
use ecdsa::{PrivateSigKey, PublicSigKey};
use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};
use eddsa::Ed25519;
use hashing::DomainSep;
use ml_dsa::{
    MlDsa44, MlDsa65, MlDsa87, SigningKey as MlDsaSigningKey, VerifyingKey as MlDsaVerifyingKey,
};
use mldsa::MlDsa;
use serde::{Deserialize, Serialize};
use strum::EnumIter;
use strum_macros::Display;
use tfhe_versionable::{Versionize, VersionsDispatch};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

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
    /// An integer discriminant did not correspond to any known signing scheme.
    #[error("unsupported signing scheme discriminant: {0}")]
    UnknownScheme(i32),
}

/// Trait for any value that is tied to a concrete signature scheme.
pub trait HasSigningScheme {
    fn signing_scheme_type(&self) -> SigningSchemeType;
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum SigningSchemeTypeVersions {
    V0(SigningSchemeType),
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, EnumIter, Versionize,
)]
#[versionize(SigningSchemeTypeVersions)]
pub enum SigningSchemeType {
    // WARNING: Do not reorder or remove variants; only append.
    Ecdsa256k1,
    Ed25519,
    MlDsa44, // NIST level 2
    MlDsa65, // NIST level 3
    MlDsa87, // NIST level 5
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
                UnifiedPublicSigKey::Ed25519(Ed25519::verifying_key(sk)?)
            }
            UnifiedPrivateSigKey::MlDsa44(sk) => {
                UnifiedPublicSigKey::MlDsa44(Box::new(MlDsa::<MlDsa44>::verifying_key(sk)?))
            }
            UnifiedPrivateSigKey::MlDsa65(sk) => {
                UnifiedPublicSigKey::MlDsa65(Box::new(MlDsa::<MlDsa65>::verifying_key(sk)?))
            }
            UnifiedPrivateSigKey::MlDsa87(sk) => {
                UnifiedPublicSigKey::MlDsa87(Box::new(MlDsa::<MlDsa87>::verifying_key(sk)?))
            }
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
                *sk = eddsa::keygen_from_seed(&[0u8; eddsa::SEED_LEN])
            }
            UnifiedPrivateSigKey::MlDsa44(sk) => {
                **sk = mldsa::keygen_from_seed::<MlDsa44>(&[0u8; mldsa::SEED_LEN])
            }
            UnifiedPrivateSigKey::MlDsa65(sk) => {
                **sk = mldsa::keygen_from_seed::<MlDsa65>(&[0u8; mldsa::SEED_LEN])
            }
            UnifiedPrivateSigKey::MlDsa87(sk) => {
                **sk = mldsa::keygen_from_seed::<MlDsa87>(&[0u8; mldsa::SEED_LEN])
            }
        }
    }
}

// Marker only, not derived: the boxed ML-DSA keys implement neither
// `Zeroize` nor `ZeroizeOnDrop` (the `zeroize` crate covers `Box<[T]>`, not
// `Box<T>`), so the derive macro cannot prove the bound. The invariant holds
// regardless: every variant's key material wipes itself when dropped — ECDSA
// via its `WrappedSigningKey: ZeroizeOnDrop` field, ed25519 and ML-DSA via
// their own zeroizing `Drop` — so dropping the enum zeroizes the secret.
impl ZeroizeOnDrop for UnifiedPrivateSigKey {}

/// A verification key tagged with the scheme it belongs to.
#[allow(clippy::large_enum_variant)]
pub enum UnifiedPublicSigKey {
    Ecdsa256k1(PublicSigKey),
    Ed25519(Ed25519VerifyingKey),
    MlDsa44(Box<MlDsaVerifyingKey<MlDsa44>>),
    MlDsa65(Box<MlDsaVerifyingKey<MlDsa65>>),
    MlDsa87(Box<MlDsaVerifyingKey<MlDsa87>>),
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

/// Sign `msg` (domain-separated by `dsep`) under the scheme of `sk`.
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
        UnifiedPublicSigKey::Ed25519(vk) => Ed25519::verify(dsep, msg, bytes, vk),
        UnifiedPublicSigKey::MlDsa44(vk) => MlDsa::<MlDsa44>::verify(dsep, msg, bytes, vk),
        UnifiedPublicSigKey::MlDsa65(vk) => MlDsa::<MlDsa65>::verify(dsep, msg, bytes, vk),
        UnifiedPublicSigKey::MlDsa87(vk) => MlDsa::<MlDsa87>::verify(dsep, msg, bytes, vk),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::signatures::gen_sig_keys;
    use aes_prng::AesRng;
    use rand::{RngCore, SeedableRng};
    use strum::IntoEnumIterator;

    const DSEP: &DomainSep = b"SCHMTEST";

    fn seed<R: RngCore>(rng: &mut R) -> [u8; 32] {
        let mut s = [0u8; 32];
        rng.fill_bytes(&mut s);
        s
    }

    fn all_private_keys<R: rand::CryptoRng + RngCore>(rng: &mut R) -> Vec<UnifiedPrivateSigKey> {
        vec![
            UnifiedPrivateSigKey::Ecdsa256k1(gen_sig_keys(rng).1),
            UnifiedPrivateSigKey::Ed25519(eddsa::keygen_from_seed(&seed(rng))),
            UnifiedPrivateSigKey::MlDsa44(Box::new(mldsa::keygen_from_seed::<MlDsa44>(&seed(rng)))),
            UnifiedPrivateSigKey::MlDsa65(Box::new(mldsa::keygen_from_seed::<MlDsa65>(&seed(rng)))),
            UnifiedPrivateSigKey::MlDsa87(Box::new(mldsa::keygen_from_seed::<MlDsa87>(&seed(rng)))),
        ]
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
            mldsa::keygen_from_seed::<MlDsa65>(&seed(&mut rng)),
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
}

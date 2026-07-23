//! Multi-scheme signing support (issue #3078).
//!
//! Every backend signs `dsep ‖ msg` and applies its own normalization/encoding
//! internally. The module is ungated: all schemes must eventually be available
//! in the wasm verifier, and ECDSA is already used there.

pub mod ecdsa;
pub mod eddsa;
pub mod mldsa;

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
use strum_macros::Display;
use tfhe::named::Named;
use tfhe_versionable::{Versionize, VersionsDispatch};

/// Trait for any value that is tied to a concrete signature scheme.
pub trait HasSigningScheme {
    fn signing_scheme_type(&self) -> SigningSchemeType;
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum SigningSchemeTypeVersions {
    V0(SigningSchemeType),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, Versionize)]
#[versionize(SigningSchemeTypeVersions)]
pub enum SigningSchemeType {
    // WARNING: Do not reorder or remove variants; the discriminant is what
    // gets persisted through `SigningSchemeTypeVersions::V0`. New schemes must
    // be appended.
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
    type Error = anyhow::Error;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SigningSchemeType::Ecdsa256k1),
            1 => Ok(SigningSchemeType::Ed25519),
            2 => Ok(SigningSchemeType::MlDsa44),
            3 => Ok(SigningSchemeType::MlDsa65),
            4 => Ok(SigningSchemeType::MlDsa87),
            _ => Err(anyhow::anyhow!(
                "Unsupported SigningSchemeType: {:?}",
                value
            )),
        }
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
    fn sign(dsep: &DomainSep, msg: &[u8], sk: &Self::SigningKey) -> anyhow::Result<Vec<u8>>;

    /// Verify a signature over `dsep ‖ msg`.
    fn verify(
        dsep: &DomainSep,
        msg: &[u8],
        sig: &[u8],
        vk: &Self::VerificationKey,
    ) -> anyhow::Result<()>;

    /// Derive the verification key from the signing key if possible, otherwise return an error.
    fn verifying_key(sk: &Self::SigningKey) -> anyhow::Result<Self::VerificationKey>;
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum SignatureVersions {
    V0(Signature),
}

/// A digital signature together with the scheme that produced it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(SignatureVersions)]
pub struct Signature {
    pub(crate) scheme: SigningSchemeType,
    pub(crate) sig: Vec<u8>,
}

impl Named for Signature {
    const NAME: &'static str = "Signature";
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
/// Large types are boxed s.t. the enum remains small and copyable.
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
    pub fn verifying_key(&self) -> anyhow::Result<UnifiedPublicSigKey> {
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
) -> anyhow::Result<Signature> {
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
    // TODO we should add a proper error type for this
) -> anyhow::Result<()> {
    let key_scheme = vk.signing_scheme_type();
    if sig.scheme != key_scheme {
        anyhow::bail!(
            "signature scheme {:?} does not match verification key scheme {:?}",
            sig.scheme,
            key_scheme
        );
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
}

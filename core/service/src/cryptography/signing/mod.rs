//! Multi-scheme signing support (issue #3078).
//!
//! This module is the single home for signing:
//! - the per-scheme backends [`ecdsa`], [`eddsa`] and [`mldsa`], each following
//!   the same shape (the bytes signed are always `dsep ‖ msg`, and any
//!   scheme-specific normalization/encoding is applied inside the backend);
//! - the high-level, scheme-tagged API ([`UnifiedPrivateSigKey`] /
//!   [`UnifiedPublicSigKey`] / [`UnifiedSignature`] and [`unified_sign`] /
//!   [`unified_verify`]) that dispatches to those backends.
//!
//! [`ecdsa`] also owns the low-level `internal_sign` / `internal_verify_sig` /
//! `check_normalized` primitives (re-exported from
//! [`crate::cryptography::signatures`]). It is deliberately outside the
//! `non-wasm` gate because the ECDSA path is used by the wasm verifier; the
//! ed25519 / ML-DSA backends and the `Unified*` layer are gated because they
//! depend on the `ed25519-dalek` / `ml-dsa` crates.

pub mod ecdsa;
#[cfg(feature = "non-wasm")]
pub mod eddsa;
#[cfg(feature = "non-wasm")]
pub mod mldsa;

#[cfg(feature = "non-wasm")]
pub use multi_scheme::{
    UnifiedPrivateSigKey, UnifiedPublicSigKey, UnifiedSignature, unified_sign, unified_verify,
};

/// Scheme-tagged keys/signatures and the dispatcher over the per-scheme
/// backends. Gated to `non-wasm` because it references the ed25519 / ML-DSA
/// key types.
#[cfg(feature = "non-wasm")]
mod multi_scheme {
    use super::{ecdsa, eddsa, mldsa};
    use crate::cryptography::signatures::{
        HasSigningScheme, PrivateSigKey, PublicSigKey, SigningSchemeType,
    };
    use ed25519_dalek::{SigningKey as Ed25519SigningKey, VerifyingKey as Ed25519VerifyingKey};
    use hashing::DomainSep;
    use ml_dsa::{
        MlDsa44, MlDsa65, MlDsa87, SigningKey as MlDsaSigningKey,
        VerifyingKey as MlDsaVerifyingKey,
    };

    /// A signing key tagged with the scheme it belongs to.
    ///
    /// The ECDSA variant reuses the existing [`PrivateSigKey`] so the primary
    /// secp256k1 identity is unchanged. The ML-DSA variants are boxed because
    /// their key material is large (several KB) relative to the other variants.
    #[allow(clippy::large_enum_variant)]
    pub enum UnifiedPrivateSigKey {
        /// ECDSA over secp256k1 — the existing, primary signing key.
        Ecdsa256k1(PrivateSigKey),
        /// EdDSA over ed25519.
        Ed25519(Ed25519SigningKey),
        /// ML-DSA (FIPS 204) parameter set 44. Boxed to keep the enum small.
        MlDsa44(Box<MlDsaSigningKey<MlDsa44>>),
        /// ML-DSA (FIPS 204) parameter set 65. Boxed to keep the enum small.
        MlDsa65(Box<MlDsaSigningKey<MlDsa65>>),
        /// ML-DSA (FIPS 204) parameter set 87. Boxed to keep the enum small.
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
        /// Derive the matching public verification key, when the scheme
        /// supports it.
        ///
        /// Deriving the verification key from the signing key alone is possible
        /// for every scheme supported today, so this currently always returns
        /// `Ok`. The signature is fallible on purpose: a future scheme whose
        /// public key cannot be recovered from the private key must return an
        /// error here rather than being forced to panic or fabricate a key.
        pub fn verifying_key(&self) -> anyhow::Result<UnifiedPublicSigKey> {
            Ok(match self {
                UnifiedPrivateSigKey::Ecdsa256k1(sk) => {
                    UnifiedPublicSigKey::Ecdsa256k1(ecdsa::verifying_key(sk))
                }
                UnifiedPrivateSigKey::Ed25519(sk) => {
                    UnifiedPublicSigKey::Ed25519(eddsa::verifying_key(sk))
                }
                UnifiedPrivateSigKey::MlDsa44(sk) => {
                    UnifiedPublicSigKey::MlDsa44(Box::new(mldsa::verifying_key(sk)))
                }
                UnifiedPrivateSigKey::MlDsa65(sk) => {
                    UnifiedPublicSigKey::MlDsa65(Box::new(mldsa::verifying_key(sk)))
                }
                UnifiedPrivateSigKey::MlDsa87(sk) => {
                    UnifiedPublicSigKey::MlDsa87(Box::new(mldsa::verifying_key(sk)))
                }
            })
        }
    }

    /// A verification key tagged with the scheme it belongs to.
    ///
    /// Mirrors [`UnifiedPrivateSigKey`]; the ML-DSA variants are boxed for the
    /// same size reason.
    #[allow(clippy::large_enum_variant)]
    pub enum UnifiedPublicSigKey {
        /// ECDSA over secp256k1 — the existing, primary verification key.
        Ecdsa256k1(PublicSigKey),
        /// EdDSA over ed25519.
        Ed25519(Ed25519VerifyingKey),
        /// ML-DSA (FIPS 204) parameter set 44.
        MlDsa44(Box<MlDsaVerifyingKey<MlDsa44>>),
        /// ML-DSA (FIPS 204) parameter set 65.
        MlDsa65(Box<MlDsaVerifyingKey<MlDsa65>>),
        /// ML-DSA (FIPS 204) parameter set 87.
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

    /// A digital signature together with the scheme that produced it.
    ///
    /// The `sig` bytes use each scheme's standard encoding:
    /// - `Ecdsa256k1`: the 64-byte normalized `r‖s`,
    /// - `Ed25519`: the 64-byte `R‖s`,
    /// - `MlDsa*`: the FIPS 204 signature encoding for the given parameter set.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct UnifiedSignature {
        scheme: SigningSchemeType,
        sig: Vec<u8>,
    }

    impl UnifiedSignature {
        /// The signature scheme that produced this signature.
        pub fn scheme(&self) -> SigningSchemeType {
            self.scheme
        }

        /// The raw, scheme-specific signature bytes.
        pub fn as_bytes(&self) -> &[u8] {
            &self.sig
        }

        /// Consume the signature and return its raw scheme-specific bytes.
        pub fn into_bytes(self) -> Vec<u8> {
            self.sig
        }

        /// Reconstruct a [`UnifiedSignature`] from a scheme tag and raw bytes.
        ///
        /// No validation of `sig` against `scheme` is performed here; malformed
        /// bytes surface as an error only when [`unified_verify`] decodes them.
        pub fn new(scheme: SigningSchemeType, sig: Vec<u8>) -> Self {
            Self { scheme, sig }
        }
    }

    impl HasSigningScheme for UnifiedSignature {
        fn signing_scheme_type(&self) -> SigningSchemeType {
            self.scheme
        }
    }

    /// Sign `msg` (domain-separated by `dsep`) under the scheme of `sk`.
    ///
    /// The message that is actually signed is `dsep ‖ msg`. Dispatches to the
    /// per-scheme backend, which applies any scheme-specific normalization.
    pub fn unified_sign(
        dsep: &DomainSep,
        msg: &[u8],
        sk: &UnifiedPrivateSigKey,
    ) -> anyhow::Result<UnifiedSignature> {
        let scheme = sk.signing_scheme_type();
        let sig = match sk {
            UnifiedPrivateSigKey::Ecdsa256k1(sk) => ecdsa::sign(dsep, msg, sk)?,
            UnifiedPrivateSigKey::Ed25519(sk) => eddsa::sign(dsep, msg, sk)?,
            UnifiedPrivateSigKey::MlDsa44(sk) => mldsa::sign(dsep, msg, sk)?,
            UnifiedPrivateSigKey::MlDsa65(sk) => mldsa::sign(dsep, msg, sk)?,
            UnifiedPrivateSigKey::MlDsa87(sk) => mldsa::sign(dsep, msg, sk)?,
        };
        Ok(UnifiedSignature { scheme, sig })
    }

    /// Verify `sig` over `msg` (domain-separated by `dsep`) against `vk`.
    ///
    /// Returns an error if the signature's scheme does not match the
    /// verification key, if the signature bytes are malformed for that scheme,
    /// or if verification fails.
    pub fn unified_verify(
        dsep: &DomainSep,
        msg: &[u8],
        sig: &UnifiedSignature,
        vk: &UnifiedPublicSigKey,
    ) -> anyhow::Result<()> {
        let key_scheme = vk.signing_scheme_type();
        if sig.scheme != key_scheme {
            anyhow::bail!(
                "signature scheme {:?} does not match verification key scheme {:?}",
                sig.scheme,
                key_scheme
            );
        }
        match vk {
            UnifiedPublicSigKey::Ecdsa256k1(vk) => ecdsa::verify(dsep, msg, &sig.sig, vk),
            UnifiedPublicSigKey::Ed25519(vk) => eddsa::verify(dsep, msg, &sig.sig, vk),
            UnifiedPublicSigKey::MlDsa44(vk) => mldsa::verify(dsep, msg, &sig.sig, vk),
            UnifiedPublicSigKey::MlDsa65(vk) => mldsa::verify(dsep, msg, &sig.sig, vk),
            UnifiedPublicSigKey::MlDsa87(vk) => mldsa::verify(dsep, msg, &sig.sig, vk),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::cryptography::signatures::{
            HasSigningScheme, SIG_SIZE, SigningSchemeType, gen_sig_keys,
        };
        use crate::cryptography::signing::{ecdsa, eddsa, mldsa};
        use aes_prng::AesRng;
        use hashing::DomainSep;
        use ml_dsa::{MlDsa44, MlDsa65, MlDsa87};
        use rand::{RngCore, SeedableRng};

        const DSEP: &DomainSep = b"SCHMTEST";

        fn seed<R: RngCore>(rng: &mut R) -> [u8; 32] {
            let mut s = [0u8; 32];
            rng.fill_bytes(&mut s);
            s
        }

        fn all_private_keys<R: rand::CryptoRng + RngCore>(
            rng: &mut R,
        ) -> Vec<UnifiedPrivateSigKey> {
            vec![
                UnifiedPrivateSigKey::Ecdsa256k1(gen_sig_keys(rng).1),
                UnifiedPrivateSigKey::Ed25519(eddsa::keygen_from_seed(&seed(rng))),
                UnifiedPrivateSigKey::MlDsa44(Box::new(mldsa::keygen_from_seed::<MlDsa44>(&seed(
                    rng,
                )))),
                UnifiedPrivateSigKey::MlDsa65(Box::new(mldsa::keygen_from_seed::<MlDsa65>(&seed(
                    rng,
                )))),
                UnifiedPrivateSigKey::MlDsa87(Box::new(mldsa::keygen_from_seed::<MlDsa87>(&seed(
                    rng,
                )))),
            ]
        }

        /// Every scheme must round-trip: a signature made under a key verifies
        /// against that key's verification key, and a tampered message does not.
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

                // A tampered message must fail.
                let bad = unified_verify(DSEP, b"a different message", &sig, &vk);
                assert!(
                    bad.is_err(),
                    "{:?} verified a tampered message",
                    sig.scheme()
                );
            }
        }

        /// The acceptance criterion requires a test spanning both a classic and
        /// a post-quantum scheme: signatures must not verify under the wrong key
        /// or with a mismatched scheme tag.
        #[test]
        fn cross_scheme_rejection() {
            let mut rng = AesRng::seed_from_u64(7);
            let ecdsa_key = UnifiedPrivateSigKey::Ecdsa256k1(gen_sig_keys(&mut rng).1);
            let mldsa_key = UnifiedPrivateSigKey::MlDsa65(Box::new(mldsa::keygen_from_seed::<
                MlDsa65,
            >(&seed(&mut rng))));
            let msg = b"hybrid classic + post-quantum message";

            let ecdsa_sig = unified_sign(DSEP, msg, &ecdsa_key).unwrap();
            let mldsa_sig = unified_sign(DSEP, msg, &mldsa_key).unwrap();

            // Right key, right scheme: both verify.
            unified_verify(DSEP, msg, &ecdsa_sig, &ecdsa_key.verifying_key().unwrap()).unwrap();
            unified_verify(DSEP, msg, &mldsa_sig, &mldsa_key.verifying_key().unwrap()).unwrap();

            // A scheme-mismatched verification key is rejected before decoding.
            assert!(
                unified_verify(DSEP, msg, &ecdsa_sig, &mldsa_key.verifying_key().unwrap())
                    .is_err()
            );
            assert!(
                unified_verify(DSEP, msg, &mldsa_sig, &ecdsa_key.verifying_key().unwrap())
                    .is_err()
            );
        }

        /// The ECDSA arm of [`unified_sign`] must produce exactly the same bytes
        /// as the legacy `internal_sign` path, guaranteeing no wire-format
        /// change.
        #[test]
        fn ecdsa_bytes_match_legacy_path() {
            let mut rng = AesRng::seed_from_u64(42);
            let (_pk, sk) = gen_sig_keys(&mut rng);
            let msg = b"bytes must be identical to the pre-existing ECDSA encoding";

            let legacy = ecdsa::internal_sign(DSEP, msg, &sk).unwrap();
            let unified = unified_sign(DSEP, msg, &UnifiedPrivateSigKey::Ecdsa256k1(sk)).unwrap();

            assert_eq!(unified.scheme(), SigningSchemeType::Ecdsa256k1);
            assert_eq!(unified.as_bytes(), legacy.sig.to_vec().as_slice());
            assert_eq!(unified.as_bytes().len(), SIG_SIZE);
        }
    }
}

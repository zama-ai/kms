//! Pieces shared by every signcryption envelope format.
//!
//! Signing and verifying have to build *identical* receiver bindings or nothing
//! verifies at all, and both formats encrypt the same way. Anything both
//! [`super::ecdsa_v0`] and a future composite format need lives here, so the two
//! cannot drift apart and neither has to copy it.

use crate::cryptography::encryption::{UnifiedPrivateEncKey, UnifiedPublicEncKey};
use crate::cryptography::error::CryptographyError;
use crate::cryptography::hybrid_composite_ml_kem;
use crate::cryptography::hybrid_ml_kem::{self, HybridKemCt};
use crate::cryptography::signatures::{SigningSchemeSet, SigningSchemeType};
use hashing::{DomainSep, serialize_hash_element};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

pub(super) const DSEP_SIGNCRYPTION: DomainSep = *b"SIGNCRYP";

/// The layout of a signcryption's encrypted plaintext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SigncryptionFormat {
    /// `msg ‖ sig ‖ H(sender verification key)`, ECDSA only. Frozen; see the
    /// module documentation.
    EcdsaV0,
    /// A self-describing, versioned, multi-signature envelope.
    CompositeV1,
}

/// The format a signcryption under `schemes` uses.
///
/// A total function of the scheme set, deliberately. The alternative — sniffing
/// the decrypted bytes for a magic prefix — cannot work: an
/// [`SigncryptionFormat::EcdsaV0`] plaintext begins with attacker-influenced
/// message content and has no tag to find, so detection would be a heuristic, in
/// a parser sitting directly under a decryption key.
pub(super) fn format_for(schemes: &SigningSchemeSet) -> SigncryptionFormat {
    if schemes.as_slice() == [SigningSchemeType::Ecdsa256k1].as_slice() {
        SigncryptionFormat::EcdsaV0
    } else {
        SigncryptionFormat::CompositeV1
    }
}

/// The error for a scheme set no implemented envelope format covers.
pub(super) fn unsupported_format(schemes: &SigningSchemeSet) -> CryptographyError {
    CryptographyError::UnsupportedSigncryptionFormat(schemes.to_string())
}

/// The digest of the receiver's public encryption key, as it appears in the
/// signed preimage.
fn receiver_enc_key_digest(enc_key: &UnifiedPublicEncKey) -> Result<Vec<u8>, CryptographyError> {
    match enc_key {
        UnifiedPublicEncKey::MlKem512(public_enc_key) => {
            serialize_hash_element(&DSEP_SIGNCRYPTION, public_enc_key)
                .map_err(|e| CryptographyError::DeserializationError(e.to_string()))
        }
        UnifiedPublicEncKey::MlKem1024(_) => Err(CryptographyError::MlKem1024Unsupported),
        UnifiedPublicEncKey::MlKem1024P384(public_enc_key) => {
            serialize_hash_element(&DSEP_SIGNCRYPTION, public_enc_key)
                .map_err(|e| CryptographyError::DeserializationError(e.to_string()))
        }
    }
}

/// `receiver_id ‖ H(receiver public encryption key)`: the suffix that binds a
/// signcryption to who it was made for.
pub(super) fn receiver_binding(
    receiver_id: &[u8],
    enc_key: &UnifiedPublicEncKey,
) -> Result<Vec<u8>, CryptographyError> {
    Ok([receiver_id, receiver_enc_key_digest(enc_key)?.as_slice()].concat())
}

/// Encrypt `msg` under `enc_key` with the hybrid KEM/DEM matching its scheme.
pub(super) fn hybrid_encrypt(
    rng: &mut (impl CryptoRng + RngCore),
    msg: &[u8],
    enc_key: &UnifiedPublicEncKey,
) -> Result<HybridKemCt, CryptographyError> {
    match enc_key {
        UnifiedPublicEncKey::MlKem512(public_enc_key) => {
            hybrid_ml_kem::enc::<ml_kem::MlKem512, _>(rng, msg, &public_enc_key.0)
        }
        UnifiedPublicEncKey::MlKem1024(_) => Err(CryptographyError::MlKem1024Unsupported),
        UnifiedPublicEncKey::MlKem1024P384(public_enc_key) => {
            hybrid_composite_ml_kem::enc_ml_kem_1024_p384(rng, msg, public_enc_key)
        }
    }
}

/// Decrypt `ct` under `dec_key` with the hybrid KEM/DEM matching its scheme.
pub(super) fn hybrid_decrypt(
    ct: HybridKemCt,
    dec_key: &UnifiedPrivateEncKey,
) -> Result<Zeroizing<Vec<u8>>, CryptographyError> {
    match dec_key {
        UnifiedPrivateEncKey::MlKem512(dec_key) => {
            hybrid_ml_kem::dec::<ml_kem::MlKem512>(ct, &dec_key.0)
        }
        UnifiedPrivateEncKey::MlKem1024(_) => Err(CryptographyError::MlKem1024Unsupported),
        UnifiedPrivateEncKey::MlKem1024P384(dec_key) => {
            hybrid_composite_ml_kem::dec_ml_kem_1024_p384(ct, dec_key)
        }
    }
}

// Test scaffolding shared with `super::ecdsa_v0`, which locks the frozen layout
// against the same keys. Kept at module level rather than inside `tests` so both
// modules can reach it without either copying it.
#[cfg(test)]
use crate::cryptography::encryption::{Encryption, PkeScheme, PkeSchemeType};
#[cfg(test)]
use crate::cryptography::signatures::{PrivateSigKey, PublicSigKey, gen_sig_keys};
#[cfg(test)]
use aes_prng::AesRng;
#[cfg(test)]
use rand::SeedableRng;

/// The two schemes the frozen layout is actually used with: ML-KEM-512 for
/// user decryption, MLKEM1024-P384 for custodian backup.
#[allow(dead_code)]
pub(super) const LOCKED_SCHEMES: [PkeSchemeType; 2] =
    [PkeSchemeType::MlKem512, PkeSchemeType::MlKem1024P384];

#[allow(dead_code)]
pub(super) struct LockFixture {
    rng: AesRng,
    dec_key: UnifiedPrivateEncKey,
    enc_key: UnifiedPublicEncKey,
    sender_verf_key: PublicSigKey,
    signing_key: PrivateSigKey,
    receiver_id: Vec<u8>,
}

#[allow(dead_code)]
pub(super) fn lock_fixture(scheme: PkeSchemeType, seed: u64) -> LockFixture {
    let mut rng = AesRng::seed_from_u64(seed);
    let (sender_verf_key, signing_key) = gen_sig_keys(&mut rng);
    let (receiver_verf_key, _) = gen_sig_keys(&mut rng);
    // Scoped so that `rng` is no longer borrowed once the keys are out.
    let (dec_key, enc_key) = {
        let mut encryption = Encryption::new(scheme, &mut rng);
        encryption.keygen().unwrap()
    };
    LockFixture {
        rng,
        dec_key,
        enc_key,
        sender_verf_key,
        signing_key,
        receiver_id: receiver_verf_key.verf_key_id(),
    }
}

#[allow(dead_code)]
pub(super) fn expected_enc_key_digest(enc_key: &UnifiedPublicEncKey) -> Vec<u8> {
    match enc_key {
        UnifiedPublicEncKey::MlKem512(inner) => {
            serialize_hash_element(&DSEP_SIGNCRYPTION, inner).unwrap()
        }
        UnifiedPublicEncKey::MlKem1024P384(inner) => {
            serialize_hash_element(&DSEP_SIGNCRYPTION, inner).unwrap()
        }
        _ => unreachable!("only the two locked schemes are exercised"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strum::IntoEnumIterator;
    /// The binding must separate recipients on *both* of its inputs, since it is
    /// the only thing tying a signature to who may open it.
    #[test]
    fn receiver_binding_separates_recipients() {
        let f = lock_fixture(PkeSchemeType::MlKem512, 500);
        let other = lock_fixture(PkeSchemeType::MlKem512, 501);

        let base = receiver_binding(&f.receiver_id, &f.enc_key).unwrap();
        assert_eq!(base, receiver_binding(&f.receiver_id, &f.enc_key).unwrap());
        assert_ne!(
            base,
            receiver_binding(&other.receiver_id, &f.enc_key).unwrap()
        );
        assert_ne!(
            base,
            receiver_binding(&f.receiver_id, &other.enc_key).unwrap()
        );
    }

    /// The singleton ECDSA set — and only it — selects the frozen layout. This
    /// is what keeps user decryption on `EcdsaV0` without a dedicated branch.
    #[test]
    fn only_the_ecdsa_singleton_is_the_legacy_format() {
        use strum::IntoEnumIterator;

        assert_eq!(
            format_for(&SigningSchemeSet::single(SigningSchemeType::Ecdsa256k1)),
            SigncryptionFormat::EcdsaV0
        );

        for scheme in SigningSchemeType::iter().filter(|s| *s != SigningSchemeType::Ecdsa256k1) {
            assert_eq!(
                format_for(&SigningSchemeSet::single(scheme)),
                SigncryptionFormat::CompositeV1,
                "{scheme} alone must not select the frozen ECDSA layout"
            );
        }

        // Adding any scheme to ECDSA leaves the legacy format behind, which is
        // what stops a composite signcryption being parsed as a legacy one.
        assert_eq!(
            format_for(
                &SigningSchemeSet::new([SigningSchemeType::Ecdsa256k1, SigningSchemeType::MlDsa87])
                    .unwrap()
            ),
            SigncryptionFormat::CompositeV1
        );
    }
}

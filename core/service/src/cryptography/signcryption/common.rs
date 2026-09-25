//! Code shared by every signcryption envelope format.
//!
//! Signing and verifying build *identical* receiver bindings or nothing
//! verifies at all, and both formats encrypt the same way.

use crate::cryptography::encryption::{UnifiedPrivateEncKey, UnifiedPublicEncKey};
use crate::cryptography::error::CryptographyError;
use crate::cryptography::hybrid_composite_ml_kem;
use crate::cryptography::hybrid_ml_kem::{self, HybridKemCt};
use hashing::{DomainSep, serialize_hash_element};
use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

pub(super) const DSEP_SIGNCRYPTION: DomainSep = *b"SIGNCRYP";

/// The digest of the receiver's public encryption key, as it appears in the
/// signed preimage.
pub(super) fn receiver_enc_key_digest(
    enc_key: &UnifiedPublicEncKey,
) -> Result<Vec<u8>, CryptographyError> {
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

// Test scaffolding shared by both envelope formats. At module level rather than
// inside `tests` so that `ecdsa_v0` and `composite_v1` can reach it without a
// copy.
#[cfg(test)]
use super::{UnifiedSigncryptionKey, UnifiedUnsigncryptionKey};
#[cfg(test)]
use crate::cryptography::encryption::{Encryption, PkeScheme, PkeSchemeType};
#[cfg(test)]
use crate::cryptography::signatures::{
    PrivateSigKey, PublicSigKey, SigningSchemeType, VerfKeySet, gen_sig_keys,
};
#[cfg(test)]
use aes_prng::AesRng;
#[cfg(test)]
use rand::SeedableRng;
#[cfg(test)]
use std::sync::Arc;

/// One sender, one receiver, and the rng that produced them.
#[cfg(test)]
pub(super) struct SigncryptionFixture {
    pub(super) rng: AesRng,
    pub(super) signcryption_key: UnifiedSigncryptionKey,
    pub(super) unsigncryption_key: UnifiedUnsigncryptionKey,
}

#[cfg(test)]
impl SigncryptionFixture {
    /// The sender's ECDSA verification key, as the frozen reader names it.
    pub(super) fn sender_verf_key(&self) -> PublicSigKey {
        PublicSigKey::from_sk(self.signcryption_key.signing_key())
    }

    /// The schemes the reader demands, empty for a frozen reader.
    pub(super) fn schemes(&self) -> Vec<SigningSchemeType> {
        match &self.unsigncryption_key.sender {
            super::SenderAuth::Multi(keys) => keys.schemes(),
            super::SenderAuth::Ecdsa(_) => Vec::new(),
        }
    }

    /// A reader that deviates from this fixture in its sender policy or its
    /// receiver id, so a test can vary one of them at a time.
    pub(super) fn reader_with(
        &self,
        sender: super::SenderAuth,
        receiver_id: Vec<u8>,
    ) -> UnifiedUnsigncryptionKey {
        UnifiedUnsigncryptionKey {
            decryption_key: self.unsigncryption_key.decryption_key.clone(),
            encryption_key: self.unsigncryption_key.encryption_key.clone(),
            sender,
            receiver_id,
        }
    }
}

/// A fixture whose reader demands the frozen, single-ECDSA layout.
#[cfg(test)]
pub(super) fn signcryption_fixture(scheme: PkeSchemeType, seed: u64) -> SigncryptionFixture {
    let p = fixture_parts(scheme, seed);
    SigncryptionFixture {
        signcryption_key: UnifiedSigncryptionKey::from_signing_key(
            p.signing_key,
            p.enc_key.clone(),
            p.receiver_id.clone(),
        ),
        unsigncryption_key: UnifiedUnsigncryptionKey::new(
            Arc::new(p.dec_key),
            p.enc_key,
            p.sender_verf_key,
            p.receiver_id,
        ),
        rng: p.rng,
    }
}

/// A fixture whose reader demands a signature under every scheme in `schemes`.
#[cfg(test)]
pub(super) fn composite_fixture(
    scheme: PkeSchemeType,
    seed: u64,
    schemes: &[SigningSchemeType],
) -> SigncryptionFixture {
    use crate::cryptography::signing::test_support::seeded_identity;

    // The identity is drawn after the parts, as it was when the composite tests
    // built on top of `signcryption_fixture`, so a given seed still yields the
    // same keys.
    let mut p = fixture_parts(scheme, seed);
    let identity = Arc::new(seeded_identity(&mut p.rng));
    let keys = VerfKeySet::from_identity(&identity, schemes).unwrap();
    SigncryptionFixture {
        signcryption_key: UnifiedSigncryptionKey::new(
            identity,
            p.enc_key.clone(),
            p.receiver_id.clone(),
        ),
        unsigncryption_key: UnifiedUnsigncryptionKey::new_multi(
            Arc::new(p.dec_key),
            p.enc_key,
            keys,
            p.receiver_id,
        ),
        rng: p.rng,
    }
}

/// What both constructors draw from `seed`, in the order the fixtures have
/// always drawn it.
#[cfg(test)]
struct FixtureParts {
    rng: AesRng,
    sender_verf_key: PublicSigKey,
    signing_key: PrivateSigKey,
    dec_key: UnifiedPrivateEncKey,
    enc_key: UnifiedPublicEncKey,
    receiver_id: Vec<u8>,
}

#[cfg(test)]
fn fixture_parts(scheme: PkeSchemeType, seed: u64) -> FixtureParts {
    let mut rng = AesRng::seed_from_u64(seed);
    let (sender_verf_key, signing_key) = gen_sig_keys(&mut rng);
    let (receiver_verf_key, _) = gen_sig_keys(&mut rng);
    // Scoped so that `rng` is no longer borrowed once the keys are out.
    let (dec_key, enc_key) = {
        let mut encryption = Encryption::new(scheme, &mut rng);
        encryption.keygen().unwrap()
    };
    FixtureParts {
        rng,
        sender_verf_key,
        signing_key,
        dec_key,
        enc_key,
        receiver_id: receiver_verf_key.verf_key_id(),
    }
}

//! Code shared by every signcryption envelope format.
//!
//! Signing and verifying build *identical* receiver bindings or nothing
//! verifies at all.

use crate::cryptography::encryption::UnifiedPublicEncKey;
use crate::cryptography::error::CryptographyError;
use hashing::{DomainSep, serialize_hash_element};

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

#[cfg(test)]
pub(crate) mod test_support {
    //! Fixtures shared by both envelope formats' tests.

    use super::super::{SenderAuth, UnifiedSigncryptionKey, UnifiedUnsigncryptionKey};
    use crate::cryptography::encryption::{
        Encryption, PkeScheme, PkeSchemeType, UnifiedPrivateEncKey, UnifiedPublicEncKey,
    };
    use crate::cryptography::signatures::{
        PrivateSigKey, PublicSigKey, SigningSchemeType, VerfKeySet, gen_sig_keys,
    };
    use crate::cryptography::signing::test_support::seeded_identity;
    use aes_prng::AesRng;
    use rand::SeedableRng;
    use std::sync::Arc;

    /// One sender, one receiver, and the rng that produced them.
    pub(crate) struct SigncryptionFixture {
        pub(crate) rng: AesRng,
        pub(crate) signcryption_key: UnifiedSigncryptionKey,
        pub(crate) unsigncryption_key: UnifiedUnsigncryptionKey,
        /// Empty for a frozen fixture, which names no scheme set.
        schemes: Vec<SigningSchemeType>,
    }

    impl SigncryptionFixture {
        /// The sender's ECDSA verification key, as the frozen reader names it.
        pub(crate) fn sender_verf_key(&self) -> PublicSigKey {
            PublicSigKey::from_sk(self.signcryption_key.signing_key())
        }

        /// The schemes this fixture's reader demands.
        pub(crate) fn schemes(&self) -> Vec<SigningSchemeType> {
            self.schemes.clone()
        }

        /// A reader deviating from this fixture's in its sender policy alone.
        pub(crate) fn reader_for(&self, sender: SenderAuth) -> UnifiedUnsigncryptionKey {
            self.reader_with(sender, self.unsigncryption_key.receiver_id.clone())
        }

        /// A reader deviating from this fixture's in its receiver id alone.
        pub(crate) fn reader_to(&self, receiver_id: Vec<u8>) -> UnifiedUnsigncryptionKey {
            self.reader_with(self.unsigncryption_key.sender.clone(), receiver_id)
        }

        fn reader_with(
            &self,
            sender: SenderAuth,
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
    pub(crate) fn signcryption_fixture(scheme: PkeSchemeType, seed: u64) -> SigncryptionFixture {
        let p = fixture_parts(scheme, seed);
        let sender_verf_key = PublicSigKey::from_sk(&p.signing_key);
        SigncryptionFixture {
            signcryption_key: UnifiedSigncryptionKey::from_signing_key(
                p.signing_key,
                p.enc_key.clone(),
                p.receiver_id.clone(),
            ),
            unsigncryption_key: UnifiedUnsigncryptionKey::new(
                Arc::new(p.dec_key),
                p.enc_key,
                sender_verf_key,
                p.receiver_id,
            ),
            schemes: Vec::new(),
            rng: p.rng,
        }
    }

    /// A fixture whose reader demands a signature under every scheme in `schemes`.
    pub(crate) fn composite_fixture(
        scheme: PkeSchemeType,
        seed: u64,
        schemes: &[SigningSchemeType],
    ) -> SigncryptionFixture {
        // The identity is drawn after the parts, as it was when the composite tests
        // built on top of `signcryption_fixture`, so a given seed still yields the
        // same keys.
        let mut p = fixture_parts(scheme, seed);
        let identity = Arc::new(seeded_identity(&mut p.rng));
        let keys = VerfKeySet::from_identity(&identity, schemes).unwrap();
        // Canonical order, which is what the reader will demand.
        let demanded = keys.schemes();
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
            schemes: demanded,
            rng: p.rng,
        }
    }

    /// What both constructors draw from `seed`, in the order the fixtures have
    /// always drawn it.
    struct FixtureParts {
        rng: AesRng,
        signing_key: PrivateSigKey,
        dec_key: UnifiedPrivateEncKey,
        enc_key: UnifiedPublicEncKey,
        receiver_id: Vec<u8>,
    }

    fn fixture_parts(scheme: PkeSchemeType, seed: u64) -> FixtureParts {
        let mut rng = AesRng::seed_from_u64(seed);
        let (_sender_verf_key, signing_key) = gen_sig_keys(&mut rng);
        let (receiver_verf_key, _) = gen_sig_keys(&mut rng);
        // Scoped so that `rng` is no longer borrowed once the keys are out.
        let (dec_key, enc_key) = {
            let mut encryption = Encryption::new(scheme, &mut rng);
            encryption.keygen().unwrap()
        };
        FixtureParts {
            rng,
            signing_key,
            dec_key,
            enc_key,
            receiver_id: receiver_verf_key.verf_key_id(),
        }
    }
}

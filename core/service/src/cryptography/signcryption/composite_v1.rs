//! The composite signcryption envelope.

use super::UnifiedSigncryption;
#[cfg(feature = "non-wasm")]
use super::common::hybrid_encrypt;
use super::common::{hybrid_decrypt, receiver_enc_key_digest};
use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::cryptography::encryption::{HasPkeScheme, UnifiedPublicEncKey};
use crate::cryptography::error::CryptographyError;
use crate::cryptography::hybrid_ml_kem::HybridKemCt;
use crate::cryptography::signatures::StoredTypedSignature;
#[cfg(feature = "non-wasm")]
use crate::cryptography::signatures::SigningSchemeType;
#[cfg(feature = "non-wasm")]
use crate::cryptography::signcryption::UnifiedSigncryptionKey;
use crate::cryptography::signcryption::UnifiedUnsigncryptionKey;
#[cfg(feature = "non-wasm")]
use crate::cryptography::signing::composite::sign_uniform;
use crate::cryptography::signing::composite::verify_uniform;
#[cfg(feature = "non-wasm")]
use crate::cryptography::zeroizing_writer::ZeroizingWriter;
use hashing::DomainSep;
#[cfg(feature = "non-wasm")]
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tfhe::named::Named;
use tfhe::safe_serialization::safe_deserialize;
#[cfg(feature = "non-wasm")]
use tfhe::safe_serialization::safe_serialize;
use tfhe_versionable::{Versionize, VersionsDispatch};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, VersionsDispatch)]
pub enum CompositeEnvelopeVersions {
    V0(CompositeEnvelope),
}

/// The plaintext of a composite signcryption, before encryption.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(CompositeEnvelopeVersions)]
pub struct CompositeEnvelope {
    pub msg: Vec<u8>,
    pub signature: Vec<StoredTypedSignature>,
}

impl Named for CompositeEnvelope {
    const NAME: &'static str = "signcryption::CompositeEnvelope";
}

impl Zeroize for CompositeEnvelope {
    fn zeroize(&mut self) {
        // `signature` is public; `msg` is the secret this envelope exists to carry.
        self.msg.zeroize();
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, VersionsDispatch)]
pub enum SigncryptionSignedPayloadVersions {
    V0(SigncryptionSignedPayload),
}

/// What every signature of a composite signcryption covers: the message, and the
/// two values that tie it to one receiver.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(SigncryptionSignedPayloadVersions)]
pub struct SigncryptionSignedPayload {
    pub msg: Vec<u8>,
    /// The receiver's identifier, e.g. a blockchain address.
    pub receiver_id: Vec<u8>,
    pub enc_key_digest: Vec<u8>,
}

impl Named for SigncryptionSignedPayload {
    const NAME: &'static str = "signcryption::SigncryptionSignedPayload";
}

impl Zeroize for SigncryptionSignedPayload {
    fn zeroize(&mut self) {
        // The receiver id and the digest are public; `msg` is the secret.
        self.msg.zeroize();
    }
}

impl SigncryptionSignedPayload {
    /// What the signatures of a signcryption of `msg` to this receiver cover.
    fn new(
        msg: &[u8],
        receiver_id: &[u8],
        encryption_key: &UnifiedPublicEncKey,
    ) -> Result<Self, CryptographyError> {
        Ok(Self {
            msg: msg.to_vec(),
            receiver_id: receiver_id.to_vec(),
            enc_key_digest: receiver_enc_key_digest(encryption_key)?,
        })
    }
}

/// Signcrypt `msg` in the composite layout.
///
/// Sign-then-encrypt, as in the frozen layout. Each signature covers a
/// [`SigncryptionSignedPayload`]. The whole envelope is then encrypted to the
/// receiver.
#[cfg(feature = "non-wasm")]
pub(super) fn seal(
    signcrypt_key: &UnifiedSigncryptionKey,
    rng: &mut (impl CryptoRng + RngCore),
    dsep: &DomainSep,
    schemes: &[SigningSchemeType],
    msg: &[u8],
) -> Result<UnifiedSigncryption, CryptographyError> {
    let receiver_enc_key = &signcrypt_key.receiver_enc_key;
    let mut signed =
        SigncryptionSignedPayload::new(msg, &signcrypt_key.receiver_id, receiver_enc_key)?;
    let signature = sign_uniform(&signcrypt_key.identity, schemes, dsep, &signed);
    signed.zeroize();
    let signature = signature?;

    let mut envelope = CompositeEnvelope {
        msg: msg.to_vec(),
        signature,
    };
    let mut plaintext = ZeroizingWriter::new();
    let serialized = safe_serialize(&envelope, &mut plaintext, SAFE_SER_SIZE_LIMIT);
    // The envelope owns a second copy of the payload and nothing wipes it on drop,
    // so wipe it here, before either outcome leaves the function.
    envelope.zeroize();
    serialized.map_err(|e| CryptographyError::SerializationError(e.to_string()))?;

    let ciphertext = hybrid_encrypt(rng, plaintext.as_slice(), receiver_enc_key)?;
    let mut payload = Vec::new();
    safe_serialize(&ciphertext, &mut payload, SAFE_SER_SIZE_LIMIT)
        .map_err(|e| CryptographyError::SerializationError(e.to_string()))?;
    Ok(UnifiedSigncryption::new(
        payload,
        receiver_enc_key.encryption_scheme_type(),
    ))
}

/// Open a composite signcryption, returning the message only once every
/// constituent signature has verified.
///
/// `sender_keys` is the verifier's policy the signatures will be validated against.
pub(super) fn open(
    unsign_key: &UnifiedUnsigncryptionKey,
    dsep: &DomainSep,
    cipher: &UnifiedSigncryption,
) -> Result<Zeroizing<Vec<u8>>, CryptographyError> {
    if cipher.pke_type != unsign_key.encryption_key.encryption_scheme_type() {
        return Err(CryptographyError::VerificationError(
            "encryption type of cipher does not match the decryption key type".to_string(),
        ));
    }
    let sender_keys = match &unsign_key.sender {
        super::SenderAuth::Ecdsa(_public_sig_key) => {
            return Err(CryptographyError::VerificationError(
                "Unsigncryption key for legacy scheme supplied for composite signcryption"
                    .to_string(),
            ));
        }
        super::SenderAuth::Multi(verf_key_set) => verf_key_set,
    };
    let kem_ct: HybridKemCt =
        safe_deserialize(std::io::Cursor::new(&cipher.payload), SAFE_SER_SIZE_LIMIT)
            .map_err(CryptographyError::SerializationError)?;
    let plaintext = hybrid_decrypt(kem_ct, &unsign_key.decryption_key)?;
    let mut envelope: CompositeEnvelope =
        safe_deserialize(std::io::Cursor::new(&*plaintext), SAFE_SER_SIZE_LIMIT)
            .map_err(CryptographyError::SerializationError)?;

    let msg = Zeroizing::new(std::mem::take(&mut envelope.msg));

    let mut signed =
        SigncryptionSignedPayload::new(&msg, &unsign_key.receiver_id, &unsign_key.encryption_key)?;
    let verified = verify_uniform(&envelope.signature, sender_keys, dsep, &signed);
    signed.zeroize();
    verified.map_err(|e| CryptographyError::VerificationError(e.to_string()))?;

    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::super::common::{composite_fixture, signcryption_fixture};
    use super::super::{SenderAuth, Signcrypt, UnifiedSigncryptionKey, Unsigncrypt};
    use super::*;
    use crate::cryptography::encryption::PkeSchemeType;
    use crate::cryptography::signatures::{UnifiedPublicSigKey, VerfKeySet};
    use crate::cryptography::signing::test_support::seeded_identity;
    use crate::vault::storage::tests::TestType;
    use aes_prng::AesRng;
    use rand::SeedableRng;

    const DSEP: &DomainSep = b"COMPV1TT";

    fn pair() -> Vec<SigningSchemeType> {
        vec![SigningSchemeType::Ecdsa256k1, SigningSchemeType::MlDsa87]
    }

    /// Round-trips for both PKE schemes the backup and user-decryption paths use.
    #[test]
    fn round_trip() {
        for scheme in [PkeSchemeType::MlKem512, PkeSchemeType::MlKem1024P384] {
            let mut f = composite_fixture(scheme, 100, &pair());
            let cipher = seal(
                &f.signcryption_key,
                &mut f.rng,
                DSEP,
                &f.schemes(),
                b"a composite message",
            )
            .unwrap();
            assert_eq!(cipher.pke_type, scheme);

            let opened = f.unsigncryption_key.open(DSEP, &cipher).unwrap();
            assert_eq!(&*opened, b"a composite message", "{scheme}");
        }
    }

    /// The headline property at the envelope level: a verifier that demands the
    /// pair rejects a signcryption made under a weaker one.
    #[test]
    fn a_signature_under_another_scheme_set_is_rejected() {
        let mut f = composite_fixture(PkeSchemeType::MlKem512, 200, &pair());

        // The sender signs under a weaker pair; using MlDsa44 instead of MlDsa87.
        let weaker = vec![SigningSchemeType::Ecdsa256k1, SigningSchemeType::MlDsa44];
        let cipher = seal(
            &f.signcryption_key,
            &mut f.rng,
            DSEP,
            &weaker,
            b"downgrade me",
        )
        .unwrap();

        let err = f.unsigncryption_key.open(DSEP, &cipher).unwrap_err();
        assert!(
            matches!(err, CryptographyError::VerificationError(_)),
            "{err}"
        );

        // ...and the same signcryption opens for a verifier that asked for
        // exactly what was signed, confirming the rejection above is the policy
        // check and not an unrelated failure.
        let weaker_keys =
            VerfKeySet::from_identity(&f.signcryption_key.identity, &weaker).unwrap();
        let opened = f
            .reader_with(
                SenderAuth::Multi(weaker_keys),
                f.signcryption_key.receiver_id.clone(),
            )
            .open(DSEP, &cipher)
            .unwrap();
        assert_eq!(&*opened, b"downgrade me");
    }

    /// Neither reader accepts the other's envelope.
    /// The single-ECDSA set holds the very key that signed the envelope and must still refuse
    /// it, because the payload is a safe-serialized KEM ciphertext that its
    /// bincode parse rejects before anything is decrypted.
    #[test]
    fn the_two_formats_do_not_cross() {
        for (seed, schemes) in [
            (300_u64, pair()),
            (400_u64, vec![SigningSchemeType::Ecdsa256k1]),
        ] {
            let mut f = composite_fixture(PkeSchemeType::MlKem512, seed, &schemes);
            let composite = seal(
                &f.signcryption_key,
                &mut f.rng,
                DSEP,
                &f.schemes(),
                b"composite payload",
            )
            .unwrap();

            // The envelope does open for the reader it was made for, so each
            // rejection below is the format mismatch and not a broken fixture.
            assert_eq!(
                &*f.unsigncryption_key.open(DSEP, &composite).unwrap(),
                b"composite payload"
            );

            // Frozen reader, handed a composite envelope.
            let legacy_ecdsa = match &f.unsigncryption_key.sender {
                SenderAuth::Multi(keys) => {
                    match keys.require(SigningSchemeType::Ecdsa256k1).unwrap() {
                        UnifiedPublicSigKey::Ecdsa256k1(key) => key.clone(),
                        _ => unreachable!("the ECDSA member of the set is an ECDSA key"),
                    }
                }
                SenderAuth::Ecdsa(_) => unreachable!("the fixture reader is a composite one"),
            };
            let err = f
                .reader_with(
                    SenderAuth::Ecdsa(legacy_ecdsa),
                    f.signcryption_key.receiver_id.clone(),
                )
                .unsigncrypt::<TestType>(DSEP, &composite)
                .unwrap_err();
            assert!(
                matches!(err, CryptographyError::BincodeError(_)),
                "the frozen reader must reject a composite envelope on the KEM ciphertext, got: {err}"
            );

            // Composite reader, handed a frozen envelope. The frozen layout
            // writes its `HybridKemCt` with bincode and no header, so
            // `safe_deserialize` refuses it — again before any decryption.
            let mut frozen_f = signcryption_fixture(PkeSchemeType::MlKem512, seed);
            let frozen = frozen_f
                .signcryption_key
                .signcrypt(&mut frozen_f.rng, DSEP, &TestType { i: 7 })
                .unwrap();
            let err = f.unsigncryption_key.open(DSEP, &frozen).unwrap_err();
            assert!(
                matches!(err, CryptographyError::SerializationError(_)),
                "the composite reader must reject a frozen envelope on deserialization, got: {err}"
            );
        }
    }

    /// Opening fails on every deviation from what was sealed.
    #[test]
    fn open_rejects_any_deviation_from_what_was_sealed() {
        let mut f = composite_fixture(PkeSchemeType::MlKem512, 500, &pair());
        let cipher = seal(
            &f.signcryption_key,
            &mut f.rng,
            DSEP,
            &f.schemes(),
            b"bound to one sender and one receiver",
        )
        .unwrap();

        // The untouched envelope opens, so each rejection below is the
        // deviation and not an unrelated failure.
        f.unsigncryption_key.open(DSEP, &cipher).unwrap();

        assert!(
            f.unsigncryption_key.open(b"OTHERDSP", &cipher).is_err(),
            "a different domain separator opened the envelope"
        );

        let mut flipped = cipher.clone();
        flipped.payload[0] ^= 0x01;
        assert!(
            f.unsigncryption_key.open(DSEP, &flipped).is_err(),
            "a tampered ciphertext opened the envelope"
        );

        let mut rng = AesRng::seed_from_u64(999);
        let other_keys =
            VerfKeySet::from_identity(&seeded_identity(&mut rng), &f.schemes()).unwrap();
        assert!(
            f.reader_with(
                SenderAuth::Multi(other_keys),
                f.signcryption_key.receiver_id.clone()
            )
            .open(DSEP, &cipher)
            .is_err(),
            "another party's key set opened the envelope"
        );

        assert!(
            f.reader_with(
                f.unsigncryption_key.sender.clone(),
                b"a different receiver".to_vec()
            )
            .open(DSEP, &cipher)
            .is_err(),
            "a different receiver id opened the envelope"
        );
    }

    /// A node with no root seed has no post-quantum key to sign with, so the
    /// composite layout is refused for the schemes that need one — rather than
    /// quietly dropping them and sealing under what is left.
    #[test]
    fn a_seedless_identity_cannot_seal_a_post_quantum_composite() {
        let mut f = signcryption_fixture(PkeSchemeType::MlKem512, 600);

        let err = seal(
            &f.signcryption_key,
            &mut f.rng,
            DSEP,
            &pair(),
            b"no seed here",
        )
        .unwrap_err();
        assert!(matches!(err, CryptographyError::SigningError(_)), "{err}");
    }

    /// ...but ECDSA alone needs no seed, so a seedless node can still write a
    /// one-signature composite envelope. That envelope is a composite, not the
    /// frozen layout: it is only readable by a reader demanding exactly
    /// `{Ecdsa256k1}`, which is what keeps the two apart.
    #[test]
    fn a_seedless_identity_can_seal_an_ecdsa_only_composite() {
        let mut f = signcryption_fixture(PkeSchemeType::MlKem512, 700);
        let ecdsa_only = [SigningSchemeType::Ecdsa256k1];

        let cipher = seal(
            &f.signcryption_key,
            &mut f.rng,
            DSEP,
            &ecdsa_only,
            b"one signature",
        )
        .unwrap();

        let keys =
            VerfKeySet::from_identity(&f.signcryption_key.identity, &ecdsa_only).unwrap();
        let opened = f
            .reader_with(
                SenderAuth::Multi(keys),
                f.signcryption_key.receiver_id.clone(),
            )
            .open(DSEP, &cipher)
            .unwrap();
        assert_eq!(&*opened, b"one signature");
    }
}

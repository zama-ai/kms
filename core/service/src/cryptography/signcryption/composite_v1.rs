//! The composite signcryption envelope.

use super::UnifiedSigncryption;
use super::common::{hybrid_decrypt, hybrid_encrypt, receiver_binding};
use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::cryptography::encryption::{HasPkeScheme, UnifiedPrivateEncKey, UnifiedPublicEncKey};
use crate::cryptography::error::CryptographyError;
use crate::cryptography::hybrid_ml_kem::HybridKemCt;
use crate::cryptography::signatures::{
    CompositeSignature, NodeSigningIdentity, SigningSchemeType, VerfKeySet,
};
use crate::cryptography::zeroizing_writer::ZeroizingWriter;
use hashing::DomainSep;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use tfhe::named::Named;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
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
    pub signature: CompositeSignature,
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

/// Signcrypt `msg` in the composite layout.
///
/// Sign-then-encrypt, as in the frozen layout: each signature covers
/// `dsep ‖ schemes ‖ msg ‖ receiver_id ‖ H(receiver enc key)`, and the whole
/// envelope is then encrypted to the receiver.
#[cfg(feature = "non-wasm")]
#[allow(unknown_lints)]
// We allow modifying the rng before return
#[allow(non_local_effect_before_error_return)]
pub fn seal(
    identity: &NodeSigningIdentity,
    schemes: &[SigningSchemeType],
    receiver_enc_key: &UnifiedPublicEncKey,
    receiver_id: &[u8],
    rng: &mut (impl CryptoRng + RngCore),
    dsep: &DomainSep,
    msg: &[u8],
) -> Result<UnifiedSigncryption, CryptographyError> {
    let binding = receiver_binding(receiver_id, receiver_enc_key)?;
    let signed = Zeroizing::new([msg, binding.as_slice()].concat());
    let signature = CompositeSignature::sign_uniform(identity, schemes, dsep, &signed)?;

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
    decryption_key: &UnifiedPrivateEncKey,
    encryption_key: &UnifiedPublicEncKey,
    sender_keys: &VerfKeySet,
    receiver_id: &[u8],
    dsep: &DomainSep,
    cipher: &UnifiedSigncryption,
) -> Result<Zeroizing<Vec<u8>>, CryptographyError> {
    if cipher.pke_type != encryption_key.encryption_scheme_type() {
        return Err(CryptographyError::VerificationError(
            "encryption type of cipher does not match the decryption key type".to_string(),
        ));
    }
    let kem_ct: HybridKemCt =
        safe_deserialize(std::io::Cursor::new(&cipher.payload), SAFE_SER_SIZE_LIMIT)
            .map_err(CryptographyError::SerializationError)?;
    let plaintext = hybrid_decrypt(kem_ct, decryption_key)?;
    let mut envelope: CompositeEnvelope =
        safe_deserialize(std::io::Cursor::new(&*plaintext), SAFE_SER_SIZE_LIMIT)
            .map_err(CryptographyError::SerializationError)?;

    let msg = Zeroizing::new(std::mem::take(&mut envelope.msg));

    let binding = receiver_binding(receiver_id, encryption_key)?;
    let signed = Zeroizing::new([msg.as_slice(), binding.as_slice()].concat());
    envelope
        .signature
        .verify_uniform(sender_keys, dsep, &signed)
        .map_err(|e| CryptographyError::VerificationError(e.to_string()))?;

    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::super::common::signcryption_fixture;
    use super::super::{Signcrypt, UnifiedSigncryptionKey, UnifiedUnsigncryptionKey, Unsigncrypt};
    use super::*;
    use crate::cryptography::encryption::PkeSchemeType;
    use crate::cryptography::signing::test_support::seeded_identity;
    use crate::vault::storage::tests::TestType;
    use aes_prng::AesRng;
    use rand::SeedableRng;

    const DSEP: &DomainSep = b"COMPV1TT";

    fn pair() -> Vec<SigningSchemeType> {
        vec![SigningSchemeType::Ecdsa256k1, SigningSchemeType::MlDsa87]
    }

    struct CompositeFixture {
        rng: AesRng,
        identity: NodeSigningIdentity,
        keys: VerfKeySet,
        schemes: Vec<SigningSchemeType>,
        dec_key: UnifiedPrivateEncKey,
        enc_key: UnifiedPublicEncKey,
        receiver_id: Vec<u8>,
    }

    fn fixture(scheme: PkeSchemeType, seed: u64) -> CompositeFixture {
        fixture_under(scheme, seed, pair())
    }

    fn fixture_under(
        scheme: PkeSchemeType,
        seed: u64,
        schemes: Vec<SigningSchemeType>,
    ) -> CompositeFixture {
        let mut base = signcryption_fixture(scheme, seed);
        let identity = seeded_identity(&mut base.rng);
        let keys = VerfKeySet::from_identity(&identity, &schemes).unwrap();
        CompositeFixture {
            rng: base.rng,
            identity,
            keys,
            schemes,
            dec_key: base.dec_key,
            enc_key: base.enc_key,
            receiver_id: base.receiver_id,
        }
    }

    fn seal_msg(f: &mut CompositeFixture, msg: &[u8]) -> UnifiedSigncryption {
        seal(
            &f.identity,
            &f.schemes,
            &f.enc_key,
            &f.receiver_id,
            &mut f.rng,
            DSEP,
            msg,
        )
        .unwrap()
    }

    fn open_with(
        f: &CompositeFixture,
        cipher: &UnifiedSigncryption,
    ) -> Result<Zeroizing<Vec<u8>>, CryptographyError> {
        UnifiedUnsigncryptionKey::new_multi(&f.dec_key, &f.enc_key, &f.keys, &f.receiver_id)
            .open(DSEP, cipher)
    }

    /// Round-trips for both PKE schemes the backup and user-decryption paths use.
    #[test]
    fn round_trip() {
        for scheme in [PkeSchemeType::MlKem512, PkeSchemeType::MlKem1024P384] {
            let mut f = fixture(scheme, 100);
            let cipher = seal_msg(&mut f, b"a composite message");
            assert_eq!(cipher.pke_type, scheme);

            let opened = open_with(&f, &cipher).unwrap();
            assert_eq!(&*opened, b"a composite message", "{scheme}");
        }
    }

    /// The headline property at the envelope level: a verifier that demands the
    /// pair rejects a signcryption made under a weaker one.
    #[test]
    fn a_signature_under_another_scheme_set_is_rejected() {
        let mut f = fixture(PkeSchemeType::MlKem512, 200);

        // The sender signs under a weaker pair; using MlDsa44 instead of MlDsa87.
        let weaker = vec![SigningSchemeType::Ecdsa256k1, SigningSchemeType::MlDsa44];
        let cipher = seal(
            &f.identity,
            &weaker,
            &f.enc_key,
            &f.receiver_id,
            &mut f.rng,
            DSEP,
            b"downgrade me",
        )
        .unwrap();

        let err = open_with(&f, &cipher).unwrap_err();
        assert!(
            matches!(err, CryptographyError::VerificationError(_)),
            "{err}"
        );

        // ...and the same signcryption opens for a verifier that asked for
        // exactly what was signed, confirming the rejection above is the policy
        // check and not an unrelated failure.
        let weaker_keys = VerfKeySet::from_identity(&f.identity, &weaker).unwrap();
        let opened = open(
            &f.dec_key,
            &f.enc_key,
            &weaker_keys,
            &f.receiver_id,
            DSEP,
            &cipher,
        )
        .unwrap();
        assert_eq!(&*opened, b"downgrade me");
    }

    /// Neither reader accepts the other's envelope.
    #[test]
    fn the_two_formats_do_not_cross() {
        let mut f = fixture(PkeSchemeType::MlKem512, 300);
        let composite = seal_msg(&mut f, b"composite payload");

        // Frozen reader, handed a composite envelope.
        let legacy_verf = f
            .keys
            .require(SigningSchemeType::Ecdsa256k1)
            .unwrap()
            .clone();
        let legacy_ecdsa = match &legacy_verf {
            crate::cryptography::signatures::UnifiedPublicSigKey::Ecdsa256k1(k) => k.clone(),
            _ => unreachable!("the ECDSA member of the set is an ECDSA key"),
        };
        let legacy_key =
            UnifiedUnsigncryptionKey::new(&f.dec_key, &f.enc_key, &legacy_ecdsa, &f.receiver_id);
        let err = legacy_key
            .unsigncrypt::<TestType>(DSEP, &composite)
            .unwrap_err();
        assert!(
            matches!(err, CryptographyError::BincodeError(_)),
            "the frozen reader must reject a composite envelope on the KEM ciphertext, got: {err}"
        );

        // Composite reader, handed a frozen envelope. The frozen layout writes
        // its `HybridKemCt` with bincode and no header, so `safe_deserialize`
        // refuses it — again before anything is decrypted.
        let base = signcryption_fixture(PkeSchemeType::MlKem512, 300);
        let mut rng = base.rng;
        let ecdsa_key =
            UnifiedSigncryptionKey::new(&base.signing_key, &base.enc_key, &base.receiver_id);
        let frozen = ecdsa_key
            .signcrypt(&mut rng, DSEP, &TestType { i: 7 })
            .unwrap();
        let err = open_with(&f, &frozen).unwrap_err();
        assert!(
            matches!(err, CryptographyError::SerializationError(_)),
            "the composite reader must reject a frozen envelope on deserialization, got: {err}"
        );
    }

    /// ECDSA alone is a legitimate scheme set for this layout.
    #[test]
    fn the_ecdsa_singleton_round_trips_and_still_does_not_cross() {
        let mut f = fixture_under(
            PkeSchemeType::MlKem512,
            400,
            vec![SigningSchemeType::Ecdsa256k1],
        );
        let cipher = seal_msg(&mut f, b"ecdsa alone");
        let opened = open_with(&f, &cipher).unwrap();
        assert_eq!(&*opened, b"ecdsa alone");

        // The frozen reader, holding the very key that signed this envelope,
        // still rejects it: the payload is a safe-serialized KEM ciphertext,
        // which its bincode parse refuses.
        let legacy_verf = f
            .keys
            .require(SigningSchemeType::Ecdsa256k1)
            .unwrap()
            .clone();
        let legacy_ecdsa = match &legacy_verf {
            crate::cryptography::signatures::UnifiedPublicSigKey::Ecdsa256k1(k) => k.clone(),
            _ => unreachable!("the ECDSA member of the set is an ECDSA key"),
        };
        let legacy_key =
            UnifiedUnsigncryptionKey::new(&f.dec_key, &f.enc_key, &legacy_ecdsa, &f.receiver_id);
        assert!(
            legacy_key.unsigncrypt::<TestType>(DSEP, &cipher).is_err(),
            "the frozen reader must not accept a single-ECDSA composite envelope"
        );

        // ...and the composite reader still rejects a frozen envelope, even now
        // that the set it demands is exactly {ECDSA}.
        let base = signcryption_fixture(PkeSchemeType::MlKem512, 400);
        let mut rng = base.rng;
        let frozen =
            UnifiedSigncryptionKey::new(&base.signing_key, &base.enc_key, &base.receiver_id)
                .signcrypt(&mut rng, DSEP, &TestType { i: 7 })
                .unwrap();
        assert!(
            matches!(
                open_with(&f, &frozen),
                Err(CryptographyError::SerializationError(_))
            ),
            "the composite reader must reject a frozen envelope on deserialization"
        );
    }

    /// A sender whose key set differs from the one the receiver holds is
    /// detected, even though the ciphertext decrypts. There is no sender
    /// identifier in the envelope to compare.
    #[test]
    fn a_different_sender_key_set_is_rejected() {
        let mut f = fixture(PkeSchemeType::MlKem512, 500);
        let cipher = seal_msg(&mut f, b"whose message is this");

        let mut rng = AesRng::seed_from_u64(999);
        let other = seeded_identity(&mut rng);
        let other_keys = VerfKeySet::from_identity(&other, &pair()).unwrap();
        assert!(
            open(
                &f.dec_key,
                &f.enc_key,
                &other_keys,
                &f.receiver_id,
                DSEP,
                &cipher,
            )
            .is_err()
        );
    }

    /// The receiver binding is covered by the signature, so opening with a
    /// different receiver id fails.
    #[test]
    fn a_different_receiver_id_is_rejected() {
        let mut f = fixture(PkeSchemeType::MlKem512, 600);
        let cipher = seal_msg(&mut f, b"bound to a receiver");

        let other_id = b"a different receiver".to_vec();
        assert!(open(&f.dec_key, &f.enc_key, &f.keys, &other_id, DSEP, &cipher,).is_err());
    }

    #[test]
    fn a_tampered_ciphertext_or_dsep_fails() {
        let mut f = fixture(PkeSchemeType::MlKem512, 700);
        let cipher = seal_msg(&mut f, b"tamper with me");

        let mut flipped = cipher.clone();
        flipped.payload[0] ^= 0x01;
        assert!(open_with(&f, &flipped).is_err());

        assert!(
            open(
                &f.dec_key,
                &f.enc_key,
                &f.keys,
                &f.receiver_id,
                b"OTHERDSP",
                &cipher,
            )
            .is_err()
        );
    }
}

//! The composite signcryption envelope: one signature per scheme.

use super::common::{
    SigncryptionFormat, format_for, hybrid_decrypt, hybrid_encrypt, receiver_binding,
    unsupported_format,
};
use super::{Signcrypt, UnifiedSigncryption, Unsigncrypt};
use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::cryptography::encryption::{
    HasPkeScheme, PkeSchemeType, UnifiedPrivateEncKey, UnifiedPublicEncKey,
};
use crate::cryptography::error::CryptographyError;
use crate::cryptography::hybrid_ml_kem::HybridKemCt;
use crate::cryptography::signatures::{
    CompositeSignature, NodeSigningIdentity, SigningSchemeSet, VerfKeySet,
};
use crate::cryptography::zeroizing_writer::ZeroizingWriter;
use hashing::DomainSep;
use rand::{CryptoRng, RngCore};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tfhe::named::Named;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe_versionable::{Versionize, VersionsDispatch};
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, VersionsDispatch)]
pub enum CompositeEnvelopeVersions {
    V0(CompositeEnvelope),
}

/// The plaintext of a composite signcryption, before encryption.
///
/// `signature` carries its own scheme set, so this struct does not repeat it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(CompositeEnvelopeVersions)]
pub struct CompositeEnvelope {
    pub msg: Vec<u8>,
    pub signature: CompositeSignature,
}

impl Named for CompositeEnvelope {
    const NAME: &'static str = "signcryption::CompositeEnvelope";
}

/// The signing half of a composite signcryption.
///
/// Holds a [`NodeSigningIdentity`] rather than a single key, and is not
/// persisted — deliberately, since the underlying identity is a in-memory structure.
#[derive(Clone, Debug)]
pub struct CompositeSigncryptionKey<'a> {
    pub identity: &'a NodeSigningIdentity,
    pub schemes: &'a SigningSchemeSet,
    pub receiver_enc_key: &'a UnifiedPublicEncKey,
    pub receiver_id: &'a [u8],
}

impl<'a> CompositeSigncryptionKey<'a> {
    pub fn new(
        identity: &'a NodeSigningIdentity,
        schemes: &'a SigningSchemeSet,
        receiver_enc_key: &'a UnifiedPublicEncKey,
        receiver_id: &'a [u8],
    ) -> Self {
        Self {
            identity,
            schemes,
            receiver_enc_key,
            receiver_id,
        }
    }
}

impl HasPkeScheme for CompositeSigncryptionKey<'_> {
    fn encryption_scheme_type(&self) -> PkeSchemeType {
        self.receiver_enc_key.encryption_scheme_type()
    }
}

/// The verifying half of a composite signcryption.
///
/// `expected_schemes` is not optional, and it is the verifier's policy rather
/// than anything read off the message.
///
/// The set inside the envelope is authenticated, so it says truthfully which
/// schemes signed.
#[derive(Clone, Debug)]
pub struct CompositeUnsigncryptionKey<'a> {
    pub decryption_key: &'a UnifiedPrivateEncKey,
    pub encryption_key: &'a UnifiedPublicEncKey,
    pub sender_keys: &'a VerfKeySet,
    pub expected_schemes: &'a SigningSchemeSet,
    pub receiver_id: &'a [u8],
}

impl<'a> CompositeUnsigncryptionKey<'a> {
    pub fn new(
        decryption_key: &'a UnifiedPrivateEncKey,
        encryption_key: &'a UnifiedPublicEncKey,
        sender_keys: &'a VerfKeySet,
        expected_schemes: &'a SigningSchemeSet,
        receiver_id: &'a [u8],
    ) -> Self {
        Self {
            decryption_key,
            encryption_key,
            sender_keys,
            expected_schemes,
            receiver_id,
        }
    }
}

impl HasPkeScheme for CompositeUnsigncryptionKey<'_> {
    fn encryption_scheme_type(&self) -> PkeSchemeType {
        self.encryption_key.encryption_scheme_type()
    }
}

/// Signcrypt `msg` in the composite layout.
///
/// Sign-then-encrypt, as in the frozen layout: each signature covers
/// `dsep ‖ schemes ‖ msg ‖ receiver_id ‖ H(receiver enc key)`, and the whole
/// envelope is then encrypted to the receiver.
#[cfg(feature = "non-wasm")]
pub(super) fn seal(
    signcrypt_key: &CompositeSigncryptionKey,
    rng: &mut (impl CryptoRng + RngCore),
    dsep: &DomainSep,
    msg: &[u8],
) -> Result<UnifiedSigncryption, CryptographyError> {
    // Refuse to produce a composite envelope under a scheme set that selects the
    // frozen layout: it would be tagged `EcdsaV0` and handed to a parser that
    // cannot read it.
    if format_for(signcrypt_key.schemes) != SigncryptionFormat::CompositeV1 {
        return Err(unsupported_format(signcrypt_key.schemes));
    }

    let binding = receiver_binding(signcrypt_key.receiver_id, signcrypt_key.receiver_enc_key)?;
    let signed = Zeroizing::new([msg, binding.as_slice()].concat());
    let signature =
        CompositeSignature::sign(signcrypt_key.identity, signcrypt_key.schemes, dsep, &signed)?;

    let envelope = CompositeEnvelope {
        msg: msg.to_vec(),
        signature,
    };
    let mut plaintext = Vec::new();
    safe_serialize(&envelope, &mut plaintext, SAFE_SER_SIZE_LIMIT)
        .map_err(|e| CryptographyError::SerializationError(e.to_string()))?;
    let plaintext = Zeroizing::new(plaintext);

    let ciphertext = hybrid_encrypt(rng, &plaintext, signcrypt_key.receiver_enc_key)?;
    Ok(UnifiedSigncryption::new(
        bc2wrap::serialize(&ciphertext)
            .map_err(|e| CryptographyError::BincodeError(e.to_string()))?,
        signcrypt_key.encryption_scheme_type(),
        signcrypt_key.schemes.clone(),
    ))
}

/// Open a composite signcryption, returning the message only once every
/// constituent signature has verified.
pub(super) fn open(
    unsign_key: &CompositeUnsigncryptionKey,
    dsep: &DomainSep,
    cipher: &UnifiedSigncryption,
) -> Result<Zeroizing<Vec<u8>>, CryptographyError> {
    if cipher.pke_type != unsign_key.encryption_key.encryption_scheme_type() {
        return Err(CryptographyError::VerificationError(
            "encryption type of cipher does not match the decryption key type".to_string(),
        ));
    }
    let kem_ct: HybridKemCt = bc2wrap::deserialize_slice(&cipher.payload)
        .map_err(|e| CryptographyError::BincodeError(e.to_string()))?;
    let plaintext = hybrid_decrypt(kem_ct, unsign_key.decryption_key)?;
    let envelope: CompositeEnvelope =
        safe_deserialize(std::io::Cursor::new(&*plaintext), SAFE_SER_SIZE_LIMIT)
            .map_err(CryptographyError::SerializationError)?;

    let binding = receiver_binding(unsign_key.receiver_id, unsign_key.encryption_key)?;
    let signed = Zeroizing::new([envelope.msg.as_slice(), binding.as_slice()].concat());
    envelope
        .signature
        .verify(
            unsign_key.sender_keys,
            unsign_key.expected_schemes,
            dsep,
            &signed,
        )
        .map_err(|e| CryptographyError::VerificationError(e.to_string()))?;

    Ok(Zeroizing::new(envelope.msg))
}

/// Serialize `msg` and signcrypt it in the composite layout.
///
/// The same `Signcrypt` contract the frozen path implements, so a caller is
/// polymorphic over the two and the format follows from the key type it holds.
#[cfg(feature = "non-wasm")]
impl<'a> Signcrypt for CompositeSigncryptionKey<'a> {
    #[allow(unknown_lints)]
    // We allow modifying the rng before return
    #[allow(non_local_effect_before_error_return)]
    fn signcrypt<T>(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        dsep: &DomainSep,
        msg: &T,
    ) -> Result<UnifiedSigncryption, CryptographyError>
    where
        T: Serialize + tfhe::Versionize + tfhe::named::Named,
    {
        let mut serialized_msg = ZeroizingWriter::new();
        safe_serialize(msg, &mut serialized_msg, SAFE_SER_SIZE_LIMIT).map_err(|e| {
            CryptographyError::SerializationError(format!(
                "Could not serialize message for signcryption: {e}",
            ))
        })?;
        seal(self, rng, dsep, serialized_msg.as_slice())
    }
}

impl<'a> Unsigncrypt for CompositeUnsigncryptionKey<'a> {
    fn unsigncrypt<T: DeserializeOwned + tfhe::Unversionize + tfhe::named::Named>(
        &self,
        dsep: &DomainSep,
        cipher: &UnifiedSigncryption,
    ) -> Result<T, CryptographyError> {
        let msg = open(self, dsep, cipher)?;
        safe_deserialize(std::io::Cursor::new(&*msg), SAFE_SER_SIZE_LIMIT)
            .map_err(CryptographyError::SerializationError)
    }

    fn validate_signcryption(
        &self,
        dsep: &DomainSep,
        signcryption: &UnifiedSigncryption,
    ) -> Result<(), CryptographyError> {
        // Sign-then-encrypt, so authenticity is only established by decrypting.
        let _ = open(self, dsep, signcryption).map_err(|e| {
            CryptographyError::VerificationError(format!(
                "failed to decrypt signcryption for validation: {e}"
            ))
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::common::lock_fixture;
    use super::super::{UnifiedSigncryptionKey, UnifiedUnsigncryptionKey};
    use super::*;
    use crate::cryptography::encryption::PkeSchemeType;
    use crate::cryptography::signatures::SigningSchemeType;
    use crate::cryptography::signing::test_support::seeded_identity;
    use crate::vault::storage::tests::TestType;
    use aes_prng::AesRng;
    use rand::SeedableRng;

    const DSEP: &DomainSep = b"COMPV1TT";

    fn pair() -> SigningSchemeSet {
        SigningSchemeSet::new([SigningSchemeType::Ecdsa256k1, SigningSchemeType::MlDsa87]).unwrap()
    }

    struct Fixture {
        rng: AesRng,
        identity: NodeSigningIdentity,
        keys: VerfKeySet,
        schemes: SigningSchemeSet,
        dec_key: UnifiedPrivateEncKey,
        enc_key: UnifiedPublicEncKey,
        receiver_id: Vec<u8>,
    }

    fn fixture(scheme: PkeSchemeType, seed: u64) -> Fixture {
        let base = lock_fixture(scheme, seed);
        let mut rng = AesRng::seed_from_u64(seed ^ 0xC0FFEE);
        let identity = seeded_identity(&mut rng);
        let schemes = pair();
        let keys = VerfKeySet::from_identity(&identity, &schemes).unwrap();
        Fixture {
            rng: base.rng,
            identity,
            keys,
            schemes,
            dec_key: base.dec_key,
            enc_key: base.enc_key,
            receiver_id: base.receiver_id,
        }
    }

    fn seal_msg(f: &mut Fixture, msg: &[u8]) -> UnifiedSigncryption {
        let key =
            CompositeSigncryptionKey::new(&f.identity, &f.schemes, &f.enc_key, &f.receiver_id);
        seal(&key, &mut f.rng, DSEP, msg).unwrap()
    }

    fn unsign_key<'a>(
        f: &'a Fixture,
        expected: &'a SigningSchemeSet,
    ) -> CompositeUnsigncryptionKey<'a> {
        CompositeUnsigncryptionKey::new(&f.dec_key, &f.enc_key, &f.keys, expected, &f.receiver_id)
    }

    /// Round-trips for both PKE schemes the backup and user-decryption paths use.
    #[test]
    fn round_trip() {
        for scheme in [PkeSchemeType::MlKem512, PkeSchemeType::MlKem1024P384] {
            let mut f = fixture(scheme, 100);
            let cipher = seal_msg(&mut f, b"a composite message");
            assert_eq!(cipher.pke_type, scheme);
            assert_eq!(cipher.signing_schemes, pair());

            let schemes = pair();
            let opened = open(&unsign_key(&f, &schemes), DSEP, &cipher).unwrap();
            assert_eq!(&*opened, b"a composite message", "{scheme}");
        }
    }

    /// The headline property at the envelope level: a verifier that demands the
    /// pair rejects a signcryption claiming only ECDSA, before decrypting.
    #[test]
    fn a_signature_under_another_scheme_set_is_rejected() {
        let mut f = fixture(PkeSchemeType::MlKem512, 200);

        // The sender signs under a weaker pair; using MlDsa44 instead of MlDsa87.
        let weaker =
            SigningSchemeSet::new([SigningSchemeType::Ecdsa256k1, SigningSchemeType::MlDsa44])
                .unwrap();
        let key = CompositeSigncryptionKey::new(&f.identity, &weaker, &f.enc_key, &f.receiver_id);
        let cipher = seal(&key, &mut f.rng, DSEP, b"downgrade me").unwrap();

        let required = pair();
        let err = open(&unsign_key(&f, &required), DSEP, &cipher).unwrap_err();
        assert!(
            matches!(err, CryptographyError::VerificationError(_)),
            "{err}"
        );

        // ...and the same signcryption opens for a verifier that asked for
        // exactly what was signed, confirming the rejection above is the policy
        // check and not an unrelated failure.
        let weaker_keys = VerfKeySet::from_identity(&f.identity, &weaker).unwrap();
        let permissive = CompositeUnsigncryptionKey::new(
            &f.dec_key,
            &f.enc_key,
            &weaker_keys,
            &weaker,
            &f.receiver_id,
        );
        assert_eq!(&*open(&permissive, DSEP, &cipher).unwrap(), b"downgrade me");
    }

    /// The outer scheme tag is unauthenticated so altering it changes nothing:
    /// the authoritative set is the one inside the signed envelope.
    #[test]
    fn the_outer_scheme_tag_is_not_load_bearing() {
        let mut f = fixture(PkeSchemeType::MlKem512, 250);
        let mut cipher = seal_msg(&mut f, b"tag is only a hint");
        cipher.signing_schemes = SigningSchemeSet::single(SigningSchemeType::Ecdsa256k1);

        let schemes = pair();
        assert_eq!(
            &*open(&unsign_key(&f, &schemes), DSEP, &cipher).unwrap(),
            b"tag is only a hint"
        );
    }

    /// A composite envelope must not be openable by the frozen ECDSA reader, and
    /// the frozen layout must not be openable as composite.
    #[test]
    fn the_two_formats_do_not_cross() {
        let mut f = fixture(PkeSchemeType::MlKem512, 300);
        let composite = seal_msg(&mut f, b"composite payload");

        // Legacy reader, handed a composite signcryption: refused by dispatch.
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
            legacy_key
                .unsigncrypt::<TestType>(DSEP, &composite)
                .is_err(),
            "the frozen reader accepted a composite envelope"
        );

        // Composite reader, handed a frozen-layout signcryption: it decrypts,
        // but the plaintext is `msg ‖ sig ‖ digest` rather than a serialized
        // `CompositeEnvelope`, so deserialization refuses it.
        let base = lock_fixture(PkeSchemeType::MlKem512, 300);
        let mut rng = base.rng;
        let ecdsa_key =
            UnifiedSigncryptionKey::new(&base.signing_key, &base.enc_key, &base.receiver_id);
        let frozen = ecdsa_key
            .signcrypt(&mut rng, DSEP, &TestType { i: 7 })
            .unwrap();
        let schemes = pair();
        assert!(
            open(&unsign_key(&f, &schemes), DSEP, &frozen).is_err(),
            "the composite reader accepted a frozen envelope"
        );
    }

    /// Sealing under a set that selects the frozen layout is refused, rather
    /// than producing an envelope no reader can open.
    #[test]
    fn sealing_under_the_ecdsa_singleton_is_refused() {
        let mut f = fixture(PkeSchemeType::MlKem512, 400);
        let single = SigningSchemeSet::single(SigningSchemeType::Ecdsa256k1);
        let key = CompositeSigncryptionKey::new(&f.identity, &single, &f.enc_key, &f.receiver_id);
        assert!(matches!(
            seal(&key, &mut f.rng, DSEP, b"nope"),
            Err(CryptographyError::UnsupportedSigncryptionFormat(_))
        ));
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
        let schemes = pair();
        let key = CompositeUnsigncryptionKey::new(
            &f.dec_key,
            &f.enc_key,
            &other_keys,
            &schemes,
            &f.receiver_id,
        );
        assert!(open(&key, DSEP, &cipher).is_err());
    }

    /// The receiver binding is covered by the signature, so opening with a
    /// different receiver id fails.
    #[test]
    fn a_different_receiver_id_is_rejected() {
        let mut f = fixture(PkeSchemeType::MlKem512, 600);
        let cipher = seal_msg(&mut f, b"bound to a receiver");

        let schemes = pair();
        let other_id = b"a different receiver".to_vec();
        let key =
            CompositeUnsigncryptionKey::new(&f.dec_key, &f.enc_key, &f.keys, &schemes, &other_id);
        assert!(open(&key, DSEP, &cipher).is_err());
    }

    #[test]
    fn a_tampered_ciphertext_or_dsep_fails() {
        let mut f = fixture(PkeSchemeType::MlKem512, 700);
        let cipher = seal_msg(&mut f, b"tamper with me");
        let schemes = pair();

        let mut flipped = cipher.clone();
        flipped.payload[0] ^= 0x01;
        assert!(open(&unsign_key(&f, &schemes), DSEP, &flipped).is_err());

        assert!(open(&unsign_key(&f, &schemes), b"OTHERDSP", &cipher).is_err());
    }
}

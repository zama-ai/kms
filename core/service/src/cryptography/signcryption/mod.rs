//! Necessary methods for secure client communication in relation to user decryption requests.
//!
//! Client requests to the server should be validated against the client's wallet address,
//! which is derived from a ECDSA secp256k1 key.
//! Based on the request the server does sign-then-encrypt to securely encrypt a payload for the
//! client. Signing for the server is also carried out using ECDSA with secp256k1 and the client
//! can validate this against the server's public key.
//! Unfortunately we cannot use PQ signatures such as ML-DSA because the server identities
//! must be compatible with EVM on-chain verification.
//!
//! For encryption a hybrid encryption scheme is used based on ML-KEM and AES GCM.
//!
//! # Envelope formats
//!
//! A signcryption's encrypted plaintext has a layout, and there is more than
//! one. **A [`UnifiedSigncryption`] does not say which.** The layout follows from
//! the key material a reader holds, named by [`SenderAuth`]: a single
//! [`PublicSigKey`] can only open the frozen layout, and a [`VerfKeySet`] plus a
//! scheme policy can only open the multi-signature one.

mod common;
mod composite_v1;
mod ecdsa_v0;

pub(crate) use ecdsa_v0::insecure_decrypt_ignoring_signature;

use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::cryptography::encryption::{
    HasPkeScheme, PkeSchemeType, UnifiedPrivateEncKey, UnifiedPublicEncKey,
};
use crate::cryptography::error::CryptographyError;
use crate::cryptography::signatures::{
    NodeSigningIdentity, PrivateSigKey, PublicSigKey, SigningSchemeType, VerfKeySet,
};
use crate::cryptography::zeroizing_writer::ZeroizingWriter;
use hashing::DomainSep;
use kms_grpc::kms::v1::TypedPlaintext;
use rand::{CryptoRng, RngCore};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tfhe::FheTypes;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe_versionable::{Upgrade, Version, Versionize, VersionsDispatch};
use zeroize::{Zeroize, Zeroizing};

pub trait Signcrypt {
    /// Signcrypt a message of type T with a specified domain separator, in the
    /// frozen layout: one ECDSA signature, so there is no scheme set to name.
    fn signcrypt<T: Serialize + tfhe::Versionize + tfhe::named::Named>(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        dsep: &DomainSep,
        msg: &T,
    ) -> Result<UnifiedSigncryption, CryptographyError>;

    /// Signcrypt `msg` in the multi-signature layout, signed under exactly
    /// `schemes`.
    #[cfg(feature = "non-wasm")]
    fn signcrypt_composite<T: Serialize + tfhe::Versionize + tfhe::named::Named>(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        dsep: &DomainSep,
        schemes: &[SigningSchemeType],
        msg: &T,
    ) -> Result<UnifiedSigncryption, CryptographyError>;
}

pub trait Unsigncrypt {
    /// Decrypt a signcrypted message and verify the signature before returning the result.
    /// If the signature verification fails, an error is returned.
    fn unsigncrypt<T: DeserializeOwned + tfhe::Unversionize + tfhe::named::Named>(
        &self,
        dsep: &DomainSep,
        cipher: &UnifiedSigncryption,
    ) -> Result<T, CryptographyError>;

    /// Authenticate a signcrypted message and discard the payload.
    fn validate_signcryption(
        &self,
        dsep: &DomainSep,
        signcryption: &UnifiedSigncryption,
    ) -> Result<(), CryptographyError>;
}

pub trait SigncryptFHEPlaintext: Signcrypt {
    /// Signcrypt a plaintext message with a specified domain separator and FHE type.
    /// The link parameter is used to bind the signcryption to a specific context or session.
    /// The link should be unique for each signcryption operation to prevent replay attacks.
    /// The method is exclusively used to encrypt partially decrypted FHE ciphertexts for user decryption.
    fn signcrypt_plaintext(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        dsep: &DomainSep,
        plaintext: &[u8],
        fhe_type: FheTypes,
        link: &[u8],
    ) -> Result<UnifiedSigncryption, CryptographyError>;
}

pub trait UnsigncryptFHEPlaintext: Unsigncrypt {
    /// Decrypt a signcrypted plaintext message and verify the signature before returning the result.
    /// If the signature verification fails, an error is returned.
    /// The link parameter is used to verify that the signcryption corresponds to the expected context or session.
    /// The method is exclusively used to decrypt partially decrypted FHE ciphertexts for user decryption.
    ///
    /// The returned payload contains cleartext and implements [`Zeroize`], but not
    /// [`zeroize::ZeroizeOnDrop`], because callers may move out `plaintext`.
    fn unsigncrypt_plaintext(
        &self,
        dsep: &DomainSep,
        signcryption: &[u8],
        link: &[u8],
    ) -> Result<SigncryptionPayload, CryptographyError>;
}

/// Who is sealing, and to whom.
#[derive(Clone, Debug)]
pub struct UnifiedSigncryptionKey {
    pub identity: Arc<NodeSigningIdentity>,
    pub receiver_enc_key: UnifiedPublicEncKey,
    pub receiver_id: Vec<u8>, // Identifier for the receiver's encryption key, e.g. blockchain address
}

impl UnifiedSigncryptionKey {
    pub fn new(
        identity: Arc<NodeSigningIdentity>,
        receiver_enc_key: UnifiedPublicEncKey,
        receiver_id: Vec<u8>,
    ) -> Self {
        Self {
            identity,
            receiver_enc_key,
            receiver_id,
        }
    }

    /// A sealer for a caller that holds only an ECDSA key.
    ///
    /// The key becomes a seedless identity: it writes the frozen envelope, and a
    /// composite one under `Ecdsa256k1` alone. Asking it for any other scheme
    /// fails with `CryptographyError::Signing`, wrapping the
    /// `SigningError::MissingRootSeed` raised by the identity.
    pub fn from_signing_key(
        signing_key: PrivateSigKey,
        receiver_enc_key: UnifiedPublicEncKey,
        receiver_id: Vec<u8>,
    ) -> Self {
        Self::new(
            Arc::new(NodeSigningIdentity::from(signing_key)),
            receiver_enc_key,
            receiver_id,
        )
    }

    /// The ECDSA key the frozen layout signs with.
    pub fn signing_key(&self) -> &PrivateSigKey {
        self.identity.ecdsa()
    }
}

impl HasPkeScheme for UnifiedSigncryptionKey {
    fn encryption_scheme_type(&self) -> PkeSchemeType {
        self.receiver_enc_key.encryption_scheme_type()
    }
}

/// What a reader authenticates a signcryption with — and therefore which
/// envelope layout it can open.
///
/// The two are the same choice, so they are the same value. There is no way to
/// build a key that is ambiguous about the layout it reads, and no layout tag on
/// the message for the two to disagree with.
#[derive(Clone, Debug)]
pub enum SenderAuth {
    /// A single ECDSA verification key: the frozen layout.
    Ecdsa(PublicSigKey),
    /// One verification key per scheme: the multi-signature layout.
    Multi(VerfKeySet),
}

/// Who is reading a signcryption, and what it will authenticate the sender with.
#[derive(Clone, Debug)]
pub struct UnifiedUnsigncryptionKey {
    pub decryption_key: Arc<UnifiedPrivateEncKey>,
    pub encryption_key: UnifiedPublicEncKey, // Needed for validation of the signcrypted payload
    pub sender: SenderAuth,
    /// The ID of the receiver of the signcryption, e.g. blockchain address
    pub receiver_id: Vec<u8>,
}

impl UnifiedUnsigncryptionKey {
    /// A reader of the frozen, single-ECDSA layout.
    pub fn new(
        decryption_key: Arc<UnifiedPrivateEncKey>,
        encryption_key: UnifiedPublicEncKey,
        sender_verf_key: PublicSigKey,
        receiver_id: Vec<u8>,
    ) -> Self {
        Self {
            sender: SenderAuth::Ecdsa(sender_verf_key),
            decryption_key,
            encryption_key,
            receiver_id,
        }
    }

    /// A reader of the multi-signature layout, requiring a signature under every
    /// scheme `keys` holds a key for.
    pub fn new_multi(
        decryption_key: Arc<UnifiedPrivateEncKey>,
        encryption_key: UnifiedPublicEncKey,
        keys: VerfKeySet,
        receiver_id: Vec<u8>,
    ) -> Self {
        Self {
            sender: SenderAuth::Multi(keys),
            decryption_key,
            encryption_key,
            receiver_id,
        }
    }

    /// Decrypt and authenticate `cipher`, returning the message bytes.
    ///
    /// The layout follows from `sender`; see the module documentation.
    fn open(
        &self,
        dsep: &DomainSep,
        cipher: &UnifiedSigncryption,
    ) -> Result<Zeroizing<Vec<u8>>, CryptographyError> {
        // Neither layout can open a ciphertext written for another KEM, so the
        // check is made once here rather than at the head of each opener.
        if cipher.pke_type != self.encryption_key.encryption_scheme_type() {
            return Err(CryptographyError::VerificationError(
                "encryption type of cipher does not match the decryption key type".to_string(),
            ));
        }
        match &self.sender {
            SenderAuth::Ecdsa(sender_verf_key) => {
                ecdsa_v0::open(self, sender_verf_key, dsep, cipher)
            }
            SenderAuth::Multi(keys) => composite_v1::open(self, keys, dsep, cipher),
        }
    }
}

impl HasPkeScheme for UnifiedUnsigncryptionKey {
    fn encryption_scheme_type(&self) -> PkeSchemeType {
        self.encryption_key.encryption_scheme_type()
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum UnifiedSigncryptionVersions {
    V0(UnifiedSigncryptionV0),
    V1(UnifiedSigncryption),
}

/// A signcryption as it was stored and sent before multi-signature envelopes,
/// naming the signing scheme that produced it.
///
/// Kept so that legacy material can still be read. The scheme it names is
/// dropped on upgrade: a reader gets the layout from the opener it calls, not
/// from the message.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Version)]
pub struct UnifiedSigncryptionV0 {
    pub payload: Vec<u8>,
    pub pke_type: PkeSchemeType,
    pub signing_type: SigningSchemeType,
}

impl Upgrade<UnifiedSigncryption> for UnifiedSigncryptionV0 {
    type Error = std::convert::Infallible;

    fn upgrade(self) -> Result<UnifiedSigncryption, Self::Error> {
        Ok(UnifiedSigncryption {
            payload: self.payload,
            pke_type: self.pke_type,
        })
    }
}

/// A signcrypted message.
///
/// Carries no indication of which envelope layout `payload` is in, and no
/// indication of which schemes signed it. Both follow from the opener a reader
/// calls — see the module documentation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Versionize)]
#[versionize(UnifiedSigncryptionVersions)]
pub struct UnifiedSigncryption {
    pub payload: Vec<u8>,
    pub pke_type: PkeSchemeType,
}
impl UnifiedSigncryption {
    pub fn new(payload: Vec<u8>, pke_type: PkeSchemeType) -> Self {
        Self { payload, pke_type }
    }
}

#[derive(Clone, Serialize, Deserialize, Hash, PartialEq, Eq, Debug, VersionsDispatch)]
pub enum SigncryptionPayloadVersions {
    V0(SigncryptionPayload),
}

/// Payload structure for signcrypted user decryption responses needed to facilitate FHE decryption and request linking.
///
/// # Versioning Strategy
///
/// This type is serialized and embedded in user decryption responses using `bc2wrap::serialize()`.
/// Changes to this structure would break compatibility with existing signcrypted ciphertexts.
///
/// ## Serialization Details
///
/// - **Serializer:** `bc2wrap` (wrapper around bincode v2 with legacy v1-compatible config)
/// - **Format:** Bincode v1 legacy format (deterministic, little-endian)
/// - **Stability:** Binary format is locked and cannot change
/// - **Dependencies:** Changes to `bincode` or `serde` versions may break compatibility
///
/// **WARNING:** Upgrading `bc2wrap` dependencies (bincode, serde) requires careful testing
/// with the backward compatibility test suite to ensure no breaking changes.
///
/// ## Why Not Using tfhe-versionable
///
/// This type contains `TypedPlaintext`, a protobuf-generated type that originally did not implement
/// `Versionize`. While we could work around this, we chose to rely on bincode's structural
/// stability for simplicity and to avoid breaking existing v0.11.x data.
///
/// ## Backward Compatibility Contract
///
/// **CRITICAL:** This struct is FROZEN - the binary format cannot change:
/// - Cannot add fields (even at the end)
/// - Cannot remove fields
/// - Cannot change field types
/// - Cannot reorder fields
/// - Cannot rename fields
///
/// Any modification requires creating a new versioned type (e.g., `SigncryptionPayloadV1`)
/// and implementing proper version dispatch.
/// NOTE: Even doing so requires care to ensure backwards compatibility with existing data.
/// Specifically any new version, `SigncryptionPayloadV1`, must ensure implementation of
/// `LegacySerialization` since the type was initially not implemented with tfhe-versionable.
/// In particular this means that care must be taken in (de)signcryption to ensure backwards
/// compatible (de)serialization of existing data.
///
/// ## Version History
/// - V0 (current): Initial version with `plaintext: TypedPlaintext` and `link: Vec<u8>`
///
/// ## Testing
/// - The BC test `test_signcryption_payload` replays the stored fixtures from 0.11.0
///   onwards and compares each parsed value against its recorded metadata. It locks the
///   read path. Bincode writes no field tags, so a field that is added, removed, reordered
///   or retyped also breaks the replay.
/// - The fixtures are LFS objects. The test cannot run without them.
/// - It MUST pass before any changes to this type
//
// TODO(zama-ai/tfhe-rs-internal/issues/1535)
// we should also have ZeroizeOnDrop but this requires some changes on tfhe-rs
#[derive(Clone, Serialize, Deserialize, Hash, PartialEq, Eq, Debug, Versionize)]
#[versionize(SigncryptionPayloadVersions)]
pub struct SigncryptionPayload {
    pub plaintext: TypedPlaintext,
    pub link: Vec<u8>,
}

impl Zeroize for SigncryptionPayload {
    fn zeroize(&mut self) {
        // `fhe_type` is public metadata; wipe the plaintext and link.
        self.plaintext.zeroize();
        self.link.zeroize();
    }
}

/// Compute the signcryption of a message encrypted under the public keys received from a client and
/// signed by the server's signing key.
///
/// Returns the signcrypted message.
///
/// WARNING: It is assumed that the client's public key HAS been validated to come from a valid
/// `ClientRequest` and validated to be consistent with the blockchain identity of the client BEFORE
/// calling this method. IF THIS HAS NOT BEEN DONE THEN ANYONE CAN IMPERSONATE ANY CLIENT!!!
impl Signcrypt for UnifiedSigncryptionKey {
    fn signcrypt<T>(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        dsep: &DomainSep,
        msg: &T,
    ) -> Result<UnifiedSigncryption, CryptographyError>
    where
        T: Serialize + tfhe::Versionize + tfhe::named::Named,
    {
        let serialized_msg = serialize_for_signcryption(msg)?;
        ecdsa_v0::seal(self, rng, dsep, serialized_msg.as_slice())
    }

    #[cfg(feature = "non-wasm")]
    fn signcrypt_composite<T>(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        dsep: &DomainSep,
        schemes: &[SigningSchemeType],
        msg: &T,
    ) -> Result<UnifiedSigncryption, CryptographyError>
    where
        T: Serialize + tfhe::Versionize + tfhe::named::Named,
    {
        let serialized_msg = serialize_for_signcryption(msg)?;
        composite_v1::seal(self, rng, dsep, schemes, serialized_msg.as_slice())
    }
}

/// The message bytes both layouts sign and encrypt, wiped after use.
fn serialize_for_signcryption<T>(msg: &T) -> Result<ZeroizingWriter, CryptographyError>
where
    T: Serialize + tfhe::Versionize + tfhe::named::Named,
{
    let mut serialized_msg = ZeroizingWriter::new();
    safe_serialize(msg, &mut serialized_msg, SAFE_SER_SIZE_LIMIT).map_err(|e| {
        CryptographyError::SerializationError(format!(
            "Could not serialize message for signcryption: {e}",
        ))
    })?;
    Ok(serialized_msg)
}

impl SigncryptFHEPlaintext for UnifiedSigncryptionKey {
    fn signcrypt_plaintext(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        dsep: &DomainSep,
        plaintext: &[u8],
        fhe_type: FheTypes,
        link: &[u8],
    ) -> Result<UnifiedSigncryption, CryptographyError> {
        // Wipe the cleartext payload after serialization.
        let signcryption_msg = Zeroizing::new(SigncryptionPayload {
            plaintext: TypedPlaintext::from_bytes(plaintext.to_owned(), fhe_type),
            link: link.to_owned(),
        });
        // LEGACY Code: should be using safe_serialization
        // Serialize into a sink that wipes intermediate buffers.
        let mut serialized_msg = ZeroizingWriter::new();
        bc2wrap::serialize_into(&*signcryption_msg, &mut serialized_msg)
            .map_err(|e| CryptographyError::BincodeError(e.to_string()))?;
        // The wire type this produces,
        // `TypedSigncryptedCiphertext.signcrypted_ciphertext`, is a bare `bytes`
        // field, and the deployed browser-side verifier parses exactly one
        // layout. The frozen one is not a default here, it is the only option,
        // which is why this calls the frozen sealer rather than offering a
        // choice. It takes no scheme set for the same reason.
        ecdsa_v0::seal(self, rng, dsep, serialized_msg.as_slice())
    }
}

impl Unsigncrypt for UnifiedUnsigncryptionKey {
    fn unsigncrypt<T: DeserializeOwned + tfhe::Unversionize + tfhe::named::Named>(
        &self,
        dsep: &DomainSep,
        cipher: &UnifiedSigncryption,
    ) -> Result<T, CryptographyError> {
        let msg_vec = self.open(dsep, cipher)?;
        safe_deserialize(std::io::Cursor::new(&*msg_vec), SAFE_SER_SIZE_LIMIT)
            .map_err(CryptographyError::SerializationError)
    }

    fn validate_signcryption(
        &self,
        dsep: &DomainSep,
        signcryption: &UnifiedSigncryption,
    ) -> Result<(), CryptographyError> {
        // Since we use sign-then-encrypt, we need to decrypt first to get the message for signature verification
        let _ = self.open(dsep, signcryption).map_err(|e| {
            CryptographyError::VerificationError(format!(
                "failed to decrypt signcryption for validation: {}",
                e
            ))
        })?;
        Ok(())
    }
}

impl UnsigncryptFHEPlaintext for UnifiedUnsigncryptionKey {
    fn unsigncrypt_plaintext(
        &self,
        dsep: &DomainSep,
        signcryption: &[u8],
        link: &[u8],
    ) -> Result<SigncryptionPayload, CryptographyError> {
        // The legacy user-decryption path; see the note in `signcrypt_plaintext`.
        let parsed_signcryption = UnifiedSigncryption::new(
            signcryption.to_owned(),
            self.encryption_key.encryption_scheme_type(),
        );
        let decrypted_signcryption = self.open(dsep, &parsed_signcryption)?;
        // LEGACY should be using safe_deserialization from tfhe-rs
        let mut signcrypted_msg: SigncryptionPayload =
            bc2wrap::deserialize_slice(&decrypted_signcryption)
                .map_err(|e| CryptographyError::BincodeError(e.to_string()))?;
        if link != signcrypted_msg.link {
            // Wipe the payload before returning on a link mismatch.
            signcrypted_msg.zeroize();
            return Err(CryptographyError::VerificationError(
                "signcryption link does not match!".to_string(),
            ));
        }
        Ok(signcrypted_msg)
    }
}

/// Helper method for what the client is supposed to do when generating ephemeral keys linked to the
/// client's blockchain signing key
#[cfg(test)]
pub fn ephemeral_signcryption_key_generation(
    rng: &mut (impl CryptoRng + RngCore + Send + Sync + 'static),
    client_verf_key_id: &[u8],
    server_sig_key: Option<&PrivateSigKey>,
) -> UnifiedSigncryptionKeyPairOwned {
    use crate::cryptography::{
        encryption::{Encryption, PkeScheme},
        signatures::gen_sig_keys,
    };

    let (server_verf_key, server_sig_key) = match server_sig_key {
        Some(sk) => (PublicSigKey::from_sk(sk), sk.clone()),
        None => gen_sig_keys(rng),
    };
    let mut encryption = Encryption::new(PkeSchemeType::MlKem512, rng);
    let (dec_key, enc_key) = encryption.keygen().unwrap();
    UnifiedSigncryptionKeyPairOwned {
        signcrypt_key: UnifiedSigncryptionKey::from_signing_key(
            server_sig_key.clone(),
            enc_key.clone(),
            client_verf_key_id.to_vec(),
        ),
        unsigncryption_key: UnifiedUnsigncryptionKey::new(
            Arc::new(dec_key),
            enc_key,
            server_verf_key.clone(),
            client_verf_key_id.to_vec(),
        ),
    }
}

/// Helper struct that contains both signcryption and unsigncryption keys for a client
/// For now only used for testing
#[cfg(test)]
#[derive(Clone, Debug)]
pub struct UnifiedSigncryptionKeyPairOwned {
    pub signcrypt_key: UnifiedSigncryptionKey,
    pub unsigncryption_key: UnifiedUnsigncryptionKey,
}

#[cfg(test)]
mod tests {
    use core::panic;
    use super::*;
    use crate::cryptography::{
        encryption::{Encryption, PkeScheme, PkeSchemeType},
        signatures::gen_sig_keys,
    };
    use crate::vault::storage::tests::TestType;
    use aes_prng::AesRng;
    use rand::SeedableRng;
    use tfhe::FheTypes;

    /// Helper method that creates an rng, a valid client request (on a dummy fhe cipher) and client
    /// signcryption keys SigncryptionPair Returns the rng, client request, client signcryption
    /// keys and the dummy fhe cipher the request is made for.
    fn test_setup() -> (AesRng, UnifiedSigncryptionKeyPairOwned) {
        let mut rng = AesRng::seed_from_u64(1);
        let (client_verf_key, _) = gen_sig_keys(&mut rng);
        let keys =
            ephemeral_signcryption_key_generation(&mut rng, &client_verf_key.verf_key_id(), None);
        (rng, keys)
    }

    fn test_setup_with_scheme(scheme: PkeSchemeType) -> (AesRng, UnifiedSigncryptionKeyPairOwned) {
        let mut rng = AesRng::seed_from_u64(1);
        let (client_verf_key, _) = gen_sig_keys(&mut rng);
        let (server_verf_key, server_sig_key) = gen_sig_keys(&mut rng);
        let mut encryption = Encryption::new(scheme, &mut rng);
        let (dec_key, enc_key) = encryption.keygen().unwrap();
        let receiver_id = client_verf_key.verf_key_id();
        let keys = UnifiedSigncryptionKeyPairOwned {
            signcrypt_key: UnifiedSigncryptionKey::from_signing_key(
                server_sig_key,
                enc_key.clone(),
                receiver_id.clone(),
            ),
            unsigncryption_key: UnifiedUnsigncryptionKey::new(
                Arc::new(dec_key),
                enc_key,
                server_verf_key,
                receiver_id,
            ),
        };
        (rng, keys)
    }

    /// Round-trips under every PKE scheme signcryption supports.
    #[test]
    fn sunshine() {
        for scheme in [PkeSchemeType::MlKem512, PkeSchemeType::MlKem1024P384] {
            let (mut rng, keys) = test_setup_with_scheme(scheme);
            let msg = TestType { i: 1333 };
            let cipher = keys
                .signcrypt_key
                .signcrypt(&mut rng, b"TESTTEST", &msg)
                .unwrap();
            assert_eq!(cipher.pke_type, scheme);

            let decrypted_msg = keys
                .unsigncryption_key
                .unsigncrypt(b"TESTTEST", &cipher)
                .unwrap();
            assert_eq!(msg, decrypted_msg, "{scheme}");
        }
    }

    #[test]
    fn mlkem1024_p384_cipher_is_rejected_by_an_ml_kem_512_key() {
        let (mut rng, p384_keys) = test_setup_with_scheme(PkeSchemeType::MlKem1024P384);
        let (_, ml_kem_512_keys) = test_setup();
        let msg = TestType { i: 1333 };
        let cipher = p384_keys
            .signcrypt_key
            .signcrypt(&mut rng, b"TESTTEST", &msg)
            .unwrap();

        let err = ml_kem_512_keys
            .unsigncryption_key
            .unsigncrypt::<TestType>(b"TESTTEST", &cipher)
            .unwrap_err();
        assert!(matches!(err, CryptographyError::VerificationError(_)));
    }

    #[test]
    fn sunshine_encoding_decoding() {
        // test the bincode serialization because that is what we use for all of kms
        let (mut rng, client_signcryption_keys) = test_setup();
        let msg = TestType { i: 1333 };
        let cipher = client_signcryption_keys
            .signcrypt_key
            .signcrypt(&mut rng, b"TESTTEST", &msg)
            .unwrap();
        let serialized_cipher = bc2wrap::serialize(&cipher).unwrap();
        let deserialized_cipher: UnifiedSigncryption =
            bc2wrap::deserialize_slice(&serialized_cipher).unwrap();

        let sender_verf_key = match &client_signcryption_keys.unsigncryption_key.sender {
            SenderAuth::Ecdsa(verf_key) => Some(verf_key),
            SenderAuth::Multi(_) => panic!("the test reader is a frozen one"),
        };

        let serialized_server_verf_key = bc2wrap::serialize(&sender_verf_key).unwrap();
        let deserialized_server_verf_key: PublicSigKey =
            bc2wrap::deserialize_slice(&serialized_server_verf_key).unwrap();
        let client_id = client_signcryption_keys
            .unsigncryption_key
            .receiver_id
            .clone();
        let new_keys = UnifiedUnsigncryptionKey::new(
            client_signcryption_keys
                .unsigncryption_key
                .decryption_key
                .clone(),
            client_signcryption_keys
                .unsigncryption_key
                .encryption_key
                .clone(),
            deserialized_server_verf_key,
            client_id,
        );
        let decrypted_msg = new_keys
            .unsigncrypt(b"TESTTEST", &deserialized_cipher)
            .unwrap();
        assert_eq!(msg, decrypted_msg);
    }

    #[test]
    fn bad_signcryption() {
        let (mut rng, client_signcryption_keys) = test_setup();
        let msg = TestType { i: 1333 };
        let correct_cipher = client_signcryption_keys
            .signcrypt_key
            .signcrypt(&mut rng, b"TESTTEST", &msg)
            .unwrap();

        // flip a bit in the payload
        {
            let mut cipher = correct_cipher.clone();
            cipher.payload[0] ^= 1;

            assert!(
                client_signcryption_keys
                    .unsigncryption_key
                    .unsigncrypt::<TestType>(b"TESTTEST", &cipher)
                    .is_err()
            );
        }

        // wrong scheme
        {
            let mut cipher = correct_cipher.clone();
            cipher.pke_type = PkeSchemeType::MlKem1024;
            assert!(
                client_signcryption_keys
                    .unsigncryption_key
                    .unsigncrypt::<TestType>(b"TESTTEST", &cipher)
                    .is_err()
            );
        }

        // use the wrong client signcryption key
        {
            let mut rng = AesRng::seed_from_u64(2);
            let wrong_keys = ephemeral_signcryption_key_generation(
                &mut rng,
                &client_signcryption_keys.unsigncryption_key.receiver_id,
                Some(client_signcryption_keys.signcrypt_key.signing_key()),
            );
            assert!(
                wrong_keys
                    .unsigncryption_key
                    .unsigncrypt::<TestType>(b"TESTTEST", &correct_cipher)
                    .is_err()
            );
        }

        // use the wrong server key
        {
            let mut rng = AesRng::seed_from_u64(2);
            let (wrong_verf_key, _) = gen_sig_keys(&mut rng);
            let wrong_keys = UnifiedUnsigncryptionKey::new(
                client_signcryption_keys
                    .unsigncryption_key
                    .decryption_key
                    .clone(),
                client_signcryption_keys
                    .unsigncryption_key
                    .encryption_key
                    .clone(),
                wrong_verf_key,
                client_signcryption_keys
                    .unsigncryption_key
                    .receiver_id
                    .clone(),
            );
            assert!(
                wrong_keys
                    .unsigncrypt::<TestType>(b"TESTTEST", &correct_cipher)
                    .is_err()
            );
        }

        // use bad domain separator
        {
            assert!(
                client_signcryption_keys
                    .unsigncryption_key
                    .unsigncrypt::<TestType>(b"blahblah", &correct_cipher)
                    .is_err()
            );
        }

        // happy path should still work at the end
        let decrypted_msg = client_signcryption_keys
            .unsigncryption_key
            .unsigncrypt::<TestType>(b"TESTTEST", &correct_cipher)
            .unwrap();
        assert_eq!(msg, decrypted_msg);
    }

    #[test]
    fn signcryption_with_bad_link() {
        let (mut rng, client_signcryption_keys) = test_setup();
        let link = vec![0, 1, 2, 3u8];
        let cipher = client_signcryption_keys
            .signcrypt_key
            .signcrypt_plaintext(&mut rng, b"TESTTEST", &[1], FheTypes::Bool, &link)
            .unwrap();
        let bad_link = vec![1, 2, 3, 4u8];
        let _ = client_signcryption_keys
            .unsigncryption_key
            .unsigncrypt_plaintext(b"TESTTEST", &cipher.payload, &bad_link)
            .unwrap_err();
    }

    /// Material written before multi-signature envelopes must still read. The
    /// scheme it named is dropped: a reader gets the layout from the opener it
    /// calls, and every V0 artifact was written in the frozen layout regardless
    /// of which scheme the field claimed.
    #[test]
    fn v0_upgrades_by_dropping_the_scheme() {
        use strum::IntoEnumIterator;

        for scheme in SigningSchemeType::iter() {
            let v0 = UnifiedSigncryptionV0 {
                payload: vec![1, 2, 3],
                pke_type: PkeSchemeType::MlKem512,
                signing_type: scheme,
            };

            // The upgrade is exactly what the constructor builds, so a
            // regenerated artifact still compares equal to a frozen one.
            let upgraded = v0.clone().upgrade().unwrap();
            assert_eq!(
                upgraded,
                UnifiedSigncryption::new(v0.payload, v0.pke_type),
                "{scheme}"
            );
        }
    }
}

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

use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::cryptography::encryption::{
    HasPkeScheme, PkeSchemeType, UnifiedPrivateEncKey, UnifiedPublicEncKey,
};
use crate::cryptography::error::CryptographyError;
use crate::cryptography::hybrid_ml_kem::{self, HybridKemCt};
use crate::cryptography::signatures::{
    check_normalized, internal_sign, HasSigningScheme, PrivateSigKey, PublicSigKey, Signature,
    SigningSchemeType, SIG_SIZE,
};
use ::signature::Verifier;
use kms_grpc::kms::v1::TypedPlaintext;
use rand::{CryptoRng, RngCore};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::FheTypes;
use tfhe_versionable::{Versionize, VersionsDispatch};
use threshold_fhe::hashing::{serialize_hash_element, DomainSep, DIGEST_BYTES};
use zeroize::{Zeroize, ZeroizeOnDrop};

const DSEP_SIGNCRYPTION: DomainSep = *b"SIGNCRYP";

pub trait Signcrypt {
    /// Signcrypt a message of type T with a specified domain separator.
    fn signcrypt<T: Serialize + tfhe::Versionize + tfhe::named::Named>(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        dsep: &DomainSep,
        msg: &T,
    ) -> Result<UnifiedSigncryption, CryptographyError>;
}

pub trait Unsigncrypt {
    /// Decrypt a signcrypted message and verify the signature before returning the result.
    /// If the signature verification fails, an error is returned.
    ///
    /// This fn also checks that the provided link parameter corresponds to the link in the signcryption
    /// payload.
    fn unsigncrypt<T: DeserializeOwned + tfhe::Unversionize + tfhe::named::Named>(
        &self,
        dsep: &DomainSep,
        cipher: &UnifiedSigncryption,
    ) -> Result<T, CryptographyError>;

    /// Validate the signature of a signcrypted message without decrypting the payload.
    /// This can be used to check authenticity if decryption is not needed.
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
    fn unsigncrypt_plaintext(
        &self,
        dsep: &DomainSep,
        signcryption: &[u8],
        link: &[u8],
    ) -> Result<SigncryptionPayload, CryptographyError>;
}

#[derive(
    Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, VersionsDispatch,
)]
pub enum UnifiedSigncryptionKeyOwnedVersioned {
    V0(UnifiedSigncryptionKeyOwned),
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug, Zeroize, Versionize)]
#[versionize(UnifiedSigncryptionKeyOwnedVersioned)]
pub struct UnifiedSigncryptionKeyOwned {
    pub signing_key: PrivateSigKey,
    pub receiver_enc_key: UnifiedPublicEncKey,
    pub receiver_id: Vec<u8>, // Identifier for the receiver's encryption key, e.g. blockchain address
}
impl UnifiedSigncryptionKeyOwned {
    pub fn new(
        signing_key: PrivateSigKey,
        receiver_enc_key: UnifiedPublicEncKey,
        receiver_id: Vec<u8>,
    ) -> Self {
        Self {
            signing_key,
            receiver_enc_key,
            receiver_id,
        }
    }

    pub fn reference<'a>(&'a self) -> UnifiedSigncryptionKey<'a> {
        UnifiedSigncryptionKey {
            signing_key: &self.signing_key,
            receiver_enc_key: &self.receiver_enc_key,
            receiver_id: &self.receiver_id,
        }
    }
}

impl HasPkeScheme for UnifiedSigncryptionKeyOwned {
    fn encryption_scheme_type(&self) -> PkeSchemeType {
        self.receiver_enc_key.encryption_scheme_type()
    }
}
impl HasSigningScheme for UnifiedSigncryptionKeyOwned {
    fn signing_scheme_type(&self) -> SigningSchemeType {
        self.signing_key.signing_scheme_type()
    }
}

/// Internal type for signcryption keys, storing only references to the real internal keys.
/// Thus this type should not be serialized instead `UnifiedSigncryptionKeyOwned` should be used.
#[derive(Clone, Debug)]
pub struct UnifiedSigncryptionKey<'a> {
    pub signing_key: &'a PrivateSigKey,
    pub receiver_enc_key: &'a UnifiedPublicEncKey,
    pub receiver_id: &'a [u8], // Identifier for the receiver's encryption key, e.g. blockchain address
}

impl<'a> UnifiedSigncryptionKey<'a> {
    pub fn new(
        signing_key: &'a PrivateSigKey,
        receiver_enc_key: &'a UnifiedPublicEncKey,
        receiver_id: &'a [u8],
    ) -> Self {
        Self {
            signing_key,
            receiver_enc_key,
            receiver_id,
        }
    }
}

impl HasPkeScheme for UnifiedSigncryptionKey<'_> {
    fn encryption_scheme_type(&self) -> PkeSchemeType {
        self.receiver_enc_key.encryption_scheme_type()
    }
}
impl HasSigningScheme for UnifiedSigncryptionKey<'_> {
    fn signing_scheme_type(&self) -> SigningSchemeType {
        self.signing_key.signing_scheme_type()
    }
}

/// Internal reference type for unsigncryption keys, storing only references to the real internal keys.
#[derive(Clone, Debug)]
pub struct UnifiedUnsigncryptionKey<'a> {
    pub decryption_key: &'a UnifiedPrivateEncKey,
    pub encryption_key: &'a UnifiedPublicEncKey, // Needed for validation of the signcrypted payload
    pub sender_verf_key: &'a PublicSigKey,
    /// The ID of the receiver of the signcryption, e.g. blockchain address
    pub receiver_id: &'a [u8],
}

impl<'a> UnifiedUnsigncryptionKey<'a> {
    pub fn new(
        decryption_key: &'a UnifiedPrivateEncKey,
        encryption_key: &'a UnifiedPublicEncKey,
        sender_verf_key: &'a PublicSigKey,
        receiver_id: &'a [u8],
    ) -> Self {
        Self {
            sender_verf_key,
            decryption_key,
            encryption_key,
            receiver_id,
        }
    }

    //  TODO this file should be split up and this moved to signcryption
}

impl HasPkeScheme for UnifiedUnsigncryptionKey<'_> {
    fn encryption_scheme_type(&self) -> PkeSchemeType {
        self.encryption_key.encryption_scheme_type()
    }
}

impl HasSigningScheme for UnifiedUnsigncryptionKey<'_> {
    fn signing_scheme_type(&self) -> SigningSchemeType {
        self.sender_verf_key.signing_scheme_type()
    }
}

#[derive(
    Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, VersionsDispatch,
)]
pub enum UnifiedUnsigncryptionKeyOwnedVersioned {
    V0(UnifiedUnsigncryptionKeyOwned),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(UnifiedUnsigncryptionKeyOwnedVersioned)]
pub struct UnifiedUnsigncryptionKeyOwned {
    pub decryption_key: UnifiedPrivateEncKey,
    pub encryption_key: UnifiedPublicEncKey, // Needed for validation of the signcrypted payload
    pub sender_verf_key: PublicSigKey,
    /// The ID of the receiver of the signcryption, e.g. blockchain address]
    pub receiver_id: Vec<u8>,
}

impl Zeroize for UnifiedUnsigncryptionKeyOwned {
    fn zeroize(&mut self) {
        // We only need to zeroize the private key
        self.decryption_key.zeroize();
    }
}

impl UnifiedUnsigncryptionKeyOwned {
    pub fn new(
        decryption_key: UnifiedPrivateEncKey,
        encryption_key: UnifiedPublicEncKey,
        sender_verf_key: PublicSigKey,
        receiver_id: Vec<u8>,
    ) -> Self {
        Self {
            sender_verf_key,
            decryption_key,
            encryption_key,
            receiver_id,
        }
    }

    pub fn reference<'a>(&'a self) -> UnifiedUnsigncryptionKey<'a> {
        UnifiedUnsigncryptionKey {
            decryption_key: &self.decryption_key,
            encryption_key: &self.encryption_key,
            sender_verf_key: &self.sender_verf_key,
            receiver_id: &self.receiver_id,
        }
    }
}

impl HasPkeScheme for UnifiedUnsigncryptionKeyOwned {
    fn encryption_scheme_type(&self) -> PkeSchemeType {
        self.encryption_key.encryption_scheme_type()
    }
}

impl HasSigningScheme for UnifiedUnsigncryptionKeyOwned {
    fn signing_scheme_type(&self) -> SigningSchemeType {
        self.sender_verf_key.signing_scheme_type()
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum UnifiedSigncryptionVersioned {
    V0(UnifiedSigncryption),
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Versionize)]
#[versionize(UnifiedSigncryptionVersioned)]
pub struct UnifiedSigncryption {
    pub payload: Vec<u8>,
    pub pke_type: PkeSchemeType,
    pub signing_type: SigningSchemeType,
}
impl UnifiedSigncryption {
    pub fn new(payload: Vec<u8>, pke_type: PkeSchemeType, signing_type: SigningSchemeType) -> Self {
        Self {
            payload,
            pke_type,
            signing_type,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Hash, PartialEq, Eq, Debug, VersionsDispatch)]
pub enum SigncryptionPayloadVersioned {
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
/// - Unit test: `test_signcryption_payload_v0_serialization_locked` locks the binary format
/// - BC tests: Verify v0.11.x data can be deserialized by current version
/// - Both tests MUST pass before any changes to this type

#[derive(Clone, Serialize, Deserialize, Hash, PartialEq, Eq, Debug, Versionize)]
#[versionize(SigncryptionPayloadVersioned)]
pub struct SigncryptionPayload {
    pub plaintext: TypedPlaintext,
    pub link: Vec<u8>,
}

/// Compute the signcryption of a message encrypted under the public keys received from a client and
/// signed by the server's signing key.
///
/// Returns the signcrypted message.
///
/// WARNING: It is assumed that the client's public key HAS been validated to come from a valid
/// `ClientRequest` and validated to be consistent with the blockchain identity of the client BEFORE
/// calling this method. IF THIS HAS NOT BEEN DONE THEN ANYONE CAN IMPERSONATE ANY CLIENT!!!
impl<'a> Signcrypt for UnifiedSigncryptionKey<'a> {
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
        let mut serialized_msg = Vec::new();
        safe_serialize(msg, &mut serialized_msg, SAFE_SER_SIZE_LIMIT).map_err(|e| {
            CryptographyError::SerializationError(format!(
                "Could not serialize message for signcryption: {e}",
            ))
        })?;
        inner_signcryption(self, rng, dsep, &serialized_msg)
    }
}

impl Signcrypt for UnifiedSigncryptionKeyOwned {
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
        let ref_type = self.reference();
        ref_type.signcrypt(rng, dsep, msg)
    }
}

impl<'a> SigncryptFHEPlaintext for UnifiedSigncryptionKey<'a> {
    fn signcrypt_plaintext(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        dsep: &DomainSep,
        plaintext: &[u8],
        fhe_type: FheTypes,
        link: &[u8],
    ) -> Result<UnifiedSigncryption, CryptographyError> {
        let signcryption_msg = SigncryptionPayload {
            plaintext: TypedPlaintext::from_bytes(plaintext.to_owned(), fhe_type),
            link: link.to_owned(),
        };
        // LEGACY Code: should be using safe_serialization
        inner_signcryption(self, rng, dsep, &bc2wrap::serialize(&signcryption_msg)?)
    }
}

impl SigncryptFHEPlaintext for UnifiedSigncryptionKeyOwned {
    fn signcrypt_plaintext(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        dsep: &DomainSep,
        plaintext: &[u8],
        fhe_type: FheTypes,
        link: &[u8],
    ) -> Result<UnifiedSigncryption, CryptographyError> {
        let ref_type = self.reference();
        ref_type.signcrypt_plaintext(rng, dsep, plaintext, fhe_type, link)
    }
}

// Implements the actual signcryption but without serialization
fn inner_signcryption<T: Serialize + AsRef<[u8]>>(
    signcrypt_key: &UnifiedSigncryptionKey,
    rng: &mut (impl CryptoRng + RngCore),
    dsep: &DomainSep,
    msg: &T,
) -> Result<UnifiedSigncryption, CryptographyError> {
    // Adds the hash digest of the receivers public encryption key to the message to sign
    // Sign msg || H(client_verf_key) || H(client_pub_key)
    // Note that H(client_verf_key) = client_address
    // Only serialize the inner structure to ensure backwards compatibility!!!
    let serialized_enc_key = match &signcrypt_key.receiver_enc_key {
        UnifiedPublicEncKey::MlKem512(public_enc_key) => {
            serialize_hash_element(&DSEP_SIGNCRYPTION, public_enc_key)
                .map_err(|e| CryptographyError::DeserializationError(e.to_string()))?
        }
        UnifiedPublicEncKey::MlKem1024(public_enc_key) => {
            serialize_hash_element(&DSEP_SIGNCRYPTION, public_enc_key)
                .map_err(|e| CryptographyError::DeserializationError(e.to_string()))?
        }
    };
    let to_sign = [msg.as_ref(), signcrypt_key.receiver_id, &serialized_enc_key].concat();
    let sig = internal_sign(dsep, &to_sign, signcrypt_key.signing_key)
        .map_err(|e| CryptographyError::SigningError(e.to_string()))?
        .sig;

    // Encrypt msg || sig || H(server_verification_key) || H(server_enc_pub_key)
    // OBSERVE: serialization is simply r concatenated with s. That is NOT an Ethereum compatible
    // signature since we preclude the v value.
    // The verification key is serialized based on the SEC1 standard.
    let verf_key_hash = serialize_hash_element(
        &DSEP_SIGNCRYPTION,
        // LEGACY: this is horrible! We are using address above be here we use digest! This should be changed to use  &self.signing_key.verf_key().verf_key_id(),
        // Idem below
        &PublicSigKey::from_sk(signcrypt_key.signing_key),
    )
    .map_err(|e| CryptographyError::DeserializationError(e.to_string()))?;
    let to_encrypt = [
        msg.as_ref(),
        sig.to_bytes().as_ref(),
        verf_key_hash.as_ref(),
    ]
    .concat();

    let ciphertext = match &signcrypt_key.receiver_enc_key {
        UnifiedPublicEncKey::MlKem512(public_enc_key) => {
            hybrid_ml_kem::enc::<ml_kem::MlKem512, _>(rng, &to_encrypt, &public_enc_key.0)
        }
        UnifiedPublicEncKey::MlKem1024(public_enc_key) => {
            hybrid_ml_kem::enc::<ml_kem::MlKem1024, _>(rng, &to_encrypt, &public_enc_key.0)
        }
    }?;
    // LEGACY: approach to serialization
    Ok(UnifiedSigncryption {
        payload: bc2wrap::serialize(&ciphertext)
            .map_err(|e| CryptographyError::BincodeError(e.to_string()))?,
        pke_type: signcrypt_key.encryption_scheme_type(),
        signing_type: signcrypt_key.signing_scheme_type(),
    })
}

impl<'a> Unsigncrypt for UnifiedUnsigncryptionKey<'a> {
    fn unsigncrypt<T: DeserializeOwned + tfhe::Unversionize + tfhe::named::Named>(
        &self,
        dsep: &DomainSep,
        cipher: &UnifiedSigncryption,
    ) -> Result<T, CryptographyError> {
        let msg_vec = inner_unsigncrypt(self, dsep, cipher)?;
        safe_deserialize(std::io::Cursor::new(&msg_vec), SAFE_SER_SIZE_LIMIT)
            .map_err(CryptographyError::SerializationError)
    }

    fn validate_signcryption(
        &self,
        dsep: &DomainSep,
        signcryption: &UnifiedSigncryption,
    ) -> Result<(), CryptographyError> {
        // Since we use sign-then-encrypt, we need to decrypt first to get the message for signature verification
        let _ = inner_unsigncrypt(self, dsep, signcryption).map_err(|e| {
            CryptographyError::VerificationError(format!(
                "failed to decrypt signcryption for validation: {}",
                e
            ))
        })?;
        Ok(())
    }
}

impl Unsigncrypt for UnifiedUnsigncryptionKeyOwned {
    fn unsigncrypt<T: DeserializeOwned + tfhe::Unversionize + tfhe::named::Named>(
        &self,
        dsep: &DomainSep,
        cipher: &UnifiedSigncryption,
    ) -> Result<T, CryptographyError> {
        let ref_type = self.reference();
        ref_type.unsigncrypt(dsep, cipher)
    }

    fn validate_signcryption(
        &self,
        dsep: &DomainSep,
        signcryption: &UnifiedSigncryption,
    ) -> Result<(), CryptographyError> {
        let ref_type = self.reference();
        ref_type.validate_signcryption(dsep, signcryption)
    }
}

impl<'a> UnsigncryptFHEPlaintext for UnifiedUnsigncryptionKey<'a> {
    fn unsigncrypt_plaintext(
        &self,
        dsep: &DomainSep,
        signcryption: &[u8],
        link: &[u8],
    ) -> Result<SigncryptionPayload, CryptographyError> {
        let parsed_signcryption = UnifiedSigncryption {
            payload: signcryption.to_owned(),
            pke_type: self.encryption_key.encryption_scheme_type(),
            signing_type: self.sender_verf_key.signing_scheme_type(),
        };
        let decrypted_signcryption = inner_unsigncrypt(self, dsep, &parsed_signcryption)?;
        // LEGACY should be using safe_deserialization
        let signcrypted_msg: SigncryptionPayload = bc2wrap::deserialize(&decrypted_signcryption)
            .map_err(|e| CryptographyError::BincodeError(e.to_string()))?;
        if link != signcrypted_msg.link {
            return Err(CryptographyError::VerificationError(
                "signcryption link does not match!".to_string(),
            ));
        }
        Ok(signcrypted_msg)
    }
}

impl UnsigncryptFHEPlaintext for UnifiedUnsigncryptionKeyOwned {
    fn unsigncrypt_plaintext(
        &self,
        dsep: &DomainSep,
        signcryption: &[u8],
        link: &[u8],
    ) -> Result<SigncryptionPayload, CryptographyError> {
        let ref_type = self.reference();
        ref_type.unsigncrypt_plaintext(dsep, signcryption, link)
    }
}

/// Implements the actual unsigncryption process, but without any deserialization
fn inner_unsigncrypt(
    unsign_key: &UnifiedUnsigncryptionKey,
    dsep: &DomainSep,
    cipher: &UnifiedSigncryption,
) -> Result<Vec<u8>, CryptographyError> {
    if cipher.pke_type != unsign_key.encryption_key.encryption_scheme_type() {
        return Err(CryptographyError::VerificationError(
            "encryption type of cipher does not match the decryption key type".to_string(),
        ));
    }
    // LEGACY Code: should be using safe_deserialization
    let deserialized_payload: HybridKemCt = bc2wrap::deserialize(&cipher.payload)
        .map_err(|e| CryptographyError::BincodeError(e.to_string()))?;
    let decrypted_plaintext = match &unsign_key.decryption_key {
        UnifiedPrivateEncKey::MlKem512(dec_key) => {
            hybrid_ml_kem::dec::<ml_kem::MlKem512>(deserialized_payload, &dec_key.0)
        }
        UnifiedPrivateEncKey::MlKem1024(dec_key) => {
            hybrid_ml_kem::dec::<ml_kem::MlKem1024>(deserialized_payload, &dec_key.0)
        }
    }?;
    let (msg, sig) = parse_msg(decrypted_plaintext, unsign_key.sender_verf_key)?;
    check_format_and_signature(dsep, msg.clone(), &sig, unsign_key)?;
    Ok(msg)
}

/// Helper method for parsing a signcrypted message consisting of the _true_ msg || sig ||
/// H(server_verification_key)
fn parse_msg(
    decrypted_plaintext: Vec<u8>,
    server_verf_key: &PublicSigKey,
) -> Result<(Vec<u8>, Signature), CryptographyError> {
    // The plaintext contains msg || sig || H(server_verification_key)
    let msg_len = decrypted_plaintext
        .len()
        .checked_sub(DIGEST_BYTES)
        .and_then(|len| len.checked_sub(SIG_SIZE))
        .ok_or_else(||
            CryptographyError::LengthError(
                format!("Message is too short ({} bytes) to contain sig || H(server_verification_key) ({} bytes) ",
                decrypted_plaintext.len(),
                DIGEST_BYTES + SIG_SIZE)
            )
        )?;
    let msg = &decrypted_plaintext[..msg_len];
    let sig_bytes = &decrypted_plaintext[msg_len..(msg_len + SIG_SIZE)];
    let server_ver_key_digest =
        &decrypted_plaintext[(msg_len + SIG_SIZE)..(msg_len + SIG_SIZE + DIGEST_BYTES)];
    // LEGACY: this should just be based on key id. Again legacy code that could be done more proper by using the notion of an id!
    // Verify verification key digest
    if serialize_hash_element(&DSEP_SIGNCRYPTION, server_verf_key)
        .map_err(|e| CryptographyError::BincodeError(e.to_string()))?
        != server_ver_key_digest
    {
        return Err(CryptographyError::VerificationError(format!(
            "unexpected verification key digest {server_ver_key_digest:X?} was part of the decryption",
        )));
    }
    let sig = k256::ecdsa::Signature::from_slice(sig_bytes)
        .map_err(|e| CryptographyError::SerializationError(e.to_string()))?;
    Ok((msg.to_vec(), Signature { sig }))
}

/// Helper method for performing the necessary checks on a signcryption signature.
/// Returns true if the signature is ok and false otherwise
fn check_format_and_signature(
    dsep: &DomainSep,
    msg: Vec<u8>,
    sig: &Signature,
    unsigncryption_key: &UnifiedUnsigncryptionKey,
) -> Result<(), CryptographyError> {
    // What should be signed is dsep || msg || H(client_verification_key) || H(client_enc_key)
    let serialized_enc_key = match &unsigncryption_key.encryption_key {
        UnifiedPublicEncKey::MlKem512(public_enc_key) => {
            serialize_hash_element(&DSEP_SIGNCRYPTION, public_enc_key)
                .map_err(|e| CryptographyError::DeserializationError(e.to_string()))?
        }
        UnifiedPublicEncKey::MlKem1024(public_enc_key) => {
            serialize_hash_element(&DSEP_SIGNCRYPTION, public_enc_key)
                .map_err(|e| CryptographyError::DeserializationError(e.to_string()))?
        }
    };
    let msg_signed = [
        dsep.to_vec(),
        msg,
        unsigncryption_key.receiver_id.to_vec(),
        serialized_enc_key,
    ]
    .concat();
    // Check that the signature is normalized
    check_normalized(sig)?;
    // Verify signature
    unsigncryption_key
        .sender_verf_key
        .pk()
        .verify(&msg_signed[..], &sig.sig)
        .map_err(|e| CryptographyError::VerificationError(e.to_string()))
}

/// Decrypt a signcrypted message and ignore the signature
///
/// This function does *not* do any verification and is thus insecure and should be used only for
/// testing.
/// TODO hide behind flag for insecure function?
pub(crate) fn insecure_decrypt_ignoring_signature(
    cipher: &[u8],
    client_keys: &UnifiedUnsigncryptionKey,
) -> Result<TypedPlaintext, CryptographyError> {
    // LEGACY should be using safe_deserialization
    let cipher: HybridKemCt =
        bc2wrap::deserialize(cipher).map_err(|e| CryptographyError::BincodeError(e.to_string()))?;
    let decrypted_plaintext = match &client_keys.decryption_key {
        UnifiedPrivateEncKey::MlKem512(client_keys) => {
            hybrid_ml_kem::dec::<ml_kem::MlKem512>(cipher.clone(), &client_keys.0)?
        }
        UnifiedPrivateEncKey::MlKem1024(client_keys) => {
            hybrid_ml_kem::dec::<ml_kem::MlKem1024>(cipher.clone(), &client_keys.0)?
        }
    };

    // strip off the signature bytes (these are ignored here)
    let msg_len = decrypted_plaintext.len() - DIGEST_BYTES - SIG_SIZE;
    let msg = &decrypted_plaintext[..msg_len];
    // LEGACY should be using safe_deserialization
    let signcrypted_msg: SigncryptionPayload =
        bc2wrap::deserialize(msg).map_err(|e| CryptographyError::BincodeError(e.to_string()))?;

    Ok(signcrypted_msg.plaintext)
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
        signcrypt_key: UnifiedSigncryptionKeyOwned::new(
            server_sig_key.clone(),
            enc_key.clone(),
            client_verf_key_id.to_vec(),
        ),
        unsigncryption_key: UnifiedUnsigncryptionKeyOwned::new(
            dec_key,
            enc_key,
            server_verf_key.clone(),
            client_verf_key_id.to_vec(),
        ),
    }
}

/// Helper struct that contains both signcryption and unsigncryption keys for a client
/// For now only used for testing
#[cfg(test)]
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct UnifiedSigncryptionKeyPairOwned {
    pub signcrypt_key: UnifiedSigncryptionKeyOwned,
    pub unsigncryption_key: UnifiedUnsigncryptionKeyOwned,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::{encryption::PkeSchemeType, signatures::gen_sig_keys};
    use crate::vault::storage::tests::TestType;
    use aes_prng::AesRng;
    use kms_grpc::kms::v1::TypedPlaintext;
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

    #[test]
    fn sunshine() {
        let (mut rng, client_signcryption_keys) = test_setup();
        let msg = TestType { i: 1333 };
        let cipher = client_signcryption_keys
            .signcrypt_key
            .signcrypt(&mut rng, b"TESTTEST", &msg)
            .unwrap();
        let decrypted_msg = client_signcryption_keys
            .unsigncryption_key
            .unsigncrypt(b"TESTTEST", &cipher)
            .unwrap();
        assert_eq!(msg, decrypted_msg);
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
            bc2wrap::deserialize(&serialized_cipher).unwrap();

        let serialized_server_verf_key =
            bc2wrap::serialize(&client_signcryption_keys.unsigncryption_key.sender_verf_key)
                .unwrap();
        let deserialized_server_verf_key: PublicSigKey =
            bc2wrap::deserialize(&serialized_server_verf_key).unwrap();
        let client_id = client_signcryption_keys
            .unsigncryption_key
            .receiver_id
            .clone();
        let new_keys = UnifiedUnsigncryptionKey::new(
            &client_signcryption_keys.unsigncryption_key.decryption_key,
            &client_signcryption_keys.unsigncryption_key.encryption_key,
            &deserialized_server_verf_key,
            &client_id,
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

            assert!(client_signcryption_keys
                .unsigncryption_key
                .unsigncrypt::<TestType>(b"TESTTEST", &cipher)
                .is_err());
        }

        // wrong scheme
        {
            let mut cipher = correct_cipher.clone();
            cipher.pke_type = PkeSchemeType::MlKem1024;
            assert!(client_signcryption_keys
                .unsigncryption_key
                .unsigncrypt::<TestType>(b"TESTTEST", &cipher)
                .is_err());
        }

        // use the wrong client signcryption key
        {
            let mut rng = AesRng::seed_from_u64(2);
            let wrong_keys = ephemeral_signcryption_key_generation(
                &mut rng,
                &client_signcryption_keys.unsigncryption_key.receiver_id,
                Some(&client_signcryption_keys.signcrypt_key.signing_key),
            );
            assert!(wrong_keys
                .unsigncryption_key
                .unsigncrypt::<TestType>(b"TESTTEST", &correct_cipher)
                .is_err());
        }

        // use the wrong server key
        {
            let mut rng = AesRng::seed_from_u64(2);
            let (wrong_verf_key, _) = gen_sig_keys(&mut rng);
            let wrong_keys = UnifiedUnsigncryptionKey::new(
                &client_signcryption_keys.unsigncryption_key.decryption_key,
                &client_signcryption_keys.unsigncryption_key.encryption_key,
                &wrong_verf_key,
                &client_signcryption_keys.unsigncryption_key.receiver_id,
            );
            assert!(wrong_keys
                .unsigncrypt::<TestType>(b"TESTTEST", &correct_cipher)
                .is_err());
        }

        // use bad domain separator
        {
            assert!(client_signcryption_keys
                .unsigncryption_key
                .unsigncrypt::<TestType>(b"blahblah", &correct_cipher)
                .is_err());
        }

        // happy path should still work at the end
        let decrypted_msg = client_signcryption_keys
            .unsigncryption_key
            .unsigncrypt::<TestType>(b"TESTTEST", &correct_cipher)
            .unwrap();
        assert_eq!(msg, decrypted_msg);
    }

    #[test]
    fn incorrect_server_verf_key() {
        let mut rng = AesRng::seed_from_u64(42);
        let (server_verf_key, _server_sig_key) = gen_sig_keys(&mut rng);
        let to_encrypt = [0_u8; 1 + DIGEST_BYTES + SIG_SIZE];
        let res = parse_msg(to_encrypt.to_vec(), &server_verf_key);
        // unwrapping fails
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("unexpected verification key digest"));
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

    // ============================================================================
    // Backward Compatibility Tests for SigncryptionPayload
    // ============================================================================

    /// This test locks the binary serialization format of SigncryptionPayload.
    ///
    /// If this test fails, you have made a BREAKING CHANGE to SigncryptionPayload
    /// that will prevent users from decrypting existing signcrypted ciphertexts.
    ///
    /// Breaking changes include:
    /// - Reordering fields
    /// - Changing field types
    /// - Removing fields
    /// - Renaming fields
    ///
    /// If you need to make changes, you MUST:
    /// 1. Create a new version of the struct (e.g., SigncryptionPayloadV1)
    /// 2. Implement migration logic from V0 to V1
    /// 3. Update all serialization/deserialization code to handle both versions
    #[test]
    fn test_signcryption_payload_v0_serialization_locked() {
        let payload = SigncryptionPayload {
            plaintext: TypedPlaintext {
                bytes: vec![1, 2, 3, 4, 5],
                fhe_type: 8, // FheTypes::Uint8
            },
            link: vec![222, 173, 190, 239],
        };

        let serialized = bc2wrap::serialize(&payload).expect("serialization should succeed");

        // LOCKED V0 FORMAT - DO NOT CHANGE
        let expected_bytes = vec![
            5, 0, 0, 0, 0, 0, 0, 0, // plaintext.bytes length
            1, 2, 3, 4, 5, // plaintext.bytes content
            8, 0, 0, 0, // plaintext.fhe_type
            4, 0, 0, 0, 0, 0, 0, 0, // link length
            222, 173, 190, 239, // link content
        ];

        assert_eq!(
            serialized, expected_bytes,
            "BREAKING CHANGE: SigncryptionPayload format changed!\n\
             This will break user decryption for existing ciphertexts."
        );
    }
}

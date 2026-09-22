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
//! one. Which one applies is a total function of the signcryption's scheme set.
//!
//! [`SigncryptionFormat::EcdsaV0`] is the original layout and is **frozen**:
//! every user-decryption ciphertext produced since 0.11 uses it, the deployed
//! browser-side verifier in `crate::client::user_decryption_wasm` parses it, and
//! because it carries no version tag of its own and is recovered by subtracting
//! two fixed-size tail fields, it cannot be made self-describing after the fact
//! either. What is locked, and by what:
//!
//! - The plaintext layout `msg ‖ sig ‖ H(sender verification key)`, by
//!   `tests::ecdsa_v0_envelope_layout_is_locked`.
//! - The signed preimage `dsep ‖ msg ‖ receiver_id ‖ H(receiver enc key)`, by
//!   `tests::ecdsa_v0_signed_preimage_is_locked`.
//! - The [`SigncryptionPayload`] bincode layout, by
//!   `tests::test_signcryption_payload_v0_serialization_locked`.
//! - The whole artifact, including **the order in which the RNG is drawn from**,
//!   by the backward-compatibility harness: `test_unified_signcryption` in
//!   `core/service/tests/backward_compatibility_kms.rs` regenerates a
//!   signcryption from a seeded RNG and compares it byte-for-byte against a
//!   fixture frozen at 0.13.0. Moving an RNG draw in [`inner_signcryption`]
//!   breaks it.
//!
//! [`SigncryptionFormat::CompositeV1`] will carry one signature per scheme, for
//! the custodian-backup chain. Not implemented yet: asking for it is a
//! [`CryptographyError::UnsupportedSigncryptionFormat`].

mod common;
pub mod composite_v1;
mod ecdsa_v0;

pub use composite_v1::{CompositeSigncryptionKey, CompositeUnsigncryptionKey};
pub(crate) use ecdsa_v0::insecure_decrypt_ignoring_signature;

use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::cryptography::encryption::{
    HasPkeScheme, PkeSchemeType, UnifiedPrivateEncKey, UnifiedPublicEncKey,
};
use crate::cryptography::error::CryptographyError;
use crate::cryptography::signatures::{
    HasSigningScheme, PrivateSigKey, PublicSigKey, SigningSchemeSet, SigningSchemeType,
};
use crate::cryptography::zeroizing_writer::ZeroizingWriter;
use hashing::DomainSep;
use kms_grpc::kms::v1::TypedPlaintext;
use rand::{CryptoRng, RngCore};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tfhe::FheTypes;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe_versionable::{Upgrade, Version, Versionize, VersionsDispatch};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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
    ///
    /// The returned payload contains cleartext and implements [`Zeroize`], but not
    /// [`ZeroizeOnDrop`], because callers may move out `plaintext`.
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
pub enum UnifiedSigncryptionKeyOwnedVersions {
    V0(UnifiedSigncryptionKeyOwned),
}

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug, Zeroize, Versionize)]
#[versionize(UnifiedSigncryptionKeyOwnedVersions)]
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

    /// The schemes this key signs under.
    ///
    /// A single scheme today, because the key it holds is the ECDSA
    /// [`PrivateSigKey`].
    pub fn signing_schemes(&self) -> SigningSchemeSet {
        SigningSchemeSet::single(self.signing_key.signing_scheme_type())
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

    /// The schemes this key accepts a signature under.
    ///
    /// The counterpart of [`UnifiedSigncryptionKey::signing_schemes`], and a
    /// single scheme for the same reason.
    pub fn signing_schemes(&self) -> SigningSchemeSet {
        SigningSchemeSet::single(self.sender_verf_key.signing_scheme_type())
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
pub enum UnifiedUnsigncryptionKeyOwnedVersions {
    V0(UnifiedUnsigncryptionKeyOwned),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(UnifiedUnsigncryptionKeyOwnedVersions)]
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
pub enum UnifiedSigncryptionVersions {
    V0(UnifiedSigncryptionV0),
    V1(UnifiedSigncryption),
}

/// A signcryption as it was stored and sent before composite signing, carrying
/// exactly one signature scheme.
///
/// Kept so that legacy material can still be read.
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
            signing_schemes: SigningSchemeSet::single(self.signing_type),
        })
    }
}

/// A signcrypted message, tagged with the schemes used to protect it.
///
/// `signing_schemes` names every scheme whose signature is inside `payload`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Versionize)]
#[versionize(UnifiedSigncryptionVersions)]
pub struct UnifiedSigncryption {
    pub payload: Vec<u8>,
    pub pke_type: PkeSchemeType,
    pub signing_schemes: SigningSchemeSet,
}
impl UnifiedSigncryption {
    /// A signcryption protected by every scheme in `signing_schemes`.
    pub fn new(
        payload: Vec<u8>,
        pke_type: PkeSchemeType,
        signing_schemes: SigningSchemeSet,
    ) -> Self {
        Self {
            payload,
            pke_type,
            signing_schemes,
        }
    }

    /// The one scheme protecting this signcryption, or `None` if several do.
    pub fn sole_signing_scheme(&self) -> Option<SigningSchemeType> {
        self.signing_schemes.sole()
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
/// - Unit test: `test_signcryption_payload_v0_serialization_locked` locks the binary format
/// - BC tests: Verify v0.11.x data can be deserialized by current version
/// - Both tests MUST pass before any changes to this type
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
impl<'a> Signcrypt for UnifiedSigncryptionKey<'a> {
    #[allow(unknown_lints)]
    // We allow modifying the rng before return
    #[allow(non_local_effect_before_unhandled_error)]
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
        let schemes = self.signing_schemes();
        match common::format_for(&schemes) {
            common::SigncryptionFormat::EcdsaV0 => {
                ecdsa_v0::inner_signcryption(self, rng, dsep, serialized_msg.as_slice())
            }
            common::SigncryptionFormat::CompositeV1 => Err(common::unsupported_format(&schemes)),
        }
    }
}

impl Signcrypt for UnifiedSigncryptionKeyOwned {
    #[allow(unknown_lints)]
    // We allow modifying the rng before return
    #[allow(non_local_effect_before_unhandled_error)]
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
        // Deliberately not routed through `format_for`: the wire type this
        // produces, `TypedSigncryptedCiphertext.signcrypted_ciphertext`, is a
        // bare `bytes` field with nowhere to record a format, so the only
        // layout its readers can parse is the frozen one.
        ecdsa_v0::inner_signcryption(self, rng, dsep, serialized_msg.as_slice())
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

/// Open `cipher` in whichever format its scheme set names.
fn open_dispatch(
    unsign_key: &UnifiedUnsigncryptionKey,
    dsep: &DomainSep,
    cipher: &UnifiedSigncryption,
) -> Result<Zeroizing<Vec<u8>>, CryptographyError> {
    match common::format_for(&cipher.signing_schemes) {
        common::SigncryptionFormat::EcdsaV0 => {
            ecdsa_v0::inner_unsigncrypt(unsign_key, dsep, cipher)
        }
        common::SigncryptionFormat::CompositeV1 => {
            Err(common::unsupported_format(&cipher.signing_schemes))
        }
    }
}

impl<'a> Unsigncrypt for UnifiedUnsigncryptionKey<'a> {
    fn unsigncrypt<T: DeserializeOwned + tfhe::Unversionize + tfhe::named::Named>(
        &self,
        dsep: &DomainSep,
        cipher: &UnifiedSigncryption,
    ) -> Result<T, CryptographyError> {
        let msg_vec = open_dispatch(self, dsep, cipher)?;
        safe_deserialize(std::io::Cursor::new(&*msg_vec), SAFE_SER_SIZE_LIMIT)
            .map_err(CryptographyError::SerializationError)
    }

    fn validate_signcryption(
        &self,
        dsep: &DomainSep,
        signcryption: &UnifiedSigncryption,
    ) -> Result<(), CryptographyError> {
        // Since we use sign-then-encrypt, we need to decrypt first to get the message for signature verification
        let _ = open_dispatch(self, dsep, signcryption).map_err(|e| {
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
        // The legacy user-decryption path. See the note in `signcrypt_plaintext`
        // for why the format is fixed here rather than chosen: the raw bytes
        // this receives have nowhere to record one.
        let parsed_signcryption = UnifiedSigncryption::new(
            signcryption.to_owned(),
            self.encryption_key.encryption_scheme_type(),
            self.signing_schemes(),
        );
        let decrypted_signcryption = ecdsa_v0::inner_unsigncrypt(self, dsep, &parsed_signcryption)?;
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
    use crate::cryptography::{
        encryption::{Encryption, PkeScheme, PkeSchemeType},
        signatures::gen_sig_keys,
    };
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

    fn test_setup_with_scheme(scheme: PkeSchemeType) -> (AesRng, UnifiedSigncryptionKeyPairOwned) {
        let mut rng = AesRng::seed_from_u64(1);
        let (client_verf_key, _) = gen_sig_keys(&mut rng);
        let (server_verf_key, server_sig_key) = gen_sig_keys(&mut rng);
        let mut encryption = Encryption::new(scheme, &mut rng);
        let (dec_key, enc_key) = encryption.keygen().unwrap();
        let receiver_id = client_verf_key.verf_key_id();
        let keys = UnifiedSigncryptionKeyPairOwned {
            signcrypt_key: UnifiedSigncryptionKeyOwned::new(
                server_sig_key,
                enc_key.clone(),
                receiver_id.clone(),
            ),
            unsigncryption_key: UnifiedUnsigncryptionKeyOwned::new(
                dec_key,
                enc_key,
                server_verf_key,
                receiver_id,
            ),
        };
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
        assert_eq!(cipher.pke_type, PkeSchemeType::MlKem512);
        let decrypted_msg = client_signcryption_keys
            .unsigncryption_key
            .unsigncrypt(b"TESTTEST", &cipher)
            .unwrap();
        assert_eq!(msg, decrypted_msg);
    }

    #[test]
    fn sunshine_mlkem1024_p384() {
        let (mut rng, keys) = test_setup_with_scheme(PkeSchemeType::MlKem1024P384);
        let msg = TestType { i: 1333 };
        let cipher = keys
            .signcrypt_key
            .signcrypt(&mut rng, b"TESTTEST", &msg)
            .unwrap();
        assert_eq!(cipher.pke_type, PkeSchemeType::MlKem1024P384);

        let decrypted_msg = keys
            .unsigncryption_key
            .unsigncrypt(b"TESTTEST", &cipher)
            .unwrap();
        assert_eq!(msg, decrypted_msg);
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

        let serialized_server_verf_key =
            bc2wrap::serialize(&client_signcryption_keys.unsigncryption_key.sender_verf_key)
                .unwrap();
        let deserialized_server_verf_key: PublicSigKey =
            bc2wrap::deserialize_slice(&serialized_server_verf_key).unwrap();
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
                Some(&client_signcryption_keys.signcrypt_key.signing_key),
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
                &client_signcryption_keys.unsigncryption_key.decryption_key,
                &client_signcryption_keys.unsigncryption_key.encryption_key,
                &wrong_verf_key,
                &client_signcryption_keys.unsigncryption_key.receiver_id,
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

    /// Everything produced by the pre-composite path must be tagged with the
    /// singleton ECDSA set, because that is what keeps it on the frozen layout.
    #[test]
    fn the_legacy_path_produces_the_ecdsa_singleton() {
        let (mut rng, keys) = test_setup();
        let expected = SigningSchemeSet::single(SigningSchemeType::Ecdsa256k1);

        let cipher = keys
            .signcrypt_key
            .signcrypt(&mut rng, b"TESTTEST", &TestType { i: 7 })
            .unwrap();
        assert_eq!(cipher.signing_schemes, expected);
        assert_eq!(
            cipher.sole_signing_scheme(),
            Some(SigningSchemeType::Ecdsa256k1)
        );

        let plaintext_cipher = keys
            .signcrypt_key
            .signcrypt_plaintext(&mut rng, b"TESTTEST", &[1], FheTypes::Bool, &[9u8; 4])
            .unwrap();
        assert_eq!(plaintext_cipher.signing_schemes, expected);

        assert_eq!(keys.signcrypt_key.reference().signing_schemes(), expected);
        assert_eq!(
            keys.unsigncryption_key.reference().signing_schemes(),
            expected
        );
    }

    /// A signcryption claiming a composite scheme set must be refused rather
    /// than parsed as a legacy one. Until the composite envelope lands that is
    /// an "unsupported format" error; once it lands, the composite opener takes
    /// over and this must still never reach [`inner_unsigncrypt`].
    #[test]
    fn a_composite_scheme_set_does_not_reach_the_legacy_opener() {
        let (mut rng, keys) = test_setup();
        let mut cipher = keys
            .signcrypt_key
            .signcrypt(&mut rng, b"TESTTEST", &TestType { i: 11 })
            .unwrap();
        cipher.signing_schemes =
            SigningSchemeSet::new([SigningSchemeType::Ecdsa256k1, SigningSchemeType::MlDsa87])
                .unwrap();

        let err = keys
            .unsigncryption_key
            .unsigncrypt::<TestType>(b"TESTTEST", &cipher)
            .unwrap_err();
        assert!(
            matches!(err, CryptographyError::UnsupportedSigncryptionFormat(_)),
            "a composite tag must not be handled by the legacy opener: {err}"
        );
    }

    /// Material written before composite signing must still read, and must mean
    /// the same thing: one scheme, spelled as a set of one.
    #[test]
    fn v0_upgrades_to_the_singleton_set() {
        use strum::IntoEnumIterator;

        for scheme in SigningSchemeType::iter() {
            let v0 = UnifiedSigncryptionV0 {
                payload: vec![1, 2, 3],
                pke_type: PkeSchemeType::MlKem512,
                signing_type: scheme,
            };
            let upgraded = v0.clone().upgrade().unwrap();
            assert_eq!(upgraded.payload, v0.payload);
            assert_eq!(upgraded.pke_type, v0.pke_type);
            assert_eq!(upgraded.signing_schemes, SigningSchemeSet::single(scheme));
            assert_eq!(upgraded.sole_signing_scheme(), Some(scheme));

            // The upgrade is exactly what the singleton constructor builds, so a
            // regenerated artifact still compares equal to a frozen one.
            assert_eq!(
                upgraded,
                UnifiedSigncryption::new(v0.payload, v0.pke_type, SigningSchemeSet::single(scheme))
            );
        }
    }

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

use crate::consts::{DEFAULT_PARAM, SAFE_SER_SIZE_LIMIT, SIG_SIZE, TEST_PARAM};
use crate::cryptography::error::CryptographyError;
use crate::cryptography::hybrid_ml_kem::{self, HybridKemCt};
use crate::cryptography::signcryption::SigncryptionPayload;
use aes_prng::AesRng;
use k256::ecdsa::{SigningKey, VerifyingKey};
use kms_grpc::kms::v1::FheParameter;
use kms_grpc::kms::v1::OperatorBackupOutput;
use kms_grpc::rpc_types::PrivDataType;
use kms_grpc::RequestId;
use ml_kem::{EncodedSizeUser, KemCore, MlKem1024, MlKem512};
use nom::AsBytes;
use rand::{CryptoRng, RngCore, SeedableRng};
use serde::de::{DeserializeOwned, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::sync::Arc;
use strum::Display;
use tfhe::named::Named;
use tfhe::safe_serialization::safe_deserialize;
use tfhe::FheTypes;
use tfhe_versionable::{Versionize, VersionsDispatch};
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use threshold_fhe::hashing::DomainSep;
use wasm_bindgen::prelude::wasm_bindgen;
use zeroize::Zeroize;

#[macro_export]
macro_rules! impl_generic_versionize {
    ($t:ty) => {
        impl tfhe_versionable::Versionize for $t {
            type Versioned<'vers> = &'vers $t;

            fn versionize(&self) -> Self::Versioned<'_> {
                self
            }
        }

        impl tfhe_versionable::VersionizeOwned for $t {
            type VersionedOwned = $t;
            fn versionize_owned(self) -> Self::VersionedOwned {
                self
            }
        }

        impl tfhe_versionable::Unversionize for $t {
            fn unversionize(
                versioned: Self::VersionedOwned,
            ) -> Result<Self, tfhe_versionable::UnversionizeError> {
                Ok(versioned)
            }
        }

        impl tfhe_versionable::NotVersioned for $t {}
    };
}

/// Trait to help handling difficult cases of legacy serialization and deserialization
/// where versioning was not originally in play on the underlying type.
pub trait LegacySerialization {
    /// Serializes data of old types using bincode, and data of new types using safe serialization
    /// Be careful if you start using old types with safe serialization as this will break compatibility
    fn to_legacy_bytes(&self) -> Result<Vec<u8>, CryptographyError>;
    /// Deserializes data of old types using bincode, and data of new types using safe deserialization
    fn from_legacy_bytes(bytes: &[u8]) -> Result<Self, CryptographyError>
    where
        Self: Sized;
}

#[derive(Clone, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum UnifiedPublicEncKeyVersioned {
    V0(UnifiedPublicEncKey),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(UnifiedPublicEncKeyVersioned)]
#[expect(clippy::large_enum_variant)]
pub enum UnifiedPublicEncKey {
    MlKem512(PublicEncKey<ml_kem::MlKem512>),
    // LEGACY: Note that this should ONLY be used for legacy reasons, new code should use MlKem512.
    // If used in current code, then take care to NOT use to_legacy_bytes or from_legacy_bytes on this variant
    // as this will do bincode serialization instead of safe serialization
    MlKem1024(PublicEncKey<ml_kem::MlKem1024>),
}

impl Zeroize for UnifiedPublicEncKey {
    fn zeroize(&mut self) {
        // Don't do anything, public key is not secret, but method is needed for types using both this and private keys
    }
}

impl tfhe::named::Named for UnifiedPublicEncKey {
    const NAME: &'static str = "UnifiedPublicEncKey";
}

impl HasEncryptionScheme for UnifiedPublicEncKey {
    fn encryption_scheme_type(&self) -> EncryptionSchemeType {
        match self {
            UnifiedPublicEncKey::MlKem512(_) => EncryptionSchemeType::MlKem512,
            UnifiedPublicEncKey::MlKem1024(_) => EncryptionSchemeType::MlKem1024,
        }
    }
}

// LEGACY: Remove once it is no longer needed
impl LegacySerialization for UnifiedPublicEncKey {
    fn to_legacy_bytes(&self) -> Result<Vec<u8>, CryptographyError> {
        match self {
            UnifiedPublicEncKey::MlKem512(user_pk) => {
                let mut enc_key_buf = Vec::new();
                tfhe::safe_serialization::safe_serialize(
                    &UnifiedPublicEncKey::MlKem512(user_pk.clone()),
                    &mut enc_key_buf,
                    SAFE_SER_SIZE_LIMIT,
                )
                .map_err(|e| CryptographyError::BincodeError(e.to_string()))?;
                Ok(enc_key_buf)
            }
            // LEGACY: The following bincode serialization is done to be backward compatible
            // with the old serialization format, used in relayer-sdk v0.2.0-0 and older (tkms v0.11.0-rc20 and older).
            // It should be replaced with safe serialization (as above) in the future.
            UnifiedPublicEncKey::MlKem1024(user_pk) => {
                bc2wrap::serialize(user_pk).map_err(CryptographyError::BincodeEncodeError)
            }
        }
    }

    fn from_legacy_bytes(bytes: &[u8]) -> Result<Self, CryptographyError> {
        // LEGACY CODE: we used to only support ML-KEM1024 encoded with bincode
        // NOTE: we need to do some backward compatibility support here so
        // first try to deserialize it using the old format (ML-KEM1024 encoded with bincode)

        match bc2wrap::deserialize::<PublicEncKey<ml_kem::MlKem1024>>(bytes) {
            Ok(inner) => {
                // we got an old MlKem1024 public key, wrap it in the enum
                tracing::warn!("🔒 Using MlKem1024 public encryption key");
                Ok(UnifiedPublicEncKey::MlKem1024(inner))
            }
            // in case the old deserialization fails, try the new format
            Err(_) => tfhe::safe_serialization::safe_deserialize::<UnifiedPublicEncKey>(
                std::io::Cursor::new(&bytes),
                crate::consts::SAFE_SER_SIZE_LIMIT,
            )
            .map_err(|e| CryptographyError::DeserializationError(e.to_string())),
        }
    }
}

impl UnifiedPublicEncKey {
    /// Expect the inner type to be the default MlKem512 and return it, otherwise panic
    pub fn unwrap_ml_kem_512(self) -> PublicEncKey<ml_kem::MlKem512> {
        match self {
            UnifiedPublicEncKey::MlKem512(pk) => pk,
            _ => panic!("Expected MlKem512 public encryption key"),
        }
    }
}

// Alias wrapping the ephemeral public encryption key the user's wallet constructs and the server
// uses to encrypt its payload
// The only reason this format is not private is that it is needed to handle the legacy case, as we do this by distinguishing between 512 and 1024 bit keys
pub struct PublicEncKey<C: KemCore>(pub(crate) C::EncapsulationKey);

impl<C: KemCore> Eq for PublicEncKey<C> {}
impl<C: KemCore> PartialEq for PublicEncKey<C> {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_bytes().as_bytes() == other.0.as_bytes().as_bytes()
    }
}

impl<C: KemCore> Serialize for PublicEncKey<C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.as_bytes())
    }
}

impl<C: KemCore> Named for PublicEncKey<C> {
    const NAME: &'static str = "PublicEncKey";
}

/// workaround because clone doesn't get derived for this type
impl<C: KemCore> Clone for PublicEncKey<C> {
    fn clone(&self) -> Self {
        let buf = self.0.as_bytes();
        PublicEncKey(C::EncapsulationKey::from_bytes(&buf))
    }
}

impl<C: KemCore> std::fmt::Debug for PublicEncKey<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicEncKey")
            .field("encapsulation_key", &self.0.as_bytes())
            .finish()
    }
}

impl<C: KemCore> tfhe_versionable::Versionize for PublicEncKey<C> {
    type Versioned<'vers>
        = &'vers PublicEncKey<C>
    where
        C: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        self
    }
}

impl<C: KemCore> tfhe_versionable::VersionizeOwned for PublicEncKey<C> {
    type VersionedOwned = PublicEncKey<C>;
    fn versionize_owned(self) -> Self::VersionedOwned {
        self
    }
}

impl<C: KemCore> tfhe_versionable::Unversionize for PublicEncKey<C> {
    fn unversionize(
        versioned: Self::VersionedOwned,
    ) -> Result<Self, tfhe_versionable::UnversionizeError> {
        Ok(versioned)
    }
}

impl<C: KemCore> tfhe_versionable::NotVersioned for PublicEncKey<C> {}

impl<'de, C: KemCore> Deserialize<'de> for PublicEncKey<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_bytes(PublicEncKeyVisitor::<C>(std::marker::PhantomData))
    }
}

struct PublicEncKeyVisitor<C: KemCore>(std::marker::PhantomData<C>);
impl<C: KemCore> Visitor<'_> for PublicEncKeyVisitor<C> {
    type Value = PublicEncKey<C>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("A ML-KEM Encapsulation key")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let array = match v.try_into() {
            Ok(array) => array,
            Err(_) => {
                let msg = "ML-KEM Public Enc Key Byte array of incorrect length";
                return Err(serde::de::Error::custom(msg));
            }
        };
        let ek = C::EncapsulationKey::from_bytes(array);
        Ok(PublicEncKey(ek))
    }
}

/// Trait to add to an object that allows encryption
/// The type T is the type of the message to be encrypted
/// It is enforced that T must implement Versionize and be Named
/// in order to prevent missing versioning of encrypted data.
pub trait Encrypt {
    /// Encrypt a message of type T using a given randomness generator
    fn encrypt<T: Serialize + tfhe::Versionize + tfhe::named::Named>(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        msg: &T,
    ) -> Result<UnifiedCipher, CryptographyError>;
}

impl Encrypt for UnifiedPublicEncKey {
    #[allow(unknown_lints)]
    // We allow modifying the rng before an error return
    #[allow(non_local_effect_before_error_return)]
    fn encrypt<T: Serialize + tfhe::Versionize + tfhe::named::Named>(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        msg: &T,
    ) -> Result<UnifiedCipher, CryptographyError> {
        let mut serialized_msg = Vec::new();
        tfhe::safe_serialization::safe_serialize(msg, &mut serialized_msg, SAFE_SER_SIZE_LIMIT)
            .map_err(|e| CryptographyError::DeserializationError(e.to_string()))?;
        let (inner_ct, scheme) = match self {
            UnifiedPublicEncKey::MlKem512(public_enc_key) => (
                hybrid_ml_kem::enc::<MlKem512, _>(rng, &serialized_msg, &public_enc_key.0)?,
                EncryptionSchemeType::MlKem512,
            ),
            UnifiedPublicEncKey::MlKem1024(public_enc_key) => (
                hybrid_ml_kem::enc::<MlKem1024, _>(rng, &serialized_msg, &public_enc_key.0)?,
                EncryptionSchemeType::MlKem1024,
            ),
        };
        let mut ct_buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(&inner_ct, &mut ct_buf, SAFE_SER_SIZE_LIMIT)
            .map_err(|e| CryptographyError::BincodeError(e.to_string()))?;
        Ok(UnifiedCipher::new(ct_buf, scheme))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, VersionsDispatch)]
pub enum UnifiedPrivateEncKeyVersioned {
    V0(UnifiedPrivateEncKey),
}

#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, Versionize)]
#[expect(clippy::large_enum_variant)]
#[versionize(UnifiedPrivateEncKeyVersioned)]
pub enum UnifiedPrivateEncKey {
    MlKem512(PrivateEncKey<ml_kem::MlKem512>),
    MlKem1024(PrivateEncKey<ml_kem::MlKem1024>),
    // WARNING: Do not modify the order of the variants or remove any variant as this will break deserialization of existing keys!
    // Only acceptable if you make a new version
}

impl tfhe::named::Named for UnifiedPrivateEncKey {
    const NAME: &'static str = "UnifiedPrivateDecKey";
}

impl From<UnifiedPrivateEncKey> for EncryptionSchemeType {
    fn from(value: UnifiedPrivateEncKey) -> Self {
        match value {
            UnifiedPrivateEncKey::MlKem512(_) => EncryptionSchemeType::MlKem512,
            UnifiedPrivateEncKey::MlKem1024(_) => EncryptionSchemeType::MlKem1024,
        }
    }
}
impl From<&UnifiedPrivateEncKey> for EncryptionSchemeType {
    fn from(value: &UnifiedPrivateEncKey) -> Self {
        match value {
            UnifiedPrivateEncKey::MlKem512(_) => EncryptionSchemeType::MlKem512,
            UnifiedPrivateEncKey::MlKem1024(_) => EncryptionSchemeType::MlKem1024,
        }
    }
}

impl UnifiedPrivateEncKey {
    /// Expect the inner type to be the default MlKem512 and return it, otherwise panic
    pub fn unwrap_ml_kem_512(self) -> PrivateEncKey<ml_kem::MlKem512> {
        match self {
            UnifiedPrivateEncKey::MlKem512(pk) => pk,
            _ => panic!("Expected MlKem512 private encryption key"),
        }
    }
}

impl HasEncryptionScheme for UnifiedPrivateEncKey {
    fn encryption_scheme_type(&self) -> EncryptionSchemeType {
        match self {
            UnifiedPrivateEncKey::MlKem512(_) => EncryptionSchemeType::MlKem512,
            UnifiedPrivateEncKey::MlKem1024(_) => EncryptionSchemeType::MlKem1024,
        }
    }
}

// Alias wrapping the ephemeral private decryption key the user's wallet constructs to receive the
// server's encrypted payload
// The only reason this format is not private is that it is needed to handle the legacy case, as we do this by distinguishing between 512 and 1024 bit keys
pub struct PrivateEncKey<C: KemCore>(pub(crate) C::DecapsulationKey);

impl<C: KemCore> Zeroize for PrivateEncKey<C> {
    fn zeroize(&mut self) {
        // Directly zeroize the underlying key bytes without creating copies
        // This is more secure as it avoids temporary allocations of sensitive data
        let key_bytes_ptr = self.0.as_bytes().as_ptr() as *mut u8;
        let key_len = self.0.as_bytes().len();

        // SAFETY: We're zeroizing the memory that belongs to this struct
        // The pointer is valid and the length is correct from as_bytes()
        unsafe {
            std::ptr::write_bytes(key_bytes_ptr, 0, key_len);
        }
    }
}

impl<C: KemCore> Drop for PrivateEncKey<C> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<C: KemCore> Clone for PrivateEncKey<C> {
    fn clone(&self) -> Self {
        let buf = self.0.as_bytes();
        PrivateEncKey(C::DecapsulationKey::from_bytes(&buf))
    }
}

impl<C: KemCore> std::fmt::Debug for PrivateEncKey<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateEncKey")
            .field("decapsulation_key", &"ommitted")
            .finish()
    }
}

impl<C: KemCore> tfhe_versionable::Versionize for PrivateEncKey<C> {
    type Versioned<'vers>
        = &'vers PrivateEncKey<C>
    where
        C: 'vers;

    fn versionize(&self) -> Self::Versioned<'_> {
        self
    }
}

impl<C: KemCore> tfhe_versionable::VersionizeOwned for PrivateEncKey<C> {
    type VersionedOwned = PrivateEncKey<C>;
    fn versionize_owned(self) -> Self::VersionedOwned {
        self
    }
}

impl<C: KemCore> tfhe_versionable::Unversionize for PrivateEncKey<C> {
    fn unversionize(
        versioned: Self::VersionedOwned,
    ) -> Result<Self, tfhe_versionable::UnversionizeError> {
        Ok(versioned)
    }
}

impl<C: KemCore> Serialize for PrivateEncKey<C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.as_bytes())
    }
}

impl<'de, C: KemCore> Deserialize<'de> for PrivateEncKey<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(PrivateEncKeyVisitor::<C>(std::marker::PhantomData))
    }
}

struct PrivateEncKeyVisitor<C: KemCore>(std::marker::PhantomData<C>);
impl<C: KemCore> Visitor<'_> for PrivateEncKeyVisitor<C> {
    type Value = PrivateEncKey<C>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("A ML-KEM decapsulation key")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let array = match v.try_into() {
            Ok(array) => array,
            Err(_) => {
                let msg = "ML-KEM Private Enc Key Byte array of incorrect length";
                return Err(serde::de::Error::custom(msg));
            }
        };
        let dk = C::DecapsulationKey::from_bytes(array);
        Ok(PrivateEncKey(dk))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum BackupCiphertextVersioned {
    V0(BackupCiphertext),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(BackupCiphertextVersioned)]
pub struct BackupCiphertext {
    pub ciphertext: UnifiedCipher,
    pub priv_data_type: PrivDataType,
    pub backup_id: RequestId,
}

impl Named for BackupCiphertext {
    const NAME: &'static str = "cryptography::BackupCiphertext";
}

/// Trait to add to an object that allows decryption
/// The type T is the type of the plaintext to be decrypted
/// It is enforced that T must implement Unversionize and be Named
/// in order to prevent missing versioning of en/decrypted data.
pub trait Decrypt {
    /// Decrypt a ciphertext of type UnifiedCipher into a plaintext of type T
    fn decrypt<T: serde::de::DeserializeOwned + tfhe::Unversionize + tfhe::named::Named>(
        &self,
        cipher: &UnifiedCipher,
    ) -> Result<T, CryptographyError>;
}

impl Decrypt for UnifiedPrivateEncKey {
    fn decrypt<T: serde::de::DeserializeOwned + tfhe::Unversionize + tfhe::named::Named>(
        &self,
        cipher: &UnifiedCipher,
    ) -> Result<T, CryptographyError> {
        let mut cipher_buf: std::io::Cursor<&Vec<u8>> = std::io::Cursor::new(&cipher.cipher);
        let inner_ct: HybridKemCt = safe_deserialize(&mut cipher_buf, SAFE_SER_SIZE_LIMIT)
            .map_err(CryptographyError::DeserializationError)?;
        let raw_plaintext = match self {
            UnifiedPrivateEncKey::MlKem512(private_enc_key) => {
                hybrid_ml_kem::dec::<MlKem512>(inner_ct, &private_enc_key.0)?
            }
            UnifiedPrivateEncKey::MlKem1024(private_enc_key) => {
                hybrid_ml_kem::dec::<MlKem1024>(inner_ct, &private_enc_key.0)?
            }
        };
        let mut res_buf = std::io::Cursor::new(raw_plaintext);
        safe_deserialize(&mut res_buf, SAFE_SER_SIZE_LIMIT)
            .map_err(CryptographyError::DeserializationError)
    }
}

pub trait HasEncryptionScheme {
    fn encryption_scheme_type(&self) -> EncryptionSchemeType;
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum EncryptionSchemeTypeVersioned {
    V0(EncryptionSchemeType),
}

// TODO(#2782) separate into signature and encryption files
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Display, Versionize)]
#[versionize(EncryptionSchemeTypeVersioned)]
pub enum EncryptionSchemeType {
    MlKem512,
    #[deprecated(
        since = "0.12.0",
        note = "Use MlKem512 instead. MlKem1024 is only for legacy compatibility with relayer-sdk v0.2.0-0 and older."
    )]
    MlKem1024,
}

// Observe that since we serialize this enum, we need to implement a separate variant to keep it versioned properly
impl From<kms_grpc::kms::v1::EncryptionSchemeType> for EncryptionSchemeType {
    fn from(value: kms_grpc::kms::v1::EncryptionSchemeType) -> Self {
        // Map the gRPC enum to your local enum
        match value {
            kms_grpc::kms::v1::EncryptionSchemeType::Mlkem512 => EncryptionSchemeType::MlKem512,
            kms_grpc::kms::v1::EncryptionSchemeType::Mlkem1024 => EncryptionSchemeType::MlKem1024,
        }
    }
}

impl TryFrom<i32> for EncryptionSchemeType {
    type Error = anyhow::Error;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(EncryptionSchemeType::MlKem512),
            1 => Ok(EncryptionSchemeType::MlKem1024),
            // Future encryption schemes can be added here
            _ => Err(anyhow::anyhow!(
                "Unsupported EncryptionSchemeType: {:?}",
                value
            )),
        }
    }
}
pub trait EncryptionScheme: Send + Sync {
    /// Return the type of encryption scheme used by this instance
    fn scheme_type(&self) -> EncryptionSchemeType;
    /// Generate a new keypair for this encryption scheme
    fn keygen(&mut self) -> Result<(UnifiedPrivateEncKey, UnifiedPublicEncKey), CryptographyError>;
}

pub struct Encryption<'a, R: CryptoRng + RngCore + Send + Sync> {
    scheme_type: EncryptionSchemeType,
    rng: &'a mut R,
}

impl<'a, R: CryptoRng + RngCore + Send + Sync> Encryption<'a, R> {
    pub fn new(scheme_type: EncryptionSchemeType, rng: &'a mut R) -> Self {
        Self { scheme_type, rng }
    }
}

impl<'a, R: CryptoRng + RngCore + Send + Sync> EncryptionScheme for Encryption<'a, R> {
    fn scheme_type(&self) -> EncryptionSchemeType {
        self.scheme_type
    }

    fn keygen(&mut self) -> Result<(UnifiedPrivateEncKey, UnifiedPublicEncKey), CryptographyError> {
        let (sk, pk) = match self.scheme_type {
            EncryptionSchemeType::MlKem512 => {
                let (decapsulation_key, encapsulation_key) =
                    hybrid_ml_kem::keygen::<ml_kem::MlKem512, _>(&mut self.rng);
                (
                    UnifiedPrivateEncKey::MlKem512(PrivateEncKey(decapsulation_key)),
                    UnifiedPublicEncKey::MlKem512(PublicEncKey(encapsulation_key)),
                )
            }
            EncryptionSchemeType::MlKem1024 => {
                let (decapsulation_key, encapsulation_key) =
                    hybrid_ml_kem::keygen::<ml_kem::MlKem1024, _>(&mut self.rng);
                (
                    UnifiedPrivateEncKey::MlKem1024(PrivateEncKey(decapsulation_key)),
                    UnifiedPublicEncKey::MlKem1024(PublicEncKey(encapsulation_key)),
                )
            }
        };
        Ok((sk, pk))
    }
}

pub fn gen_sig_keys<R: rand::CryptoRng + rand::Rng>(rng: &mut R) -> (PublicSigKey, PrivateSigKey) {
    use k256::ecdsa::SigningKey;

    let sk = SigningKey::random(rng);
    let pk = SigningKey::verifying_key(&sk);
    (PublicSigKey::new(*pk), PrivateSigKey::new(sk))
}

pub trait HasSigningScheme {
    fn signing_scheme_type(&self) -> SigningSchemeType;
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum SigningSchemeTypeVersioned {
    V0(SigningSchemeType),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Display, Versionize)]
#[versionize(SigningSchemeTypeVersioned)]
pub enum SigningSchemeType {
    Ecdsa256k1,
    // Eventually we will support post quantum signatures as well
}

impl From<kms_grpc::kms::v1::SigningSchemeType> for SigningSchemeType {
    fn from(value: kms_grpc::kms::v1::SigningSchemeType) -> Self {
        // Map the gRPC enum to your local enum
        match value {
            kms_grpc::kms::v1::SigningSchemeType::Ecdsa256k1 => SigningSchemeType::Ecdsa256k1,
        }
    }
}
impl TryFrom<i32> for SigningSchemeType {
    type Error = anyhow::Error;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SigningSchemeType::Ecdsa256k1),
            // Future signing schemes can be added here
            _ => Err(anyhow::anyhow!(
                "Unsupported SigningSchemeType: {:?}",
                value
            )),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum PublicSigKeyVersioned {
    V0(PublicSigKey),
}

// Struct wrapping signature verification key used by both the user's wallet and server
#[wasm_bindgen]
#[derive(Clone, PartialEq, Eq, Debug, Hash, Serialize, Deserialize, Versionize)]
#[versionize(PublicSigKeyVersioned)]
pub struct PublicSigKey {
    pk: WrappedVerifyingKey,
}
impl Zeroize for PublicSigKey {
    fn zeroize(&mut self) {
        // Don't do anything, public key is not secret, but method is needed for types using both this and private keys
    }
}

impl Named for PublicSigKey {
    const NAME: &'static str = "PublicSigKey";
}

impl PublicSigKey {
    pub fn new(pk: k256::ecdsa::VerifyingKey) -> Self {
        Self {
            pk: WrappedVerifyingKey(pk),
        }
    }

    /// Return a concise identifier for this verification key. For ECDSA keys, this is the Ethereum address.
    pub fn verf_key_id(&self) -> Vec<u8> {
        // Let the ID of both a normal ecdsa256k1 key and an eip712 key be the Ethereum address
        let addr = alloy_primitives::Address::from_public_key(self.pk());
        addr.to_vec()
    }

    /// DEPRECATED LEGACY code since this is not the right way to serialize as it is not versioned
    pub fn get_serialized_verf_key(&self) -> anyhow::Result<Vec<u8>> {
        let serialized_verf_key = bc2wrap::serialize(&PublicSigKey::new(self.pk().to_owned()))?;
        Ok(serialized_verf_key)
    }

    pub fn from_sk(sk: &PrivateSigKey) -> Self {
        let pk = SigningKey::verifying_key(&sk.sk.0).to_owned();
        PublicSigKey {
            pk: WrappedVerifyingKey(pk),
        }
    }

    pub fn pk(&self) -> &k256::ecdsa::VerifyingKey {
        &self.pk.0
    }
}

impl HasSigningScheme for PublicSigKey {
    fn signing_scheme_type(&self) -> SigningSchemeType {
        // Only one scheme for now
        SigningSchemeType::Ecdsa256k1
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct WrappedVerifyingKey(k256::ecdsa::VerifyingKey);
impl_generic_versionize!(WrappedVerifyingKey);

/// Serialize the public key as a SEC1 point, which is what is used in Ethereum
impl Serialize for WrappedVerifyingKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.0.to_sec1_bytes().as_bytes())
    }
}

impl<'de> Deserialize<'de> for WrappedVerifyingKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_bytes(PublicSigKeyVisitor)
    }
}
impl std::hash::Hash for WrappedVerifyingKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.to_sec1_bytes().hash(state);
    }
}

impl From<PrivateSigKey> for PublicSigKey {
    fn from(value: PrivateSigKey) -> Self {
        let pk = SigningKey::verifying_key(&value.sk.0).to_owned();
        PublicSigKey {
            pk: WrappedVerifyingKey(pk),
        }
    }
}
impl From<Arc<PrivateSigKey>> for PublicSigKey {
    fn from(value: Arc<PrivateSigKey>) -> Self {
        let pk = SigningKey::verifying_key(&value.sk.0).to_owned();
        PublicSigKey {
            pk: WrappedVerifyingKey(pk),
        }
    }
}

struct PublicSigKeyVisitor;
impl Visitor<'_> for PublicSigKeyVisitor {
    type Value = WrappedVerifyingKey;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("A public verification key for ECDSA signatures using secp256k1")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match VerifyingKey::from_sec1_bytes(v) {
            Ok(pk) => Ok(WrappedVerifyingKey(pk)),
            Err(e) => Err(E::custom(format!(
                "Could not decode verification key: {e:?}"
            ))),
        }
    }
}
// Drop manually implemented due to conflict with Versionize macro
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Zeroize, VersionsDispatch)]
pub enum PrivateSigKeyVersioned {
    V0(PrivateSigKey),
}
// TODO(#2781) should eventually be replaced or consolidated with the UnifiedPrivateSigningKey
// Struct wrapping signature signing key used by both the client and server to authenticate their
// messages to one another
#[wasm_bindgen]
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Zeroize, Versionize)]
#[versionize(PrivateSigKeyVersioned)]
pub struct PrivateSigKey {
    sk: WrappedSigningKey,
}

impl Named for PrivateSigKey {
    const NAME: &'static str = "PrivateSigKey";
}

impl PrivateSigKey {
    pub fn new(sk: k256::ecdsa::SigningKey) -> Self {
        Self {
            sk: WrappedSigningKey(sk),
        }
    }

    /// TODO(#2781) DEPRECATED: code should be refactored to not use this outside on this class
    pub fn sk(&self) -> &k256::ecdsa::SigningKey {
        &self.sk.0
    }

    pub fn verf_key(&self) -> PublicSigKey {
        PublicSigKey::from_sk(self)
    }

    /// Return a concise identifier for this signing key. For ECDSA keys, this is the Ethereum address.
    pub fn signing_key_id(&self) -> Vec<u8> {
        // Let the ID of both a normal ecdsa256k1 key and an eip712 key be the Ethereum address
        let addr = alloy_primitives::Address::from_private_key(self.sk());
        addr.as_bytes().to_vec()
    }
}

impl HasSigningScheme for PrivateSigKey {
    fn signing_scheme_type(&self) -> SigningSchemeType {
        // Only one scheme for now
        SigningSchemeType::Ecdsa256k1
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct WrappedSigningKey(k256::ecdsa::SigningKey);
impl_generic_versionize!(WrappedSigningKey);

impl Zeroize for WrappedSigningKey {
    // We want to allow unused assignments here as we are intentionally overwriting the key material
    #[warn(unused_assignments)]
    fn zeroize(&mut self) {
        let mut rng = AesRng::seed_from_u64(0);
        // The simplest way is to overwrite the entire key with a random, static key, since we cannot directly zerorize the content of the key
        let (_pk, sk) = gen_sig_keys(&mut rng);
        // SAFETY: We're modifying a local copy of the key bytes, but this does not modify the actual key in memory.
        // To securely zeroize the key, use the Zeroize trait on the underlying scalar or key type if available.
        unsafe {
            std::ptr::write(self, sk.sk);
        }
    }
}

impl Drop for WrappedSigningKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Serialize for WrappedSigningKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(self.0.to_bytes().as_bytes())
    }
}
impl<'de> Deserialize<'de> for WrappedSigningKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_bytes(PrivateSigKeyVisitor)
    }
}

struct PrivateSigKeyVisitor;
impl Visitor<'_> for PrivateSigKeyVisitor {
    type Value = WrappedSigningKey;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("A public verification key for ECDSA signatures using secp256k1")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        match k256::ecdsa::SigningKey::from_bytes(v.into()) {
            Ok(sk) => Ok(WrappedSigningKey(sk)),
            Err(e) => Err(E::custom(format!("Could not decode signing key: {e:?}"))),
        }
    }
}
// Type used for the signcrypted payload returned by a server
#[derive(Clone, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum UnifiedCipherVersioned {
    V0(UnifiedCipher),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(UnifiedCipherVersioned)]
pub struct UnifiedCipher {
    // The safe_serialization of the ciphertext specified by the encryption_type
    pub cipher: Vec<u8>,
    pub encryption_type: EncryptionSchemeType,
}

impl Named for UnifiedCipher {
    const NAME: &'static str = "signcryption::UnifiedCipher";
}

impl UnifiedCipher {
    pub fn new(cipher: Vec<u8>, encryption_type: EncryptionSchemeType) -> Self {
        Self {
            cipher,
            encryption_type,
        }
    }
}

pub trait Signcrypt {
    /// Signcrypt a message of type T with a specified domain separator.
    fn signcrypt<T: Serialize + tfhe::Versionize + tfhe::named::Named>(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        dsep: &DomainSep,
        msg: &T,
    ) -> Result<UnifiedSigncryption, CryptographyError>;
}

pub trait Designcrypt {
    /// Decrypt a signcrypted message and verify the signature before returning the result.
    /// If the signature verification fails, an error is returned.
    ///
    /// This fn also checks that the provided link parameter corresponds to the link in the signcryption
    /// payload.
    fn designcrypt<T: DeserializeOwned + tfhe::Unversionize + tfhe::named::Named>(
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

pub trait DesigncryptFHEPlaintext: Designcrypt {
    /// Decrypt a signcrypted plaintext message and verify the signature before returning the result.
    /// If the signature verification fails, an error is returned.
    /// The link parameter is used to verify that the signcryption corresponds to the expected context or session.
    /// The method is exclusively used to decrypt partially decrypted FHE ciphertexts for user decryption.
    fn designcrypt_plaintext(
        &self,
        dsep: &DomainSep,
        signcryption: &[u8],
        link: &[u8],
    ) -> Result<SigncryptionPayload, CryptographyError>;
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum UnifiedSigncryptionVersioned {
    V0(UnifiedSigncryption),
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Versionize)]
#[versionize(UnifiedSigncryptionVersioned)]
pub struct UnifiedSigncryption {
    pub payload: Vec<u8>,
    pub encryption_type: EncryptionSchemeType, // TODO do we need any future validation for downgrade attacks, and is it fine to fail if meta data is incorrect? (Should be)
    pub signing_type: SigningSchemeType,
}
impl UnifiedSigncryption {
    pub fn new(
        payload: Vec<u8>,
        encryption_type: EncryptionSchemeType,
        signing_type: SigningSchemeType,
    ) -> Self {
        Self {
            payload,
            encryption_type,
            signing_type,
        }
    }
}

impl TryFrom<OperatorBackupOutput> for UnifiedSigncryption {
    type Error = anyhow::Error;

    fn try_from(value: OperatorBackupOutput) -> Result<Self, Self::Error> {
        let encryption_type = value.encryption_type().into();
        let signing_type = value.signing_type().into();
        Ok(UnifiedSigncryption::new(
            value.signcryption,
            encryption_type,
            signing_type,
        ))
    }
}

impl TryFrom<&OperatorBackupOutput> for UnifiedSigncryption {
    type Error = anyhow::Error;

    fn try_from(value: &OperatorBackupOutput) -> Result<Self, Self::Error> {
        let encryption_type = value.encryption_type.try_into()?;
        let signing_type = value.signing_type.try_into()?;
        Ok(UnifiedSigncryption::new(
            value.signcryption.clone(),
            encryption_type,
            signing_type,
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, VersionsDispatch)]
pub enum UnifiedSigncryptionKeyVersioned {
    V0(UnifiedSigncryptionKey),
}

#[derive(Clone, Serialize, Deserialize, Debug, Versionize)]
#[versionize(UnifiedSigncryptionKeyVersioned)]
pub struct UnifiedSigncryptionKey {
    pub signing_key: PrivateSigKey,
    pub receiver_enc_key: UnifiedPublicEncKey,
    pub receiver_id: Vec<u8>, // Identifier for the receiver's encryption key, e.g. blockchain address
}
// TODO implement and use reference toyes where possible

impl Zeroize for UnifiedSigncryptionKey {
    fn zeroize(&mut self) {
        self.signing_key.zeroize();
        // receiver_enc_key and receiver_id are public, no need to zeroize
    }
}

impl UnifiedSigncryptionKey {
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
}

impl HasEncryptionScheme for UnifiedSigncryptionKey {
    fn encryption_scheme_type(&self) -> EncryptionSchemeType {
        self.receiver_enc_key.encryption_scheme_type()
    }
}
impl HasSigningScheme for UnifiedSigncryptionKey {
    fn signing_scheme_type(&self) -> SigningSchemeType {
        self.signing_key.signing_scheme_type()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, VersionsDispatch)]
pub enum UnifiedDesigncryptionKeyVersioned {
    V0(UnifiedDesigncryptionKey),
}

#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, Versionize)]
#[versionize(UnifiedDesigncryptionKeyVersioned)]
pub struct UnifiedDesigncryptionKey {
    pub decryption_key: UnifiedPrivateEncKey,
    pub encryption_key: UnifiedPublicEncKey, // Needed for validation of the signcrypted payload
    pub sender_verf_key: PublicSigKey,
    /// The ID of the receiver of the signcryption, e.g. blockchain address
    pub receiver_id: Vec<u8>,
}

impl UnifiedDesigncryptionKey {
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

    //  TODO this file should be split up and this moved to signcryption
}

impl HasEncryptionScheme for UnifiedDesigncryptionKey {
    fn encryption_scheme_type(&self) -> EncryptionSchemeType {
        self.encryption_key.encryption_scheme_type()
    }
}

impl HasSigningScheme for UnifiedDesigncryptionKey {
    fn signing_scheme_type(&self) -> SigningSchemeType {
        self.sender_verf_key.signing_scheme_type()
    }
}
// TODO should just be for tests
/// Convinence type for efficiency
#[derive(Clone, Debug)]
pub struct UnifiedSigncryptionKeyPair<'a> {
    pub signcrypt_key: &'a UnifiedSigncryptionKey,
    pub designcryption_key: &'a UnifiedDesigncryptionKey,
}

impl HasEncryptionScheme for UnifiedSigncryptionKeyPair<'_> {
    fn encryption_scheme_type(&self) -> EncryptionSchemeType {
        self.signcrypt_key.encryption_scheme_type()
    }
}
impl HasSigningScheme for UnifiedSigncryptionKeyPair<'_> {
    fn signing_scheme_type(&self) -> SigningSchemeType {
        self.signcrypt_key.signing_scheme_type()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, VersionsDispatch)]
pub enum UnifiedSigncryptionKeyPairOwnedVersioned {
    V0(UnifiedSigncryptionKeyPairOwned),
}

#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, Versionize)]
#[versionize(UnifiedSigncryptionKeyPairOwnedVersioned)]
pub struct UnifiedSigncryptionKeyPairOwned {
    pub signcrypt_key: UnifiedSigncryptionKey,
    pub designcrypt_key: UnifiedDesigncryptionKey,
}

impl UnifiedSigncryptionKeyPairOwned {
    pub fn reference<'a>(&'a self) -> UnifiedSigncryptionKeyPair<'a> {
        UnifiedSigncryptionKeyPair {
            signcrypt_key: &self.signcrypt_key,
            designcryption_key: &self.designcrypt_key,
        }
    }
}

impl HasEncryptionScheme for UnifiedSigncryptionKeyPairOwned {
    fn encryption_scheme_type(&self) -> EncryptionSchemeType {
        self.designcrypt_key.encryption_scheme_type()
    }
}

impl HasSigningScheme for UnifiedSigncryptionKeyPairOwned {
    fn signing_scheme_type(&self) -> SigningSchemeType {
        self.designcrypt_key.signing_scheme_type()
    }
}

//TODO(#2781) should also be versionized
/// Wrapper struct for a digital signature
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signature {
    pub sig: k256::ecdsa::Signature,
}
/// Serialize a signature as a 64 bytes sequence of big endian bytes, consisting of r followed by s
impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut to_ser = Vec::new();
        to_ser.append(&mut self.sig.to_vec());
        serializer.serialize_bytes(&to_ser)
    }
}
impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(SignatureVisitor)
    }
}
struct SignatureVisitor;
impl Visitor<'_> for SignatureVisitor {
    type Value = Signature;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("A signature for ECDSA signatures using secp256k1")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let sig = match k256::ecdsa::Signature::from_slice(&v[0..SIG_SIZE]) {
            Ok(sig) => sig,
            Err(e) => Err(E::custom(format!("Could not decode signature: {e:?}")))?,
        };
        Ok(Signature { sig })
    }
}

/// This is a wrapper around [DKGParams] so that we can
/// implement [From<FheParameter>]. It has a [std::ops::Deref] implementation
/// which can be used for for converting from [FheParameter] to [DKGParams]
pub(crate) struct WrappedDKGParams(DKGParams);
impl From<FheParameter> for WrappedDKGParams {
    fn from(value: FheParameter) -> WrappedDKGParams {
        match value {
            FheParameter::Test => WrappedDKGParams(TEST_PARAM),
            FheParameter::Default => WrappedDKGParams(DEFAULT_PARAM),
        }
    }
}

impl std::ops::Deref for WrappedDKGParams {
    type Target = DKGParams;
    fn deref(&self) -> &DKGParams {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        consts::SAFE_SER_SIZE_LIMIT,
        cryptography::{
            error::CryptographyError,
            hybrid_ml_kem::{self, HybridKemCt},
            internal_crypto_types::{
                gen_sig_keys, Decrypt, Encrypt, Encryption, EncryptionScheme, EncryptionSchemeType,
                PrivateEncKey, PublicEncKey, UnifiedPrivateEncKey, UnifiedPublicEncKey,
            },
        },
        vault::storage::tests::TestType,
    };
    use aes_prng::AesRng;
    use rand::SeedableRng;
    use serde::{Deserialize, Serialize};
    use tokio_rustls::rustls::crypto::cipher::NONCE_LEN;
    use zeroize::Zeroize;

    #[test]
    fn nested_pke_sunshine() {
        let msg = TestType { i: 42 };
        let mut rng = AesRng::seed_from_u64(0);
        let mut enc = Encryption::new(EncryptionSchemeType::MlKem512, &mut rng);
        let (sk, pk) = enc.keygen().unwrap();

        let ct = pk.encrypt(&mut rng, &msg).unwrap();
        let pt = sk.decrypt(&ct).unwrap();
        assert_eq!(msg, pt);

        let mut pk_buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(&pk, &mut pk_buf, SAFE_SER_SIZE_LIMIT).unwrap();
        let pk2: UnifiedPublicEncKey = tfhe::safe_serialization::safe_deserialize(
            std::io::Cursor::new(pk_buf),
            SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();
        let ct2 = pk2.encrypt(&mut rng, &msg).unwrap();

        let mut sk_buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(&sk, &mut sk_buf, SAFE_SER_SIZE_LIMIT).unwrap();
        let sk2: UnifiedPrivateEncKey = tfhe::safe_serialization::safe_deserialize(
            std::io::Cursor::new(sk_buf),
            SAFE_SER_SIZE_LIMIT,
        )
        .unwrap();
        let pt2 = sk2.decrypt(&ct2).unwrap();
        assert_eq!(msg, pt2);
    }

    #[test]
    fn pke_wrong_kem_key() {
        let msg = TestType { i: 42 };
        let mut rng = AesRng::seed_from_u64(0);
        let mut enc = Encryption::new(EncryptionSchemeType::MlKem512, &mut rng);
        let (_sk_orig, pk) = enc.keygen().unwrap();
        let (sk, _pk) = enc.keygen().unwrap();

        let ct = pk.encrypt(&mut rng, &msg).unwrap();
        let err = sk.decrypt::<TestType>(&ct).unwrap_err();
        // We get an AesGcm error due to implicit rejection
        assert!(matches!(err, CryptographyError::AesGcmError(..)));
    }

    #[test]
    fn pke_wrong_ct() {
        let msg = TestType { i: 42 };
        let mut rng = AesRng::seed_from_u64(0);
        let mut enc = Encryption::new(EncryptionSchemeType::MlKem512, &mut rng);
        let (sk, pk) = enc.keygen().unwrap();
        let mut ct = pk.encrypt(&mut rng, &msg).unwrap();
        ct.cipher[0] ^= 1;
        let err = sk.decrypt::<TestType>(&ct).unwrap_err();
        assert!(matches!(err, CryptographyError::DeserializationError(..)));
    }

    #[test]
    fn test_pke_serialize_size() {
        let mut rng = AesRng::seed_from_u64(0);
        let mut encryption = Encryption::new(EncryptionSchemeType::MlKem512, &mut rng);
        let (sk, pk) = encryption.keygen().unwrap();
        let pk_buf = bc2wrap::serialize(&pk.unwrap_ml_kem_512()).unwrap();
        let sk_buf = bc2wrap::serialize(&sk.unwrap_ml_kem_512()).unwrap();
        // there is extra 8 bytes in the serialization to encode the length
        // see https://github.com/bincode-org/bincode/blob/trunk/docs/spec.md#linear-collections-vec-arrays-etc

        assert_eq!(sk_buf.len(), hybrid_ml_kem::ML_KEM_512_SK_LEN + 8);
        assert_eq!(pk_buf.len(), hybrid_ml_kem::ML_KEM_512_PK_LENGTH + 8);
        // deserialize and test if encryption still works.
        let pk2: PublicEncKey<ml_kem::MlKem512> = bc2wrap::deserialize(&pk_buf).unwrap();
        let sk2: PrivateEncKey<ml_kem::MlKem512> = bc2wrap::deserialize(&sk_buf).unwrap();

        let msg = b"four legs good, two legs better";
        let ct = hybrid_ml_kem::enc::<ml_kem::MlKem512, _>(&mut rng, msg, &pk2.0).unwrap();
        let pt = hybrid_ml_kem::dec::<ml_kem::MlKem512>(ct, &sk2.0).unwrap();
        assert_eq!(msg.to_vec(), pt);
    }

    // Test is purely here as a reference and sanity check.
    // That it passes comes directly from the way serde works
    #[test]
    fn validate_consistent_cipher_encoding() {
        #[derive(Clone, Serialize, Deserialize, Debug)]
        struct Cipher(pub hybrid_ml_kem::HybridKemCt);

        let ct = hybrid_ml_kem::HybridKemCt {
            nonce: [0_u8; NONCE_LEN],
            kem_ct: vec![1u8; 100],
            payload_ct: vec![2u8; 200],
        };

        let plain_encoding = bc2wrap::serialize(&Cipher(ct.clone())).unwrap();
        let wrapped_encoding = bc2wrap::serialize(&Cipher(ct.clone())).unwrap();
        assert_eq!(plain_encoding, wrapped_encoding);
        let decoded_wrapping = bc2wrap::deserialize::<Cipher>(&plain_encoding).unwrap();
        let decoded_unwrapped = bc2wrap::deserialize::<HybridKemCt>(&wrapped_encoding).unwrap();
        assert_eq!(decoded_wrapping.0.nonce, decoded_unwrapped.nonce);
        assert_eq!(decoded_wrapping.0.kem_ct, decoded_unwrapped.kem_ct);
        assert_eq!(decoded_wrapping.0.payload_ct, decoded_unwrapped.payload_ct);
    }

    #[test]
    fn validate_zeroize_signing_key() {
        let mut rng = AesRng::seed_from_u64(1);
        let (_pk, mut sk) = gen_sig_keys(&mut rng);
        let old_sk = sk.clone();
        sk.zeroize();
        // Validate a change happens from zeroize
        assert_ne!(sk, old_sk);
    }
}

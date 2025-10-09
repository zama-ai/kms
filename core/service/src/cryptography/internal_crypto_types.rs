use crate::consts::{DEFAULT_PARAM, SAFE_SER_SIZE_LIMIT, SIG_SIZE, TEST_PARAM};
use crate::cryptography::error::CryptographyError;
use crate::cryptography::hybrid_ml_kem::{self, HybridKemCt};
use k256::ecdsa::{SigningKey, VerifyingKey};
use kms_grpc::kms::v1::FheParameter;
use ml_kem::{EncodedSizeUser, KemCore, MlKem1024, MlKem512};
use nom::AsBytes;
use rand::{CryptoRng, RngCore};
use serde::de::Visitor;
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

#[derive(Clone, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum UnifiedPublicEncKeyVersioned {
    V0(UnifiedPublicEncKey),
}

// TODO ideally this should be a trait but this required quite a bit of refactoring
#[derive(Clone, Debug, Serialize, Deserialize, Versionize)]
#[versionize(UnifiedPublicEncKeyVersioned)]
#[expect(clippy::large_enum_variant)]
pub enum UnifiedPublicEncKey {
    MlKem512(PublicEncKey<ml_kem::MlKem512>),
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

impl From<UnifiedPublicEncKey> for EncryptionSchemeType {
    fn from(value: UnifiedPublicEncKey) -> Self {
        match value {
            UnifiedPublicEncKey::MlKem512(_) => EncryptionSchemeType::MlKem512,
            UnifiedPublicEncKey::MlKem1024(_) => EncryptionSchemeType::MlKem1024,
        }
    }
}
impl From<&UnifiedPublicEncKey> for EncryptionSchemeType {
    fn from(value: &UnifiedPublicEncKey) -> Self {
        match value {
            UnifiedPublicEncKey::MlKem512(_) => EncryptionSchemeType::MlKem512,
            UnifiedPublicEncKey::MlKem1024(_) => EncryptionSchemeType::MlKem1024,
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

// TODO why is this manual and not derived?
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
/// Trait to add to an object that allows decryption
/// The type T is the type of the plaintext to be decrypted
/// It is enforced that T must implement Unversionize and be Named
/// in order to prevent missing versioning of en/decrypted data.
pub trait Decrypt {
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

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum EncryptionSchemeTypeVersioned {
    V0(EncryptionSchemeType),
}

// TODO separate into signature and encryption files
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Display, Versionize)]
#[versionize(EncryptionSchemeTypeVersioned)]
pub enum EncryptionSchemeType {
    MlKem512,
    MlKem1024,
}

pub trait EncryptionScheme: Send + Sync {
    fn scheme_type(&self) -> EncryptionSchemeType;
    fn keygen(&mut self) -> Result<(UnifiedPrivateEncKey, UnifiedPublicEncKey), CryptographyError>;
}

pub trait CryptoRand: CryptoRng + RngCore + Send + Sync {}
impl<T: CryptoRng + RngCore + Send + Sync> CryptoRand for T {}

pub struct Encryption<'a> {
    scheme_type: EncryptionSchemeType,
    rng: &'a mut dyn CryptoRand, //Box<dyn CryptoRand + Send + Sync>,
}

impl<'a> Encryption<'a> {
    pub fn new(
        scheme_type: EncryptionSchemeType,
        rng: &'a mut (impl CryptoRng + RngCore + Send + Sync + 'static),
    ) -> Self {
        Self { scheme_type, rng }
    }
}

impl<'a> EncryptionScheme for Encryption<'a> {
    fn scheme_type(&self) -> EncryptionSchemeType {
        self.scheme_type.clone()
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

    /// DEPRECATED legacy code since this is not the right way to serialize as it is not versioned
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
impl From<PublicSigKey> for SigningSchemeType {
    fn from(_value: PublicSigKey) -> Self {
        // TODO only scheme for now
        SigningSchemeType::Ecdsa256k1
    }
}
impl From<&PublicSigKey> for SigningSchemeType {
    fn from(_value: &PublicSigKey) -> Self {
        // TODO only scheme for now
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
// TODO should eventually be replaced or consolidated with the UnifiedPriavateSignKey
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

    /// TODO DEPRECATED: code should be refactored to not use this outside on this class
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

impl From<PrivateSigKey> for SigningSchemeType {
    fn from(_value: PrivateSigKey) -> Self {
        // Only one scheme for now
        SigningSchemeType::Ecdsa256k1
    }
}
impl From<&PrivateSigKey> for SigningSchemeType {
    fn from(_value: &PrivateSigKey) -> Self {
        // Only one scheme for now
        SigningSchemeType::Ecdsa256k1
    }
}
#[derive(Clone, PartialEq, Eq, Debug)]
struct WrappedSigningKey(k256::ecdsa::SigningKey);
impl_generic_versionize!(WrappedSigningKey);

impl Zeroize for WrappedSigningKey {
    fn zeroize(&mut self) {
        let mut bytes = self.0.to_bytes();
        bytes.zeroize();
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
// TODO shoudl be versionized in a struct as legacy XXXX
// Type used for the signcrypted payload returned by a server
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Cipher(pub hybrid_ml_kem::HybridKemCt);

#[derive(Clone, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum UnifiedCipherVersioned {
    V0(UnifiedCipher),
}

// TODO separate into signature and encryption files
#[derive(Debug, Clone, Serialize, Deserialize, Versionize)]
#[versionize(UnifiedCipherVersioned)]
pub struct UnifiedCipher {
    pub cipher: Vec<u8>,
    pub encryption_type: EncryptionSchemeType,
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
    // TODO should be generalized to the following
    // fn signcrypt<T: Serialize + tfhe::Versionize + tfhe::named::Named>(
    //     &self,
    //     rng: &mut (impl CryptoRng + RngCore),
    //     dsep: &DomainSep,
    //     msg: &T,
    // ) -> Result<UnifiedSigncryption, CryptographyError> {
    fn signcrypt<T: Serialize + AsRef<[u8]>>(
        // TOTO should probablly be typedPlaintext for now
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        dsep: &DomainSep,
        msg: &T,
    ) -> Result<UnifiedSigncryption, CryptographyError>;
}

pub trait Designcrypt {
    // TODO should eventually look like this
    // fn designcrypt<T: Serialize + tfhe::Versionize + tfhe::named::Named>(
    //     &self,
    //     signcryption: &UnifiedSigncryption,
    // ) -> Result<T, CryptographyError>;
    fn designcrypt(
        &self,
        dsep: &DomainSep,
        cipher: &UnifiedSigncryption,
    ) -> Result<Vec<u8>, CryptographyError>;
}

pub trait SigncryptFHEPlaintext: Signcrypt {
    fn signcrypt_plaintext(
        &self,
        rng: &mut (impl CryptoRng + RngCore),
        dsep: &DomainSep,
        plaintext: Vec<u8>,
        fhe_type: FheTypes,
        link: Vec<u8>,
    ) -> Result<UnifiedSigncryption, CryptographyError>;
}

pub trait DesigncryptFHEPlaintext: Designcrypt {
    fn designcrypt_plaintext(
        &self,
        dsep: &DomainSep,
        signcryption: &UnifiedSigncryption,
        link: Vec<u8>,
    ) -> Result<Vec<u8>, CryptographyError>;
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum UnifiedSigncryptionVersioned {
    V0(UnifiedSigncryption),
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Versionize)]
#[versionize(UnifiedSigncryptionVersioned)]
pub struct UnifiedSigncryption {
    pub payload: Vec<u8>,
    pub encryption_type: EncryptionSchemeType,
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

#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, VersionsDispatch)]
pub enum UnifiedDesigncryptionKeyVersioned {
    V0(UnifiedDesigncryptionKey),
}

// TODO make ref type
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, Versionize)]
#[versionize(UnifiedDesigncryptionKeyVersioned)]
pub struct UnifiedDesigncryptionKey {
    pub decryption_key: UnifiedPrivateEncKey,
    pub encryption_key: UnifiedPublicEncKey, // Needed for validation of the signcrypted payload
    pub sender_verf_key: PublicSigKey,
    pub receiver_id: Vec<u8>, // Identifier for the receiver's encryption key, e.g. blockchain address
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
}

/// Convinence type for efficiency
#[derive(Clone, Debug)]
pub struct UnifiedSigncryptionKeyPair<'a> {
    pub signcrypt_key: &'a UnifiedSigncryptionKey,
    pub designcryption_key: &'a UnifiedDesigncryptionKey,
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
// TODO add new methods and ensure that private keys always have public keys as well

//TODO should also be versionized
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
/// which can be usefor for converting from [FheParameter] to [DKGParams]
// TODO versionize
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
    use crate::cryptography::{
        hybrid_ml_kem,
        internal_crypto_types::{
            Encryption, EncryptionScheme, EncryptionSchemeType, PrivateEncKey, PublicEncKey,
        },
    };
    use rand::rngs::OsRng;

    #[test]
    fn test_pke_serialize_size() {
        let mut rng = OsRng;
        let mut encryption = Encryption::new(EncryptionSchemeType::MlKem512, &mut rng);
        let (sk, pk) = encryption.keygen().unwrap();
        let pk_buf = bc2wrap::serialize(&pk).unwrap();
        let sk_buf = bc2wrap::serialize(&sk).unwrap();
        // there is extra 8 bytes in the serialization to encode the length
        // see https://github.com/bincode-org/bincode/blob/trunk/docs/spec.md#linear-collections-vec-arrays-etc
        assert_eq!(pk_buf.len(), hybrid_ml_kem::ML_KEM_512_PK_LENGTH + 8);
        assert_eq!(sk_buf.len(), hybrid_ml_kem::ML_KEM_512_SK_LEN + 8);

        // deserialize and test if encryption still works.
        let pk2: PublicEncKey<ml_kem::MlKem512> = bc2wrap::deserialize(&pk_buf).unwrap();
        let sk2: PrivateEncKey<ml_kem::MlKem512> = bc2wrap::deserialize(&sk_buf).unwrap();

        let msg = b"four legs good, two legs better";
        let ct = hybrid_ml_kem::enc::<ml_kem::MlKem512, _>(&mut rng, msg, &pk2.0).unwrap();
        let pt = hybrid_ml_kem::dec::<ml_kem::MlKem512>(ct, &sk2.0).unwrap();
        assert_eq!(msg.to_vec(), pt);
    }
}

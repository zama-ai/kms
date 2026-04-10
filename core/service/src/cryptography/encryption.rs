use crate::{
    consts::SAFE_SER_SIZE_LIMIT,
    cryptography::{error::CryptographyError, hybrid_ml_kem, hybrid_ml_kem::HybridKemCt},
};
use ml_kem::EncodedSizeUser;
use ml_kem::KemCore;
use ml_kem::MlKem512;
use tfhe_versionable::Upgrade;

/// Error returned when upgrading from a legacy versioned type that contained MlKem1024.
#[derive(Debug)]
pub struct MlKem1024RemovedError;

impl std::fmt::Display for MlKem1024RemovedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlKem1024 is no longer supported")
    }
}

impl std::error::Error for MlKem1024RemovedError {}
use nom::AsBytes;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, de::Visitor};
use strum_macros::Display;
use tfhe::{
    Versionize,
    named::Named,
    safe_serialization::{safe_deserialize, safe_serialize},
};
use tfhe_versionable::VersionsDispatch;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, VersionsDispatch)]
pub enum UnifiedPublicEncKeyVersioned {
    V0(UnifiedPublicEncKeyV0),
    V1(UnifiedPublicEncKey),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, tfhe_versionable::Version)]
pub enum UnifiedPublicEncKeyV0 {
    MlKem512(PublicEncKey<ml_kem::MlKem512>),
    MlKem1024(PublicEncKey<ml_kem::MlKem1024>),
}

impl Upgrade<UnifiedPublicEncKey> for UnifiedPublicEncKeyV0 {
    type Error = MlKem1024RemovedError;
    fn upgrade(self) -> Result<UnifiedPublicEncKey, Self::Error> {
        match self {
            UnifiedPublicEncKeyV0::MlKem512(pk) => Ok(UnifiedPublicEncKey::MlKem512(pk)),
            UnifiedPublicEncKeyV0::MlKem1024(_) => Err(MlKem1024RemovedError),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(UnifiedPublicEncKeyVersioned)]
pub enum UnifiedPublicEncKey {
    MlKem512(PublicEncKey<ml_kem::MlKem512>),
}

impl Zeroize for UnifiedPublicEncKey {
    fn zeroize(&mut self) {
        // Don't do anything, public key is not secret, but method is needed for types using both this and private keys
    }
}

impl tfhe::named::Named for UnifiedPublicEncKey {
    const NAME: &'static str = "UnifiedPublicEncKey";
}

impl HasPkeScheme for UnifiedPublicEncKey {
    fn encryption_scheme_type(&self) -> PkeSchemeType {
        match self {
            UnifiedPublicEncKey::MlKem512(_) => PkeSchemeType::MlKem512,
        }
    }
}

impl UnifiedPublicEncKey {
    pub fn unwrap_ml_kem_512(self) -> PublicEncKey<ml_kem::MlKem512> {
        match self {
            UnifiedPublicEncKey::MlKem512(pk) => pk,
        }
    }
}

// Alias wrapping the ephemeral public encryption key the user's wallet constructs and the server
// uses to encrypt its payload
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

// See this issue: https://github.com/zama-ai/kms-internal/issues/2781
// We basically need to use standard serialization fo ecdsa keys to remain compatible with the KMS verifier contract
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
                PkeSchemeType::MlKem512,
            ),
        };
        Ok(UnifiedCipher::new(inner_ct, scheme))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop, VersionsDispatch)]
pub enum UnifiedPrivateEncKeyVersioned {
    V0(UnifiedPrivateEncKeyV0),
    V1(UnifiedPrivateEncKey),
}

#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, tfhe_versionable::Version)]
pub enum UnifiedPrivateEncKeyV0 {
    MlKem512(PrivateEncKey<ml_kem::MlKem512>),
    MlKem1024(PrivateEncKey<ml_kem::MlKem1024>),
}

impl Upgrade<UnifiedPrivateEncKey> for UnifiedPrivateEncKeyV0 {
    type Error = MlKem1024RemovedError;
    fn upgrade(self) -> Result<UnifiedPrivateEncKey, Self::Error> {
        match self {
            UnifiedPrivateEncKeyV0::MlKem512(sk) => Ok(UnifiedPrivateEncKey::MlKem512(sk)),
            UnifiedPrivateEncKeyV0::MlKem1024(_) => Err(MlKem1024RemovedError),
        }
    }
}

/// # Current Usage
/// - `user_decryption_wasm.rs`, `user_decryption_non_wasm.rs`, and custodian based backup (`core/service/src/backup`)
/// - Lifetime: Lifetime of a custodian context
/// - Scope: Lifetime of a backup (i.e. lifetime of a custodian context), but local to client application
#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, Versionize)]
#[versionize(UnifiedPrivateEncKeyVersioned)]
pub enum UnifiedPrivateEncKey {
    MlKem512(PrivateEncKey<ml_kem::MlKem512>),
}

impl tfhe::named::Named for UnifiedPrivateEncKey {
    const NAME: &'static str = "UnifiedPrivateDecKey";
}

impl PartialEq for UnifiedPrivateEncKey {
    fn eq(&self, other: &Self) -> bool {
        // Compare the serialized forms for equality
        let mut ser = Vec::new();
        safe_serialize(self, &mut ser, SAFE_SER_SIZE_LIMIT)
            .expect("Serialization of UnifiedPrivateEncKey failed for equality check");
        let mut other_ser = Vec::new();
        safe_serialize(other, &mut other_ser, SAFE_SER_SIZE_LIMIT)
            .expect("Serialization of UnifiedPrivateEncKey failed for equality check");
        ser == other_ser
    }
}

impl Eq for UnifiedPrivateEncKey {}

impl From<UnifiedPrivateEncKey> for PkeSchemeType {
    fn from(value: UnifiedPrivateEncKey) -> Self {
        match value {
            UnifiedPrivateEncKey::MlKem512(_) => PkeSchemeType::MlKem512,
        }
    }
}
impl From<&UnifiedPrivateEncKey> for PkeSchemeType {
    fn from(value: &UnifiedPrivateEncKey) -> Self {
        match value {
            UnifiedPrivateEncKey::MlKem512(_) => PkeSchemeType::MlKem512,
        }
    }
}

impl UnifiedPrivateEncKey {
    pub fn unwrap_ml_kem_512(self) -> PrivateEncKey<ml_kem::MlKem512> {
        match self {
            UnifiedPrivateEncKey::MlKem512(pk) => pk,
        }
    }
}

impl HasPkeScheme for UnifiedPrivateEncKey {
    fn encryption_scheme_type(&self) -> PkeSchemeType {
        match self {
            UnifiedPrivateEncKey::MlKem512(_) => PkeSchemeType::MlKem512,
        }
    }
}

// Alias wrapping the ephemeral private decryption key the user's wallet constructs to receive the
// server's encrypted payload
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
        let raw_plaintext = match self {
            UnifiedPrivateEncKey::MlKem512(private_enc_key) => {
                hybrid_ml_kem::dec::<MlKem512>(cipher.cipher.to_owned(), &private_enc_key.0)?
            }
        };
        let mut res_buf = std::io::Cursor::new(raw_plaintext);
        safe_deserialize(&mut res_buf, SAFE_SER_SIZE_LIMIT)
            .map_err(CryptographyError::DeserializationError)
    }
}

pub trait HasPkeScheme {
    fn encryption_scheme_type(&self) -> PkeSchemeType;
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum PkeSchemeTypeVersioned {
    V0(PkeSchemeTypeV0),
    V1(PkeSchemeType),
}

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Display,
    tfhe_versionable::Version,
)]
pub enum PkeSchemeTypeV0 {
    MlKem512,
    MlKem1024,
}

impl Upgrade<PkeSchemeType> for PkeSchemeTypeV0 {
    type Error = MlKem1024RemovedError;
    fn upgrade(self) -> Result<PkeSchemeType, Self::Error> {
        match self {
            PkeSchemeTypeV0::MlKem512 => Ok(PkeSchemeType::MlKem512),
            PkeSchemeTypeV0::MlKem1024 => Err(MlKem1024RemovedError),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Display, Versionize)]
#[versionize(PkeSchemeTypeVersioned)]
pub enum PkeSchemeType {
    MlKem512,
}

impl From<kms_grpc::kms::v1::PkeSchemeType> for PkeSchemeType {
    fn from(value: kms_grpc::kms::v1::PkeSchemeType) -> Self {
        match value {
            kms_grpc::kms::v1::PkeSchemeType::Mlkem512 => PkeSchemeType::MlKem512,
        }
    }
}

impl TryFrom<i32> for PkeSchemeType {
    type Error = anyhow::Error;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(PkeSchemeType::MlKem512),
            _ => Err(anyhow::anyhow!("Unsupported PkeSchemeType: {:?}", value)),
        }
    }
}
pub trait PkeScheme: Send + Sync {
    /// Return the type of encryption scheme used by this instance
    fn scheme_type(&self) -> PkeSchemeType;
    /// Generate a new keypair for this encryption scheme
    fn keygen(&mut self) -> Result<(UnifiedPrivateEncKey, UnifiedPublicEncKey), CryptographyError>;
}

pub struct Encryption<'a, R: CryptoRng + RngCore + Send + Sync> {
    scheme_type: PkeSchemeType,
    rng: &'a mut R,
}

impl<'a, R: CryptoRng + RngCore + Send + Sync> Encryption<'a, R> {
    pub fn new(scheme_type: PkeSchemeType, rng: &'a mut R) -> Self {
        Self { scheme_type, rng }
    }
}

impl<'a, R: CryptoRng + RngCore + Send + Sync> PkeScheme for Encryption<'a, R> {
    fn scheme_type(&self) -> PkeSchemeType {
        self.scheme_type
    }

    fn keygen(&mut self) -> Result<(UnifiedPrivateEncKey, UnifiedPublicEncKey), CryptographyError> {
        let (sk, pk) = match self.scheme_type {
            PkeSchemeType::MlKem512 => {
                let (decapsulation_key, encapsulation_key) =
                    hybrid_ml_kem::keygen::<ml_kem::MlKem512, _>(&mut self.rng);
                (
                    UnifiedPrivateEncKey::MlKem512(PrivateEncKey(decapsulation_key)),
                    UnifiedPublicEncKey::MlKem512(PublicEncKey(encapsulation_key)),
                )
            }
        };
        Ok((sk, pk))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, VersionsDispatch)]
pub enum UnifiedCipherVersioned {
    V0(UnifiedCipher),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(UnifiedCipherVersioned)]
pub struct UnifiedCipher {
    pub cipher: HybridKemCt,
    pub pke_type: PkeSchemeType,
}

impl Named for UnifiedCipher {
    const NAME: &'static str = "signcryption::UnifiedCipher";
}

impl UnifiedCipher {
    pub fn new(cipher: HybridKemCt, pke_type: PkeSchemeType) -> Self {
        Self { cipher, pke_type }
    }
}

#[cfg(test)]
mod tests {
    use crate::vault::storage::tests::TestType;
    use aes_prng::AesRng;
    use kms_lib::consts::SAFE_SER_SIZE_LIMIT;
    use kms_lib::cryptography::encryption::{
        Decrypt, Encrypt, Encryption, PkeScheme, PkeSchemeType, UnifiedPrivateEncKey,
        UnifiedPublicEncKey,
    };
    use kms_lib::cryptography::error::CryptographyError;
    use rand::SeedableRng;

    #[test]
    fn nested_pke_sunshine() {
        let msg = TestType { i: 42 };
        let mut rng = AesRng::seed_from_u64(0);
        let mut enc = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
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
        let mut enc = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (_sk_orig, pk) = enc.keygen().unwrap();
        let (sk, _pk) = enc.keygen().unwrap();

        let ct = pk.encrypt(&mut rng, &msg).unwrap();
        let err = sk.decrypt::<TestType>(&ct).unwrap_err();
        // We get an AesGcm error due to implicit rejection
        assert!(matches!(err, CryptographyError::AesGcmError(..)));
    }

    #[test]
    fn pke_wrong_ct_enc() {
        let msg = TestType { i: 42 };
        let mut rng = AesRng::seed_from_u64(0);
        let mut enc = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (sk, pk) = enc.keygen().unwrap();
        let mut ct = pk.encrypt(&mut rng, &msg).unwrap();
        ct.cipher.kem_ct[0] ^= 1;
        assert!(sk.decrypt::<TestType>(&ct).is_err());
    }
}

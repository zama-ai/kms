use crate::consts::{DEFAULT_PARAM, SIG_SIZE, TEST_PARAM};
use crate::cryptography::hybrid_ml_kem::{self, KemParam};
use k256::ecdsa::{SigningKey, VerifyingKey};
use kms_grpc::kms::v1::FheParameter;
use ml_kem::kem::{DecapsulationKey, EncapsulationKey};
use ml_kem::EncodedSizeUser;
use nom::AsBytes;
use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize};
use tfhe::named::Named;
use tfhe_versionable::{Versionize, VersionsDispatch};
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use wasm_bindgen::prelude::wasm_bindgen;

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

// Alias wrapping the ephemeral public encryption key the user's wallet constructs and the server
// uses to encrypt its payload
#[wasm_bindgen]
#[derive(Clone, PartialEq, Debug)]
pub struct PublicEncKey(pub(crate) EncapsulationKey<KemParam>);
impl Serialize for PublicEncKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.as_bytes())
    }
}

impl_generic_versionize!(PublicEncKey);

impl<'de> Deserialize<'de> for PublicEncKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_bytes(PublicEncKeyVisitor)
    }
}

struct PublicEncKeyVisitor;
impl Visitor<'_> for PublicEncKeyVisitor {
    type Value = PublicEncKey;

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
                let msg = "Byte array of incorrect length";
                tracing::error!(msg);
                return Err(serde::de::Error::custom(msg));
            }
        };
        let ek = EncapsulationKey::<KemParam>::from_bytes(array);
        Ok(PublicEncKey(ek))
    }
}

// Alias wrapping the ephemeral private decryption key the user's wallet constructs to receive the
// server's encrypted payload
#[wasm_bindgen]
#[derive(Clone, Debug)]
pub struct PrivateEncKey(pub(crate) DecapsulationKey<KemParam>);

impl Serialize for PrivateEncKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.as_bytes())
    }
}

impl<'de> Deserialize<'de> for PrivateEncKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(PrivateEncKeyVisitor)
    }
}

struct PrivateEncKeyVisitor;
impl Visitor<'_> for PrivateEncKeyVisitor {
    type Value = PrivateEncKey;

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
                let msg = "Byte array of incorrect length";
                tracing::error!(msg);
                return Err(serde::de::Error::custom(msg));
            }
        };
        let dk = DecapsulationKey::<KemParam>::from_bytes(array);
        Ok(PrivateEncKey(dk))
    }
}

pub fn gen_sig_keys<R: rand::CryptoRng + rand::Rng>(rng: &mut R) -> (PublicSigKey, PrivateSigKey) {
    use k256::ecdsa::SigningKey;

    let sk = SigningKey::random(rng);
    let pk = SigningKey::verifying_key(&sk);
    (PublicSigKey::new(*pk), PrivateSigKey::new(sk))
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

impl Named for PublicSigKey {
    const NAME: &'static str = "PublicSigKey";
}

impl PublicSigKey {
    pub fn new(pk: k256::ecdsa::VerifyingKey) -> Self {
        Self {
            pk: WrappedVerifyingKey(pk),
        }
    }

    pub fn pk(&self) -> &k256::ecdsa::VerifyingKey {
        &self.pk.0
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
                "Could not decode verification key: {:?}",
                e
            ))),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, VersionsDispatch)]
pub enum PrivateSigKeyVersioned {
    V0(PrivateSigKey),
}

// Struct wrapping signature signing key used by both the client and server to authenticate their
// messages to one another
#[wasm_bindgen]
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Versionize)]
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

    pub fn sk(&self) -> &k256::ecdsa::SigningKey {
        &self.sk.0
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct WrappedSigningKey(k256::ecdsa::SigningKey);
impl_generic_versionize!(WrappedSigningKey);

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
            Err(e) => Err(E::custom(format!("Could not decode signing key: {:?}", e))),
        }
    }
}

// Type used for the signcrypted payload returned by a server
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Cipher(pub hybrid_ml_kem::HybridKemCt);

#[derive(Clone, Debug)]
pub struct SigncryptionPrivKey {
    pub signing_key: Option<PrivateSigKey>,
    pub decryption_key: PrivateEncKey,
}

/// Structure for public keys for signcryption that can get encoded as follows:
///     client_address, a 20-byte blockchain address, created from a public key
///     enc_key, (Montgomery point following libsodium serialization)
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SigncryptionPubKey {
    pub client_address: alloy_primitives::Address,
    pub enc_key: PublicEncKey,
}

/// Structure for private keys for signcryption
#[derive(Clone, Debug)]
pub struct SigncryptionPair {
    pub sk: SigncryptionPrivKey,
    pub pk: SigncryptionPubKey,
}

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
            Err(e) => Err(E::custom(format!("Could not decode signature: {:?}", e)))?,
        };
        Ok(Signature { sig })
    }
}

/// This is a wrapper around [DKGParams] so that we can
/// implement [From<FheParameter>]. It has a [std::ops::Deref] implementation
/// which can be usefor for converting from [FheParameter] to [DKGParams]
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
    use rand::rngs::OsRng;

    use crate::cryptography::{
        hybrid_ml_kem,
        internal_crypto_types::{PrivateEncKey, PublicEncKey},
        signcryption::ephemeral_encryption_key_generation,
    };

    #[test]
    fn test_pke_serialize_size() {
        let mut rng = OsRng;
        let (pk, sk) = ephemeral_encryption_key_generation(&mut rng);
        let pk_buf = bc2wrap::serialize(&pk).unwrap();
        let sk_buf = bc2wrap::serialize(&sk).unwrap();
        // there is extra 8 bytes in the serialization to encode the length
        // see https://github.com/bincode-org/bincode/blob/trunk/docs/spec.md#linear-collections-vec-arrays-etc
        assert_eq!(pk_buf.len(), hybrid_ml_kem::ML_KEM_CT_PK_LENGTH + 8);
        assert_eq!(sk_buf.len(), hybrid_ml_kem::ML_KEM_SK_LEN + 8);

        // deserialize and test if encryption still works.
        let pk2: PublicEncKey = bc2wrap::deserialize(&pk_buf).unwrap();
        let sk2: PrivateEncKey = bc2wrap::deserialize(&sk_buf).unwrap();

        let msg = b"four legs good, two legs better";
        let ct = hybrid_ml_kem::enc(&mut rng, msg, &pk2.0).unwrap();
        let pt = hybrid_ml_kem::dec(ct, &sk2.0).unwrap();
        assert_eq!(msg.to_vec(), pt);
    }
}

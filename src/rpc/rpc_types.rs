use crate::core::der_types::{PublicEncKey, PublicSigKey, Signature};
use crate::kms::{
    DecryptionRequest, DecryptionResponsePayload, FheType, ReencryptionRequestPayload,
    ReencryptionResponse,
};
use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize};
use serde_asn1_der::from_bytes;
use std::fmt;

pub trait BaseKms {
    fn verify_sig<T: fmt::Debug + Serialize>(
        payload: &T,
        signature: &Signature,
        verification_key: &PublicSigKey,
    ) -> bool;
    fn sign<T: fmt::Debug + Serialize>(&self, msg: &T) -> anyhow::Result<Signature>;
    fn get_verf_key(&self) -> PublicSigKey;
    fn digest<T: fmt::Debug + Serialize>(msg: &T) -> anyhow::Result<Vec<u8>>;
}
/// The [Kms] trait represents either a dummy KMS, an HSM, or an MPC network.
pub trait Kms: BaseKms {
    fn decrypt(&self, ct: &[u8], fhe_type: FheType) -> anyhow::Result<Plaintext>;
    fn reencrypt(
        &self,
        ct: &[u8],
        ct_type: FheType,
        digest_link: Vec<u8>,
        enc_key: &PublicEncKey,
        pub_verf_key: &PublicSigKey,
    ) -> anyhow::Result<Option<Vec<u8>>>;
}

/// Representation of the data stored in a signcryption, needed to facilitate FHE decryption and
/// request linking
#[derive(Clone, Serialize, Deserialize, Hash, PartialEq, Eq, Debug)]
pub struct SigncryptionPayload {
    pub raw_decryption: RawDecryption,
    pub req_digest: Vec<u8>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawDecryption {
    pub bytes: Vec<u8>,
    pub fhe_type: FheType,
}

impl RawDecryption {
    pub fn new(bytes: Vec<u8>, fhe_type: FheType) -> Self {
        Self { bytes, fhe_type }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plaintext {
    pub value: u128,
    fhe_type: FheType,
}

/// Little endian encoding to allow for easy serialization by allowing most significant bytes to be
/// 0
impl Plaintext {
    pub fn new(value: u128, fhe_type: FheType) -> Self {
        Self { value, fhe_type }
    }

    pub fn from_bool(value: bool) -> Self {
        let plaintext = match value {
            true => 1,
            false => 0,
        };
        Self {
            value: plaintext,
            fhe_type: FheType::Bool,
        }
    }

    pub fn from_u4(value: u8) -> Self {
        Self {
            value: value as u128,
            fhe_type: FheType::Euint4,
        }
    }

    pub fn from_u8(value: u8) -> Self {
        Self {
            value: value as u128,
            fhe_type: FheType::Euint8,
        }
    }

    pub fn from_u16(value: u16) -> Self {
        Self {
            value: value as u128,
            fhe_type: FheType::Euint16,
        }
    }

    pub fn from_u32(value: u32) -> Self {
        Self {
            value: value as u128,
            fhe_type: FheType::Euint32,
        }
    }

    pub fn from_u64(value: u64) -> Self {
        Self {
            value: value as u128,
            fhe_type: FheType::Euint64,
        }
    }

    pub fn as_bool(&self) -> bool {
        if self.fhe_type != FheType::Bool {
            tracing::warn!(
                "Plaintext is not of type u8. Returning the least significant bit as bool"
            );
        }
        self.value % 2 == 1
    }

    pub fn as_u4(&self) -> u8 {
        if self.fhe_type != FheType::Euint4 {
            tracing::warn!("Plaintext is not of type u4. Returning the value modulo 16");
        }
        (self.value % 16) as u8
    }

    pub fn as_u8(&self) -> u8 {
        if self.fhe_type != FheType::Euint8 {
            tracing::warn!("Plaintext is not of type u8. Returning the value modulo 256");
        }
        self.value as u8
    }

    pub fn as_u16(&self) -> u16 {
        if self.fhe_type != FheType::Euint16 {
            tracing::warn!("Plaintext is not of type u16. Returning the value modulo 65536");
        }
        self.value as u16
    }

    pub fn as_u32(&self) -> u32 {
        if self.fhe_type != FheType::Euint32 {
            tracing::warn!("Plaintext is not of type u32. Returning the value modulo 2^32");
        }
        self.value as u32
    }

    pub fn as_u64(&self) -> u64 {
        if self.fhe_type != FheType::Euint64 {
            tracing::warn!("Plaintext is not of type u32. Returning the value modulo 2^64");
        }
        self.value as u64
    }

    pub fn fhe_type(&self) -> FheType {
        self.fhe_type
    }
}

impl TryFrom<RawDecryption> for Plaintext {
    type Error = anyhow::Error;

    fn try_from(value: RawDecryption) -> Result<Self, Self::Error> {
        match value.fhe_type {
            FheType::Bool => {
                if value.bytes[0] % 2 == 1 {
                    Ok(Plaintext::from_bool(true))
                } else {
                    Ok(Plaintext::from_bool(false))
                }
            }
            FheType::Euint4 => Ok(Plaintext::from_u4(value.bytes[0])),
            FheType::Euint8 => Ok(Plaintext::from_u8(value.bytes[0])),
            FheType::Euint16 => {
                let value_arr: [u8; 2] = value
                    .bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Failed to convert bytes to u16"))?;
                Ok(Plaintext::from_u16(u16::from_le_bytes(value_arr)))
            }
            FheType::Euint32 => {
                let value_arr: [u8; 4] = value
                    .bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Failed to convert bytes to u32"))?;
                Ok(Plaintext::from_u32(u32::from_le_bytes(value_arr)))
            }
            FheType::Euint64 => {
                let value_arr: [u8; 8] = value
                    .bytes
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Failed to convert bytes to u64"))?;
                Ok(Plaintext::from_u64(u64::from_le_bytes(value_arr)))
            }
        }
    }
}

/// Observe that this seemingly redundant types are required since the Protobuf compiled types do
/// not implement the serializable and deserializable traits. Hence [DecryptionRequestSerializable]
/// implement data to be asn1 serialized and hashed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecryptionRequestSerializable {
    pub version: u32,
    pub shares_needed: u32,
    pub fhe_type: FheType,
    pub ciphertext: Vec<u8>,
    pub randomness: Vec<u8>,
}
impl From<DecryptionRequestSerializable> for DecryptionRequest {
    fn from(val: DecryptionRequestSerializable) -> DecryptionRequest {
        DecryptionRequest {
            version: val.version,
            shares_needed: val.shares_needed,
            fhe_type: val.fhe_type.into(),
            ciphertext: val.ciphertext,
            randomness: val.randomness,
        }
    }
}
impl TryFrom<DecryptionRequest> for DecryptionRequestSerializable {
    type Error = anyhow::Error;

    fn try_from(val: DecryptionRequest) -> Result<Self, Self::Error> {
        Ok(DecryptionRequestSerializable {
            version: val.version,
            shares_needed: val.shares_needed,
            fhe_type: val.fhe_type.try_into()?,
            ciphertext: val.ciphertext,
            randomness: val.randomness,
        })
    }
}

/// Observe that this seemingly redundant types are required since the Protobuf compiled types do
/// not implement the serializable and deserializable traits. Hence [DecryptionResponseSigPayload]
/// implement data to be asn1 serialized which will be signed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecryptionResponseSigPayload {
    pub version: u32,
    pub shares_needed: u32,
    pub verification_key: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub digest: Vec<u8>,
    pub randomness: Vec<u8>,
}
impl From<DecryptionResponseSigPayload> for DecryptionResponsePayload {
    fn from(val: DecryptionResponseSigPayload) -> DecryptionResponsePayload {
        DecryptionResponsePayload {
            version: val.version,
            shares_needed: val.shares_needed,
            verification_key: val.verification_key,
            plaintext: val.plaintext,
            digest: val.digest,
            randomness: val.randomness,
        }
    }
}
impl From<DecryptionResponsePayload> for DecryptionResponseSigPayload {
    fn from(val: DecryptionResponsePayload) -> Self {
        DecryptionResponseSigPayload {
            version: val.version,
            shares_needed: val.shares_needed,
            verification_key: val.verification_key,
            plaintext: val.plaintext,
            digest: val.digest,
            randomness: val.randomness,
        }
    }
}

/// Observe that this seemingly redundant types are required since the Protobuf compiled types do
/// not implement the serializable and deserializable traits. Hence [ReencryptionRequestSigPayload]
/// implement data to be asn1 serialized which will be signed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReencryptionRequestSigPayload {
    pub version: u32,
    pub shares_needed: u32,
    pub verification_key: Vec<u8>,
    pub enc_key: Vec<u8>,
    pub fhe_type: FheType,
    pub ciphertext: Vec<u8>,
    pub randomness: Vec<u8>,
}
impl From<ReencryptionRequestSigPayload> for ReencryptionRequestPayload {
    fn from(val: ReencryptionRequestSigPayload) -> ReencryptionRequestPayload {
        ReencryptionRequestPayload {
            version: val.version,
            shares_needed: val.shares_needed,
            verification_key: val.verification_key,
            enc_key: val.enc_key,
            fhe_type: val.fhe_type.into(),
            ciphertext: val.ciphertext,
            randomness: val.randomness,
        }
    }
}
impl TryFrom<ReencryptionRequestPayload> for ReencryptionRequestSigPayload {
    type Error = anyhow::Error;

    fn try_from(val: ReencryptionRequestPayload) -> Result<Self, Self::Error> {
        Ok(ReencryptionRequestSigPayload {
            version: val.version,
            shares_needed: val.shares_needed,
            verification_key: val.verification_key,
            enc_key: val.enc_key,
            fhe_type: val.fhe_type.try_into()?,
            ciphertext: val.ciphertext,
            randomness: val.randomness,
        })
    }
}

impl serde::Serialize for FheType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Use i32 as this is what protobuf automates to
        serializer.serialize_bytes(&(*self as i32).to_le_bytes())
    }
}
impl<'de> Deserialize<'de> for FheType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(FheTypeVisitor)
    }
}
struct FheTypeVisitor;
impl<'de> Visitor<'de> for FheTypeVisitor {
    type Value = FheType;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("A type of fhe ciphertext")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        let res_array: [u8; 4] = v.try_into().map_err(serde::de::Error::custom)?;
        let res: i32 = i32::from_le_bytes(res_array);
        FheType::try_from(res).map_err(|_| E::custom("Error in converting i32 to FheType"))
    }
}
pub trait MetaResponse {
    fn version(&self) -> u32;
    fn shares_needed(&self) -> u32;
    fn verification_key(&self) -> Vec<u8>;
    fn fhe_type(&self) -> anyhow::Result<FheType>;
    fn digest(&self) -> Vec<u8>;
    fn randomness(&self) -> Option<Vec<u8>>;
}

impl MetaResponse for ReencryptionResponse {
    fn shares_needed(&self) -> u32 {
        self.shares_needed
    }

    fn verification_key(&self) -> Vec<u8> {
        self.verification_key.to_owned()
    }

    fn fhe_type(&self) -> anyhow::Result<FheType> {
        Ok(self.fhe_type())
    }

    fn digest(&self) -> Vec<u8> {
        self.digest.to_owned()
    }

    fn randomness(&self) -> Option<Vec<u8>> {
        None
    }

    fn version(&self) -> u32 {
        self.version
    }
}

impl MetaResponse for DecryptionResponsePayload {
    fn shares_needed(&self) -> u32 {
        self.shares_needed
    }

    fn verification_key(&self) -> Vec<u8> {
        self.verification_key.to_owned()
    }

    fn fhe_type(&self) -> anyhow::Result<FheType> {
        let plaintext: Plaintext = from_bytes(&self.plaintext)?;
        Ok(plaintext.fhe_type)
    }

    fn digest(&self) -> Vec<u8> {
        self.digest.to_owned()
    }

    fn randomness(&self) -> Option<Vec<u8>> {
        Some(self.randomness.to_owned())
    }

    fn version(&self) -> u32 {
        self.version
    }
}

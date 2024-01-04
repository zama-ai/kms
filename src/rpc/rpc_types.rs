use serde::{de::Visitor, Deserialize, Deserializer, Serialize};
use serde_asn1_der::from_bytes;
use std::fmt;
use tendermint::block::signed_header::SignedHeader;

use crate::{
    core::der_types::{PublicEncKey, PublicSigKey, Signature},
    kms::{
        DecryptionRequestPayload, DecryptionResponsePayload, FheType, Proof,
        ReencryptionRequestPayload, ReencryptionResponse,
    },
};

use super::kms_rpc::some_or_err;

/// The [Kms] trait represents either a dummy KMS, an HSM, or an MPC network.
pub trait Kms {
    fn verify_sig<T: fmt::Debug + Serialize>(
        &self,
        payload: &T,
        signature: &Signature,
        verification_key: &PublicSigKey,
    ) -> bool;
    fn sign<T: fmt::Debug + Serialize>(&self, msg: &T) -> anyhow::Result<Signature>;
    fn decrypt(&self, ct: &[u8], fhe_type: FheType) -> anyhow::Result<Plaintext>;
    fn reencrypt(
        &self,
        ct: &[u8],
        ct_type: FheType,
        digest_link: Vec<u8>,
        enc_key: &PublicEncKey,
        pub_verf_key: &PublicSigKey,
    ) -> anyhow::Result<Option<Vec<u8>>>;
    fn get_verf_key(&self) -> PublicSigKey;
}

/// Representation of the data stored in a signcryption, needed to facilitate FHE decryption and request linking
#[derive(Clone, Serialize, Deserialize, Hash, PartialEq, Eq, Debug)]
pub struct SigncryptionPayload {
    pub plaintext: Plaintext,
    pub digest: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LightClientCommitResponse {
    _jsonrpc: String,
    _id: i32,
    pub result: SignedHeaderWrapper,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedHeaderWrapper {
    pub signed_header: SignedHeader,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plaintext {
    bytes: Vec<u8>,
    fhe_type: FheType,
}

/// Little endian encoding to allow for easy serialization by allowing most significant bytes to be 0
impl Plaintext {
    pub fn new(bytes: Vec<u8>, fhe_type: FheType) -> Self {
        Self { bytes, fhe_type }
    }

    pub fn from_bool(value: bool) -> Self {
        let plaintext = match value {
            true => [1_u8, 1],
            false => [0_u8, 1],
        };
        Self {
            bytes: plaintext.to_vec(),
            fhe_type: FheType::Bool,
        }
    }

    pub fn from_u8(value: u8) -> Self {
        Self {
            bytes: value.to_le_bytes().to_vec(),
            fhe_type: FheType::Euint8,
        }
    }

    pub fn from_u16(value: u16) -> Self {
        Self {
            bytes: value.to_le_bytes().to_vec(),
            fhe_type: FheType::Euint16,
        }
    }

    pub fn from_u32(value: u32) -> Self {
        Self {
            bytes: value.to_le_bytes().to_vec(),
            fhe_type: FheType::Euint32,
        }
    }

    pub fn as_bool(&self) -> anyhow::Result<bool> {
        if self.fhe_type == FheType::Bool {
            Ok(self.bytes[0] % 2 == 1)
        } else {
            tracing::warn!(
                "Plaintext is not of type u8. Returning the least significant bit as bool"
            );
            Ok(self.get_large_int()? % 2 == 1)
        }
    }

    pub fn as_u8(&self) -> anyhow::Result<u8> {
        if self.fhe_type == FheType::Euint8 {
            Ok(self.bytes[0])
        } else {
            tracing::warn!("Plaintext is not of type u8. Returning the value modulo 256");
            Ok(self.get_large_int()? as u8)
        }
    }

    pub fn as_u16(&self) -> anyhow::Result<u16> {
        if self.fhe_type == FheType::Euint16 {
            tracing::warn!("Plaintext is not of type u16. Returning the value modulo 65536");
        }
        Ok(self.get_large_int()? as u16)
    }

    pub fn as_u32(&self) -> anyhow::Result<u32> {
        if self.fhe_type == FheType::Euint32 {
            tracing::warn!("Plaintext is not of type u32. Returning the value modulo 2^32");
        }
        Ok(self.get_large_int()? as u32)
    }

    pub fn fhe_type(&self) -> FheType {
        self.fhe_type
    }

    fn get_large_int(&self) -> anyhow::Result<u128> {
        let buf: [u8; 16] = self
            .bytes
            .clone()
            .try_into()
            .map_err(|_| anyhow::Error::msg("Failed to convert bytes to array"))?;
        Ok(u128::from_le_bytes(buf))
    }
}

/// Observe that this seemingly redundant types are required since the Protobuf compiled types do not implement
/// the serializable and deserializable traits. Hence [DecryptionRequestSigPayload] implement data to be asn1
/// serialized which will be signed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecryptionRequestSigPayload {
    pub verification_key: Vec<u8>,
    pub fhe_type: FheType,
    pub ciphertext: Vec<u8>,
    pub randomness: Vec<u8>,
    pub height: u32,
    pub merkle_patricia_proof: Vec<u8>,
}
impl From<DecryptionRequestSigPayload> for DecryptionRequestPayload {
    fn from(val: DecryptionRequestSigPayload) -> DecryptionRequestPayload {
        DecryptionRequestPayload {
            verification_key: val.verification_key,
            fhe_type: val.fhe_type.into(),
            ciphertext: val.ciphertext,
            randomness: val.randomness,
            proof: Some(Proof {
                height: val.height,
                merkle_patricia_proof: val.merkle_patricia_proof,
            }),
        }
    }
}
impl TryFrom<DecryptionRequestPayload> for DecryptionRequestSigPayload {
    type Error = anyhow::Error;

    fn try_from(val: DecryptionRequestPayload) -> Result<Self, Self::Error> {
        let proof = some_or_err(val.proof, "Proof not present in value".to_string())?;
        Ok(DecryptionRequestSigPayload {
            verification_key: val.verification_key,
            fhe_type: val.fhe_type.try_into()?,
            ciphertext: val.ciphertext,
            randomness: val.randomness,
            height: proof.height,
            merkle_patricia_proof: proof.merkle_patricia_proof,
        })
    }
}

/// Observe that this seemingly redundant types are required since the Protobuf compiled types do not implement
/// the serializable and deserializable traits. Hence [DecryptionResponseSigPayload] implement data to be asn1
/// serialized which will be signed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecryptionResponseSigPayload {
    pub shares_needed: u32,
    pub verification_key: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub digest: Vec<u8>,
    pub randomness: Vec<u8>,
}
impl From<DecryptionResponseSigPayload> for DecryptionResponsePayload {
    fn from(val: DecryptionResponseSigPayload) -> DecryptionResponsePayload {
        DecryptionResponsePayload {
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
            shares_needed: val.shares_needed,
            verification_key: val.verification_key,
            plaintext: val.plaintext,
            digest: val.digest,
            randomness: val.randomness,
        }
    }
}

/// Observe that this seemingly redundant types are required since the Protobuf compiled types do not implement
/// the serializable and deserializable traits. Hence [ReencryptionRequestSigPayload] implement data to be asn1
/// serialized which will be signed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReencryptionRequestSigPayload {
    pub verification_key: Vec<u8>,
    pub enc_key: Vec<u8>,
    pub fhe_type: FheType,
    pub ciphertext: Vec<u8>,
    pub randomness: Vec<u8>,
    pub height: u32,
    pub merkle_patricia_proof: Vec<u8>,
}
impl From<ReencryptionRequestSigPayload> for ReencryptionRequestPayload {
    fn from(val: ReencryptionRequestSigPayload) -> ReencryptionRequestPayload {
        ReencryptionRequestPayload {
            verification_key: val.verification_key,
            enc_key: val.enc_key,
            fhe_type: val.fhe_type.into(),
            ciphertext: val.ciphertext,
            randomness: val.randomness,
            proof: Some(Proof {
                height: val.height,
                merkle_patricia_proof: val.merkle_patricia_proof,
            }),
        }
    }
}
impl TryFrom<ReencryptionRequestPayload> for ReencryptionRequestSigPayload {
    type Error = anyhow::Error;

    fn try_from(val: ReencryptionRequestPayload) -> Result<Self, Self::Error> {
        let proof = some_or_err(val.proof, "Proof not present in value".to_string())?;
        Ok(ReencryptionRequestSigPayload {
            verification_key: val.verification_key,
            enc_key: val.enc_key,
            fhe_type: val.fhe_type.try_into()?,
            ciphertext: val.ciphertext,
            randomness: val.randomness,
            height: proof.height,
            merkle_patricia_proof: proof.merkle_patricia_proof,
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
    fn shares_needed(&self) -> u32;
    fn verification_key(&self) -> Vec<u8>;
    fn fhe_type(&self) -> FheType;
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

    fn fhe_type(&self) -> FheType {
        self.fhe_type()
    }

    fn digest(&self) -> Vec<u8> {
        self.digest.to_owned()
    }

    fn randomness(&self) -> Option<Vec<u8>> {
        None
    }
}

impl MetaResponse for DecryptionResponsePayload {
    fn shares_needed(&self) -> u32 {
        self.shares_needed
    }

    fn verification_key(&self) -> Vec<u8> {
        self.verification_key.to_owned()
    }

    fn fhe_type(&self) -> FheType {
        // TODO should be Result
        let plaintext: Plaintext = from_bytes(&self.plaintext).unwrap();
        plaintext.fhe_type
    }

    fn digest(&self) -> Vec<u8> {
        self.digest.to_owned()
    }

    fn randomness(&self) -> Option<Vec<u8>> {
        Some(self.randomness.to_owned())
    }
}

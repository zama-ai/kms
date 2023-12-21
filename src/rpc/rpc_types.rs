use serde::{de::Visitor, ser::Error, Deserialize, Deserializer, Serialize};
use serde_asn1_der::to_vec;
use std::fmt;
use tendermint::block::signed_header::SignedHeader;

use crate::{
    core::der_types::{PublicEncKey, PublicSigKey, Signature},
    kms::{
        DecryptionRequest, DecryptionRequestPayload, DecryptionResponsePayload, FheType, Proof,
        ReencryptionRequest, ReencryptionRequestPayload,
    },
};

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
    // TODO add digest of decrypted cipher
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
        if self.fhe_type == FheType::Euint8 {
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

impl serde::Serialize for Proof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // TODO use proper encoding
        let mut to_ser = Vec::new();
        to_ser.append(&mut self.height.to_be_bytes().to_vec());
        to_ser.append(&mut self.merkle_patricia_proof.to_vec());
        serializer.serialize_bytes(&to_ser)
    }
}

impl serde::Serialize for ReencryptionRequestPayload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // TODO use proper encoding
        let mut to_ser = Vec::new();
        to_ser.append(&mut self.verification_key.to_vec());
        to_ser.append(&mut self.enc_key.to_vec());
        to_ser.append(&mut to_vec(&self.proof).map_err(Error::custom)?);
        to_ser.append(&mut self.ciphertext.to_vec());
        let mut proof = to_vec(&self.proof).map_err(Error::custom)?;
        to_ser.append(&mut proof);
        to_ser.append(&mut self.randomness.to_vec());
        serializer.serialize_bytes(&to_ser)
    }
}

impl serde::Serialize for ReencryptionRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // TODO use proper encoding
        let mut to_ser = Vec::new();
        to_ser.append(&mut self.signature.to_vec());
        to_ser.append(&mut to_vec(&self.payload).map_err(Error::custom)?);
        serializer.serialize_bytes(&to_ser)
    }
}

impl serde::Serialize for DecryptionRequestPayload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // TODO use proper encoding
        let mut to_ser = Vec::new();
        to_ser.append(&mut self.verification_key.to_vec());
        to_ser.append(&mut to_vec(&self.proof).map_err(Error::custom)?);
        to_ser.append(&mut self.ciphertext.to_vec());
        let mut proof = to_vec(&self.proof).map_err(Error::custom)?;
        to_ser.append(&mut proof);
        to_ser.append(&mut self.randomness.to_vec());
        serializer.serialize_bytes(&to_ser)
    }
}

impl serde::Serialize for DecryptionRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // TODO use proper encoding
        let mut to_ser = Vec::new();
        to_ser.append(&mut self.signature.to_vec());
        to_ser.append(&mut to_vec(&self.payload).map_err(Error::custom)?);
        serializer.serialize_bytes(&to_ser)
    }
}

impl serde::Serialize for DecryptionResponsePayload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // TODO use proper encoding
        let mut to_ser = Vec::new();
        to_ser.append(&mut self.verification_key.to_vec());
        to_ser.append(&mut self.plaintext.to_vec());
        to_ser.append(&mut self.digest.to_vec());
        to_ser.append(&mut self.randomness.to_vec());
        serializer.serialize_bytes(&to_ser)
    }
}

impl serde::Serialize for FheType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Use i32 as this is what protobuf automates to
        serializer.serialize_bytes(&(*self as i32).to_be_bytes())
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
        // TODO fix potential panic
        let res_array: [u8; 4] = v.try_into().unwrap();
        let res_int: i32 = i32::from_be_bytes(res_array);
        Ok(FheType::try_from(res_int).unwrap())
    }
}

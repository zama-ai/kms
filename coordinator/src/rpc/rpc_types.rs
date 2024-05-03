use crate::anyhow_error_and_log;
use crate::kms::{
    DecryptionRequest, DecryptionResponsePayload, Eip712DomainMsg, FheType,
    ReencryptionRequestPayload, ReencryptionResponse,
};
use crate::{consts::ID_LENGTH, kms::RequestId};
use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{sol, Eip712Domain};
use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize};
use serde_asn1_der::from_bytes;
use std::fmt;
use wasm_bindgen::prelude::wasm_bindgen;

cfg_if::cfg_if! {
    if #[cfg(feature = "non-wasm")] {
        use crate::util::key_setup::FhePrivateKey;
        use crate::cryptography::der_types::{PublicEncKey, PublicSigKey, Signature};
        use crate::{cryptography::der_types::PrivateSigKey};
        use alloy_sol_types::SolStruct;
        use rand::{CryptoRng, RngCore};
    }
}

pub static CURRENT_FORMAT_VERSION: u32 = 1;

/// Enum which represents the different kinds of public information that can be stored as part of key generation.
/// In practice this means the CRS and different types of public keys.
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum PubDataType {
    PublicKey,
    ServerKey,
    SnsKey,
    CRS,
}

impl fmt::Display for PubDataType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PubDataType::PublicKey => write!(f, "PublicKey"),
            PubDataType::ServerKey => write!(f, "ServerKey"),
            PubDataType::SnsKey => write!(f, "SnsKey"),
            PubDataType::CRS => write!(f, "CRS"),
        }
    }
}

pub(crate) fn protobuf_to_alloy_domain(
    pb_domain: &Eip712DomainMsg,
) -> anyhow::Result<Eip712Domain> {
    let salt = if pb_domain.salt.is_empty() {
        None
    } else {
        Some(B256::from_slice(&pb_domain.salt))
    };
    let out = Eip712Domain::new(
        Some(pb_domain.name.clone().into()),
        Some(pb_domain.version.clone().into()),
        Some(
            U256::try_from_le_slice(&pb_domain.chain_id)
                .ok_or(anyhow_error_and_log("invalid chain ID"))?,
        ),
        Some(Address::parse_checksummed(
            pb_domain.verifying_contract.clone(),
            None,
        )?),
        salt,
    );
    Ok(out)
}

pub(crate) fn allow_to_protobuf_domain(domain: &Eip712Domain) -> anyhow::Result<Eip712DomainMsg> {
    let name = domain
        .name
        .as_ref()
        .ok_or(anyhow_error_and_log("missing domain name"))?
        .to_string();
    let version = domain
        .version
        .as_ref()
        .ok_or(anyhow_error_and_log("missing domain version"))?
        .to_string();
    let chain_id = domain
        .chain_id
        .ok_or(anyhow_error_and_log("missing domain chain_id"))?
        .to_le_bytes_vec();
    let verifying_contract = domain
        .verifying_contract
        .as_ref()
        .ok_or(anyhow_error_and_log("missing domain chain_id"))?
        .to_string();
    let salt = match domain.salt {
        Some(x) => x.to_vec(),
        None => vec![],
    };
    let domain_msg = Eip712DomainMsg {
        name,
        version,
        chain_id,
        verifying_contract,
        salt,
    };
    Ok(domain_msg)
}

#[cfg(feature = "non-wasm")]
pub trait BaseKms {
    fn verify_sig<T: Serialize + AsRef<[u8]>>(
        payload: &T,
        signature: &Signature,
        verification_key: &PublicSigKey,
    ) -> bool;
    fn verify_sig_eip712<T: SolStruct>(
        payload: &T,
        domain: &Eip712Domain,
        signature: &Signature,
        verification_key: &PublicSigKey,
    ) -> bool;
    fn sign<T: Serialize + AsRef<[u8]>>(&self, msg: &T) -> anyhow::Result<Signature>;
    fn sign_eip712<T: SolStruct>(
        &self,
        msg: &T,
        domain: &Eip712Domain,
    ) -> anyhow::Result<Signature>;
    fn get_verf_key(&self) -> PublicSigKey;
    fn digest<T: fmt::Debug + Serialize>(msg: &T) -> anyhow::Result<Vec<u8>>;
}
/// The [Kms] trait represents either a dummy KMS, an HSM, or an MPC network.
#[cfg(feature = "non-wasm")]
pub trait Kms: BaseKms {
    fn decrypt(
        client_key: &FhePrivateKey,
        ct: &[u8],
        fhe_type: FheType,
    ) -> anyhow::Result<Plaintext>;
    #[allow(clippy::too_many_arguments)]
    fn reencrypt(
        client_key: &FhePrivateKey,
        sig_key: &PrivateSigKey,
        rng: &mut (impl CryptoRng + RngCore),
        ct: &[u8],
        ct_type: FheType,
        digest_link: &[u8],
        enc_key: &PublicEncKey,
        pub_verf_key: &PublicSigKey,
    ) -> anyhow::Result<Vec<u8>>;
}

/// Representation of the data stored in a signcryption, needed to facilitate FHE decryption and
/// request linking
#[derive(Clone, Serialize, Deserialize, Hash, PartialEq, Eq, Debug)]
pub(crate) struct SigncryptionPayload {
    pub(crate) raw_decryption: RawDecryption,
    pub(crate) req_digest: Vec<u8>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RawDecryption {
    pub(crate) bytes: Vec<u8>,
    pub(crate) fhe_type: FheType,
}

#[cfg(feature = "non-wasm")]
impl RawDecryption {
    pub(crate) fn new(bytes: Vec<u8>, fhe_type: FheType) -> Self {
        Self { bytes, fhe_type }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct Plaintext {
    // Observe that the clunky representation is needed due to the wasm binding, which does not work with vectors or u128 elements directly
    pub lowest_bits: u64,
    pub middle_bits: u64,
    pub higest_bits: u32,
    fhe_type: FheType,
}

/// Little endian encoding to allow for easy serialization by allowing most significant bytes to be
/// 0
impl Plaintext {
    /// Make a new plaintext from a 128 bit integer
    pub fn new(value: u128, fhe_type: FheType) -> Self {
        if fhe_type == FheType::Euint160 {
            tracing::warn!("Trying to create plaintext of 160 bits from only 128 bits. Upper 32 bits will be set as 0");
        }
        let high = (value >> 64) as u64;
        let low = value as u64;
        Self {
            lowest_bits: low,
            middle_bits: high,
            higest_bits: 0,
            fhe_type,
        }
    }

    pub fn from_bool(value: bool) -> Self {
        let plaintext: u64 = match value {
            true => 1,
            false => 0,
        };
        Self {
            lowest_bits: plaintext,
            middle_bits: 0,
            higest_bits: 0,
            fhe_type: FheType::Bool,
        }
    }

    pub fn from_u4(value: u8) -> Self {
        Self {
            lowest_bits: value as u64,
            middle_bits: 0,
            higest_bits: 0,
            fhe_type: FheType::Euint4,
        }
    }

    pub fn from_u8(value: u8) -> Self {
        Self {
            lowest_bits: value as u64,
            middle_bits: 0,
            higest_bits: 0,
            fhe_type: FheType::Euint8,
        }
    }

    pub fn from_u16(value: u16) -> Self {
        Self {
            lowest_bits: value as u64,
            middle_bits: 0,
            higest_bits: 0,
            fhe_type: FheType::Euint16,
        }
    }

    pub fn from_u32(value: u32) -> Self {
        Self {
            lowest_bits: value as u64,
            middle_bits: 0,
            higest_bits: 0,
            fhe_type: FheType::Euint32,
        }
    }

    pub fn from_u64(value: u64) -> Self {
        Self {
            lowest_bits: value,
            middle_bits: 0,
            higest_bits: 0,
            fhe_type: FheType::Euint64,
        }
    }

    pub fn from_u128(value: u128) -> Self {
        let high = (value >> 64) as u64;
        let low = value as u64;
        Self {
            lowest_bits: low,
            middle_bits: high,
            higest_bits: 0,
            fhe_type: FheType::Euint128,
        }
    }

    // le encoding
    pub fn from_u160(value: tfhe::integer::U256) -> Self {
        let (low_128, high_128) = value.to_low_high_u128();
        let high_64 = (low_128 >> 64) as u64;
        let low_64 = low_128 as u64;
        Self {
            lowest_bits: low_64,
            middle_bits: high_64,
            higest_bits: high_128 as u32,
            fhe_type: FheType::Euint160,
        }
    }

    pub fn from_u160_low_high(value: (u128, u32)) -> Self {
        let high_64 = (value.0 >> 64) as u64;
        let low_64 = value.0 as u64;
        Self {
            lowest_bits: low_64,
            middle_bits: high_64,
            higest_bits: value.1,
            fhe_type: FheType::Euint160,
        }
    }

    pub fn as_bool(&self) -> bool {
        if self.fhe_type != FheType::Bool {
            tracing::warn!(
                "Plaintext is not of type u8. Returning the least significant bit as bool"
            );
        }
        self.lowest_bits % 2 == 1
    }

    pub fn as_u4(&self) -> u8 {
        if self.fhe_type != FheType::Euint4 {
            tracing::warn!("Plaintext is not of type u4. Returning the value modulo 16");
        }
        (self.lowest_bits % 16) as u8
    }

    pub fn as_u8(&self) -> u8 {
        if self.fhe_type != FheType::Euint8 {
            tracing::warn!("Plaintext is not of type u8. Returning the value modulo 256");
        }
        self.lowest_bits as u8
    }

    pub fn as_u16(&self) -> u16 {
        if self.fhe_type != FheType::Euint16 {
            tracing::warn!("Plaintext is not of type u16. Returning the value modulo 65536");
        }
        self.lowest_bits as u16
    }

    pub fn as_u32(&self) -> u32 {
        if self.fhe_type != FheType::Euint32 {
            tracing::warn!("Plaintext is not of type u32. Returning the value modulo 2^32");
        }
        self.lowest_bits as u32
    }
    pub fn as_u64(&self) -> u64 {
        if self.fhe_type != FheType::Euint64 {
            tracing::warn!("Plaintext is not of type u64. Returning the value modulo 2^64");
        }
        self.lowest_bits
    }

    pub fn as_u128(&self) -> u128 {
        if self.fhe_type != FheType::Euint128 {
            tracing::warn!("Plaintext is not of type u128. Returning the value modulo 2^128");
        }
        (self.lowest_bits as u128) + ((self.middle_bits as u128) << 64)
    }

    pub fn as_u160(&self) -> tfhe::integer::U256 {
        if self.fhe_type != FheType::Euint160 {
            tracing::warn!("Plaintext is not of type u160. Returning the value modulo 2^160");
        }
        let low_128 = (self.lowest_bits as u128) + ((self.middle_bits as u128) << 64);
        let high_128 = self.higest_bits as u128;
        tfhe::integer::U256::from((low_128, high_128))
    }

    pub fn fhe_type(&self) -> FheType {
        self.fhe_type
    }
}

impl From<Plaintext> for Vec<u8> {
    fn from(value: Plaintext) -> Self {
        match value.fhe_type {
            FheType::Bool => vec![(value.lowest_bits % 2) as u8],
            FheType::Euint4 => vec![(value.lowest_bits % 16) as u8],
            FheType::Euint8 => vec![value.lowest_bits as u8],
            FheType::Euint16 => value.lowest_bits.to_le_bytes()[0..2].to_vec(),
            FheType::Euint32 => value.lowest_bits.to_le_bytes()[0..4].to_vec(),
            FheType::Euint64 => value.lowest_bits.to_le_bytes().to_vec(),
            FheType::Euint128 => {
                let mut val = value.lowest_bits.to_le_bytes().to_vec();
                val.extend(value.middle_bits.to_le_bytes().to_vec());
                val
            }
            FheType::Euint160 => {
                let mut val = value.lowest_bits.to_le_bytes().to_vec();
                val.extend(value.middle_bits.to_le_bytes().to_vec());
                val.extend(value.higest_bits.to_le_bytes().to_vec());
                val
            }
        }
    }
}

impl TryFrom<RawDecryption> for Plaintext {
    type Error = anyhow::Error;

    fn try_from(value: RawDecryption) -> Result<Self, Self::Error> {
        match value.fhe_type {
            FheType::Bool => Ok(Plaintext::from_bool(value.bytes[0] % 2 == 1)),
            FheType::Euint4 => Ok(Plaintext::from_u4(value.bytes[0])),
            FheType::Euint8 => Ok(Plaintext::from_u8(value.bytes[0])),
            FheType::Euint16 => Ok(Plaintext::from_u16(u16::from_le_bytes(
                value.bytes[0..=1].try_into()?,
            ))),
            FheType::Euint32 => Ok(Plaintext::from_u32(u32::from_le_bytes(
                value.bytes[0..=3].try_into()?,
            ))),
            FheType::Euint64 => Ok(Plaintext::from_u64(u64::from_le_bytes(
                value.bytes[0..=7].try_into()?,
            ))),
            FheType::Euint128 => Ok(Plaintext::from_u128(u128::from_le_bytes(
                value.bytes[0..=15].try_into()?,
            ))),
            FheType::Euint160 => {
                let lower_bits = u128::from_le_bytes(value.bytes[0..=15].try_into()?);
                let higher_bits = u32::from_le_bytes(value.bytes[16..=19].try_into()?);
                Ok(Plaintext::from_u160_low_high((lower_bits, higher_bits)))
            }
        }
    }
}

// TODO these serializable types can be removed by using the type_attribute additions on protobuf
/// Observe that this seemingly redundant types are required since the Protobuf compiled types do
/// not implement the serializable and deserializable traits. Hence [DecryptionRequestSerializable]
/// implement data to be asn1 serialized and hashed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecryptionRequestSerializable {
    pub version: u32,
    pub servers_needed: u32,
    pub fhe_type: FheType,
    pub randomness: Vec<u8>,
    pub key_id: RequestId,
    pub ciphertext: Vec<u8>,
    pub request_id: RequestId,
}
impl From<DecryptionRequestSerializable> for DecryptionRequest {
    fn from(val: DecryptionRequestSerializable) -> DecryptionRequest {
        DecryptionRequest {
            version: val.version,
            servers_needed: val.servers_needed,
            fhe_type: val.fhe_type.into(),
            randomness: val.randomness,
            key_id: Some(val.key_id),
            ciphertext: val.ciphertext,
            request_id: Some(val.request_id),
        }
    }
}
impl TryFrom<DecryptionRequest> for DecryptionRequestSerializable {
    type Error = anyhow::Error;

    fn try_from(val: DecryptionRequest) -> Result<Self, Self::Error> {
        let (key_id, req_id) = match (val.key_id, val.request_id) {
            (Some(key_id), Some(req_id)) => (key_id, req_id),
            _ => return Err(anyhow::anyhow!("No request_id found")),
        };
        Ok(DecryptionRequestSerializable {
            version: val.version,
            servers_needed: val.servers_needed,
            fhe_type: val.fhe_type.try_into()?,
            randomness: val.randomness,
            ciphertext: val.ciphertext,
            key_id,
            request_id: req_id,
        })
    }
}

/// Observe that this seemingly redundant types are required since the Protobuf compiled types do
/// not implement the serializable and deserializable traits. Hence [DecryptionResponseSigPayload]
/// implement data to be asn1 serialized which will be signed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecryptionResponseSigPayload {
    pub version: u32,
    pub servers_needed: u32,
    pub verification_key: Vec<u8>,
    pub plaintext: Vec<u8>,
    pub digest: Vec<u8>,
}
impl From<DecryptionResponseSigPayload> for DecryptionResponsePayload {
    fn from(val: DecryptionResponseSigPayload) -> DecryptionResponsePayload {
        DecryptionResponsePayload {
            version: val.version,
            servers_needed: val.servers_needed,
            verification_key: val.verification_key,
            plaintext: val.plaintext,
            digest: val.digest,
        }
    }
}
impl From<DecryptionResponsePayload> for DecryptionResponseSigPayload {
    fn from(val: DecryptionResponsePayload) -> Self {
        DecryptionResponseSigPayload {
            version: val.version,
            servers_needed: val.servers_needed,
            verification_key: val.verification_key,
            plaintext: val.plaintext,
            digest: val.digest,
        }
    }
}

sol! {
    /// Observe that this seemingly redundant types are required since the Protobuf compiled types do
    /// not implement the serializable and deserializable traits. Hence [ReencryptionRequestSigPayload]
    /// implement data to be asn1 serialized which will be signed.
    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct ReencryptionRequestSigPayload {
        uint32 version;
        uint32 servers_needed;
        uint8[] verification_key;
        uint8[] enc_key;
        uint8 fhe_type;
        uint8[] randomness;
        uint8[] ciphertext;
        string key_id;
        string request_id;
    }
}
impl From<ReencryptionRequestSigPayload> for ReencryptionRequestPayload {
    fn from(val: ReencryptionRequestSigPayload) -> ReencryptionRequestPayload {
        ReencryptionRequestPayload {
            version: val.version,
            servers_needed: val.servers_needed,
            verification_key: val.verification_key,
            enc_key: val.enc_key,
            fhe_type: val.fhe_type.into(),
            randomness: val.randomness,
            ciphertext: val.ciphertext,
            key_id: Some(RequestId {
                request_id: val.key_id,
            }),
            request_id: Some(RequestId {
                request_id: val.request_id,
            }),
        }
    }
}
impl TryFrom<ReencryptionRequestPayload> for ReencryptionRequestSigPayload {
    type Error = anyhow::Error;

    fn try_from(val: ReencryptionRequestPayload) -> Result<Self, Self::Error> {
        Ok(ReencryptionRequestSigPayload {
            version: val.version,
            servers_needed: val.servers_needed,
            verification_key: val.verification_key,
            enc_key: val.enc_key,
            fhe_type: val.fhe_type.try_into()?,
            randomness: val.randomness,
            ciphertext: val.ciphertext,
            key_id: val
                .key_id
                .ok_or_else(|| anyhow_error_and_log("Key id missing in".to_string()))?
                .request_id,
            request_id: val
                .request_id
                .ok_or_else(|| anyhow_error_and_log("Request id is missing".to_string()))?
                .request_id,
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
    fn servers_needed(&self) -> u32;
    fn verification_key(&self) -> Vec<u8>;
    fn fhe_type(&self) -> anyhow::Result<FheType>;
    fn digest(&self) -> Vec<u8>;
}

impl MetaResponse for ReencryptionResponse {
    fn servers_needed(&self) -> u32 {
        self.servers_needed
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

    fn version(&self) -> u32 {
        self.version
    }
}

impl MetaResponse for DecryptionResponsePayload {
    fn servers_needed(&self) -> u32 {
        self.servers_needed
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

    fn version(&self) -> u32 {
        self.version
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.request_id)
    }
}

impl RequestId {
    /// Validates if a user-specified input is a request ID.
    ///
    /// By valid we mean it is a hex string of a static length. This is done to ensure it can be part of a valid
    /// path, without risk of path-traversal attacks in case the key request call is publicly accessible.
    pub fn is_valid(&self) -> bool {
        let hex = match hex::decode(self.to_string()) {
            Ok(hex) => hex,
            Err(_e) => {
                tracing::warn!("Input {} is not a hex string", &self.to_string());
                return false;
            }
        };
        if hex.len() != ID_LENGTH {
            tracing::warn!(
                "Hex value length is {}, but {} characters were expected",
                hex.len(),
                2 * ID_LENGTH
            );
            return false;
        }
        true
    }
}

impl From<RequestId> for u128 {
    // Should not panic if RequestId passed is_valid()
    fn from(value: RequestId) -> Self {
        let hex = hex::decode(value.to_string()).unwrap();
        // hex.len() should equal to ID_LENGTH, and ID_LENGTH >= 16
        let hex_truncated: [u8; 16] = hex[ID_LENGTH - 16..ID_LENGTH].try_into().unwrap();
        u128::from_be_bytes(hex_truncated)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::kms::RequestId;

    use super::{Plaintext, RawDecryption};
    use aes_prng::AesRng;
    use rand::{RngCore, SeedableRng};

    #[test]
    fn sunshine_plaintext_as_u160() {
        let mut rng = AesRng::seed_from_u64(1);
        let mut bytes = [0u8; 20];
        rng.fill_bytes(&mut bytes);

        let raw = RawDecryption::new(bytes.to_vec(), crate::kms::FheType::Euint160);
        let plaintext: Plaintext = raw.try_into().unwrap();
        // Check the value is greater than 2^128
        assert!(plaintext.as_u160() > tfhe::integer::U256::from((u128::MAX, 1)));
        // Sanitiy check the internal values
        assert_ne!(plaintext.lowest_bits, 0);
        assert_ne!(plaintext.middle_bits, 0);
        assert_ne!(plaintext.higest_bits, 0);
        assert_eq!(plaintext.fhe_type, crate::kms::FheType::Euint160);
        // Check consistent representations
        assert!(bytes[0] % 2 == plaintext.as_bool() as u8);
        assert_eq!(plaintext.as_u4(), bytes[0] % 16);
        assert_eq!(plaintext.as_u8(), bytes[0]);
        let u16_ref = u16::from_le_bytes(bytes[0..2].try_into().unwrap());
        assert_eq!(plaintext.as_u16(), u16_ref);
        let u32_ref = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        assert_eq!(plaintext.as_u32(), u32_ref);
        let u64_ref = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        assert_eq!(plaintext.as_u64(), u64_ref);
        let u128_ref = u128::from_le_bytes(bytes[0..16].try_into().unwrap());
        assert_eq!(plaintext.as_u128(), u128_ref);
    }

    #[test]
    fn idempotent_plaintext() {
        assert!(Plaintext::from_bool(true).as_bool());
        assert!(!Plaintext::from_bool(false).as_bool());
        assert_eq!(Plaintext::from_u4(3).as_u4(), 3);
        assert_eq!(Plaintext::from_u8(7).as_u4(), 7);
        assert_eq!(Plaintext::from_u16(65000).as_u16(), 65000);
        assert_eq!(Plaintext::from_u32(u32::MAX - 1).as_u32(), u32::MAX - 1);
        assert_eq!(Plaintext::from_u64(u64::MAX - 1).as_u64(), u64::MAX - 1);
        assert_eq!(Plaintext::from_u128(u128::MAX - 1).as_u128(), u128::MAX - 1);
        let alt_u128_plaintext = Plaintext::new(u128::MAX - 1, crate::kms::FheType::Euint128);
        assert_eq!(Plaintext::from_u128(u128::MAX - 1), alt_u128_plaintext);
        let u160_val = tfhe::integer::U256::from((u128::MAX, 1000));
        assert_eq!(Plaintext::from_u160(u160_val).as_u160(), u160_val);
        let alt_u160_val = Plaintext::from_u160_low_high((u128::MAX, 1000));
        assert_eq!(Plaintext::from_u160(u160_val), alt_u160_val);
    }

    #[test]
    fn plaintext_raw_decryption_conversion() {
        let mut rng = AesRng::seed_from_u64(2);
        let mut bytes = [0u8; 20];
        rng.fill_bytes(&mut bytes);

        let bool_raw = RawDecryption::new(bytes.to_vec(), crate::kms::FheType::Bool);
        let bool_plaintext: Plaintext = bool_raw.try_into().unwrap();
        let bool_vec: Vec<u8> = bool_plaintext.into();
        assert_eq!(bool_vec, vec![bytes[0] % 2]);

        let u4_raw = RawDecryption::new(bytes.to_vec(), crate::kms::FheType::Euint4);
        let u4_plaintext: Plaintext = u4_raw.try_into().unwrap();
        let u4_vec: Vec<u8> = u4_plaintext.into();
        assert_eq!(u4_vec, vec![bytes[0] % 16]);

        let u8_raw = RawDecryption::new(bytes.to_vec(), crate::kms::FheType::Euint8);
        let u8_plaintext: Plaintext = u8_raw.try_into().unwrap();
        let u8_vec: Vec<u8> = u8_plaintext.into();
        assert_eq!(u8_vec, vec![bytes[0]]);

        let u16_raw = RawDecryption::new(bytes.to_vec(), crate::kms::FheType::Euint16);
        let u16_plaintext: Plaintext = u16_raw.try_into().unwrap();
        let u16_vec: Vec<u8> = u16_plaintext.into();
        assert_eq!(u16_vec, vec![bytes[0], bytes[1]]);

        let u32_raw = RawDecryption::new(bytes.to_vec(), crate::kms::FheType::Euint32);
        let u32_plaintext: Plaintext = u32_raw.try_into().unwrap();
        let u32_vec: Vec<u8> = u32_plaintext.into();
        assert_eq!(u32_vec, vec![bytes[0], bytes[1], bytes[2], bytes[3]]);

        let u64_raw = RawDecryption::new(bytes.to_vec(), crate::kms::FheType::Euint64);
        let u64_plaintext: Plaintext = u64_raw.try_into().unwrap();
        let u64_vec: Vec<u8> = u64_plaintext.into();
        assert_eq!(
            u64_vec,
            vec![bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]]
        );

        let u128_raw = RawDecryption::new(bytes.to_vec(), crate::kms::FheType::Euint128);
        let u128_plaintext: Plaintext = u128_raw.try_into().unwrap();
        let u128_vec: Vec<u8> = u128_plaintext.into();
        assert_eq!(
            u128_vec,
            vec![
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                bytes[15]
            ]
        );

        let u160_raw = RawDecryption::new(bytes.to_vec(), crate::kms::FheType::Euint160);
        let u160_plaintext: Plaintext = u160_raw.try_into().unwrap();
        let u160_vec: Vec<u8> = u160_plaintext.into();
        assert_eq!(u160_vec, bytes);
    }

    #[test]
    fn test_request_id_convert() {
        let request_id = RequestId {
            request_id: "0000000000000000000000000000000000000001".to_owned(),
        };
        assert!(request_id.is_valid());
        let x: u128 = request_id.into();
        assert_eq!(x, 1);
    }
}

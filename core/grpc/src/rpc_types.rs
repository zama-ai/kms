use crate::kms::v1::{
    DecryptionResponsePayload, Eip712DomainMsg, FheType, RequestId, TypedPlaintext,
};
use crate::kms::v1::{ReencryptionResponsePayload, SignedPubDataHandle};
use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::Eip712Domain;
use anyhow::anyhow;
use bincode::serialize;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::fmt;
use strum_macros::EnumIter;
use tfhe::integer::bigint::StaticUnsignedBigInt;
use tfhe::named::Named;
use tfhe::shortint::ClassicPBSParameters;
use tfhe::Versionize;
use tfhe_versionable::VersionsDispatch;

lazy_static::lazy_static! {
    // The static ID we will use for the signing key for each of the MPC parties.
    // We do so, since there is ever only one conceptual signing key per party (at least for now).
    // This is a bit hackish, but it works for now.
    pub static ref SIGNING_KEY_ID: RequestId = RequestId::derive("SIGNING_KEY_ID").unwrap();
}

cfg_if::cfg_if! {
    if #[cfg(feature = "non-wasm")] {
        use alloy_sol_types::SolStruct;

        const ERR_CLIENT_ADDR_EQ_CONTRACT_ADDR: &str =
            "client address is the same as verifying contract address";
        const ERR_DOMAIN_NOT_FOUND: &str = "domain not found";
        const ERR_VERIFYING_CONTRACT_NOT_FOUND: &str = "verifying contract not found";
        const ERR_THERE_ARE_NO_HANDLES: &str = "there are no handles";
    }
}

pub const ID_LENGTH: usize = 32;
pub const SAFE_SER_SIZE_LIMIT: u64 = 1024 * 1024 * 1024 * 2;

pub static KEY_GEN_REQUEST_NAME: &str = "key_gen_request";
pub static CRS_GEN_REQUEST_NAME: &str = "crs_gen_request";
pub static DEC_REQUEST_NAME: &str = "dec_request";
pub static REENC_REQUEST_NAME: &str = "reenc_request";

alloy_sol_types::sol! {
    struct UserDecryptionResult {
        bytes publicKey;
        uint256[] handles;
        bytes reencryptedShare;
    }
}

// This is used internally to link a request and a response.
alloy_sol_types::sol! {
    struct UserDecryptionLinker {
        bytes publicKey;
        uint256[] handles;
        address userAddress;
    }
}

// Solidity struct for decryption result signature
// Struct needs to match what is in
// https://github.com/zama-ai/gateway-l2/blob/main/contracts/DecryptionManager.sol#L18
// and the name must be what is defined under `EIP712_PUBLIC_DECRYPT_TYPE`
alloy_sol_types::sol! {
    struct EIP712PublicDecrypt {
        uint256[] handlesList;
        bytes decryptedResult;
    }
}

// Solidity struct for signing the FHE public key
alloy_sol_types::sol! {
    struct FhePubKey {
        bytes pubkey;
    }
}

// Solidity struct for signing the FHE server key
alloy_sol_types::sol! {
    struct FheServerKey {
        bytes server_key;
    }
}

// Solidity struct for signing the CRS
alloy_sol_types::sol! {
    struct CRS {
        bytes crs;
    }
}

// Solidity struct for signing the SnsKey
alloy_sol_types::sol! {
    struct SnsKey {
        bytes sns_key;
    }
}

pub fn protobuf_to_alloy_domain_option(
    domain_ref: Option<&Eip712DomainMsg>,
) -> Option<Eip712Domain> {
    if let Some(domain) = domain_ref {
        match protobuf_to_alloy_domain(domain) {
            Ok(domain) => Some(domain),
            Err(e) => {
                tracing::warn!(
                    "Could not turn domain to alloy: {:?}. Error: {:?}. Returning None.",
                    domain,
                    e
                );
                None
            }
        }
    } else {
        None
    }
}

pub fn protobuf_to_alloy_domain(pb_domain: &Eip712DomainMsg) -> anyhow::Result<Eip712Domain> {
    // any salt that has the wrong length will result in an error
    let salt = pb_domain
        .salt
        .as_ref()
        .map(|inner_salt| B256::try_from(inner_salt.as_slice()))
        .map_or(Ok(None), |v| v.map(Some))?;
    let out = Eip712Domain::new(
        Some(pb_domain.name.clone().into()),
        Some(pb_domain.version.clone().into()),
        Some(
            U256::try_from_be_slice(&pb_domain.chain_id)
                .ok_or_else(|| anyhow::anyhow!("invalid chain ID"))?,
        ),
        Some(Address::parse_checksummed(
            pb_domain.verifying_contract.clone(),
            None,
        )?),
        salt,
    );
    Ok(out)
}

pub fn alloy_to_protobuf_domain(domain: &Eip712Domain) -> anyhow::Result<Eip712DomainMsg> {
    let name = domain
        .name
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing domain name"))?
        .to_string();
    let version = domain
        .version
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing domain version"))?
        .to_string();
    let chain_id = domain
        .chain_id
        .ok_or_else(|| anyhow::anyhow!("missing domain chain_id"))?
        .to_be_bytes_vec();
    let verifying_contract = domain
        .verifying_contract
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing domain chain_id"))?
        .to_string();
    let domain_msg = Eip712DomainMsg {
        name,
        version,
        chain_id,
        verifying_contract,
        salt: domain.salt.map(|x| x.to_vec()),
    };
    Ok(domain_msg)
}

/// Compute the SHA3-256 has of an element. Returns the hash as a vector of bytes.
pub fn hash_element<T>(element: &T) -> Vec<u8>
where
    T: ?Sized + AsRef<[u8]>,
{
    // Use of SHA3 to stay as much as possible with current NIST standards
    let mut hasher = Sha3_256::new();
    hasher.update(element.as_ref());
    let digest = hasher.finalize();
    digest.to_vec()
}

/// Serialize an element and hash it using SHA3-256. Returns the hash as a vector of bytes.
pub fn serialize_hash_element<T>(msg: &T) -> anyhow::Result<Vec<u8>>
where
    T: Serialize,
{
    let to_hash = match serialize(msg) {
        Ok(to_hash) => to_hash,
        Err(e) => {
            anyhow::bail!("Could not encode message due to error: {:?}", e);
        }
    };
    Ok(hash_element(&to_hash))
}

#[cfg(feature = "non-wasm")]
pub fn safe_serialize_hash_element_versioned<T>(msg: &T) -> anyhow::Result<Vec<u8>>
where
    T: Serialize + tfhe::Versionize + tfhe::named::Named,
{
    let mut buf = Vec::new();
    match tfhe::safe_serialization::safe_serialize(msg, &mut buf, SAFE_SER_SIZE_LIMIT) {
        Ok(()) => Ok(hash_element(&buf)),
        Err(e) => anyhow::bail!("Could not encode message due to error: {:?}", e),
    }
}

/// The format of what will be stored, and returned in gRPC, as a result of CRS generation in the KMS
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, VersionsDispatch)]
pub enum SignedPubDataHandleInternalVersioned {
    V0(SignedPubDataHandleInternal),
}

/// This type is the internal type that corresponds to
/// the generate protobuf type `SignedPubDataHandle`.
///
/// It's needed because we are not able to derive versioned
/// for the protobuf type.
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(SignedPubDataHandleInternalVersioned)]
pub struct SignedPubDataHandleInternal {
    // Digest (the 256-bit hex-encoded value, computed using compute_info/handle)
    pub key_handle: String,
    // The signature on the handle
    pub signature: Vec<u8>,
    // The signature on the key for the external recipient
    // (e.g. using EIP712 for the fhevm)
    pub external_signature: Vec<u8>,
}

impl Named for SignedPubDataHandleInternal {
    const NAME: &'static str = "SignedPubDataHandleInternal";
}

impl SignedPubDataHandleInternal {
    pub fn new(
        key_handle: String,
        signature: Vec<u8>,
        external_signature: Vec<u8>,
    ) -> SignedPubDataHandleInternal {
        SignedPubDataHandleInternal {
            key_handle,
            signature,
            external_signature,
        }
    }
}

impl From<SignedPubDataHandle> for SignedPubDataHandleInternal {
    fn from(handle: SignedPubDataHandle) -> Self {
        SignedPubDataHandleInternal {
            key_handle: handle.key_handle,
            signature: handle.signature,
            external_signature: handle.external_signature,
        }
    }
}
impl From<SignedPubDataHandleInternal> for SignedPubDataHandle {
    fn from(crs: SignedPubDataHandleInternal) -> Self {
        SignedPubDataHandle {
            key_handle: crs.key_handle,
            signature: crs.signature,
            external_signature: crs.external_signature,
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, VersionsDispatch)]
pub enum PubDataTypeVersioned {
    V0(PubDataType),
}

/// PubDataType
///
/// Enum which represents the different kinds of public information that can be stored as part of
/// key generation. In practice this means the CRS and different types of public keys.
/// Data of this type is supposed to be readable by anyone on the internet
/// and stored on a medium that _may_ be suseptible to malicious modifications.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, EnumIter, Versionize)]
#[versionize(PubDataTypeVersioned)]
pub enum PubDataType {
    PublicKey,
    PublicKeyMetadata,
    ServerKey,
    SnsKey,
    CRS,
    VerfKey,     // Type for the servers public verification keys
    VerfAddress, // The ethereum address of the KMS core, needed for KMS signature verification
    DecompressionKey,
}

impl fmt::Display for PubDataType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PubDataType::PublicKey => write!(f, "PublicKey"),
            PubDataType::PublicKeyMetadata => write!(f, "PublicKeyMetadata"),
            PubDataType::ServerKey => write!(f, "ServerKey"),
            PubDataType::SnsKey => write!(f, "SnsKey"),
            PubDataType::CRS => write!(f, "CRS"),
            PubDataType::VerfKey => write!(f, "VerfKey"),
            PubDataType::VerfAddress => write!(f, "VerfAddress"),
            PubDataType::DecompressionKey => write!(f, "DecompressionKey"),
        }
    }
}

/// PrivDataType
///
/// Enum which represents the different kinds of private information that can be stored as part of
/// running the KMS. In practice this means the signing key, public key and CRS meta data and
/// signatures. Data of this type is supposed to only be readable, writable and modifiable by a
/// single entity and stored on a medium that is not readable, writable or modifiable by any other
/// entity (without detection).
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, EnumIter)]
pub enum PrivDataType {
    SigningKey,
    FheKeyInfo,
    CrsInfo,
    FhePrivateKey, // Only used for the centralized case
    PrssSetup,
}

impl fmt::Display for PrivDataType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PrivDataType::FheKeyInfo => write!(f, "FheKeyInfo"),
            PrivDataType::SigningKey => write!(f, "SigningKey"),
            PrivDataType::CrsInfo => write!(f, "CrsInfo"),
            PrivDataType::FhePrivateKey => write!(f, "FhePrivateKey"),
            PrivDataType::PrssSetup => write!(f, "PrssSetup"),
        }
    }
}

#[cfg(feature = "non-wasm")]
impl TryFrom<u8> for FheType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(FheType::Ebool),
            1 => Ok(FheType::Euint4),
            2 => Ok(FheType::Euint8),
            3 => Ok(FheType::Euint16),
            4 => Ok(FheType::Euint32),
            5 => Ok(FheType::Euint64),
            6 => Ok(FheType::Euint128),
            7 => Ok(FheType::Euint160),
            8 => Ok(FheType::Euint256),
            9 => Ok(FheType::Euint512),
            10 => Ok(FheType::Euint1024),
            11 => Ok(FheType::Euint2048),
            _ => Err(anyhow::anyhow!(
                "Trying to import FheType from unsupported value"
            )),
        }
    }
}

#[cfg(feature = "non-wasm")]
impl TryFrom<String> for FheType {
    type Error = anyhow::Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "Ebool" => Ok(FheType::Ebool),
            "Euint4" => Ok(FheType::Euint4),
            "Euint8" => Ok(FheType::Euint8),
            "Euint16" => Ok(FheType::Euint16),
            "Euint32" => Ok(FheType::Euint32),
            "Euint64" => Ok(FheType::Euint64),
            "Euint128" => Ok(FheType::Euint128),
            "Euint160" => Ok(FheType::Euint160),
            "Euint256" => Ok(FheType::Euint256),
            "Euint512" => Ok(FheType::Euint512),
            "Euint1024" => Ok(FheType::Euint1024),
            "Euint2048" => Ok(FheType::Euint2048),
            _ => Err(anyhow::anyhow!(
                "Trying to import FheType from unsupported value"
            )),
        }
    }
}

impl FheType {
    /// Calculates the number of blocks needed to encode a message of the given FHE
    /// type, based on the usable message modulus log from the
    /// parameters. Rounds up to ensure enough blocks.
    ///
    /// The values might need to be adjusted if we use more than what's available
    /// in the message modulus.
    pub fn to_num_blocks(&self, params: &ClassicPBSParameters) -> usize {
        match self {
            FheType::Ebool => 1_usize.div_ceil(params.message_modulus.0.ilog2() as usize),
            FheType::Euint4 => 4_usize.div_ceil(params.message_modulus.0.ilog2() as usize),
            FheType::Euint8 => 8_usize.div_ceil(params.message_modulus.0.ilog2() as usize),
            FheType::Euint16 => 16_usize.div_ceil(params.message_modulus.0.ilog2() as usize),
            FheType::Euint32 => 32_usize.div_ceil(params.message_modulus.0.ilog2() as usize),
            FheType::Euint64 => 64_usize.div_ceil(params.message_modulus.0.ilog2() as usize),
            FheType::Euint128 => 128_usize.div_ceil(params.message_modulus.0.ilog2() as usize),
            FheType::Euint160 => 160_usize.div_ceil(params.message_modulus.0.ilog2() as usize),
            FheType::Euint256 => 256_usize.div_ceil(params.message_modulus.0.ilog2() as usize),
            FheType::Euint512 => 512_usize.div_ceil(params.message_modulus.0.ilog2() as usize),
            FheType::Euint1024 => 1024_usize.div_ceil(params.message_modulus.0.ilog2() as usize),
            FheType::Euint2048 => 2048_usize.div_ceil(params.message_modulus.0.ilog2() as usize),
        }
    }
}

/// Representation of the data stored in a signcryption,
/// needed to facilitate FHE decryption and request linking.
/// The result is linked to some byte array.
#[derive(Clone, Serialize, Deserialize, Hash, PartialEq, Eq, Debug)]
pub struct SigncryptionPayload {
    pub plaintext: TypedPlaintext,
    pub link: Vec<u8>,
}

#[cfg(feature = "non-wasm")]
impl crate::kms::v1::ReencryptionRequest {
    /// The only information we can use is userAddress, the handles and public key
    /// because these are the only information available
    /// to the user *and* to the KMS.
    /// So we can only use these information to link the request and the response.
    pub fn compute_link_checked(&self) -> anyhow::Result<(Vec<u8>, alloy_sol_types::Eip712Domain)> {
        let domain = protobuf_to_alloy_domain(
            self.domain
                .as_ref()
                .ok_or_else(|| anyhow!(ERR_DOMAIN_NOT_FOUND))?,
        )?;

        let handles = self
            .typed_ciphertexts
            .iter()
            .map(|x| alloy_primitives::U256::from_be_slice(&x.external_handle))
            .collect::<Vec<_>>();

        if handles.is_empty() {
            anyhow::bail!(ERR_THERE_ARE_NO_HANDLES);
        }

        let client_address =
            alloy_primitives::Address::parse_checksummed(&self.client_address, None)?;
        let verifying_contract = domain
            .verifying_contract
            .ok_or(anyhow::anyhow!(ERR_VERIFYING_CONTRACT_NOT_FOUND))?;

        if client_address == verifying_contract {
            anyhow::bail!(ERR_CLIENT_ADDR_EQ_CONTRACT_ADDR);
        }

        let linker = UserDecryptionLinker {
            publicKey: self.enc_key.clone().into(),
            handles,
            userAddress: client_address,
        };

        let link = linker.eip712_signing_hash(&domain).to_vec();

        Ok((link, domain))
    }
}

/// returns a slice of the first N bytes of the vector, padding with zeros if the vector is too short
fn sub_slice<const N: usize>(vec: &[u8]) -> [u8; N] {
    // Get a slice of the first len bytes, if available
    let bytes = if vec.len() >= N { &vec[..N] } else { vec };

    // Pad with zeros if the slice is shorter than N bytes
    let padded: [u8; N] = match bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            let mut temp = [0u8; N];
            temp[..bytes.len()].copy_from_slice(bytes);
            temp
        }
    };
    padded
}

/// Little endian encoding for easy serialization by allowing most significant bytes to be 0
impl TypedPlaintext {
    /// Make a new plaintext from a 128 bit integer
    pub fn new(value: u128, fhe_type: FheType) -> Self {
        if fhe_type == FheType::Euint160
            || fhe_type == FheType::Euint256
            || fhe_type == FheType::Euint512
            || fhe_type == FheType::Euint1024
            || fhe_type == FheType::Euint2048
        {
            tracing::warn!(
                "Trying to create larger plaintext from only 128 bits. Upper bits will be set to 0."
            );
        }
        Self {
            bytes: value.to_le_bytes().to_vec(),
            fhe_type: fhe_type.into(),
        }
    }

    pub fn from_bytes(bytes: Vec<u8>, fhe_type: impl Into<FheType>) -> Self {
        // TODO need to make sure we have enough bytes for the type
        Self {
            bytes,
            fhe_type: (fhe_type.into() as FheType) as i32,
        }
    }

    pub fn from_bool(value: bool) -> Self {
        let plaintext: u8 = match value {
            true => 1,
            false => 0,
        };
        Self {
            bytes: vec![plaintext],
            fhe_type: FheType::Ebool as i32,
        }
    }

    pub fn from_u4(value: u8) -> Self {
        Self {
            bytes: vec![value % 16],
            fhe_type: FheType::Euint4 as i32,
        }
    }

    pub fn from_u8(value: u8) -> Self {
        Self {
            bytes: vec![value],
            fhe_type: FheType::Euint8 as i32,
        }
    }

    pub fn from_u16(value: u16) -> Self {
        Self {
            bytes: value.to_le_bytes().to_vec(),
            fhe_type: FheType::Euint16 as i32,
        }
    }

    pub fn from_u32(value: u32) -> Self {
        Self {
            bytes: value.to_le_bytes().to_vec(),
            fhe_type: FheType::Euint32 as i32,
        }
    }

    pub fn from_u64(value: u64) -> Self {
        Self {
            bytes: value.to_le_bytes().to_vec(),
            fhe_type: FheType::Euint64 as i32,
        }
    }

    pub fn from_u128(value: u128) -> Self {
        Self {
            bytes: value.to_le_bytes().to_vec(),
            fhe_type: FheType::Euint128 as i32,
        }
    }

    pub fn from_u160(value: tfhe::integer::U256) -> Self {
        let (low_128, high_128) = value.to_low_high_u128();
        let mut bytes = low_128.to_le_bytes().to_vec();
        bytes.extend(high_128.to_le_bytes()[0..4].to_vec());
        Self {
            bytes,
            fhe_type: FheType::Euint160 as i32,
        }
    }

    pub fn from_u160_low_high(value: (u128, u32)) -> Self {
        let mut bytes = value.0.to_le_bytes().to_vec();
        bytes.extend(value.1.to_le_bytes().to_vec());
        Self {
            bytes,
            fhe_type: FheType::Euint160 as i32,
        }
    }

    pub fn from_u256(value: tfhe::integer::U256) -> Self {
        let (low_128, high_128) = value.to_low_high_u128();
        let mut bytes = low_128.to_le_bytes().to_vec();
        bytes.extend(high_128.to_le_bytes().to_vec());
        Self {
            bytes,
            fhe_type: FheType::Euint256 as i32,
        }
    }

    pub fn from_u512(value: StaticUnsignedBigInt<8>) -> TypedPlaintext {
        let mut bytes = vec![0_u8; 64];
        value.copy_to_le_byte_slice(&mut bytes);
        TypedPlaintext {
            bytes,
            fhe_type: FheType::Euint512 as i32,
        }
    }

    pub fn from_u1024(value: StaticUnsignedBigInt<16>) -> TypedPlaintext {
        let mut bytes = vec![0_u8; 128];
        value.copy_to_le_byte_slice(&mut bytes);
        TypedPlaintext {
            bytes,
            fhe_type: FheType::Euint1024 as i32,
        }
    }

    pub fn from_u2048(value: tfhe::integer::bigint::U2048) -> Self {
        let mut bytes = [0u8; 256];
        value.copy_to_le_byte_slice(&mut bytes);
        Self {
            bytes: bytes.to_vec(),
            fhe_type: FheType::Euint2048 as i32,
        }
    }

    pub fn as_bool(&self) -> bool {
        if self.fhe_type() != FheType::Ebool {
            tracing::warn!(
                "Plaintext is not of type Bool or has more than 1 Byte. Returning the least significant bit as Bool"
            );
        }
        if self.bytes[0] > 1 {
            tracing::warn!("Plaintext should be Bool (0 or 1), but was bigger ({}). Returning the least significant bit as Bool.", self.bytes[0]);
        }
        self.bytes[0] % 2 == 1
    }

    pub fn as_u4(&self) -> u8 {
        if self.fhe_type() != FheType::Euint4 {
            tracing::warn!("Plaintext is not of type u4. Returning the value modulo 16");
        }
        if self.bytes[0] > 15 {
            tracing::warn!(
                "Plaintext should be u4, but was bigger ({}). Returning the value modulo 16.",
                self.bytes[0]
            );
        }
        self.bytes[0] % 16
    }

    pub fn as_u8(&self) -> u8 {
        if self.fhe_type() != FheType::Euint8 {
            tracing::warn!("Plaintext is not of type u8. Returning the value modulo 256");
        }
        if self.bytes.len() != 1 {
            tracing::warn!("U8 Plaintext should have 1 Byte, but was bigger ({} Bytes). Returning the least significant Byte", self.bytes.len());
        }
        self.bytes[0]
    }

    pub fn as_u16(&self) -> u16 {
        if self.fhe_type() != FheType::Euint16 {
            tracing::warn!("Plaintext is not of type u16. Returning the value modulo 65536 or padding with leading zeros");
        }
        if self.bytes.len() != 2 {
            tracing::warn!("U16 Plaintext should have 2 Bytes, but was not ({} Bytes). Truncating/Padding to 2 Bytes", self.bytes.len());
        }
        u16::from_le_bytes(sub_slice::<2>(&self.bytes))
    }

    pub fn as_u32(&self) -> u32 {
        if self.fhe_type() != FheType::Euint32 {
            tracing::warn!("Plaintext is not of type u32. Returning the value modulo 2^32 or padding with leading zeros");
        }
        if self.bytes.len() != 4 {
            tracing::warn!("U32 Plaintext should have 4 Bytes, but was not ({} Bytes). Truncating/Padding to 4 Bytes", self.bytes.len());
        }
        u32::from_le_bytes(sub_slice::<4>(&self.bytes))
    }
    pub fn as_u64(&self) -> u64 {
        if self.fhe_type() != FheType::Euint64 {
            tracing::warn!("Plaintext is not of type u64. Returning the value modulo 2^64 or padding with leading zeros");
        }
        if self.bytes.len() != 8 {
            tracing::warn!("U64 Plaintext should have 8 Bytes, but was not ({} Bytes). Truncating/Padding to 8 Bytes", self.bytes.len());
        }
        u64::from_le_bytes(sub_slice::<8>(&self.bytes))
    }

    pub fn as_u128(&self) -> u128 {
        if self.fhe_type() != FheType::Euint128 {
            tracing::warn!("Plaintext is not of type u128. Returning the value modulo 2^128 or padding with leading zeros");
        }
        if self.bytes.len() != 16 {
            tracing::warn!("U128 Plaintext should have 16 Bytes, but was not ({} Bytes). Truncating/Padding to 16 Bytes", self.bytes.len());
        }
        u128::from_le_bytes(sub_slice::<16>(&self.bytes))
    }

    pub fn as_u160(&self) -> tfhe::integer::U256 {
        if self.fhe_type() != FheType::Euint160 {
            tracing::warn!("Plaintext is not of type u160. Returning the value modulo 2^160 or padding with leading zeros");
        }
        if self.bytes.len() != 20 {
            tracing::warn!("U160 Plaintext should have 20 Bytes, but was not ({} Bytes). Truncating/Padding to 20 Bytes", self.bytes.len());
        }
        let slice = sub_slice::<20>(&self.bytes);
        let low_128 = u128::from_le_bytes(
            slice[0..16]
                .try_into()
                .expect("error converting slice to u160"),
        );
        let high_128 = u32::from_le_bytes(
            slice[16..20]
                .try_into()
                .expect("error converting slice to u160"),
        );
        tfhe::integer::U256::from((low_128, high_128 as u128))
    }

    pub fn as_u256(&self) -> tfhe::integer::U256 {
        if self.fhe_type() != FheType::Euint256 {
            tracing::warn!("Plaintext is not of type u256. Returning the value modulo 2^256 or padding with leading zeros");
        }
        if self.bytes.len() != 32 {
            tracing::warn!("U256 Plaintext should have 32 Bytes, but was not ({} Bytes). Truncating/Padding to 32 Bytes", self.bytes.len());
        }
        let slice = sub_slice::<32>(&self.bytes);
        let low_128 = u128::from_le_bytes(
            slice[0..16]
                .try_into()
                .expect("error converting slice to u256"),
        );
        let high_128 = u128::from_le_bytes(
            slice[16..32]
                .try_into()
                .expect("error converting slice to u256"),
        );
        tfhe::integer::U256::from((low_128, high_128))
    }

    pub fn as_u512(&self) -> tfhe::integer::U512 {
        if self.fhe_type() != FheType::Euint512 {
            tracing::warn!("Plaintext is not of type u512. Returning the value modulo 2^512 or padding with leading zeros");
        }
        if self.bytes.len() != 64 {
            tracing::warn!("U512 Plaintext should have 64 Bytes, but was not ({} Bytes). Truncating/Padding to 64 Bytes", self.bytes.len());
        }
        let slice = sub_slice::<64>(&self.bytes);
        let mut value = tfhe::integer::bigint::U512::default();
        tfhe::integer::bigint::U512::copy_from_le_byte_slice(&mut value, &slice);
        value
    }

    pub fn as_u1024(&self) -> tfhe::integer::bigint::U1024 {
        if self.fhe_type() != FheType::Euint1024 {
            tracing::warn!("Plaintext is not of type u1024. Returning the value modulo 2^1024 or padding with leading zeros");
        }
        if self.bytes.len() != 128 {
            tracing::warn!("U1024 Plaintext should have 128 Bytes, but was not ({} Bytes). Truncating/Padding to 128 Bytes", self.bytes.len());
        }
        let slice = sub_slice::<128>(&self.bytes);
        let mut value = tfhe::integer::bigint::U1024::default();
        tfhe::integer::bigint::U1024::copy_from_le_byte_slice(&mut value, &slice);
        value
    }

    pub fn as_u2048(&self) -> tfhe::integer::bigint::U2048 {
        if self.fhe_type() != FheType::Euint2048 {
            tracing::warn!("Plaintext is not of type u2048. Returning the value modulo 2^2048 or padding with leading zeros");
        }
        if self.bytes.len() != 256 {
            tracing::warn!("U256 Plaintext should have 256 Bytes, but was not ({} Bytes). Truncating/Padding to 256 Bytes", self.bytes.len());
        }
        let slice = sub_slice::<256>(&self.bytes);
        let mut value = tfhe::integer::bigint::U2048::default();
        tfhe::integer::bigint::U2048::copy_from_le_byte_slice(&mut value, &slice);
        value
    }
}

impl From<TypedPlaintext> for FheType {
    fn from(value: TypedPlaintext) -> Self {
        value.fhe_type()
    }
}

impl From<TypedPlaintext> for Vec<u8> {
    fn from(value: TypedPlaintext) -> Self {
        match value.fhe_type() {
            FheType::Ebool => vec![value.bytes[0] % 2],
            FheType::Euint4 => vec![value.bytes[0] % 16],
            FheType::Euint8 => vec![value.bytes[0]],
            FheType::Euint16 => value.bytes[0..2].to_vec(),
            FheType::Euint32 => value.bytes[0..4].to_vec(),
            FheType::Euint64 => value.bytes[0..8].to_vec(),
            FheType::Euint128 => value.bytes[0..16].to_vec(),
            FheType::Euint160 => value.bytes[0..20].to_vec(),
            FheType::Euint256 => value.bytes[0..32].to_vec(),
            FheType::Euint512 => value.bytes[0..64].to_vec(),
            FheType::Euint1024 => value.bytes[0..128].to_vec(),
            FheType::Euint2048 => value.bytes[0..256].to_vec(),
        }
    }
}

impl From<u128> for TypedPlaintext {
    fn from(value: u128) -> Self {
        Self::from_u128(value)
    }
}

impl From<u64> for TypedPlaintext {
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

impl From<u32> for TypedPlaintext {
    fn from(value: u32) -> Self {
        Self::from_u32(value)
    }
}

impl From<u16> for TypedPlaintext {
    fn from(value: u16) -> Self {
        Self::from_u16(value)
    }
}

impl From<u8> for TypedPlaintext {
    fn from(value: u8) -> Self {
        Self::from_u8(value)
    }
}

impl From<bool> for TypedPlaintext {
    fn from(value: bool) -> Self {
        Self::from_bool(value)
    }
}

pub trait MetaResponse {
    fn verification_key(&self) -> Vec<u8>;
    fn digest(&self) -> Vec<u8>;
}

pub trait FheTypeResponse {
    fn fhe_types(&self) -> anyhow::Result<Vec<FheType>>;
}

impl MetaResponse for ReencryptionResponsePayload {
    fn verification_key(&self) -> Vec<u8> {
        self.verification_key.to_owned()
    }

    fn digest(&self) -> Vec<u8> {
        self.digest.to_owned()
    }
}

impl FheTypeResponse for ReencryptionResponsePayload {
    fn fhe_types(&self) -> anyhow::Result<Vec<FheType>> {
        Ok(self
            .signcrypted_ciphertexts
            .iter()
            .map(|x| x.fhe_type())
            .collect())
    }
}

impl MetaResponse for DecryptionResponsePayload {
    fn verification_key(&self) -> Vec<u8> {
        self.verification_key.to_owned()
    }

    fn digest(&self) -> Vec<u8> {
        self.digest.to_owned()
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.request_id)
    }
}

impl RequestId {
    /// Method for deterministically deriving a request ID from an arbitrary string.
    /// Is currently only used for testing purposes, since deriving is the responsibility of the smart contract.
    pub fn derive(name: &str) -> anyhow::Result<Self> {
        let mut digest = serialize_hash_element(&name.to_string())?;
        if digest.len() < ID_LENGTH {
            anyhow::bail!(
                "derived request ID should have at least length {ID_LENGTH}, but only got {}",
                digest.len()
            )
        }
        // Truncate and convert to hex
        digest.truncate(ID_LENGTH);
        let res_hash = hex::encode(digest);
        Ok(RequestId {
            request_id: res_hash,
        })
    }

    /// Validates if a user-specified input is a request ID.
    /// By valid we mean if it is a hex string of a static length. This is done to ensure it can be
    /// part of a valid path, without risk of path-traversal attacks in case the key request
    /// call is publicly accessible.
    pub fn is_valid(&self) -> bool {
        let decoded = match hex::decode(self.to_string()) {
            Ok(hex) => hex,
            Err(_e) => {
                tracing::warn!("Input {} is not a hex string", &self.to_string());
                return false;
            }
        };
        if decoded.len() != ID_LENGTH {
            tracing::warn!(
                "Decoded value length is {}, but {} is expected",
                decoded.len(),
                ID_LENGTH
            );
            return false;
        }
        true
    }

    /// create a new random RequestId
    pub fn new_random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let mut bytes = [0u8; ID_LENGTH];
        rng.fill_bytes(&mut bytes);
        RequestId {
            request_id: hex::encode(bytes),
        }
    }
}

impl From<RequestId> for String {
    fn from(request_id: RequestId) -> Self {
        request_id.request_id
    }
}

impl TryFrom<RequestId> for u128 {
    type Error = anyhow::Error;

    // Convert a RequestId to a u128 through truncation of the first bytes.
    fn try_from(value: RequestId) -> Result<Self, Self::Error> {
        TryFrom::<&RequestId>::try_from(&value)
    }
}

impl TryFrom<&RequestId> for u128 {
    type Error = anyhow::Error;

    // Convert a RequestId to a u128 through truncation of the first bytes.
    fn try_from(value: &RequestId) -> Result<Self, Self::Error> {
        let hex = hex::decode(value.to_string())?;
        let hex_truncated: [u8; 16] = hex[4..20].try_into()?;
        Ok(u128::from_be_bytes(hex_truncated))
    }
}

impl TryFrom<String> for RequestId {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let request_id = RequestId { request_id: value };
        if !request_id.is_valid() {
            return Err(anyhow!("The string is not valid as request ID"));
        }
        Ok(request_id)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, VersionsDispatch)]
pub enum PublicKeyTypeVersioned {
    V0(PublicKeyType),
}

#[derive(Serialize, Deserialize, Debug, Clone, Versionize, PartialEq)]
#[versionize(PublicKeyTypeVersioned)]
pub enum PublicKeyType {
    Compact,
}

impl Named for PublicKeyType {
    const NAME: &'static str = "PublicKeyType";
}

pub enum WrappedPublicKey<'a> {
    Compact(&'a tfhe::CompactPublicKey),
}

#[derive(Clone, Serialize, Deserialize)]
pub enum WrappedPublicKeyOwned {
    Compact(tfhe::CompactPublicKey),
}

impl<'a> From<&'a WrappedPublicKeyOwned> for WrappedPublicKey<'a> {
    fn from(value: &'a WrappedPublicKeyOwned) -> Self {
        match value {
            WrappedPublicKeyOwned::Compact(pk) => WrappedPublicKey::Compact(pk),
        }
    }
}

impl TryFrom<(String, String)> for TypedPlaintext {
    type Error = anyhow::Error;
    fn try_from(value: (String, String)) -> Result<Self, Self::Error> {
        let ptx = TypedPlaintext {
            bytes: value.0.into(),
            fhe_type: FheType::from_str_name(&value.1)
                .ok_or(anyhow::anyhow!("Conversion failed for {}", &value.1))?
                as i32,
        };
        Ok(ptx)
    }
}

impl From<(String, FheType)> for TypedPlaintext {
    fn from(value: (String, FheType)) -> Self {
        TypedPlaintext {
            bytes: value.0.into(),
            fhe_type: value.1 as i32,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{alloy_to_protobuf_domain, TypedPlaintext};
    use crate::{
        kms::v1::{
            ComputeKeyType, FheParameter, KeySetCompressionConfig, RequestId, TypedCiphertext,
        },
        rpc_types::{
            ERR_CLIENT_ADDR_EQ_CONTRACT_ADDR, ERR_DOMAIN_NOT_FOUND, ERR_THERE_ARE_NO_HANDLES,
        },
    };

    #[test]
    fn idempotent_plaintext() {
        assert!(TypedPlaintext::from_bool(true).as_bool());
        assert!(!TypedPlaintext::from_bool(false).as_bool());
        assert_eq!(TypedPlaintext::from_u4(3).as_u4(), 3);
        assert_eq!(TypedPlaintext::from_u8(7).as_u4(), 7);
        assert_eq!(TypedPlaintext::from_u16(65000).as_u16(), 65000);

        assert_eq!(
            TypedPlaintext::from_u32(u32::MAX - 1).as_u32(),
            u32::MAX - 1
        );
        assert_eq!(TypedPlaintext::from_u32(u32::MAX).as_u32(), u32::MAX);
        assert_eq!(TypedPlaintext::from_u32(0).as_u32(), 0);

        assert_eq!(
            TypedPlaintext::from_u64(u64::MAX - 1).as_u64(),
            u64::MAX - 1
        );
        assert_eq!(TypedPlaintext::from_u64(u64::MAX).as_u64(), u64::MAX);
        assert_eq!(TypedPlaintext::from_u64(0).as_u64(), 0);

        assert_eq!(
            TypedPlaintext::from_u128(u128::MAX - 1).as_u128(),
            u128::MAX - 1
        );
        let alt_u128_plaintext =
            TypedPlaintext::new(u128::MAX - 1, crate::kms::v1::FheType::Euint128);
        assert_eq!(TypedPlaintext::from_u128(u128::MAX - 1), alt_u128_plaintext);

        let u160_val = tfhe::integer::U256::from((23, 999));
        assert_eq!(TypedPlaintext::from_u160(u160_val).as_u160(), u160_val);
        let u160_val = tfhe::integer::U256::from((u128::MAX, 1000));
        assert_eq!(TypedPlaintext::from_u160(u160_val).as_u160(), u160_val);
        let alt_u160_val = TypedPlaintext::from_u160_low_high((u128::MAX, 1000));
        assert_eq!(TypedPlaintext::from_u160(u160_val), alt_u160_val);

        let u256_val = tfhe::integer::U256::from((u128::MAX, u128::MAX));
        assert_eq!(TypedPlaintext::from_u256(u256_val).as_u256(), u256_val);
        let u256_val = tfhe::integer::U256::from((1, 1 << 77));
        assert_eq!(TypedPlaintext::from_u256(u256_val).as_u256(), u256_val);

        let bytes = [0xFF; 256];
        let mut u2048_val = tfhe::integer::bigint::U2048::default();
        tfhe::integer::bigint::U2048::copy_from_le_byte_slice(&mut u2048_val, &bytes);
        assert_eq!(TypedPlaintext::from_u2048(u2048_val).as_u2048(), u2048_val);
        let u2048_val = tfhe::integer::bigint::U2048::from(12345_u64);
        assert_eq!(TypedPlaintext::from_u2048(u2048_val).as_u2048(), u2048_val);
    }

    #[test]
    fn test_request_id_raw_string() {
        let request_id = RequestId {
            request_id: "0000000000000000000000000000000000000000000000000000000000000001"
                .to_owned(),
        };
        assert!(request_id.is_valid());
    }

    #[test]
    fn test_enum_default() {
        assert_eq!(FheParameter::default(), FheParameter::Default);
        assert_eq!(ComputeKeyType::default(), ComputeKeyType::Cpu);
        assert_eq!(
            KeySetCompressionConfig::default(),
            KeySetCompressionConfig::Generate
        );
    }

    #[test]
    fn test_eip712_verification() {
        let alloy_domain = alloy_sol_types::eip712_domain!(
            name: "Authorization token",
            version: "1",
            chain_id: 8006,
            verifying_contract: alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
        );
        let domain = alloy_to_protobuf_domain(&alloy_domain).unwrap();
        let request_id = RequestId::derive("request_id").unwrap();
        let key_id = RequestId::derive("key_id").unwrap();

        let ciphertexts = vec![TypedCiphertext {
            ciphertext: vec![],
            fhe_type: 0,
            external_handle: vec![],
            ciphertext_format: 0,
        }];
        let client_address = alloy_primitives::address!("d8da6bf26964af9d7eed9e03e53415d37aa96045");

        // empty domain
        {
            let req = crate::kms::v1::ReencryptionRequest {
                request_id: Some(request_id.clone()),
                typed_ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.clone()),
                client_address: client_address.to_checksum(None),
                enc_key: vec![],
                domain: None,
            };
            assert!(req
                .compute_link_checked()
                .unwrap_err()
                .to_string()
                .contains(ERR_DOMAIN_NOT_FOUND));
        }

        // empty ciphertexts
        {
            let req = crate::kms::v1::ReencryptionRequest {
                request_id: Some(request_id.clone()),
                typed_ciphertexts: vec![],
                key_id: Some(key_id.clone()),
                client_address: client_address.to_checksum(None),
                enc_key: vec![],
                domain: Some(domain.clone()),
            };
            assert!(req
                .compute_link_checked()
                .unwrap_err()
                .to_string()
                .contains(ERR_THERE_ARE_NO_HANDLES));
        }

        // use the same address for verifying contract and client address should fail
        {
            let mut bad_domain = domain.clone();
            bad_domain.verifying_contract = client_address.to_checksum(None);

            let req = crate::kms::v1::ReencryptionRequest {
                request_id: Some(request_id.clone()),
                typed_ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.clone()),
                client_address: client_address.to_checksum(None),
                enc_key: vec![],
                domain: Some(bad_domain),
            };

            assert!(req
                .compute_link_checked()
                .unwrap_err()
                .to_string()
                .contains(ERR_CLIENT_ADDR_EQ_CONTRACT_ADDR));
        }

        // everything is ok
        {
            let req = crate::kms::v1::ReencryptionRequest {
                request_id: Some(request_id.clone()),
                typed_ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.clone()),
                client_address: client_address.to_checksum(None),
                enc_key: vec![],
                domain: Some(domain.clone()),
            };
            assert!(req.compute_link_checked().is_ok());
        }
    }
}

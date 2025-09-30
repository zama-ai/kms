use crate::kms::v1::UserDecryptionResponsePayload;
use crate::kms::v1::{
    CustodianRecoveryOutput, CustodianRecoveryRequest, Eip712DomainMsg, TypedCiphertext,
    TypedPlaintext, TypedSigncryptedCiphertext,
};
use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::Eip712Domain;
use serde::{Deserialize, Serialize};
use std::fmt::{self};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;
use tfhe::integer::bigint::StaticUnsignedBigInt;
use tfhe::named::Named;
use tfhe::shortint::ClassicPBSParameters;
use tfhe::{FheTypes, Versionize};
use tfhe_versionable::{Version, VersionsDispatch};
use threshold_fhe::execution::runtime::party::Role;

pub use crate::identifiers::{KeyId, RequestId, ID_LENGTH};

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

const ERR_PARSE_CHECKSUMMED: &str = "error parsing checksummed address";

pub static KEY_GEN_REQUEST_NAME: &str = "key_gen_request";
pub static CRS_GEN_REQUEST_NAME: &str = "crs_gen_request";
pub static PUB_DEC_REQUEST_NAME: &str = "pub_dec_request";
pub static USER_DECRYPT_REQUEST_NAME: &str = "user_decrypt_request";

static UNSUPPORTED_FHE_TYPE_STR: &str = "UnsupportedFheType";

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, Copy)]
pub enum KMSType {
    Centralized,
    Threshold,
}
impl fmt::Display for KMSType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KMSType::Centralized => write!(f, "Centralized KMS"),
            KMSType::Threshold => write!(f, "Threshold KMS"),
        }
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
    // This lower-case hex values without the 0x prefix.
    pub key_handle: String,
    // The signature on the handle
    // OBSOLETE: no longer in use, but cannot be removed because of backwards compatibility
    pub signature: Vec<u8>,
    // The signature on the key for the external recipient
    // (e.g. using EIP712 for fhevm)
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

/// Wrapper struct to allow upgrading of CrsGenMetadata.
/// This is needed because `SignedPubDataHandleInternal`
/// still need to be supported for other types so it cannot derive Version.
/// See https://github.com/zama-ai/tfhe-rs/blob/main/utils/tfhe-versionable/examples/transparent_then_not.rs
/// for more details.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Version)]
#[repr(transparent)]
pub struct CrsGenSignedPubDataHandleInternalWrapper(pub SignedPubDataHandleInternal);

// This function needs to use the non-wasm feature because tonic is not available in wasm builds.
#[cfg(feature = "non-wasm")]
pub fn optional_protobuf_to_alloy_domain(
    domain_ref: Option<&Eip712DomainMsg>,
) -> Result<Eip712Domain, crate::utils::tonic_result::BoxedStatus> {
    let inner = domain_ref.ok_or(tonic::Status::invalid_argument("missing domain"))?;
    let out = protobuf_to_alloy_domain(inner).map_err(|e| {
        tonic::Status::invalid_argument(format!(
            "failed to convert protobuf domain to alloy domain: {e}"
        ))
    })?;
    Ok(out)
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
        Some(
            Address::parse_checksummed(pb_domain.verifying_contract.clone(), None).map_err(
                |e| {
                    anyhow::anyhow!(
                        "{ERR_PARSE_CHECKSUMMED}: {} - {e}",
                        pb_domain.verifying_contract,
                    )
                },
            )?,
        ),
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

#[derive(
    Clone,
    Copy,
    Debug,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    VersionsDispatch,
)]
pub enum PubDataTypeVersioned {
    V0(PubDataType),
}

/// PubDataType
///
/// Enum which represents the different kinds of public information that can be stored as part of
/// key generation. In practice this means the CRS and different types of public keys.
/// Data of this type is supposed to be readable by anyone on the internet
/// and stored on a medium that _may_ be suseptible to malicious modifications.
///
/// __NOTE__: ORDERING OF THE VARIANT IS IMPORTANT, DO NOT CHANGE WITHOUT CONSIDERING BACKWARDS COMPATIBILITY
/// In particular, the ServerKey must be before the PublicKey for proper signature checking on the GW.
#[derive(
    Clone,
    Copy,
    Debug,
    Hash,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    PartialOrd,
    Ord,
    EnumIter,
    Versionize,
)]
#[versionize(PubDataTypeVersioned)]
pub enum PubDataType {
    ServerKey,
    PublicKey,
    PublicKeyMetadata,
    CRS,
    VerfKey,     // Type for the servers public verification keys
    VerfAddress, // The ethereum address of the KMS core, needed for KMS signature verification
    DecompressionKey,
    CACert, // Certificate that signs TLS certificates used by MPC nodes // TODO will change in connection with #2491, also see #2723
    RecoveryRequest, // Recovery request for backup vault TODO(#2748) ensure that data gets validated at read, since we cannot fully trust the public storage
    RecoveryMaterial, // Recovery material for the backup vault
}

impl fmt::Display for PubDataType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PubDataType::PublicKey => write!(f, "PublicKey"),
            PubDataType::PublicKeyMetadata => write!(f, "PublicKeyMetadata"),
            PubDataType::ServerKey => write!(f, "ServerKey"),
            PubDataType::CRS => write!(f, "CRS"),
            PubDataType::VerfKey => write!(f, "VerfKey"),
            PubDataType::VerfAddress => write!(f, "VerfAddress"),
            PubDataType::DecompressionKey => write!(f, "DecompressionKey"),
            PubDataType::CACert => write!(f, "CACert"),
            PubDataType::RecoveryRequest => write!(f, "RecoveryRequest"),
            PubDataType::RecoveryMaterial => write!(f, "RecoveryMaterial"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum PrivDataTypeVersioned {
    V0(PrivDataType),
}

/// PrivDataType
///
/// Enum which represents the different kinds of private information that can be stored as part of
/// running the KMS. In practice this means the signing key, public key and CRS meta data and
/// signatures. Data of this type is supposed to only be readable, writable and modifiable by a
/// single entity and stored on a medium that is not readable, writable or modifiable by any other
/// entity (without detection).
///
/// Data stored with this type either need to be kept secret and/or need to be kept authentic.
/// Thus some data may indeed be safe to release publicly, but a malicious replacement could completely
/// compromise the entire system.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, EnumIter, Versionize)]
#[versionize(PrivDataTypeVersioned)]
pub enum PrivDataType {
    SigningKey,
    FheKeyInfo, // Only for the threshold case
    CrsInfo,
    FhePrivateKey, // Only used for the centralized case
    PrssSetup,
    ContextInfo,
}

impl fmt::Display for PrivDataType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PrivDataType::FheKeyInfo => write!(f, "FheKeyInfo"),
            PrivDataType::SigningKey => write!(f, "SigningKey"),
            PrivDataType::CrsInfo => write!(f, "CrsInfo"),
            PrivDataType::FhePrivateKey => write!(f, "FhePrivateKey"),
            PrivDataType::PrssSetup => write!(f, "PrssSetup"),
            PrivDataType::ContextInfo => write!(f, "Context"),
        }
    }
}

#[allow(clippy::derivable_impls)]
impl Default for PrivDataType {
    fn default() -> Self {
        PrivDataType::FheKeyInfo // Default is private FHE key material
    }
}

impl TryFrom<&str> for PrivDataType {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        for priv_data_type in PrivDataType::iter() {
            if value.to_ascii_lowercase().trim()
                == priv_data_type.to_string().to_ascii_lowercase().trim()
            {
                return Ok(priv_data_type);
            }
        }
        Err(anyhow::anyhow!("Unknown PrivDataType: {}", value))
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, EnumIter)]
pub enum BackupDataType {
    PrivData(PrivDataType), // Backup of a piece of private data
}
impl fmt::Display for BackupDataType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BackupDataType::PrivData(data_type) => write!(f, "PrivData({data_type})"),
        }
    }
}

fn unchecked_fhe_types_to_string(value: FheTypes) -> String {
    match value {
        FheTypes::Bool => "Ebool".to_string(),
        FheTypes::Uint4 => "Euint4".to_string(),
        FheTypes::Uint8 => "Euint8".to_string(),
        FheTypes::Uint16 => "Euint16".to_string(),
        FheTypes::Uint32 => "Euint32".to_string(),
        FheTypes::Uint64 => "Euint64".to_string(),
        FheTypes::Uint80 => "Euint80".to_string(),
        FheTypes::Uint128 => "Euint128".to_string(),
        FheTypes::Uint160 => "Euint160".to_string(),
        FheTypes::Uint256 => "Euint256".to_string(),
        FheTypes::Uint512 => "Euint512".to_string(),
        FheTypes::Uint1024 => "Euint1024".to_string(),
        FheTypes::Uint2048 => "Euint2048".to_string(),
        _ => UNSUPPORTED_FHE_TYPE_STR.to_string(),
    }
}

fn string_to_fhe_types(value: &str) -> anyhow::Result<FheTypes> {
    match value {
        "Ebool" => Ok(FheTypes::Bool),
        "Euint4" => Ok(FheTypes::Uint4),
        "Euint8" => Ok(FheTypes::Uint8),
        "Euint16" => Ok(FheTypes::Uint16),
        "Euint32" => Ok(FheTypes::Uint32),
        "Euint80" => Ok(FheTypes::Uint80),
        "Euint64" => Ok(FheTypes::Uint64),
        "Euint128" => Ok(FheTypes::Uint128),
        "Euint160" => Ok(FheTypes::Uint160),
        "Euint256" => Ok(FheTypes::Uint256),
        "Euint512" => Ok(FheTypes::Uint512),
        "Euint1024" => Ok(FheTypes::Uint1024),
        "Euint2048" => Ok(FheTypes::Uint2048),
        _ => Err(anyhow::anyhow!(
            "Trying to import FheType from unsupported value"
        )),
    }
}

pub fn fhe_type_to_num_bits(fhe_type: FheTypes) -> anyhow::Result<usize> {
    match fhe_type {
        FheTypes::Bool => Ok(1_usize),
        FheTypes::Uint4 => Ok(4_usize),
        FheTypes::Uint8 => Ok(8_usize),
        FheTypes::Uint16 => Ok(16_usize),
        FheTypes::Uint32 => Ok(32_usize),
        FheTypes::Uint64 => Ok(64_usize),
        FheTypes::Uint80 => Ok(80_usize),
        FheTypes::Uint128 => Ok(128_usize),
        FheTypes::Uint160 => Ok(160_usize),
        FheTypes::Uint256 => Ok(256_usize),
        FheTypes::Uint512 => Ok(512_usize),
        FheTypes::Uint1024 => Ok(1024_usize),
        FheTypes::Uint2048 => Ok(2048_usize),
        _ => anyhow::bail!("Unsupported fhe_type: {:?}", fhe_type),
    }
}

/// Calculates the number of blocks needed to encode a message of the given FHE
/// type, based on the usable message modulus log from the
/// parameters. Rounds up to ensure enough blocks.
///
/// The values might need to be adjusted if we use more than what's available
/// in the message modulus.
pub fn fhe_types_to_num_blocks(
    fhe_type: FheTypes,
    params: &ClassicPBSParameters,
    packing_factor: u32,
) -> anyhow::Result<usize> {
    let num_bits = fhe_type_to_num_bits(fhe_type)?;
    let msg_modulus = (params.message_modulus.0.ilog2() * packing_factor) as usize;
    Ok(num_bits.div_ceil(msg_modulus))
}

#[cfg(feature = "non-wasm")]
impl crate::kms::v1::UserDecryptionRequest {
    /// The only information we can use is userAddress, the handles and public key
    /// because these are the only information available
    /// to the user *and* to the KMS.
    /// So we can only use these information to link the request and the response.
    pub fn compute_link_checked(&self) -> anyhow::Result<(Vec<u8>, alloy_sol_types::Eip712Domain)> {
        use crate::solidity_types::UserDecryptionLinker;

        let domain = protobuf_to_alloy_domain(
            self.domain
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!(ERR_DOMAIN_NOT_FOUND))?,
        )?;

        let handles = self
            .typed_ciphertexts
            .iter()
            .enumerate()
            .map(|(idx, c)| {
                if c.external_handle.len() > 32 {
                    anyhow::bail!(
                        "external_handle at index {idx} too long: {} bytes (max 32)",
                        c.external_handle.len()
                    );
                }
                Ok(alloy_primitives::FixedBytes::<32>::left_padding_from(
                    &c.external_handle,
                ))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        if handles.is_empty() {
            anyhow::bail!(ERR_THERE_ARE_NO_HANDLES);
        }

        let client_address =
            alloy_primitives::Address::parse_checksummed(&self.client_address, None).map_err(
                |e| anyhow::anyhow!("{ERR_PARSE_CHECKSUMMED}: {} - {e}", &self.client_address),
            )?;
        let verifying_contract = domain
            .verifying_contract
            .ok_or_else(|| anyhow::anyhow!(ERR_VERIFYING_CONTRACT_NOT_FOUND))?;

        if client_address == verifying_contract {
            anyhow::bail!("{ERR_CLIENT_ADDR_EQ_CONTRACT_ADDR}: {client_address}");
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
    /// Make a new plaintext from a 128 bit integer.
    /// Note that the we truncate the we may truncate the byte resulting from the u128 vector depending on the provided [`FheTypes`] .
    pub fn new(value: u128, fhe_type: FheTypes) -> Self {
        // If the FHE type is not supported, we default to using the whole u128
        let num_bytes = fhe_type_to_num_bits(fhe_type).unwrap_or(128).div_ceil(8);
        Self {
            bytes: value.to_le_bytes()[0..num_bytes].to_vec(),
            fhe_type: fhe_type as i32,
        }
    }

    pub fn fhe_type(&self) -> anyhow::Result<FheTypes> {
        self.fhe_type
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid FHE type: {}", self.fhe_type))
    }

    pub fn fhe_type_string(&self) -> String {
        if let Ok(fhe_type) = self.fhe_type.try_into() {
            unchecked_fhe_types_to_string(fhe_type)
        } else {
            UNSUPPORTED_FHE_TYPE_STR.to_string()
        }
    }

    pub fn from_bytes(bytes: Vec<u8>, fhe_type: impl Into<FheTypes>) -> Self {
        // TODO need to make sure we have enough bytes for the type
        Self {
            bytes,
            fhe_type: (fhe_type.into() as FheTypes) as i32,
        }
    }

    pub fn from_bool(value: bool) -> Self {
        let plaintext: u8 = match value {
            true => 1,
            false => 0,
        };
        Self {
            bytes: vec![plaintext],
            fhe_type: FheTypes::Bool as i32,
        }
    }

    pub fn from_u4(value: u8) -> Self {
        Self {
            bytes: vec![value % 16],
            fhe_type: FheTypes::Uint4 as i32,
        }
    }

    pub fn from_u8(value: u8) -> Self {
        Self {
            bytes: vec![value],
            fhe_type: FheTypes::Uint8 as i32,
        }
    }

    pub fn from_u16(value: u16) -> Self {
        Self {
            bytes: value.to_le_bytes().to_vec(),
            fhe_type: FheTypes::Uint16 as i32,
        }
    }

    pub fn from_u32(value: u32) -> Self {
        Self {
            bytes: value.to_le_bytes().to_vec(),
            fhe_type: FheTypes::Uint32 as i32,
        }
    }

    pub fn from_u64(value: u64) -> Self {
        Self {
            bytes: value.to_le_bytes().to_vec(),
            fhe_type: FheTypes::Uint64 as i32,
        }
    }

    pub fn from_u80(value: u128) -> Self {
        Self {
            // Safe to take slice of 10 byte since the value is 16 bytes
            bytes: value.to_le_bytes()[..10].to_vec(),
            fhe_type: FheTypes::Uint80 as i32,
        }
    }

    pub fn from_u128(value: u128) -> Self {
        Self {
            bytes: value.to_le_bytes().to_vec(),
            fhe_type: FheTypes::Uint128 as i32,
        }
    }

    pub fn from_u160(value: tfhe::integer::U256) -> Self {
        let (low_128, high_128) = value.to_low_high_u128();
        let mut bytes = low_128.to_le_bytes().to_vec();
        bytes.extend(high_128.to_le_bytes()[0..4].to_vec());
        Self {
            bytes,
            fhe_type: FheTypes::Uint160 as i32,
        }
    }

    pub fn from_u160_low_high(value: (u128, u32)) -> Self {
        let mut bytes = value.0.to_le_bytes().to_vec();
        bytes.extend(value.1.to_le_bytes().to_vec());
        Self {
            bytes,
            fhe_type: FheTypes::Uint160 as i32,
        }
    }

    pub fn from_u256(value: tfhe::integer::U256) -> Self {
        let (low_128, high_128) = value.to_low_high_u128();
        let mut bytes = low_128.to_le_bytes().to_vec();
        bytes.extend(high_128.to_le_bytes().to_vec());
        Self {
            bytes,
            fhe_type: FheTypes::Uint256 as i32,
        }
    }

    pub fn from_u512(value: StaticUnsignedBigInt<8>) -> TypedPlaintext {
        let mut bytes = vec![0_u8; 64];
        value.copy_to_le_byte_slice(&mut bytes);
        TypedPlaintext {
            bytes,
            fhe_type: FheTypes::Uint512 as i32,
        }
    }

    pub fn from_u1024(value: StaticUnsignedBigInt<16>) -> TypedPlaintext {
        let mut bytes = vec![0_u8; 128];
        value.copy_to_le_byte_slice(&mut bytes);
        TypedPlaintext {
            bytes,
            fhe_type: FheTypes::Uint1024 as i32,
        }
    }

    pub fn from_u2048(value: tfhe::integer::bigint::U2048) -> Self {
        let mut bytes = [0u8; 256];
        value.copy_to_le_byte_slice(&mut bytes);
        Self {
            bytes: bytes.to_vec(),
            fhe_type: FheTypes::Uint2048 as i32,
        }
    }

    pub fn as_bool(&self) -> bool {
        if self.fhe_type != FheTypes::Bool as i32 {
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
        if self.fhe_type != FheTypes::Uint4 as i32 {
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
        if self.fhe_type != FheTypes::Uint8 as i32 {
            tracing::warn!("Plaintext is not of type u8. Returning the value modulo 256");
        }
        if self.bytes.len() != 1 {
            tracing::warn!("U8 Plaintext should have 1 Byte, but was bigger ({} Bytes). Returning the least significant Byte", self.bytes.len());
        }
        self.bytes[0]
    }

    pub fn as_u16(&self) -> u16 {
        if self.fhe_type != FheTypes::Uint16 as i32 {
            tracing::warn!("Plaintext is not of type u16. Returning the value modulo 65536 or padding with leading zeros");
        }
        if self.bytes.len() != 2 {
            tracing::warn!("U16 Plaintext should have 2 Bytes, but was not ({} Bytes). Truncating/Padding to 2 Bytes", self.bytes.len());
        }
        u16::from_le_bytes(sub_slice::<2>(&self.bytes))
    }

    pub fn as_u32(&self) -> u32 {
        if self.fhe_type != FheTypes::Uint32 as i32 {
            tracing::warn!("Plaintext is not of type u32. Returning the value modulo 2^32 or padding with leading zeros");
        }
        if self.bytes.len() != 4 {
            tracing::warn!("U32 Plaintext should have 4 Bytes, but was not ({} Bytes). Truncating/Padding to 4 Bytes", self.bytes.len());
        }
        u32::from_le_bytes(sub_slice::<4>(&self.bytes))
    }
    pub fn as_u64(&self) -> u64 {
        if self.fhe_type != FheTypes::Uint64 as i32 {
            tracing::warn!("Plaintext is not of type u64. Returning the value modulo 2^64 or padding with leading zeros");
        }
        if self.bytes.len() != 8 {
            tracing::warn!("U64 Plaintext should have 8 Bytes, but was not ({} Bytes). Truncating/Padding to 8 Bytes", self.bytes.len());
        }
        u64::from_le_bytes(sub_slice::<8>(&self.bytes))
    }

    pub fn as_u80(&self) -> u128 {
        if self.fhe_type != FheTypes::Uint80 as i32 {
            tracing::warn!("Plaintext is not of type u80. Returning the value modulo 2^80 or padding with leading zeros");
        }
        if self.bytes.len() != 10 {
            tracing::warn!("U80 Plaintext should have 10 Bytes, but was not ({} Bytes). Truncating/Padding to 10 Bytes", self.bytes.len());
        }

        // We need a full 128-bit slice to convert to u128, but also need to make sure it's within 2^80.
        let res = u128::from_le_bytes(sub_slice::<16>(&self.bytes));
        res % (1 << 80)
    }

    pub fn as_u128(&self) -> u128 {
        if self.fhe_type != FheTypes::Uint128 as i32 {
            tracing::warn!("Plaintext is not of type u128. Returning the value modulo 2^128 or padding with leading zeros");
        }
        if self.bytes.len() != 16 {
            tracing::warn!("U128 Plaintext should have 16 Bytes, but was not ({} Bytes). Truncating/Padding to 16 Bytes", self.bytes.len());
        }
        u128::from_le_bytes(sub_slice::<16>(&self.bytes))
    }

    pub fn as_u160(&self) -> tfhe::integer::U256 {
        if self.fhe_type != FheTypes::Uint160 as i32 {
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
        if self.fhe_type != FheTypes::Uint256 as i32 {
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
        if self.fhe_type != FheTypes::Uint512 as i32 {
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
        if self.fhe_type != FheTypes::Uint1024 as i32 {
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
        if self.fhe_type != FheTypes::Uint2048 as i32 {
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

impl TryFrom<TypedPlaintext> for FheTypes {
    type Error = anyhow::Error;
    fn try_from(value: TypedPlaintext) -> anyhow::Result<Self> {
        value.fhe_type()
    }
}

impl TryFrom<TypedPlaintext> for Vec<u8> {
    type Error = anyhow::Error;
    fn try_from(value: TypedPlaintext) -> anyhow::Result<Self> {
        match value.fhe_type()? {
            FheTypes::Bool => Ok(vec![value.bytes[0] % 2]),
            FheTypes::Uint4 => Ok(vec![value.bytes[0] % 16]),
            FheTypes::Uint8 => Ok(vec![value.bytes[0]]),
            FheTypes::Uint16 => Ok(value.bytes[0..2].to_vec()),
            FheTypes::Uint32 => Ok(value.bytes[0..4].to_vec()),
            FheTypes::Uint64 => Ok(value.bytes[0..8].to_vec()),
            FheTypes::Uint128 => Ok(value.bytes[0..16].to_vec()),
            FheTypes::Uint160 => Ok(value.bytes[0..20].to_vec()),
            FheTypes::Uint256 => Ok(value.bytes[0..32].to_vec()),
            FheTypes::Uint512 => Ok(value.bytes[0..64].to_vec()),
            FheTypes::Uint1024 => Ok(value.bytes[0..128].to_vec()),
            FheTypes::Uint2048 => Ok(value.bytes[0..256].to_vec()),
            _ => anyhow::bail!("Unsupported fhe_type in TypedPlaintext: {}", value.fhe_type),
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

pub trait FheTypeResponse {
    fn fhe_types(&self) -> anyhow::Result<Vec<FheTypes>>;
}

impl TypedSigncryptedCiphertext {
    pub fn fhe_type(&self) -> anyhow::Result<FheTypes> {
        self.fhe_type
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid FHE type: {}", self.fhe_type))
    }

    pub fn fhe_type_string(&self) -> String {
        if let Ok(fhe_type) = self.fhe_type.try_into() {
            unchecked_fhe_types_to_string(fhe_type)
        } else {
            UNSUPPORTED_FHE_TYPE_STR.to_string()
        }
    }
}

impl TypedCiphertext {
    pub fn fhe_type(&self) -> anyhow::Result<FheTypes> {
        self.fhe_type
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid FHE type: {}", self.fhe_type))
    }

    pub fn fhe_type_string(&self) -> String {
        if let Ok(fhe_type) = self.fhe_type.try_into() {
            unchecked_fhe_types_to_string(fhe_type)
        } else {
            UNSUPPORTED_FHE_TYPE_STR.to_string()
        }
    }
}

impl FheTypeResponse for UserDecryptionResponsePayload {
    fn fhe_types(&self) -> anyhow::Result<Vec<FheTypes>> {
        self.signcrypted_ciphertexts
            .iter()
            .map(|x| x.fhe_type())
            .collect::<Result<Vec<_>, _>>()
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
            fhe_type: string_to_fhe_types(&value.1)? as i32,
        };
        Ok(ptx)
    }
}

impl From<(String, FheTypes)> for TypedPlaintext {
    fn from(value: (String, FheTypes)) -> Self {
        TypedPlaintext {
            bytes: value.0.into(),
            fhe_type: value.1 as i32,
        }
    }
}
#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum CustodianRecoveryOutputVersioned {
    V0(InternalCustodianRecoveryOutput),
}

/// This is the message that a custodian sends to an operator after starting recovery.
/// TODO this should be changed to use proper signcryption to ensure that the operator role is signed as well
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(CustodianRecoveryOutputVersioned)]
pub struct InternalCustodianRecoveryOutput {
    pub signature: Vec<u8>,  // sigt_i_j
    pub ciphertext: Vec<u8>, // st_i_j
    pub custodian_role: Role,
    pub operator_role: Role,
}

impl Named for InternalCustodianRecoveryOutput {
    const NAME: &'static str = "backup::CustodianRecoveryOutput";
}

impl TryFrom<CustodianRecoveryOutput> for InternalCustodianRecoveryOutput {
    type Error = anyhow::Error;

    fn try_from(value: CustodianRecoveryOutput) -> Result<Self, Self::Error> {
        if value.custodian_role == 0 {
            return Err(anyhow::anyhow!(
                "Invalid custodian role in CustodianRecoveryOutput"
            ));
        }
        if value.operator_role == 0 {
            return Err(anyhow::anyhow!(
                "Invalid operator role in CustodianRecoveryOutput"
            ));
        }
        Ok(InternalCustodianRecoveryOutput {
            signature: value.signature.to_vec(),
            ciphertext: value.ciphertext,
            custodian_role: Role::indexed_from_one(value.custodian_role as usize),
            operator_role: Role::indexed_from_one(value.operator_role as usize),
        })
    }
}

impl TryFrom<InternalCustodianRecoveryOutput> for CustodianRecoveryOutput {
    type Error = anyhow::Error;

    fn try_from(value: InternalCustodianRecoveryOutput) -> Result<Self, Self::Error> {
        Ok(CustodianRecoveryOutput {
            signature: value.signature,
            ciphertext: value.ciphertext,
            custodian_role: value.custodian_role.one_based() as u64,
            operator_role: value.operator_role.one_based() as u64,
        })
    }
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum InternalCustodianRecoveryRequestVersioned {
    V0(InternalCustodianRecoveryRequest),
}

/// This is the internal representation of the custodian context.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Versionize)]
#[versionize(InternalCustodianRecoveryRequestVersioned)]
pub struct InternalCustodianRecoveryRequest {
    pub custodian_context_id: RequestId,
    pub custodian_recovery_outputs: Vec<InternalCustodianRecoveryOutput>,
}

impl Named for InternalCustodianRecoveryRequest {
    const NAME: &'static str = "backup::BackupRestoreRequest";
}

impl TryFrom<CustodianRecoveryRequest> for InternalCustodianRecoveryRequest {
    type Error = anyhow::Error;

    fn try_from(value: CustodianRecoveryRequest) -> Result<Self, Self::Error> {
        Ok(InternalCustodianRecoveryRequest {
            custodian_context_id: value
                .custodian_context_id
                .ok_or_else(|| {
                    anyhow::anyhow!("Missing custodian context ID in BackupRestoreRequest")
                })?
                .try_into()?,
            custodian_recovery_outputs: value
                .custodian_recovery_outputs
                .into_iter()
                .map(InternalCustodianRecoveryOutput::try_from)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kms::v1;
    use std::str::FromStr;
    use strum::IntoEnumIterator;

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
        let alt_u128_plaintext = TypedPlaintext::new(u128::MAX - 1, FheTypes::Uint128);
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
    fn test_request_id() {
        let hex_str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let id = RequestId::from_str(hex_str).unwrap();
        assert_eq!(id.to_string(), hex_str);
    }

    #[test]
    fn test_request_id_raw_string() {
        // Test using our new RequestId type
        let hex_str = "0000000000000000000000000000000000000000000000000000000000000001";
        let id = RequestId::from_str(hex_str).unwrap();
        let proto_id: v1::RequestId = id.into();

        assert_eq!(proto_id.request_id, hex_str);
    }

    #[test]
    fn test_enum_default() {
        assert_eq!(v1::FheParameter::default(), v1::FheParameter::Default);
        assert_eq!(v1::ComputeKeyType::default(), v1::ComputeKeyType::Cpu);
        assert_eq!(
            v1::KeySetCompressionConfig::default(),
            v1::KeySetCompressionConfig::Generate
        );
    }

    #[test]
    fn test_old_fhe_type_enum_compatibility() {
        // In this test we want to make sure the enum definition in tfhe-rs matches
        // the old enums we had in kms, define in protobuf.

        // This is copied from the old protobuf.
        #[repr(i32)]
        #[derive(EnumIter, Debug)]
        enum OldFheType {
            Ebool = 0,
            Euint4 = 1,
            Euint8 = 2,
            Euint16 = 3,
            Euint32 = 4,
            Euint64 = 5,
            Euint128 = 6,
            Euint160 = 7,
            Euint256 = 8,
            Euint512 = 9,
            Euint1024 = 10,
            Euint2048 = 11,
        }

        for old_type in OldFheType::iter() {
            match old_type {
                OldFheType::Ebool => assert_eq!(FheTypes::Bool as i32, old_type as i32),
                OldFheType::Euint4 => assert_eq!(FheTypes::Uint4 as i32, old_type as i32),
                OldFheType::Euint8 => assert_eq!(FheTypes::Uint8 as i32, old_type as i32),
                OldFheType::Euint16 => assert_eq!(FheTypes::Uint16 as i32, old_type as i32),
                OldFheType::Euint32 => assert_eq!(FheTypes::Uint32 as i32, old_type as i32),
                OldFheType::Euint64 => assert_eq!(FheTypes::Uint64 as i32, old_type as i32),
                OldFheType::Euint128 => assert_eq!(FheTypes::Uint128 as i32, old_type as i32),
                OldFheType::Euint160 => assert_eq!(FheTypes::Uint160 as i32, old_type as i32),
                OldFheType::Euint256 => assert_eq!(FheTypes::Uint256 as i32, old_type as i32),
                OldFheType::Euint512 => assert_eq!(FheTypes::Uint512 as i32, old_type as i32),
                OldFheType::Euint1024 => assert_eq!(FheTypes::Uint1024 as i32, old_type as i32),
                OldFheType::Euint2048 => assert_eq!(FheTypes::Uint2048 as i32, old_type as i32),
            }
        }
    }

    #[test]
    fn test_eip712_verification() {
        let request_id =
            RequestId::from_str("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
                .unwrap();

        let key_id =
            RequestId::from_str("2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40")
                .unwrap();
        let context_id =
            RequestId::from_str("4142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60")
                .unwrap();

        let alloy_domain = alloy_sol_types::eip712_domain!(
            name: "Authorization token",
            version: "1",
            chain_id: 8006,
            verifying_contract: alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
        );
        let domain = alloy_to_protobuf_domain(&alloy_domain).unwrap();
        let client_address = alloy_primitives::Address::parse_checksummed(
            "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
            None,
        )
        .unwrap();
        let ciphertexts = vec![TypedCiphertext {
            ciphertext: vec![],
            fhe_type: 0,
            external_handle: vec![],
            ciphertext_format: 0,
        }];

        // empty domain
        {
            let req = v1::UserDecryptionRequest {
                request_id: Some(request_id.into()),
                typed_ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.into()),
                client_address: client_address.to_checksum(None),
                enc_key: vec![],
                domain: None,
                extra_data: vec![],
                context_id: Some(context_id.into()),
                epoch_id: None,
            };
            assert!(req
                .compute_link_checked()
                .unwrap_err()
                .to_string()
                .contains(ERR_DOMAIN_NOT_FOUND));
        }

        // empty ciphertexts
        {
            let req = v1::UserDecryptionRequest {
                request_id: Some(request_id.into()),
                typed_ciphertexts: vec![],
                key_id: Some(key_id.into()),
                client_address: client_address.to_checksum(None),
                enc_key: vec![],
                domain: Some(domain.clone()),
                extra_data: vec![],
                context_id: Some(context_id.into()),
                epoch_id: None,
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

            let req = v1::UserDecryptionRequest {
                request_id: Some(request_id.into()),
                typed_ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.into()),
                client_address: client_address.to_checksum(None),
                enc_key: vec![],
                domain: Some(bad_domain),
                extra_data: vec![],
                context_id: Some(context_id.into()),
                epoch_id: None,
            };

            assert!(req
                .compute_link_checked()
                .unwrap_err()
                .to_string()
                .contains(ERR_CLIENT_ADDR_EQ_CONTRACT_ADDR));
        }

        // everything is ok
        {
            let req = v1::UserDecryptionRequest {
                request_id: Some(request_id.into()),
                typed_ciphertexts: ciphertexts.clone(),
                key_id: Some(key_id.into()),
                client_address: client_address.to_checksum(None),
                enc_key: vec![],
                domain: Some(domain.clone()),
                extra_data: vec![],
                context_id: Some(context_id.into()),
                epoch_id: None,
            };
            assert!(req.compute_link_checked().is_ok());
        }
    }
}

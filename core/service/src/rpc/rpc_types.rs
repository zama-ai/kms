use crate::anyhow_error_and_log;
use crate::consts::ID_LENGTH;
use crate::kms::{DecryptionResponsePayload, Eip712DomainMsg, FheType, RequestId};
use crate::kms::{ReencryptionResponsePayload, SignedPubDataHandle};
use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::Eip712Domain;
use anyhow::anyhow;
use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use strum_macros::EnumIter;
use tfhe::integer::bigint::StaticUnsignedBigInt;
use tfhe::named::Named;
use tfhe::Versionize;
use tfhe_versionable::VersionsDispatch;
use wasm_bindgen::prelude::wasm_bindgen;

#[cfg(test)]
use crate::kms::CrsGenRequest;

cfg_if::cfg_if! {
    if #[cfg(feature = "non-wasm")] {
        use crate::cryptography::internal_crypto_types::{PrivateSigKey, PublicEncKey, PublicSigKey, Signature};
        use crate::cryptography::signcryption::{hash_element, Reencrypt,DecryptionResult, CiphertextVerificationForKMS};
        use crate::cryptography::central_kms::KmsFheKeyHandles;
        use distributed_decryption::execution::zk::ceremony::PublicParameter;
        use alloy_dyn_abi::DynSolValue;
        use alloy_primitives::Bytes;
        use alloy_signer::SignerSync;
        use alloy_signer_local::PrivateKeySigner;
        use alloy_sol_types::SolStruct;
        use rand::{CryptoRng, RngCore};
        use crate::kms::ZkVerifyRequest;
        use std::str::FromStr;
    }
}

pub static CURRENT_FORMAT_VERSION: u32 = 1;
pub static KEY_GEN_REQUEST_NAME: &str = "key_gen_request";
pub static CRS_GEN_REQUEST_NAME: &str = "crs_gen_request";
pub static DEC_REQUEST_NAME: &str = "dec_request";
pub static REENC_REQUEST_NAME: &str = "reenc_request";

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
    // Digest (the 160-bit hex-encoded value, computed using compute_info/handle)
    pub key_handle: String,
    // The signature on the handle
    pub signature: Vec<u8>,
}

impl Named for SignedPubDataHandleInternal {
    const NAME: &'static str = "SignedPubDataHandleInternal";
}

impl SignedPubDataHandleInternal {
    pub fn new(key_handle: String, signature: Vec<u8>) -> SignedPubDataHandleInternal {
        SignedPubDataHandleInternal {
            key_handle,
            signature,
        }
    }
}

impl From<SignedPubDataHandle> for SignedPubDataHandleInternal {
    fn from(handle: SignedPubDataHandle) -> Self {
        SignedPubDataHandleInternal {
            key_handle: handle.key_handle,
            signature: handle.signature,
        }
    }
}
impl From<SignedPubDataHandleInternal> for SignedPubDataHandle {
    fn from(crs: SignedPubDataHandleInternal) -> Self {
        SignedPubDataHandle {
            key_handle: crs.key_handle,
            signature: crs.signature,
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, VersionsDispatch)]
pub enum PubDataTypeVersioned {
    V0(PubDataType),
}

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
        }
    }
}

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
    FhePrivateKey,
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

pub fn protobuf_to_alloy_domain(pb_domain: &Eip712DomainMsg) -> anyhow::Result<Eip712Domain> {
    let salt = if pb_domain.salt.is_empty() {
        None
    } else {
        Some(B256::from_slice(&pb_domain.salt))
    };
    let out = Eip712Domain::new(
        Some(pb_domain.name.clone().into()),
        Some(pb_domain.version.clone().into()),
        Some(
            U256::try_from_be_slice(&pb_domain.chain_id)
                .ok_or_else(|| anyhow_error_and_log("invalid chain ID"))?,
        ),
        Some(Address::parse_checksummed(
            pb_domain.verifying_contract.clone(),
            None,
        )?),
        salt,
    );
    Ok(out)
}

pub(crate) fn alloy_to_protobuf_domain(domain: &Eip712Domain) -> anyhow::Result<Eip712DomainMsg> {
    let name = domain
        .name
        .as_ref()
        .ok_or_else(|| anyhow_error_and_log("missing domain name"))?
        .to_string();
    let version = domain
        .version
        .as_ref()
        .ok_or_else(|| anyhow_error_and_log("missing domain version"))?
        .to_string();
    let chain_id = domain
        .chain_id
        .ok_or_else(|| anyhow_error_and_log("missing domain chain_id"))?
        .to_be_bytes_vec();
    let verifying_contract = domain
        .verifying_contract
        .as_ref()
        .ok_or_else(|| anyhow_error_and_log("missing domain chain_id"))?
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
// take an ordered list of plaintexts and ABI encode them into Solidity Bytes
fn abi_encode_plaintexts(ptxts: &[Plaintext]) -> Bytes {
    // This is a hack to get the offsets right for Byte types.
    // Every offset needs to be shifted by 32 bytes (256 bits), so we prepend a U256 and delete it at the and, after encoding.
    let mut data = vec![DynSolValue::Uint(U256::from(0), 256)];

    // This is another hack to handle Euint2048 Bytes properly (alloy adds another all-zero 256 bytes to the beginning of the encoded bytes)
    let mut offset_mul = 1;

    for ptxt in ptxts.iter() {
        tracing::debug!("Encoding Plaintext with FheType: {:#?}", ptxt.fhe_type());
        let res = match ptxt.fhe_type() {
            FheType::Ebool => {
                let val = if ptxt.as_bool() { 1_u8 } else { 0 };
                DynSolValue::Uint(U256::from(val), 256)
            }
            FheType::Euint4 => DynSolValue::Uint(U256::from(ptxt.as_u4()), 256),
            FheType::Euint8 => DynSolValue::Uint(U256::from(ptxt.as_u8()), 256),
            FheType::Euint16 => DynSolValue::Uint(U256::from(ptxt.as_u16()), 256),
            FheType::Euint32 => DynSolValue::Uint(U256::from(ptxt.as_u32()), 256),
            FheType::Euint64 => DynSolValue::Uint(U256::from(ptxt.as_u64()), 256),
            FheType::Euint128 => DynSolValue::Uint(U256::from(ptxt.as_u128()), 256),
            FheType::Euint160 => {
                let mut cake = vec![0u8; 32];
                ptxt.as_u160().copy_to_be_byte_slice(cake.as_mut_slice());
                DynSolValue::Uint(U256::from_be_slice(&cake), 256)
            }
            FheType::Euint256 => {
                let mut cake = vec![0u8; 32];
                ptxt.as_u256().copy_to_be_byte_slice(cake.as_mut_slice());
                DynSolValue::Uint(U256::from_be_slice(&cake), 256)
            }
            FheType::Euint2048 => {
                // if we have at least 1 Euint2048, we need to throw away 256 more bytes at the beginning of the encoding below, thus set offset_mul to 2
                offset_mul = 2;
                let mut cake = vec![0u8; 256];
                ptxt.as_u2048().copy_to_be_byte_slice(cake.as_mut_slice());
                DynSolValue::Bytes(cake)
            }
            FheType::Euint512 => {
                todo!("Implement Euint512")
            }
            FheType::Euint1024 => {
                todo!("Implement Euint1024")
            }
        };
        data.push(res);
    }

    // wrap data in a Tuple, so we can encode it with position information
    let encoded = DynSolValue::Tuple(data).abi_encode();

    // strip off the extra U256 at the beginning, and possibly also 256 bytes more zero bytes, when we encode one or more Euint2048s
    let encoded_bytes: Vec<u8> = encoded[offset_mul * 32..].to_vec();

    let hexbytes = hex::encode(encoded_bytes.clone());
    tracing::debug!("Encoded plaintext ABI {:?}", hexbytes);

    Bytes::from(encoded_bytes)
}

#[cfg(feature = "non-wasm")]
/// take external handles and plaintext in the form of bytes, convert them to the required solidity types and sign them using EIP-712 for external verification (e.g. in the fhevm).
pub(crate) fn compute_external_pt_signature(
    client_sk: &PrivateSigKey,
    ext_handles_bytes: Vec<Option<Vec<u8>>>,
    pts: &[Plaintext],
    eip712_domain: Eip712Domain,
    acl_address: Address,
) -> Vec<u8> {
    // convert external_handles back to U256 to be signed
    let external_handles: Vec<_> = ext_handles_bytes
        .into_iter()
        .flatten()
        .map(|e| U256::from_be_slice(e.as_slice()))
        .collect();

    let pt_bytes = abi_encode_plaintexts(pts);

    // the solidity structure to sign with EIP-712
    let message = DecryptionResult {
        aclAddress: acl_address,
        handlesList: external_handles,
        decryptedResult: pt_bytes,
    };

    let signer = PrivateKeySigner::from_signing_key(client_sk.sk().clone());
    let signer_address = signer.address();

    tracing::info!("Signer address: {:?}", signer_address);

    let message_hash = message.eip712_signing_hash(&eip712_domain);
    tracing::info!("PT Message hash: {:?}", message_hash);

    // Sign the hash synchronously with the wallet.
    let signature = signer
        .sign_hash_sync(&message_hash)
        .unwrap()
        .as_bytes()
        .to_vec();

    tracing::info!("PT Signature: {:?}", hex::encode(signature.clone()));

    signature
}

#[cfg(feature = "non-wasm")]
/// Take the ZK proof verification metadata, convert it to the required solidity types and sign them using EIP-712 for external verification (e.g. in the fhevm).
pub(crate) fn compute_external_zkp_verf_signature(
    client_sk: &PrivateSigKey,
    ct_digest: &Vec<u8>,
    req: &ZkVerifyRequest,
) -> anyhow::Result<Vec<u8>> {
    let eip712_domain = match req.domain.as_ref() {
        Some(domain) => protobuf_to_alloy_domain(domain)?,
        None => {
            return Err(anyhow::anyhow!(
                "EIP-712 domain is not set for ZK verification signature!"
            ));
        }
    };

    // the solidity structure to sign with EIP-712
    let message = CiphertextVerificationForKMS {
        aclAddress: alloy_primitives::Address::from_str(&req.acl_address)?,
        hashOfCiphertext: ct_digest.as_slice().try_into()?,
        userAddress: alloy_primitives::Address::from_str(&req.client_address)?,
        contractAddress: alloy_primitives::Address::from_str(&req.contract_address)?,
    };

    let signer = PrivateKeySigner::from_signing_key(client_sk.sk().clone());
    let signer_address = signer.address();

    tracing::info!("Signer address: {:?}", signer_address);

    let message_hash = message.eip712_signing_hash(&eip712_domain);
    tracing::info!("ZKP Verf Message hash: {:?}", message_hash);

    // Sign the hash synchronously with the wallet.
    let signature = signer
        .sign_hash_sync(&message_hash)
        .unwrap()
        .as_bytes()
        .to_vec();

    tracing::info!("ZKP Verf Signature: {:?}", hex::encode(signature.clone()));

    Ok(signature)
}

#[cfg(feature = "non-wasm")]
pub trait BaseKms {
    fn verify_sig<T: Serialize + AsRef<[u8]>>(
        payload: &T,
        signature: &Signature,
        verification_key: &PublicSigKey,
    ) -> anyhow::Result<()>;
    fn sign<T: Serialize + AsRef<[u8]>>(&self, msg: &T) -> anyhow::Result<Signature>;
    fn get_serialized_verf_key(&self) -> Vec<u8>;
    fn digest<T: ?Sized + AsRef<[u8]>>(msg: &T) -> anyhow::Result<Vec<u8>>;
}
/// The [Kms] trait represents either a dummy KMS, an HSM, or an MPC network.
#[cfg(feature = "non-wasm")]
pub trait Kms: BaseKms {
    fn decrypt(keys: &KmsFheKeyHandles, ct: &[u8], fhe_type: FheType) -> anyhow::Result<Plaintext>;
    #[allow(clippy::too_many_arguments)]
    fn reencrypt(
        keys: &KmsFheKeyHandles,
        sig_key: &PrivateSigKey,
        rng: &mut (impl CryptoRng + RngCore),
        ct: &[u8],
        ct_type: FheType,
        digest_link: &[u8],
        enc_key: &PublicEncKey,
        client_address: &alloy_primitives::Address,
    ) -> anyhow::Result<Vec<u8>>;
}

/// Representation of the data stored in a signcryption,
/// needed to facilitate FHE decryption and request linking.
/// The result is linked to some byte array.
#[derive(Clone, Serialize, Deserialize, Hash, PartialEq, Eq, Debug)]
pub(crate) struct SigncryptionPayload {
    pub(crate) plaintext: Plaintext,
    pub(crate) link: Vec<u8>,
}

#[cfg(feature = "non-wasm")]
impl crate::kms::ReencryptionRequest {
    pub(crate) fn compute_link_checked(&self) -> anyhow::Result<Vec<u8>> {
        let payload = self
            .payload
            .as_ref()
            .ok_or_else(|| anyhow!("payload not found"))?;
        let pk_sol = Reencrypt {
            publicKey: Bytes::copy_from_slice(&payload.enc_key),
        };

        let domain = protobuf_to_alloy_domain(
            self.domain
                .as_ref()
                .ok_or_else(|| anyhow!("domain not found"))?,
        )?;

        let req_digest = pk_sol.eip712_signing_hash(&domain).to_vec();

        let mut actual_ct_digest = hash_element(
            payload
                .ciphertext
                .as_ref()
                .ok_or_else(|| anyhow!("missing ciphertext"))?,
        );
        if payload.ciphertext_digest != actual_ct_digest {
            return Err(anyhow!("ciphertext digest mismatch"));
        }

        let mut link = req_digest;
        link.append(&mut actual_ct_digest);
        Ok(link)
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[wasm_bindgen(getter_with_clone)]
pub struct Plaintext {
    pub bytes: Vec<u8>,
    fhe_type: FheType,
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
impl Plaintext {
    /// Make a new plaintext from a 128 bit integer
    pub fn new(value: u128, fhe_type: FheType) -> Self {
        if fhe_type == FheType::Euint160
            || fhe_type == FheType::Euint256
            || fhe_type == FheType::Euint2048
        {
            tracing::warn!(
                "Trying to create larger plaintext from only 128 bits. Upper bits will be set to 0."
            );
        }
        Self {
            bytes: value.to_le_bytes().to_vec(),
            fhe_type,
        }
    }

    pub fn from_bytes(bytes: Vec<u8>, fhe_type: FheType) -> Self {
        Self { bytes, fhe_type }
    }

    pub fn from_bool(value: bool) -> Self {
        let plaintext: u8 = match value {
            true => 1,
            false => 0,
        };
        Self {
            bytes: vec![plaintext],
            fhe_type: FheType::Ebool,
        }
    }

    pub fn from_u4(value: u8) -> Self {
        Self {
            bytes: vec![value % 16],
            fhe_type: FheType::Euint4,
        }
    }

    pub fn from_u8(value: u8) -> Self {
        Self {
            bytes: vec![value],
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

    pub fn from_u64(value: u64) -> Self {
        Self {
            bytes: value.to_le_bytes().to_vec(),
            fhe_type: FheType::Euint64,
        }
    }

    pub fn from_u128(value: u128) -> Self {
        Self {
            bytes: value.to_le_bytes().to_vec(),
            fhe_type: FheType::Euint128,
        }
    }

    pub fn from_u160(value: tfhe::integer::U256) -> Self {
        let (low_128, high_128) = value.to_low_high_u128();
        let mut bytes = low_128.to_le_bytes().to_vec();
        bytes.extend(high_128.to_le_bytes()[0..4].to_vec());
        Self {
            bytes,
            fhe_type: FheType::Euint160,
        }
    }

    pub fn from_u160_low_high(value: (u128, u32)) -> Self {
        let mut bytes = value.0.to_le_bytes().to_vec();
        bytes.extend(value.1.to_le_bytes().to_vec());
        Self {
            bytes,
            fhe_type: FheType::Euint160,
        }
    }

    pub fn from_u256(value: tfhe::integer::U256) -> Self {
        let (low_128, high_128) = value.to_low_high_u128();
        let mut bytes = low_128.to_le_bytes().to_vec();
        bytes.extend(high_128.to_le_bytes().to_vec());
        Self {
            bytes,
            fhe_type: FheType::Euint256,
        }
    }

    pub fn from_u2048(value: tfhe::integer::bigint::U2048) -> Self {
        let mut bytes = [0u8; 256];
        value.copy_to_le_byte_slice(&mut bytes);
        Self {
            bytes: bytes.to_vec(),
            fhe_type: FheType::Euint2048,
        }
    }

    pub fn as_bool(&self) -> bool {
        if self.fhe_type != FheType::Ebool {
            tracing::warn!(
                "Plaintext is not of type Bool. Returning the least significant bit as Bool"
            );
        }
        if self.bytes[0] > 1 {
            tracing::warn!("Plaintext should be Bool (0 or 1), but was bigger ({}). Returning the least significant bit as Bool.", self.bytes[0]);
        }
        self.bytes[0] % 2 == 1
    }

    pub fn as_u4(&self) -> u8 {
        if self.fhe_type != FheType::Euint4 {
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
        if self.fhe_type != FheType::Euint8 {
            tracing::warn!("Plaintext is not of type u8. Returning the value modulo 256");
        }
        self.bytes[0]
    }

    pub fn as_u16(&self) -> u16 {
        if self.fhe_type != FheType::Euint16 {
            tracing::warn!("Plaintext is not of type u16. Returning the value modulo 65536 or padding with leading zeros");
        }
        u16::from_le_bytes(sub_slice::<2>(&self.bytes))
    }

    pub fn as_u32(&self) -> u32 {
        if self.fhe_type != FheType::Euint32 {
            tracing::warn!("Plaintext is not of type u32. Returning the value modulo 2^32 or padding with leading zeros");
        }
        u32::from_le_bytes(sub_slice::<4>(&self.bytes))
    }
    pub fn as_u64(&self) -> u64 {
        if self.fhe_type != FheType::Euint64 {
            tracing::warn!("Plaintext is not of type u64. Returning the value modulo 2^64 or padding with leading zeros");
        }
        u64::from_le_bytes(sub_slice::<8>(&self.bytes))
    }

    pub fn as_u128(&self) -> u128 {
        if self.fhe_type != FheType::Euint128 {
            tracing::warn!("Plaintext is not of type u128. Returning the value modulo 2^128 or padding with leading zeros");
        }
        u128::from_le_bytes(sub_slice::<16>(&self.bytes))
    }

    pub fn as_u160(&self) -> tfhe::integer::U256 {
        if self.fhe_type != FheType::Euint160 {
            tracing::warn!("Plaintext is not of type u160. Returning the value modulo 2^160 or padding with leading zeros");
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
        if self.fhe_type != FheType::Euint256 {
            tracing::warn!("Plaintext is not of type u256. Returning the value modulo 2^256 or padding with leading zeros");
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

    pub fn as_u2048(&self) -> tfhe::integer::bigint::U2048 {
        if self.fhe_type != FheType::Euint2048 {
            tracing::warn!("Plaintext is not of type u2048. Returning the value modulo 2^2048 or padding with leading zeros");
        }
        let mut value = tfhe::integer::bigint::U2048::default();
        tfhe::integer::bigint::U2048::copy_from_le_byte_slice(&mut value, &self.bytes);
        value
    }

    pub fn fhe_type(&self) -> FheType {
        self.fhe_type
    }
    // TODO: Implement something that does something like `as_<fhe_type>`

    pub fn from_u512(value: StaticUnsignedBigInt<8>) -> Plaintext {
        let mut bytes = vec![0_u8; 8];
        value.copy_to_le_byte_slice(&mut bytes);
        Plaintext {
            bytes,
            fhe_type: FheType::Euint512,
        }
    }

    pub fn from_u1024(value: StaticUnsignedBigInt<16>) -> Plaintext {
        let mut bytes = vec![0_u8; 16];
        value.copy_to_le_byte_slice(&mut bytes);
        Plaintext {
            bytes,
            fhe_type: FheType::Euint1024,
        }
    }
}

impl From<Plaintext> for Vec<u8> {
    fn from(value: Plaintext) -> Self {
        match value.fhe_type {
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

impl From<u128> for Plaintext {
    fn from(value: u128) -> Self {
        Self::from_u128(value)
    }
}

impl From<u64> for Plaintext {
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

impl From<u32> for Plaintext {
    fn from(value: u32) -> Self {
        Self::from_u32(value)
    }
}

impl From<u16> for Plaintext {
    fn from(value: u16) -> Self {
        Self::from_u16(value)
    }
}

impl From<u8> for Plaintext {
    fn from(value: u8) -> Self {
        Self::from_u8(value)
    }
}

impl From<bool> for Plaintext {
    fn from(value: bool) -> Self {
        Self::from_bool(value)
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
    fn verification_key(&self) -> Vec<u8>;
    fn digest(&self) -> Vec<u8>;
}

pub trait FheTypeResponse {
    fn fhe_type(&self) -> anyhow::Result<FheType>;
}

impl MetaResponse for ReencryptionResponsePayload {
    fn verification_key(&self) -> Vec<u8> {
        self.verification_key.to_owned()
    }

    fn digest(&self) -> Vec<u8> {
        self.digest.to_owned()
    }

    fn version(&self) -> u32 {
        self.version
    }
}

impl FheTypeResponse for ReencryptionResponsePayload {
    fn fhe_type(&self) -> anyhow::Result<FheType> {
        Ok(self.fhe_type())
    }
}

impl MetaResponse for DecryptionResponsePayload {
    fn verification_key(&self) -> Vec<u8> {
        self.verification_key.to_owned()
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
    /// Method for deterministically deriving a request ID from an arbitrary string.
    /// Is currently only used for testing purposes, since deriving is the responsibility of the smart contract.
    #[cfg(any(test, feature = "testing"))]
    pub fn derive(name: &str) -> anyhow::Result<Self> {
        let mut hashed_name =
            crate::cryptography::signcryption::serialize_hash_element(&name.to_string())?;
        // Truncate and convert to hex
        hashed_name.truncate(ID_LENGTH);
        let res_hash = hex::encode(hashed_name);
        Ok(RequestId {
            request_id: res_hash,
        })
    }

    /// Validates if a user-specified input is a request ID.
    /// By valid we mean if it is a hex string of a static length. This is done to ensure it can be
    /// part of a valid path, without risk of path-traversal attacks in case the key request
    /// call is publicly accessible.
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

impl From<RequestId> for String {
    fn from(request_id: RequestId) -> Self {
        request_id.request_id
    }
}

impl TryFrom<RequestId> for u128 {
    type Error = anyhow::Error;

    // Convert a RequestId to a u128 through truncation of the first bytes.
    fn try_from(value: RequestId) -> Result<Self, Self::Error> {
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

impl From<u128> for RequestId {
    fn from(value: u128) -> Self {
        let bytes = value.to_be_bytes();
        let hex_string = hex::encode(bytes); // 128 bits / 32 bytes
        RequestId {
            request_id: "00000000".to_string() + hex_string.as_str(), // fill up to 160 bits / 40 bytes with 8 leading hex zeros
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, Hash, VersionsDispatch)]
#[cfg(feature = "non-wasm")]
pub enum PublicParameterWithParamIDVersioned {
    V0(PublicParameterWithParamID),
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, Hash, Versionize)]
#[versionize(PublicParameterWithParamIDVersioned)]
#[cfg(feature = "non-wasm")]
pub struct PublicParameterWithParamID {
    pub pp: PublicParameter,
    // We simply use the i32 instead of ParamChoice because ParamChoice is
    // a grpc type and cannot be versioned easily.
    pub param_id: i32,
}

#[cfg(feature = "non-wasm")]
impl Named for PublicParameterWithParamID {
    const NAME: &'static str = "PublicParameterWithParamID";
}

#[derive(Serialize, Deserialize, Debug, Clone, VersionsDispatch)]
pub enum PublicKeyTypeVersioned {
    V0(PublicKeyType),
}

#[derive(Serialize, Deserialize, Debug, Clone, Versionize)]
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

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(Serialize))]
pub enum WrappedPublicKeyOwned {
    Compact(tfhe::CompactPublicKey),
}

#[cfg(test)]
pub(crate) trait RequestIdGetter {
    fn request_id(&self) -> Option<RequestId>;
}

#[cfg(test)]
impl RequestIdGetter for CrsGenRequest {
    fn request_id(&self) -> Option<RequestId> {
        self.request_id.clone()
    }
}

#[cfg(test)]
impl RequestIdGetter for ZkVerifyRequest {
    fn request_id(&self) -> Option<RequestId> {
        self.request_id.clone()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::Plaintext;
    use crate::kms::RequestId;
    use aes_prng::AesRng;
    use rand::{RngCore, SeedableRng};

    #[test]
    fn sunshine_plaintext_as_u256() {
        let mut rng = AesRng::seed_from_u64(1);
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);

        let plaintext = Plaintext {
            bytes: bytes.to_vec(),
            fhe_type: crate::kms::FheType::Euint160,
        };
        // Check the value is greater than 2^128
        assert!(plaintext.as_u160() > tfhe::integer::U256::from((0, 1)));
        assert!(plaintext.as_u256() > tfhe::integer::U256::from((0, 1)));
        // Sanity check the internal values - at least one byte must be different from zero
        assert!(bytes.iter().any(|&b| b != 0));
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
        assert_eq!(Plaintext::from_u32(u32::MAX).as_u32(), u32::MAX);
        assert_eq!(Plaintext::from_u32(0).as_u32(), 0);

        assert_eq!(Plaintext::from_u64(u64::MAX - 1).as_u64(), u64::MAX - 1);
        assert_eq!(Plaintext::from_u64(u64::MAX).as_u64(), u64::MAX);
        assert_eq!(Plaintext::from_u64(0).as_u64(), 0);

        assert_eq!(Plaintext::from_u128(u128::MAX - 1).as_u128(), u128::MAX - 1);
        let alt_u128_plaintext = Plaintext::new(u128::MAX - 1, crate::kms::FheType::Euint128);
        assert_eq!(Plaintext::from_u128(u128::MAX - 1), alt_u128_plaintext);

        let u160_val = tfhe::integer::U256::from((23, 999));
        assert_eq!(Plaintext::from_u160(u160_val).as_u160(), u160_val);
        let u160_val = tfhe::integer::U256::from((u128::MAX, 1000));
        assert_eq!(Plaintext::from_u160(u160_val).as_u160(), u160_val);
        let alt_u160_val = Plaintext::from_u160_low_high((u128::MAX, 1000));
        assert_eq!(Plaintext::from_u160(u160_val), alt_u160_val);

        let u256_val = tfhe::integer::U256::from((u128::MAX, u128::MAX));
        assert_eq!(Plaintext::from_u256(u256_val).as_u256(), u256_val);
        let u256_val = tfhe::integer::U256::from((1, 1 << 77));
        assert_eq!(Plaintext::from_u256(u256_val).as_u256(), u256_val);

        let bytes = [0xFF; 256];
        let mut u2048_val = tfhe::integer::bigint::U2048::default();
        tfhe::integer::bigint::U2048::copy_from_le_byte_slice(&mut u2048_val, &bytes);
        assert_eq!(Plaintext::from_u2048(u2048_val).as_u2048(), u2048_val);
        let u2048_val = tfhe::integer::bigint::U2048::from(12345_u64);
        assert_eq!(Plaintext::from_u2048(u2048_val).as_u2048(), u2048_val);
    }

    #[test]
    fn test_request_id_convert() {
        let request_id = RequestId {
            request_id: "0000000000000000000000000000000000000001".to_owned(),
        };
        assert!(request_id.is_valid());
        let x: u128 = request_id.clone().try_into().unwrap();
        let req_id2 = RequestId::from(x);
        assert_eq!(request_id, req_id2);
    }

    #[test]
    fn test_abi_encoding_fhevm() {
        let u256_val = tfhe::integer::U256::from((1, 256));
        let u2048_val = tfhe::integer::bigint::U2048::from(257_u64);

        // a batch of multiple plaintexts of different types
        let pts_2048: Vec<Plaintext> = vec![
            Plaintext::from_u2048(u2048_val),
            Plaintext::from_bool(true),
            Plaintext::from_u4(4),
            Plaintext::from_u4(5),
            Plaintext::from_u2048(u2048_val),
            Plaintext::from_u8(8),
            Plaintext::from_u16(16),
            Plaintext::from_u32(32),
            Plaintext::from_u128(128),
            Plaintext::from_u160_low_high((234, 255)),
            Plaintext::from_u256(u256_val),
            Plaintext::from_u2048(u2048_val),
        ];

        // encode plaintexts into a list of solidity bytes using `alloy`
        let bytes_2048 = super::abi_encode_plaintexts(&pts_2048);
        let hexbytes_2048 = hex::encode(bytes_2048);

        // this is the encoding of the same list of plaintexts (pts_2048) using the outdated `ethers` crate.
        let reference_2048 = "00000000000000000000000000000000000000000000000000000000000001a0\
                               0000000000000000000000000000000000000000000000000000000000000001\
                               0000000000000000000000000000000000000000000000000000000000000004\
                               0000000000000000000000000000000000000000000000000000000000000005\
                               00000000000000000000000000000000000000000000000000000000000002c0\
                               0000000000000000000000000000000000000000000000000000000000000008\
                               0000000000000000000000000000000000000000000000000000000000000010\
                               0000000000000000000000000000000000000000000000000000000000000020\
                               0000000000000000000000000000000000000000000000000000000000000080\
                               000000000000000000000000000000ff000000000000000000000000000000ea\
                               0000000000000000000000000000010000000000000000000000000000000001\
                               00000000000000000000000000000000000000000000000000000000000003e0\
                               0000000000000000000000000000000000000000000000000000000000000100\
                               0000000000000000000000000000000000000000000000000000000000000000\
                               0000000000000000000000000000000000000000000000000000000000000000\
                               0000000000000000000000000000000000000000000000000000000000000000\
                               0000000000000000000000000000000000000000000000000000000000000000\
                               0000000000000000000000000000000000000000000000000000000000000000\
                               0000000000000000000000000000000000000000000000000000000000000000\
                               0000000000000000000000000000000000000000000000000000000000000000\
                               0000000000000000000000000000000000000000000000000000000000000101\
                               0000000000000000000000000000000000000000000000000000000000000100\
                               0000000000000000000000000000000000000000000000000000000000000000\
                               0000000000000000000000000000000000000000000000000000000000000000\
                               0000000000000000000000000000000000000000000000000000000000000000\
                               0000000000000000000000000000000000000000000000000000000000000000\
                               0000000000000000000000000000000000000000000000000000000000000000\
                               0000000000000000000000000000000000000000000000000000000000000000\
                               0000000000000000000000000000000000000000000000000000000000000000\
                               0000000000000000000000000000000000000000000000000000000000000101\
                               0000000000000000000000000000000000000000000000000000000000000100\
                               0000000000000000000000000000000000000000000000000000000000000000\
                               0000000000000000000000000000000000000000000000000000000000000000\
                               0000000000000000000000000000000000000000000000000000000000000000\
                               0000000000000000000000000000000000000000000000000000000000000000\
                               0000000000000000000000000000000000000000000000000000000000000000\
                               0000000000000000000000000000000000000000000000000000000000000000\
                               0000000000000000000000000000000000000000000000000000000000000000\
                               0000000000000000000000000000000000000000000000000000000000000101";

        assert_eq!(reference_2048, hexbytes_2048.as_str());

        // a batch of a single plaintext
        let pts_16: Vec<Plaintext> = vec![Plaintext::from_u16(16)];

        // encode plaintexts into a list of solidity bytes using `alloy`
        let bytes_16 = super::abi_encode_plaintexts(&pts_16);
        let hexbytes_16 = hex::encode(bytes_16);

        // this is the encoding of the same list of plaintexts (pts_16) using the outdated `ethers` crate.
        let reference_16 = "0000000000000000000000000000000000000000000000000000000000000010";

        assert_eq!(reference_16, hexbytes_16.as_str());

        // a batch of a two plaintext that are not of type Euint2048
        let pts_16_2: Vec<Plaintext> = vec![Plaintext::from_u16(16), Plaintext::from_u16(16)];

        // encode plaintexts into a list of solidity bytes using `alloy`
        let bytes_16_2 = super::abi_encode_plaintexts(&pts_16_2);
        let hexbytes_16_2 = hex::encode(bytes_16_2);

        // this is the encoding of the same list of plaintexts (pts_16_2) using the outdated `ethers` crate.
        let reference_16_2 = "0000000000000000000000000000000000000000000000000000000000000010\
                                    0000000000000000000000000000000000000000000000000000000000000010";

        assert_eq!(reference_16_2, hexbytes_16_2.as_str());
    }
}

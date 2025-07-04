use super::traits::BaseKms;
use crate::consts::ID_LENGTH;
use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::cryptography::decompression;
use crate::cryptography::internal_crypto_types::UnifiedPublicEncKey;
use crate::cryptography::internal_crypto_types::{PrivateSigKey, PublicSigKey};
use crate::cryptography::signcryption::internal_verify_sig;
use crate::util::key_setup::FhePrivateKey;
use crate::{anyhow_error_and_log, compute_user_decrypt_message_hash};
use aes_prng::AesRng;
use alloy_dyn_abi::DynSolValue;
use alloy_primitives::{Bytes, FixedBytes, Uint};
use alloy_primitives::{B256, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::Eip712Domain;
use alloy_sol_types::SolStruct;
use k256::ecdsa::SigningKey;
use kms_grpc::kms::v1::{
    CiphertextFormat, FheParameter, SignedPubDataHandle, TypedPlaintext,
    UserDecryptionResponsePayload,
};
use kms_grpc::rpc_types::{
    FhePubKey, FheServerKey, PubDataType, PublicDecryptVerification, SignedPubDataHandleInternal,
    CRS,
};
use kms_grpc::RequestId;
use rand::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tfhe::integer::compression_keys::DecompressionKey;
use tfhe::integer::BooleanBlock;
use tfhe::named::Named;
use tfhe::safe_serialization::safe_deserialize;
use tfhe::FheUint80;
use tfhe::{
    FheBool, FheUint1024, FheUint128, FheUint16, FheUint160, FheUint2048, FheUint256, FheUint32,
    FheUint4, FheUint512, FheUint64, FheUint8,
};
use tfhe::{FheTypes, Versionize};
use tfhe_versionable::VersionsDispatch;
use threshold_fhe::execution::endpoints::decryption::RadixOrBoolCiphertext;
use threshold_fhe::execution::endpoints::decryption::{
    LowLevelCiphertext, SnsRadixOrBoolCiphertext,
};
use threshold_fhe::execution::endpoints::keygen::FhePubKeySet;
#[cfg(feature = "non-wasm")]
use threshold_fhe::execution::keyset_config as ddec_keyset_config;
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use threshold_fhe::hashing::hash_element;
use threshold_fhe::hashing::serialize_hash_element;
use threshold_fhe::hashing::DomainSep;
use tokio::sync::Mutex;
use tracing::error;

// Domain separators for cryptographic operations to ensure domain separation

/// Domain separator for request ID hashing
pub(crate) const DSEP_REQUEST_ID: DomainSep = *b"REQST_ID";
/// Domain separator for handle generation
pub(crate) const DSEP_HANDLE: DomainSep = *b"_HANDLE_";
/// Domain separator for external public data
pub(crate) const DSEP_PUBDATA_EXTERNAL: DomainSep = *b"PDAT_EXT";
/// Domain separator for public key data
pub(crate) const DSEP_PUBDATA_KEY: DomainSep = *b"PDAT_KEY";
/// Domain separator for CRS (Common Reference String) data
pub(crate) const DSEP_PUBDATA_CRS: DomainSep = *b"PDAT_CRS";

#[cfg(feature = "non-wasm")]
#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum KmsFheKeyHandlesVersioned {
    V0(KmsFheKeyHandles),
}

/// Centralized KMS private key material storage
///
/// This structure securely holds sensitive key material used by the KMS,
/// including the client key, optional decompression key, and public key metadata.
#[cfg(feature = "non-wasm")]
#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(KmsFheKeyHandlesVersioned)]
pub struct KmsFheKeyHandles {
    /// Client's private key for FHE operations
    pub client_key: FhePrivateKey,

    /// Optional key for ciphertext decompression
    pub decompression_key: Option<DecompressionKey>,

    /// Maps public key types to their corresponding signed handles and metadata
    pub public_key_info: HashMap<PubDataType, SignedPubDataHandleInternal>,
}

impl Named for KmsFheKeyHandles {
    /// Returns the type name for versioning and serialization
    const NAME: &'static str = "KmsFheKeyHandles";
}

#[cfg(feature = "non-wasm")]
impl KmsFheKeyHandles {
    /// Computes key handles for public key materials with signatures.
    ///
    /// # Important
    /// - Only use with freshly generated keys
    /// - Not suitable for existing keys due to versioning constraints
    /// - Version upgrades will invalidate signatures
    ///
    /// # Security Note
    /// Signatures are computed over versionized keys to ensure consistency.
    pub fn new(
        sig_key: &PrivateSigKey,
        client_key: FhePrivateKey,
        public_keys: &FhePubKeySet,
        decompression_key: Option<DecompressionKey>,
        eip712_domain: Option<&alloy_sol_types::Eip712Domain>,
    ) -> anyhow::Result<Self> {
        let mut public_key_info = HashMap::new();
        public_key_info.insert(
            PubDataType::PublicKey,
            compute_info(
                sig_key,
                &crate::engine::base::DSEP_PUBDATA_KEY,
                &public_keys.public_key,
                eip712_domain,
            )?,
        );
        public_key_info.insert(
            PubDataType::ServerKey,
            compute_info(
                sig_key,
                &DSEP_PUBDATA_KEY,
                &public_keys.server_key,
                eip712_domain,
            )?,
        );
        Ok(KmsFheKeyHandles {
            client_key,
            decompression_key,
            public_key_info,
        })
    }
}

/// Derives a deterministic request ID from an input string.
///
/// # Usage
/// Primarily for testing and internal purposes (e.g., PRSS IDs).
/// In production, request IDs should be derived by the smart contract.
///
/// # Arguments
/// * `name` - Input string to derive ID from
///
/// # Returns
/// - `Ok(RequestId)` on success
/// - `Err` if hashing fails
pub fn derive_request_id(name: &str) -> anyhow::Result<RequestId> {
    let mut digest = serialize_hash_element(&DSEP_REQUEST_ID, &name.to_string())?;
    if digest.len() < ID_LENGTH {
        anyhow::bail!(
            "derived request ID should have at least length {ID_LENGTH}, but only got {}",
            digest.len()
        )
    }
    // Truncate and convert to hex
    digest.truncate(ID_LENGTH);
    let res_hex = hex::encode(digest);
    Ok(RequestId::from_str(&res_hex)?)
}

/// Computes and signs a unique handle for a serializable element.
///
/// # Process
/// 1. Serializes the element
/// 2. Computes a unique handle
/// 3. Signs the handle using the provided key
///
/// # Security
/// Uses domain separation to prevent signature misuse.
pub(crate) fn compute_info<S: Serialize + Versionize + Named>(
    sk: &PrivateSigKey,
    dsep: &DomainSep,
    element: &S,
    domain: Option<&alloy_sol_types::Eip712Domain>,
) -> anyhow::Result<SignedPubDataHandleInternal> {
    let handle = compute_handle(element)?;
    let signature = crate::cryptography::signcryption::internal_sign(dsep, &handle, sk)?;

    // if we get an EIP-712 domain, compute the external signature
    let external_signature = match domain {
        Some(domain) => compute_external_pubdata_signature(sk, element, domain)?,
        None => {
            tracing::warn!("Skipping external signature computation due to missing domain");
            vec![]
        }
    };

    Ok(SignedPubDataHandleInternal {
        key_handle: handle,
        signature: bc2wrap::serialize(&signature)?,
        external_signature,
    })
}

/// Computes a unique handle for an element using its hash digest.
///
/// # Process
/// 1. Hashes the element with domain separation
/// 2. Truncates the hash
/// 3. Converts to hex string
///
/// # Returns
/// - `Ok(String)` with hex-encoded handle
/// - `Err` if hashing fails
pub fn compute_handle<S>(element: &S) -> anyhow::Result<String>
where
    S: Serialize + Versionize + Named,
{
    let mut digest = safe_serialize_hash_element_versioned(&DSEP_HANDLE, element)?;
    // Truncate and convert to hex
    digest.truncate(ID_LENGTH);
    Ok(hex::encode(digest))
}

macro_rules! deserialize_to_low_level_helper {
    ($rust_type:ty,$ct_format:expr,$serialized_high_level:expr,$decompression_key:expr) => {{
        match $ct_format {
            CiphertextFormat::SmallCompressed => {
                let hl_ct: $rust_type =
                    decompression::tfhe_safe_deserialize_and_uncompress::<$rust_type>(
                        $decompression_key
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("missing decompression key"))?,
                        $serialized_high_level,
                    )?;
                let (radix_ct, _id, _tag) = hl_ct.into_raw_parts();
                LowLevelCiphertext::Small(RadixOrBoolCiphertext::Radix(radix_ct))
            }
            CiphertextFormat::SmallExpanded => {
                let hl_ct: $rust_type =
                    decompression::tfhe_safe_deserialize::<$rust_type>($serialized_high_level)?;
                let (radix_ct, _id, _tag) = hl_ct.into_raw_parts();
                LowLevelCiphertext::Small(RadixOrBoolCiphertext::Radix(radix_ct))
            }
            CiphertextFormat::BigCompressed => {
                anyhow::bail!("big compressed ciphertexts are not supported yet");
            }
            CiphertextFormat::BigExpanded => {
                let r = safe_deserialize::<tfhe::SquashedNoiseFheUint>(
                    std::io::Cursor::new($serialized_high_level),
                    SAFE_SER_SIZE_LIMIT,
                )
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let radix_ct = r.underlying_squashed_noise_ciphertext().clone();
                LowLevelCiphertext::Big(SnsRadixOrBoolCiphertext::Radix(radix_ct))
            }
        }
    }};
}

pub fn deserialize_to_low_level(
    fhe_type: FheTypes,
    ct_format: CiphertextFormat,
    serialized_high_level: &[u8],
    decompression_key: &Option<DecompressionKey>,
) -> anyhow::Result<LowLevelCiphertext> {
    let radix_ct = match fhe_type {
        FheTypes::Bool => match ct_format {
            CiphertextFormat::SmallCompressed => {
                let hl_ct: FheBool = decompression::tfhe_safe_deserialize_and_uncompress::<FheBool>(
                    decompression_key
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("missing decompression key"))?,
                    serialized_high_level,
                )?;
                let radix_ct = hl_ct.into_raw_parts();
                LowLevelCiphertext::Small(RadixOrBoolCiphertext::Bool(BooleanBlock::new_unchecked(
                    radix_ct,
                )))
            }
            CiphertextFormat::SmallExpanded => {
                let hl_ct: FheBool =
                    decompression::tfhe_safe_deserialize::<FheBool>(serialized_high_level)?;
                let radix_ct = hl_ct.into_raw_parts();
                LowLevelCiphertext::Small(RadixOrBoolCiphertext::Bool(BooleanBlock::new_unchecked(
                    radix_ct,
                )))
            }
            CiphertextFormat::BigCompressed => {
                anyhow::bail!("big compressed ciphertexts are not supported yet");
            }
            CiphertextFormat::BigExpanded => {
                let r = safe_deserialize::<tfhe::SquashedNoiseFheBool>(
                    std::io::Cursor::new(serialized_high_level),
                    SAFE_SER_SIZE_LIMIT,
                )
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let radix_ct = r.underlying_squashed_noise_ciphertext().clone();
                LowLevelCiphertext::Big(SnsRadixOrBoolCiphertext::Bool(radix_ct))
            }
        },
        FheTypes::Uint4 => {
            deserialize_to_low_level_helper!(
                FheUint4,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheTypes::Uint8 => {
            deserialize_to_low_level_helper!(
                FheUint8,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheTypes::Uint16 => {
            deserialize_to_low_level_helper!(
                FheUint16,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheTypes::Uint32 => {
            deserialize_to_low_level_helper!(
                FheUint32,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheTypes::Uint64 => {
            deserialize_to_low_level_helper!(
                FheUint64,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheTypes::Uint80 => {
            deserialize_to_low_level_helper!(
                FheUint80,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheTypes::Uint128 => {
            deserialize_to_low_level_helper!(
                FheUint128,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheTypes::Uint160 => {
            deserialize_to_low_level_helper!(
                FheUint160,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheTypes::Uint256 => {
            deserialize_to_low_level_helper!(
                FheUint256,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheTypes::Uint512 => {
            deserialize_to_low_level_helper!(
                FheUint512,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheTypes::Uint1024 => {
            deserialize_to_low_level_helper!(
                FheUint1024,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheTypes::Uint2048 => {
            deserialize_to_low_level_helper!(
                FheUint2048,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        unsupported_fhe_type => {
            anyhow::bail!("Unsupported fhe_type: {:?}", unsupported_fhe_type);
        }
    };
    Ok(radix_ct)
}

/// Serialize and hash a versioned element using tfhe-rs' `safe_serialize` function.
#[cfg(feature = "non-wasm")]
pub fn safe_serialize_hash_element_versioned<T>(
    domain_separator: &DomainSep,
    msg: &T,
) -> anyhow::Result<Vec<u8>>
where
    T: Serialize + tfhe::Versionize + tfhe::named::Named,
{
    let mut buf = Vec::new();
    match tfhe::safe_serialization::safe_serialize(msg, &mut buf, SAFE_SER_SIZE_LIMIT) {
        Ok(()) => Ok(hash_element(domain_separator, &buf)),
        Err(e) => anyhow::bail!("Could not encode message due to error: {:?}", e),
    }
}

pub(crate) fn compute_external_user_decrypt_signature(
    server_sk: &PrivateSigKey,
    payload: &UserDecryptionResponsePayload,
    eip712_domain: &Eip712Domain,
    user_pk: &UnifiedPublicEncKey,
) -> anyhow::Result<Vec<u8>> {
    let message_hash = compute_user_decrypt_message_hash(payload, eip712_domain, user_pk)?;

    let signer = PrivateKeySigner::from_signing_key(server_sk.sk().clone());
    let signer_address = signer.address();
    tracing::info!("Signer address: {:?}", signer_address);

    // Sign the hash synchronously with the wallet.
    let signature = signer.sign_hash_sync(&message_hash)?.as_bytes().to_vec();

    tracing::info!(
        "UserDecryptResponseVerification Signature: {:?} with length {}",
        hex::encode(signature.clone()),
        signature.len(),
    );
    Ok(signature)
}

/// take external handles and plaintext in the form of bytes, convert them to the required solidity types and sign them using EIP-712 for external verification (e.g. in fhevm).
pub(crate) fn compute_external_pt_signature(
    server_sk: &PrivateSigKey,
    ext_handles_bytes: Vec<Vec<u8>>,
    pts: &[TypedPlaintext],
    eip712_domain: Eip712Domain,
) -> Vec<u8> {
    let message_hash = compute_pt_message_hash(ext_handles_bytes, pts, eip712_domain);

    let signer = PrivateKeySigner::from_signing_key(server_sk.sk().clone());
    let signer_address = signer.address();
    tracing::info!("Signer address: {:?}", signer_address);

    // Sign the hash synchronously with the wallet.
    let signature = signer
        .sign_hash_sync(&message_hash)
        .unwrap()
        .as_bytes()
        .to_vec();

    tracing::info!("PT Signature: {:?}", hex::encode(signature.clone()));

    signature
}

/// Safely serialize some public data, convert it to a solidity type byte array and compute the EIP-712 message hash for external verification (e.g. in fhevm).
pub fn compute_external_pubdata_message_hash<D: Serialize + Versionize + Named>(
    data: &D,
    eip712_domain: &Eip712Domain,
) -> anyhow::Result<B256> {
    let bytes = safe_serialize_hash_element_versioned(&DSEP_PUBDATA_EXTERNAL, data)?;

    // distinguish between the different types of public data we can sign according to their type name and sign it with EIP-712
    let message_hash = match D::NAME {
        "zk::CompactPkeCrs" => {
            let message = CRS { crs: bytes.into() };
            message.eip712_signing_hash(eip712_domain)
        }
        "high_level_api::CompactPublicKey" => {
            let message = FhePubKey {
                pubkey: bytes.into(),
            };
            message.eip712_signing_hash(eip712_domain)
        }
        "high_level_api::ServerKey" => {
            let message = FheServerKey {
                server_key: bytes.into(),
            };
            message.eip712_signing_hash(eip712_domain)
        }
        e => {
            return Err(anyhow_error_and_log(format!(
                "Cannot compute EIP-712 signature on type {e}. Expected one of: zk::CompactPkeCrs, high_level_api::CompactPublicKey, high_level_api::ServerKey."
            )))
        }
    };
    tracing::info!("Public Data EIP-712 Message hash: {:?}", message_hash);
    Ok(message_hash)
}

/// take some public data (e.g. public key or CRS) and sign it using EIP-712 for external verification (e.g. in fhevm).
pub fn compute_external_pubdata_signature<D: Serialize + Versionize + Named>(
    client_sk: &PrivateSigKey,
    data: &D,
    eip712_domain: &Eip712Domain,
) -> anyhow::Result<Vec<u8>> {
    let message_hash = compute_external_pubdata_message_hash(data, eip712_domain)?;

    let signer = PrivateKeySigner::from_signing_key(client_sk.sk().clone());
    let signer_address = signer.address();
    tracing::info!("Signer address: {:?}", signer_address);

    // Sign the hash synchronously with the wallet.
    let signature = signer.sign_hash_sync(&message_hash)?.as_bytes().to_vec();

    tracing::info!(
        "Public Data EIP-712 Signature: {:?}",
        hex::encode(signature.clone())
    );

    Ok(signature)
}

pub struct BaseKmsStruct {
    pub(crate) sig_key: Arc<PrivateSigKey>,
    pub(crate) serialized_verf_key: Arc<Vec<u8>>,
    pub(crate) rng: Arc<Mutex<AesRng>>,
}

impl BaseKmsStruct {
    pub fn new(sig_key: PrivateSigKey) -> anyhow::Result<Self> {
        let serialized_verf_key = Arc::new(bc2wrap::serialize(&PublicSigKey::new(
            SigningKey::verifying_key(sig_key.sk()).to_owned(),
        ))?);
        Ok(BaseKmsStruct {
            sig_key: Arc::new(sig_key),
            serialized_verf_key,
            rng: Arc::new(Mutex::new(AesRng::from_entropy())),
        })
    }

    /// Make a clone of this struct with a newly initialized RNG s.t. that both the new and old struct are safe to use.
    pub async fn new_instance(&self) -> Self {
        Self {
            sig_key: self.sig_key.clone(),
            serialized_verf_key: self.serialized_verf_key.clone(),
            rng: Arc::new(Mutex::new(self.new_rng().await)),
        }
    }

    pub async fn new_rng(&self) -> AesRng {
        let mut seed = [0u8; crate::consts::RND_SIZE];
        // Make a seperate scope for the rng so that it is dropped before the lock is released
        {
            let mut base_rng = self.rng.lock().await;
            base_rng.fill_bytes(seed.as_mut());
        }
        AesRng::from_seed(seed)
    }
}

impl BaseKms for BaseKmsStruct {
    fn verify_sig<T>(
        dsep: &DomainSep,
        payload: &T,
        signature: &crate::cryptography::internal_crypto_types::Signature,
        key: &PublicSigKey,
    ) -> anyhow::Result<()>
    where
        T: Serialize + AsRef<[u8]>,
    {
        internal_verify_sig(dsep, &payload, signature, key)
    }

    /// sign `msg` using the KMS' private signing key
    fn sign<T>(
        &self,
        dsep: &DomainSep,
        msg: &T,
    ) -> anyhow::Result<crate::cryptography::internal_crypto_types::Signature>
    where
        T: Serialize + AsRef<[u8]>,
    {
        crate::cryptography::signcryption::internal_sign(dsep, msg, &self.sig_key)
    }

    fn get_serialized_verf_key(&self) -> Vec<u8> {
        self.serialized_verf_key.as_ref().clone()
    }

    fn digest<T>(domain_separator: &DomainSep, msg: &T) -> anyhow::Result<Vec<u8>>
    where
        T: ?Sized + AsRef<[u8]>,
    {
        Ok(hash_element(domain_separator, msg))
    }
}

/// ABI encodes a list of typed plaintexts into a single byte vector for Ethereum compatibility.
/// This follows the encoding pattern used in the JavaScript version for decrypted results.
pub fn abi_encode_plaintexts(ptxts: &[TypedPlaintext]) -> Bytes {
    let mut results: Vec<DynSolValue> = Vec::new();
    results.push(DynSolValue::Uint(U256::from(42), 256)); // requestID placeholder

    for clear_text in ptxts.iter() {
        if let Ok(fhe_type) = clear_text.fhe_type() {
            match fhe_type {
                FheTypes::Uint512 => {
                    if clear_text.bytes.len() != 64 {
                        error!(
                            "Invalid length for Euint512: expected 64, got {}",
                            clear_text.bytes.len()
                        );
                        results.push(DynSolValue::Bytes(vec![0u8; 64]));
                    } else {
                        let arr: [u8; 64] = match clear_text.bytes.as_slice().try_into() {
                            Ok(arr) => arr,
                            Err(e) => {
                                error!("Failed to convert bytes to array for Euint512: {}", e);
                                [0u8; 64]
                            }
                        };
                        let value = Uint::<512, 8>::from_le_bytes(arr);
                        let bytes: [u8; 64] = value.to_be_bytes();
                        results.push(DynSolValue::Bytes(bytes.to_vec()));
                    }
                }
                FheTypes::Uint1024 => {
                    if clear_text.bytes.len() != 128 {
                        error!(
                            "Invalid length for Euint1024: expected 128, got {}",
                            clear_text.bytes.len()
                        );
                        results.push(DynSolValue::Bytes(vec![0u8; 128]));
                    } else {
                        let arr: [u8; 128] = match clear_text.bytes.as_slice().try_into() {
                            Ok(arr) => arr,
                            Err(e) => {
                                error!("Failed to convert bytes to array for Euint1024: {}", e);
                                [0u8; 128]
                            }
                        };
                        let value = Uint::<1024, 16>::from_le_bytes(arr);
                        let bytes: [u8; 128] = value.to_be_bytes();
                        results.push(DynSolValue::Bytes(bytes.to_vec()));
                    }
                }
                FheTypes::Uint2048 => {
                    if clear_text.bytes.len() != 256 {
                        error!(
                            "Invalid length for Euint2048: expected 256, got {}",
                            clear_text.bytes.len()
                        );
                        results.push(DynSolValue::Bytes(vec![0u8; 256]));
                    } else {
                        let arr: [u8; 256] = match clear_text.bytes.as_slice().try_into() {
                            Ok(arr) => arr,
                            Err(e) => {
                                error!("Failed to convert bytes to array for Euint2048: {}", e);
                                [0u8; 256]
                            }
                        };
                        let value = Uint::<2048, 32>::from_le_bytes(arr);
                        let bytes: [u8; 256] = value.to_be_bytes();
                        results.push(DynSolValue::Bytes(bytes.to_vec()));
                    }
                }
                _ => {
                    // For other types, convert to U256
                    if clear_text.bytes.len() > 32 {
                        error!(
                            "Byte length too large for U256: got {}, max is 32",
                            clear_text.bytes.len()
                        );
                        results.push(DynSolValue::Uint(U256::from(0), 256));
                    } else {
                        // Pad the bytes to 32 bytes for U256 (assuming little-endian input)
                        let mut padded = [0u8; 32];
                        padded[..clear_text.bytes.len()].copy_from_slice(&clear_text.bytes);
                        let value = U256::from_le_bytes(padded);
                        results.push(DynSolValue::Uint(value, 256));
                    }
                }
            }
        }
    }

    results.push(DynSolValue::Array(vec![])); // signatures placeholder

    let data = DynSolValue::Tuple(results).abi_encode_params();
    let decrypted_result = data[32..data.len() - 32].to_vec(); // remove placeholder corresponding to requestID and signatures
    Bytes::from(decrypted_result)
}

pub fn compute_pt_message_hash(
    ext_handles_bytes: Vec<Vec<u8>>,
    pts: &[TypedPlaintext],
    eip712_domain: Eip712Domain,
) -> B256 {
    // convert external_handles back to U256 to be signed
    #[allow(clippy::useless_conversion)]
    // Added `allow` as without using `.into()` displays an error despite it works
    let external_handles: Vec<_> = ext_handles_bytes
        .into_iter()
        .map(|e| FixedBytes::<32>::left_padding_from(e.as_slice()).into())
        .collect();

    let pt_bytes = abi_encode_plaintexts(pts);

    // the solidity structure to sign with EIP-712
    let message = PublicDecryptVerification {
        ctHandles: external_handles,
        decryptedResult: pt_bytes,
    };

    let message_hash = message.eip712_signing_hash(&eip712_domain);
    tracing::info!("PT EIP-712 Message hash: {:?}", message_hash);
    message_hash
}

pub(crate) fn retrieve_parameters(fhe_parameter: i32) -> anyhow::Result<DKGParams> {
    let fhe_parameter: crate::cryptography::internal_crypto_types::WrappedDKGParams =
        FheParameter::try_from(fhe_parameter)?.into();
    Ok(*fhe_parameter)
}

// Values that need to be stored temporarily as part of an async key generation call.
#[cfg(feature = "non-wasm")]
pub type KeyGenCallValues = HashMap<PubDataType, SignedPubDataHandleInternal>;

// Values that need to be stored temporarily as part of an async decryption call.
// Represents the digest of the request and the result of the decryption (a batch of plaintests),
// as well as an external signature on the batch.
#[cfg(feature = "non-wasm")]
pub type PubDecCallValues = (Vec<u8>, Vec<TypedPlaintext>, Vec<u8>);

// Values that need to be stored temporarily as part of an async user decryption call.
// Represents UserDecryptionResponsePayload, external_handles, external_signature.
#[cfg(feature = "non-wasm")]
pub type UserDecryptCallValues = (UserDecryptionResponsePayload, Vec<u8>);

/// Helper method which takes a [HashMap<PubDataType, SignedPubDataHandle>] and returns
/// [HashMap<String, SignedPubDataHandle>] by applying the [ToString] function on [PubDataType] for each element in the map.
/// The function is needed since protobuf does not support enums in maps.
pub(crate) fn convert_key_response(
    key_info_map: HashMap<PubDataType, SignedPubDataHandleInternal>,
) -> HashMap<String, SignedPubDataHandle> {
    key_info_map
        .into_iter()
        .map(|(key_type, key_info)| {
            let key_type = key_type.to_string();
            (key_type, key_info.into())
        })
        .collect()
}

#[cfg(feature = "non-wasm")]
pub(crate) struct WrappedKeySetConfig(kms_grpc::kms::v1::KeySetConfig);

#[cfg(feature = "non-wasm")]
impl TryFrom<WrappedKeySetConfig> for ddec_keyset_config::KeySetConfig {
    type Error = anyhow::Error;

    fn try_from(value: WrappedKeySetConfig) -> Result<Self, Self::Error> {
        let keyset_type = kms_grpc::kms::v1::KeySetType::try_from(value.0.keyset_type)?;
        match keyset_type {
            kms_grpc::kms::v1::KeySetType::Standard => {
                let inner_config = value
                    .0
                    .standard_keyset_config
                    .ok_or_else(|| anyhow::anyhow!("missing StandardKeySetConfig"))?;
                let compute_key_type =
                    kms_grpc::kms::v1::ComputeKeyType::try_from(inner_config.compute_key_type)?;
                let compression_type = kms_grpc::kms::v1::KeySetCompressionConfig::try_from(
                    inner_config.keyset_compression_config,
                )?;
                Ok(ddec_keyset_config::KeySetConfig::Standard(
                    ddec_keyset_config::StandardKeySetConfig {
                        computation_key_type: WrappedComputeKeyType(compute_key_type).into(),
                        compression_config: WrappedCompressionConfig(compression_type).into(),
                    },
                ))
            }
            kms_grpc::kms::v1::KeySetType::DecompressionOnly => {
                Ok(ddec_keyset_config::KeySetConfig::DecompressionOnly)
            }
        }
    }
}

#[cfg(feature = "non-wasm")]
pub(crate) struct WrappedComputeKeyType(kms_grpc::kms::v1::ComputeKeyType);

#[cfg(feature = "non-wasm")]
impl From<WrappedComputeKeyType> for ddec_keyset_config::ComputeKeyType {
    fn from(value: WrappedComputeKeyType) -> Self {
        match value.0 {
            kms_grpc::kms::v1::ComputeKeyType::Cpu => ddec_keyset_config::ComputeKeyType::Cpu,
        }
    }
}

#[cfg(feature = "non-wasm")]
pub(crate) struct WrappedCompressionConfig(kms_grpc::kms::v1::KeySetCompressionConfig);

#[cfg(feature = "non-wasm")]
impl From<WrappedCompressionConfig> for ddec_keyset_config::KeySetCompressionConfig {
    fn from(value: WrappedCompressionConfig) -> Self {
        match value.0 {
            kms_grpc::kms::v1::KeySetCompressionConfig::Generate => {
                ddec_keyset_config::KeySetCompressionConfig::Generate
            }
            kms_grpc::kms::v1::KeySetCompressionConfig::UseExisting => {
                ddec_keyset_config::KeySetCompressionConfig::UseExisting
            }
        }
    }
}

#[cfg(feature = "non-wasm")]
pub(crate) fn preproc_proto_to_keyset_config(
    keyset_config: &Option<kms_grpc::kms::v1::KeySetConfig>,
) -> anyhow::Result<ddec_keyset_config::KeySetConfig> {
    match keyset_config {
        None => Ok(ddec_keyset_config::KeySetConfig::default()),
        Some(inner) => Ok(WrappedKeySetConfig(*inner).try_into()?),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{deserialize_to_low_level, TypedPlaintext};
    use crate::{
        consts::{SAFE_SER_SIZE_LIMIT, TEST_PARAM},
        cryptography::internal_crypto_types::gen_sig_keys,
        engine::centralized::central_kms::generate_fhe_keys,
    };
    use aes_prng::AesRng;
    use kms_grpc::kms::v1::CiphertextFormat;
    use rand::{RngCore, SeedableRng};
    use tfhe::{prelude::SquashNoise, safe_serialization::safe_serialize, FheTypes, FheUint32};
    use threshold_fhe::execution::{
        keyset_config::StandardKeySetConfig, tfhe_internals::utils::expanded_encrypt,
    };

    #[test]
    fn sunshine_plaintext_as_u256() {
        let mut rng = AesRng::seed_from_u64(1);
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);

        let plaintext = TypedPlaintext {
            bytes: bytes.to_vec(),
            fhe_type: FheTypes::Uint160 as i32,
        };
        // Check the value is greater than 2^128
        assert!(plaintext.as_u160() > tfhe::integer::U256::from((0, 1)));
        assert!(plaintext.as_u256() > tfhe::integer::U256::from((0, 1)));
        // Sanity check the internal values - at least one byte must be different from zero
        assert!(bytes.iter().any(|&b| b != 0));
        assert_eq!(plaintext.fhe_type().unwrap(), FheTypes::Uint160);
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
    fn test_abi_encoding_fhevm() {
        let u256_val = tfhe::integer::U256::from((1, 256));
        let u512_val = tfhe::integer::bigint::U512::from(512_u64);
        let u2048_val = tfhe::integer::bigint::U2048::from(257_u64);

        // a batch of multiple plaintexts of different types
        let pts_2048: Vec<TypedPlaintext> = vec![
            TypedPlaintext::from_u2048(u2048_val),
            TypedPlaintext::from_bool(true),
            TypedPlaintext::from_u4(4),
            TypedPlaintext::from_u4(5),
            TypedPlaintext::from_u2048(u2048_val),
            TypedPlaintext::from_u8(8),
            TypedPlaintext::from_u16(16),
            TypedPlaintext::from_u32(32),
            TypedPlaintext::from_u128(128),
            TypedPlaintext::from_u160_low_high((234, 255)),
            TypedPlaintext::from_u256(u256_val),
            TypedPlaintext::from_u2048(u2048_val),
        ];

        // encode plaintexts into a list of solidity bytes using `alloy`
        let bytes_2048 = super::abi_encode_plaintexts(&pts_2048);
        let hexbytes_2048 = hex::encode(bytes_2048);

        // this is the encoding of the same list of plaintexts (pts_2048) using the outdated `ethers` crate.
        let reference_2048 = "00000000000000000000000000000000000000000000000000000000000001c000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000002e00000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000ff000000000000000000000000000000ea000000000000000000000000000001000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000520000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101";

        assert_eq!(reference_2048, hexbytes_2048.as_str());

        // a batch of a single plaintext
        let pts_16: Vec<TypedPlaintext> = vec![TypedPlaintext::from_u16(16)];

        // encode plaintexts into a list of solidity bytes using `alloy`
        let bytes_16 = super::abi_encode_plaintexts(&pts_16);
        let hexbytes_16 = hex::encode(bytes_16);

        // this is the encoding of the same list of plaintexts (pts_16) using the outdated `ethers` crate.
        let reference_16 = "00000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000060";

        assert_eq!(reference_16, hexbytes_16.as_str());

        // a batch of a two plaintext that are not of type Euint2048
        let pts_16_2: Vec<TypedPlaintext> =
            vec![TypedPlaintext::from_u16(16), TypedPlaintext::from_u16(16)];

        // encode plaintexts into a list of solidity bytes using `alloy`
        let bytes_16_2 = super::abi_encode_plaintexts(&pts_16_2);
        let hexbytes_16_2 = hex::encode(bytes_16_2);

        // this is the encoding of the same list of plaintexts (pts_16_2) using the outdated `ethers` crate.
        let reference_16_2 = "000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000080";
        assert_eq!(reference_16_2, hexbytes_16_2.as_str());

        // test more versions of plaintext batches in the rest of this test in a similar fashion as above
        let pts_mix_2: Vec<TypedPlaintext> = vec![
            TypedPlaintext::from_u2048(u2048_val),
            TypedPlaintext::from_bool(true),
            TypedPlaintext::from_u4(4),
            TypedPlaintext::from_u4(5),
            TypedPlaintext::from_u2048(u2048_val),
            TypedPlaintext::from_u8(8),
            TypedPlaintext::from_u16(16),
            TypedPlaintext::from_u32(32),
            TypedPlaintext::from_u128(128),
            TypedPlaintext::from_u160_low_high((234, 255)),
            TypedPlaintext::from_u256(u256_val),
            TypedPlaintext::from_u2048(u2048_val),
            TypedPlaintext::from_u512(u512_val),
            TypedPlaintext::from_u32(32),
        ];

        let pts_mix_3: Vec<TypedPlaintext> = vec![
            TypedPlaintext::from_u2048(u2048_val),
            TypedPlaintext::from_u512(u512_val),
        ];

        let pts_double_u2048: Vec<TypedPlaintext> = vec![
            TypedPlaintext::from_u2048(u2048_val),
            TypedPlaintext::from_u2048(u2048_val),
        ];

        let pts_single_u2048: Vec<TypedPlaintext> = vec![TypedPlaintext::from_u2048(u2048_val)];

        let pts_single_u512: Vec<TypedPlaintext> = vec![TypedPlaintext::from_u512(u512_val)];

        let u512_val_mx = tfhe::integer::bigint::U512::from(18446744073709551600_u64);

        let pts_single_u512_mx: Vec<TypedPlaintext> = vec![TypedPlaintext::from_u512(u512_val_mx)];
        let pts_single_u512_mx_2 = vec![TypedPlaintext::from_u512(18446744073709551600_u64.into())];
        // check that both plaintext are identical, even if constructed from different input types
        assert_eq!(pts_single_u512_mx, pts_single_u512_mx_2);

        // reference encoding of the above plaintexts using the outdated `ethers` crate.
        let reference_mix_2 = "000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000003200000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000ff000000000000000000000000000000ea000000000000000000000000000001000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000004400000000000000000000000000000000000000000000000000000000000000560000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000005c0000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200";
        let bytes_mix_2 = super::abi_encode_plaintexts(&pts_mix_2);

        let hexbytes_mix_2 = hex::encode(bytes_mix_2);
        assert_eq!(reference_mix_2, hexbytes_mix_2.as_str());

        let reference_mix_3 = "000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000001a00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200";
        let bytes_mix_3 = super::abi_encode_plaintexts(&pts_mix_3);

        let hexbytes_mix_3 = hex::encode(bytes_mix_3);
        assert_eq!(reference_mix_3, hexbytes_mix_3.as_str());

        let reference_double_u2048 = "000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000001a000000000000000000000000000000000000000000000000000000000000002c0000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101";
        let bytes_double_u2048 = super::abi_encode_plaintexts(&pts_double_u2048);

        let hexbytes_double_u2048 = hex::encode(bytes_double_u2048);
        assert_eq!(reference_double_u2048, hexbytes_double_u2048.as_str());

        let reference_single_u2048 = "00000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000180000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000101";
        let bytes_single_u2048 = super::abi_encode_plaintexts(&pts_single_u2048);

        let hexbytes_single_u2048 = hex::encode(bytes_single_u2048);
        assert_eq!(reference_single_u2048, hexbytes_single_u2048.as_str());

        let reference_single_u512 = "000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200";
        let bytes_single_u512 = super::abi_encode_plaintexts(&pts_single_u512);

        let hexbytes_single_u512 = hex::encode(bytes_single_u512);
        assert_eq!(reference_single_u512, hexbytes_single_u512.as_str());

        let reference_val_mx = "000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fffffffffffffff0";
        let bytes_val_mx = super::abi_encode_plaintexts(&pts_single_u512_mx);

        let hexbytes_val_mx = hex::encode(bytes_val_mx);
        assert_eq!(reference_val_mx, hexbytes_val_mx.as_str());
    }

    #[test]
    fn test_deserialize_ciphertext_wrong_type() {
        // we just use small ciphertexts for these tests
        let mut rng = AesRng::seed_from_u64(100);
        let (_sig_pk, sig_sk) = gen_sig_keys(&mut rng);
        let (pubkeyset, _sk) = generate_fhe_keys(
            &sig_sk,
            TEST_PARAM,
            StandardKeySetConfig::default(),
            None,
            None,
            None,
        )
        .unwrap();

        let msg = 32u32;
        tfhe::set_server_key(pubkeyset.server_key);
        let ct: FheUint32 = expanded_encrypt(&pubkeyset.public_key, msg, 32).unwrap();

        let mut ct_buf = Vec::new();
        safe_serialize(&ct, &mut ct_buf, SAFE_SER_SIZE_LIMIT).unwrap();

        // use the wrong type
        assert!(deserialize_to_low_level(
            FheTypes::Bool,
            CiphertextFormat::SmallExpanded,
            &ct_buf,
            &None,
        )
        .is_err());

        // should pass with the correct type
        assert!(deserialize_to_low_level(
            FheTypes::Uint32,
            CiphertextFormat::SmallExpanded,
            &ct_buf,
            &None,
        )
        .is_ok());
    }

    #[test]
    fn test_deserialize_ciphertext_wrong_ct_format() {
        // we just use small ciphertexts for these tests
        let mut rng = AesRng::seed_from_u64(100);
        let (_sig_pk, sig_sk) = gen_sig_keys(&mut rng);
        let (pubkeyset, _sk) = generate_fhe_keys(
            &sig_sk,
            TEST_PARAM,
            StandardKeySetConfig::default(),
            None,
            None,
            None,
        )
        .unwrap();

        let msg = 32u32;
        tfhe::set_server_key(pubkeyset.server_key);
        let ct: FheUint32 = expanded_encrypt(&pubkeyset.public_key, msg, 32).unwrap();

        // test SmallExpanded
        {
            let mut ct_buf = Vec::new();
            safe_serialize(&ct, &mut ct_buf, SAFE_SER_SIZE_LIMIT).unwrap();

            // use the wrong format
            assert!(deserialize_to_low_level(
                FheTypes::Uint32,
                CiphertextFormat::BigExpanded,
                &ct_buf,
                &None,
            )
            .is_err());

            // should pass with the correct format
            deserialize_to_low_level(
                FheTypes::Uint32,
                CiphertextFormat::SmallExpanded,
                &ct_buf,
                &None,
            )
            .unwrap();
        }

        {
            let large_ct = ct.squash_noise().unwrap();
            let mut ct_buf = Vec::new();
            safe_serialize(&large_ct, &mut ct_buf, SAFE_SER_SIZE_LIMIT).unwrap();

            // use the wrong format
            assert!(deserialize_to_low_level(
                FheTypes::Uint32,
                CiphertextFormat::SmallExpanded,
                &ct_buf,
                &None,
            )
            .is_err());

            // should pass with the correct format
            deserialize_to_low_level(
                FheTypes::Uint32,
                CiphertextFormat::BigExpanded,
                &ct_buf,
                &None,
            )
            .unwrap();
        }
    }

    #[test]
    fn test_deserialize_ciphertext_missing_decompression_key() {
        // we just use small ciphertexts for these tests
        let mut rng = AesRng::seed_from_u64(100);
        let (_sig_pk, sig_sk) = gen_sig_keys(&mut rng);
        let (pubkeyset, _sk) = generate_fhe_keys(
            &sig_sk,
            TEST_PARAM,
            StandardKeySetConfig::default(),
            None,
            None,
            None,
        )
        .unwrap();

        let (
            _raw_server_key,
            _cpk_ksk,
            compression_key,
            decompression_key,
            _noise_squashing_key,
            _tag,
        ) = pubkeyset.server_key.clone().into_raw_parts();
        assert!(compression_key.is_some());
        assert!(decompression_key.is_some());

        let msg = 32u32;
        tfhe::set_server_key(pubkeyset.server_key);
        let ct: FheUint32 = expanded_encrypt(&pubkeyset.public_key, msg, 32).unwrap();

        let ct_buf =
            crate::cryptography::decompression::test_tools::compress_serialize_versioned(ct);

        // setting decompression key to None should fail
        {
            assert!(deserialize_to_low_level(
                FheTypes::Uint32,
                CiphertextFormat::SmallCompressed,
                &ct_buf,
                &None,
            )
            .is_err());
        }

        // should pass with the correct decompression key
        {
            deserialize_to_low_level(
                FheTypes::Uint32,
                CiphertextFormat::SmallCompressed,
                &ct_buf,
                &decompression_key,
            )
            .unwrap();
        }
    }
}

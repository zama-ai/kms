use super::traits::BaseKms;
use crate::compute_user_decrypt_message_hash;
use crate::consts::ID_LENGTH;
use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::cryptography::decompression;
use crate::cryptography::internal_crypto_types::UnifiedPublicEncKey;
use crate::cryptography::internal_crypto_types::WrappedDKGParams;
use crate::cryptography::internal_crypto_types::{PrivateSigKey, PublicSigKey};
use crate::cryptography::signcryption::internal_verify_sig;
use crate::util::key_setup::FhePrivateKey;
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
    CiphertextFormat, FheParameter, TypedPlaintext, UserDecryptionResponsePayload,
};
#[cfg(feature = "non-wasm")]
use kms_grpc::rpc_types::CrsGenSignedPubDataHandleInternalWrapper;
use kms_grpc::rpc_types::PubDataType;
#[cfg(feature = "non-wasm")]
use kms_grpc::rpc_types::SignedPubDataHandleInternal;
use kms_grpc::solidity_types::{
    CrsgenVerification, FheDecompressionUpgradeKey, KeygenVerification, PrepKeygenVerification,
    PublicDecryptVerification,
};
use kms_grpc::utils::tonic_result::BoxedStatus;
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
use tfhe::zk::CompactPkeCrs;
use tfhe::FheUint80;
use tfhe::{
    FheBool, FheUint1024, FheUint128, FheUint16, FheUint160, FheUint2048, FheUint256, FheUint32,
    FheUint4, FheUint512, FheUint64, FheUint8,
};
use tfhe::{FheTypes, Versionize};
use tfhe_versionable::Upgrade;
use tfhe_versionable::Version;
use tfhe_versionable::VersionsDispatch;
use threshold_fhe::execution::endpoints::decryption::RadixOrBoolCiphertext;
use threshold_fhe::execution::endpoints::decryption::{
    LowLevelCiphertext, SnsRadixOrBoolCiphertext,
};
use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
use threshold_fhe::execution::tfhe_internals::public_keysets::FhePubKeySet;
use threshold_fhe::execution::zk::ceremony::max_num_bits_from_crs;
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
/// Domain separator for public key data
pub const DSEP_PUBDATA_KEY: DomainSep = *b"PDAT_KEY";
/// Domain separator for CRS (Common Reference String) data
pub const DSEP_PUBDATA_CRS: DomainSep = *b"PDAT_CRS";

lazy_static::lazy_static! {
    pub static ref CENTRALIZED_DUMMY_PREPROCESSING_ID: RequestId =
        crate::engine::base::derive_request_id("CENTRALIZED_DUMMY_PREPROCESSING_ID").unwrap();

    pub static ref INSECURE_PREPROCESSING_ID: RequestId =
        crate::engine::base::derive_request_id("INSECURE_PREPROCESSING_ID").unwrap();
}

#[cfg(feature = "non-wasm")]
#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum KmsFheKeyHandlesVersioned {
    V0(KmsFheKeyHandlesV0),
    V1(KmsFheKeyHandles),
}

impl Upgrade<KmsFheKeyHandles> for KmsFheKeyHandlesV0 {
    type Error = std::convert::Infallible;
    fn upgrade(self) -> Result<KmsFheKeyHandles, Self::Error> {
        Ok(KmsFheKeyHandles {
            client_key: self.client_key,
            decompression_key: self.decompression_key,
            public_key_info: KeyGenMetadata::LegacyV0(self.public_key_info),
        })
    }
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
    pub public_key_info: KeyGenMetadata,
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
        key_id: &RequestId,
        keyset: &FhePubKeySet,
        decompression_key: Option<DecompressionKey>,
        eip712_domain: &alloy_sol_types::Eip712Domain,
    ) -> anyhow::Result<Self> {
        let public_key_info = compute_info_standard_keygen(
            sig_key,
            &crate::engine::base::DSEP_PUBDATA_KEY,
            &CENTRALIZED_DUMMY_PREPROCESSING_ID,
            key_id,
            keyset,
            eip712_domain,
        )?;

        Ok(KmsFheKeyHandles {
            client_key,
            decompression_key,
            public_key_info,
        })
    }
}

#[cfg(feature = "non-wasm")]
#[derive(Clone, Serialize, Deserialize, Version)]
pub struct KmsFheKeyHandlesV0 {
    /// Client's private key for FHE operations
    pub client_key: FhePrivateKey,

    /// Optional key for ciphertext decompression
    pub decompression_key: Option<DecompressionKey>,

    /// Maps public key types to their corresponding signed handles and metadata
    pub public_key_info: HashMap<PubDataType, SignedPubDataHandleInternal>,
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

pub(crate) fn compute_info_crs(
    sk: &PrivateSigKey,
    domain_separator: &DomainSep,
    crs_id: &RequestId,
    pp: &CompactPkeCrs,
    domain: &alloy_sol_types::Eip712Domain,
) -> anyhow::Result<CrsGenMetadata> {
    let max_num_bits = max_num_bits_from_crs(pp);
    let crs_digest = safe_serialize_hash_element_versioned(domain_separator, pp)?;

    let sol_type = CrsgenVerification::new(crs_id, max_num_bits, crs_digest.clone());
    let external_signature = compute_external_pubdata_signature(sk, &sol_type, domain)?;

    Ok(CrsGenMetadata::new(
        *crs_id,
        crs_digest,
        max_num_bits as u32,
        external_signature,
    ))
}

pub(crate) fn compute_external_signature_preprocessing(
    sk: &PrivateSigKey,
    prep_id: &RequestId,
    domain: &alloy_sol_types::Eip712Domain,
) -> anyhow::Result<Vec<u8>> {
    let sol_type = PrepKeygenVerification::new(prep_id);
    let external_signature = compute_external_pubdata_signature(sk, &sol_type, domain)?;
    Ok(external_signature)
}

pub(crate) fn compute_info_standard_keygen(
    sk: &PrivateSigKey,
    domain_separator: &DomainSep,
    prep_id: &RequestId,
    key_id: &RequestId,
    keyset: &FhePubKeySet,
    domain: &alloy_sol_types::Eip712Domain,
) -> anyhow::Result<KeyGenMetadata> {
    let server_key_digest =
        safe_serialize_hash_element_versioned(domain_separator, &keyset.server_key)?;
    let public_key_digest =
        safe_serialize_hash_element_versioned(domain_separator, &keyset.public_key)?;

    let sol_type = KeygenVerification::new(
        prep_id,
        key_id,
        server_key_digest.clone(),
        public_key_digest.clone(),
    );
    let external_signature = compute_external_pubdata_signature(sk, &sol_type, domain)?;

    Ok(KeyGenMetadata::new(
        *key_id,
        *prep_id,
        HashMap::from([
            (PubDataType::ServerKey, server_key_digest),
            (PubDataType::PublicKey, public_key_digest),
        ]),
        external_signature,
    ))
}

pub(crate) fn compute_info_decompression_keygen(
    sk: &PrivateSigKey,
    domain_separator: &DomainSep,
    prep_id: &RequestId,
    key_id: &RequestId,
    decompression_key: &DecompressionKey,
    domain: &alloy_sol_types::Eip712Domain,
) -> anyhow::Result<KeyGenMetadata> {
    let key_digest = safe_serialize_hash_element_versioned(domain_separator, decompression_key)?;

    let sol_type = FheDecompressionUpgradeKey {
        decompressionUpgradeKeyDigest: key_digest.to_vec().into(),
    };
    let external_signature = compute_external_pubdata_signature(sk, &sol_type, domain)?;

    Ok(KeyGenMetadata::new(
        *key_id,
        *prep_id,
        HashMap::from([(PubDataType::DecompressionKey, key_digest)]),
        external_signature,
    ))
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
                let ct_list = safe_deserialize::<tfhe::CompressedSquashedNoiseCiphertextList>(
                    std::io::Cursor::new($serialized_high_level),
                    SAFE_SER_SIZE_LIMIT,
                )
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let ct: tfhe::SquashedNoiseFheUint = ct_list.get(0)?.ok_or(anyhow::anyhow!(
                    "expected at least one ciphertext in the compressed list"
                ))?;
                let radix_ct = ct.underlying_squashed_noise_ciphertext().clone();
                LowLevelCiphertext::BigCompressed(SnsRadixOrBoolCiphertext::Radix(radix_ct))
            }
            CiphertextFormat::BigExpanded => {
                let r = safe_deserialize::<tfhe::SquashedNoiseFheUint>(
                    std::io::Cursor::new($serialized_high_level),
                    SAFE_SER_SIZE_LIMIT,
                )
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let radix_ct = r.underlying_squashed_noise_ciphertext().clone();
                LowLevelCiphertext::BigStandard(SnsRadixOrBoolCiphertext::Radix(radix_ct))
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
                let ct_list = safe_deserialize::<tfhe::CompressedSquashedNoiseCiphertextList>(
                    std::io::Cursor::new(serialized_high_level),
                    SAFE_SER_SIZE_LIMIT,
                )
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let ct: tfhe::SquashedNoiseFheBool = ct_list.get(0)?.ok_or(anyhow::anyhow!(
                    "expected at least one ciphertext in the compressed list"
                ))?;
                let radix_ct = ct.underlying_squashed_noise_ciphertext().clone();
                LowLevelCiphertext::BigCompressed(SnsRadixOrBoolCiphertext::Bool(radix_ct))
            }
            CiphertextFormat::BigExpanded => {
                let r = safe_deserialize::<tfhe::SquashedNoiseFheBool>(
                    std::io::Cursor::new(serialized_high_level),
                    SAFE_SER_SIZE_LIMIT,
                )
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                let radix_ct = r.underlying_squashed_noise_ciphertext().clone();
                LowLevelCiphertext::BigStandard(SnsRadixOrBoolCiphertext::Bool(radix_ct))
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
    extra_data: Vec<u8>,
) -> anyhow::Result<Vec<u8>> {
    let message_hash =
        compute_user_decrypt_message_hash(payload, eip712_domain, user_pk, extra_data)?;

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
    extra_data: Vec<u8>,
    eip712_domain: Eip712Domain,
) -> anyhow::Result<Vec<u8>> {
    let message_hash = compute_pt_message_hash(ext_handles_bytes, pts, eip712_domain, extra_data)?;

    let signer = PrivateKeySigner::from_signing_key(server_sk.sk().clone());
    let signer_address = signer.address();
    tracing::info!("Signer address: {:?}", signer_address);

    // Sign the hash synchronously with the wallet.
    let signature = signer.sign_hash_sync(&message_hash)?.as_bytes().to_vec();

    tracing::info!("PT Signature: {:?}", hex::encode(signature.clone()));

    Ok(signature)
}

pub fn hash_sol_struct<D: SolStruct>(
    data: &D,
    eip712_domain: &Eip712Domain,
) -> anyhow::Result<B256> {
    let message_hash = data.eip712_signing_hash(eip712_domain);
    tracing::info!("Public Data EIP-712 Message hash: {:?}", message_hash);
    Ok(message_hash)
}

/// take some public data (e.g. public key or CRS) and sign it using EIP-712 for external verification (e.g. in fhevm).
pub fn compute_external_pubdata_signature<D: SolStruct>(
    client_sk: &PrivateSigKey,
    data: &D,
    eip712_domain: &Eip712Domain,
) -> anyhow::Result<Vec<u8>> {
    let message_hash = hash_sol_struct(data, eip712_domain)?;

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
    extra_data: Vec<u8>,
) -> anyhow::Result<B256> {
    // convert external_handles back to U256 to be signed
    let external_handles: Vec<_> = ext_handles_bytes
        .into_iter()
        .enumerate()
        .map(|(idx, h)| {
            if h.as_slice().len() > 32 {
                anyhow::bail!(
                    "external_handle at index {idx} too long: {} bytes (max 32)",
                    h.as_slice().len()
                );
            }
            Ok(FixedBytes::<32>::left_padding_from(h.as_slice()))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let pt_bytes = abi_encode_plaintexts(pts);

    // the solidity structure to sign with EIP-712
    let message = PublicDecryptVerification {
        ctHandles: external_handles.clone(),
        decryptedResult: pt_bytes.clone(),
        extraData: extra_data.clone().into(),
    };

    let message_hash = message.eip712_signing_hash(&eip712_domain);
    tracing::info!(
        "PT EIP-712 Message hash: {:?}. Handles: {:?}. PT Bytes: {:?}. Extra Data: {:?}",
        message_hash,
        external_handles,
        pt_bytes,
        extra_data
    );
    Ok(message_hash)
}

/// Attempt to find the concrete parameters from an enum variant defined by
/// [kms_grpc::kms::v1::FheParameter].
///
/// Since this function is normally used by the grpc service, we return the error code
/// InvalidArgument if the concrete parameter does not exist.
/// The default DKG parameters are returned if None is provided.
pub(crate) fn retrieve_parameters(fhe_parameter: Option<i32>) -> Result<DKGParams, BoxedStatus> {
    match fhe_parameter {
        Some(inner) => {
            let fhe_parameter: WrappedDKGParams = FheParameter::try_from(inner)
                .map_err(|e| {
                    tonic::Status::invalid_argument(format!("DKG parameter not found: {e}"))
                })?
                .into();
            Ok(*fhe_parameter)
        }
        None => Ok(*WrappedDKGParams::from(FheParameter::default())),
    }
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum KeyGenMetadataInnerVersioned {
    V0(KeyGenMetadataInner),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(KeyGenMetadataInnerVersioned)]
pub struct KeyGenMetadataInner {
    pub(crate) key_id: RequestId,
    pub(crate) preprocessing_id: RequestId,
    pub(crate) key_digest_map: HashMap<PubDataType, Vec<u8>>,
    pub(crate) external_signature: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum KeyGenMetadataVersioned {
    V0(KeyGenMetadata),
}

// Values that need to be stored temporarily as part of an async key generation call.
#[cfg(feature = "non-wasm")]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Versionize)]
#[versionize(KeyGenMetadataVersioned)]
pub enum KeyGenMetadata {
    Current(KeyGenMetadataInner),
    LegacyV0(HashMap<PubDataType, SignedPubDataHandleInternal>),
}

impl Named for KeyGenMetadata {
    /// Returns the type name for versioning and serialization
    const NAME: &'static str = "KeyGenMetadata";
}

impl KeyGenMetadata {
    pub fn new(
        key_id: RequestId,
        preprocessing_id: RequestId,
        key_digest_map: HashMap<PubDataType, Vec<u8>>,
        external_signature: Vec<u8>,
    ) -> Self {
        KeyGenMetadata::Current(KeyGenMetadataInner {
            key_id,
            preprocessing_id,
            key_digest_map,
            external_signature,
        })
    }

    #[cfg(test)]
    pub fn external_signature(&self) -> &[u8] {
        match self {
            KeyGenMetadata::Current(inner) => &inner.external_signature,
            KeyGenMetadata::LegacyV0(_inner) => {
                // we cannot return a single external signature because there might be multiple
                &[]
            }
        }
    }
}

#[cfg(feature = "non-wasm")]
#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum CrsGenMetadataInnerVersioned {
    V0(CrsGenMetadataInner),
}

#[cfg(feature = "non-wasm")]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(CrsGenMetadataInnerVersioned)]
pub struct CrsGenMetadataInner {
    pub(crate) crs_id: RequestId,
    pub(crate) crs_digest: Vec<u8>,
    pub(crate) max_num_bits: u32,
    pub(crate) external_signature: Vec<u8>,
}

#[cfg(feature = "non-wasm")]
#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum CrsGenMetadataVersioned {
    V0(CrsGenSignedPubDataHandleInternalWrapper),
    V1(CrsGenMetadata),
}

#[cfg(feature = "non-wasm")]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Versionize)]
#[versionize(CrsGenMetadataVersioned)]
pub enum CrsGenMetadata {
    Current(CrsGenMetadataInner),
    LegacyV0(SignedPubDataHandleInternal),
}

#[cfg(feature = "non-wasm")]
impl Upgrade<CrsGenMetadata> for CrsGenSignedPubDataHandleInternalWrapper {
    type Error = std::convert::Infallible;
    fn upgrade(self) -> Result<CrsGenMetadata, Self::Error> {
        Ok(CrsGenMetadata::LegacyV0(self.0))
    }
}

#[cfg(feature = "non-wasm")]
impl CrsGenMetadata {
    pub fn new(
        crs_id: RequestId,
        crs_digest: Vec<u8>,
        max_num_bits: u32,
        external_signature: Vec<u8>,
    ) -> Self {
        CrsGenMetadata::Current(CrsGenMetadataInner {
            crs_id,
            crs_digest,
            max_num_bits,
            external_signature,
        })
    }

    #[cfg(test)]
    pub fn external_signature(&self) -> &[u8] {
        match self {
            CrsGenMetadata::Current(inner) => &inner.external_signature,
            CrsGenMetadata::LegacyV0(_) => &[],
        }
    }
}

#[cfg(feature = "non-wasm")]
impl Named for CrsGenMetadata {
    /// Returns the type name for versioning and serialization
    const NAME: &'static str = "CrsGenMetadata";
}

// Values that need to be stored temporarily as part of an async decryption call.
// Represents the request ID of the request and the result of the decryption (a batch of plaintests),
// an external signature on the batch and any extra data.
#[cfg(feature = "non-wasm")]
pub type PubDecCallValues = (RequestId, Vec<TypedPlaintext>, Vec<u8>, Vec<u8>);

// Values that need to be stored temporarily as part of an async user decryption call.
// Represents UserDecryptionResponsePayload, external_handles, external_signature and extra_data.
#[cfg(feature = "non-wasm")]
pub type UserDecryptCallValues = (UserDecryptionResponsePayload, Vec<u8>, Vec<u8>);

#[cfg(test)]
pub(crate) mod tests {
    use super::{deserialize_to_low_level, TypedPlaintext};
    use crate::{
        consts::{SAFE_SER_SIZE_LIMIT, TEST_PARAM},
        cryptography::internal_crypto_types::gen_sig_keys,
        dummy_domain,
        engine::{
            base::{
                compute_external_signature_preprocessing, compute_info_standard_keygen,
                compute_pt_message_hash, hash_sol_struct, safe_serialize_hash_element_versioned,
                DSEP_PUBDATA_CRS, DSEP_PUBDATA_KEY,
            },
            centralized::central_kms::{
                gen_centralized_crs, generate_client_fhe_key, generate_fhe_keys,
            },
        },
        util::key_setup::FhePublicKey,
    };
    use aes_prng::AesRng;
    use alloy_dyn_abi::Eip712Domain;
    use alloy_primitives::Address;
    use alloy_sol_types::SolStruct;
    use kms_grpc::{
        kms::v1::CiphertextFormat,
        solidity_types::{CrsgenVerification, KeygenVerification, PrepKeygenVerification},
        RequestId,
    };
    use rand::{RngCore, SeedableRng};
    use tfhe::{
        prelude::SquashNoise, safe_serialization::safe_serialize, FheTypes, FheUint32, Seed,
    };
    use threshold_fhe::execution::{
        keyset_config::StandardKeySetConfig,
        tfhe_internals::{public_keysets::FhePubKeySet, utils::expanded_encrypt},
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
        let key_id = RequestId::new_random(&mut rng);
        let (pubkeyset, _sk) = generate_fhe_keys(
            &sig_sk,
            TEST_PARAM,
            StandardKeySetConfig::default(),
            None,
            &key_id,
            None,
            &dummy_domain(),
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
        let key_id = RequestId::new_random(&mut rng);
        let (pubkeyset, _sk) = generate_fhe_keys(
            &sig_sk,
            TEST_PARAM,
            StandardKeySetConfig::default(),
            None,
            &key_id,
            None,
            &dummy_domain(),
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
        let key_id = RequestId::new_random(&mut rng);
        let (pubkeyset, _sk) = generate_fhe_keys(
            &sig_sk,
            TEST_PARAM,
            StandardKeySetConfig::default(),
            None,
            &key_id,
            None,
            &dummy_domain(),
        )
        .unwrap();

        let (
            _raw_server_key,
            _cpk_ksk,
            compression_key,
            decompression_key,
            _noise_squashing_key,
            _noise_squashing_compression_key,
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

    fn recover_address(
        data: impl SolStruct,
        domain: &Eip712Domain,
        external_sig: &[u8],
    ) -> Address {
        // Since the signature is 65 bytes long, the last byte is the parity bit
        // so we extract it and use it as the parity.
        let sig = alloy_signer::Signature::from_bytes_and_parity(
            external_sig,
            external_sig[64] & 0x01 == 0,
        );
        let hash = hash_sol_struct(&data, domain).unwrap();

        sig.recover_address_from_prehash(&hash).unwrap()
    }

    #[test]
    fn test_compute_info_standard_keygen() {
        let mut rng = AesRng::seed_from_u64(123);
        let (pk, sk) = gen_sig_keys(&mut rng);
        let actual_address = alloy_signer::utils::public_key_to_address(pk.pk());
        let prep_id = RequestId::new_random(&mut rng);
        let key_id = RequestId::new_random(&mut rng);
        let params = TEST_PARAM;
        let client_key = generate_client_fhe_key(params, Some(Seed(1)));
        let server_key = client_key.generate_server_key();
        let public_key = FhePublicKey::new(&client_key);

        let server_key_digest =
            safe_serialize_hash_element_versioned(&DSEP_PUBDATA_KEY, &server_key).unwrap();
        let public_key_digest =
            safe_serialize_hash_element_versioned(&DSEP_PUBDATA_KEY, &public_key).unwrap();

        let keyset = FhePubKeySet {
            public_key,
            server_key,
        };
        let domain = dummy_domain();
        let meta_data = compute_info_standard_keygen(
            &sk,
            &crate::engine::base::DSEP_PUBDATA_KEY,
            &prep_id,
            &key_id,
            &keyset,
            &domain,
        )
        .unwrap();

        {
            // do the verification correctly
            let sol_struct = KeygenVerification::new(
                &prep_id,
                &key_id,
                server_key_digest.clone(),
                public_key_digest.clone(),
            );

            assert_eq!(
                recover_address(sol_struct, &domain, meta_data.external_signature()),
                actual_address
            );
        }
        {
            // wrong domain
            let bad_domain = alloy_sol_types::eip712_domain!(
                name: "Wrong name",
                version: "1",
                chain_id: 8006,
                verifying_contract: alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
            );
            let sol_struct = KeygenVerification::new(
                &prep_id,
                &key_id,
                server_key_digest.clone(),
                public_key_digest.clone(),
            );

            assert_ne!(
                recover_address(sol_struct, &bad_domain, meta_data.external_signature()),
                actual_address
            );
        }
        {
            // should fail if we use a wrong prep_id
            let bad_prep_id = RequestId::new_random(&mut rng);
            let sol_struct = KeygenVerification::new(
                &bad_prep_id,
                &key_id,
                server_key_digest.clone(),
                public_key_digest.clone(),
            );
            assert_ne!(
                recover_address(sol_struct, &domain, meta_data.external_signature()),
                actual_address
            );
        }
        {
            // should fail if we use the wrong key_id
            let bad_key_id = RequestId::new_random(&mut rng);
            let sol_struct = KeygenVerification::new(
                &prep_id,
                &bad_key_id,
                server_key_digest.clone(),
                public_key_digest.clone(),
            );
            assert_ne!(
                recover_address(sol_struct, &domain, meta_data.external_signature()),
                actual_address
            );
        }
        {
            // should fail if we use the wrong digest
            let mut bad_server_key_digest = server_key_digest.clone();
            bad_server_key_digest[0] ^= 1;
            let sol_struct = KeygenVerification::new(
                &prep_id,
                &key_id,
                bad_server_key_digest.clone(),
                public_key_digest.clone(),
            );
            assert_ne!(
                recover_address(sol_struct, &domain, meta_data.external_signature()),
                actual_address
            );
        }
        {
            // should fail if we use the wrong signature

            let (_, bad_sk) = gen_sig_keys(&mut rng);
            let meta_data = compute_info_standard_keygen(
                &bad_sk,
                &crate::engine::base::DSEP_PUBDATA_KEY,
                &prep_id,
                &key_id,
                &keyset,
                &domain,
            )
            .unwrap();
            let bad_signature = meta_data.external_signature();
            let sol_struct = KeygenVerification::new(
                &prep_id,
                &key_id,
                server_key_digest.clone(),
                public_key_digest.clone(),
            );
            assert_ne!(
                recover_address(sol_struct, &domain, bad_signature),
                actual_address
            );
        }
    }

    #[test]
    fn test_compute_info_crs() {
        let mut rng = AesRng::seed_from_u64(123);
        let (pk, sk) = gen_sig_keys(&mut rng);
        let actual_address = alloy_signer::utils::public_key_to_address(pk.pk());
        let crs_id = RequestId::new_random(&mut rng);
        let params = TEST_PARAM;
        let max_num_bits = 64;
        let domain = dummy_domain();

        let (crs, meta_data) =
            gen_centralized_crs(&sk, &params, Some(max_num_bits), &domain, &crs_id, &mut rng)
                .unwrap();

        let crs_digest = safe_serialize_hash_element_versioned(&DSEP_PUBDATA_CRS, &crs).unwrap();

        {
            // do the verification correctly
            let sol_struct =
                CrsgenVerification::new(&crs_id, max_num_bits as usize, crs_digest.clone());

            assert_eq!(
                recover_address(sol_struct, &domain, meta_data.external_signature()),
                actual_address
            );
        }
        {
            // should fail if we use a wrong crs_id
            let bad_crs_id = RequestId::new_random(&mut rng);
            let sol_struct =
                CrsgenVerification::new(&bad_crs_id, max_num_bits as usize, crs_digest.clone());

            assert_ne!(
                recover_address(sol_struct, &domain, meta_data.external_signature()),
                actual_address
            );
        }
        {
            // wrong domain
            let bad_domain = alloy_sol_types::eip712_domain!(
                name: "Wrong name",
                version: "1",
                chain_id: 8006,
                verifying_contract: alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
            );
            let sol_struct =
                CrsgenVerification::new(&crs_id, max_num_bits as usize, crs_digest.clone());
            assert_ne!(
                recover_address(sol_struct, &bad_domain, meta_data.external_signature()),
                actual_address
            );
        }
        {
            // should fail if we use the wrong max_num_bits
            let wrong_max_num_bits = 16;
            let sol_struct =
                CrsgenVerification::new(&crs_id, wrong_max_num_bits as usize, crs_digest.clone());

            assert_ne!(
                recover_address(sol_struct, &domain, meta_data.external_signature()),
                actual_address
            );
        }
        {
            // should fail if we use the wrong digest
            let mut wrong_digest = crs_digest.clone();
            wrong_digest[0] ^= 1;
            let sol_struct = CrsgenVerification::new(&crs_id, max_num_bits as usize, wrong_digest);

            assert_ne!(
                recover_address(sol_struct, &domain, meta_data.external_signature()),
                actual_address
            );
        }
        {
            // shold fail if we use the wrong signature
            let (_, bad_sk) = gen_sig_keys(&mut rng);
            let (crs, meta_data) = gen_centralized_crs(
                &bad_sk, // using bad_sk
                &params,
                Some(max_num_bits),
                &domain,
                &crs_id,
                &mut rng,
            )
            .unwrap();
            let crs_digest =
                safe_serialize_hash_element_versioned(&DSEP_PUBDATA_CRS, &crs).unwrap();

            let sol_struct =
                CrsgenVerification::new(&crs_id, max_num_bits as usize, crs_digest.clone());

            assert_ne!(
                recover_address(sol_struct, &domain, meta_data.external_signature()),
                actual_address
            );
        }
    }

    #[test]
    fn test_compute_pt_message_hash() {
        let domain = dummy_domain();

        // Plaintexts to sign
        let pts: Vec<TypedPlaintext> = vec![
            TypedPlaintext::from_u16(16),
            TypedPlaintext::from_bool(true),
        ];

        // External handles (all 32 bytes long)
        let handles = vec![vec![0xAAu8; 32], vec![0xBBu8; 32]];

        // Extra data (empty for now)
        let extra_data: Vec<u8> = vec![];

        // Determinism: same inputs -> same hash
        let h1 = compute_pt_message_hash(handles.clone(), &pts, domain.clone(), extra_data.clone())
            .expect("hash computation should succeed");
        let h2 = compute_pt_message_hash(handles.clone(), &pts, domain.clone(), extra_data.clone())
            .expect("hash computation should succeed");
        assert_eq!(h1, h2, "Hashes must be the same for identical inputs");

        // Changing a handle changes the hash
        let mut mutated_handles = handles.clone();
        mutated_handles[1][0] ^= 0x23;
        let h_changed_handle =
            compute_pt_message_hash(mutated_handles, &pts, domain.clone(), extra_data.clone())
                .expect("hash computation should succeed");
        assert_ne!(
            h1, h_changed_handle,
            "Hash should change when a handle changes"
        );

        // Changing a plaintext value changes the hash
        let mut pts_modified = pts.clone();
        pts_modified[0] = TypedPlaintext::from_u16(69);
        let h_changed_pt = compute_pt_message_hash(
            handles.clone(),
            &pts_modified,
            domain.clone(),
            extra_data.clone(),
        )
        .expect("hash computation should succeed");
        assert_ne!(
            h1, h_changed_pt,
            "Hash should change when a plaintext changes"
        );

        // Changing extra data changes the hash
        let extra_data2 = vec![1u8, 2, 3, 5, 23];
        let h_changed_extra =
            compute_pt_message_hash(handles.clone(), &pts, domain.clone(), extra_data2)
                .expect("hash computation should succeed");
        assert_ne!(
            h1, h_changed_extra,
            "Hash should change when extra_data changes"
        );

        // Error path: a handle longer than 32 bytes should fail
        let bad_handles = vec![vec![0u8; 33]];
        let err = compute_pt_message_hash(bad_handles, &pts, domain, vec![])
            .expect_err("Expected error for handle > 32 bytes");
        assert!(
            err.to_string().contains("too long"),
            "Error message should mention 'too long', got: {err}"
        );

        // If the following test fails, we have changed how the hash is computed so the reference does not match anymore.
        // This is a breaking change that needs to be synced across components. The reference should then be updated.
        let reference_hash_hex = "4fd5c11201089afe441112103fd55bf025d46bad722a3236242dbaa6f3aa4bb6";
        assert_eq!(
            hex::encode(h1),
            reference_hash_hex,
            "Reference hash mismatch"
        );
    }

    #[test]
    fn test_compute_external_signature_preproc() {
        let mut rng = AesRng::seed_from_u64(123);
        let (pk, sk) = gen_sig_keys(&mut rng);
        let actual_address = alloy_signer::utils::public_key_to_address(pk.pk());
        let preproc_id = RequestId::new_random(&mut rng);
        let domain = dummy_domain();
        let sig = compute_external_signature_preprocessing(&sk, &preproc_id, &domain).unwrap();

        {
            // happy path
            let sol_struct = PrepKeygenVerification::new(&preproc_id);
            assert_eq!(recover_address(sol_struct, &domain, &sig), actual_address);
        }
        {
            // wrong ID
            let bad_preproc_id = RequestId::new_random(&mut rng);
            let sol_struct = PrepKeygenVerification::new(&bad_preproc_id);
            assert_ne!(recover_address(sol_struct, &domain, &sig), actual_address);
        }
        {
            // wrong domain
            let bad_domain = alloy_sol_types::eip712_domain!(
                name: "Wrong name",
                version: "1",
                chain_id: 8006,
                verifying_contract: alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
            );
            let sol_struct = PrepKeygenVerification::new(&preproc_id);
            assert_ne!(
                recover_address(sol_struct, &bad_domain, &sig),
                actual_address
            );
        }
        {
            // wrong signature
            let (_, bad_sk) = gen_sig_keys(&mut rng);
            let sig =
                compute_external_signature_preprocessing(&bad_sk, &preproc_id, &domain).unwrap();
            let sol_struct = PrepKeygenVerification::new(&preproc_id);
            assert_ne!(recover_address(sol_struct, &domain, &sig), actual_address);
        }
    }
}

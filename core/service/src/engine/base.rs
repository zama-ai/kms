use std::collections::HashMap;
use std::sync::Arc;

use crate::anyhow_error_and_log;
use crate::consts::ID_LENGTH;
use crate::cryptography::decompression;
use crate::cryptography::internal_crypto_types::{PrivateSigKey, PublicEncKey, PublicSigKey};
use crate::cryptography::signcryption::internal_verify_sig;
use crate::util::key_setup::FhePrivateKey;
use aes_prng::AesRng;
use alloy_dyn_abi::DynSolValue;
use alloy_primitives::Bytes;
use alloy_primitives::{B256, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::Eip712Domain;
use alloy_sol_types::SolStruct;
use distributed_decryption::execution::endpoints::keygen::FhePubKeySet;
#[cfg(feature = "non-wasm")]
use distributed_decryption::execution::keyset_config as ddec_keyset_config;
use distributed_decryption::execution::tfhe_internals::parameters::{
    Ciphertext128, DKGParams, LowLevelCiphertext,
};
use distributed_decryption::execution::tfhe_internals::test_feature::SnsClientKey;
use k256::ecdsa::SigningKey;
use kms_grpc::kms::v1::{
    CiphertextFormat, FheParameter, FheType, SignedPubDataHandle, TypedPlaintext,
    TypedSigncryptedCiphertext,
};
use kms_grpc::rpc_types::{
    hash_element, safe_serialize_hash_element_versioned, EIP712PublicDecrypt, FhePubKey,
    FheServerKey, PubDataType, SignedPubDataHandleInternal, SnsKey, UserDecryptionResult, CRS,
};
use rand::{CryptoRng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use tfhe::integer::ciphertext::BaseRadixCiphertext;
use tfhe::integer::compression_keys::DecompressionKey;
use tfhe::integer::IntegerCiphertext;
use tfhe::named::Named;
use tfhe::safe_serialization::safe_deserialize;
use tfhe::Versionize;
use tfhe::{
    FheBool, FheUint1024, FheUint128, FheUint16, FheUint160, FheUint2048, FheUint256, FheUint32,
    FheUint4, FheUint512, FheUint64, FheUint8,
};
use tfhe_versionable::VersionsDispatch;
use tokio::sync::Mutex;

use super::traits::BaseKms;

#[cfg(feature = "non-wasm")]
#[derive(Clone, Serialize, Deserialize, VersionsDispatch)]
pub enum KmsFheKeyHandlesVersioned {
    V0(KmsFheKeyHandles),
}

/// This is a data structure that holds the private key material
/// of the centralized KMS.
#[cfg(feature = "non-wasm")]
#[derive(Clone, Serialize, Deserialize, Versionize)]
#[versionize(KmsFheKeyHandlesVersioned)]
pub struct KmsFheKeyHandles {
    pub client_key: FhePrivateKey,
    pub sns_client_key: SnsClientKey,
    pub decompression_key: Option<DecompressionKey>,
    /// Mapping key type to information
    pub public_key_info: HashMap<PubDataType, SignedPubDataHandleInternal>,
}

impl Named for KmsFheKeyHandles {
    const NAME: &'static str = "KmsFheKeyHandles";
}

#[cfg(feature = "non-wasm")]
impl KmsFheKeyHandles {
    /// Compute key handles for the public key materials.
    /// Note that the handles include a signature on the versionized keys.
    pub fn new(
        sig_key: &PrivateSigKey,
        client_key: FhePrivateKey,
        sns_client_key: SnsClientKey,
        public_keys: &FhePubKeySet,
        decompression_key: Option<DecompressionKey>,
        eip712_domain: Option<&alloy_sol_types::Eip712Domain>,
    ) -> anyhow::Result<Self> {
        let mut public_key_info = HashMap::new();
        public_key_info.insert(
            PubDataType::PublicKey,
            compute_info(sig_key, &public_keys.public_key, eip712_domain)?,
        );
        public_key_info.insert(
            PubDataType::ServerKey,
            compute_info(sig_key, &public_keys.server_key, eip712_domain)?,
        );
        if let Some(sns) = &public_keys.sns_key {
            public_key_info.insert(
                PubDataType::SnsKey,
                compute_info(sig_key, sns, eip712_domain)?,
            );
        }
        Ok(KmsFheKeyHandles {
            client_key,
            sns_client_key,
            decompression_key,
            public_key_info,
        })
    }
}

/// Computes the public into on a serializable `element`.
/// More specifically, computes the unique handle of the `element` and signs this handle using the
/// `kms`.
pub(crate) fn compute_info<S: Serialize + Versionize + Named>(
    sk: &PrivateSigKey,
    element: &S,
    domain: Option<&alloy_sol_types::Eip712Domain>,
) -> anyhow::Result<SignedPubDataHandleInternal> {
    let handle = compute_handle(element)?;
    let signature = crate::cryptography::signcryption::sign(&handle, sk)?;

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
        signature: bincode::serialize(&signature)?,
        external_signature,
    })
}

/// Compute a handle of an element, based on its digest
/// More specifically compute the hash digest, truncate it and convert it to a hex string
pub fn compute_handle<S>(element: &S) -> anyhow::Result<String>
where
    S: Serialize + Versionize + Named,
{
    let mut digest = safe_serialize_hash_element_versioned(element)?;
    // Truncate and convert to hex
    digest.truncate(ID_LENGTH);
    Ok(hex::encode(digest))
}

#[cfg(feature = "non-wasm")]
pub fn gen_sig_keys<R: CryptoRng + rand::Rng>(rng: &mut R) -> (PublicSigKey, PrivateSigKey) {
    use k256::ecdsa::SigningKey;

    let sk = SigningKey::random(rng);
    let pk = SigningKey::verifying_key(&sk);
    (PublicSigKey::new(*pk), PrivateSigKey::new(sk))
}

macro_rules! deserialize_to_low_level_helper {
    ($rust_type:ty,$ct_format:expr,$serialized_high_level:expr,$decompression_key:expr) => {{
        match $ct_format {
            CiphertextFormat::SmallCompressed => {
                let hl_ct: $rust_type =
                    decompression::tfhe_safe_deserialize_and_uncompress::<$rust_type>(
                        $decompression_key
                            .as_ref()
                            .ok_or(anyhow::anyhow!("missing decompression key"))?,
                        $serialized_high_level,
                    )?;
                let (radix_ct, _id, _tag) = hl_ct.into_raw_parts();
                LowLevelCiphertext::Small(radix_ct)
            }
            CiphertextFormat::SmallExpanded => {
                let hl_ct: $rust_type =
                    decompression::tfhe_safe_deserialize::<$rust_type>($serialized_high_level)?;
                let (radix_ct, _id, _tag) = hl_ct.into_raw_parts();
                LowLevelCiphertext::Small(radix_ct)
            }
            CiphertextFormat::BigCompressed => {
                anyhow::bail!("big compressed ciphertexts are not supported yet");
            }
            CiphertextFormat::BigExpanded => {
                let r = safe_deserialize::<Ciphertext128>(
                    std::io::Cursor::new($serialized_high_level),
                    kms_grpc::rpc_types::SAFE_SER_SIZE_LIMIT,
                )
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                LowLevelCiphertext::Big(r)
            }
        }
    }};
}

pub fn deserialize_to_low_level(
    fhe_type: &FheType,
    ct_format: CiphertextFormat,
    serialized_high_level: &[u8],
    decompression_key: &Option<DecompressionKey>,
) -> anyhow::Result<LowLevelCiphertext> {
    let radix_ct = match fhe_type {
        FheType::Ebool => match ct_format {
            CiphertextFormat::SmallCompressed => {
                let hl_ct: FheBool = decompression::tfhe_safe_deserialize_and_uncompress::<FheBool>(
                    decompression_key
                        .as_ref()
                        .ok_or(anyhow::anyhow!("missing decompression key"))?,
                    serialized_high_level,
                )?;
                let radix_ct = hl_ct.into_raw_parts();
                LowLevelCiphertext::Small(BaseRadixCiphertext::from_blocks(vec![radix_ct]))
            }
            CiphertextFormat::SmallExpanded => {
                let hl_ct: FheBool =
                    decompression::tfhe_safe_deserialize::<FheBool>(serialized_high_level)?;
                let radix_ct = hl_ct.into_raw_parts();
                LowLevelCiphertext::Small(BaseRadixCiphertext::from_blocks(vec![radix_ct]))
            }
            CiphertextFormat::BigCompressed => {
                anyhow::bail!("big compressed ciphertexts are not supported yet");
            }
            CiphertextFormat::BigExpanded => {
                let r = safe_deserialize::<Ciphertext128>(
                    std::io::Cursor::new(serialized_high_level),
                    kms_grpc::rpc_types::SAFE_SER_SIZE_LIMIT,
                )
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;
                LowLevelCiphertext::Big(r)
            }
        },
        FheType::Euint4 => {
            deserialize_to_low_level_helper!(
                FheUint4,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheType::Euint8 => {
            deserialize_to_low_level_helper!(
                FheUint8,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheType::Euint16 => {
            deserialize_to_low_level_helper!(
                FheUint16,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheType::Euint32 => {
            deserialize_to_low_level_helper!(
                FheUint32,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheType::Euint64 => {
            deserialize_to_low_level_helper!(
                FheUint64,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheType::Euint128 => {
            deserialize_to_low_level_helper!(
                FheUint128,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheType::Euint160 => {
            deserialize_to_low_level_helper!(
                FheUint160,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheType::Euint256 => {
            deserialize_to_low_level_helper!(
                FheUint256,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheType::Euint512 => {
            deserialize_to_low_level_helper!(
                FheUint512,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheType::Euint1024 => {
            deserialize_to_low_level_helper!(
                FheUint1024,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
        FheType::Euint2048 => {
            deserialize_to_low_level_helper!(
                FheUint2048,
                ct_format,
                serialized_high_level,
                decompression_key
            )
        }
    };
    Ok(radix_ct)
}

pub(crate) fn compute_external_reenc_signature(
    server_sk: &PrivateSigKey,
    cts: &[TypedSigncryptedCiphertext],
    eip712_domain: &Eip712Domain,
    user_pk: &PublicEncKey,
) -> anyhow::Result<Vec<u8>> {
    let message_hash = compute_reenc_message_hash(cts, eip712_domain, user_pk)?;

    let signer = PrivateKeySigner::from_signing_key(server_sk.sk().clone());
    let signer_address = signer.address();
    tracing::info!("Signer address: {:?}", signer_address);

    // Sign the hash synchronously with the wallet.
    let signature = signer.sign_hash_sync(&message_hash)?.as_bytes().to_vec();

    tracing::info!(
        "UserDecryptionResult Signature: {:?}",
        hex::encode(signature.clone())
    );

    Ok(signature)
}

/// take external handles and plaintext in the form of bytes, convert them to the required solidity types and sign them using EIP-712 for external verification (e.g. in the fhevm).
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

/// Safely serialize some public data, convert it to a solidity type byte array and compute the EIP-712 message hash for external verification (e.g. in the fhevm).
pub fn compute_external_pubdata_message_hash<D: Serialize + Versionize + Named>(
    data: &D,
    eip712_domain: &Eip712Domain,
) -> anyhow::Result<B256> {
    let bytes = kms_grpc::rpc_types::safe_serialize_hash_element_versioned(data)?;

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
        "SwitchAndSquashKey" => {
            // TODO name might change after we have the struct from tfhe-rs
            let message = SnsKey {
                sns_key: bytes.into(),
            };
            message.eip712_signing_hash(eip712_domain)
        }
        e => {
            return Err(anyhow_error_and_log(format!(
                "Cannot compute EIP-712 signature on type {}. Expected one of: zk::CompactPkeCrs, high_level_api::CompactPublicKey, high_level_api::ServerKey.",
                e
            )))
        }
    };
    tracing::info!("Public Data EIP-712 Message hash: {:?}", message_hash);
    Ok(message_hash)
}

/// take some public data (e.g. public key or CRS) and sign it using EIP-712 for external verification (e.g. in the fhevm).
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
        let serialized_verf_key = Arc::new(bincode::serialize(&PublicSigKey::new(
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
        payload: &T,
        signature: &crate::cryptography::internal_crypto_types::Signature,
        key: &PublicSigKey,
    ) -> anyhow::Result<()>
    where
        T: Serialize + AsRef<[u8]>,
    {
        internal_verify_sig(&payload, signature, key)
    }

    /// sign `msg` using the KMS' private signing key
    fn sign<T>(
        &self,
        msg: &T,
    ) -> anyhow::Result<crate::cryptography::internal_crypto_types::Signature>
    where
        T: Serialize + AsRef<[u8]>,
    {
        crate::cryptography::signcryption::sign(msg, &self.sig_key)
    }

    fn get_serialized_verf_key(&self) -> Vec<u8> {
        self.serialized_verf_key.as_ref().clone()
    }

    fn digest<T>(msg: &T) -> anyhow::Result<Vec<u8>>
    where
        T: ?Sized + AsRef<[u8]>,
    {
        Ok(hash_element(msg))
    }
}

// take an ordered list of plaintexts and ABI encode them into Solidity Bytes
fn abi_encode_plaintexts(ptxts: &[TypedPlaintext]) -> Bytes {
    // This is a hack to get the offsets right for Byte types.
    // Every offset needs to be shifted by 32 bytes (256 bits), so we prepend a U256 and delete it at the and, after encoding.
    let mut data = vec![DynSolValue::Uint(U256::from(0), 256)];

    // This is another hack to handle Euint512, Euint1024 and Euint2048 Bytes properly (alloy adds another all-zero 256 bytes to the beginning of the encoded bytes)
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
            FheType::Euint512 => {
                // if we have at least 1 Euint larger than 256 bits, we need to throw away 256 more bytes at the beginning of the encoding below, thus set offset_mul to 2
                offset_mul = 2;
                let mut cake = vec![0u8; 64];
                ptxt.as_u512().copy_to_be_byte_slice(cake.as_mut_slice());
                DynSolValue::Bytes(cake)
            }
            FheType::Euint1024 => {
                // if we have at least 1 Euint larger than 256 bits, we need to throw away 256 more bytes at the beginning of the encoding below, thus set offset_mul to 2
                offset_mul = 2;
                let mut cake = vec![0u8; 128];
                ptxt.as_u1024().copy_to_be_byte_slice(cake.as_mut_slice());
                DynSolValue::Bytes(cake)
            }
            FheType::Euint2048 => {
                // if we have at least 1 Euint larger than 256 bits, we need to throw away 256 more bytes at the beginning of the encoding below, thus set offset_mul to 2
                offset_mul = 2;
                let mut cake = vec![0u8; 256];
                ptxt.as_u2048().copy_to_be_byte_slice(cake.as_mut_slice());
                DynSolValue::Bytes(cake)
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

pub fn compute_pt_message_hash(
    ext_handles_bytes: Vec<Vec<u8>>,
    pts: &[TypedPlaintext],
    eip712_domain: Eip712Domain,
) -> B256 {
    // convert external_handles back to U256 to be signed
    let external_handles: Vec<_> = ext_handles_bytes
        .into_iter()
        .map(|e| U256::from_be_slice(e.as_slice()))
        .collect();

    let pt_bytes = abi_encode_plaintexts(pts);

    // the solidity structure to sign with EIP-712
    let message = EIP712PublicDecrypt {
        handlesList: external_handles,
        decryptedResult: pt_bytes,
    };

    let message_hash = message.eip712_signing_hash(&eip712_domain);
    tracing::info!("PT EIP-712 Message hash: {:?}", message_hash);
    message_hash
}

pub fn compute_reenc_message_hash(
    cts: &[TypedSigncryptedCiphertext],
    eip712_domain: &Eip712Domain,
    user_pk: &PublicEncKey,
) -> anyhow::Result<B256> {
    // convert external_handles back to U256 to be signed
    let external_handles: Vec<_> = cts
        .iter()
        .map(|e| U256::from_be_slice(e.external_handle.as_slice()))
        .collect();

    let reencrypted_share_buf = bincode::serialize(cts)?;

    // the solidity structure to sign with EIP-712
    // note that the JS client must also use the same encoding to verify the result
    let user_pk = bincode::serialize(user_pk)?;
    let message = UserDecryptionResult {
        publicKey: user_pk.into(),
        handles: external_handles,
        reencryptedShare: reencrypted_share_buf.into(),
    };

    let message_hash = message.eip712_signing_hash(eip712_domain);
    tracing::info!(
        "UserDecryptionResult EIP-712 Message hash: {:?}",
        message_hash
    );
    Ok(message_hash)
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
pub type DecCallValues = (Vec<u8>, Vec<TypedPlaintext>, Vec<u8>);

// Values that need to be stored temporarily as part of an async reencryption call.
// Represents Vec<TypedSigncryptedCiphertext>, external_handles, external_signature, request digest/link.
#[cfg(feature = "non-wasm")]
pub type ReencCallValues = (Vec<TypedSigncryptedCiphertext>, Vec<u8>, Vec<u8>);

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
                    .ok_or(anyhow::anyhow!("missing StandardKeySetConfig"))?;
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
    use super::TypedPlaintext;
    use aes_prng::AesRng;
    use rand::{RngCore, SeedableRng};

    #[test]
    fn sunshine_plaintext_as_u256() {
        let mut rng = AesRng::seed_from_u64(1);
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);

        let plaintext = TypedPlaintext {
            bytes: bytes.to_vec(),
            fhe_type: kms_grpc::kms::v1::FheType::Euint160 as i32,
        };
        // Check the value is greater than 2^128
        assert!(plaintext.as_u160() > tfhe::integer::U256::from((0, 1)));
        assert!(plaintext.as_u256() > tfhe::integer::U256::from((0, 1)));
        // Sanity check the internal values - at least one byte must be different from zero
        assert!(bytes.iter().any(|&b| b != 0));
        assert_eq!(plaintext.fhe_type(), kms_grpc::kms::v1::FheType::Euint160);
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
        let pts_16: Vec<TypedPlaintext> = vec![TypedPlaintext::from_u16(16)];

        // encode plaintexts into a list of solidity bytes using `alloy`
        let bytes_16 = super::abi_encode_plaintexts(&pts_16);
        let hexbytes_16 = hex::encode(bytes_16);

        // this is the encoding of the same list of plaintexts (pts_16) using the outdated `ethers` crate.
        let reference_16 = "0000000000000000000000000000000000000000000000000000000000000010";

        assert_eq!(reference_16, hexbytes_16.as_str());

        // a batch of a two plaintext that are not of type Euint2048
        let pts_16_2: Vec<TypedPlaintext> =
            vec![TypedPlaintext::from_u16(16), TypedPlaintext::from_u16(16)];

        // encode plaintexts into a list of solidity bytes using `alloy`
        let bytes_16_2 = super::abi_encode_plaintexts(&pts_16_2);
        let hexbytes_16_2 = hex::encode(bytes_16_2);

        // this is the encoding of the same list of plaintexts (pts_16_2) using the outdated `ethers` crate.
        let reference_16_2 = "0000000000000000000000000000000000000000000000000000000000000010\
                                    0000000000000000000000000000000000000000000000000000000000000010";

        assert_eq!(reference_16_2, hexbytes_16_2.as_str());
    }
}

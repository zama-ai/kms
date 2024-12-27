use crate::anyhow_error_and_log;
use crate::cryptography::central_kms::KmsFheKeyHandles;
use crate::cryptography::decompression;
use crate::cryptography::internal_crypto_types::{
    PrivateSigKey, PublicEncKey, PublicSigKey, Signature,
};
use alloy_dyn_abi::DynSolValue;
use alloy_primitives::Bytes;
use alloy_primitives::{Address, B256, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::Eip712Domain;
use alloy_sol_types::SolStruct;
use distributed_decryption::execution::tfhe_internals::parameters::{Ciphertext64, DKGParams};
use kms_grpc::kms::{FheParameter, FheType, TypedPlaintext, VerifyProvenCtRequest};
use kms_grpc::rpc_types::{
    CiphertextVerificationForKMS, DecryptionResult, FhePubKey, FheServerKey, CRS,
};
use rand::{CryptoRng, RngCore};
use serde::Serialize;
use tfhe::integer::ciphertext::BaseRadixCiphertext;
use tfhe::integer::compression_keys::DecompressionKey;
use tfhe::integer::IntegerCiphertext;
use tfhe::named::Named;
use tfhe::Versionize;
use tfhe::{
    FheBool, FheUint1024, FheUint128, FheUint16, FheUint160, FheUint2048, FheUint256, FheUint32,
    FheUint4, FheUint512, FheUint64, FheUint8,
};

pub fn deserialize_to_low_level(
    fhe_type: &FheType,
    serialized_high_level: &[u8],
    decompression_key: &Option<DecompressionKey>,
) -> anyhow::Result<Ciphertext64> {
    let radix_ct = match fhe_type {
        FheType::Ebool => {
            let hl_ct: FheBool =
                decompression::from_bytes::<FheBool>(decompression_key, serialized_high_level)?;
            let radix_ct = hl_ct.into_raw_parts();
            BaseRadixCiphertext::from_blocks(vec![radix_ct])
        }
        FheType::Euint4 => {
            let hl_ct: FheUint4 =
                decompression::from_bytes::<FheUint4>(decompression_key, serialized_high_level)?;
            let (radix_ct, _id, _tag) = hl_ct.into_raw_parts();
            radix_ct
        }
        FheType::Euint8 => {
            let hl_ct: FheUint8 =
                decompression::from_bytes::<FheUint8>(decompression_key, serialized_high_level)?;
            let (radix_ct, _id, _tag) = hl_ct.into_raw_parts();
            radix_ct
        }
        FheType::Euint16 => {
            let hl_ct: FheUint16 =
                decompression::from_bytes::<FheUint16>(decompression_key, serialized_high_level)?;
            let (radix_ct, _id, _tag) = hl_ct.into_raw_parts();
            radix_ct
        }
        FheType::Euint32 => {
            let hl_ct: FheUint32 =
                decompression::from_bytes::<FheUint32>(decompression_key, serialized_high_level)?;
            let (radix_ct, _id, _tag) = hl_ct.into_raw_parts();
            radix_ct
        }
        FheType::Euint64 => {
            let hl_ct: FheUint64 =
                decompression::from_bytes::<FheUint64>(decompression_key, serialized_high_level)?;
            let (radix_ct, _id, _tag) = hl_ct.into_raw_parts();
            radix_ct
        }
        FheType::Euint128 => {
            let hl_ct: FheUint128 =
                decompression::from_bytes::<FheUint128>(decompression_key, serialized_high_level)?;
            let (radix_ct, _id, _tag) = hl_ct.into_raw_parts();
            radix_ct
        }
        FheType::Euint160 => {
            let hl_ct: FheUint160 =
                decompression::from_bytes::<FheUint160>(decompression_key, serialized_high_level)?;
            let (radix_ct, _id, _tag) = hl_ct.into_raw_parts();
            radix_ct
        }
        FheType::Euint256 => {
            let hl_ct: FheUint256 =
                decompression::from_bytes::<FheUint256>(decompression_key, serialized_high_level)?;
            let (radix_ct, _id, _tag) = hl_ct.into_raw_parts();
            radix_ct
        }
        FheType::Euint512 => {
            let hl_ct: FheUint512 =
                decompression::from_bytes::<FheUint512>(decompression_key, serialized_high_level)?;
            let (radix_ct, _id, _tag) = hl_ct.into_raw_parts();
            radix_ct
        }
        FheType::Euint1024 => {
            let hl_ct: FheUint1024 =
                decompression::from_bytes::<FheUint1024>(decompression_key, serialized_high_level)?;
            let (radix_ct, _id, _tag) = hl_ct.into_raw_parts();
            radix_ct
        }
        FheType::Euint2048 => {
            let hl_ct: FheUint2048 =
                decompression::from_bytes::<FheUint2048>(decompression_key, serialized_high_level)?;
            let (radix_ct, _id, _tag) = hl_ct.into_raw_parts();
            radix_ct
        }
    };
    Ok(radix_ct)
}

/// take external handles and plaintext in the form of bytes, convert them to the required solidity types and sign them using EIP-712 for external verification (e.g. in the fhevm).
pub(crate) fn compute_external_pt_signature(
    client_sk: &PrivateSigKey,
    ext_handles_bytes: Vec<Option<Vec<u8>>>,
    pts: &[TypedPlaintext],
    eip712_domain: Eip712Domain,
    acl_address: Address,
) -> Vec<u8> {
    let message_hash = compute_pt_message_hash(ext_handles_bytes, pts, eip712_domain, acl_address);

    let signer = PrivateKeySigner::from_signing_key(client_sk.sk().clone());
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

/// Take the ZK proof verification metadata, convert it to the required solidity types and sign them using EIP-712 for external verification (e.g. in the fhevm).
pub fn compute_external_verify_proven_ct_signature(
    client_sk: &PrivateSigKey,
    ct_digest: &Vec<u8>,
    req: &VerifyProvenCtRequest,
) -> anyhow::Result<Vec<u8>> {
    let eip712_domain = match req.domain.as_ref() {
        Some(domain) => kms_grpc::rpc_types::protobuf_to_alloy_domain(domain)?,
        None => {
            return Err(anyhow::anyhow!(
                "EIP-712 domain is not set for ZK verification signature!"
            ));
        }
    };

    // the solidity structure to sign with EIP-712
    let message = CiphertextVerificationForKMS {
        aclAddress: alloy_primitives::Address::parse_checksummed(&req.acl_address, None)?,
        hashOfCiphertext: ct_digest.as_slice().try_into()?,
        userAddress: alloy_primitives::Address::parse_checksummed(&req.client_address, None)?,
        contractAddress: alloy_primitives::Address::parse_checksummed(&req.contract_address, None)?,
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

/// Safely serialize some public data, convert it to a solidity type byte array and compute the EIP-712 message hash for external verification (e.g. in the fhevm).
pub fn compute_external_pubdata_message_hash<D: Serialize + Versionize + Named>(
    data: &D,
    eip712_domain: &Eip712Domain,
) -> anyhow::Result<B256> {
    let bytes = kms_grpc::rpc_types::safe_serialize_hash_element_versioned(data)?;

    // distinguish between the different types of public data we can sign according to their type name and sign it with EIP-712
    let message_hash = match D::NAME {
        "zk::CompactPkePublicParams" => {
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
                "Cannot compute EIP-712 signature on type {}. Expected one of: zk::CompactPkePublicParams, high_level_api::CompactPublicKey, high_level_api::ServerKey.",
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
    let signature = signer
        .sign_hash_sync(&message_hash)
        .unwrap()
        .as_bytes()
        .to_vec();

    tracing::info!(
        "Public Data EIP-712 Signature: {:?}",
        hex::encode(signature.clone())
    );

    Ok(signature)
}

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
pub trait Kms: BaseKms {
    fn decrypt(
        keys: &KmsFheKeyHandles,
        ct: &[u8],
        fhe_type: FheType,
    ) -> anyhow::Result<TypedPlaintext>;
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
/// Trait for shutting down the KMS gracefully.
#[tonic::async_trait]
pub trait Shutdown {
    async fn shutdown(&self) -> anyhow::Result<()>;
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
    ext_handles_bytes: Vec<Option<Vec<u8>>>,
    pts: &[TypedPlaintext],
    eip712_domain: Eip712Domain,
    acl_address: Address,
) -> B256 {
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

    let message_hash = message.eip712_signing_hash(&eip712_domain);
    tracing::info!("PT EIP-712 Message hash: {:?}", message_hash);
    message_hash
}

pub(crate) fn retrieve_parameters(fhe_parameter: i32) -> anyhow::Result<DKGParams> {
    let fhe_parameter: crate::cryptography::internal_crypto_types::WrappedDKGParams =
        FheParameter::try_from(fhe_parameter)?.into();
    Ok(*fhe_parameter)
}

#[cfg(test)]
pub(crate) trait RequestIdGetter {
    fn request_id(&self) -> Option<kms_grpc::kms::RequestId>;
}

#[cfg(test)]
impl RequestIdGetter for kms_grpc::kms::CrsGenRequest {
    fn request_id(&self) -> Option<kms_grpc::kms::RequestId> {
        self.request_id.clone()
    }
}

#[cfg(test)]
impl RequestIdGetter for VerifyProvenCtRequest {
    fn request_id(&self) -> Option<kms_grpc::kms::RequestId> {
        self.request_id.clone()
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
            fhe_type: kms_grpc::kms::FheType::Euint160 as i32,
        };
        // Check the value is greater than 2^128
        assert!(plaintext.as_u160() > tfhe::integer::U256::from((0, 1)));
        assert!(plaintext.as_u256() > tfhe::integer::U256::from((0, 1)));
        // Sanity check the internal values - at least one byte must be different from zero
        assert!(bytes.iter().any(|&b| b != 0));
        assert_eq!(plaintext.fhe_type(), kms_grpc::kms::FheType::Euint160);
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

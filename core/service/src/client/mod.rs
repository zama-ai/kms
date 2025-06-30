use crate::cryptography::internal_crypto_types::Signature;
use crate::cryptography::internal_crypto_types::{
    PrivateEncKey, PrivateSigKey, PublicEncKey, PublicSigKey, SigncryptionPair,
    SigncryptionPrivKey, SigncryptionPubKey,
};
use crate::cryptography::signcryption::{
    decrypt_signcryption_with_link, ephemeral_encryption_key_generation,
    insecure_decrypt_ignoring_signature, internal_verify_sig,
};
#[cfg(feature = "non-wasm")]
use crate::engine::base::DSEP_PUBDATA_KEY;
#[cfg(feature = "non-wasm")]
use crate::engine::validation::DSEP_PUBLIC_DECRYPTION;
use crate::engine::validation::{
    check_ext_user_decryption_signature, validate_user_decrypt_responses_against_request,
    DSEP_USER_DECRYPTION,
};
use crate::{anyhow_error_and_log, some_or_err};
use aes_prng::AesRng;
use alloy_sol_types::Eip712Domain;
use alloy_sol_types::SolStruct;
#[cfg(feature = "non-wasm")]
use futures_util::future::{try_join_all, TryFutureExt};
use itertools::Itertools;
use kms_grpc::kms::v1::{
    TypedCiphertext, TypedPlaintext, UserDecryptionRequest, UserDecryptionResponse,
    UserDecryptionResponsePayload,
};
use kms_grpc::rpc_types::{
    alloy_to_protobuf_domain, fhe_types_to_num_blocks, UserDecryptionLinker,
};
use kms_grpc::RequestId;
use rand::SeedableRng;
use std::collections::HashMap;
use std::num::Wrapping;
use tfhe::shortint::ClassicPBSParameters;
use tfhe::FheTypes;
use threshold_fhe::algebra::base_ring::{Z128, Z64};
use threshold_fhe::algebra::error_correction::MemoizedExceptionals;
use threshold_fhe::algebra::galois_rings::degree_4::ResiduePolyF4;
use threshold_fhe::algebra::structure_traits::{BaseRing, ErrorCorrect};
use threshold_fhe::execution::endpoints::decryption::DecryptionMode;
use threshold_fhe::execution::endpoints::reconstruct::{
    combine_decryptions, reconstruct_packed_message,
};
use threshold_fhe::execution::runtime::party::Role;
use threshold_fhe::execution::sharing::shamir::{
    fill_indexed_shares, reconstruct_w_errors_sync, ShamirSharings,
};
use threshold_fhe::execution::tfhe_internals::parameters::{
    AugmentedCiphertextParameters, DKGParams,
};
use wasm_bindgen::prelude::*;

cfg_if::cfg_if! {
    if #[cfg(feature = "non-wasm")] {
        use crate::engine::base::{compute_handle};
        use crate::engine::base::DSEP_PUBDATA_CRS;
        use threshold_fhe::hashing::DomainSep;
        use crate::engine::traits::BaseKms;
        use crate::engine::base::BaseKmsStruct;
        use crate::vault::storage::{Storage, StorageReader, crypto_material::{get_core_verification_key, get_client_verification_key, get_client_signing_key}};
        use kms_grpc::kms::v1::{
            KeySetAddedInfo, CrsGenRequest, CrsGenResult, PublicDecryptionRequest,
            PublicDecryptionResponse, FheParameter, KeyGenPreprocRequest,
            KeyGenRequest, KeyGenResult, KeySetConfig,
        };
        use kms_grpc::rpc_types::{PubDataType, PublicKeyType, WrappedPublicKeyOwned};
        use std::fmt;
        use tfhe::zk::CompactPkeCrs;
        use tfhe::ServerKey;
        use tfhe_versionable::{Unversionize, Versionize};
        use tonic::transport::Channel;
        use tonic_health::pb::health_client::HealthClient;
        use tonic_health::ServingStatus;
        use tonic_health::pb::HealthCheckRequest;
        use crate::consts::{DEFAULT_PROTOCOL, DEFAULT_URL, MAX_TRIES};
        use crate::engine::validation::validate_public_decrypt_responses_against_request;
    }
}

#[cfg(not(feature = "non-wasm"))]
pub mod js_api;

/// Helper method for combining reconstructed messages after decryption.
fn decrypted_blocks_to_plaintext(
    params: &ClassicPBSParameters,
    fhe_type: FheTypes,
    packing_factor: u32,
    recon_blocks: Vec<Z128>,
) -> anyhow::Result<TypedPlaintext> {
    let bits_in_block = params.message_modulus_log() * packing_factor;
    let res_pt = match fhe_type {
        FheTypes::Uint2048 => {
            combine_decryptions::<tfhe::integer::bigint::U2048>(bits_in_block, recon_blocks)
                .map(TypedPlaintext::from_u2048)
        }
        FheTypes::Uint1024 => {
            combine_decryptions::<tfhe::integer::bigint::U1024>(bits_in_block, recon_blocks)
                .map(TypedPlaintext::from_u1024)
        }
        FheTypes::Uint512 => {
            combine_decryptions::<tfhe::integer::bigint::U512>(bits_in_block, recon_blocks)
                .map(TypedPlaintext::from_u512)
        }
        FheTypes::Uint256 => {
            combine_decryptions::<tfhe::integer::U256>(bits_in_block, recon_blocks)
                .map(TypedPlaintext::from_u256)
        }
        FheTypes::Uint160 => {
            combine_decryptions::<tfhe::integer::U256>(bits_in_block, recon_blocks)
                .map(TypedPlaintext::from_u160)
        }
        FheTypes::Uint128 => combine_decryptions::<u128>(bits_in_block, recon_blocks)
            .map(|x| TypedPlaintext::new(x, fhe_type)),
        FheTypes::Uint80 => {
            combine_decryptions::<u128>(bits_in_block, recon_blocks).map(TypedPlaintext::from_u80)
        }
        FheTypes::Bool
        | FheTypes::Uint4
        | FheTypes::Uint8
        | FheTypes::Uint16
        | FheTypes::Uint32
        | FheTypes::Uint64 => combine_decryptions::<u64>(bits_in_block, recon_blocks)
            .map(|x| TypedPlaintext::new(x as u128, fhe_type)),
        unsupported_fhe_type => anyhow::bail!("Unsupported fhe_type {unsupported_fhe_type:?}"),
    };
    res_pt.map_err(|error| anyhow_error_and_log(format!("Panicked in combining {error}")))
}

/// For user decryption, we only use the Addr variant,
/// for everything else, we use the Pk variant.
#[derive(Clone)]
pub enum ServerIdentities {
    Pks(HashMap<u32, PublicSigKey>),
    Addrs(HashMap<u32, alloy_primitives::Address>),
}

impl ServerIdentities {
    fn len(&self) -> usize {
        match &self {
            ServerIdentities::Pks(vec) => vec.len(),
            ServerIdentities::Addrs(vec) => vec.len(),
        }
    }
}

/// Core Client
///
/// Simple client to interact with the KMS servers. This can be seen as a proof-of-concept
/// and reference code for validating the KMS. The logic supplied by the client will be
/// distributed across the aggregator/proxy and smart contracts.
#[wasm_bindgen]
pub struct Client {
    rng: Box<AesRng>,
    server_identities: ServerIdentities,
    client_address: alloy_primitives::Address,
    client_sk: Option<PrivateSigKey>,
    params: DKGParams,
    decryption_mode: DecryptionMode,
}

// This testing struct needs to be outside of js_api module
// since it is needed in the tests to generate the right files for js/wasm tests.
#[cfg(feature = "wasm_tests")]
#[wasm_bindgen]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct TestingUserDecryptionTranscript {
    // client
    server_addrs: HashMap<u32, alloy_primitives::Address>,
    client_address: alloy_primitives::Address,
    client_sk: Option<PrivateSigKey>,
    degree: u32,
    params: DKGParams,
    // example pt and ct
    fhe_types: Vec<i32>,
    pts: Vec<Vec<u8>>,
    cts: Vec<Vec<u8>>,
    // request
    request: Option<UserDecryptionRequest>,
    eph_sk: PrivateEncKey,
    eph_pk: PublicEncKey,
    // response
    agg_resp: Vec<UserDecryptionResponse>,
}

#[wasm_bindgen]
#[derive(serde::Serialize, Debug)]
pub struct CiphertextHandle(Vec<u8>);

impl CiphertextHandle {
    pub fn new(handle: Vec<u8>) -> Self {
        CiphertextHandle(handle)
    }
}

/// Validity of this struct is not checked.
#[wasm_bindgen]
pub struct ParsedUserDecryptionRequest {
    // We allow dead_code because these are required to parse from JSON
    #[allow(dead_code)]
    signature: Option<alloy_primitives::Signature>,
    #[allow(dead_code)]
    client_address: alloy_primitives::Address,
    enc_key: Vec<u8>,
    ciphertext_handles: Vec<CiphertextHandle>,
    eip712_verifying_contract: alloy_primitives::Address,
}

impl ParsedUserDecryptionRequest {
    pub fn new(
        signature: Option<alloy_primitives::Signature>,
        client_address: alloy_primitives::Address,
        enc_key: Vec<u8>,
        ciphertext_handles: Vec<CiphertextHandle>,
        eip712_verifying_contract: alloy_primitives::Address,
    ) -> Self {
        Self {
            signature,
            client_address,
            enc_key,
            ciphertext_handles,
            eip712_verifying_contract,
        }
    }

    pub fn enc_key(&self) -> &[u8] {
        &self.enc_key
    }
}

pub(crate) fn hex_decode_js_err(msg: &str) -> Result<Vec<u8>, JsError> {
    if msg.len() >= 2 {
        if msg[0..2] == *"0x" {
            hex::decode(&msg[2..]).map_err(|e| JsError::new(&e.to_string()))
        } else {
            hex::decode(msg).map_err(|e| JsError::new(&e.to_string()))
        }
    } else {
        Err(JsError::new(
            "cannot decode hex string with fewer than 2 characters",
        ))
    }
}

// we need this type because the json fields are hex-encoded
// which cannot be converted to Vec<u8> automatically.
#[derive(serde::Serialize, serde::Deserialize)]
struct ParsedUserDecryptionRequestHex {
    signature: Option<String>,
    client_address: String,
    enc_key: String,
    ciphertext_handles: Vec<String>,
    eip712_verifying_contract: String,
}

impl TryFrom<&ParsedUserDecryptionRequestHex> for ParsedUserDecryptionRequest {
    type Error = JsError;

    fn try_from(req_hex: &ParsedUserDecryptionRequestHex) -> Result<Self, Self::Error> {
        let signature_buf = req_hex
            .signature
            .as_ref()
            .map(|sig| hex_decode_js_err(sig))
            .transpose()?;
        let signature = signature_buf
            .map(|buf| alloy_primitives::Signature::try_from(buf.as_slice()))
            .transpose()
            .map_err(|e| JsError::new(&e.to_string()))?;
        let client_address =
            alloy_primitives::Address::parse_checksummed(&req_hex.client_address, None)
                .map_err(|e| JsError::new(&e.to_string()))?;
        let eip712_verifying_contract =
            alloy_primitives::Address::parse_checksummed(&req_hex.eip712_verifying_contract, None)
                .map_err(|e| JsError::new(&e.to_string()))?;
        let out = Self {
            signature,
            client_address,
            enc_key: hex_decode_js_err(&req_hex.enc_key)?,
            ciphertext_handles: req_hex
                .ciphertext_handles
                .iter()
                .map(|hdl_str| hex_decode_js_err(hdl_str).map(CiphertextHandle))
                .collect::<Result<Vec<_>, JsError>>()?,
            eip712_verifying_contract,
        };
        Ok(out)
    }
}

impl TryFrom<JsValue> for ParsedUserDecryptionRequest {
    type Error = JsError;

    fn try_from(value: JsValue) -> Result<Self, Self::Error> {
        // JsValue -> JsClientUserDecryptionRequestHex
        let req_hex: ParsedUserDecryptionRequestHex =
            serde_wasm_bindgen::from_value(value).map_err(|e| JsError::new(&e.to_string()))?;

        // JsClientUserDecryptionRequestHex -> JsClientUserDecryptionRequest
        ParsedUserDecryptionRequest::try_from(&req_hex)
    }
}

impl From<&ParsedUserDecryptionRequest> for ParsedUserDecryptionRequestHex {
    fn from(value: &ParsedUserDecryptionRequest) -> Self {
        Self {
            signature: value
                .signature
                .as_ref()
                .map(|sig| hex::encode(sig.as_bytes())),
            client_address: value.client_address.to_checksum(None),
            enc_key: hex::encode(&value.enc_key),
            ciphertext_handles: value
                .ciphertext_handles
                .iter()
                .map(|hdl| hex::encode(&hdl.0))
                .collect::<Vec<_>>(),
            eip712_verifying_contract: value.eip712_verifying_contract.to_checksum(None),
        }
    }
}

impl TryFrom<&UserDecryptionRequest> for ParsedUserDecryptionRequest {
    type Error = anyhow::Error;

    fn try_from(value: &UserDecryptionRequest) -> Result<Self, Self::Error> {
        let domain = value
            .domain
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing domain"))?;

        let client_address =
            alloy_primitives::Address::parse_checksummed(&value.client_address, None)?;

        let eip712_verifying_contract =
            alloy_primitives::Address::parse_checksummed(domain.verifying_contract.clone(), None)?;

        let ciphertext_handles = value
            .typed_ciphertexts
            .iter()
            .map(|ct| CiphertextHandle(ct.external_handle.clone()))
            .collect::<Vec<_>>();

        let out = Self {
            signature: None,
            client_address,
            enc_key: value.enc_key.clone(),
            ciphertext_handles,
            eip712_verifying_contract,
        };
        Ok(out)
    }
}

/// Compute the link as (eip712_signing_hash(pk, domain) || hash(ciphertext handles)).
/// TODO
pub fn compute_link(
    req: &ParsedUserDecryptionRequest,
    domain: &Eip712Domain,
) -> anyhow::Result<Vec<u8>> {
    // check consistency
    let handles = req
        .ciphertext_handles
        .iter()
        .map(|x| alloy_primitives::FixedBytes::<32>::left_padding_from(&x.0))
        .collect::<Vec<_>>();

    let linker = UserDecryptionLinker {
        publicKey: req.enc_key.clone().into(),
        handles,
        userAddress: req.client_address,
    };

    let link = linker.eip712_signing_hash(domain).to_vec();

    Ok(link)
}

/// Client data type
///
/// Enum which represents the different kinds of public information that can be stored as part of key generation.
/// In practice this means the CRS and different types of public keys.
/// Data of this type is supposed to be readable by anyone on the internet
/// and stored on a medium that _may_ be susceptible to malicious modifications.
#[cfg(feature = "non-wasm")]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ClientDataType {
    SigningKey, // Type of the client's signing key
    VerfKey,    // Type for the servers verification keys
}

#[cfg(feature = "non-wasm")]
impl fmt::Display for ClientDataType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ClientDataType::SigningKey => write!(f, "SigningKey"),
            ClientDataType::VerfKey => write!(f, "VerfKey"),
        }
    }
}

impl Client {
    /// Constructor method to be used for WASM and other situations where data cannot be directly loaded
    /// from a [PublicStorage].
    ///
    /// * `server_pks` - a set of tkms core public keys.
    /// * `client_address` - the client wallet address.
    /// * `client_sk` - client private key.
    ///   This is optional because sometimes the private signing key is kept
    ///   in a secure location, e.g., hardware wallet or web extension.
    ///   Calling functions that requires `client_sk` when it is None will return an error.
    /// * `params` - the FHE parameters.
    /// * `decryption_mode` - the decryption mode to use. Currently available modes are: NoiseFloodSmall and BitDecSmall.
    ///   If set to none, DecryptionMode::default() is used.
    pub fn new(
        server_pks: HashMap<u32, PublicSigKey>,
        client_address: alloy_primitives::Address,
        client_sk: Option<PrivateSigKey>,
        params: DKGParams,
        decryption_mode: Option<DecryptionMode>,
    ) -> Self {
        let decryption_mode = decryption_mode.unwrap_or_default();
        Client {
            rng: Box::new(AesRng::from_entropy()), // todo should be argument
            server_identities: ServerIdentities::Pks(server_pks),
            client_address,
            client_sk,
            params,
            decryption_mode,
        }
    }

    /// Helper method to create a client based on a specific type of storage for loading the keys.
    /// Observe that this method is decoupled from the [Client] to ensure wasm compliance as wasm cannot handle
    /// file reading or generic traits.
    ///
    /// * `client_storage` - the storage where the client's keys (for signing and verifying) are stored.
    /// * `pub_storages` - the storages where the public verification keys of the servers are stored. These must be unique.
    /// * `params` - the FHE parameters
    /// * `decryption_mode` - the decryption mode to use. Currently available modes are: NoiseFloodSmall and BitDecSmall.
    ///   If set to none, DecryptionMode::default() is used.
    #[cfg(feature = "non-wasm")]
    pub async fn new_client<ClientS: Storage, PubS: StorageReader>(
        client_storage: ClientS,
        pub_storages: HashMap<u32, PubS>,
        params: &DKGParams,
        decryption_mode: Option<DecryptionMode>,
    ) -> anyhow::Result<Client> {
        let pks = try_join_all(pub_storages.iter().map(|(party_id, cur_storage)| {
            get_core_verification_key(cur_storage).map_ok(|pk| (*party_id, pk))
        }))
        .await?
        .into_iter()
        .collect::<HashMap<_, _>>();

        let pks_unique_count = pks.values().unique().count();

        if pks_unique_count != pks.len() {
            return Err(anyhow_error_and_log(format!(
                "Duplicate public keys present in map: {} unique, {} total",
                pks_unique_count,
                pks.len()
            )));
        }

        let client_pk = get_client_verification_key(&client_storage).await?;
        let client_address = alloy_primitives::Address::from_public_key(client_pk.pk());

        let client_sk = get_client_signing_key(&client_storage).await?;

        Ok(Client::new(
            pks,
            client_address,
            Some(client_sk),
            *params,
            decryption_mode,
        ))
    }

    /// Verify the signature received from the server on keys or other data objects.
    /// This verification will pass if one of the public keys can verify the signature.
    #[cfg(feature = "non-wasm")]
    fn verify_server_signature<T: serde::Serialize + AsRef<[u8]>>(
        &self,
        dsep: &DomainSep,
        data: &T,
        signature: &[u8],
    ) -> anyhow::Result<()> {
        if self
            .find_verifying_public_key(dsep, data, signature)
            .is_some()
        {
            Ok(())
        } else {
            Err(anyhow::anyhow!("server signature verification failed"))
        }
    }

    /// Verify the signature received from the server on keys or other data objects
    /// and return the public key that verified the signature.
    #[cfg(feature = "non-wasm")]
    fn find_verifying_public_key<T: serde::Serialize + AsRef<[u8]>>(
        &self,
        dsep: &DomainSep,
        data: &T,
        signature: &[u8],
    ) -> Option<PublicSigKey> {
        let signature_struct: Signature = match bc2wrap::deserialize(signature) {
            Ok(signature_struct) => signature_struct,
            Err(_) => {
                tracing::error!("Could not deserialize signature");
                return None;
            }
        };

        let server_pks = match self.get_server_pks() {
            Ok(pks) => pks,
            Err(e) => {
                tracing::error!("failed to get server pks ({})", e);
                return None;
            }
        };

        for verf_key in server_pks.values() {
            let ok = BaseKmsStruct::verify_sig(dsep, &data, &signature_struct, verf_key).is_ok();
            if ok {
                return Some(verf_key.clone());
            }
        }
        None
    }

    /// Generates a key gen request.
    ///
    /// The key generated will then be stored under the request_id handle.
    /// In the threshold case, we also need to reference the preprocessing we want to consume via
    /// its [`RequestId`] it can be set to None in the centralized case
    #[cfg(feature = "non-wasm")]
    pub fn key_gen_request(
        &self,
        request_id: &RequestId,
        preproc_id: Option<RequestId>,
        param: Option<FheParameter>,
        keyset_config: Option<KeySetConfig>,
        keyset_added_info: Option<KeySetAddedInfo>,
        eip712_domain: Option<Eip712Domain>,
    ) -> anyhow::Result<KeyGenRequest> {
        let parsed_param: i32 = match param {
            Some(parsed_param) => parsed_param.into(),
            None => FheParameter::Default.into(),
        };
        if !request_id.is_valid() {
            return Err(anyhow_error_and_log(format!(
                "The request id format is not valid {request_id}"
            )));
        }

        let domain = match eip712_domain {
            Some(eip712_domain) => Some(alloy_to_protobuf_domain(&eip712_domain)?),
            None => None,
        };

        let prep_id = preproc_id.map(|res| res.into());

        Ok(KeyGenRequest {
            params: parsed_param,
            preproc_id: prep_id,
            request_id: Some((*request_id).into()),
            domain,
            keyset_config,
            keyset_added_info,
        })
    }

    #[cfg(feature = "non-wasm")]
    pub fn crs_gen_request(
        &self,
        request_id: &RequestId,
        max_num_bits: Option<u32>,
        param: Option<FheParameter>,
        eip712_domain: Option<Eip712Domain>,
    ) -> anyhow::Result<CrsGenRequest> {
        let parsed_param: i32 = match param {
            Some(parsed_param) => parsed_param.into(),
            None => FheParameter::Default.into(),
        };
        if !request_id.is_valid() {
            return Err(anyhow_error_and_log(format!(
                "The request id format is not valid {request_id}"
            )));
        }

        let domain = match eip712_domain {
            Some(eip712_domain) => Some(alloy_to_protobuf_domain(&eip712_domain)?),
            None => None,
        };

        Ok(CrsGenRequest {
            params: parsed_param,
            max_num_bits,
            request_id: Some((*request_id).into()),
            domain,
        })
    }

    #[cfg(feature = "non-wasm")]
    pub fn preproc_request(
        &self,
        request_id: &RequestId,
        param: Option<FheParameter>,
        keyset_config: Option<KeySetConfig>,
    ) -> anyhow::Result<KeyGenPreprocRequest> {
        if !request_id.is_valid() {
            return Err(anyhow_error_and_log(format!(
                "The request id format is not valid {request_id}"
            )));
        }

        Ok(KeyGenPreprocRequest {
            params: param.unwrap_or_default().into(),
            keyset_config,
            request_id: Some((*request_id).into()),
        })
    }

    /// Process a vector of CRS generation results along with a storage reader for each result.
    ///
    /// In the ideal scenario, the generated CRS should be the same
    /// for all parties. But if there are adversaries, this might not
    /// be the case. In addition to checking the digests and signatures,
    /// This function takes care of finding the CRS that is returned by
    /// the majority and ensuring that this involves agreement by at least
    /// `min_agree_count` of the parties.
    #[cfg(feature = "non-wasm")]
    pub async fn process_distributed_crs_result<S: StorageReader>(
        &self,
        request_id: &RequestId,
        res_storage: Vec<(CrsGenResult, S)>,
        min_agree_count: u32,
    ) -> anyhow::Result<CompactPkeCrs> {
        let mut verifying_pks = std::collections::HashSet::new();
        // counter of digest (digest -> usize)
        let mut hash_counter_map = HashMap::new();
        // map of digest -> public parameter
        let mut pp_map = HashMap::new();

        if !request_id.is_valid() {
            return Err(anyhow_error_and_log(format!(
                "The request id format is not valid {request_id}"
            )));
        }

        let res_len = res_storage.len();
        for (result, storage) in res_storage {
            let (pp_w_id, info) = if let Some(info) = result.crs_results {
                let pp: CompactPkeCrs = storage
                    .read_data(request_id, &PubDataType::CRS.to_string())
                    .await?;
                (pp, info)
            } else {
                tracing::warn!("empty SignedPubDataHandle");
                continue;
            };

            // check the result matches our request ID
            if request_id.as_str()
                != result
                    .request_id
                    .ok_or_else(|| anyhow_error_and_log("request ID missing"))?
                    .request_id
            {
                tracing::warn!("request ID mismatch; discarding the CRS");
                continue;
            }

            // check the digest
            let hex_digest = compute_handle(&pp_w_id)?;
            if info.key_handle != hex_digest {
                tracing::warn!("crs_handle does not match the computed digest; discarding the CRS");
                continue;
            }

            // check the signature
            match self.find_verifying_public_key(&DSEP_PUBDATA_CRS, &hex_digest, &info.signature) {
                Some(pk) => {
                    verifying_pks.insert(pk);
                }
                None => {
                    tracing::warn!("Signature could not be verified for a CRS");
                    // do not insert
                }
            }

            // put the result in a hash map so that we can check for majority
            match hash_counter_map.get_mut(&hex_digest) {
                Some(v) => {
                    *v += 1;
                }
                None => {
                    hash_counter_map.insert(hex_digest.clone(), 1usize);
                }
            }
            pp_map.insert(hex_digest, pp_w_id);
        }

        tracing::info!(
            "CRS map contains {} entries, should contain {} entries",
            pp_map.len(),
            res_len
        );
        // find the digest that has the most votes
        let (h, c) = hash_counter_map
            .into_iter()
            .max_by(|a, b| a.1.cmp(&b.1))
            .ok_or_else(|| anyhow_error_and_log("logic error: hash_counter_map is empty"))?;

        if c < min_agree_count as usize {
            return Err(anyhow_error_and_log(format!(
                "No consensus on CRS digest! {c} < {min_agree_count}"
            )));
        }

        if verifying_pks.len() < min_agree_count as usize {
            Err(anyhow_error_and_log(format!(
                "Not enough signatures on CRS results! {} < {}",
                verifying_pks.len(),
                min_agree_count
            )))
        } else {
            Ok(some_or_err(
                pp_map.remove(&h),
                "No public parameter found in the result map".to_string(),
            )?)
        }
    }

    /// Creates a decryption request to send to the KMS servers.
    ///
    /// The key_id should be the request ID of the key generation
    /// request that generated the key which should be used for public decryption
    #[cfg(feature = "non-wasm")]
    pub fn public_decryption_request(
        &mut self,
        ciphertexts: Vec<TypedCiphertext>,
        domain: &Eip712Domain,
        request_id: &RequestId,
        key_id: &RequestId,
    ) -> anyhow::Result<PublicDecryptionRequest> {
        if !request_id.is_valid() {
            return Err(anyhow_error_and_log(format!(
                "The request id format is not valid {request_id}"
            )));
        }

        let domain_msg = alloy_to_protobuf_domain(domain)?;

        let req = PublicDecryptionRequest {
            ciphertexts,
            key_id: Some((*key_id).into()),
            domain: Some(domain_msg),
            request_id: Some((*request_id).into()),
        };
        Ok(req)
    }

    /// Creates a user decryption request to send to the KMS servers. This generates
    /// an ephemeral user decryption key pair, signature payload containing the ciphertext,
    /// required number of shares, and other metadata. It signs this payload with
    /// the users's wallet private key. Returns the full [UserDecryptionRequest] containing
    /// the signed payload to send to the servers, along with the generated
    /// user decryption key pair.
    pub fn user_decryption_request(
        &mut self,
        domain: &Eip712Domain,
        typed_ciphertexts: Vec<TypedCiphertext>,
        request_id: &RequestId,
        key_id: &RequestId,
    ) -> anyhow::Result<(UserDecryptionRequest, PublicEncKey, PrivateEncKey)> {
        if !request_id.is_valid() {
            return Err(anyhow_error_and_log(format!(
                "The request id format is not valid {request_id}"
            )));
        }
        let _client_sk = some_or_err(
            self.client_sk.clone(),
            "missing client signing key".to_string(),
        )?;

        let domain_msg = alloy_to_protobuf_domain(domain)?;

        let (enc_pk, enc_sk) = ephemeral_encryption_key_generation(&mut self.rng);

        Ok((
            UserDecryptionRequest {
                request_id: Some((*request_id).into()),
                // The key is freshly generated, so we can safely unwrap the serialization
                enc_key: bc2wrap::serialize(&enc_pk)
                    .expect("Failed to serialize ephemeral encryption key"),
                client_address: self.client_address.to_checksum(None),
                typed_ciphertexts,
                key_id: Some((*key_id).into()),
                domain: Some(domain_msg),
            },
            enc_pk,
            enc_sk,
        ))
    }

    // NOTE: we're not checking it against the request
    // since this part of the client is only used for testing
    // see https://github.com/zama-ai/kms-core/issues/911
    #[cfg(feature = "non-wasm")]
    pub async fn process_get_key_gen_resp<R: StorageReader>(
        &self,
        resp: &KeyGenResult,
        storage: &R,
    ) -> anyhow::Result<(WrappedPublicKeyOwned, ServerKey)> {
        let pk = some_or_err(
            self.retrieve_public_key(resp, storage).await?,
            "Could not validate public key".to_string(),
        )?;
        let server_key: ServerKey = match self.retrieve_server_key(resp, storage).await? {
            Some(server_key) => server_key,
            None => {
                return Err(anyhow_error_and_log("Could not validate server key"));
            }
        };
        Ok((pk, server_key))
    }

    /// Retrieve and validate a server key based on the result from storage.
    /// The method will return the key if retrieval and validation is successful,
    /// but will return None in case the signature is invalid or does not match the actual key
    /// handle.
    #[cfg(feature = "non-wasm")]
    pub async fn retrieve_server_key<R: StorageReader>(
        &self,
        key_gen_result: &KeyGenResult,
        storage: &R,
    ) -> anyhow::Result<Option<ServerKey>> {
        if let Some(server_key) = self
            .retrieve_key(key_gen_result, PubDataType::ServerKey, storage)
            .await?
        {
            Ok(Some(server_key))
        } else {
            Ok(None)
        }
    }

    /// Retrieve and validate a public key based on the result from storage.
    /// The method will return the key if retrieval and validation is successful,
    /// but will return None in case the signature is invalid or does not match the actual key
    /// handle.
    #[cfg(feature = "non-wasm")]
    pub async fn retrieve_public_key<R: StorageReader>(
        &self,
        key_gen_result: &KeyGenResult,
        storage: &R,
    ) -> anyhow::Result<Option<WrappedPublicKeyOwned>> {
        // first we need to read the key type
        let request_id = some_or_err(
            key_gen_result.request_id.clone(),
            "No request id".to_string(),
        )?
        .into();
        tracing::debug!(
            "getting public key metadata using storage {} with request id {}",
            storage.info(),
            &request_id
        );
        let pk_type: PublicKeyType = crate::vault::storage::read_versioned_at_request_id(
            storage,
            &request_id,
            &PubDataType::PublicKeyMetadata.to_string(),
        )
        .await?;
        tracing::debug!(
            "getting wrapped public key using storage {} with request id {}",
            storage.info(),
            &request_id
        );
        let wrapped_pk = match pk_type {
            PublicKeyType::Compact => self
                .retrieve_key(key_gen_result, PubDataType::PublicKey, storage)
                .await?
                .map(WrappedPublicKeyOwned::Compact),
        };
        Ok(wrapped_pk)
    }

    /// Retrieve and validate a decompression key based on the result from storage.
    /// The method will return the key if retrieval and validation is successful,
    /// but will return None in case the signature is invalid or does not match the actual key
    /// handle.
    #[cfg(feature = "non-wasm")]
    pub async fn retrieve_decompression_key<R: StorageReader>(
        &self,
        key_gen_result: &KeyGenResult,
        storage: &R,
    ) -> anyhow::Result<Option<tfhe::integer::compression_keys::DecompressionKey>> {
        let decompression_key = self
            .retrieve_key(key_gen_result, PubDataType::DecompressionKey, storage)
            .await?;
        Ok(decompression_key)
    }

    #[cfg(feature = "non-wasm")]
    async fn retrieve_key<
        S: serde::de::DeserializeOwned
            + serde::Serialize
            + Versionize
            + Unversionize
            + tfhe::named::Named
            + Send,
        R: StorageReader,
    >(
        &self,
        key_gen_result: &KeyGenResult,
        key_type: PubDataType,
        storage: &R,
    ) -> anyhow::Result<Option<S>> {
        let pki = some_or_err(
            key_gen_result.key_results.get(&key_type.to_string()),
            format!("Could not find key of type {key_type}"),
        )?;
        let request_id = some_or_err(
            key_gen_result.request_id.clone(),
            "No request id".to_string(),
        )?;
        let key: S = self.get_key(&request_id.into(), key_type, storage).await?;
        let key_handle = compute_handle(&key)?;
        if key_handle != pki.key_handle {
            tracing::warn!(
                "Computed key handle {} of retrieved key does not match expected key handle {}",
                key_handle,
                pki.key_handle,
            );
            return Ok(None);
        }
        if self
            .verify_server_signature(&DSEP_PUBDATA_KEY, &key_handle, &pki.signature)
            .is_err()
        {
            tracing::warn!(
                "Could not verify server signature for key handle {}",
                key_handle,
            );
            return Ok(None);
        }
        Ok(Some(key))
    }

    /// Get a key from a public storage depending on the data type
    #[cfg(feature = "non-wasm")]
    async fn get_key<
        S: serde::de::DeserializeOwned + Unversionize + tfhe::named::Named + Send,
        R: StorageReader,
    >(
        &self,
        key_id: &RequestId,
        key_type: PubDataType,
        storage: &R,
    ) -> anyhow::Result<S> {
        storage.read_data(key_id, &key_type.to_string()).await
    }

    /// Retrieve and validate a CRS based on the result from a server.
    /// The method will return the CRS if retrieval and validation is successful,
    /// but will return None in case the signature is invalid or does not match the actual CRS
    /// handle.
    // NOTE: we're not checking it against the request
    // since this part of the client is only used for testing
    // see https://github.com/zama-ai/kms-core/issues/911
    #[cfg(feature = "non-wasm")]
    pub async fn process_get_crs_resp<R: StorageReader>(
        &self,
        crs_gen_result: &CrsGenResult,
        storage: &R,
    ) -> anyhow::Result<Option<CompactPkeCrs>> {
        let crs_info = some_or_err(
            crs_gen_result.crs_results.clone(),
            "Could not find CRS info".to_string(),
        )?;
        let request_id = some_or_err(
            crs_gen_result.request_id.clone(),
            "No request id".to_string(),
        )?;
        let pp = self.get_crs(&request_id.into(), storage).await?;
        let crs_handle = compute_handle(&pp)?;
        if crs_handle != crs_info.key_handle {
            tracing::warn!(
                "Computed crs handle {} of retrieved crs does not match expected crs handle {}",
                crs_handle,
                crs_info.key_handle,
            );
            return Ok(None);
        }
        if self
            .verify_server_signature(&DSEP_PUBDATA_CRS, &crs_handle, &crs_info.signature)
            .is_err()
        {
            tracing::warn!(
                "Could not verify server signature for crs handle {}",
                crs_handle,
            );
            return Ok(None);
        }
        Ok(Some(pp))
    }

    /// Get a CRS from a public storage
    #[cfg(feature = "non-wasm")]
    pub async fn get_crs<R: StorageReader>(
        &self,
        crs_id: &RequestId,
        storage: &R,
    ) -> anyhow::Result<CompactPkeCrs> {
        let pp: CompactPkeCrs = storage
            .read_data(crs_id, &PubDataType::CRS.to_string())
            .await?;
        Ok(pp)
    }

    /// Validates the aggregated decryption response `agg_resp` against the
    /// original `DecryptionRequest` `request`, and returns the decrypted
    /// plaintext if valid and at least [min_agree_count] agree on the result.
    /// Returns `None` if validation fails.
    ///
    /// __NOTE__: If the original request is not provided, we can __not__ check
    /// that the response correctly contains the digest of the request.
    #[cfg(feature = "non-wasm")]
    pub fn process_decryption_resp(
        &self,
        request: Option<PublicDecryptionRequest>,
        agg_resp: &[PublicDecryptionResponse],
        min_agree_count: u32,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        validate_public_decrypt_responses_against_request(
            self.get_server_pks()?,
            request,
            agg_resp,
            min_agree_count,
        )?;

        // TODO pivot should actually be picked as the most common response instead of just an
        // arbitrary one.
        let pivot = some_or_err(
            agg_resp.last(),
            "No elements in user decryption response".to_string(),
        )?;
        let pivot_payload = some_or_err(
            pivot.payload.to_owned(),
            "No payload in pivot response".to_string(),
        )?;
        for cur_resp in agg_resp {
            let cur_payload = some_or_err(
                cur_resp.payload.to_owned(),
                "No payload in current response!".to_string(),
            )?;
            let sig = Signature {
                sig: k256::ecdsa::Signature::from_slice(&cur_resp.signature)?,
            };
            // Observe that the values contained in the pivot has already been validated to be
            // correct
            // TODO I think this is redundant
            if cur_payload.digest != pivot_payload.digest
                || cur_payload.plaintexts != pivot_payload.plaintexts
            {
                return Err(anyhow_error_and_log(
                    "Some server did not provide the proper response!",
                ));
            }
            // Observe that it has already been verified in [self.validate_meta_data] that server
            // verification key is in the set of permissible keys
            let cur_verf_key: PublicSigKey = bc2wrap::deserialize(&cur_payload.verification_key)?;
            BaseKmsStruct::verify_sig(
                &DSEP_PUBLIC_DECRYPTION,
                &bc2wrap::serialize(&cur_payload)?,
                &sig,
                &cur_verf_key,
            )
            .inspect_err(|e| {
                tracing::warn!("Signature on received response is not valid! {}", e);
            })?;
        }
        let pts = some_or_err(
            pivot.payload.to_owned(),
            "No payload in pivot response for decryption".to_owned(),
        )?
        .plaintexts;

        Ok(pts)
    }

    /// Processes the aggregated user decryption responses to attempt to decrypt
    /// the encryption of the secret shared plaintext and returns this. Validates the
    /// response matches the request, checks signatures, and handles both
    /// centralized and distributed cases.
    ///
    /// If there is more than one response or more than one server identity,
    /// then the threshold mode is used.
    pub fn process_user_decryption_resp(
        &self,
        client_request: &ParsedUserDecryptionRequest,
        eip712_domain: &Eip712Domain,
        agg_resp: &[UserDecryptionResponse],
        enc_pk: &PublicEncKey,
        enc_sk: &PrivateEncKey,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        let client_keys = SigncryptionPair {
            sk: SigncryptionPrivKey {
                signing_key: self.client_sk.clone(),
                decryption_key: enc_sk.clone(),
            },
            pk: SigncryptionPubKey {
                client_address: self.client_address,
                enc_key: enc_pk.clone(),
            },
        };

        // The condition below decides whether we'll parse the response
        // in the centralized mode or threshold mode.
        //
        // It's important to check both the length of the server identities
        // and the number of responses at the start to avoid "falling back"
        // to the centralized mode by mistake since the checks that happen
        // in the centralized mode is weaker (there are no checks on the threshold).
        if agg_resp.len() <= 1 && self.server_identities.len() == 1 {
            // Execute simplified and faster flow for the centralized case
            // Observe that we don't encode exactly the same in the centralized case and in the
            // distributed case. For the centralized case we directly encode the [Plaintext]
            // object whereas for the distributed we encode the plain text as a
            // Vec<ResiduePolyF4Z128>.
            self.centralized_user_decryption_resp(
                client_request,
                eip712_domain,
                agg_resp,
                &client_keys,
            )
        } else {
            self.threshold_user_decryption_resp(
                client_request,
                eip712_domain,
                agg_resp,
                &client_keys,
            )
        }
    }

    /// Processes the aggregated user decryption response to attempt to decrypt
    /// the encryption of the secret shared plaintext and returns this.
    /// This function does *not* do any verification and is thus insecure and should be used only for testing.
    /// TODO hide behind flag for insecure function?
    pub fn insecure_process_user_decryption_resp(
        &self,
        agg_resp: &[UserDecryptionResponse],
        enc_pk: &PublicEncKey,
        enc_sk: &PrivateEncKey,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        let client_keys = SigncryptionPair {
            sk: SigncryptionPrivKey {
                signing_key: self.client_sk.clone(),
                decryption_key: enc_sk.clone(),
            },
            pk: SigncryptionPubKey {
                client_address: self.client_address,
                enc_key: enc_pk.clone(),
            },
        };

        // The same logic is used in `process_user_decryption_resp`.
        if agg_resp.len() <= 1 && self.server_identities.len() == 1 {
            self.insecure_centralized_user_decryption_resp(agg_resp, &client_keys)
        } else {
            self.insecure_threshold_user_decryption_resp(agg_resp, &client_keys)
        }
    }

    /// Decrypt the user decryption response from the centralized KMS and verify that the signatures are valid
    fn centralized_user_decryption_resp(
        &self,
        request: &ParsedUserDecryptionRequest,
        eip712_domain: &Eip712Domain,
        agg_resp: &[UserDecryptionResponse],
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        let resp = some_or_err(agg_resp.last(), "Response does not exist".to_owned())?;
        let payload = some_or_err(resp.payload.clone(), "Payload does not exist".to_owned())?;

        let link = compute_link(request, eip712_domain)?;
        if link != payload.digest {
            return Err(anyhow_error_and_log(format!(
                "link mismatch ({} != {}) for domain {:?}",
                hex::encode(&link),
                hex::encode(&payload.digest),
                eip712_domain,
            )));
        }

        let stored_server_addrs = &self.get_server_addrs();
        if stored_server_addrs.len() != 1 {
            return Err(anyhow_error_and_log("incorrect length for addresses"));
        }

        let cur_verf_key: PublicSigKey = bc2wrap::deserialize(&payload.verification_key)?;

        // NOTE: ID starts at 1
        let expected_server_addr = if let Some(server_addr) = stored_server_addrs.get(&1) {
            if *server_addr != alloy_signer::utils::public_key_to_address(cur_verf_key.pk()) {
                return Err(anyhow_error_and_log("server address is not consistent"));
            }
            server_addr
        } else {
            return Err(anyhow_error_and_log("missing server address at ID 1"));
        };

        // prefer the normal ECDSA verification over the EIP712 one
        if resp.signature.is_empty() {
            // we only consider the external signature in wasm
            let eip712_signature = &resp.external_signature;

            // check signature
            if eip712_signature.is_empty() {
                return Err(anyhow_error_and_log("empty signature"));
            }

            check_ext_user_decryption_signature(
                eip712_signature,
                &payload,
                request,
                eip712_domain,
                expected_server_addr,
            )
            .inspect_err(|e| {
                tracing::warn!("signature on received response is not valid ({})", e)
            })?;
        } else {
            let sig = Signature {
                sig: k256::ecdsa::Signature::from_slice(&resp.signature)?,
            };
            internal_verify_sig(
                &DSEP_USER_DECRYPTION,
                &bc2wrap::serialize(&payload)?,
                &sig,
                &cur_verf_key,
            )
            .inspect_err(|e| {
                tracing::warn!("signature on received response is not valid ({})", e)
            })?;
        }

        payload
            .signcrypted_ciphertexts
            .into_iter()
            .map(|ct| {
                decrypt_signcryption_with_link(
                    &DSEP_USER_DECRYPTION,
                    &ct.signcrypted_ciphertext,
                    &link,
                    client_keys,
                    &cur_verf_key,
                )
            })
            .collect()
    }

    /// Decrypt the user decryption response from the centralized KMS.
    /// This function does *not* do any verification and is thus insecure and should be used only for testing.
    /// TODO hide behind flag for insecure function?
    fn insecure_centralized_user_decryption_resp(
        &self,
        agg_resp: &[UserDecryptionResponse],
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        let resp = some_or_err(agg_resp.last(), "Response does not exist".to_owned())?;
        let payload = some_or_err(resp.payload.clone(), "Payload does not exist".to_owned())?;

        let mut out = vec![];
        for ct in payload.signcrypted_ciphertexts {
            out.push(
                crate::cryptography::signcryption::insecure_decrypt_ignoring_signature(
                    &ct.signcrypted_ciphertext,
                    client_keys,
                )?,
            )
        }
        Ok(out)
    }

    /// Decrypt the user decryption responses from the threshold KMS and verify that the signatures are valid
    fn threshold_user_decryption_resp(
        &self,
        client_request: &ParsedUserDecryptionRequest,
        eip712_domain: &Eip712Domain,
        agg_resp: &[UserDecryptionResponse],
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        let validated_resps = some_or_err(
            validate_user_decrypt_responses_against_request(
                &self.get_server_addrs(),
                client_request,
                eip712_domain,
                agg_resp,
            )?,
            "Could not validate request".to_owned(),
        )?;
        let degree = some_or_err(
            validated_resps.first(),
            "No valid responses parsed".to_string(),
        )?
        .degree as usize;

        let amount_shares = validated_resps.len();
        // TODO: in general this is not true, degree isn't a perfect proxy for num_parties
        let num_parties = 3 * degree + 1;
        if amount_shares > num_parties {
            return Err(anyhow_error_and_log(format!(
                    "Received more shares than expected for number of parties. n={num_parties}, #shares={amount_shares}"
                )));
        }

        let pbs_params = self
            .params
            .get_params_basics_handle()
            .to_classic_pbs_parameters();

        tracing::info!(
            "User decryption response reconstruction with mode: {:?}. deg={degree}, #shares={amount_shares}",
            self.decryption_mode
        );

        let res = match self.decryption_mode {
            DecryptionMode::BitDecSmall => {
                let all_sharings = self.recover_sharings::<Z64>(&validated_resps, client_keys)?;

                let mut out = vec![];
                for (fhe_type, packing_factor, sharings, recovery_errors) in all_sharings {
                    // we can tolerate at most t=degree errors in the recovered shares
                    if recovery_errors > degree {
                        return Err(anyhow_error_and_log(
                            format!("Too many errors in share recovery / signcryption: {recovery_errors} (threshold {degree})"),
                        ));
                    }
                    let mut decrypted_blocks = Vec::new();
                    for cur_block_shares in sharings {
                        // NOTE: this performs optimistic reconstruction
                        match reconstruct_w_errors_sync(
                            num_parties,
                            degree,
                            degree,
                            num_parties - amount_shares,
                            &cur_block_shares,
                        ) {
                            Ok(Some(r)) => decrypted_blocks.push(r),
                            Ok(None) => {
                                return Err(anyhow_error_and_log(
                                    format!("Not enough shares to reconstruct. n={num_parties}, deg={degree}, #shares={amount_shares}, block_shares={}, recovery_errors={recovery_errors}", &cur_block_shares.shares.len()),
                                ));
                            }
                            Err(e) => {
                                return Err(anyhow_error_and_log(format!(
                                    "Error reconstructing all blocks: {e}. n={num_parties}, deg={degree}, #shares={amount_shares}, block_shares={}, recovery_errors={recovery_errors}", &cur_block_shares.shares.len()
                                )));
                            }
                        }
                    }
                    // extract plaintexts from decrypted blocks
                    let mut ptxts64 = Vec::new();
                    for block in decrypted_blocks {
                        let scalar = block.to_scalar()?;
                        ptxts64.push(scalar);
                    }

                    // convert to Z128
                    out.push((
                        fhe_type,
                        packing_factor,
                        ptxts64
                            .iter()
                            .map(|ptxt| Wrapping(ptxt.0 as u128))
                            .collect_vec(),
                    ));
                }
                out
            }
            DecryptionMode::NoiseFloodSmall => {
                let all_sharings = self.recover_sharings::<Z128>(&validated_resps, client_keys)?;

                let mut out = vec![];
                for (fhe_type, packing_factor, sharings, recovery_errors) in all_sharings {
                    // we can tolerate at most t=degree errors in the recovered shares
                    if recovery_errors > degree {
                        return Err(anyhow_error_and_log(
                            format!("Too many errors in share recovery / signcryption: {recovery_errors} (threshold {degree})"),
                        ));
                    }

                    let mut decrypted_blocks = Vec::new();
                    for cur_block_shares in sharings {
                        // NOTE: this performs optimistic reconstruction
                        match reconstruct_w_errors_sync(
                            num_parties,
                            degree,
                            degree,
                            num_parties - amount_shares,
                            &cur_block_shares,
                        ) {
                            Ok(Some(r)) => decrypted_blocks.push(r),
                            Ok(None) => {
                                return Err(anyhow_error_and_log(
                                    format!("Not enough shares to reconstruct. n={num_parties}, deg={degree}, #shares={amount_shares}, block_shares={}, recovery_errors={recovery_errors}", &cur_block_shares.shares.len()),
                                ));
                            }
                            Err(e) => {
                                return Err(anyhow_error_and_log(format!(
                                    "Error reconstructing all blocks: {e}. n={num_parties}, deg={degree}, #shares={amount_shares}, block_shares={}, recovery_errors={recovery_errors}", &cur_block_shares.shares.len()
                                )));
                            }
                        }
                    }

                    out.push((
                        fhe_type,
                        packing_factor,
                        reconstruct_packed_message(
                            Some(decrypted_blocks),
                            &pbs_params,
                            fhe_types_to_num_blocks(
                                fhe_type,
                                &self
                                    .params
                                    .get_params_basics_handle()
                                    .to_classic_pbs_parameters(),
                            )?
                            .div_ceil(packing_factor as usize),
                        )?,
                    ));
                }
                out
            }
            e => {
                return Err(anyhow_error_and_log(format!(
                    "Unsupported decryption mode: {e}"
                )));
            }
        };

        let mut final_result = vec![];
        for (fhe_type, packing_factor, res) in res {
            final_result.push(decrypted_blocks_to_plaintext(
                &pbs_params,
                fhe_type,
                packing_factor,
                res,
            )?);
        }
        Ok(final_result)
    }

    fn insecure_threshold_user_decryption_resp(
        &self,
        agg_resp: &[UserDecryptionResponse],
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        match self.decryption_mode {
            DecryptionMode::BitDecSmall => {
                self.insecure_threshold_user_decryption_resp_z64(agg_resp, client_keys)
            }
            DecryptionMode::NoiseFloodSmall => {
                self.insecure_threshold_user_decryption_resp_z128(agg_resp, client_keys)
            }
            e => Err(anyhow_error_and_log(format!(
                "Unsupported decryption mode: {e}"
            ))),
        }
    }

    #[allow(clippy::type_complexity)]
    fn insecure_threshold_user_decryption_resp_to_blocks<Z: BaseRing>(
        agg_resp: &[UserDecryptionResponse],
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Vec<(FheTypes, u32, Vec<ResiduePolyF4<Z>>)>>
    where
        ResiduePolyF4<Z>: ErrorCorrect + MemoizedExceptionals,
    {
        let batch_count = agg_resp
            .first()
            .ok_or_else(|| anyhow::anyhow!("agg_resp is empty"))?
            .payload
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("payload is empty in user deryption response"))?
            .signcrypted_ciphertexts
            .len();

        let mut out = vec![];
        for batch_i in 0..batch_count {
            // Recover sharings
            let mut opt_sharings = None;
            let degree = some_or_err(
                some_or_err(agg_resp.first().as_ref(), "empty responses".to_owned())?
                    .payload
                    .as_ref(),
                "empty payload".to_owned(),
            )?
            .degree as usize;
            let fhe_type = agg_resp
                .first()
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("agg_resp is empty"))?
                .payload
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("payload is empty"))?
                .signcrypted_ciphertexts[batch_i]
                .fhe_type()?;
            let packing_factor = agg_resp
                .first()
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("agg_resp is empty"))?
                .payload
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("payload is empty"))?
                .signcrypted_ciphertexts[batch_i]
                .packing_factor;

            // Trust all responses have all expected blocks
            for cur_resp in agg_resp {
                let payload = some_or_err(
                    cur_resp.payload.clone(),
                    "Payload does not exist".to_owned(),
                )?;
                let shares = insecure_decrypt_ignoring_signature(
                    &payload.signcrypted_ciphertexts[batch_i].signcrypted_ciphertext,
                    client_keys,
                )?;

                let cipher_blocks_share: Vec<ResiduePolyF4<Z>> =
                    bc2wrap::deserialize(&shares.bytes)?;
                let mut cur_blocks = Vec::with_capacity(cipher_blocks_share.len());
                for cur_block_share in cipher_blocks_share {
                    cur_blocks.push(cur_block_share);
                }
                if opt_sharings.is_none() {
                    opt_sharings = Some(Vec::new());
                    for _i in 0..cur_blocks.len() {
                        (opt_sharings.as_mut()).unwrap().push(ShamirSharings::new());
                    }
                }
                let num_values = cur_blocks.len();
                fill_indexed_shares(
                    opt_sharings.as_mut().unwrap(),
                    cur_blocks,
                    num_values,
                    Role::indexed_from_one(payload.party_id as usize),
                )?;
            }
            let sharings = opt_sharings.unwrap();
            // TODO: in general this is not true, degree isn't a perfect proxy for num_parties
            let num_parties = 3 * degree + 1;
            let amount_shares = agg_resp.len();
            if amount_shares > num_parties {
                return Err(anyhow_error_and_log(format!(
                    "Received more shares than expected for number of parties. n={num_parties}, #shares={amount_shares}"
                )));
            }

            let mut decrypted_blocks = Vec::new();
            for cur_block_shares in sharings {
                // NOTE: this performs optimistic reconstruction
                match reconstruct_w_errors_sync(
                    num_parties,
                    degree,
                    degree,
                    num_parties - amount_shares,
                    &cur_block_shares,
                ) {
                    Ok(Some(r)) => decrypted_blocks.push(r),
                    Ok(None) => {
                        return Err(anyhow_error_and_log(
                                    format!("Not enough shares to reconstruct. n={num_parties}, deg={degree}, #shares={amount_shares}, block_shares={}", &cur_block_shares.shares.len()),
                                ));
                    }
                    Err(e) => {
                        return Err(anyhow_error_and_log(format!(
                                    "Error reconstructing all blocks: {e}. n={num_parties}, deg={degree}, #shares={amount_shares}, block_shares={}", &cur_block_shares.shares.len()
                                )));
                    }
                }
            }
            out.push((fhe_type, packing_factor, decrypted_blocks))
        }
        Ok(out)
    }

    fn insecure_threshold_user_decryption_resp_z128(
        &self,
        agg_resp: &[UserDecryptionResponse],
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        let all_decrypted_blocks =
            Self::insecure_threshold_user_decryption_resp_to_blocks::<Z128>(agg_resp, client_keys)?;

        let mut out = vec![];
        for (fhe_type, packing_factor, decrypted_blocks) in all_decrypted_blocks {
            let pbs_params = self
                .params
                .get_params_basics_handle()
                .to_classic_pbs_parameters();

            let recon_blocks = reconstruct_packed_message(
                Some(decrypted_blocks),
                &pbs_params,
                fhe_types_to_num_blocks(
                    fhe_type,
                    &self
                        .params
                        .get_params_basics_handle()
                        .to_classic_pbs_parameters(),
                )?
                .div_ceil(packing_factor as usize),
            )?;

            out.push(decrypted_blocks_to_plaintext(
                &pbs_params,
                fhe_type,
                packing_factor,
                recon_blocks,
            )?);
        }
        Ok(out)
    }

    /// Decrypt the user decryption response from the threshold KMS.
    /// This function does *not* do any verification and is thus insecure and should be used only for testing.
    /// TODO hide behind flag for insecure function?
    fn insecure_threshold_user_decryption_resp_z64(
        &self,
        agg_resp: &[UserDecryptionResponse],
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        let all_decrypted_blocks =
            Self::insecure_threshold_user_decryption_resp_to_blocks::<Z64>(agg_resp, client_keys)?;

        let mut out = vec![];
        for (fhe_type, packing_factor, decrypted_blocks) in all_decrypted_blocks {
            let pbs_params = self
                .params
                .get_params_basics_handle()
                .to_classic_pbs_parameters();

            let mut ptxts64 = Vec::new();

            for opened in decrypted_blocks {
                let v_scalar = opened.to_scalar()?;
                ptxts64.push(v_scalar);
            }

            let ptxts128: Vec<_> = ptxts64
                .iter()
                .map(|ptxt| Wrapping(ptxt.0 as u128))
                .collect();

            out.push(decrypted_blocks_to_plaintext(
                &pbs_params,
                fhe_type,
                packing_factor,
                ptxts128,
            )?);
        }
        Ok(out)
    }

    /// Decrypts the user decryption responses and decodes the responses onto the Shamir shares
    /// that the servers should have encrypted.
    #[allow(clippy::type_complexity)]
    fn recover_sharings<Z: BaseRing>(
        &self,
        agg_resp: &[UserDecryptionResponsePayload],
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Vec<(FheTypes, u32, Vec<ShamirSharings<ResiduePolyF4<Z>>>, usize)>> {
        let batch_count = agg_resp
            .first()
            .ok_or_else(|| anyhow::anyhow!("response payloads is empty"))?
            .signcrypted_ciphertexts
            .len();

        let mut out = vec![];
        for batch_i in 0..batch_count {
            // taking agg_resp[0] is safe since batch_count before exists
            let fhe_type = agg_resp[0].signcrypted_ciphertexts[batch_i].fhe_type()?;
            let num_blocks = fhe_types_to_num_blocks(
                fhe_type,
                &self
                    .params
                    .get_params_basics_handle()
                    .to_classic_pbs_parameters(),
            )?;
            let mut sharings = Vec::new();
            for _i in 0..num_blocks {
                sharings.push(ShamirSharings::new());
            }
            // It is ok to use the first packing factor because this is checked by [self.validate_user_decrypt_responses_against_request]
            let packing_factor = agg_resp[0].signcrypted_ciphertexts[batch_i].packing_factor;
            // the number of recovery errors in this block (e.g. due to failed signcryption)
            let mut recovery_errors = 0;
            for cur_resp in agg_resp {
                // Observe that it has already been verified in [validate_meta_data] that server
                // verification key is in the set of permissible keys
                //
                // Also it's ok to use [cur_resp.digest] as the link since we already checked
                // that it matches with the original request
                let cur_verf_key: PublicSigKey = bc2wrap::deserialize(&cur_resp.verification_key)?;
                match decrypt_signcryption_with_link(
                    &DSEP_USER_DECRYPTION,
                    &cur_resp.signcrypted_ciphertexts[batch_i].signcrypted_ciphertext,
                    &cur_resp.digest,
                    client_keys,
                    &cur_verf_key,
                ) {
                    Ok(decryption_share) => {
                        let cipher_blocks_share: Vec<ResiduePolyF4<Z>> =
                            bc2wrap::deserialize(&decryption_share.bytes)?;
                        let mut cur_blocks = Vec::with_capacity(cipher_blocks_share.len());
                        for cur_block_share in cipher_blocks_share {
                            cur_blocks.push(cur_block_share);
                        }
                        fill_indexed_shares(
                            &mut sharings,
                            cur_blocks,
                            num_blocks,
                            Role::indexed_from_one(cur_resp.party_id as usize),
                        )?;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Could not decrypt or validate signcrypted response from party {}: {}",
                            cur_resp.party_id,
                            e
                        );
                        recovery_errors += 1;
                    }
                };
            }
            out.push((fhe_type, packing_factor, sharings, recovery_errors));
        }
        Ok(out)
    }

    pub fn get_server_pks(&self) -> anyhow::Result<&HashMap<u32, PublicSigKey>> {
        match &self.server_identities {
            ServerIdentities::Pks(inner) => Ok(inner),
            ServerIdentities::Addrs(_) => {
                Err(anyhow::anyhow!("expected public keys, got addresses"))
            }
        }
    }

    pub fn get_server_addrs(&self) -> HashMap<u32, alloy_primitives::Address> {
        match &self.server_identities {
            ServerIdentities::Pks(pks) => pks
                .iter()
                .map(|(i, pk)| (*i, alloy_signer::utils::public_key_to_address(pk.pk())))
                .collect(),
            ServerIdentities::Addrs(inner) => inner.clone(),
        }
    }

    pub fn get_client_address(&self) -> alloy_primitives::Address {
        self.client_address
    }
}

/// Wait for a server to be ready for requests. I.e. wait until it enters the SERVING state.
/// Note that this method may panic if the server does not become ready within a certain time frame.
#[cfg(feature = "non-wasm")]
pub async fn await_server_ready(service_name: &str, port: u16) {
    let mut wrapped_client = get_health_client(port).await;
    let mut client_tries = 1;
    while wrapped_client.is_err() {
        if client_tries >= MAX_TRIES {
            panic!("Failed to start health client on server {service_name} on port {port}");
        }
        wrapped_client = get_health_client(port).await;
        client_tries += 1;
    }
    // We can safely unwrap here since we know the wrapped client does not contain an error
    let mut client = wrapped_client.unwrap();
    let mut status = get_status(&mut client, service_name).await;
    let mut service_tries = 1;
    while status.is_err()
        || status
            .clone()
            .is_ok_and(|status| status == ServingStatus::NotServing as i32)
    {
        if service_tries >= MAX_TRIES {
            panic!(
                "Failed to get health status on {service_name} on port {port}. Status: {status:?}"
            );
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        status = get_status(&mut client, service_name).await;
        service_tries += 1;
    }
}

#[cfg(feature = "non-wasm")]
async fn get_health_client(port: u16) -> anyhow::Result<HealthClient<Channel>> {
    let server_address = &format!("{DEFAULT_PROTOCOL}://{DEFAULT_URL}:{port}");
    let channel_builder = Channel::from_shared(server_address.to_string())?;
    let channel = channel_builder.connect().await?;
    Ok(HealthClient::new(channel))
}

#[cfg(feature = "non-wasm")]
async fn get_status(
    health_client: &mut HealthClient<Channel>,
    service_name: &str,
) -> Result<i32, tonic::Status> {
    let request = tonic::Request::new(HealthCheckRequest {
        service: service_name.to_string(),
    });
    let response = health_client.check(request).await?;
    Ok(response.into_inner().status)
}

// TODO this module should be behind cfg(test) normally
// but we need it in other places such as the connector
// and cfg(test) is not compiled by tests in other crates.
// Consider putting this behind a test-specific crate.
#[cfg(any(test, feature = "testing"))]
#[cfg(feature = "non-wasm")]
pub mod test_tools {
    use super::*;
    use crate::consts::{DEC_CAPACITY, DEFAULT_PROTOCOL, DEFAULT_URL, MAX_TRIES, MIN_DEC_CACHE};
    use crate::engine::centralized::central_kms::RealCentralizedKms;
    use crate::engine::threshold::service::new_real_threshold_kms;
    use crate::engine::{run_server, Shutdown};
    use crate::util::key_setup::test_tools::setup::ensure_testing_material_exists;
    use crate::util::rate_limiter::RateLimiterConfig;
    use crate::vault::storage::{
        crypto_material::get_core_signing_key, file::FileStorage, Storage, StorageType,
    };
    use crate::{
        conf::{
            threshold::{PeerConf, ThresholdPartyConf},
            ServiceEndpoint,
        },
        util::random_free_port::get_listeners_random_free_ports,
    };
    use futures_util::FutureExt;
    use itertools::Itertools;
    use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
    use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer;
    use std::str::FromStr;
    use std::sync::Arc;
    use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
    use threshold_fhe::networking::grpc::GrpcServer;
    use tonic::server::NamedService;
    use tonic::transport::{Channel, Uri};

    #[cfg(feature = "slow_tests")]
    use crate::util::key_setup::test_tools::setup::ensure_default_material_exists;

    // Put gRPC size limit to 100 MB.
    // We need a high limit because ciphertexts may be large after SnS.
    const GRPC_MAX_MESSAGE_SIZE: usize = 100 * 1024 * 1024;

    pub async fn setup_threshold_no_client<
        PubS: Storage + Clone + Sync + Send + 'static,
        PrivS: Storage + Clone + Sync + Send + 'static,
    >(
        threshold: u8,
        pub_storage: Vec<PubS>,
        priv_storage: Vec<PrivS>,
        run_prss: bool,
        rate_limiter_conf: Option<RateLimiterConfig>,
        decryption_mode: Option<DecryptionMode>,
    ) -> HashMap<u32, ServerHandle> {
        ensure_testing_material_exists().await;
        #[cfg(feature = "slow_tests")]
        ensure_default_material_exists().await;

        let mut handles = Vec::new();
        tracing::info!("Spawning servers...");
        let num_parties = priv_storage.len();
        let ip_addr = DEFAULT_URL.parse().unwrap();
        let service_listeners = get_listeners_random_free_ports(&ip_addr, num_parties)
            .await
            .unwrap();
        let mpc_listeners = get_listeners_random_free_ports(&ip_addr, num_parties)
            .await
            .unwrap();

        let service_ports = service_listeners
            .iter()
            .map(|listener_and_port| listener_and_port.1)
            .collect_vec();
        let mpc_ports = mpc_listeners
            .iter()
            .map(|listener_and_port| listener_and_port.1)
            .collect_vec();

        tracing::info!("service ports: {:?}", service_ports);
        tracing::info!("MPC ports: {:?}", mpc_ports);
        let mpc_confs = mpc_ports
            .into_iter()
            .enumerate()
            .map(|(i, port)| PeerConf {
                party_id: i + 1,
                address: ip_addr.to_string(),
                port,
                tls_cert: None,
            })
            .collect_vec();

        // use NoiseFloodSmall unless some other DecryptionMode was set as parameter
        let decryption_mode = decryption_mode.unwrap_or_default();

        // a vector of sender that will trigger shutdown of core/threshold servers
        let mut mpc_shutdown_txs = Vec::new();

        for (i, (mpc_listener, _mpc_port)) in (1..=num_parties).zip_eq(mpc_listeners.into_iter()) {
            let cur_pub_storage = pub_storage[i - 1].to_owned();
            let cur_priv_storage = priv_storage[i - 1].to_owned();
            let service_config = ServiceEndpoint {
                listen_address: ip_addr.to_string(),
                listen_port: service_ports[i - 1],
                timeout_secs: 60u64,
                grpc_max_message_size: GRPC_MAX_MESSAGE_SIZE,
            };
            let mpc_conf = mpc_confs.clone();

            // create channels that will trigger core/threshold shutdown
            let (mpc_core_tx, mpc_core_rx): (
                tokio::sync::oneshot::Sender<()>,
                tokio::sync::oneshot::Receiver<()>,
            ) = tokio::sync::oneshot::channel();
            mpc_shutdown_txs.push(mpc_core_tx);
            let rl_conf = rate_limiter_conf.clone();
            handles.push(tokio::spawn(async move {
                let threshold_party_config = ThresholdPartyConf {
                    listen_address: mpc_conf[i - 1].address.clone(),
                    listen_port: mpc_conf[i - 1].port,
                    threshold,
                    dec_capacity: DEC_CAPACITY,
                    min_dec_cache: MIN_DEC_CACHE,
                    my_id: i,
                    preproc_redis: None,
                    num_sessions_preproc: None,
                    tls: None,
                    peers: mpc_conf,
                    core_to_core_net: None,
                    decryption_mode,
                };
                let sk = get_core_signing_key(&cur_priv_storage).await.unwrap();
                // TODO pass in cert_paths for testing TLS
                let server = new_real_threshold_kms(
                    threshold_party_config,
                    cur_pub_storage,
                    cur_priv_storage,
                    None as Option<PrivS>,
                    mpc_listener,
                    sk,
                    None,
                    run_prss,
                    rl_conf,
                    mpc_core_rx.map(drop),
                )
                .await;
                (i, server, service_config)
            }));
        }
        assert_eq!(handles.len(), num_parties);
        // Wait for the server to start
        tracing::info!("Client waiting for server");
        let mut servers = Vec::with_capacity(num_parties);
        for cur_handle in handles {
            let (i, kms_server_res, service_config) =
                cur_handle.await.expect("Server {i} failed to start");
            match kms_server_res {
                Ok((kms_server, health_service)) => {
                    servers.push((i, kms_server, service_config, health_service))
                }
                Err(e) => panic!("Failed to start server {i} with error {e:?}"),
            }
        }
        tracing::info!("Servers initialized. Starting servers...");
        let mut server_handles = HashMap::new();
        for (
            ((i, cur_server, service_config, cur_health_service), cur_mpc_shutdown),
            (service_listener, _service_port),
        ) in servers
            .into_iter()
            .zip_eq(mpc_shutdown_txs)
            .zip_eq(service_listeners.into_iter())
        {
            let cur_arc_server = Arc::new(cur_server);
            let arc_server_clone = Arc::clone(&cur_arc_server);
            let (server_shutdown_tx, server_shutdown_rx) = tokio::sync::oneshot::channel::<()>();
            tokio::spawn(async move {
                run_server(
                    service_config,
                    service_listener,
                    cur_arc_server,
                    cur_health_service,
                    server_shutdown_rx.map(drop),
                )
                .await
                .expect("Failed to start threshold server");
            });
            server_handles.insert(
                i as u32,
                ServerHandle::new_threshold(
                    arc_server_clone,
                    service_ports[i - 1],
                    mpc_confs[i - 1].port,
                    server_shutdown_tx,
                    cur_mpc_shutdown,
                ),
            );
            // Wait until MPC server is ready, this should happen as soon as the MPC server boots up
            let threshold_service_name = <GrpcServer as NamedService>::NAME;
            await_server_ready(threshold_service_name, mpc_confs[i - 1].port).await;
            // Observe that we don't check that the core server is ready here. The reason is that it depends on whether PRSS has been executed or loaded from disc.
            // Thus if requests are send to the core without PRSS being executed, then a failure will happen.
        }
        server_handles
    }

    /// try to connect to a URI and retry every 200ms for 50 times before giving up after 5 seconds.
    pub async fn connect_with_retry(uri: Uri) -> Channel {
        tracing::info!("Client connecting to {}", uri);
        let mut channel = Channel::builder(uri.clone()).connect().await;
        let mut tries = 0usize;
        loop {
            match channel {
                Ok(_) => {
                    break;
                }
                Err(_) => {
                    tracing::info!("Retrying: Client connection to {}", uri);
                    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
                    channel = Channel::builder(uri.clone()).connect().await;
                    tries += 1;
                    if tries > MAX_TRIES {
                        break;
                    }
                }
            }
        }
        match channel {
            Ok(channel) => {
                tracing::info!("Client connected to {}", uri);
                channel
            }
            Err(e) => {
                tracing::error!("Client unable to connect to {}: Error {:?}", uri, e);
                panic!("Client unable to connect to {uri}: Error {e:?}")
            }
        }
    }

    pub(crate) async fn check_port_is_closed(port: u16) {
        let addr = std::net::SocketAddr::new(
            DEFAULT_URL.parse().expect("Default URL cannot be parsed"),
            port,
        );
        // try for 10 seconds to wait for the ports to close
        for _ in 0..10 {
            let res = tokio::net::TcpListener::bind(addr).await;
            match res {
                Ok(listener) => {
                    drop(listener);
                    // port is closed if we can bind again
                    break;
                }
                Err(_) => {
                    tracing::warn!("port {} is still not closed, retrying", addr);
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
        }
    }

    /// Helper struct for managing servers in testing
    pub struct ServerHandle {
        pub server: Arc<dyn Shutdown>,
        // The service port is the port that is used to connect to the core server
        pub service_port: u16,
        // In the threshold setting the mpc port is the port that is used to connect to the other MPC parties
        pub mpc_port: Option<u16>,
        // The handle to shut down the core service which is receiving the external requests
        pub service_shutdown_tx: tokio::sync::oneshot::Sender<()>,
        // The handle to shut down the optional MPC server
        pub mpc_shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    }

    impl ServerHandle {
        pub fn new_threshold(
            server: Arc<dyn Shutdown>,
            service_port: u16,
            mpc_port: u16,
            service_shutdown_tx: tokio::sync::oneshot::Sender<()>,
            mpc_shutdown_tx: tokio::sync::oneshot::Sender<()>,
        ) -> Self {
            Self {
                server,
                service_port,
                mpc_port: Some(mpc_port),
                service_shutdown_tx,
                mpc_shutdown_tx: Some(mpc_shutdown_tx),
            }
        }

        pub fn new_centralized(
            server: Arc<dyn Shutdown>,
            service_port: u16,
            service_shutdown_tx: tokio::sync::oneshot::Sender<()>,
        ) -> Self {
            Self {
                server,
                service_port,
                mpc_port: None,
                service_shutdown_tx,
                mpc_shutdown_tx: None,
            }
        }

        pub fn service_port(&self) -> u16 {
            self.service_port
        }

        pub fn mpc_port(&self) -> Option<u16> {
            self.mpc_port
        }

        pub async fn assert_shutdown(self) {
            // Call shutdown so we can await the server to shut down even though sending the shutdown signal already calls this
            self.server
                .shutdown()
                .await
                .expect("Failed to await core service server shutdown");
            // Shut down the core server
            // The receiver should not be closed, that's why we unwrap
            self.service_shutdown_tx
                .send(())
                .expect("Could not send shut down signal to  core server");

            if let Some(chan) = self.mpc_shutdown_tx {
                // Shut down MPC server
                chan.send(())
                    .expect("Could not send shut down signal to the MPC server");
            }

            // Validate that both the MPC and server are fully closed
            check_port_is_closed(self.service_port).await;
            if let Some(mpc_port) = self.mpc_port {
                check_port_is_closed(mpc_port).await;
            }
        }
    }

    pub async fn setup_threshold<
        PubS: Storage + Clone + Sync + Send + 'static,
        PrivS: Storage + Clone + Sync + Send + 'static,
    >(
        threshold: u8,
        pub_storage: Vec<PubS>,
        priv_storage: Vec<PrivS>,
        run_prss: bool,
        rate_limiter_conf: Option<RateLimiterConfig>,
        decryption_mode: Option<DecryptionMode>,
    ) -> (
        HashMap<u32, ServerHandle>,
        HashMap<u32, CoreServiceEndpointClient<Channel>>,
    ) {
        let num_parties = priv_storage.len();
        // Setup the threshold scheme with lazy PRSS generation
        let server_handles = setup_threshold_no_client::<PubS, PrivS>(
            threshold,
            pub_storage,
            priv_storage,
            run_prss,
            rate_limiter_conf,
            decryption_mode,
        )
        .await;
        assert_eq!(server_handles.len(), num_parties);
        let mut client_handles = HashMap::new();

        for (i, server_handle) in &server_handles {
            let url = format!(
                "{DEFAULT_PROTOCOL}://{DEFAULT_URL}:{}",
                server_handle.service_port()
            );
            let uri = Uri::from_str(&url).unwrap();
            let channel = connect_with_retry(uri).await;
            client_handles.insert(*i, CoreServiceEndpointClient::new(channel));
        }
        tracing::info!("Client connected to servers");
        (server_handles, client_handles)
    }

    /// Setup a client and a server running with non-persistent storage.
    pub async fn setup_centralized_no_client<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
    >(
        pub_storage: PubS,
        priv_storage: PrivS,
        rate_limiter_conf: Option<RateLimiterConfig>,
    ) -> ServerHandle {
        ensure_testing_material_exists().await;
        #[cfg(feature = "slow_tests")]
        ensure_default_material_exists().await;

        let ip_addr = DEFAULT_URL.parse().unwrap();
        // we use port numbers above 40001 so that it's easy to identify
        // which cores are running in the centralized mode from the logs
        let (listener, listen_port) = get_listeners_random_free_ports(&ip_addr, 1)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let sk = get_core_signing_key(&priv_storage).await.unwrap();
        let (kms, health_service) = RealCentralizedKms::new(
            pub_storage,
            priv_storage,
            None as Option<PrivS>,
            sk,
            rate_limiter_conf,
        )
        .await
        .expect("Could not create KMS");
        let arc_kms = Arc::new(kms);
        let arc_kms_clone = Arc::clone(&arc_kms);
        tokio::spawn(async move {
            let config = ServiceEndpoint {
                listen_address: ip_addr.to_string(),
                listen_port,
                timeout_secs: 360,
                grpc_max_message_size: GRPC_MAX_MESSAGE_SIZE,
            };

            run_server(config, listener, arc_kms, health_service, rx.map(drop))
                .await
                .expect("Could not start server");
        });
        let service_name = <CoreServiceEndpointServer<
            RealCentralizedKms<FileStorage, FileStorage, FileStorage>,
        > as NamedService>::NAME;
        await_server_ready(service_name, listen_port).await;
        ServerHandle::new_centralized(arc_kms_clone, listen_port, tx)
    }

    pub(crate) async fn setup_centralized<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
    >(
        pub_storage: PubS,
        priv_storage: PrivS,
        rate_limiter_conf: Option<RateLimiterConfig>,
    ) -> (
        ServerHandle,
        CoreServiceEndpointClient<tonic::transport::Channel>,
    ) {
        let server_handle =
            setup_centralized_no_client(pub_storage, priv_storage, rate_limiter_conf).await;
        let url = format!(
            "{DEFAULT_PROTOCOL}://{DEFAULT_URL}:{}",
            server_handle.service_port
        );
        let uri = Uri::from_str(&url).unwrap();
        let channel = connect_with_retry(uri).await;
        let client = CoreServiceEndpointClient::new(channel);
        (server_handle, client)
    }

    /// Read the centralized keys for testing from `centralized_key_path` and construct a KMS
    /// server, client end-point connection (which is needed to communicate with the server) and
    /// an internal client (for constructing requests and validating responses).
    pub async fn centralized_handles(
        param: &DKGParams,
        rate_limiter_conf: Option<RateLimiterConfig>,
    ) -> (ServerHandle, CoreServiceEndpointClient<Channel>, Client) {
        let priv_storage = FileStorage::new(None, StorageType::PRIV, None).unwrap();
        let pub_storage = FileStorage::new(None, StorageType::PUB, None).unwrap();
        let (kms_server, kms_client) =
            setup_centralized(pub_storage, priv_storage, rate_limiter_conf).await;
        let pub_storage =
            HashMap::from_iter([(1, FileStorage::new(None, StorageType::PUB, None).unwrap())]);
        let client_storage = FileStorage::new(None, StorageType::CLIENT, None).unwrap();
        let internal_client = Client::new_client(client_storage, pub_storage, param, None)
            .await
            .unwrap();
        (kms_server, kms_client, internal_client)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::test_tools::ServerHandle;
    use super::Client;
    use crate::client::test_tools::check_port_is_closed;
    #[cfg(feature = "wasm_tests")]
    use crate::client::TestingUserDecryptionTranscript;
    use crate::client::{await_server_ready, get_health_client, get_status};
    use crate::client::{ParsedUserDecryptionRequest, ServerIdentities};
    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    use crate::consts::MAX_TRIES;
    use crate::consts::TEST_THRESHOLD_KEY_ID_4P;
    use crate::consts::{DEFAULT_AMOUNT_PARTIES, TEST_CENTRAL_KEY_ID};
    #[cfg(feature = "slow_tests")]
    use crate::consts::{DEFAULT_CENTRAL_KEY_ID, DEFAULT_THRESHOLD_KEY_ID_4P};
    use crate::consts::{DEFAULT_THRESHOLD, TEST_THRESHOLD_KEY_ID_10P};
    use crate::consts::{PRSS_INIT_REQ_ID, TEST_PARAM, TEST_THRESHOLD_KEY_ID};
    use crate::cryptography::internal_crypto_types::WrappedDKGParams;
    use crate::cryptography::internal_crypto_types::{
        PrivateEncKey, PrivateSigKey, PublicEncKey, Signature,
    };
    use crate::engine::base::{compute_handle, derive_request_id, BaseKmsStruct, DSEP_PUBDATA_CRS};
    #[cfg(feature = "slow_tests")]
    use crate::engine::centralized::central_kms::tests::get_default_keys;
    use crate::engine::centralized::central_kms::RealCentralizedKms;
    use crate::engine::threshold::service::RealThresholdKms;
    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    use crate::engine::threshold::service::ThresholdFheKeys;
    use crate::engine::traits::BaseKms;
    use crate::engine::validation::DSEP_USER_DECRYPTION;
    #[cfg(feature = "wasm_tests")]
    use crate::util::file_handling::write_element;
    use crate::util::key_setup::max_threshold;
    use crate::util::key_setup::test_tools::{
        compute_cipher_from_stored_key, purge, EncryptionConfig, TestingPlaintext,
    };
    use crate::util::rate_limiter::RateLimiterConfig;
    use crate::vault::storage::crypto_material::get_core_signing_key;
    use crate::vault::storage::StorageReader;
    use crate::vault::storage::{file::FileStorage, StorageType};
    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    use kms_grpc::kms::v1::CrsGenRequest;
    use kms_grpc::kms::v1::{
        Empty, FheParameter, InitRequest, KeySetAddedInfo, KeySetConfig, KeySetType,
        TypedCiphertext, TypedPlaintext, UserDecryptionRequest, UserDecryptionResponse,
    };
    use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
    use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer;
    use kms_grpc::rpc_types::{fhe_types_to_num_blocks, PrivDataType};
    use kms_grpc::rpc_types::{protobuf_to_alloy_domain, PubDataType};
    use kms_grpc::RequestId;
    use serial_test::serial;
    use std::collections::{hash_map::Entry, HashMap};
    use std::str::FromStr;
    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    use std::sync::Arc;
    use tfhe::core_crypto::prelude::{ContiguousEntityContainer, LweCiphertextOwned};
    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    use tfhe::integer::compression_keys::DecompressionKey;
    use tfhe::prelude::ParameterSetConformant;
    use tfhe::zk::CompactPkeCrs;
    use tfhe::Tag;
    use tfhe::{FheTypes, ProvenCompactCiphertextList};
    use threshold_fhe::execution::endpoints::decryption::DecryptionMode;
    use threshold_fhe::execution::runtime::party::Role;
    use threshold_fhe::execution::tfhe_internals::parameters::DKGParams;
    #[cfg(feature = "wasm_tests")]
    use threshold_fhe::execution::tfhe_internals::parameters::PARAMS_TEST_BK_SNS;
    use threshold_fhe::execution::tfhe_internals::test_feature::run_decompression_test;
    use threshold_fhe::networking::grpc::GrpcServer;
    use tokio::task::JoinSet;
    use tonic::server::NamedService;
    use tonic::transport::Channel;
    use tonic_health::pb::health_check_response::ServingStatus;
    use tonic_health::pb::HealthCheckRequest;

    #[cfg(feature = "slow_tests")]
    mod nightly_tests;

    // Time to sleep to ensure that previous servers and tests have shut down properly.
    const TIME_TO_SLEEP_MS: u64 = 500;

    fn dummy_domain() -> alloy_sol_types::Eip712Domain {
        alloy_sol_types::eip712_domain!(
            name: "Authorization token",
            version: "1",
            chain_id: 8006,
            verifying_contract: alloy_primitives::address!("66f9664f97F2b50F62D13eA064982f936dE76657"),
        )
    }

    /// Reads the testing keys for the threshold servers and starts them up, and returns a hash map
    /// of the servers, based on their ID, which starts from 1. A similar map is also returned
    /// is the client endpoints needed to talk with each of the servers, finally the internal
    /// client is returned (which is responsible for constructing requests and validating
    /// responses).
    async fn threshold_handles(
        params: DKGParams,
        amount_parties: usize,
        run_prss: bool,
        rate_limiter_conf: Option<RateLimiterConfig>,
        decryption_mode: Option<DecryptionMode>,
    ) -> (
        HashMap<u32, ServerHandle>,
        HashMap<u32, CoreServiceEndpointClient<Channel>>,
        Client,
    ) {
        // Compute threshold < amount_parties/3
        let threshold = max_threshold(amount_parties);
        let mut pub_storage = Vec::new();
        let mut priv_storage = Vec::new();
        for i in 1..=amount_parties {
            priv_storage.push(
                FileStorage::new(None, StorageType::PRIV, Some(Role::indexed_from_one(i))).unwrap(),
            );
            pub_storage.push(
                FileStorage::new(None, StorageType::PUB, Some(Role::indexed_from_one(i))).unwrap(),
            );
        }
        let (kms_servers, kms_clients) = super::test_tools::setup_threshold(
            threshold as u8,
            pub_storage,
            priv_storage,
            run_prss,
            rate_limiter_conf,
            decryption_mode,
        )
        .await;
        let mut pub_storage = HashMap::with_capacity(amount_parties);
        for i in 1..=amount_parties {
            pub_storage.insert(
                i as u32,
                FileStorage::new(None, StorageType::PUB, Some(Role::indexed_from_one(i))).unwrap(),
            );
        }
        let client_storage = FileStorage::new(None, StorageType::CLIENT, None).unwrap();
        let internal_client =
            Client::new_client(client_storage, pub_storage, &params, decryption_mode)
                .await
                .unwrap();
        (kms_servers, kms_clients, internal_client)
    }

    /// Check that the centralized health service is serving as soons as boot is completed.
    #[tokio::test]
    #[serial]
    async fn test_central_health_endpoint_availability() {
        let (kms_server, _kms_client, _internal_client) =
            super::test_tools::centralized_handles(&TEST_PARAM, None).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
        let mut health_client = get_health_client(kms_server.service_port)
            .await
            .expect("Failed to get health client");
        let service_name = <CoreServiceEndpointServer<
            RealCentralizedKms<FileStorage, FileStorage, FileStorage>,
        > as NamedService>::NAME;
        let request = tonic::Request::new(HealthCheckRequest {
            service: service_name.to_string(),
        });

        let response = health_client
            .check(request)
            .await
            .expect("Health check request failed");

        let status = response.into_inner().status;
        assert_eq!(
            status,
            ServingStatus::Serving as i32,
            "Service is not in SERVING status. Got status: {status}"
        );
    }

    /// Test that the health endpoint is available for the threshold service only *after* they have been initialized.
    /// Also check that shutdown of the servers triggers the health endpoint to stop serving as expected.
    /// This tests validates the availability of both the core service but also the internal service between the MPC parties.
    ///
    /// The crux of the test is based on the fact that the MPC servers serve immidiately but the core server only serves after
    /// the PRSS initialization has been completed.
    #[tokio::test]
    #[serial]
    async fn test_threshold_health_endpoint_availability() {
        // make sure the store does not contain any PRSS info (currently stored under ID PRSS_INIT_REQ_ID)
        let req_id = &derive_request_id(&format!(
            "PRSSSetup_Z128_ID_{PRSS_INIT_REQ_ID}_{DEFAULT_AMOUNT_PARTIES}_{DEFAULT_THRESHOLD}"
        ))
        .unwrap();
        purge(None, None, req_id, DEFAULT_AMOUNT_PARTIES).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;

        // DON'T setup PRSS in order to ensure the server is not ready yet
        let (kms_servers, kms_clients, mut internal_client) =
            threshold_handles(TEST_PARAM, DEFAULT_AMOUNT_PARTIES, false, None, None).await;

        // Validate that the core server is not ready
        let (dec_tasks, req_id) = send_dec_reqs(
            1,
            &TEST_THRESHOLD_KEY_ID,
            &kms_clients,
            &mut internal_client,
        )
        .await;
        let dec_res = dec_tasks.join_all().await;
        // Even though servers are not initialized they will accept the requests
        assert!(dec_res.iter().all(|res| res.is_ok()));
        // But the response will result in an error
        let dec_resp_tasks = get_pub_dec_resp(&req_id, &kms_clients).await;
        let dec_resp_res = dec_resp_tasks.join_all().await;
        assert!(dec_resp_res.iter().all(|res| res.is_err()));

        // Get health client for main server 1
        let mut main_health_client = get_health_client(kms_servers.get(&1).unwrap().service_port)
            .await
            .expect("Failed to get core health client");
        let core_service_name = <CoreServiceEndpointServer<
            RealThresholdKms<FileStorage, FileStorage, FileStorage>,
        > as NamedService>::NAME;
        let status = get_status(&mut main_health_client, core_service_name)
            .await
            .unwrap();
        // Check that the main server is not serving since it has not been initialized yet
        assert_eq!(
            status,
            ServingStatus::NotServing as i32,
            "Service is not in NOT_SERVING status. Got status: {status}"
        );
        // Get health client for main server 1
        let mut threshold_health_client =
            get_health_client(kms_servers.get(&1).unwrap().mpc_port.unwrap())
                .await
                .expect("Failed to get threshold health client");
        let threshold_service_name = <GrpcServer as NamedService>::NAME;
        let status = get_status(&mut threshold_health_client, threshold_service_name)
            .await
            .unwrap();
        // Threshold servers will start serving as soon as they boot
        assert_eq!(
            status,
            ServingStatus::Serving as i32,
            "Service is not in SERVING status. Got status: {status}"
        );

        // Now initialize and check that the server is serving
        let mut req_tasks = JoinSet::new();
        for i in 1..=DEFAULT_AMOUNT_PARTIES as u32 {
            let mut cur_client = kms_clients.get(&i).unwrap().clone();
            req_tasks.spawn(async move {
                let req_id = RequestId::from_str(PRSS_INIT_REQ_ID).unwrap();
                cur_client
                    .init(tonic::Request::new(InitRequest {
                        request_id: Some(req_id.into()),
                    }))
                    .await
            });
        }
        while let Some(inner) = req_tasks.join_next().await {
            assert!(inner.unwrap().is_ok());
        }
        let status = get_status(&mut main_health_client, core_service_name)
            .await
            .unwrap();
        assert_eq!(
            status,
            ServingStatus::Serving as i32,
            "Service is not in SERVING status. Got status: {status}"
        );

        // Shutdown the servers and check that the health endpoint is no longer serving
        for (_, server) in kms_servers {
            // Shut down MPC servers triggers a shutdown of the core server
            server.mpc_shutdown_tx.unwrap().send(()).unwrap();
        }
        //  The core server should not be serving
        let mut status = get_status(&mut main_health_client, core_service_name).await;
        // As long as the server is open check that it is not serving
        while status.is_ok() {
            assert_eq!(
                status.clone().unwrap(),
                ServingStatus::NotServing as i32,
                "Service is not in NOT_SERVING status. Got status: {}",
                status.unwrap()
            );
            // Sleep a bit and check whether the server has shut down
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            status = get_status(&mut main_health_client, core_service_name).await;
        }

        // The MPC servers should be closed at this point
        let status = get_status(&mut threshold_health_client, threshold_service_name).await;
        assert!(status.is_err(),);
    }

    /// Validate that dropping the server signal triggers the server to shut down
    #[tokio::test]
    #[serial]
    async fn test_central_close_after_drop() {
        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
        let (kms_server, kms_client, mut internal_client) =
            super::test_tools::centralized_handles(&TEST_PARAM, None).await;
        let mut health_client = get_health_client(kms_server.service_port)
            .await
            .expect("Failed to get health client");
        let service_name = <CoreServiceEndpointServer<
            RealCentralizedKms<FileStorage, FileStorage, FileStorage>,
        > as NamedService>::NAME;
        let request = tonic::Request::new(HealthCheckRequest {
            service: service_name.to_string(),
        });

        let response = health_client
            .check(request)
            .await
            .expect("Health check request failed");

        let status = response.into_inner().status;
        assert_eq!(
            status,
            ServingStatus::Serving as i32,
            "Service is not in SERVING status. Got status: {status}"
        );
        let client_map = HashMap::from([(1, kms_client)]);
        // Keep the server occupied so it won't shut down immidiately after dropping the handle
        let (tasks, req_id) =
            send_dec_reqs(3, &TEST_CENTRAL_KEY_ID, &client_map, &mut internal_client).await;
        // Drop server
        drop(kms_server);
        // Get status and validate that it is not serving
        let status = get_status(&mut health_client, service_name).await.unwrap();
        // Threshold servers will start serving as soon as they boot
        // WARNING there is a risk this check fails if the server is shut down before was can complete the status check
        assert_eq!(
            status,
            ServingStatus::NotServing as i32,
            "Service is not in NOT SERVING status. Got status: {status}"
        );
        // Wait for dec tasks to be done
        let dec_res = tasks.join_all().await;
        assert!(dec_res.iter().all(|res| res.is_ok()));
        // And wait for public decryption to also be done
        let dec_resp_tasks = get_pub_dec_resp(&req_id, &client_map).await;
        let dec_resp_res = dec_resp_tasks.join_all().await;
        // TODO the response for the server that were not dropped should actually be ok since we only drop one <=t server
        assert!(dec_resp_res.iter().all(|res| res.is_err()));
        // Check the server is no longer there
        assert!(get_status(&mut health_client, service_name).await.is_err());
    }

    /// Validate that dropping the server signal triggers the server to shut down
    #[tokio::test]
    #[serial]
    async fn test_threshold_close_after_drop() {
        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
        let (mut kms_servers, _kms_clients, _internal_client) =
            threshold_handles(TEST_PARAM, DEFAULT_AMOUNT_PARTIES, true, None, None).await;

        // Get health client for main server 1
        let mut core_health_client = get_health_client(kms_servers.get(&1).unwrap().service_port)
            .await
            .expect("Failed to get core health client");
        let core_service_name = <CoreServiceEndpointServer<
            RealThresholdKms<FileStorage, FileStorage, FileStorage>,
        > as NamedService>::NAME;
        // Get health client for main server 1
        let mut threshold_health_client =
            get_health_client(kms_servers.get(&1).unwrap().mpc_port.unwrap())
                .await
                .expect("Failed to get threshold health client");
        let threshold_service_name = <GrpcServer as NamedService>::NAME;
        // Check things are working
        let status = get_status(&mut core_health_client, core_service_name)
            .await
            .unwrap();
        assert_eq!(
            status,
            ServingStatus::Serving as i32,
            "Service is not in SERVING status. Got status: {status}"
        );
        let status = get_status(&mut threshold_health_client, threshold_service_name)
            .await
            .unwrap();
        assert_eq!(
            status,
            ServingStatus::Serving as i32,
            "Service is not in SERVING status. Got status: {status}"
        );
        let res = kms_servers.remove(&1).unwrap();
        // Trigger the shutdown
        drop(res);
        // Sleep to allow completion of the shut down which should be quick since we waited for existing tasks to be done
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
        // Check the server is no longer there
        assert!(get_status(&mut core_health_client, core_service_name)
            .await
            .is_err());
        assert!(
            get_status(&mut threshold_health_client, threshold_service_name)
                .await
                .is_err()
        );
    }

    /// Validate that shutdown signals work
    #[tokio::test]
    #[serial]
    async fn test_threshold_shutdown() {
        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
        let (mut kms_servers, kms_clients, mut internal_client) =
            threshold_handles(TEST_PARAM, DEFAULT_AMOUNT_PARTIES, true, None, None).await;
        // Ensure that the servers are ready
        for cur_handle in kms_servers.values() {
            let service_name = <CoreServiceEndpointServer<
                RealThresholdKms<FileStorage, FileStorage, FileStorage>,
            > as NamedService>::NAME;
            await_server_ready(service_name, cur_handle.service_port).await;
        }
        let mpc_port = kms_servers.get(&1).unwrap().mpc_port.unwrap();
        let service_port = kms_servers.get(&1).unwrap().service_port;
        // Get health client for main server 1
        let mut core_health_client = get_health_client(kms_servers.get(&1).unwrap().service_port)
            .await
            .expect("Failed to get core health client");
        let core_service_name = <CoreServiceEndpointServer<
            RealThresholdKms<FileStorage, FileStorage, FileStorage>,
        > as NamedService>::NAME;
        let status = get_status(&mut core_health_client, core_service_name)
            .await
            .unwrap();
        assert_eq!(
            status,
            ServingStatus::Serving as i32,
            "Service is not in SERVING status. Got status: {status}"
        );
        // Get health client for main server 1
        let mut threshold_health_client = get_health_client(mpc_port)
            .await
            .expect("Failed to get threshold health client");
        let threshold_service_name = <GrpcServer as NamedService>::NAME;
        let status = get_status(&mut threshold_health_client, threshold_service_name)
            .await
            .unwrap();
        assert_eq!(
            status,
            ServingStatus::Serving as i32,
            "Service is not in SERVING status. Got status: {status}"
        );
        // Keep the server occupied so it won't shut down immidiately after dropping the handle
        let (tasks, _req_id) = send_dec_reqs(
            3,
            &TEST_THRESHOLD_KEY_ID,
            &kms_clients,
            &mut internal_client,
        )
        .await;
        let dec_res = tasks.join_all().await;
        assert!(dec_res.iter().all(|res| res.is_ok()));
        let server_handle = kms_servers.remove(&1).unwrap();
        // Shut down the Core server (which also shuts down the MPC server)
        server_handle.service_shutdown_tx.send(()).unwrap();
        // Get status and validate that it is not serving
        // Observe that the server should already have set status to net serving while it is finishing the decryption requests.
        // Sleep to give the server some time to set the health reporter to not serving. To fix we need to add shutdown that takes care of thread_group is finished before finishing
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        let status = get_status(&mut core_health_client, core_service_name)
            .await
            .unwrap();
        // Threshold servers will start serving as soon as they boot
        // WARNING there is a risk this check fails if the server is shut down before was can complete the status check
        assert_eq!(
            status,
            ServingStatus::NotServing as i32,
            "Service is not in NOT SERVING status. Got status: {status}"
        );
        let _ = server_handle.server.shutdown().await;
        check_port_is_closed(mpc_port).await;
        check_port_is_closed(service_port).await;
    }

    async fn send_dec_reqs(
        amount_cts: usize,
        key_id: &RequestId,
        kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
        internal_client: &mut Client,
    ) -> (
        JoinSet<Result<tonic::Response<kms_grpc::kms::v1::Empty>, tonic::Status>>,
        RequestId,
    ) {
        let mut cts = Vec::new();
        for i in 0..amount_cts {
            let msg = TestingPlaintext::U32(i as u32);
            let (ct, ct_format, fhe_type) = compute_cipher_from_stored_key(
                None,
                msg,
                key_id,
                EncryptionConfig {
                    compression: true,
                    precompute_sns: false,
                },
            )
            .await;
            let ctt = TypedCiphertext {
                ciphertext: ct,
                fhe_type: fhe_type as i32,
                ciphertext_format: ct_format.into(),
                external_handle: i.to_be_bytes().to_vec(),
            };
            cts.push(ctt);
        }

        // make parallel requests by calling [public_decrypt] in a thread
        let request_id = derive_request_id("TEST_DEC_ID").unwrap();
        let req = internal_client
            .public_decryption_request(cts.clone(), &dummy_domain(), &request_id, key_id)
            .unwrap();
        let mut join_set = JoinSet::new();
        for i in 1..=kms_clients.len() as u32 {
            let req_clone = req.clone();
            let mut cur_client = kms_clients.get(&i).unwrap().clone();
            join_set.spawn(async move {
                cur_client
                    .public_decrypt(tonic::Request::new(req_clone))
                    .await
            });
        }
        (join_set, request_id)
    }

    async fn get_pub_dec_resp(
        request_id: &RequestId,
        kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    ) -> JoinSet<Result<tonic::Response<kms_grpc::kms::v1::PublicDecryptionResponse>, tonic::Status>>
    {
        // make parallel requests by calling [get_public_decryption_result] in a thread
        let mut join_set = JoinSet::new();
        for i in 1..=kms_clients.len() as u32 {
            let mut cur_client = kms_clients.get(&i).unwrap().clone();
            let req_id_clone = *request_id;
            join_set.spawn(async move {
                cur_client
                    .get_public_decryption_result(tonic::Request::new(req_id_clone.into()))
                    .await
            });
        }
        join_set
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn test_key_gen_centralized() {
        let request_id = derive_request_id("test_key_gen_centralized").unwrap();
        // Delete potentially old data
        purge(None, None, &request_id, 1).await;
        key_gen_centralized(&request_id, FheParameter::Test, None, None).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn test_decompression_key_gen_centralized() {
        let request_id_1 = derive_request_id("test_key_gen_centralized-1").unwrap();
        let request_id_2 = derive_request_id("test_key_gen_centralized-2").unwrap();
        let request_id_3 = derive_request_id("test_decompression_key_gen_centralized").unwrap();
        // Delete potentially old data
        purge(None, None, &request_id_1, 1).await;
        purge(None, None, &request_id_2, 1).await;
        purge(None, None, &request_id_3, 1).await;

        key_gen_centralized(&request_id_1, FheParameter::Default, None, None).await;
        key_gen_centralized(&request_id_2, FheParameter::Default, None, None).await;

        key_gen_centralized(
            &request_id_3,
            FheParameter::Default,
            Some(KeySetConfig {
                keyset_type: KeySetType::DecompressionOnly.into(),
                standard_keyset_config: None,
            }),
            Some(KeySetAddedInfo {
                compression_keyset_id: None,
                from_keyset_id_decompression_only: Some(request_id_1.into()),
                to_keyset_id_decompression_only: Some(request_id_2.into()),
            }),
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn default_key_gen_centralized() {
        let request_id = derive_request_id("default_key_gen_centralized").unwrap();
        // Delete potentially old data
        purge(None, None, &request_id, 1).await;
        key_gen_centralized(&request_id, FheParameter::Default, None, None).await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn default_decompression_key_gen_centralized() {
        let request_id_1 = derive_request_id("default_key_gen_centralized-1").unwrap();
        let request_id_2 = derive_request_id("default_key_gen_centralized-2").unwrap();
        let request_id_3 = derive_request_id("default_decompression_key_gen_centralized").unwrap();
        // Delete potentially old data
        purge(None, None, &request_id_1, 1).await;
        purge(None, None, &request_id_2, 1).await;
        purge(None, None, &request_id_3, 1).await;

        key_gen_centralized(&request_id_1, FheParameter::Default, None, None).await;
        key_gen_centralized(&request_id_2, FheParameter::Default, None, None).await;

        key_gen_centralized(
            &request_id_3,
            FheParameter::Default,
            Some(KeySetConfig {
                keyset_type: KeySetType::DecompressionOnly.into(),
                standard_keyset_config: None,
            }),
            Some(KeySetAddedInfo {
                compression_keyset_id: None,
                from_keyset_id_decompression_only: Some(request_id_1.into()),
                to_keyset_id_decompression_only: Some(request_id_2.into()),
            }),
        )
        .await;
    }

    async fn key_gen_centralized(
        request_id: &RequestId,
        params: FheParameter,
        keyset_config: Option<KeySetConfig>,
        keyset_added_info: Option<KeySetAddedInfo>,
    ) {
        let dkg_params: WrappedDKGParams = params.into();

        let rate_limiter_conf = RateLimiterConfig {
            bucket_size: 100 * 3, // Multiply by 3 to account for the decompression key generation case
            pub_decrypt: 1,
            user_decrypt: 1,
            crsgen: 1,
            preproc: 1,
            keygen: 100,
        };
        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
        let (kms_server, mut kms_client, internal_client) =
            super::test_tools::centralized_handles(&dkg_params, Some(rate_limiter_conf)).await;

        let gen_req = internal_client
            .key_gen_request(
                request_id,
                None,
                Some(params),
                keyset_config,
                keyset_added_info.clone(),
                None,
            )
            .unwrap();
        let req_id = gen_req.request_id.clone().unwrap();
        let gen_response = kms_client
            .key_gen(tonic::Request::new(gen_req.clone()))
            .await
            .unwrap();
        assert_eq!(gen_response.into_inner(), Empty {});
        let mut response = kms_client
            .get_key_gen_result(tonic::Request::new(req_id.clone()))
            .await;
        while response.is_err() && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
        {
            // Sleep to give the server some time to complete key generation
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            response = kms_client
                .get_key_gen_result(tonic::Request::new(req_id.clone()))
                .await;
        }
        let inner_resp = response.unwrap().into_inner();
        let pub_storage = FileStorage::new(None, StorageType::PUB, None).unwrap();
        let priv_storage = FileStorage::new(None, StorageType::PRIV, None).unwrap();

        let inner_config = keyset_config.unwrap_or_default();
        let keyset_type = KeySetType::try_from(inner_config.keyset_type).unwrap();
        match keyset_type {
            KeySetType::Standard => {
                let pk = internal_client
                    .retrieve_public_key(&inner_resp, &pub_storage)
                    .await
                    .unwrap();
                assert!(pk.is_some());
                let server_key: Option<tfhe::ServerKey> = internal_client
                    .retrieve_server_key(&inner_resp, &pub_storage)
                    .await
                    .unwrap();
                assert!(server_key.is_some());

                // read the client key
                let handle: crate::engine::base::KmsFheKeyHandles = priv_storage
                    .read_data(
                        &inner_resp.request_id.unwrap().into(),
                        &PrivDataType::FheKeyInfo.to_string(),
                    )
                    .await
                    .unwrap();
                let client_key = handle.client_key;

                check_conformance(server_key.unwrap(), client_key);
            }
            KeySetType::DecompressionOnly => {
                // setup storage
                let keyid_1 = RequestId::from_str(
                    keyset_added_info
                        .clone()
                        .unwrap()
                        .from_keyset_id_decompression_only
                        .as_ref()
                        .unwrap()
                        .request_id
                        .as_str(),
                )
                .unwrap();
                let keyid_2 = RequestId::from_str(
                    keyset_added_info
                        .unwrap()
                        .to_keyset_id_decompression_only
                        .as_ref()
                        .unwrap()
                        .request_id
                        .as_str(),
                )
                .unwrap();
                let handles_1: crate::engine::base::KmsFheKeyHandles = priv_storage
                    .read_data(&keyid_1, &PrivDataType::FheKeyInfo.to_string())
                    .await
                    .unwrap();
                let handles_2: crate::engine::base::KmsFheKeyHandles = priv_storage
                    .read_data(&keyid_2, &PrivDataType::FheKeyInfo.to_string())
                    .await
                    .unwrap();

                // get the client key 1 and client key 2
                let client_key_1 = handles_1.client_key;
                let client_key_2 = handles_2.client_key;

                // get the server key 1
                let server_key_1: tfhe::ServerKey = internal_client
                    .get_key(&keyid_1, PubDataType::ServerKey, &pub_storage)
                    .await
                    .unwrap();

                // get decompression key
                let decompression_key = internal_client
                    .retrieve_decompression_key(&inner_resp, &pub_storage)
                    .await
                    .unwrap()
                    .unwrap()
                    .into_raw_parts();
                run_decompression_test(
                    &client_key_1,
                    &client_key_2,
                    Some(&server_key_1),
                    decompression_key,
                );
            }
        }

        kms_server.assert_shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_crs_gen_manual() {
        let crs_req_id = derive_request_id("test_crs_gen_manual").unwrap();
        // Delete potentially old data
        purge(None, None, &crs_req_id, 1).await;
        // TEST_PARAM uses V1 CRS
        crs_gen_centralized_manual(&TEST_PARAM, &crs_req_id, Some(FheParameter::Test)).await;
    }

    /// test centralized crs generation and do all the reading, processing and verification manually
    async fn crs_gen_centralized_manual(
        dkg_params: &DKGParams,
        request_id: &RequestId,
        params: Option<FheParameter>,
    ) {
        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
        let (kms_server, mut kms_client, internal_client) =
            super::test_tools::centralized_handles(dkg_params, None).await;

        let max_num_bits = if params.unwrap() == FheParameter::Test {
            Some(1)
        } else {
            // The default is 2048 which is too slow for tests, so we switch to 256
            Some(256)
        };
        let ceremony_req = internal_client
            .crs_gen_request(request_id, max_num_bits, params, None)
            .unwrap();

        let client_request_id = ceremony_req.request_id.clone().unwrap();

        // response is currently empty
        let gen_response = kms_client
            .crs_gen(tonic::Request::new(ceremony_req.clone()))
            .await
            .unwrap();
        assert_eq!(gen_response.into_inner(), Empty {});
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        // Check that we can retrieve the CRS under that request id
        let mut get_response = kms_client
            .get_crs_gen_result(tonic::Request::new(client_request_id.clone()))
            .await;
        while get_response.is_err() {
            // Sleep to give the server some time to complete CRS generation
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            get_response = kms_client
                .get_crs_gen_result(tonic::Request::new((*request_id).into()))
                .await;
        }

        let resp = get_response.unwrap().into_inner();
        let rvcd_req_id = resp.request_id.unwrap();

        // // check that the received request id matches the one we sent in the request
        assert_eq!(rvcd_req_id, client_request_id);

        let crs_info = resp.crs_results.unwrap();
        let pub_storage = FileStorage::new(None, StorageType::PUB, None).unwrap();
        // check that CRS signature is verified correctly for the current version
        let crs_unversioned: CompactPkeCrs = pub_storage
            .read_data(request_id, &PubDataType::CRS.to_string())
            .await
            .unwrap();
        let client_handle = compute_handle(&crs_unversioned).unwrap();
        assert_eq!(&client_handle, &crs_info.key_handle);

        // try verification with each of the server keys; at least one must pass
        let crs_sig: Signature = bc2wrap::deserialize(&crs_info.signature).unwrap();
        let mut verified = false;
        let server_pks = internal_client.get_server_pks().unwrap();
        for vk in server_pks.values() {
            let v =
                BaseKmsStruct::verify_sig(&DSEP_PUBDATA_CRS, &client_handle, &crs_sig, vk).is_ok();
            verified = verified || v;
        }

        // check that verification (with at least 1 server key) worked
        assert!(verified);

        kms_server.assert_shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_crs_gen_centralized() {
        let crs_req_id = derive_request_id("test_crs_gen_centralized").unwrap();
        // Delete potentially old data
        purge(None, None, &crs_req_id, 1).await;
        // TEST_PARAM uses V1 CRS
        crs_gen_centralized(&crs_req_id, FheParameter::Test, false).await;
    }

    #[cfg(feature = "insecure")]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_insecure_crs_gen_centralized() {
        let crs_req_id = derive_request_id("test_insecure_crs_gen_centralized").unwrap();
        // Delete potentially old data
        purge(None, None, &crs_req_id, 1).await;
        // TEST_PARAM uses V1 CRS
        crs_gen_centralized(&crs_req_id, FheParameter::Test, true).await;
    }

    /// test centralized crs generation via client interface
    async fn crs_gen_centralized(crs_req_id: &RequestId, params: FheParameter, insecure: bool) {
        let dkg_param: WrappedDKGParams = params.into();
        let rate_limiter_conf = RateLimiterConfig {
            bucket_size: 100,
            pub_decrypt: 1,
            user_decrypt: 1,
            crsgen: 100,
            preproc: 1,
            keygen: 1,
        };
        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
        let (kms_server, mut kms_client, internal_client) =
            super::test_tools::centralized_handles(&dkg_param, Some(rate_limiter_conf)).await;

        let max_num_bits = if params == FheParameter::Test {
            Some(1)
        } else {
            // The default is 2048 which is too slow for tests, so we switch to 256
            Some(256)
        };
        let gen_req = internal_client
            .crs_gen_request(crs_req_id, max_num_bits, Some(params), None)
            .unwrap();

        tracing::debug!("making crs request, insecure? {insecure}");
        match insecure {
            true => {
                #[cfg(feature = "insecure")]
                {
                    let gen_response = kms_client
                        .insecure_crs_gen(tonic::Request::new(gen_req.clone()))
                        .await
                        .unwrap();
                    assert_eq!(gen_response.into_inner(), Empty {});
                }
                #[cfg(not(feature = "insecure"))]
                {
                    panic!("cannot perform insecure central crs gen")
                }
            }
            false => {
                let gen_response = kms_client
                    .crs_gen(tonic::Request::new(gen_req.clone()))
                    .await
                    .unwrap();
                assert_eq!(gen_response.into_inner(), Empty {});
            }
        };

        let mut response = Err(tonic::Status::not_found(""));
        let mut ctr = 0;
        while response.is_err() && ctr < 5 {
            response = kms_client
                .get_crs_gen_result(tonic::Request::new((*crs_req_id).into()))
                .await;
            ctr += 1;
        }
        let inner_resp = response.unwrap().into_inner();
        let pub_storage = FileStorage::new(None, StorageType::PUB, None).unwrap();
        let pp = internal_client
            .process_get_crs_resp(&inner_resp, &pub_storage)
            .await
            .unwrap()
            .unwrap();

        // Validate the CRS as a sanity check
        verify_pp(&dkg_param, &pp).await;

        kms_server.assert_shutdown().await;
    }

    async fn verify_pp(dkg_params: &DKGParams, pp: &CompactPkeCrs) {
        let dkg_params_handle = dkg_params.get_params_basics_handle();

        let cks = tfhe::integer::ClientKey::new(dkg_params_handle.to_classic_pbs_parameters());

        // If there is indeed a dedicated compact pk, we need to generate the corresponding
        // keys to expand when encrypting later on
        let pk = if dkg_params_handle.has_dedicated_compact_pk_params() {
            // Generate the secret key PKE encrypts to
            let compact_private_key = tfhe::integer::public_key::CompactPrivateKey::new(
                dkg_params_handle.get_compact_pk_enc_params(),
            );
            // Generate the corresponding public key
            let pk = tfhe::integer::public_key::CompactPublicKey::new(&compact_private_key);
            tfhe::CompactPublicKey::from_raw_parts(pk, Tag::default())
        } else {
            let cks = cks.clone().into_raw_parts();
            let pk = tfhe::shortint::CompactPublicKey::new(&cks);
            let pk = tfhe::integer::CompactPublicKey::from_raw_parts(pk);

            tfhe::CompactPublicKey::from_raw_parts(pk, Tag::default())
        };

        let max_msg_len = pp.max_num_messages().0;
        let msgs = (0..max_msg_len)
            .map(|i| i as u64 % dkg_params_handle.get_message_modulus().0)
            .collect::<Vec<_>>();

        let metadata = vec![23_u8, 42];
        let mut compact_list_builder = ProvenCompactCiphertextList::builder(&pk);
        for msg in msgs {
            compact_list_builder.push_with_num_bits(msg, 64).unwrap();
        }
        let proven_ct = compact_list_builder
            .build_with_proof_packed(pp, &metadata, tfhe::zk::ZkComputeLoad::Proof)
            .unwrap();
        assert!(proven_ct.verify(pp, &pk, &metadata).is_valid());
    }

    /////////////////////////////////
    //
    //         CRS SECTION
    //
    /////////////////////////////////

    #[cfg(feature = "insecure")]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_insecure_crs_gen_threshold() {
        // Test parameters use V1 CRS
        crs_gen(
            4,
            FheParameter::Test,
            Some(16),
            true, // insecure
            1,
            false,
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn secure_threshold_crs() {
        crs_gen(4, FheParameter::Default, Some(16), false, 1, false).await;
    }

    // Poll the client method function `f_to_poll` until there is a result
    // or error out until some timeout.
    // The requests from the `reqs` argument need to implement `RequestIdGetter`.
    #[macro_export]
    macro_rules! par_poll_responses {
    ($kms_clients:expr,$reqs:expr,$f_to_poll:ident,$amount_parties:expr) => {{
        use $crate::consts::MAX_TRIES;
        let mut joined_responses = vec![];
        for count in 0..MAX_TRIES {
            // Reset the list every time since we get all old results as well
            joined_responses = vec![];
            tokio::time::sleep(tokio::time::Duration::from_secs(30 * $reqs.len() as u64)).await;

            let mut tasks_get = JoinSet::new();
            for req in $reqs {
                for i in 1..=$amount_parties as u32 {
                    // Make sure we only consider clients for which
                    // we haven't killed the corresponding server
                    if let Some(cur_client) = $kms_clients.get(&i) {
                        let mut cur_client = cur_client.clone();
                        let req_id_proto = req.request_id.clone().unwrap();
                        tasks_get.spawn(async move {
                            (
                                i,
                                req_id_proto.clone(),
                                cur_client
                                    .$f_to_poll(tonic::Request::new(req_id_proto))
                                    .await,
                            )
                        });
                    }
                }
            }

            while let Some(res) = tasks_get.join_next().await {
                match res {
                    Ok(inner) => {
                        // Validate if the result returned is ok, if not we ignore, since it likely means that the process is still running on the server
                        if let (j, req_id, Ok(resp)) = inner {
                            joined_responses.push((j, req_id, resp.into_inner()));
                        } else {
                            let (j, req_id, inner_resp) = inner;
                            // Explicitly convert to string to avoid any type conversion issues
                            let req_id_str = match kms_grpc::RequestId::from(req_id.clone()) {
                                id => id.to_string(),
                            };
                            tracing::info!("Response in iteration {count} for server {j} and req_id {req_id_str} is: {:?}", inner_resp);
                        }
                    }
                    _ => {
                        panic!("Something went wrong while polling for responses");
                    }
                }
            }

            if joined_responses.len() >= $kms_clients.len() * $reqs.len() {
                break;
            }

            // fail if we can't find a response
            if count >= MAX_TRIES - 1 {
                panic!("could not get response after {} tries", count);
            }
        }

        joined_responses
    }};
}
    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    async fn crs_gen(
        amount_parties: usize,
        parameter: FheParameter,
        max_bits: Option<u32>,
        insecure: bool,
        iterations: usize,
        concurrent: bool,
    ) {
        for i in 0..iterations {
            let req_crs: RequestId = derive_request_id(&format!(
                "full_crs_{amount_parties}_{max_bits:?}_{parameter:?}_{i}_{insecure}"
            ))
            .unwrap();
            purge(None, None, &req_crs, amount_parties).await;
        }
        let dkg_param: WrappedDKGParams = parameter.into();

        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
        // The threshold handle should only be started after the storage is purged
        // since the threshold parties will load the CRS from private storage
        let (_kms_servers, kms_clients, internal_client) =
            threshold_handles(*dkg_param, amount_parties, true, None, None).await;

        if concurrent {
            let arc_clients = Arc::new(kms_clients);
            let arc_internalclient = Arc::new(internal_client);
            let mut crs_set = JoinSet::new();
            for i in 0..iterations {
                let cur_id: RequestId = derive_request_id(&format!(
                    "full_crs_{amount_parties}_{max_bits:?}_{parameter:?}_{i}_{insecure}"
                ))
                .unwrap();
                crs_set.spawn({
                    let clients_clone = Arc::clone(&arc_clients);
                    let internalclient_clone = Arc::clone(&arc_internalclient);
                    async move {
                        run_crs(
                            parameter,
                            &clients_clone,
                            &internalclient_clone,
                            insecure,
                            &cur_id,
                            max_bits,
                        )
                        .await
                    }
                });
            }
            let res = crs_set.join_all().await;
            assert_eq!(res.len(), iterations);
        } else {
            for i in 0..iterations {
                let cur_id: RequestId = derive_request_id(&format!(
                    "full_crs_{amount_parties}_{max_bits:?}_{parameter:?}_{i}_{insecure}"
                ))
                .unwrap();
                run_crs(
                    parameter,
                    &kms_clients,
                    &internal_client,
                    insecure,
                    &cur_id,
                    max_bits,
                )
                .await;
            }
        }
    }

    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    #[allow(clippy::too_many_arguments)]
    async fn run_crs(
        parameter: FheParameter,
        kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
        internal_client: &Client,
        insecure: bool,
        crs_req_id: &RequestId,
        max_bits: Option<u32>,
    ) {
        let dkg_param: WrappedDKGParams = parameter.into();
        let crs_req = internal_client
            .crs_gen_request(crs_req_id, max_bits, Some(parameter), None)
            .unwrap();

        let responses = launch_crs(&vec![crs_req.clone()], kms_clients, insecure).await;
        for response in responses {
            assert!(response.is_ok());
        }
        wait_for_crsgen_result(&vec![crs_req], kms_clients, internal_client, &dkg_param).await;
    }

    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    async fn launch_crs(
        reqs: &Vec<CrsGenRequest>,
        kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
        insecure: bool,
    ) -> Vec<Result<tonic::Response<Empty>, tonic::Status>> {
        let amount_parties = kms_clients.len();
        let mut tasks_gen = JoinSet::new();
        for req in reqs {
            for i in 1..=amount_parties as u32 {
                let mut cur_client = kms_clients.get(&i).unwrap().clone();
                let req_clone = req.clone();
                tasks_gen.spawn(async move {
                    if insecure {
                        #[cfg(feature = "insecure")]
                        {
                            cur_client
                                .insecure_crs_gen(tonic::Request::new(req_clone))
                                .await
                        }
                        #[cfg(not(feature = "insecure"))]
                        {
                            panic!("cannot perform insecure crs gen")
                        }
                    } else {
                        cur_client.crs_gen(tonic::Request::new(req_clone)).await
                    }
                });
            }
        }
        let mut responses_gen = Vec::new();
        while let Some(inner) = tasks_gen.join_next().await {
            let resp = inner.unwrap();
            responses_gen.push(resp);
        }
        assert_eq!(responses_gen.len(), amount_parties * reqs.len());
        responses_gen
    }

    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    async fn wait_for_crsgen_result(
        reqs: &Vec<CrsGenRequest>,
        kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
        internal_client: &Client,
        param: &DKGParams,
    ) {
        let amount_parties = kms_clients.len();
        // wait a bit for the crs generation to finish
        let joined_responses =
            par_poll_responses!(kms_clients, reqs, get_crs_gen_result, amount_parties);

        // first check the happy path
        // the public parameter is checked in ddec tests, so we don't specifically check _pp
        for req in reqs {
            use itertools::Itertools;

            let req_id: RequestId = req.clone().request_id.unwrap().into();
            let joined_responses: Vec<_> = joined_responses
                .iter()
                .cloned()
                .filter_map(|(i, rid, resp)| {
                    if rid == req_id.into() {
                        Some((i, resp))
                    } else {
                        None
                    }
                })
                .collect();

            // we need to setup the storage devices in the right order
            // so that the client can read the CRS
            let res_storage = joined_responses
                .into_iter()
                .map(|(i, res)| {
                    (res, {
                        FileStorage::new(
                            None,
                            StorageType::PUB,
                            Some(Role::indexed_from_one(i as usize)),
                        )
                        .unwrap()
                    })
                })
                .collect_vec();
            // Compute threshold < amount_parties/3
            let threshold = max_threshold(amount_parties);
            let min_count_agree = (threshold + 1) as u32;

            let pp = internal_client
                .process_distributed_crs_result(&req_id, res_storage.clone(), min_count_agree)
                .await
                .unwrap();
            verify_pp(param, &pp).await;

            // if there are [THRESHOLD] result missing, we can still recover the result
            let _pp = internal_client
                .process_distributed_crs_result(
                    &req_id,
                    res_storage[0..res_storage.len() - threshold].to_vec(),
                    min_count_agree,
                )
                .await
                .unwrap();

            // if there are only THRESHOLD results then we do not have consensus as at least THRESHOLD+1 is needed
            assert!(internal_client
                .process_distributed_crs_result(
                    &req_id,
                    res_storage[0..threshold].to_vec(),
                    min_count_agree
                )
                .await
                .is_err());

            // if the request_id is wrong, we get nothing
            let bad_request_id = derive_request_id("bad_request_id").unwrap();
            assert!(internal_client
                .process_distributed_crs_result(
                    &bad_request_id,
                    res_storage.clone(),
                    min_count_agree
                )
                .await
                .is_err());

            // test that having [THRESHOLD] wrong signatures still works
            let mut final_responses_with_bad_sig = res_storage.clone();
            let client_sk = internal_client.client_sk.clone().unwrap();
            let bad_sig = bc2wrap::serialize(
                &crate::cryptography::signcryption::internal_sign(
                    &DSEP_PUBDATA_CRS,
                    &"wrong msg".to_string(),
                    &client_sk,
                )
                .unwrap(),
            )
            .unwrap();
            set_signatures(&mut final_responses_with_bad_sig, threshold, &bad_sig);

            let _pp = internal_client
                .process_distributed_crs_result(
                    &req_id,
                    final_responses_with_bad_sig,
                    min_count_agree,
                )
                .await
                .unwrap();

            // having [amount_parties-threshold] wrong signatures won't work
            let mut final_responses_with_bad_sig = res_storage.clone();
            set_signatures(
                &mut final_responses_with_bad_sig,
                amount_parties - threshold,
                &bad_sig,
            );
            assert!(internal_client
                .process_distributed_crs_result(
                    &req_id,
                    final_responses_with_bad_sig,
                    min_count_agree
                )
                .await
                .is_err());

            // having [amount_parties-(threshold+1)] wrong digests still works
            let mut final_responses_with_bad_digest = res_storage.clone();
            set_digests(
                &mut final_responses_with_bad_digest,
                amount_parties - (threshold + 1),
                "9fdca770403e2eed9dacb4cdd405a14fc6df7226",
            );
            let _pp = internal_client
                .process_distributed_crs_result(
                    &req_id,
                    final_responses_with_bad_digest,
                    min_count_agree,
                )
                .await
                .unwrap();

            // having [amount_parties-threshold] wrong digests will fail
            let mut final_responses_with_bad_digest = res_storage.clone();
            set_digests(
                &mut final_responses_with_bad_digest,
                amount_parties - threshold,
                "9fdca770403e2eed9dacb4cdd405a14fc6df7226",
            );
            assert!(internal_client
                .process_distributed_crs_result(
                    &req_id,
                    final_responses_with_bad_digest,
                    min_count_agree
                )
                .await
                .is_err());
        }
    }

    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    fn set_signatures(
        crs_res_storage: &mut [(crate::client::CrsGenResult, FileStorage)],
        count: usize,
        sig: &[u8],
    ) {
        for (crs_gen_result, _) in crs_res_storage.iter_mut().take(count) {
            match &mut crs_gen_result.crs_results {
                Some(info) => {
                    info.signature = sig.to_vec();
                }
                None => panic!("missing SignedPubDataHandle"),
            };
        }
    }

    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    fn set_digests(
        crs_res_storage: &mut [(crate::client::CrsGenResult, FileStorage)],
        count: usize,
        digest: &str,
    ) {
        for (crs_gen_result, _) in crs_res_storage.iter_mut().take(count) {
            match &mut crs_gen_result.crs_results {
                Some(info) => {
                    // each hex-digit is 4 bits, 256 bits is 64 characters
                    assert_eq!(64, info.key_handle.len());
                    // it's unlikely that we generate the same signature more than once
                    info.key_handle = digest.to_string();
                }
                None => panic!("missing SignedPubDataHandle"),
            }
        }
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_crs_gen_threshold() {
        crs_gen(4, FheParameter::Test, Some(1), false, 1, false).await;
    }

    /////////////////////////////////
    //
    //        END OF CRS SECTION
    //
    /////////////////////////////////

    #[tokio::test]
    #[serial]
    async fn test_decryption_central() {
        decryption_centralized(
            &TEST_PARAM,
            &TEST_CENTRAL_KEY_ID,
            vec![
                TestingPlaintext::U8(42),
                TestingPlaintext::U32(9876),
                TestingPlaintext::U16(420),
                TestingPlaintext::Bool(true),
            ],
            EncryptionConfig {
                compression: true,
                precompute_sns: false,
            },
            3, // 3 parallel requests
        )
        .await;
    }

    #[tokio::test]
    #[serial]
    async fn test_decryption_central_no_decompression() {
        decryption_centralized(
            &TEST_PARAM,
            &TEST_CENTRAL_KEY_ID,
            vec![
                TestingPlaintext::U8(42),
                TestingPlaintext::U32(9876),
                TestingPlaintext::U16(420),
                TestingPlaintext::Bool(true),
            ],
            EncryptionConfig {
                compression: false,
                precompute_sns: false,
            },
            3, // 3 parallel requests
        )
        .await;
    }

    #[tokio::test]
    #[serial]
    async fn test_decryption_central_precompute_sns() {
        decryption_centralized(
            &TEST_PARAM,
            &TEST_CENTRAL_KEY_ID,
            vec![
                TestingPlaintext::U8(42),
                TestingPlaintext::U32(9876),
                TestingPlaintext::U16(420),
                TestingPlaintext::Bool(true),
                TestingPlaintext::U80((1u128 << 80) - 1),
            ],
            EncryptionConfig {
                compression: false,
                precompute_sns: true,
            },
            3, // 3 parallel requests
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[rstest::rstest]
    #[case(vec![TestingPlaintext::U8(u8::MAX)], 4)]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn default_decryption_centralized(
        #[case] msgs: Vec<TestingPlaintext>,
        #[case] parallelism: usize,
    ) {
        use crate::consts::DEFAULT_PARAM;

        decryption_centralized(
            &DEFAULT_PARAM,
            &DEFAULT_CENTRAL_KEY_ID,
            msgs,
            EncryptionConfig {
                compression: true,
                precompute_sns: false,
            },
            parallelism,
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[rstest::rstest]
    #[case(vec![TestingPlaintext::U8(u8::MAX)], 4)]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn default_decryption_centralized_precompute_sns(
        #[case] msgs: Vec<TestingPlaintext>,
        #[case] parallelism: usize,
    ) {
        use crate::consts::DEFAULT_PARAM;

        decryption_centralized(
            &DEFAULT_PARAM,
            &DEFAULT_CENTRAL_KEY_ID,
            msgs,
            EncryptionConfig {
                compression: false,
                precompute_sns: true,
            },
            parallelism,
        )
        .await;
    }

    pub(crate) async fn decryption_centralized(
        dkg_params: &DKGParams,
        key_id: &RequestId,
        msgs: Vec<TestingPlaintext>,
        encryption_config: EncryptionConfig,
        parallelism: usize,
    ) {
        assert!(parallelism > 0);
        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
        let (kms_server, kms_client, mut internal_client) =
            super::test_tools::centralized_handles(dkg_params, None).await;
        let mut cts = Vec::new();
        for (i, msg) in msgs.clone().into_iter().enumerate() {
            let (ct, ct_format, fhe_type) =
                compute_cipher_from_stored_key(None, msg, key_id, encryption_config).await;
            let ctt = TypedCiphertext {
                ciphertext: ct,
                fhe_type: fhe_type as i32,
                ciphertext_format: ct_format.into(),
                external_handle: i.to_be_bytes().to_vec(),
            };
            cts.push(ctt);
        }

        // build parallel requests
        let reqs: Vec<_> = (0..parallelism)
            .map(|j: usize| {
                let request_id = derive_request_id(&format!("TEST_DEC_ID_{j}")).unwrap();

                internal_client
                    .public_decryption_request(cts.clone(), &dummy_domain(), &request_id, key_id)
                    .unwrap()
            })
            .collect();

        // send all decryption requests simultaneously
        let mut req_tasks = JoinSet::new();
        for j in 0..parallelism {
            let req_cloned = reqs.get(j).unwrap().clone();
            let mut cur_client = kms_client.clone();
            req_tasks.spawn(async move {
                cur_client
                    .public_decrypt(tonic::Request::new(req_cloned))
                    .await
            });
        }

        // collect request task responses
        let mut req_response_vec = Vec::new();
        while let Some(inner) = req_tasks.join_next().await {
            req_response_vec.push(inner.unwrap().unwrap().into_inner());
        }
        assert_eq!(req_response_vec.len(), parallelism);

        // check that initial request responses are all Empty
        for rr in req_response_vec {
            assert_eq!(rr, Empty {});
        }

        // query for decryption responses
        let mut resp_tasks = JoinSet::new();
        for req in &reqs {
            let req_id_clone = req.request_id.as_ref().unwrap().clone();
            let mut cur_client = kms_client.clone();
            resp_tasks.spawn(async move {
                // Sleep initially to give the server some time to complete the decryption
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

                // send query
                let mut response = cur_client
                    .get_public_decryption_result(tonic::Request::new(req_id_clone.clone()))
                    .await;

                // retry counter
                let mut ctr = 0_u64;

                // retry while decryption is not finished, wait between retries and only up to a maximum number of retries
                while response.is_err()
                    && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
                {
                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                    // we may wait up to 50s for tests (include slow profiles), for big ciphertexts
                    if ctr >= 1000 {
                        panic!("timeout while waiting for decryption result");
                    }
                    ctr += 1;
                    response = cur_client
                        .get_public_decryption_result(tonic::Request::new(req_id_clone.clone()))
                        .await;
                }

                // we have a valid response or some error happened, return this
                (req_id_clone, response.unwrap().into_inner())
            });
        }

        // collect decryption outputs
        let mut resp_response_vec = Vec::new();
        while let Some(resp) = resp_tasks.join_next().await {
            resp_response_vec.push(resp.unwrap());
        }

        // go through all requests and check the corresponding responses
        for req in &reqs {
            let req_id = req.request_id.as_ref().unwrap();
            let responses: Vec<_> = resp_response_vec
                .iter()
                .filter_map(|resp| {
                    if resp.0 == *req_id {
                        Some(resp.1.clone())
                    } else {
                        None
                    }
                })
                .collect();

            // we only have single response per request in the centralized case
            assert_eq!(responses.len(), 1);

            let received_plaintexts = internal_client
                .process_decryption_resp(Some(req.clone()), &responses, 1)
                .unwrap();

            // we need 1 plaintext for each ciphertext in the batch
            assert_eq!(received_plaintexts.len(), msgs.len());

            // check that the plaintexts are correct
            for (i, plaintext) in received_plaintexts.iter().enumerate() {
                assert_plaintext(&msgs[i], plaintext);
            }
        }

        kms_server.assert_shutdown().await;
    }

    #[rstest::rstest]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_user_decryption_centralized(#[values(true, false)] secure: bool) {
        user_decryption_centralized(
            &TEST_PARAM,
            &TEST_CENTRAL_KEY_ID,
            false,
            TestingPlaintext::U8(48),
            EncryptionConfig {
                compression: true,
                precompute_sns: false,
            },
            4,
            secure,
        )
        .await;
    }

    #[rstest::rstest]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_user_decryption_centralized_precompute_sns(#[values(true, false)] secure: bool) {
        user_decryption_centralized(
            &TEST_PARAM,
            &TEST_CENTRAL_KEY_ID,
            false,
            TestingPlaintext::U8(48),
            EncryptionConfig {
                compression: false,
                precompute_sns: true,
            },
            4,
            secure,
        )
        .await;
    }

    // The transcripts only need to be 4 parties, it's used for js tests
    #[cfg(feature = "wasm_tests")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn test_user_decryption_centralized_and_write_transcript() {
        user_decryption_centralized(
            &TEST_PARAM,
            &TEST_CENTRAL_KEY_ID,
            true,
            TestingPlaintext::U8(48),
            EncryptionConfig {
                compression: true,
                precompute_sns: false,
            },
            1, // wasm tests are single-threaded
            true,
        )
        .await;
    }

    // Only need to run once for the transcript
    #[cfg(all(feature = "wasm_tests", feature = "slow_tests"))]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn default_user_decryption_centralized_and_write_transcript() {
        use crate::consts::DEFAULT_PARAM;

        let msg = TestingPlaintext::U8(u8::MAX);
        user_decryption_centralized(
            &DEFAULT_PARAM,
            &DEFAULT_CENTRAL_KEY_ID,
            true,
            msg,
            EncryptionConfig {
                compression: true,
                precompute_sns: false,
            },
            1, // wasm tests are single-threaded
            true,
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[rstest::rstest]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn default_user_decryption_centralized(#[values(true, false)] secure: bool) {
        use crate::consts::DEFAULT_PARAM;

        let msg = TestingPlaintext::U8(u8::MAX);
        let parallelism = 1;
        user_decryption_centralized(
            &DEFAULT_PARAM,
            &DEFAULT_CENTRAL_KEY_ID,
            false,
            msg,
            EncryptionConfig {
                compression: true,
                precompute_sns: false,
            },
            parallelism,
            secure,
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[rstest::rstest]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn default_user_decryption_centralized_no_compression(
        #[values(true, false)] secure: bool,
    ) {
        use crate::consts::DEFAULT_PARAM;

        let msg = TestingPlaintext::U8(u8::MAX);
        let parallelism = 1;
        user_decryption_centralized(
            &DEFAULT_PARAM,
            &DEFAULT_CENTRAL_KEY_ID,
            false,
            msg,
            EncryptionConfig {
                compression: false,
                precompute_sns: false,
            },
            parallelism,
            secure,
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[rstest::rstest]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn default_user_decryption_centralized_precompute_sns(
        #[values(true, false)] secure: bool,
    ) {
        use crate::consts::DEFAULT_PARAM;

        let msg = TestingPlaintext::U8(u8::MAX);
        let parallelism = 1;
        user_decryption_centralized(
            &DEFAULT_PARAM,
            &DEFAULT_CENTRAL_KEY_ID,
            false,
            msg,
            EncryptionConfig {
                compression: false,
                precompute_sns: true,
            },
            parallelism,
            secure,
        )
        .await;
    }

    pub(crate) async fn user_decryption_centralized(
        dkg_params: &DKGParams,
        key_id: &RequestId,
        _write_transcript: bool,
        msg: TestingPlaintext,
        enc_config: EncryptionConfig,
        parallelism: usize,
        secure: bool,
    ) {
        assert!(parallelism > 0);
        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
        let (kms_server, kms_client, mut internal_client) =
            super::test_tools::centralized_handles(dkg_params, None).await;
        let (ct, ct_format, fhe_type) =
            compute_cipher_from_stored_key(None, msg, key_id, enc_config).await;

        // The following lines are used to generate integration test-code with javascript for test `new client` in test.js
        // println!(
        //     "Client PK {:?}",
        //     internal_client.client_pk.pk.to_sec1_bytes()
        // );
        // for key in internal_client.server_pks.keys() {
        //     println!("Server PK {:?}", key.pk.to_sec1_bytes());
        // }

        // build parallel requests
        let reqs: Vec<_> = (0..parallelism)
            .map(|j| {
                let typed_ciphertexts = vec![TypedCiphertext {
                    ciphertext: ct.clone(),
                    fhe_type: fhe_type as i32,
                    ciphertext_format: ct_format.into(),
                    external_handle: j.to_be_bytes().to_vec(),
                }];
                let request_id = derive_request_id(&format!("TEST_USER_DECRYPT_ID_{j}")).unwrap();
                internal_client
                    .user_decryption_request(
                        &dummy_domain(),
                        typed_ciphertexts,
                        &request_id,
                        key_id,
                    )
                    .unwrap()
            })
            .collect();

        // send all user decryption requests simultaneously
        let mut req_tasks = JoinSet::new();
        for j in 0..parallelism {
            let req_cloned = reqs.get(j).unwrap().0.clone();
            let mut cur_client = kms_client.clone();
            req_tasks.spawn(async move {
                cur_client
                    .user_decrypt(tonic::Request::new(req_cloned))
                    .await
            });
        }

        // collect request task responses
        let mut req_response_vec = Vec::new();
        while let Some(inner) = req_tasks.join_next().await {
            req_response_vec.push(inner.unwrap().unwrap().into_inner());
        }
        assert_eq!(req_response_vec.len(), parallelism);

        // check that initial request responses are all Empty
        for rr in req_response_vec {
            assert_eq!(rr, Empty {});
        }

        // query for user decryption responses
        let mut resp_tasks = JoinSet::new();
        for req in &reqs {
            let req_id_clone = req.0.request_id.as_ref().unwrap().clone();
            let mut cur_client = kms_client.clone();
            resp_tasks.spawn(async move {
                // Sleep initially to give the server some time to complete the user decryption
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

                // send query
                let mut response = cur_client
                    .get_user_decryption_result(tonic::Request::new(req_id_clone.clone()))
                    .await;

                // retry counter
                let mut ctr = 0_u64;

                // retry while user decryption is not finished, wait between retries and only up to a maximum number of retries
                while response.is_err()
                    && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
                {
                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                    // we may wait up to 50s for tests (include slow profiles), for big ciphertexts
                    if ctr >= 1000 {
                        panic!("timeout while waiting for user deccryption result");
                    }
                    ctr += 1;
                    response = cur_client
                        .get_user_decryption_result(tonic::Request::new(req_id_clone.clone()))
                        .await;
                }

                // we have a valid response or some error happened, return this
                (req_id_clone, response.unwrap().into_inner())
            });
        }

        // collect user deccryption outputs
        let mut resp_response_vec = Vec::new();
        while let Some(resp) = resp_tasks.join_next().await {
            resp_response_vec.push(resp.unwrap());
        }

        #[cfg(feature = "wasm_tests")]
        {
            assert_eq!(parallelism, 1);
            if _write_transcript {
                // We write a plaintext/ciphertext to file as a workaround
                // for tfhe encryption on the wasm side since it cannot
                // be instantiated easily without a seeder and we don't
                // want to introduce extra npm dependency.
                let transcript = TestingUserDecryptionTranscript {
                    server_addrs: internal_client.get_server_addrs(),
                    client_address: internal_client.client_address,
                    client_sk: internal_client.client_sk.clone(),
                    degree: 0,
                    params: internal_client.params,
                    fhe_types: vec![msg.fhe_type() as i32],
                    pts: vec![TypedPlaintext::from(msg).bytes.clone()],
                    cts: reqs[0]
                        .0
                        .typed_ciphertexts
                        .iter()
                        .map(|typed_ct| typed_ct.ciphertext.clone())
                        .collect::<Vec<_>>(),
                    request: Some(reqs[0].clone().0),
                    eph_sk: reqs[0].clone().2,
                    eph_pk: reqs[0].clone().1,
                    agg_resp: vec![resp_response_vec.first().unwrap().1.clone()],
                };

                let path_prefix = if *dkg_params != PARAMS_TEST_BK_SNS {
                    crate::consts::DEFAULT_CENTRAL_WASM_TRANSCRIPT_PATH
                } else {
                    crate::consts::TEST_CENTRAL_WASM_TRANSCRIPT_PATH
                };
                let path = format!("{}.{}", path_prefix, msg.bits());
                write_element(&path, &transcript).await.unwrap();
            }
        }

        // go through all requests and check the corresponding responses
        for req in &reqs {
            let (req, enc_pk, enc_sk) = req;
            let req_id = req.request_id.as_ref().unwrap();
            let responses: Vec<_> = resp_response_vec
                .iter()
                .filter_map(|resp| {
                    if resp.0 == *req_id {
                        Some(resp.1.clone())
                    } else {
                        None
                    }
                })
                .collect();

            // we only have single response per request in the centralized case
            assert_eq!(responses.len(), 1);
            let inner_response = responses.first().unwrap();
            let responses = vec![inner_response.clone()];

            let eip712_domain = protobuf_to_alloy_domain(req.domain.as_ref().unwrap()).unwrap();
            let client_request = ParsedUserDecryptionRequest::try_from(req).unwrap();
            let plaintexts = if secure {
                internal_client
                    .process_user_decryption_resp(
                        &client_request,
                        &eip712_domain,
                        &responses,
                        enc_pk,
                        enc_sk,
                    )
                    .unwrap()
            } else {
                internal_client.server_identities =
                    // one dummy address is needed to force insecure_process_user_decryption_resp
                    // in the centralized mode
                    ServerIdentities::Addrs(HashMap::from_iter([(1, alloy_primitives::address!(
                        "d8da6bf26964af9d7eed9e03e53415d37aa96045"
                    ))]));
                internal_client
                    .insecure_process_user_decryption_resp(&responses, enc_pk, enc_sk)
                    .unwrap()
            };

            for plaintext in plaintexts {
                assert_plaintext(&msg, &plaintext);
            }
        }

        kms_server.assert_shutdown().await;
    }

    fn assert_plaintext(expected: &TestingPlaintext, plaintext: &TypedPlaintext) {
        assert_eq!(expected.fhe_type(), plaintext.fhe_type().unwrap());
        match expected {
            TestingPlaintext::Bool(x) => assert_eq!(*x, plaintext.as_bool()),
            TestingPlaintext::U4(x) => assert_eq!(*x, plaintext.as_u4()),
            TestingPlaintext::U8(x) => assert_eq!(*x, plaintext.as_u8()),
            TestingPlaintext::U16(x) => assert_eq!(*x, plaintext.as_u16()),
            TestingPlaintext::U32(x) => assert_eq!(*x, plaintext.as_u32()),
            TestingPlaintext::U64(x) => assert_eq!(*x, plaintext.as_u64()),
            TestingPlaintext::U80(x) => assert_eq!(*x, plaintext.as_u80()),
            TestingPlaintext::U128(x) => assert_eq!(*x, plaintext.as_u128()),
            TestingPlaintext::U160(x) => assert_eq!(*x, plaintext.as_u160()),
            TestingPlaintext::U256(x) => assert_eq!(*x, plaintext.as_u256()),
            TestingPlaintext::U512(x) => assert_eq!(*x, plaintext.as_u512()),
            TestingPlaintext::U1024(x) => assert_eq!(*x, plaintext.as_u1024()),
            TestingPlaintext::U2048(x) => assert_eq!(*x, plaintext.as_u2048()),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[rstest::rstest]
    #[case(10, &TEST_THRESHOLD_KEY_ID_10P, DecryptionMode::NoiseFloodSmall)]
    #[case(4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
    #[case(4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::BitDecSmall)]
    #[serial]
    async fn test_decryption_threshold_no_decompression(
        #[case] amount_parties: usize,
        #[case] key_id: &RequestId,
        #[case] decryption_mode: DecryptionMode,
    ) {
        decryption_threshold(
            TEST_PARAM,
            key_id,
            vec![
                TestingPlaintext::U8(u8::MAX),
                TestingPlaintext::U8(2),
                TestingPlaintext::U16(444),
            ],
            EncryptionConfig {
                compression: false,
                precompute_sns: false,
            },
            1,
            amount_parties,
            None,
            Some(decryption_mode),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    #[rstest::rstest]
    #[case(10, &TEST_THRESHOLD_KEY_ID_10P, DecryptionMode::NoiseFloodSmall)]
    #[case(4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
    #[case(4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::BitDecSmall)]
    #[serial]
    async fn test_decryption_threshold(
        #[case] amount_parties: usize,
        #[case] key_id: &RequestId,
        #[case] decryption_mode: DecryptionMode,
    ) {
        decryption_threshold(
            TEST_PARAM,
            key_id,
            vec![
                TestingPlaintext::U8(u8::MAX),
                TestingPlaintext::U8(2),
                TestingPlaintext::U16(444),
            ],
            EncryptionConfig {
                compression: true,
                precompute_sns: false,
            },
            2,
            amount_parties,
            None,
            Some(decryption_mode),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    #[rstest::rstest]
    #[case(4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
    #[serial]
    async fn test_decryption_threshold_precompute_sns(
        #[case] amount_parties: usize,
        #[case] key_id: &RequestId,
        #[case] decryption_mode: DecryptionMode,
    ) {
        decryption_threshold(
            TEST_PARAM,
            key_id,
            vec![
                TestingPlaintext::U8(u8::MAX),
                TestingPlaintext::U8(2),
                TestingPlaintext::U16(444),
            ],
            EncryptionConfig {
                compression: false,
                precompute_sns: true,
            },
            2,
            amount_parties,
            None,
            Some(decryption_mode),
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[rstest::rstest]
    #[case(vec![TestingPlaintext::Bool(true), TestingPlaintext::U8(u8::MAX)], 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P)]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn default_decryption_threshold(
        #[case] msg: Vec<TestingPlaintext>,
        #[case] parallelism: usize,
        #[case] amount_parties: usize,
        #[case] key_id: &RequestId,
    ) {
        use crate::consts::DEFAULT_PARAM;

        decryption_threshold(
            DEFAULT_PARAM,
            key_id,
            msg,
            EncryptionConfig {
                compression: true,
                precompute_sns: false,
            },
            parallelism,
            amount_parties,
            None,
            None,
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[rstest::rstest]
    #[case(vec![TestingPlaintext::U8(u8::MAX)], 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P)]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn default_decryption_threshold_precompute_sns(
        #[case] msg: Vec<TestingPlaintext>,
        #[case] parallelism: usize,
        #[case] amount_parties: usize,
        #[case] key_id: &RequestId,
    ) {
        use crate::consts::DEFAULT_PARAM;

        decryption_threshold(
            DEFAULT_PARAM,
            key_id,
            msg,
            EncryptionConfig {
                compression: false,
                precompute_sns: true,
            },
            parallelism,
            amount_parties,
            None,
            None,
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[rstest::rstest]
    #[case(vec![TestingPlaintext::U8(u8::MAX)], 1, 4,Some(vec![1]), &DEFAULT_THRESHOLD_KEY_ID_4P)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn default_decryption_threshold_with_crash(
        #[case] msg: Vec<TestingPlaintext>,
        #[case] parallelism: usize,
        #[case] amount_parties: usize,
        #[case] party_ids_to_crash: Option<Vec<usize>>,
        #[case] key_id: &RequestId,
    ) {
        use crate::consts::DEFAULT_PARAM;

        decryption_threshold(
            DEFAULT_PARAM,
            key_id,
            msg,
            EncryptionConfig {
                compression: true,
                precompute_sns: false,
            },
            parallelism,
            amount_parties,
            party_ids_to_crash,
            None,
        )
        .await;
    }

    #[expect(clippy::too_many_arguments)]
    pub(crate) async fn decryption_threshold(
        dkg_params: DKGParams,
        key_id: &RequestId,
        msgs: Vec<TestingPlaintext>,
        enc_config: EncryptionConfig,
        parallelism: usize,
        amount_parties: usize,
        party_ids_to_crash: Option<Vec<usize>>,
        decryption_mode: Option<DecryptionMode>,
    ) {
        assert!(parallelism > 0);
        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
        let rate_limiter_conf = RateLimiterConfig {
            bucket_size: 100 * parallelism,
            pub_decrypt: 100,
            user_decrypt: 1,
            crsgen: 1,
            preproc: 1,
            keygen: 1,
        };
        let (mut kms_servers, mut kms_clients, mut internal_client) = threshold_handles(
            dkg_params,
            amount_parties,
            true,
            Some(rate_limiter_conf),
            decryption_mode,
        )
        .await;
        let mut cts = Vec::new();
        let mut bits = 0;
        for (i, msg) in msgs.clone().into_iter().enumerate() {
            let (ct, ct_format, fhe_type) =
                compute_cipher_from_stored_key(None, msg, key_id, enc_config).await;
            let ctt = TypedCiphertext {
                ciphertext: ct,
                fhe_type: fhe_type as i32,
                ciphertext_format: ct_format.into(),
                external_handle: i.to_be_bytes().to_vec(),
            };
            cts.push(ctt);
            bits += msg.bits() as u64;
        }

        // make parallel requests by calling [decrypt] in a thread
        let mut req_tasks = JoinSet::new();
        let reqs: Vec<_> = (0..parallelism)
            .map(|j| {
                let request_id = derive_request_id(&format!("TEST_DEC_ID_{j}")).unwrap();

                internal_client
                    .public_decryption_request(cts.clone(), &dummy_domain(), &request_id, key_id)
                    .unwrap()
            })
            .collect();

        // Either send the request, or crash the party if it's in
        // party_ids_to_crash
        let party_ids_to_crash = party_ids_to_crash.unwrap_or_default();
        for i in 1..=amount_parties as u32 {
            if party_ids_to_crash.contains(&(i as usize)) {
                let server_handle = kms_servers.remove(&i).unwrap();
                server_handle.assert_shutdown().await;
                let _kms_client = kms_clients.remove(&i).unwrap();
            } else {
                for j in 0..parallelism {
                    let req_cloned = reqs.get(j).unwrap().clone();
                    let mut cur_client = kms_clients.get(&i).unwrap().clone();
                    req_tasks.spawn(async move {
                        cur_client
                            .public_decrypt(tonic::Request::new(req_cloned))
                            .await
                    });
                }
            }
        }

        let mut req_response_vec = Vec::new();
        while let Some(inner) = req_tasks.join_next().await {
            req_response_vec.push(inner.unwrap().unwrap().into_inner());
        }
        assert_eq!(
            req_response_vec.len(),
            (amount_parties - party_ids_to_crash.len()) * parallelism
        );

        // get all responses
        let mut resp_tasks = JoinSet::new();
        for i in 1..=amount_parties as u32 {
            if party_ids_to_crash.contains(&(i as usize)) {
                continue;
            }
            for req in &reqs {
                let mut cur_client = kms_clients.get(&i).unwrap().clone();
                let req_id_clone = req.request_id.as_ref().unwrap().clone();
                resp_tasks.spawn(async move {
                    // Sleep to give the server some time to complete decryption
                    tokio::time::sleep(tokio::time::Duration::from_millis(
                        100 * bits * parallelism as u64,
                    ))
                    .await;

                    let mut response = cur_client
                        .get_public_decryption_result(tonic::Request::new(req_id_clone.clone()))
                        .await;
                    let mut ctr = 0u64;
                    while response.is_err()
                        && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
                    {
                        // wait for 4*bits ms before the next query, but at least 100ms and at most 1s.
                        tokio::time::sleep(tokio::time::Duration::from_millis(
                            4 * bits.clamp(100, 1000),
                        ))
                        .await;
                        // do at most 600 retries (stop after max. 10 minutes for large types)
                        if ctr >= 600 {
                            panic!("timeout while waiting for decryption");
                        }
                        ctr += 1;
                        response = cur_client
                            .get_public_decryption_result(tonic::Request::new(req_id_clone.clone()))
                            .await;
                    }
                    (req_id_clone, response.unwrap().into_inner())
                });
            }
        }

        let mut resp_response_vec = Vec::new();
        while let Some(resp) = resp_tasks.join_next().await {
            resp_response_vec.push(resp.unwrap());
        }

        for req in &reqs {
            let req_id = req.request_id.as_ref().unwrap();
            let responses: Vec<_> = resp_response_vec
                .iter()
                .filter_map(|resp| {
                    if resp.0 == *req_id {
                        Some(resp.1.clone())
                    } else {
                        None
                    }
                })
                .collect();
            // Compute threshold < amount_parties/3
            let threshold = max_threshold(amount_parties);
            let min_count_agree = (threshold + 1) as u32;
            let received_plaintexts = internal_client
                .process_decryption_resp(Some(req.clone()), &responses, min_count_agree)
                .unwrap();

            // we need 1 plaintext for each ciphertext in the batch
            assert_eq!(received_plaintexts.len(), msgs.len());

            // check that the plaintexts are correct
            for (i, plaintext) in received_plaintexts.iter().enumerate() {
                assert_plaintext(&msgs[i], plaintext);
            }
        }
    }

    #[rstest::rstest]
    #[case(true, TestingPlaintext::U32(42), 10, &TEST_THRESHOLD_KEY_ID_10P, DecryptionMode::NoiseFloodSmall)]
    #[case(true, TestingPlaintext::Bool(true), 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
    #[case(true, TestingPlaintext::U8(88), 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
    #[case(true, TestingPlaintext::U32(u32::MAX), 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
    #[case(false, TestingPlaintext::U32(u32::MAX), 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
    #[case(true, TestingPlaintext::U80((1u128 << 80) - 1), 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
    #[case(true, TestingPlaintext::U32(u32::MAX), 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::BitDecSmall)]
    #[case(false, TestingPlaintext::U32(u32::MAX), 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::BitDecSmall)]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_user_decryption_threshold(
        #[case] secure: bool,
        #[case] pt: TestingPlaintext,
        #[case] amount_parties: usize,
        #[case] key_id: &RequestId,
        #[case] decryption_mode: DecryptionMode,
    ) {
        user_decryption_threshold(
            TEST_PARAM,
            key_id,
            false,
            pt,
            EncryptionConfig {
                compression: true,
                precompute_sns: false,
            },
            4,
            secure,
            amount_parties,
            None,
            None,
            Some(decryption_mode),
        )
        .await;
    }

    #[rstest::rstest]
    #[case(TestingPlaintext::U32(u32::MAX), &TEST_THRESHOLD_KEY_ID_4P, vec![1])]
    #[case(TestingPlaintext::U32(u32::MAX), &TEST_THRESHOLD_KEY_ID_4P, vec![4])]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_user_decryption_threshold_malicious(
        #[case] pt: TestingPlaintext,
        #[case] key_id: &RequestId,
        #[case] malicious_set: Vec<u32>,
    ) {
        user_decryption_threshold(
            TEST_PARAM,
            key_id,
            false,
            pt,
            EncryptionConfig {
                compression: true,
                precompute_sns: false,
            },
            1,    // parallelism
            true, // secure
            4,    // no. of parties
            None,
            Some(malicious_set),
            None,
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    #[should_panic]
    async fn test_user_decryption_threshold_malicious_failure() {
        // should panic because the malicious set is too big
        user_decryption_threshold(
            TEST_PARAM,
            &TEST_THRESHOLD_KEY_ID_4P,
            false,
            TestingPlaintext::U32(u32::MAX),
            EncryptionConfig {
                compression: true,
                precompute_sns: false,
            },
            1,    // parallelism
            true, // secure
            4,    // no. of parties
            None,
            Some(vec![1, 4]),
            None,
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    #[should_panic]
    async fn test_user_decryption_threshold_all_malicious_failure() {
        // should panic because the malicious set is too big
        user_decryption_threshold(
            TEST_PARAM,
            &TEST_THRESHOLD_KEY_ID_4P,
            false,
            TestingPlaintext::U16(u16::MAX),
            EncryptionConfig {
                compression: true,
                precompute_sns: false,
            },
            1,    // parallelism
            true, // secure
            4,    // no. of parties
            None,
            Some(vec![1, 2, 3, 4]), // all parties are malicious
            None,
        )
        .await;
    }

    #[rstest::rstest]
    #[case(true, 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
    #[case(false, 4, &TEST_THRESHOLD_KEY_ID_4P, DecryptionMode::NoiseFloodSmall)]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_user_decryption_threshold_precompute_sns(
        #[case] secure: bool,
        #[case] amount_parties: usize,
        #[case] key_id: &RequestId,
        #[case] decryption_mode: DecryptionMode,
    ) {
        user_decryption_threshold(
            TEST_PARAM,
            key_id,
            false,
            TestingPlaintext::U8(42),
            EncryptionConfig {
                compression: false,
                precompute_sns: true,
            },
            4,
            secure,
            amount_parties,
            None,
            None,
            Some(decryption_mode),
        )
        .await;
    }

    #[cfg(feature = "wasm_tests")]
    #[rstest::rstest]
    #[case(true, 4, &TEST_THRESHOLD_KEY_ID_4P)]
    #[case(false, 4, &TEST_THRESHOLD_KEY_ID_4P)]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_user_decryption_threshold_and_write_transcript(
        #[case] secure: bool,
        #[case] amount_parties: usize,
        #[case] key_id: &RequestId,
    ) {
        user_decryption_threshold(
            TEST_PARAM,
            key_id,
            true,
            TestingPlaintext::U8(42),
            EncryptionConfig {
                compression: true,
                precompute_sns: false,
            },
            1,
            secure,
            amount_parties,
            None,
            None,
            None,
        )
        .await;
    }

    // The transcripts only need to be 4 parties, it's used for js tests
    #[cfg(all(feature = "wasm_tests", feature = "slow_tests"))]
    #[rstest::rstest]
    #[case(TestingPlaintext::U8(u8::MAX), 4, &DEFAULT_THRESHOLD_KEY_ID_4P)]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn default_user_decryption_threshold_and_write_transcript(
        #[case] msg: TestingPlaintext,
        #[case] amount_parties: usize,
        #[case] key_id: &RequestId,
        #[values(true, false)] secure: bool,
    ) {
        use crate::consts::DEFAULT_PARAM;

        user_decryption_threshold(
            DEFAULT_PARAM,
            key_id,
            true,
            msg,
            EncryptionConfig {
                compression: true,
                precompute_sns: false,
            },
            1, // wasm tests are single-threaded
            secure,
            amount_parties,
            None,
            None,
            None,
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[rstest::rstest]
    #[case(TestingPlaintext::Bool(true), 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P)]
    #[case(TestingPlaintext::U8(u8::MAX), 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P)]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn default_user_decryption_threshold(
        #[case] msg: TestingPlaintext,
        #[case] parallelism: usize,
        #[case] amount_parties: usize,
        #[case] key_id: &RequestId,
        #[values(true)] secure: bool,
    ) {
        use crate::consts::DEFAULT_PARAM;

        user_decryption_threshold(
            DEFAULT_PARAM,
            key_id,
            false,
            msg,
            EncryptionConfig {
                compression: true,
                precompute_sns: false,
            },
            parallelism,
            secure,
            amount_parties,
            None,
            None,
            None,
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[rstest::rstest]
    #[case(TestingPlaintext::U8(u8::MAX), 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P)]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn default_user_decryption_threshold_precompute_sns(
        #[case] msg: TestingPlaintext,
        #[case] parallelism: usize,
        #[case] amount_parties: usize,
        #[case] key_id: &RequestId,
        #[values(true)] secure: bool,
    ) {
        use crate::consts::DEFAULT_PARAM;

        user_decryption_threshold(
            DEFAULT_PARAM,
            key_id,
            false,
            msg,
            EncryptionConfig {
                compression: false,
                precompute_sns: true,
            },
            parallelism,
            secure,
            amount_parties,
            None,
            None,
            None,
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[rstest::rstest]
    #[case(TestingPlaintext::U8(u8::MAX), 1, 4,Some(vec![2]), &DEFAULT_THRESHOLD_KEY_ID_4P)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn default_user_decryption_threshold_with_crash(
        #[case] msg: TestingPlaintext,
        #[case] parallelism: usize,
        #[case] amount_parties: usize,
        #[case] party_ids_to_crash: Option<Vec<usize>>,
        #[case] key_id: &RequestId,
        #[values(true, false)] secure: bool,
    ) {
        use crate::consts::DEFAULT_PARAM;

        user_decryption_threshold(
            DEFAULT_PARAM,
            key_id,
            false,
            msg,
            EncryptionConfig {
                compression: true,
                precompute_sns: false,
            },
            parallelism,
            secure,
            amount_parties,
            party_ids_to_crash,
            None,
            None,
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    async fn process_batch_threshold_user_decryption(
        internal_client: &mut Client,
        msg: TestingPlaintext,
        secure: bool,
        amount_parties: usize,
        malicious_parties: Option<Vec<u32>>,
        party_ids_to_crash: Vec<usize>,
        reqs: Vec<(UserDecryptionRequest, PublicEncKey, PrivateEncKey)>,
        response_map: HashMap<RequestId, Vec<UserDecryptionResponse>>,
        server_private_keys: HashMap<u32, PrivateSigKey>,
    ) {
        for req in &reqs {
            let (req, enc_pk, enc_sk) = req;
            let request_id = req
                .request_id
                .clone()
                .expect("Retrieving request_id failed");
            let mut responses = response_map
                .get(&request_id.into())
                .expect("Retrieving responses failed")
                .clone();
            let domain = protobuf_to_alloy_domain(req.domain.as_ref().unwrap())
                .expect("Retrieving domain failed");
            let client_req = ParsedUserDecryptionRequest::try_from(req)
                .expect("Parsing UserDecryptionRequest failed");
            let threshold = responses.first().unwrap().payload.as_ref().unwrap().degree as usize;
            // NOTE: throw away one response and it should still work.
            let plaintexts = if secure {
                // test with one fewer response if we haven't crashed too many parties already
                let result_from_dropped_response = if threshold > party_ids_to_crash.len() {
                    Some(
                        internal_client
                            .process_user_decryption_resp(
                                &client_req,
                                &domain,
                                &responses[1..],
                                enc_pk,
                                enc_sk,
                            )
                            .unwrap(),
                    )
                } else {
                    None
                };

                // modify the responses if there are malicious parties
                // note that we also need to sign the modified payload
                responses.iter_mut().for_each(|resp| {
                    if let Some(payload) = &mut resp.payload {
                        if let Some(mal_parties) = &malicious_parties {
                            if mal_parties.contains(&payload.party_id) {
                                let orig_party_id = payload.party_id;
                                // Modify the party ID maliciously
                                if payload.party_id == 1 {
                                    payload.party_id = amount_parties as u32;
                                } else {
                                    payload.party_id -= 1;
                                }
                                let sig_payload_vec = bc2wrap::serialize(&payload).unwrap();
                                let sig = crate::cryptography::signcryption::internal_sign(
                                    &DSEP_USER_DECRYPTION,
                                    &sig_payload_vec,
                                    &server_private_keys[&orig_party_id],
                                )
                                .unwrap();
                                resp.signature = sig.sig.to_vec();
                            }
                        }
                    }
                });

                // test with all responses, some may be malicious
                let final_result = internal_client
                    .process_user_decryption_resp(&client_req, &domain, &responses, enc_pk, enc_sk)
                    .unwrap();

                if let Some(res) = result_from_dropped_response {
                    assert_eq!(res, final_result)
                }
                final_result
            } else {
                // insecure processing
                internal_client.server_identities = ServerIdentities::Addrs(HashMap::new());
                // test with one fewer response if we haven't crashed too many parties already
                let result_from_dropped_response = if threshold > party_ids_to_crash.len() {
                    Some(
                        internal_client
                            .insecure_process_user_decryption_resp(&responses[1..], enc_pk, enc_sk)
                            .unwrap(),
                    )
                } else {
                    None
                };

                // test with all responses
                let final_result = internal_client
                    .insecure_process_user_decryption_resp(&responses, enc_pk, enc_sk)
                    .unwrap();
                if let Some(res) = result_from_dropped_response {
                    assert_eq!(res, final_result)
                }
                final_result
            };
            for plaintext in plaintexts {
                assert_plaintext(&msg, &plaintext);
            }
        }
    }

    async fn get_server_private_keys(amount_parties: usize) -> HashMap<u32, PrivateSigKey> {
        let mut server_private_keys = HashMap::new();
        for i in 1..=amount_parties {
            let priv_storage =
                FileStorage::new(None, StorageType::PRIV, Some(Role::indexed_from_one(i))).unwrap();
            let sk = get_core_signing_key(&priv_storage)
                .await
                .inspect_err(|e| {
                    tracing::error!("signing key hashmap is not exactly 1, {}", e);
                })
                .unwrap();
            server_private_keys.insert(i as u32, sk);
        }
        server_private_keys
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn user_decryption_threshold(
        dkg_params: DKGParams,
        key_id: &RequestId,
        write_transcript: bool,
        msg: TestingPlaintext,
        enc_config: EncryptionConfig,
        parallelism: usize,
        secure: bool,
        amount_parties: usize,
        party_ids_to_crash: Option<Vec<usize>>,
        malicious_parties: Option<Vec<u32>>,
        decryption_mode: Option<DecryptionMode>,
    ) {
        assert!(parallelism > 0);
        _ = write_transcript;
        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
        let (mut kms_servers, mut kms_clients, mut internal_client) =
            threshold_handles(dkg_params, amount_parties, true, None, decryption_mode).await;
        let (ct, ct_format, fhe_type) =
            compute_cipher_from_stored_key(None, msg, key_id, enc_config).await;

        // make requests
        let reqs: Vec<_> = (0..parallelism)
            .map(|j| {
                let request_id = derive_request_id(&format!("TEST_USER_DECRYPT_ID_{j}")).unwrap();
                let typed_ciphertexts = vec![TypedCiphertext {
                    ciphertext: ct.clone(),
                    fhe_type: fhe_type as i32,
                    ciphertext_format: ct_format.into(),
                    external_handle: j.to_be_bytes().to_vec(),
                }];
                let (req, enc_pk, enc_sk) = internal_client
                    .user_decryption_request(
                        &dummy_domain(),
                        typed_ciphertexts,
                        &request_id,
                        &key_id.to_string().try_into().unwrap(),
                    )
                    .unwrap();
                (req, enc_pk, enc_sk)
            })
            .collect();
        // Either send the request, or crash the party if it's in
        // party_ids_to_crash
        let mut req_tasks = JoinSet::new();
        let party_ids_to_crash = party_ids_to_crash.unwrap_or_default();
        for j in 0..parallelism {
            for i in 1..=amount_parties as u32 {
                if party_ids_to_crash.contains(&(i as usize)) {
                    // After the first "parallel" iteration the party is already crashed
                    if j > 0 {
                        continue;
                    }
                    let server_handle = kms_servers.remove(&i).unwrap();
                    server_handle.assert_shutdown().await;
                    let _kms_client = kms_clients.remove(&i).unwrap();
                } else {
                    let mut cur_client = kms_clients.get(&i).unwrap().clone();
                    let req_clone = reqs.get(j).as_ref().unwrap().0.clone();
                    req_tasks.spawn(async move {
                        cur_client
                            .user_decrypt(tonic::Request::new(req_clone))
                            .await
                    });
                }
            }
        }
        let mut req_response_vec = Vec::new();
        while let Some(resp) = req_tasks.join_next().await {
            req_response_vec.push(resp.unwrap().unwrap().into_inner());
        }
        assert_eq!(
            req_response_vec.len(),
            (amount_parties - party_ids_to_crash.len()) * parallelism
        );

        let mut resp_tasks = JoinSet::new();
        for j in 0..parallelism {
            for i in 1..=amount_parties as u32 {
                if party_ids_to_crash.contains(&(i as usize)) {
                    continue;
                }
                let mut cur_client = kms_clients.get(&i).unwrap().clone();
                let req_id_clone = reqs.get(j).as_ref().unwrap().0.clone().request_id.unwrap();
                let bits = msg.bits() as u64;
                resp_tasks.spawn(async move {
                    // Sleep to give the server some time to complete user decryption
                    tokio::time::sleep(tokio::time::Duration::from_millis(
                        100 * bits * parallelism as u64,
                    ))
                    .await;
                    let mut response = cur_client
                        .get_user_decryption_result(tonic::Request::new(req_id_clone.clone()))
                        .await;

                    let mut ctr = 0u64;
                    while response.is_err()
                        && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
                    {
                        // wait for 4*bits ms before the next query, but at least 100ms and at most 1s.
                        tokio::time::sleep(tokio::time::Duration::from_millis(
                            4 * bits.clamp(100, 1000),
                        ))
                        .await;
                        // do at most 600 retries (stop after max. 10 minutes for large types)
                        if ctr >= 600 {
                            panic!("timeout while waiting for user decryption");
                        }
                        ctr += 1;
                        response = cur_client
                            .get_user_decryption_result(tonic::Request::new(req_id_clone.clone()))
                            .await;
                    }

                    (req_id_clone, response)
                });
            }
        }
        let mut response_map: HashMap<RequestId, Vec<UserDecryptionResponse>> = HashMap::new();
        while let Some(res) = resp_tasks.join_next().await {
            let res = res.unwrap();
            tracing::info!("Client got a response from {}", res.0.request_id);
            let (req_id, resp) = res;
            if let Entry::Vacant(e) = response_map.entry(req_id.clone().into()) {
                e.insert(vec![resp.unwrap().into_inner()]);
            } else {
                response_map
                    .get_mut(&req_id.into())
                    .unwrap()
                    .push(resp.unwrap().into_inner());
            }
        }

        #[cfg(feature = "wasm_tests")]
        {
            assert_eq!(parallelism, 1);
            // Compute threshold < amount_parties/3
            let threshold = max_threshold(amount_parties);
            if write_transcript {
                // We write a plaintext/ciphertext to file as a workaround
                // for tfhe encryption on the wasm side since it cannot
                // be instantiated easily without a seeder and we don't
                // want to introduce extra npm dependency.

                // Observe there should only be one element in `response_map`
                let agg_resp = response_map.values().last().unwrap().clone();

                let transcript = TestingUserDecryptionTranscript {
                    server_addrs: internal_client.get_server_addrs(),
                    client_address: internal_client.client_address,
                    client_sk: internal_client.client_sk.clone(),
                    degree: threshold as u32,
                    params: internal_client.params,
                    fhe_types: vec![msg.fhe_type() as i32],
                    pts: vec![TypedPlaintext::from(msg).bytes.clone()],
                    cts: reqs[0]
                        .0
                        .typed_ciphertexts
                        .iter()
                        .map(|typed_ct| typed_ct.ciphertext.clone())
                        .collect::<Vec<_>>(),
                    request: Some(reqs[0].clone().0),
                    eph_sk: reqs[0].clone().2,
                    eph_pk: reqs[0].clone().1,
                    agg_resp,
                };
                let path_prefix = if dkg_params != PARAMS_TEST_BK_SNS {
                    crate::consts::DEFAULT_THRESHOLD_WASM_TRANSCRIPT_PATH
                } else {
                    crate::consts::TEST_THRESHOLD_WASM_TRANSCRIPT_PATH
                };
                let path = format!("{}.{}", path_prefix, msg.bits());
                write_element(&path, &transcript).await.unwrap();
            }
        }

        let server_private_keys = get_server_private_keys(amount_parties).await;

        process_batch_threshold_user_decryption(
            &mut internal_client,
            msg,
            secure,
            amount_parties,
            malicious_parties,
            party_ids_to_crash,
            reqs,
            response_map,
            server_private_keys,
        )
        .await
    }

    // Validate bug-fix to ensure that the server fails gracefully when the ciphertext is too large
    #[cfg(feature = "slow_tests")]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_largecipher() {
        use crate::{
            consts::DEFAULT_CENTRAL_KEY_ID,
            engine::centralized::central_kms::tests::{
                new_priv_ram_storage_from_existing_keys, new_pub_ram_storage_from_existing_keys,
            },
        };

        let keys = get_default_keys().await;
        let rate_limiter_conf = RateLimiterConfig {
            bucket_size: 100,
            pub_decrypt: 1,
            user_decrypt: 100,
            crsgen: 1,
            preproc: 1,
            keygen: 1,
        };
        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
        let (kms_server, mut kms_client) = super::test_tools::setup_centralized(
            new_pub_ram_storage_from_existing_keys(&keys.pub_fhe_keys)
                .await
                .unwrap(),
            new_priv_ram_storage_from_existing_keys(&keys.centralized_kms_keys)
                .await
                .unwrap(),
            Some(rate_limiter_conf),
        )
        .await;
        let ct = Vec::from([1_u8; 100000]);
        let fhe_type = FheTypes::Uint32;
        let ct_format = kms_grpc::kms::v1::CiphertextFormat::default();
        let client_address = alloy_primitives::Address::from_public_key(keys.client_pk.pk());
        let mut internal_client = Client::new(
            HashMap::from_iter(
                keys.server_keys
                    .iter()
                    .enumerate()
                    .map(|(i, key)| (i as u32 + 1, key.clone())),
            ),
            client_address,
            Some(keys.client_sk.clone()),
            keys.params,
            None,
        );
        let request_id = derive_request_id("TEST_USER_DECRYPT_ID_123").unwrap();
        let typed_ciphertexts = vec![TypedCiphertext {
            ciphertext: ct,
            fhe_type: fhe_type as i32,
            ciphertext_format: ct_format.into(),
            external_handle: vec![123],
        }];
        let (req, _enc_pk, _enc_sk) = internal_client
            .user_decryption_request(
                &dummy_domain(),
                typed_ciphertexts,
                &request_id,
                &DEFAULT_CENTRAL_KEY_ID,
            )
            .unwrap();
        let response = kms_client
            .user_decrypt(tonic::Request::new(req.clone()))
            .await
            .unwrap();
        assert_eq!(response.into_inner(), Empty {});

        let mut response = kms_client
            .get_user_decryption_result(req.request_id.clone().unwrap())
            .await;
        while response.is_err() && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
        {
            // Sleep to give the server some time to complete user decryption
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            response = kms_client
                .get_user_decryption_result(req.request_id.clone().unwrap())
                .await;
        }
        // Check that we get a server error instead of a server crash
        assert_eq!(response.as_ref().unwrap_err().code(), tonic::Code::Internal);
        assert!(response
            .err()
            .unwrap()
            .message()
            .contains("finished with an error"));
        tracing::info!("aborting");
        kms_server.assert_shutdown().await;
    }

    #[tokio::test]
    async fn num_blocks_sunshine() {
        let params: DKGParams = TEST_PARAM;
        let params = &params
            .get_params_basics_handle()
            .to_classic_pbs_parameters();
        // 2 bits per block, using Ebool as internal representation
        assert_eq!(fhe_types_to_num_blocks(FheTypes::Bool, params).unwrap(), 1);
        // 2 bits per block, using Euint4 as internal representation
        assert_eq!(fhe_types_to_num_blocks(FheTypes::Uint4, params).unwrap(), 2);
        // 2 bits per block
        assert_eq!(fhe_types_to_num_blocks(FheTypes::Uint8, params).unwrap(), 4);
        // 2 bits per block
        assert_eq!(
            fhe_types_to_num_blocks(FheTypes::Uint16, params).unwrap(),
            8
        );
        // 2 bits per block
        assert_eq!(
            fhe_types_to_num_blocks(FheTypes::Uint32, params).unwrap(),
            16
        );
        // 2 bits per block
        assert_eq!(
            fhe_types_to_num_blocks(FheTypes::Uint64, params).unwrap(),
            32
        );
        // 2 bits per block
        assert_eq!(
            fhe_types_to_num_blocks(FheTypes::Uint128, params).unwrap(),
            64
        );
        // 2 bits per block
        assert_eq!(
            fhe_types_to_num_blocks(FheTypes::Uint160, params).unwrap(),
            80
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    #[cfg(feature = "slow_tests")]
    #[serial]
    async fn test_ratelimiter() {
        let req_id: RequestId = derive_request_id("test_ratelimiter").unwrap();
        purge(None, None, &req_id, 4).await;
        let rate_limiter_conf = RateLimiterConfig {
            bucket_size: 100,
            pub_decrypt: 1,
            user_decrypt: 1,
            crsgen: 100,
            preproc: 1,
            keygen: 1,
        };
        let (_kms_servers, kms_clients, internal_client) =
            threshold_handles(TEST_PARAM, 4, true, Some(rate_limiter_conf), None).await;

        let req_id = derive_request_id("test rate limiter 1").unwrap();
        let req = internal_client
            .crs_gen_request(&req_id, Some(16), Some(FheParameter::Test), None)
            .unwrap();
        let mut cur_client = kms_clients.get(&1).unwrap().clone();
        let res = cur_client.crs_gen(req).await;
        // Check that first request is ok and accepted
        assert!(res.is_ok());
        // Try to do another request during preproc,
        // the request should be rejected due to rate limiter.
        // This should be done after the requests above start being
        // processed in the kms.
        let req_id_2 = derive_request_id("test rate limiter2").unwrap();
        let req_2 = internal_client
            .crs_gen_request(&req_id_2, Some(1), Some(FheParameter::Test), None)
            .unwrap();
        let res = cur_client.crs_gen(req_2).await;
        assert_eq!(res.unwrap_err().code(), tonic::Code::ResourceExhausted);
    }

    #[cfg(feature = "insecure")]
    #[rstest::rstest]
    #[case(4)]
    #[case(7)]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_insecure_dkg(#[case] amount_parties: usize) {
        let key_id: RequestId = derive_request_id(&format!(
            "test_inscure_dkg_key_{amount_parties}_{TEST_PARAM:?}"
        ))
        .unwrap();
        purge(None, None, &key_id, amount_parties).await;
        let (_kms_servers, kms_clients, internal_client) =
            threshold_handles(TEST_PARAM, amount_parties, true, None, None).await;
        let keys = run_keygen(
            FheParameter::Test,
            &kms_clients,
            &internal_client,
            None,
            &key_id,
            None,
            true,
        )
        .await;
        _ = keys.clone().get_standard();

        let panic_res = std::panic::catch_unwind(|| keys.get_decompression_only());
        assert!(panic_res.is_err());
    }

    #[cfg(feature = "insecure")]
    #[rstest::rstest]
    #[case(4)]
    #[case(7)]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn default_insecure_dkg(#[case] amount_parties: usize) {
        use crate::engine::base::derive_request_id;

        let param = FheParameter::Default;
        let dkg_param: WrappedDKGParams = param.into();

        let key_id: RequestId = derive_request_id(&format!(
            "default_insecure_dkg_key_{amount_parties}_{param:?}",
        ))
        .unwrap();
        purge(None, None, &key_id, amount_parties).await;
        let (_kms_servers, kms_clients, internal_client) =
            threshold_handles(*dkg_param, amount_parties, true, None, None).await;
        let keys = run_keygen(
            param,
            &kms_clients,
            &internal_client,
            None,
            &key_id,
            None,
            true,
        )
        .await;

        // check that we have the new mod switch key
        let (client_key, _, server_key) = keys.clone().get_standard();
        check_conformance(server_key, client_key);

        let panic_res = std::panic::catch_unwind(|| keys.get_decompression_only());
        assert!(panic_res.is_err());
    }

    fn check_conformance(server_key: tfhe::ServerKey, client_key: tfhe::ClientKey) {
        let pbs_params = client_key.computation_parameters();
        let int_server_key: &tfhe::integer::ServerKey = server_key.as_ref();
        let shortint_server_key: &tfhe::shortint::ServerKey = int_server_key.as_ref();
        let max_degree = shortint_server_key.max_degree; // we don't really check the max degree
        assert!(shortint_server_key.is_conformant(&(pbs_params, max_degree)));

        match &shortint_server_key.bootstrapping_key {
            tfhe::shortint::server_key::ShortintBootstrappingKey::Classic {
                bsk: _bsk,
                modulus_switch_noise_reduction_key,
            } => {
                assert!(modulus_switch_noise_reduction_key.is_some());

                // Check that we can decrypt this key to 0
                let zeros_ct = modulus_switch_noise_reduction_key
                    .as_ref()
                    .map(|x| x.modulus_switch_zeros.clone())
                    .unwrap();
                let (client_key, _compact_client_key, _compression_key, _noise_squashing_key, _tag) =
                    client_key.into_raw_parts();

                // We need to make a reference ciphertext to convert
                // the zero ciphertexts into a Ciphertext Type
                let ct_reference = client_key.encrypt_one_block(0);
                for ct in zeros_ct.iter() {
                    let ctt = tfhe::shortint::Ciphertext::new(
                        LweCiphertextOwned::from_container(
                            ct.into_container().to_vec(),
                            ct.ciphertext_modulus(),
                        ),
                        ct_reference.degree,
                        ct_reference.noise_level(),
                        ct_reference.message_modulus,
                        ct_reference.carry_modulus,
                        tfhe::shortint::PBSOrder::BootstrapKeyswitch,
                    );
                    let pt = client_key.decrypt_one_block(&ctt);
                    assert_eq!(pt, 0);
                }
            }
            _ => panic!("expected classic bsk"),
        }
    }

    #[cfg(all(feature = "slow_tests", feature = "insecure"))]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_insecure_threshold_decompression_keygen() {
        // Note that the first 2 key gens are insecure, but the last is secure as needed to generate decompression keys
        run_threshold_decompression_keygen(4, FheParameter::Test, true).await;
    }

    #[cfg(feature = "slow_tests")]
    async fn run_threshold_decompression_keygen(
        amount_parties: usize,
        parameter: FheParameter,
        insecure: bool,
    ) {
        let preproc_id_1 = if insecure {
            None
        } else {
            Some(
                derive_request_id(&format!(
                    "decom_dkg_preproc_{amount_parties}_{parameter:?}_1"
                ))
                .unwrap(),
            )
        };
        let key_id_1: RequestId =
            derive_request_id(&format!("decom_dkg_key_{amount_parties}_{parameter:?}_1")).unwrap();
        purge(None, None, &key_id_1, amount_parties).await;

        let preproc_id_2 = if insecure {
            None
        } else {
            Some(
                derive_request_id(&format!(
                    "decom_dkg_preproc_{amount_parties}_{parameter:?}_2"
                ))
                .unwrap(),
            )
        };
        let key_id_2: RequestId =
            derive_request_id(&format!("decom_dkg_key_{amount_parties}_{parameter:?}_2")).unwrap();
        purge(None, None, &key_id_2, amount_parties).await;

        let preproc_id_3 = derive_request_id(&format!(
            "decom_dkg_preproc_{amount_parties}_{parameter:?}_3"
        ))
        .unwrap();
        let key_id_3: RequestId =
            derive_request_id(&format!("decom_dkg_key_{amount_parties}_{parameter:?}_3")).unwrap();
        purge(None, None, &key_id_3, amount_parties).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
        let dkg_param: WrappedDKGParams = parameter.into();
        let (kms_servers, kms_clients, internal_client) =
            threshold_handles(*dkg_param, amount_parties, true, None, None).await;

        if !insecure {
            run_preproc(
                amount_parties,
                parameter,
                &kms_clients,
                &internal_client,
                &preproc_id_1.unwrap(),
                None,
            )
            .await;
        }

        let keys1 = run_keygen(
            parameter,
            &kms_clients,
            &internal_client,
            preproc_id_1,
            &key_id_1,
            None,
            insecure,
        )
        .await;
        let (client_key_1, _public_key_1, server_key_1) = keys1.get_standard();

        if !insecure {
            run_preproc(
                amount_parties,
                parameter,
                &kms_clients,
                &internal_client,
                &preproc_id_2.unwrap(),
                None,
            )
            .await;
        }

        let keys2 = run_keygen(
            parameter,
            &kms_clients,
            &internal_client,
            preproc_id_2,
            &key_id_2,
            None,
            insecure,
        )
        .await;
        let (client_key_2, _public_key_2, _server_key_2) = keys2.get_standard();

        // We always need to run preproc for the last keygen
        run_preproc(
            amount_parties,
            parameter,
            &kms_clients,
            &internal_client,
            &preproc_id_3,
            None,
        )
        .await;

        // finally do the decompression keygen between the first and second keysets
        let decompression_key = run_keygen(
            parameter,
            &kms_clients,
            &internal_client,
            Some(preproc_id_3),
            &key_id_3,
            Some((key_id_1, key_id_2)),
            insecure,
        )
        .await
        .get_decompression_only();

        for handle in kms_servers.into_values() {
            handle.assert_shutdown().await;
        }

        run_decompression_test(
            &client_key_1,
            &client_key_2,
            Some(&server_key_1),
            decompression_key.into_raw_parts(),
        );
    }

    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    #[allow(dead_code)]
    #[allow(clippy::large_enum_variant)]
    #[derive(Clone)]
    enum TestKeyGenResult {
        DecompressionOnly(DecompressionKey),
        Standard((tfhe::ClientKey, tfhe::CompactPublicKey, tfhe::ServerKey)),
    }

    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    #[allow(dead_code)]
    impl TestKeyGenResult {
        fn get_decompression_only(self) -> tfhe::integer::compression_keys::DecompressionKey {
            match self {
                TestKeyGenResult::DecompressionOnly(inner) => inner,
                TestKeyGenResult::Standard(_) => panic!("expecting to match decompression only"),
            }
        }

        fn get_standard(self) -> (tfhe::ClientKey, tfhe::CompactPublicKey, tfhe::ServerKey) {
            match self {
                TestKeyGenResult::DecompressionOnly(_) => panic!("expected to find standard"),
                TestKeyGenResult::Standard(inner) => inner,
            }
        }
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn secure_threshold_keygen_test() {
        preproc_and_keygen(4, FheParameter::Test, false, 1, false).await;
    }

    #[cfg(feature = "slow_tests")]
    async fn preproc_and_keygen(
        amount_parties: usize,
        parameter: FheParameter,
        insecure: bool,
        iterations: usize,
        concurrent: bool,
    ) {
        for i in 0..iterations {
            let req_preproc: RequestId = derive_request_id(&format!(
                "full_dkg_preproc_{amount_parties}_{parameter:?}_{i}"
            ))
            .unwrap();
            purge(None, None, &req_preproc, amount_parties).await;
            let req_key: RequestId =
                derive_request_id(&format!("full_dkg_key_{amount_parties}_{parameter:?}_{i}"))
                    .unwrap();
            purge(None, None, &req_key, amount_parties).await;
        }

        let dkg_param: WrappedDKGParams = parameter.into();
        // Preproc should use all the tokens in the bucket,
        // then they're returned to the bucket before keygen starts.
        // If something is wrong with the rate limiter logic
        // then the keygen step should fail since there are not enough tokens.
        let rate_limiter_conf = RateLimiterConfig {
            bucket_size: 100 * 2 * iterations, // Ensure the bucket is big enough to carry out the concurrent requests
            pub_decrypt: 1,
            user_decrypt: 1,
            crsgen: 1,
            preproc: 100,
            keygen: 100,
        };

        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
        let (_kms_servers, kms_clients, internal_client) = threshold_handles(
            *dkg_param,
            amount_parties,
            true,
            Some(rate_limiter_conf),
            None,
        )
        .await;

        if concurrent {
            let arc_clients = Arc::new(kms_clients);
            let arc_internalclient = Arc::new(internal_client);
            let mut preprocset = JoinSet::new();
            let mut preproc_ids = HashMap::new();
            for i in 0..iterations {
                let cur_id: RequestId = derive_request_id(&format!(
                    "full_dkg_preproc_{amount_parties}_{parameter:?}_{i}"
                ))
                .unwrap();
                preproc_ids.insert(i, cur_id);
                preprocset.spawn({
                    let clients_clone = Arc::clone(&arc_clients);
                    let internalclient_clone = Arc::clone(&arc_internalclient);
                    async move {
                        run_preproc(
                            amount_parties,
                            parameter,
                            &clients_clone,
                            &internalclient_clone,
                            &cur_id,
                            None,
                        )
                        .await
                    }
                });
            }
            // Ensure preprocessing is done, otherwise we risk getting blocked by the rate limiter in keygen
            preprocset.join_all().await;
            let mut keyset = JoinSet::new();
            for i in 0..iterations {
                let key_id: RequestId =
                    derive_request_id(&format!("full_dkg_key_{amount_parties}_{parameter:?}_{i}"))
                        .unwrap();
                let preproc_ids_clone = preproc_ids.get(&i).unwrap().to_owned();
                keyset.spawn({
                    let clients_clone = Arc::clone(&arc_clients);
                    let internalclient_clone = Arc::clone(&arc_internalclient);
                    async move {
                        // todo proper use of insecure to skip preproc
                        run_keygen(
                            parameter,
                            &clients_clone,
                            &internalclient_clone,
                            Some(preproc_ids_clone),
                            &key_id,
                            None,
                            insecure,
                        )
                        .await
                    }
                });
            }
            let all_key_sets = keyset.join_all().await;
            for keyset in all_key_sets {
                // blockchain parameters always have mod switch noise reduction key
                let (client_key, _, server_key) = keyset.get_standard();
                check_conformance(server_key, client_key);
            }
            tracing::info!("Finished concurrent preproc and keygen");
        } else {
            let mut preproc_ids = HashMap::new();
            for i in 0..iterations {
                let cur_id: RequestId = derive_request_id(&format!(
                    "full_dkg_preproc_{amount_parties}_{parameter:?}_{i}"
                ))
                .unwrap();
                run_preproc(
                    amount_parties,
                    parameter,
                    &kms_clients,
                    &internal_client,
                    &cur_id,
                    None,
                )
                .await;
                preproc_ids.insert(i, cur_id);
            }
            for i in 0..iterations {
                let key_id: RequestId =
                    derive_request_id(&format!("full_dkg_key_{amount_parties}_{parameter:?}_{i}"))
                        .unwrap();
                let keyset = run_keygen(
                    parameter,
                    &kms_clients,
                    &internal_client,
                    Some(preproc_ids.get(&i).unwrap().to_owned()),
                    &key_id,
                    None,
                    insecure,
                )
                .await;
                // blockchain parameters always have mod switch noise reduction key
                let (client_key, _, server_key) = keyset.get_standard();
                check_conformance(server_key, client_key);
            }
            tracing::info!("Finished sequential preproc and keygen");
        }
    }

    // TODO parallel preproc needs to be investigated, there are two issues
    // 1. for parallelism=4, it took 700, parallelism=2 is 300s, but parallelism=1 is 100s,
    // so running preproc in parallel is slower than sequential
    // 2. for parallelism=4, sometimes (not always) it fails with
    // kms_lib-9439e559ff01deb4(86525,0x16e223000) malloc: Heap corruption detected, free list is damaged at 0x600000650510
    // *** Incorrect guard value: 0
    // issue: https://github.com/zama-ai/kms-core/issues/663
    #[cfg(feature = "slow_tests")]
    async fn run_preproc(
        amount_parties: usize,
        parameter: FheParameter,
        kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
        internal_client: &Client,
        preproc_req_id: &RequestId,
        decompression_keygen: Option<(RequestId, RequestId)>,
    ) {
        let keyset_config = decompression_keygen.as_ref().map(|_| KeySetConfig {
            keyset_type: KeySetType::DecompressionOnly.into(),
            standard_keyset_config: None,
        });
        let preproc_request = internal_client
            .preproc_request(preproc_req_id, Some(parameter), keyset_config)
            .unwrap();

        // Execute preprocessing
        let mut tasks_gen = JoinSet::new();
        for i in 1..=amount_parties as u32 {
            let mut cur_client = kms_clients.get(&i).unwrap().clone();
            let req_clone = preproc_request.clone();
            tasks_gen.spawn(async move {
                cur_client
                    .key_gen_preproc(tonic::Request::new(req_clone))
                    .await
            });
        }
        let preproc_res = tasks_gen.join_all().await;
        preproc_res.iter().for_each(|x| {
            assert!(x.is_ok());
        });
        assert_eq!(preproc_res.len(), amount_parties);

        // the responses should be empty
        let _responses = poll_key_gen_preproc_result(preproc_request, kms_clients, MAX_TRIES).await;
    }

    //Check status of preproc request
    #[cfg(feature = "slow_tests")]
    async fn poll_key_gen_preproc_result(
        request: kms_grpc::kms::v1::KeyGenPreprocRequest,
        kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
        max_iter: usize,
    ) -> Vec<kms_grpc::kms::v1::KeyGenPreprocResult> {
        let mut resp_tasks = JoinSet::new();
        for (_, client) in kms_clients.iter() {
            let mut client = client.clone();
            let req_id_clone = request.request_id.as_ref().unwrap().clone();

            resp_tasks.spawn(async move {
                // Sleep to give the server some time to complete preprocessing
                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

                let mut response = client
                    .get_key_gen_preproc_result(tonic::Request::new(req_id_clone.clone()))
                    .await;
                let mut ctr = 0_usize;
                while response.is_err()
                    && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
                {
                    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                    if ctr >= max_iter {
                        panic!("timeout while waiting for preprocessing after {max_iter} retries");
                    }
                    ctr += 1;
                    response = client
                        .get_key_gen_preproc_result(tonic::Request::new(req_id_clone.clone()))
                        .await;
                }

                (req_id_clone, response.unwrap().into_inner())
            });
        }

        let mut resp_response_vec = Vec::new();
        while let Some(resp) = resp_tasks.join_next().await {
            // any failures that happen will panic here
            resp_response_vec.push(resp.unwrap().1);
        }
        resp_response_vec
    }

    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    async fn run_keygen(
        parameter: FheParameter,
        kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
        internal_client: &Client,
        preproc_req_id: Option<RequestId>,
        keygen_req_id: &RequestId,
        decompression_keygen: Option<(RequestId, RequestId)>,
        insecure: bool,
    ) -> TestKeyGenResult {
        let keyset_config = decompression_keygen.as_ref().map(|_| KeySetConfig {
            keyset_type: KeySetType::DecompressionOnly.into(),
            standard_keyset_config: None,
        });
        let keyset_added_info = decompression_keygen.map(|(from, to)| KeySetAddedInfo {
            compression_keyset_id: None,
            from_keyset_id_decompression_only: Some(from.into()),
            to_keyset_id_decompression_only: Some(to.into()),
        });

        let req_keygen = internal_client
            .key_gen_request(
                keygen_req_id,
                preproc_req_id,
                Some(parameter),
                keyset_config,
                keyset_added_info,
                None,
            )
            .unwrap();

        let responses = launch_dkg(req_keygen.clone(), kms_clients, insecure).await;
        for response in responses {
            assert!(response.is_ok());
        }

        wait_for_keygen_result(
            req_keygen.request_id.clone().try_into().unwrap(),
            preproc_req_id,
            kms_clients,
            internal_client,
            insecure,
            decompression_keygen.is_some(),
        )
        .await
    }

    //Helper function to launch dkg
    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    async fn launch_dkg(
        req_keygen: kms_grpc::kms::v1::KeyGenRequest,
        kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
        insecure: bool,
    ) -> Vec<Result<tonic::Response<Empty>, tonic::Status>> {
        let mut tasks_gen = JoinSet::new();
        for i in 1..=kms_clients.len() as u32 {
            //Send kg request
            let mut cur_client = kms_clients.get(&i).unwrap().clone();
            let req_clone = req_keygen.clone();
            tasks_gen.spawn(async move {
                if insecure {
                    #[cfg(feature = "insecure")]
                    {
                        cur_client
                            .insecure_key_gen(tonic::Request::new(req_clone))
                            .await
                    }
                    #[cfg(not(feature = "insecure"))]
                    {
                        panic!("cannot perform insecure key gen")
                    }
                } else {
                    cur_client.key_gen(tonic::Request::new(req_clone)).await
                }
            });
        }

        let mut responses_gen = Vec::new();
        while let Some(resp) = tasks_gen.join_next().await {
            responses_gen.push(resp.unwrap());
        }
        responses_gen
    }

    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    async fn wait_for_keygen_result(
        req_get_keygen: RequestId,
        req_preproc: Option<RequestId>,
        kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
        internal_client: &Client,
        insecure: bool,
        decompression_keygen: bool,
    ) -> TestKeyGenResult {
        use threshold_fhe::execution::{
            runtime::party::Role, tfhe_internals::test_feature::to_hl_client_key,
        };

        let mut finished = Vec::new();
        // Wait at most MAX_TRIES times 15 seconds for all preprocessing to finish
        for _ in 0..MAX_TRIES {
            tokio::time::sleep(tokio::time::Duration::from_secs(if insecure {
                1
            } else {
                15
            }))
            .await;

            let mut tasks = JoinSet::new();
            for i in 1..=kms_clients.len() as u32 {
                let req_clone = req_get_keygen.into();
                let mut cur_client = kms_clients.get(&i).unwrap().clone();
                tasks.spawn(async move {
                    (
                        i,
                        if insecure {
                            #[cfg(feature = "insecure")]
                            {
                                cur_client
                                    .get_insecure_key_gen_result(tonic::Request::new(req_clone))
                                    .await
                            }
                            #[cfg(not(feature = "insecure"))]
                            {
                                panic!("cannot perform insecure keygen")
                            }
                        } else {
                            cur_client
                                .get_key_gen_result(tonic::Request::new(req_clone))
                                .await
                        },
                    )
                });
            }
            let mut responses = Vec::new();
            while let Some(resp) = tasks.join_next().await {
                responses.push(resp.unwrap());
            }

            finished = responses
                .into_iter()
                .filter(|x| x.1.is_ok())
                .collect::<Vec<_>>();
            if finished.len() == kms_clients.len() {
                break;
            }
        }

        finished.sort_by(|(i, _), (j, _)| i.cmp(j));
        assert_eq!(finished.len(), kms_clients.len());

        let mut out = None;
        if decompression_keygen {
            let mut serialized_ref_decompression_key = Vec::new();
            for (idx, kg_res) in finished.into_iter() {
                let role = Role::indexed_from_one(idx as usize);
                let kg_res = kg_res.unwrap().into_inner();
                let storage = FileStorage::new(None, StorageType::PUB, Some(role)).unwrap();
                let decompression_key: Option<DecompressionKey> = internal_client
                    .retrieve_key(&kg_res, PubDataType::DecompressionKey, &storage)
                    .await
                    .unwrap();
                assert!(decompression_key.is_some());
                if role.one_based() == 1 {
                    serialized_ref_decompression_key =
                        bc2wrap::serialize(decompression_key.as_ref().unwrap()).unwrap();
                } else {
                    assert_eq!(
                        serialized_ref_decompression_key,
                        bc2wrap::serialize(decompression_key.as_ref().unwrap()).unwrap()
                    )
                }
                if out.is_none() {
                    out = Some(TestKeyGenResult::DecompressionOnly(
                        decompression_key.unwrap(),
                    ))
                }
            }
        } else {
            let mut serialized_ref_pk = Vec::new();
            let mut serialized_ref_server_key = Vec::new();
            let mut all_threshold_fhe_keys = HashMap::new();
            let mut final_public_key = None;
            let mut final_server_key = None;
            for (idx, kg_res) in finished.into_iter() {
                let role = Role::indexed_from_one(idx as usize);
                let kg_res = kg_res.unwrap().into_inner();
                let storage = FileStorage::new(None, StorageType::PUB, Some(role)).unwrap();
                let pk = internal_client
                    .retrieve_public_key(&kg_res, &storage)
                    .await
                    .unwrap();
                assert!(pk.is_some());
                if role.one_based() == 1 {
                    serialized_ref_pk = bc2wrap::serialize(pk.as_ref().unwrap()).unwrap();
                } else {
                    assert_eq!(
                        serialized_ref_pk,
                        bc2wrap::serialize(pk.as_ref().unwrap()).unwrap()
                    )
                }
                let server_key: Option<tfhe::ServerKey> = internal_client
                    .retrieve_server_key(&kg_res, &storage)
                    .await
                    .unwrap();
                assert!(server_key.is_some());
                if role.one_based() == 1 {
                    serialized_ref_server_key =
                        bc2wrap::serialize(server_key.as_ref().unwrap()).unwrap();
                } else {
                    assert_eq!(
                        serialized_ref_server_key,
                        bc2wrap::serialize(server_key.as_ref().unwrap()).unwrap()
                    )
                }

                let key_id =
                    RequestId::from_str(kg_res.request_id.unwrap().request_id.as_str()).unwrap();
                let priv_storage = FileStorage::new(None, StorageType::PRIV, Some(role)).unwrap();
                let mut threshold_fhe_keys: ThresholdFheKeys = priv_storage
                    .read_data(&key_id, &PrivDataType::FheKeyInfo.to_string())
                    .await
                    .unwrap();
                // we do not need the sns key to reconstruct, remove it to save memory
                threshold_fhe_keys.sns_key = None;
                all_threshold_fhe_keys.insert(role, threshold_fhe_keys);
                if final_public_key.is_none() {
                    final_public_key = match pk.unwrap() {
                        kms_grpc::rpc_types::WrappedPublicKeyOwned::Compact(inner) => Some(inner),
                    };
                }
                if final_server_key.is_none() {
                    final_server_key = server_key;
                }
            }

            let threshold = kms_clients.len().div_ceil(3) - 1;
            let (lwe_sk, glwe_sk, sns_glwe_sk) =
                try_reconstruct_shares(internal_client.params, threshold, all_threshold_fhe_keys);
            out = Some(TestKeyGenResult::Standard((
                to_hl_client_key(
                    &internal_client.params,
                    lwe_sk,
                    glwe_sk,
                    None,
                    None,
                    Some(sns_glwe_sk),
                )
                .unwrap(),
                final_public_key.unwrap(),
                final_server_key.unwrap(),
            )));
        }

        if !insecure {
            // Try to request another kg with the same preproc but another request id,
            // we should see that it fails because the preproc material is consumed.
            //
            // We only test for the secure variant of the dkg because the insecure
            // variant does not use preprocessing material.
            tracing::debug!("starting another dkg with a used preproc ID");
            let other_key_gen_id = derive_request_id("test_dkg other key id").unwrap();
            let keygen_req_data = internal_client
                .key_gen_request(
                    &other_key_gen_id,
                    req_preproc,
                    Some(FheParameter::Test),
                    None,
                    None,
                    None,
                )
                .unwrap();
            let responses = launch_dkg(keygen_req_data.clone(), kms_clients, insecure).await;
            for response in responses {
                assert_eq!(response.unwrap_err().code(), tonic::Code::NotFound);
            }
        }
        out.unwrap()
    }

    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    fn try_reconstruct_shares(
        param: DKGParams,
        threshold: usize,
        all_threshold_fhe_keys: HashMap<Role, crate::engine::threshold::service::ThresholdFheKeys>,
    ) -> (
        tfhe::core_crypto::prelude::LweSecretKeyOwned<u64>,
        tfhe::core_crypto::prelude::GlweSecretKeyOwned<u64>,
        tfhe::core_crypto::prelude::GlweSecretKeyOwned<u128>,
    ) {
        use tfhe::core_crypto::prelude::GlweSecretKeyOwned;
        use threshold_fhe::execution::{
            endpoints::keygen::GlweSecretKeyShareEnum, tfhe_internals::utils::reconstruct_bit_vec,
        };

        let param_handle = param.get_params_basics_handle();
        let lwe_shares = all_threshold_fhe_keys
            .iter()
            .map(|(k, v)| (*k, v.private_keys.lwe_compute_secret_key_share.data.clone()))
            .collect::<HashMap<_, _>>();
        let lwe_secret_key =
            reconstruct_bit_vec(lwe_shares, param_handle.lwe_dimension().0, threshold);
        let lwe_secret_key =
            tfhe::core_crypto::prelude::LweSecretKeyOwned::from_container(lwe_secret_key);

        let lwe_enc_shares = all_threshold_fhe_keys
            .iter()
            .map(|(k, v)| {
                (
                    *k,
                    v.private_keys.lwe_encryption_secret_key_share.data.clone(),
                )
            })
            .collect::<HashMap<_, _>>();
        _ = reconstruct_bit_vec(
            lwe_enc_shares,
            param_handle.lwe_hat_dimension().0,
            threshold,
        );

        // normal keygen should always give us a z128 glwe
        let glwe_shares = all_threshold_fhe_keys
            .iter()
            .map(|(k, v)| {
                (
                    *k,
                    match v.private_keys.glwe_secret_key_share.clone() {
                        GlweSecretKeyShareEnum::Z64(_) => {
                            panic!("expected z128 in glwe shares")
                        }
                        GlweSecretKeyShareEnum::Z128(inner) => inner.data,
                    },
                )
            })
            .collect::<HashMap<_, _>>();
        let glwe_sk = GlweSecretKeyOwned::from_container(
            reconstruct_bit_vec(glwe_shares, param_handle.glwe_sk_num_bits(), threshold),
            param_handle.polynomial_size(),
        );

        let sns_lwe_shares = all_threshold_fhe_keys
            .iter()
            .map(|(k, v)| (*k, v.private_keys.glwe_secret_key_share_sns_as_lwe.clone()))
            .filter_map(|(k, v)| match v {
                Some(vv) => Some((k, vv.data)),
                None => None,
            })
            .collect::<HashMap<_, _>>();
        let sns_param = match param {
            DKGParams::WithoutSnS(_) => panic!("missing sns param"),
            DKGParams::WithSnS(sns_param) => sns_param.sns_params,
        };
        let sns_glwe_sk = GlweSecretKeyOwned::from_container(
            reconstruct_bit_vec(
                sns_lwe_shares,
                sns_param
                    .glwe_dimension
                    .to_equivalent_lwe_dimension(sns_param.polynomial_size)
                    .0,
                threshold,
            )
            .into_iter()
            .map(|x| x as u128)
            .collect(),
            sns_param.polynomial_size,
        );
        (lwe_secret_key, glwe_sk, sns_glwe_sk)
    }
}

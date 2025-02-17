use crate::cryptography::internal_crypto_types::{
    PrivateEncKey, PrivateSigKey, PublicEncKey, PublicSigKey, SigncryptionPair,
    SigncryptionPrivKey, SigncryptionPubKey,
};
use crate::cryptography::signcryption::{
    decrypt_signcryption, ephemeral_encryption_key_generation, insecure_decrypt_ignoring_signature,
    internal_verify_sig,
};
use crate::cryptography::{internal_crypto_types::Signature, signcryption::check_normalized};
use crate::{anyhow_error_and_log, some_or_err};
use aes_prng::AesRng;
use alloy_primitives::Bytes;
use alloy_signer::SignerSync;
use alloy_sol_types::Eip712Domain;
use alloy_sol_types::SolStruct;
use bincode::{deserialize, serialize};
use distributed_decryption::algebra::base_ring::{Z128, Z64};
use distributed_decryption::algebra::error_correction::MemoizedExceptionals;
use distributed_decryption::algebra::galois_rings::degree_4::ResiduePolyF4;
use distributed_decryption::algebra::structure_traits::{BaseRing, ErrorCorrect};
use distributed_decryption::execution::endpoints::reconstruct::{
    combine_decryptions, reconstruct_packed_message,
};
use distributed_decryption::execution::runtime::party::Role;
use distributed_decryption::execution::sharing::shamir::{
    fill_indexed_shares, reconstruct_w_errors_sync, ShamirSharings,
};
use distributed_decryption::execution::tfhe_internals::parameters::{
    AugmentedCiphertextParameters, DKGParams,
};
use itertools::Itertools;
use kms_common::DecryptionMode;
use kms_grpc::kms::v1::{
    FheType, ReencryptionRequest, ReencryptionRequestPayload, ReencryptionResponse,
    ReencryptionResponsePayload, RequestId, TypedCiphertext, TypedPlaintext,
};
use kms_grpc::rpc_types::{
    alloy_to_protobuf_domain, serialize_hash_element, FheTypeResponse, MetaResponse, Reencrypt,
};
use rand::SeedableRng;
use std::collections::HashSet;
use std::num::Wrapping;
use tfhe::shortint::ClassicPBSParameters;
use wasm_bindgen::prelude::*;

// The default decryption mode to use in the client, when no other mode is specified explicitly. Currentlt Noise Flooding in the nSmall variant.
const DEFAULT_DECRYPTION_MODE: DecryptionMode = DecryptionMode::NoiseFloodSmall;

cfg_if::cfg_if! {
    if #[cfg(feature = "non-wasm")] {
        use crate::engine::base::{compute_handle};
        use crate::get_exactly_one;
        use crate::engine::traits::BaseKms;
        use crate::engine::base::BaseKmsStruct;
        use crate::vault::storage::{read_all_data_versioned, Storage, StorageReader};
        use kms_grpc::kms::v1::{
            KeySetAddedInfo, CrsGenRequest, CrsGenResult, DecryptionRequest,
            DecryptionResponse, DecryptionResponsePayload, FheParameter, KeyGenPreprocRequest,
            KeyGenRequest, KeyGenResult, VerifyProvenCtRequest,
            VerifyProvenCtResponse, KeySetConfig,
        };
        use kms_grpc::rpc_types::{PubDataType, PublicKeyType, WrappedPublicKeyOwned};
        use std::collections::HashMap;
        use std::fmt;
        use tfhe::zk::CompactPkeCrs;
        use tfhe::ProvenCompactCiphertextList;
        use tfhe::ServerKey;
        use tfhe_versionable::{Unversionize, Versionize};
        use tonic::transport::Channel;
        use tonic_health::pb::health_client::HealthClient;
        use tonic_health::ServingStatus;
        use tonic_health::pb::HealthCheckRequest;
        use crate::consts::{DEFAULT_PROTOCOL, DEFAULT_URL, MAX_TRIES};
    }
}

#[cfg(not(feature = "non-wasm"))]
pub mod js_api;

/// Helper method for combining reconstructed messages after decryption.
fn decrypted_blocks_to_plaintext(
    params: &ClassicPBSParameters,
    fhe_type: FheType,
    recon_blocks: Vec<Z128>,
) -> anyhow::Result<TypedPlaintext> {
    let bits_in_block = params.message_modulus_log();
    let res_pt = match fhe_type {
        FheType::Euint2048 => {
            combine_decryptions::<tfhe::integer::bigint::U2048>(bits_in_block, recon_blocks)
                .map(TypedPlaintext::from_u2048)
        }
        FheType::Euint1024 => {
            combine_decryptions::<tfhe::integer::bigint::U1024>(bits_in_block, recon_blocks)
                .map(TypedPlaintext::from_u1024)
        }
        FheType::Euint512 => {
            combine_decryptions::<tfhe::integer::bigint::U512>(bits_in_block, recon_blocks)
                .map(TypedPlaintext::from_u512)
        }
        FheType::Euint256 => {
            combine_decryptions::<tfhe::integer::U256>(bits_in_block, recon_blocks)
                .map(TypedPlaintext::from_u256)
        }
        FheType::Euint160 => {
            combine_decryptions::<tfhe::integer::U256>(bits_in_block, recon_blocks)
                .map(TypedPlaintext::from_u160)
        }
        FheType::Euint128 => combine_decryptions::<u128>(bits_in_block, recon_blocks)
            .map(|x| TypedPlaintext::new(x, fhe_type)),
        FheType::Ebool
        | FheType::Euint4
        | FheType::Euint8
        | FheType::Euint16
        | FheType::Euint32
        | FheType::Euint64 => combine_decryptions::<u64>(bits_in_block, recon_blocks)
            .map(|x| TypedPlaintext::new(x as u128, fhe_type)),
    };
    res_pt.map_err(|error| anyhow_error_and_log(format!("Panicked in combining {error}")))
}

/// For reencryption, we only use the Addr variant,
/// for everything else, we use the Pk variant.
#[derive(Clone)]
pub enum ServerIdentities {
    Pks(Vec<PublicSigKey>),
    Addrs(Vec<alloy_primitives::Address>),
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
pub struct TestingReencryptionTranscript {
    // client
    server_addrs: Vec<alloy_primitives::Address>,
    client_address: alloy_primitives::Address,
    client_sk: Option<PrivateSigKey>,
    degree: u32,
    params: DKGParams,
    // example pt and ct
    fhe_types: Vec<FheType>,
    pts: Vec<Vec<u8>>,
    cts: Vec<Vec<u8>>,
    // request
    request: Option<ReencryptionRequest>,
    eph_sk: PrivateEncKey,
    eph_pk: PublicEncKey,
    // response
    agg_resp: Vec<ReencryptionResponse>,
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
pub struct ParsedReencryptionRequest {
    // We allow dead_code because these are required to parse from JSON
    #[allow(dead_code)]
    signature: alloy_primitives::PrimitiveSignature,
    #[allow(dead_code)]
    client_address: alloy_primitives::Address,
    enc_key: Vec<u8>,
    ciphertext_handles: Vec<CiphertextHandle>,
    eip712_verifying_contract: alloy_primitives::Address,
}

impl ParsedReencryptionRequest {
    pub fn new(
        signature: alloy_primitives::PrimitiveSignature,
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
}

pub(crate) fn hex_decode_js_err(msg: &str) -> Result<Vec<u8>, JsError> {
    hex::decode(msg).map_err(|e| JsError::new(&e.to_string()))
}

// we need this type because the json fields are hex-encoded
// which cannot be converted to Vec<u8> automatically.
#[derive(serde::Serialize, serde::Deserialize)]
struct ParsedReencryptionRequestHex {
    signature: String,
    client_address: String,
    enc_key: String,
    ciphertext_handles: Vec<String>,
    eip712_verifying_contract: String,
}

impl TryFrom<&ParsedReencryptionRequestHex> for ParsedReencryptionRequest {
    type Error = JsError;

    fn try_from(req_hex: &ParsedReencryptionRequestHex) -> Result<Self, Self::Error> {
        let signature_buf = hex_decode_js_err(&req_hex.signature)?;
        let signature = alloy_primitives::PrimitiveSignature::try_from(signature_buf.as_slice())
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

impl TryFrom<JsValue> for ParsedReencryptionRequest {
    type Error = JsError;

    fn try_from(value: JsValue) -> Result<Self, Self::Error> {
        // JsValue -> JsClientReencryptionRequestHex
        let req_hex: ParsedReencryptionRequestHex =
            serde_wasm_bindgen::from_value(value).map_err(|e| JsError::new(&e.to_string()))?;

        // JsClientReencryptionRequestHex -> JsClientReencryptionRequest
        ParsedReencryptionRequest::try_from(&req_hex)
    }
}

impl From<&ParsedReencryptionRequest> for ParsedReencryptionRequestHex {
    fn from(value: &ParsedReencryptionRequest) -> Self {
        Self {
            signature: hex::encode(value.signature.as_bytes()),
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

impl TryFrom<&ReencryptionRequest> for ParsedReencryptionRequest {
    type Error = anyhow::Error;

    fn try_from(value: &ReencryptionRequest) -> Result<Self, Self::Error> {
        let payload = value
            .payload
            .as_ref()
            .ok_or(anyhow::anyhow!("Missing payload"))?;
        let domain = value
            .domain
            .as_ref()
            .ok_or(anyhow::anyhow!("Missing domain"))?;

        let signature = alloy_primitives::PrimitiveSignature::try_from(value.signature.as_slice())?;

        let client_address =
            alloy_primitives::Address::parse_checksummed(&payload.client_address, None)?;

        let eip712_verifying_contract =
            alloy_primitives::Address::parse_checksummed(domain.verifying_contract.clone(), None)?;

        let ciphertext_handles = payload
            .typed_ciphertexts
            .iter()
            .map(|ct| CiphertextHandle(ct.external_handle.clone()))
            .collect::<Vec<_>>();

        let out = Self {
            signature,
            client_address,
            enc_key: payload.enc_key.clone(),
            ciphertext_handles,
            eip712_verifying_contract,
        };
        Ok(out)
    }
}

/// Compute the link as (eip712_signing_hash(pk, domain) || hash(ciphertext handles)).
pub fn compute_link(
    req: &ParsedReencryptionRequest,
    domain: &Eip712Domain,
) -> anyhow::Result<Vec<u8>> {
    // check consistency
    let verifying_contract = domain
        .verifying_contract
        .ok_or_else(|| anyhow_error_and_log("Empty verifying contract"))?;

    if req.eip712_verifying_contract != verifying_contract {
        return Err(anyhow_error_and_log(format!(
            "inconsistent verifying contract: {:?} != {:?}",
            req.eip712_verifying_contract, verifying_contract,
        )));
    }

    let pk_sol = Reencrypt {
        publicKey: Bytes::copy_from_slice(&req.enc_key),
    };

    let pk_digest = pk_sol.eip712_signing_hash(domain).to_vec();
    let ct_handles_digest = serialize_hash_element(&req.ciphertext_handles)?;

    Ok([pk_digest, ct_handles_digest].concat())
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
    /// * `decryption_mode` - the decryption mode to use. Currently available modes are: NoiseFloodSmall and BitDecSmall. If set to none, the default mode in `DEFAULT_DECRYPTION_MODE` is used.
    pub fn new(
        server_pks: Vec<PublicSigKey>,
        client_address: alloy_primitives::Address,
        client_sk: Option<PrivateSigKey>,
        params: DKGParams,
        decryption_mode: Option<DecryptionMode>,
    ) -> Self {
        let decryption_mode = decryption_mode.unwrap_or(DEFAULT_DECRYPTION_MODE);
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
    /// * `decryption_mode` - the decryption mode to use. Currently available modes are: NoiseFloodSmall and BitDecSmall. If set to none, the default mode in `DEFAULT_DECRYPTION_MODE` is used.
    #[cfg(feature = "non-wasm")]
    pub async fn new_client<ClientS: Storage, PubS: StorageReader>(
        client_storage: ClientS,
        pub_storages: Vec<PubS>,
        params: &DKGParams,
        decryption_mode: Option<DecryptionMode>,
    ) -> anyhow::Result<Client> {
        let mut pks: Vec<PublicSigKey> = Vec::new();
        for cur_storage in pub_storages {
            let cur_map =
                read_all_data_versioned(&cur_storage, &PubDataType::VerfKey.to_string()).await?;
            for (cur_req_id, new_pk) in cur_map {
                // ensure that the inserted pk did not exist before / is not inserted twice
                if pks.contains(&new_pk) {
                    return Err(anyhow_error_and_log(format!(
                        "Public key for request id {} is already in the map",
                        cur_req_id,
                    )));
                }
                pks.push(new_pk);
            }
        }
        let client_pk_map: HashMap<RequestId, PublicSigKey> =
            read_all_data_versioned(&client_storage, &ClientDataType::VerfKey.to_string()).await?;
        let client_pk = get_exactly_one(client_pk_map).inspect_err(|e| {
            tracing::error!("client pk hashmap is not exactly 1: {}", e);
        })?;
        let client_address = alloy_primitives::Address::from_public_key(client_pk.pk());

        let client_sk_map: HashMap<RequestId, PrivateSigKey> =
            read_all_data_versioned(&client_storage, &ClientDataType::SigningKey.to_string())
                .await?;
        let client_sk = get_exactly_one(client_sk_map).inspect_err(|e| {
            tracing::error!("client sk hashmap is not exactly 1: {}", e);
        })?;

        Ok(Client::new(
            pks,
            client_address,
            Some(client_sk),
            *params,
            decryption_mode,
        ))
    }

    /// This is used for tests to convert public keys into addresses
    /// because when processing reencryption response, only addresses are allowed.
    pub fn convert_to_addresses(&mut self) {
        let pks = self.get_server_pks().unwrap();
        let addrs = pks
            .iter()
            .map(|pk| alloy_signer::utils::public_key_to_address(pk.pk()))
            .collect::<Vec<_>>();
        self.server_identities = ServerIdentities::Addrs(addrs);
    }

    /// Verify the signature received from the server on keys or other data objects.
    /// This verification will pass if one of the public keys can verify the signature.
    #[cfg(feature = "non-wasm")]
    fn verify_server_signature<T: serde::Serialize + AsRef<[u8]>>(
        &self,
        data: &T,
        signature: &[u8],
    ) -> anyhow::Result<()> {
        if self.find_verifying_public_key(data, signature).is_some() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("server signature verification failed"))
        }
    }

    /// Verify the signature received from the server on keys or other data objects
    /// and returns the public key that verified the signature.
    #[cfg(feature = "non-wasm")]
    fn find_verifying_public_key<T: serde::Serialize + AsRef<[u8]>>(
        &self,
        data: &T,
        signature: &[u8],
    ) -> Option<PublicSigKey> {
        let signature_struct: Signature = match bincode::deserialize(signature) {
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

        for verf_key in server_pks {
            let ok = BaseKmsStruct::verify_sig(&data, &signature_struct, verf_key).is_ok();
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

        Ok(KeyGenRequest {
            params: parsed_param,
            preproc_id,
            request_id: Some(request_id.clone()),
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
            request_id: Some(request_id.clone()),
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
            request_id: Some(request_id.clone()),
        })
    }

    /// Process a set of CRS generation results.
    /// We need a vector of storage readers also, one for each
    /// party that contributed to the result.
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
        results: Vec<CrsGenResult>,
        storage_readers: &[S],
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

        for (result, storage) in results.into_iter().zip(storage_readers) {
            let (pp_w_id, info) = if let Some(info) = result.crs_results {
                let url =
                    storage.compute_url(&request_id.to_string(), &PubDataType::CRS.to_string())?;
                let pp: CompactPkeCrs = storage.read_data(&url).await?;
                (pp, info)
            } else {
                tracing::warn!("empty SignedPubDataHandle");
                continue;
            };

            // check the result matches our request ID
            if request_id.request_id
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
            match self.find_verifying_public_key(&hex_digest, &info.signature) {
                Some(pk) => {
                    verifying_pks.insert(pk);
                }
                None => {
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

        // find the digest that has the most votes
        let (h, c) = hash_counter_map
            .into_iter()
            .max_by(|a, b| a.1.cmp(&b.1))
            .ok_or_else(|| anyhow_error_and_log("logic error: hash_counter_map is empty"))?;

        if c < min_agree_count as usize {
            return Err(anyhow_error_and_log(format!(
                "No consensus on CRS digest! {} < {}",
                c, min_agree_count
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
    /// request that generated the key which should be used for decryption
    #[cfg(feature = "non-wasm")]
    pub fn decryption_request(
        &mut self,
        ciphertexts: Vec<TypedCiphertext>,
        domain: &Eip712Domain,
        request_id: &RequestId,
        acl_address: &alloy_primitives::Address,
        key_id: &RequestId,
    ) -> anyhow::Result<DecryptionRequest> {
        if !request_id.is_valid() {
            return Err(anyhow_error_and_log(format!(
                "The request id format is not valid {request_id}"
            )));
        }

        let domain_msg = alloy_to_protobuf_domain(domain)?;

        let req = DecryptionRequest {
            ciphertexts,
            key_id: Some(key_id.clone()),
            domain: Some(domain_msg),
            request_id: Some(request_id.clone()),
            acl_address: Some(acl_address.to_string()),
        };
        Ok(req)
    }

    /// Creates a reencryption request to send to the KMS servers. This generates
    /// an ephemeral reencryption key pair, signature payload containing the ciphertext,
    /// required number of shares, and other metadata. It signs this payload with
    /// the users's wallet private key. Returns the full [ReencryptionRequest] containing
    /// the signed payload to send to the servers, along with the generated
    /// reencryption key pair.
    pub fn reencryption_request(
        &mut self,
        domain: &Eip712Domain,
        typed_ciphertexts: Vec<TypedCiphertext>,
        request_id: &RequestId,
        key_id: &RequestId,
    ) -> anyhow::Result<(ReencryptionRequest, PublicEncKey, PrivateEncKey)> {
        if !request_id.is_valid() {
            return Err(anyhow_error_and_log(format!(
                "The request id format is not valid {request_id}"
            )));
        }
        let client_sk = some_or_err(
            self.client_sk.clone(),
            "missing client signing key".to_string(),
        )?;

        let (enc_pk, enc_sk) = ephemeral_encryption_key_generation(&mut self.rng);
        let sig_payload = ReencryptionRequestPayload {
            enc_key: serialize(&enc_pk)?,
            client_address: self.client_address.to_checksum(None),
            typed_ciphertexts,
            key_id: Some(key_id.clone()),
        };
        let message = Reencrypt {
            publicKey: Bytes::copy_from_slice(&sig_payload.enc_key),
        };
        // Derive the EIP-712 signing hash.
        let message_hash = message.eip712_signing_hash(domain);
        let signer = alloy_signer_local::PrivateKeySigner::from_signing_key(client_sk.sk().clone());
        // sanity check
        if signer.address() != self.client_address {
            return Err(anyhow_error_and_log(
                "Sanity check failed: derived address does not equal to client address",
            ));
        }

        let signature = signer.sign_hash_sync(&message_hash)?;

        let domain_msg = alloy_to_protobuf_domain(domain)?;
        tracing::debug!(
            "reencryption request payload - \
            address: {:?} \
            domain: {:?}",
            sig_payload.client_address,
            domain
        );
        Ok((
            ReencryptionRequest {
                signature: signature.as_bytes().to_vec(),
                payload: Some(sig_payload),
                domain: Some(domain_msg),
                request_id: Some(request_id.clone()),
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
        )?;
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
            format!("Could not find key of type {}", key_type),
        )?;
        let request_id = some_or_err(
            key_gen_result.request_id.clone(),
            "No request id".to_string(),
        )?;
        let key: S = self.get_key(&request_id, key_type, storage).await?;
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
            .verify_server_signature(&key_handle, &pki.signature)
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
        let url = storage.compute_url(&key_id.to_string(), &key_type.to_string())?;
        storage.read_data(&url).await
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
        let pp = self.get_crs(&request_id, storage).await?;
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
            .verify_server_signature(&crs_handle, &crs_info.signature)
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
        let url = storage.compute_url(&crs_id.to_string(), &PubDataType::CRS.to_string())?;
        let pp: CompactPkeCrs = storage.read_data(&url).await?;
        Ok(pp)
    }

    /// Validates the aggregated decryption response `agg_resp` against the
    /// original `DecryptionRequest` `request`, and returns the decrypted
    /// plaintext if valid and at least [min_agree_count] agree on the result.
    /// Returns `None` if validation fails.
    #[cfg(feature = "non-wasm")]
    pub fn process_decryption_resp(
        &self,
        request: Option<DecryptionRequest>,
        agg_resp: &[DecryptionResponse],
        min_agree_count: u32,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        self.validate_decryption_req_resp(request, agg_resp, min_agree_count)?;

        // TODO pivot should actually be picked as the most common response instead of just an
        // arbitrary one. The same in reencryption
        let pivot = some_or_err(
            agg_resp.last(),
            "No elements in decryption response".to_string(),
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
            let cur_verf_key: PublicSigKey = deserialize(&cur_payload.verification_key)?;
            BaseKmsStruct::verify_sig(&bincode::serialize(&cur_payload)?, &sig, &cur_verf_key)
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

    /// Processes the aggregated reencryption response to attempt to decrypt
    /// the encryption of the secret shared plaintext and returns this. Validates the
    /// response matches the request, checks signatures, and handles both
    /// centralized and distributed cases.
    ///
    /// If there is more than one response or more than one server identity,
    /// then the threshold mode is used.
    pub fn process_reencryption_resp(
        &self,
        client_request: &ParsedReencryptionRequest,
        eip712_domain: &Eip712Domain,
        agg_resp: &[ReencryptionResponse],
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
            self.centralized_reencryption_resp(
                client_request,
                eip712_domain,
                agg_resp,
                &client_keys,
            )
        } else {
            self.threshold_reencryption_resp(client_request, eip712_domain, agg_resp, &client_keys)
        }
    }

    /// Processes the aggregated reencryption response to attempt to decrypt
    /// the encryption of the secret shared plaintext and returns this.
    /// This function does *not* do any verification and is thus insecure and should be used only for testing.
    /// TODO hide behind flag for insecure function?
    pub fn insecure_process_reencryption_resp(
        &self,
        agg_resp: &[ReencryptionResponse],
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

        // The same logic is used in `process_reencryption_resp`.
        if agg_resp.len() <= 1 && self.server_identities.len() == 1 {
            self.insecure_centralized_reencryption_resp(agg_resp, &client_keys)
        } else {
            self.insecure_threshold_reencryption_resp(agg_resp, &client_keys)
        }
    }

    /// Validates the aggregated decryption response by checking:
    /// - The responses agree on metadata like shares needed
    /// - The response matches the original request
    /// - Signatures on responses are valid
    /// - That at least [min_agree_count] agree on the same payload
    ///
    /// Returns true if the response is valid, false otherwise
    #[cfg(feature = "non-wasm")]
    fn validate_decryption_req_resp(
        &self,
        request: Option<DecryptionRequest>,
        agg_resp: &[DecryptionResponse],
        min_agree_count: u32,
    ) -> anyhow::Result<()> {
        match request {
            Some(req) => {
                let resp_parsed_payloads = some_or_err(
                    self.validate_dec_resp(agg_resp)?,
                    "Could not validate the aggregated responses".to_string(),
                )?;
                if resp_parsed_payloads.len() < min_agree_count as usize {
                    return Err(anyhow_error_and_log(
                        "Not enough correct responses to decrypt the data!",
                    ));
                }
                let pivot_payload = resp_parsed_payloads[0].clone();
                // if req.fhe_type() != pivot_payload.fhe_type()? {
                //     tracing::warn!("Fhe type in the decryption response is incorrect");
                //     return Ok(false);
                // } //TODO check fhe type?

                if req.ciphertexts.len() != pivot_payload.plaintexts.len() {
                    return Err(anyhow_error_and_log(
                        "The number of ciphertexts in the decryption response is wrong",
                    ));
                }

                if BaseKmsStruct::digest(&bincode::serialize(&req)?)? != pivot_payload.digest {
                    return Err(anyhow_error_and_log(
                        "The decryption response is not linked to the correct request",
                    ));
                }
                Ok(())
            }
            None => Err(anyhow_error_and_log(
                "No payload in the decryption request!",
            )),
        }
    }

    #[cfg(feature = "non-wasm")]
    fn validate_dec_resp(
        &self,
        agg_resp: &[DecryptionResponse],
    ) -> anyhow::Result<Option<Vec<DecryptionResponsePayload>>> {
        if agg_resp.is_empty() {
            tracing::warn!("There are no decryption responses!");
            return Ok(None);
        }
        // Pick a pivot response
        let mut option_pivot_payload: Option<DecryptionResponsePayload> = None;
        let mut resp_parsed_payloads = Vec::with_capacity(agg_resp.len());
        let mut verification_keys = HashSet::new();
        for cur_resp in agg_resp {
            let cur_payload = match &cur_resp.payload {
                Some(cur_payload) => cur_payload,
                None => {
                    tracing::warn!("No payload in current response from server!");
                    continue;
                }
            };
            // Set the first existing element as pivot
            // NOTE: this is the optimistic case where the pivot cannot be wrong
            let pivot_payload = match &option_pivot_payload {
                Some(pivot_payload) => pivot_payload,
                None => {
                    // need to clone here because `option_pivot_payload` is larger scope
                    option_pivot_payload = Some(cur_payload.clone());
                    cur_payload
                }
            };

            // check the uniqueness of verification key
            if verification_keys.contains(&cur_payload.verification_key) {
                tracing::warn!(
                    "At least two servers gave the same verification key {}",
                    hex::encode(&cur_payload.verification_key),
                );
                continue;
            }

            // Validate that all the responses agree with the pivot on the static parts of the
            // response
            if !self.validate_dec_meta_data(pivot_payload, cur_payload, &cur_resp.signature)? {
                tracing::warn!("Some server did not provide the proper response!");
                continue;
            }

            // add the verified response
            verification_keys.insert(cur_payload.verification_key.clone());
            resp_parsed_payloads.push(cur_payload.clone());
        }
        Ok(Some(resp_parsed_payloads))
    }

    /// Validates the aggregated reencryption responses received from the servers
    /// against the given reencryption request. Returns the validated responses
    /// mapped to the server ID on success.
    fn validate_reenc_req_resp(
        &self,
        client_request: &ParsedReencryptionRequest,
        eip712_domain: &Eip712Domain,
        agg_resp: &[ReencryptionResponse],
    ) -> anyhow::Result<Option<Vec<ReencryptionResponsePayload>>> {
        let resp_parsed = some_or_err(
            self.validate_reenc_resp(agg_resp)?,
            "Could not validate the aggregated responses".to_string(),
        )?;
        let expected_link = compute_link(client_request, eip712_domain)?;
        let pivot_resp = resp_parsed[0].clone();
        if expected_link != pivot_resp.digest {
            tracing::warn!("The reencryption response is not linked to the correct request");
            return Ok(None);
        }

        Ok(Some(resp_parsed))
    }

    fn validate_reenc_resp(
        &self,
        agg_resp: &[ReencryptionResponse],
    ) -> anyhow::Result<Option<Vec<ReencryptionResponsePayload>>> {
        if agg_resp.is_empty() {
            tracing::warn!("There are no responses");
            return Ok(None);
        }
        // TODO pivot should actually be picked as the most common response instead of just an
        // arbitrary one. The same in decryption
        // Pick a pivot response
        let mut option_pivot_payloads: Option<ReencryptionResponsePayload> = None;
        let mut resp_parsed_payloads = Vec::with_capacity(agg_resp.len());
        let mut party_ids = HashSet::new();
        let mut verification_keys = HashSet::new();

        for cur_resp in agg_resp {
            let cur_payload = match &cur_resp.payload {
                Some(cur_payload) => cur_payload,
                None => {
                    tracing::warn!("No payload in current response from server!");
                    continue;
                }
            };

            // Set the first existing element as pivot
            let pivot_payload = match &option_pivot_payloads {
                Some(pivot_resp) => pivot_resp,
                None => {
                    // need to clone here because `option_pivot_payload` is larger scope
                    option_pivot_payloads = Some(cur_payload.clone());
                    cur_payload
                }
            };

            // Validate that all the responses agree with the pivot on the static parts of the
            // response
            if !self.validate_reenc_meta_data(pivot_payload, cur_payload, &cur_resp.signature)? {
                tracing::warn!(
                    "Server who gave ID {} did not provide the proper response!",
                    cur_payload.party_id
                );
                continue;
            }
            if pivot_payload.degree != cur_payload.degree {
                tracing::warn!(
                    "Server who gave ID {} gave degree {} which is inconsistent with the pivot response",
                    cur_payload.party_id, cur_payload.degree
                );
                continue;
            }
            // Sanity check the ID of the server.
            // However, this will not catch all cheating since a server could claim the ID of another server
            // and we can't know who lies without consulting the verification key to ID mapping on the blockchain.
            // Furthermore, observe that we assume the optimal threshold is set.
            if cur_payload.party_id > cur_payload.degree * 3 + 1 {
                tracing::warn!(
                    "Server who gave ID {} is too large. The largest allowed id {}",
                    cur_payload.party_id,
                    cur_payload.degree * 3 + 1
                );
                continue;
            }
            if cur_payload.party_id == 0 {
                tracing::warn!("A server ID is set to 0");
                continue;
            }
            if party_ids.contains(&cur_payload.party_id) {
                tracing::warn!(
                    "At least two servers gave the same ID {}",
                    cur_payload.party_id,
                );
                continue;
            }

            // Check that verification keys are unique
            party_ids.insert(cur_payload.party_id);
            if verification_keys.contains(&cur_payload.verification_key) {
                tracing::warn!(
                    "At least two servers gave the same verification key {}",
                    hex::encode(&cur_payload.verification_key),
                );
                continue;
            }

            // only add the verified keys and responses at the end
            verification_keys.insert(cur_payload.verification_key.clone());
            resp_parsed_payloads.push(cur_payload.clone());
        }
        if option_pivot_payloads.is_some_and(|x| resp_parsed_payloads.len() < x.degree as usize) {
            tracing::warn!("Not enough correct responses to reencrypt the data!");
            return Ok(None);
        }
        Ok(Some(resp_parsed_payloads))
    }

    /// Decrypt the reencryption response from the centralized KMS and verify that the signatures are valid
    fn centralized_reencryption_resp(
        &self,
        request: &ParsedReencryptionRequest,
        eip712_domain: &Eip712Domain,
        agg_resp: &[ReencryptionResponse],
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

        // check signature
        if resp.signature.is_empty() {
            return Err(anyhow_error_and_log("empty signature"));
        }

        let stored_server_addrs = match &self.server_identities {
            ServerIdentities::Pks(_) => {
                return Err(anyhow_error_and_log(
                    "expected addresses but got public keys",
                ));
            }
            ServerIdentities::Addrs(vec) => {
                if vec.len() != 1 {
                    return Err(anyhow_error_and_log("incorrect length for addresses"));
                } else {
                    vec
                }
            }
        };

        let cur_verf_key: PublicSigKey = deserialize(&payload.verification_key)?;

        if stored_server_addrs[0] != alloy_signer::utils::public_key_to_address(cur_verf_key.pk()) {
            return Err(anyhow_error_and_log("verification key is not consistent"));
        }
        let sig = Signature {
            sig: k256::ecdsa::Signature::from_slice(&resp.signature)?,
        };
        internal_verify_sig(&bincode::serialize(&payload)?, &sig, &cur_verf_key).inspect_err(
            |e| tracing::warn!("signature on received response is not valid ({})", e),
        )?;

        payload
            .signcrypted_ciphertexts
            .into_iter()
            .map(|ct| {
                decrypt_signcryption(
                    &ct.signcrypted_ciphertext,
                    &link,
                    client_keys,
                    &cur_verf_key,
                )
            })
            .collect()
    }

    /// Decrypt the reencryption response from the centralized KMS.
    /// This function does *not* do any verification and is thus insecure and should be used only for testing.
    /// TODO hide behind flag for insecure function?
    fn insecure_centralized_reencryption_resp(
        &self,
        agg_resp: &[ReencryptionResponse],
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

    /// Decrypt the reencryption responses from the threshold KMS and verify that the signatures are valid
    fn threshold_reencryption_resp(
        &self,
        client_request: &ParsedReencryptionRequest,
        eip712_domain: &Eip712Domain,
        agg_resp: &[ReencryptionResponse],
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        let validated_resps = some_or_err(
            self.validate_reenc_req_resp(client_request, eip712_domain, agg_resp)?,
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

        let pbs_params = self
            .params
            .get_params_basics_handle()
            .to_classic_pbs_parameters();

        let res = match self.decryption_mode {
            DecryptionMode::BitDecSmall => {
                let all_sharings = self.recover_sharings::<Z64>(&validated_resps, client_keys)?;

                let mut out = vec![];
                for (fhe_type, sharings) in all_sharings {
                    let mut decrypted_blocks = Vec::new();
                    for cur_block_shares in sharings {
                        // NOTE: this performs optimistic reconstruction
                        if let Ok(Some(r)) = reconstruct_w_errors_sync(
                            num_parties,
                            degree,
                            degree,
                            num_parties - amount_shares,
                            &cur_block_shares,
                        ) {
                            decrypted_blocks.push(r);
                        } else {
                            return Err(anyhow_error_and_log("Could not reconstruct all blocks"));
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
                for (fhe_type, sharings) in all_sharings {
                    let mut decrypted_blocks = Vec::new();

                    for cur_block_shares in sharings {
                        // NOTE: this performs optimistic reconstruction
                        if let Ok(Some(r)) = reconstruct_w_errors_sync(
                            num_parties,
                            degree,
                            degree,
                            num_parties - amount_shares,
                            &cur_block_shares,
                        ) {
                            decrypted_blocks.push(r);
                        } else {
                            return Err(anyhow_error_and_log("Could not reconstruct all blocks"));
                        }
                    }

                    out.push((
                        fhe_type,
                        reconstruct_packed_message(
                            Some(decrypted_blocks),
                            &pbs_params,
                            fhe_type.to_num_blocks(
                                &self
                                    .params
                                    .get_params_basics_handle()
                                    .to_classic_pbs_parameters(),
                            ),
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
        for (fhe_type, res) in res {
            final_result.push(decrypted_blocks_to_plaintext(&pbs_params, fhe_type, res)?);
        }
        Ok(final_result)
    }

    fn insecure_threshold_reencryption_resp(
        &self,
        agg_resp: &[ReencryptionResponse],
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        match self.decryption_mode {
            DecryptionMode::BitDecSmall => {
                self.insecure_threshold_reencryption_resp_z64(agg_resp, client_keys)
            }
            DecryptionMode::NoiseFloodSmall => {
                self.insecure_threshold_reencryption_resp_z128(agg_resp, client_keys)
            }
            e => Err(anyhow_error_and_log(format!(
                "Unsupported decryption mode: {e}"
            ))),
        }
    }

    fn insecure_threshold_reencryption_resp_to_blocks<Z: BaseRing>(
        agg_resp: &[ReencryptionResponse],
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Vec<(FheType, Vec<ResiduePolyF4<Z>>)>>
    where
        ResiduePolyF4<Z>: ErrorCorrect + MemoizedExceptionals,
    {
        let batch_count = agg_resp
            .first()
            .ok_or(anyhow::anyhow!("agg_resp is empty"))?
            .payload
            .as_ref()
            .ok_or(anyhow::anyhow!("payload is empty in reencryption response"))?
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
                .ok_or(anyhow::anyhow!("agg_resp is empty"))?
                .payload
                .as_ref()
                .ok_or(anyhow::anyhow!("payload is empty"))?
                .signcrypted_ciphertexts[batch_i]
                .fhe_type();

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

                let cipher_blocks_share: Vec<ResiduePolyF4<Z>> = deserialize(&shares.bytes)?;
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
                    Role::indexed_by_one(payload.party_id as usize),
                )?;
            }
            let sharings = opt_sharings.unwrap();
            // TODO: in general this is not true, degree isn't a perfect proxy for num_parties
            let num_parties = 3 * degree + 1;
            let amount_shares = agg_resp.len();
            let mut decrypted_blocks = Vec::new();
            for cur_block_shares in sharings {
                // NOTE: this performs optimistic reconstruction
                if let Ok(Some(r)) = reconstruct_w_errors_sync(
                    num_parties,
                    degree,
                    degree,
                    num_parties - amount_shares,
                    &cur_block_shares,
                ) {
                    decrypted_blocks.push(r);
                } else {
                    return Err(anyhow_error_and_log("Could not reconstruct all blocks"));
                }
            }
            out.push((fhe_type, decrypted_blocks))
        }
        Ok(out)
    }

    fn insecure_threshold_reencryption_resp_z128(
        &self,
        agg_resp: &[ReencryptionResponse],
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        let all_decrypted_blocks =
            Self::insecure_threshold_reencryption_resp_to_blocks::<Z128>(agg_resp, client_keys)?;

        let mut out = vec![];
        for (fhe_type, decrypted_blocks) in all_decrypted_blocks {
            let pbs_params = self
                .params
                .get_params_basics_handle()
                .to_classic_pbs_parameters();

            let recon_blocks = reconstruct_packed_message(
                Some(decrypted_blocks),
                &pbs_params,
                fhe_type.to_num_blocks(
                    &self
                        .params
                        .get_params_basics_handle()
                        .to_classic_pbs_parameters(),
                ),
            )?;

            out.push(decrypted_blocks_to_plaintext(
                &pbs_params,
                fhe_type,
                recon_blocks,
            )?);
        }
        Ok(out)
    }

    /// Decrypt the reencryption response from the threshold KMS.
    /// This function does *not* do any verification and is thus insecure and should be used only for testing.
    /// TODO hide behind flag for insecure function?
    fn insecure_threshold_reencryption_resp_z64(
        &self,
        agg_resp: &[ReencryptionResponse],
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Vec<TypedPlaintext>> {
        let all_decrypted_blocks =
            Self::insecure_threshold_reencryption_resp_to_blocks::<Z64>(agg_resp, client_keys)?;

        let mut out = vec![];
        for (fhe_type, decrypted_blocks) in all_decrypted_blocks {
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
                ptxts128,
            )?);
        }
        Ok(out)
    }

    /// Decrypts the reencryption responses and decodes the responses onto the Shamir shares
    /// that the servers should have encrypted.
    #[allow(clippy::type_complexity)]
    fn recover_sharings<Z: BaseRing>(
        &self,
        agg_resp: &[ReencryptionResponsePayload],
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Vec<(FheType, Vec<ShamirSharings<ResiduePolyF4<Z>>>)>> {
        let batch_count = agg_resp
            .first()
            .ok_or(anyhow::anyhow!("response payloads is empty"))?
            .signcrypted_ciphertexts
            .len();

        let mut out = vec![];
        for batch_i in 0..batch_count {
            // taking agg_resp[0] is safe since batch_count before exists
            let fhe_type = agg_resp[0].signcrypted_ciphertexts[batch_i].fhe_type();
            let num_blocks = fhe_type.to_num_blocks(
                &self
                    .params
                    .get_params_basics_handle()
                    .to_classic_pbs_parameters(),
            );
            let mut sharings = Vec::new();
            for _i in 0..num_blocks {
                sharings.push(ShamirSharings::new());
            }
            for cur_resp in agg_resp {
                // Observe that it has already been verified in [validate_meta_data] that server
                // verification key is in the set of permissible keys
                //
                // Also it's ok to use [cur_resp.digest] as the link since we already checked
                // that it matches with the original request
                let cur_verf_key: PublicSigKey = deserialize(&cur_resp.verification_key)?;
                match decrypt_signcryption(
                    &cur_resp.signcrypted_ciphertexts[batch_i].signcrypted_ciphertext,
                    &cur_resp.digest,
                    client_keys,
                    &cur_verf_key,
                ) {
                    Ok(decryption_share) => {
                        let cipher_blocks_share: Vec<ResiduePolyF4<Z>> =
                            deserialize(&decryption_share.bytes)?;
                        let mut cur_blocks = Vec::with_capacity(cipher_blocks_share.len());
                        for cur_block_share in cipher_blocks_share {
                            cur_blocks.push(cur_block_share);
                        }
                        fill_indexed_shares(
                            &mut sharings,
                            cur_blocks,
                            num_blocks,
                            Role::indexed_by_one(cur_resp.party_id as usize),
                        )?;
                    }
                    _ => {
                        tracing::warn!(
                            "Could not decrypt or validate signcrypted response from party {}.",
                            cur_resp.party_id
                        );
                        fill_indexed_shares(
                            &mut sharings,
                            Vec::new(),
                            num_blocks,
                            Role::indexed_by_one(cur_resp.party_id as usize),
                        )?;
                    }
                };
            }
            out.push((fhe_type, sharings));
        }
        Ok(out)
    }

    pub fn get_server_pks(&self) -> anyhow::Result<&Vec<PublicSigKey>> {
        match &self.server_identities {
            ServerIdentities::Pks(vec) => Ok(vec),
            ServerIdentities::Addrs(_) => {
                Err(anyhow::anyhow!("expected public keys, got addresses"))
            }
        }
    }

    pub fn get_server_addrs(&self) -> anyhow::Result<&Vec<alloy_primitives::Address>> {
        match &self.server_identities {
            ServerIdentities::Pks(_) => Err(anyhow::anyhow!("expected addresses, got public keys")),
            ServerIdentities::Addrs(vec) => Ok(vec),
        }
    }

    pub fn get_client_address(&self) -> alloy_primitives::Address {
        self.client_address
    }

    #[cfg(feature = "non-wasm")]
    fn validate_dec_meta_data<T: MetaResponse + serde::Serialize>(
        &self,
        pivot_resp: &T,
        other_resp: &T,
        signature: &[u8],
    ) -> anyhow::Result<bool> {
        if pivot_resp.digest() != other_resp.digest() {
            tracing::warn!(
                    "Response from server with verification key {:?} gave digest {:?}, whereas the pivot server gave digest {:?}, and its verification key is {:?}",
                    pivot_resp.verification_key(),
                    pivot_resp.digest(),
                    other_resp.digest(),
                    other_resp.verification_key()
                );
            return Ok(false);
        }
        let resp_verf_key: PublicSigKey = deserialize(&other_resp.verification_key())?;
        let server_pks = self.get_server_pks()?;
        if !server_pks.contains(&resp_verf_key) {
            tracing::warn!("Server key is unknown or incorrect.");
            return Ok(false);
        }

        let sig = Signature {
            sig: k256::ecdsa::Signature::from_slice(signature)?,
        };
        // NOTE that we cannot use `BaseKmsStruct::verify_sig`
        // because `BaseKmsStruct` cannot be compiled for wasm (it has an async mutex).
        if internal_verify_sig(&bincode::serialize(&other_resp)?, &sig, &resp_verf_key).is_err() {
            tracing::warn!("Signature on received response is not valid!");
            return Ok(false);
        }
        Ok(true)
    }

    fn validate_reenc_meta_data<T: MetaResponse + FheTypeResponse + serde::Serialize>(
        &self,
        pivot_resp: &T,
        other_resp: &T,
        signature: &[u8],
    ) -> anyhow::Result<bool> {
        let types_1 = pivot_resp.fhe_types()?;
        let types_2 = other_resp.fhe_types()?;
        if types_1.len() != types_2.len() || types_1.is_empty() || types_2.is_empty() {
            tracing::warn!("incorrect lengths: {}, {}", types_1.len(), types_2.len());
            return Ok(false);
        }
        for i in 0..types_1.len() {
            if types_1[i] != types_2[i] {
                tracing::warn!(
                    "Response from server with verification key {:?} gave fhe type {:?}, whereas the pivot server's fhe type is {:?} and its verification key is {:?}",
                    pivot_resp.verification_key(),
                    types_1[i],
                    types_2[i],
                    other_resp.verification_key()
                );
                return Ok(false);
            }
        }
        if pivot_resp.digest() != other_resp.digest() {
            tracing::warn!(
                    "Response from server with verification key {:?} gave digest {:?}, whereas the pivot server gave digest {:?}, and its verification key is {:?}",
                    pivot_resp.verification_key(),
                    pivot_resp.digest(),
                    other_resp.digest(),
                    other_resp.verification_key()
                );
            return Ok(false);
        }

        let resp_verf_key: PublicSigKey = deserialize(&other_resp.verification_key())?;
        let resp_addr = alloy_signer::utils::public_key_to_address(resp_verf_key.pk());

        let stored_server_addrs = self.get_server_addrs()?;
        if !stored_server_addrs.contains(&resp_addr) {
            tracing::warn!("Server address is incorrect in reencryption request");
            return Ok(false);
        }

        let sig = Signature {
            sig: k256::ecdsa::Signature::from_slice(signature)?,
        };
        // NOTE that we cannot use `BaseKmsStruct::verify_sig`
        // because `BaseKmsStruct` cannot be compiled for wasm (it has an async mutex).
        if internal_verify_sig(&bincode::serialize(&other_resp)?, &sig, &resp_verf_key).is_err() {
            tracing::warn!("Signature on received response is not valid!");
            return Ok(false);
        }
        Ok(true)
    }

    /// Make a verification request for the given `proven_ct` with some metadata.
    /// NOTE: eventually we want to integrate the metadata into the proven ciphertext.
    #[cfg(feature = "non-wasm")]
    #[expect(clippy::too_many_arguments)]
    pub fn verify_proven_ct_request(
        &self,
        crs_handle: &RequestId,
        key_handle: &RequestId,
        contract_address: &alloy_primitives::Address,
        proven_ct: &ProvenCompactCiphertextList,
        domain: &Eip712Domain,
        acl_address: &alloy_primitives::Address,
        request_id: &RequestId,
    ) -> anyhow::Result<VerifyProvenCtRequest> {
        let mut ct_buf = Vec::new();
        tfhe::safe_serialization::safe_serialize(
            proven_ct,
            &mut ct_buf,
            crate::consts::SAFE_SER_SIZE_LIMIT,
        )
        .map_err(|e| anyhow::anyhow!(e))?;

        let domain_msg = alloy_to_protobuf_domain(domain)?;

        Ok(VerifyProvenCtRequest {
            crs_handle: Some(crs_handle.to_owned()),
            key_handle: Some(key_handle.to_owned()),
            contract_address: contract_address.to_string(),
            client_address: self.client_address.to_string(),
            ct_bytes: ct_buf,
            acl_address: acl_address.to_string(),
            request_id: Some(request_id.to_owned()),
            domain: Some(domain_msg),
        })
    }

    /// Process a set of ciphertext verification responses
    /// by attempting to find a one-to-one match between the signature and the server public key.
    /// The output is the set of verified signatures along with their corresponding public key.
    #[cfg(feature = "non-wasm")]
    pub fn process_verify_proven_ct_resp(
        &self,
        responses: &[VerifyProvenCtResponse],
        min_agree_count: u32,
    ) -> anyhow::Result<Vec<(Signature, PublicSigKey)>> {
        let server_pks = self.get_server_pks()?;
        let mut remaining_pk_idx: HashSet<usize> = HashSet::from_iter(0..server_pks.len());
        let mut out = Vec::new();

        for response in responses {
            let payload = response
                .payload
                .as_ref()
                .ok_or_else(|| anyhow_error_and_log("empty verify response payload"))?;

            let payload_serialized = bincode::serialize(payload)?;

            let verify_proven_ct_sig = Signature {
                sig: k256::ecdsa::Signature::from_slice(&response.signature)?,
            };

            let to_remove = (|| -> Option<usize> {
                for pk_idx in &remaining_pk_idx {
                    let pk = &server_pks[*pk_idx];
                    match internal_verify_sig(&payload_serialized, &verify_proven_ct_sig, pk) {
                        Ok(()) => {
                            return Some(*pk_idx);
                        }
                        Err(_) => {
                            // verification failed, we try with another public key
                            // in the next iteration
                        }
                    }
                }
                None
            })();
            if let Some(i) = to_remove {
                out.push((verify_proven_ct_sig, server_pks[i].clone()));
                remaining_pk_idx.remove(&i);
            };
        }

        if out.len() < min_agree_count as usize {
            Err(anyhow_error_and_log(
                "Not enough correct responses to process proof verification",
            ))
        } else {
            Ok(out)
        }
    }
}

/// creates the metadata (auxiliary data) for proving/verifying the input ZKPs from the individual inputs
///
/// metadata is `contract_addr || user_addr || acl_addr || chain_id` i.e. 92 bytes since chain ID is encoded as a 32 byte big endian integer
pub fn assemble_metadata_alloy(
    contract_address: &alloy_primitives::Address,
    client_address: &alloy_primitives::Address,
    acl_address: &alloy_primitives::Address,
    chain_id: &alloy_primitives::U256,
) -> [u8; 92] {
    let mut metadata = [0_u8; 92];

    let contract_bytes = contract_address.into_array();
    let client_bytes = client_address.into_array();
    let acl_bytes = acl_address.into_array();
    let chain_id_bytes: [u8; 32] = chain_id.to_be_bytes();
    let front = [contract_bytes, client_bytes, acl_bytes].concat();
    metadata[..60].copy_from_slice(front.as_slice());
    metadata[60..].copy_from_slice(&chain_id_bytes);

    metadata
}

/// creates the metadata (auxiliary data) for proving/verifying the input ZKPs from a `VerifyProvenCtRequest`
///
/// metadata is `contract_addr || user_addr || acl_addr || chain_id` i.e. 92 bytes since chain ID is encoded as a 32 byte big endian integer
#[cfg(feature = "non-wasm")]
pub fn assemble_metadata_req(req: &VerifyProvenCtRequest) -> anyhow::Result<[u8; 92]> {
    let contract_address =
        alloy_primitives::Address::parse_checksummed(&req.contract_address, None)?;
    let client_address = alloy_primitives::Address::parse_checksummed(&req.client_address, None)?;
    let acl_address = alloy_primitives::Address::parse_checksummed(&req.acl_address, None)?;

    let domain = req
        .domain
        .as_ref()
        .ok_or_else(|| anyhow_error_and_log("empty domain"))?;

    let chain_id = alloy_primitives::U256::try_from_be_slice(&domain.chain_id)
        .ok_or_else(|| anyhow_error_and_log("invalid chain ID"))?;

    Ok(assemble_metadata_alloy(
        &contract_address,
        &client_address,
        &acl_address,
        &chain_id,
    ))
}

pub fn recover_ecdsa_public_key_from_signature(
    sig: &[u8],
    pub_enc_key: &[u8],
    domain: &Eip712Domain,
    target_address: &[u8],
) -> anyhow::Result<PublicSigKey> {
    tracing::info!("Recovering public key from signature");
    // trace all inputs
    tracing::debug!("Signature: {:?}", hex::encode(sig));
    tracing::debug!("Public encryption key: {:?}", hex::encode(pub_enc_key));
    tracing::debug!("EIP712: {:?}", domain);
    tracing::debug!("Target address: {:?}", hex::encode(target_address));

    let signature = alloy_primitives::PrimitiveSignature::try_from(sig)?;
    check_normalized(&Signature {
        sig: signature.to_k256()?,
    })?;

    // Define the EIP-712 domain
    let message = Reencrypt {
        publicKey: Bytes::copy_from_slice(pub_enc_key),
    };

    // Derive the EIP-712 signing hash.
    let message_hash = message.eip712_signing_hash(domain);
    tracing::debug!("Message hash: {:?}", message_hash);

    let recovered_key = signature.recover_from_msg(message_hash)?;
    tracing::debug!("Recovered key: {:?}", recovered_key);
    tracing::debug!("Signature: {:?}", signature);

    let recovered_address = signature.recover_address_from_prehash(&message_hash)?;
    tracing::debug!("Recovered address: {:?}", recovered_address);
    Ok(PublicSigKey::new(
        signature.recover_from_prehash(&message_hash)?,
    ))
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
                "Failed to get health status on {service_name} on port {port}. Status: {:?}",
                status
            );
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        status = get_status(&mut client, service_name).await;
        service_tries += 1;
    }
}

#[cfg(feature = "non-wasm")]
async fn get_health_client(port: u16) -> anyhow::Result<HealthClient<Channel>> {
    let server_address = &format!("{DEFAULT_PROTOCOL}://{DEFAULT_URL}:{}", port);
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
    use crate::engine::threshold::service_real::threshold_server_init;
    use crate::engine::{run_server, Shutdown};
    use crate::util::key_setup::test_tools::setup::ensure_testing_material_exists;
    use crate::util::rate_limiter::RateLimiterConfig;
    use crate::vault::storage::{file::FileStorage, Storage, StorageType};
    use crate::{
        conf::{
            threshold::{PeerConf, ThresholdPartyConf},
            ServiceEndpoint,
        },
        util::random_free_port::get_listeners_random_free_ports,
    };
    use distributed_decryption::execution::tfhe_internals::parameters::DKGParams;
    use distributed_decryption::networking::grpc::GrpcServer;
    use futures_util::FutureExt;
    use itertools::Itertools;
    use kms_common::DecryptionMode;
    use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
    use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer;
    use std::str::FromStr;
    use std::sync::Arc;
    use tonic::server::NamedService;
    use tonic::transport::{Channel, Uri};

    #[cfg(feature = "slow_tests")]
    use crate::util::key_setup::test_tools::setup::ensure_default_material_exists;

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
                tls_cert_path: None,
            })
            .collect_vec();

        // use NoiseFloodSmall unless some other DecryptionMode was set as parameter
        let decryption_mode = decryption_mode.unwrap_or(DEFAULT_DECRYPTION_MODE);

        // a vector of sender that will trigger shutdown of core/threshold servers
        let mut mpc_shutdown_txs = Vec::new();

        for (i, (mpc_listener, _mpc_port)) in (1..=num_parties).zip(mpc_listeners.into_iter()) {
            let cur_pub_storage = pub_storage[i - 1].to_owned();
            let cur_priv_storage = priv_storage[i - 1].to_owned();
            let service_config = ServiceEndpoint {
                listen_address: ip_addr.to_string(),
                listen_port: service_ports[i - 1],
                timeout_secs: 60u64,
                grpc_max_message_size: 2 * 10 * 1024 * 1024, // 20 MiB
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
                    tls_cert_path: None,
                    tls_key_path: None,
                    peers: mpc_conf,
                    core_to_core_net: None,
                    decryption_mode,
                };

                // TODO pass in cert_paths for testing TLS
                let server = threshold_server_init(
                    threshold_party_config,
                    mpc_listener,
                    cur_pub_storage,
                    cur_priv_storage,
                    None as Option<PrivS>,
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
                Err(e) => panic!("Failed to start server {i} with error {:?}", e),
            }
        }
        tracing::info!("Servers initialized. Starting servers...");
        let mut server_handles = HashMap::new();
        for (
            ((i, cur_server, service_config, cur_health_service), cur_mpc_shutdown),
            (service_listener, _service_port),
        ) in servers
            .into_iter()
            .zip(mpc_shutdown_txs)
            .zip(service_listeners.into_iter())
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
                panic!("Client unable to connect to {}: Error {:?}", uri, e)
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
        let (kms, health_service) = RealCentralizedKms::new(
            pub_storage,
            priv_storage,
            None as Option<PrivS>,
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
                grpc_max_message_size: 2 * 10 * 1024 * 1024, // 20 MiB to allow for 2048 bit encryptions
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
        let pub_storage = vec![FileStorage::new(None, StorageType::PUB, None).unwrap()];
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
    use super::{recover_ecdsa_public_key_from_signature, Client};
    use crate::client::test_tools::check_port_is_closed;
    #[cfg(feature = "wasm_tests")]
    use crate::client::TestingReencryptionTranscript;
    use crate::client::{
        assemble_metadata_alloy, await_server_ready, get_health_client, get_status,
    };
    use crate::client::{ParsedReencryptionRequest, ServerIdentities};
    #[cfg(feature = "insecure")]
    use crate::consts::DEFAULT_PARAM;
    use crate::consts::DEFAULT_THRESHOLD;
    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    use crate::consts::MAX_TRIES;
    use crate::consts::PRSS_EPOCH_ID;
    use crate::consts::TEST_PARAM;
    use crate::consts::TEST_THRESHOLD_CRS_ID_4P;
    use crate::consts::TEST_THRESHOLD_CRS_ID_7P;
    use crate::consts::TEST_THRESHOLD_KEY_ID_4P;
    use crate::consts::TEST_THRESHOLD_KEY_ID_7P;
    use crate::consts::{DEFAULT_AMOUNT_PARTIES, TEST_CENTRAL_KEY_ID};
    #[cfg(feature = "slow_tests")]
    use crate::consts::{
        DEFAULT_CENTRAL_KEY_ID, DEFAULT_THRESHOLD_CRS_ID_4P, DEFAULT_THRESHOLD_CRS_ID_7P,
        DEFAULT_THRESHOLD_KEY_ID_4P, DEFAULT_THRESHOLD_KEY_ID_7P,
    };
    use crate::cryptography::internal_crypto_types::Signature;
    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    use crate::cryptography::internal_crypto_types::WrappedDKGParams;
    use crate::engine::base::{compute_handle, gen_sig_keys, BaseKmsStruct, RequestIdGetter};
    #[cfg(feature = "slow_tests")]
    use crate::engine::centralized::central_kms::tests::get_default_keys;
    use crate::engine::centralized::central_kms::RealCentralizedKms;
    use crate::engine::threshold::service_real::RealThresholdKms;
    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    use crate::engine::threshold::service_real::ThresholdFheKeys;
    use crate::engine::traits::BaseKms;
    use crate::util::file_handling::safe_read_element_versioned;
    #[cfg(feature = "wasm_tests")]
    use crate::util::file_handling::write_element;
    use crate::util::key_setup::max_threshold;
    use crate::util::key_setup::test_tools::{
        compute_cipher_from_stored_key, compute_compressed_cipher_from_stored_key,
        compute_proven_ct_from_stored_key, load_pk_from_storage, purge, TestingPlaintext,
    };
    use crate::util::rate_limiter::RateLimiterConfig;
    use crate::vault::storage::StorageReader;
    use crate::vault::storage::{file::FileStorage, StorageType};
    use alloy_primitives::Bytes;
    use alloy_signer::Signer;
    use alloy_signer_local::PrivateKeySigner;
    use alloy_sol_types::SolStruct;
    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    use distributed_decryption::execution::runtime::party::Role;
    use distributed_decryption::execution::tfhe_internals::parameters::DKGParams;
    #[cfg(feature = "wasm_tests")]
    use distributed_decryption::execution::tfhe_internals::parameters::PARAMS_TEST_BK_SNS;
    use distributed_decryption::execution::tfhe_internals::test_feature::run_decompression_test;
    use distributed_decryption::networking::grpc::GrpcServer;
    use kms_common::DecryptionMode;
    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    use kms_grpc::kms::v1::CrsGenRequest;
    #[cfg(feature = "slow_tests")]
    use kms_grpc::kms::v1::KeyGenPreprocStatusEnum;
    #[cfg(feature = "wasm_tests")]
    use kms_grpc::kms::v1::TypedPlaintext;
    use kms_grpc::kms::v1::{
        Empty, FheParameter, FheType, InitRequest, KeySetAddedInfo, KeySetConfig, KeySetType,
        ReencryptionResponse, RequestId, TypedCiphertext,
    };
    use kms_grpc::kms_service::v1::core_service_endpoint_client::CoreServiceEndpointClient;
    use kms_grpc::kms_service::v1::core_service_endpoint_server::CoreServiceEndpointServer;
    use kms_grpc::rpc_types::PrivDataType;
    use kms_grpc::rpc_types::{protobuf_to_alloy_domain, PubDataType, Reencrypt};
    use rand::SeedableRng;
    use serial_test::serial;
    use std::collections::{hash_map::Entry, HashMap};
    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    use std::sync::Arc;
    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    use tfhe::integer::compression_keys::DecompressionKey;
    use tfhe::zk::CompactPkeCrs;
    use tfhe::ProvenCompactCiphertextList;
    use tfhe::Tag;
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
            priv_storage.push(FileStorage::new(None, StorageType::PRIV, Some(i)).unwrap());
            pub_storage.push(FileStorage::new(None, StorageType::PUB, Some(i)).unwrap());
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
        let mut pub_storage = Vec::with_capacity(amount_parties);
        for i in 1..=amount_parties {
            pub_storage.push(FileStorage::new(None, StorageType::PUB, Some(i)).unwrap());
        }
        let client_storage = FileStorage::new(None, StorageType::CLIENT, None).unwrap();
        let internal_client =
            Client::new_client(client_storage, pub_storage, &params, decryption_mode)
                .await
                .unwrap();
        (kms_servers, kms_clients, internal_client)
    }

    #[tokio::test]
    async fn test_public_key_from_signature() {
        let domain = dummy_domain();
        let pub_enc_key = b"408d8cbaa51dece7f782fe04ba0b1c1d017b1088";
        let message = Reencrypt {
            publicKey: Bytes::from(pub_enc_key),
        };
        let mut rng = aes_prng::AesRng::seed_from_u64(12);
        let (client_pk, client_sk) = gen_sig_keys(&mut rng);

        let signer = PrivateKeySigner::from_signing_key(client_sk.sk().clone());
        let target_address = signer.address();
        println!("Signer address: {:?}", target_address);

        let message_hash = message.eip712_signing_hash(&domain);
        println!("Message hash: {:?}", message_hash);

        // Sign the hash asynchronously with the wallet.
        let signature = signer.sign_hash(&message_hash).await.unwrap().as_bytes();

        println!("Signature: {:?}", hex::encode(signature));
        let recovered_pk = recover_ecdsa_public_key_from_signature(
            &signature,
            pub_enc_key,
            &domain,
            target_address.as_ref(),
        )
        .unwrap();
        assert_eq!(recovered_pk, client_pk);
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
            "Service is not in SERVING status. Got status: {}",
            status
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
        // make sure the store does not contain any PRSS info (currently stored under ID PRSS_EPOCH_ID)
        let req_id = &RequestId::derive(&format!(
            "PRSSSetup_Z128_ID_{}_{}_{}",
            PRSS_EPOCH_ID, DEFAULT_AMOUNT_PARTIES, DEFAULT_THRESHOLD
        ))
        .unwrap();
        purge(None, None, &req_id.to_string(), DEFAULT_AMOUNT_PARTIES).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;

        // DON'T setup PRSS in order to ensure the server is not ready yet
        let (kms_servers, kms_clients, mut internal_client) =
            threshold_handles(TEST_PARAM, DEFAULT_AMOUNT_PARTIES, false, None, None).await;

        // Validate that the core server is not ready
        let (dec_tasks, req_id) = send_dec_reqs(
            1,
            &TEST_THRESHOLD_KEY_ID_4P,
            &kms_clients,
            &mut internal_client,
        )
        .await;
        let dec_res = dec_tasks.join_all().await;
        // Even though servers are not initialized they will accept the requests
        assert!(dec_res.iter().all(|res| res.is_ok()));
        // But the response will result in an error
        let dec_resp_tasks = get_dec_resp(&req_id, &kms_clients).await;
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
            "Service is not in NOT_SERVING status. Got status: {}",
            status
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
            "Service is not in SERVING status. Got status: {}",
            status
        );

        // Now initialize and check that the server is serving
        let mut req_tasks = JoinSet::new();
        for i in 1..=DEFAULT_AMOUNT_PARTIES as u32 {
            let mut cur_client = kms_clients.get(&i).unwrap().clone();
            req_tasks.spawn(async move {
                cur_client
                    .init(tonic::Request::new(InitRequest { config: None }))
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
            "Service is not in SERVING status. Got status: {}",
            status
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
            "Service is not in SERVING status. Got status: {}",
            status
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
            "Service is not in NOT SERVING status. Got status: {}",
            status
        );
        // Wait for dec tasks to be done
        let dec_res = tasks.join_all().await;
        assert!(dec_res.iter().all(|res| res.is_ok()));
        // And wait for decryption to also be done
        let dec_resp_tasks = get_dec_resp(&req_id, &client_map).await;
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
        // If PRSS is not already present, then let us retry and include prss initialization
        let (mut kms_servers, _kms_clients, _internal_client) =
            threshold_handles(TEST_PARAM, DEFAULT_AMOUNT_PARTIES, false, None, None).await;

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
            "Service is not in SERVING status. Got status: {}",
            status
        );
        let status = get_status(&mut threshold_health_client, threshold_service_name)
            .await
            .unwrap();
        assert_eq!(
            status,
            ServingStatus::Serving as i32,
            "Service is not in SERVING status. Got status: {}",
            status
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
            "Service is not in SERVING status. Got status: {}",
            status
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
            "Service is not in SERVING status. Got status: {}",
            status
        );
        // Keep the server occupied so it won't shut down immidiately after dropping the handle
        let (tasks, _req_id) = send_dec_reqs(
            3,
            &TEST_THRESHOLD_KEY_ID_4P,
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
            "Service is not in NOT SERVING status. Got status: {}",
            status
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
        let key_id_req = key_id.to_string().try_into().unwrap();

        let mut cts = Vec::new();
        for i in 0..amount_cts {
            let msg = TestingPlaintext::U32(i as u32);
            let (ct, fhe_type) =
                compute_compressed_cipher_from_stored_key(None, msg, &key_id.to_string()).await;
            let ctt = TypedCiphertext {
                ciphertext: ct,
                fhe_type: fhe_type.into(),
                external_handle: i.to_be_bytes().to_vec(),
            };
            cts.push(ctt);
        }

        let dummy_acl_address =
            alloy_primitives::address!("d8da6bf26964af9d7eed9e03e53415d37aa96045");

        // make parallel requests by calling [decrypt] in a thread
        let request_id = RequestId::derive("TEST_DEC_ID").unwrap();
        let req = internal_client
            .decryption_request(
                cts.clone(),
                &dummy_domain(),
                &request_id,
                &dummy_acl_address,
                &key_id_req,
            )
            .unwrap();
        let mut join_set = JoinSet::new();
        for i in 1..=kms_clients.len() as u32 {
            let req_clone = req.clone();
            let mut cur_client = kms_clients.get(&i).unwrap().clone();
            join_set.spawn(async move { cur_client.decrypt(tonic::Request::new(req_clone)).await });
        }
        (join_set, request_id)
    }

    async fn get_dec_resp(
        request_id: &RequestId,
        kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    ) -> JoinSet<Result<tonic::Response<kms_grpc::kms::v1::DecryptionResponse>, tonic::Status>>
    {
        // make parallel requests by calling [get_decrypt_result] in a thread
        let mut join_set = JoinSet::new();
        for i in 1..=kms_clients.len() as u32 {
            let mut cur_client = kms_clients.get(&i).unwrap().clone();
            let req_id_clone = request_id.clone();
            join_set.spawn(async move {
                cur_client
                    .get_decrypt_result(tonic::Request::new(req_id_clone))
                    .await
            });
        }
        join_set
    }

    #[tokio::test]
    #[serial]
    async fn double_tcp_bind() {
        // this is a serial test because another test might randomly select port 50050
        // double tcp bind should fail
        let addr = std::net::SocketAddr::new(crate::consts::DEFAULT_URL.parse().unwrap(), 50050);
        let _zz = tokio::net::TcpListener::bind(addr).await.unwrap();

        // try to bind again and it should fail
        let _yy = tokio::net::TcpListener::bind(addr).await.unwrap_err();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn test_key_gen_centralized() {
        let request_id = RequestId::derive("test_key_gen_centralized").unwrap();
        // Delete potentially old data
        purge(None, None, &request_id.to_string(), 1).await;
        key_gen_centralized(&request_id, FheParameter::Test, None, None).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn test_decompression_key_gen_centralized() {
        let request_id_1 = RequestId::derive("test_key_gen_centralized-1").unwrap();
        let request_id_2 = RequestId::derive("test_key_gen_centralized-2").unwrap();
        let request_id_3 = RequestId::derive("test_decompression_key_gen_centralized").unwrap();
        // Delete potentially old data
        purge(None, None, &request_id_1.to_string(), 1).await;
        purge(None, None, &request_id_2.to_string(), 1).await;
        purge(None, None, &request_id_3.to_string(), 1).await;

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
                from_keyset_id_decompression_only: Some(request_id_1),
                to_keyset_id_decompression_only: Some(request_id_2),
            }),
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn default_key_gen_centralized() {
        let request_id = RequestId::derive("default_key_gen_centralized").unwrap();
        // Delete potentially old data
        purge(None, None, &request_id.to_string(), 1).await;
        key_gen_centralized(&request_id, FheParameter::Default, None, None).await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn default_decompression_key_gen_centralized() {
        let request_id_1 = RequestId::derive("default_key_gen_centralized-1").unwrap();
        let request_id_2 = RequestId::derive("default_key_gen_centralized-2").unwrap();
        let request_id_3 = RequestId::derive("default_decompression_key_gen_centralized").unwrap();
        // Delete potentially old data
        purge(None, None, &request_id_1.to_string(), 1).await;
        purge(None, None, &request_id_2.to_string(), 1).await;
        purge(None, None, &request_id_3.to_string(), 1).await;

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
                from_keyset_id_decompression_only: Some(request_id_1),
                to_keyset_id_decompression_only: Some(request_id_2),
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
        let dkg_params: crate::cryptography::internal_crypto_types::WrappedDKGParams =
            params.into();

        let rate_limiter_conf = RateLimiterConfig {
            bucket_size: 100,
            dec: 1,
            reenc: 1,
            crsgen: 1,
            preproc: 1,
            keygen: 100,
            verify_proven_ct: 1,
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

        // Try to do another request during keygen,
        // the request should be rejected due to rate limiter
        {
            let req_id = RequestId::derive("test rate limiter").unwrap();
            let req = internal_client
                .crs_gen_request(&req_id, Some(1), Some(params), None)
                .unwrap();
            let e = kms_client.crs_gen(req).await.unwrap_err();
            assert_eq!(e.code(), tonic::Code::ResourceExhausted);
        }

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
        if let Some(inner_config) = keyset_config {
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
                }
                KeySetType::DecompressionOnly => {
                    // setup storage
                    let keyid_1 = keyset_added_info
                        .clone()
                        .unwrap()
                        .from_keyset_id_decompression_only
                        .unwrap();
                    let keyid_2 = keyset_added_info
                        .unwrap()
                        .to_keyset_id_decompression_only
                        .unwrap();
                    let priv_storage = FileStorage::new(None, StorageType::PRIV, None).unwrap();
                    let sk_urls = priv_storage
                        .all_urls(&PrivDataType::FheKeyInfo.to_string())
                        .await
                        .unwrap();
                    let sk_url_1 = sk_urls.get(&keyid_1.request_id).unwrap();
                    let sk_url_2 = sk_urls.get(&keyid_2.request_id).unwrap();
                    let handles_1: crate::engine::base::KmsFheKeyHandles =
                        priv_storage.read_data(sk_url_1).await.unwrap();
                    let handles_2: crate::engine::base::KmsFheKeyHandles =
                        priv_storage.read_data(sk_url_2).await.unwrap();

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
        }

        kms_server.assert_shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_crs_gen_manual() {
        let crs_req_id = RequestId::derive("test_crs_gen_manual").unwrap();
        // Delete potentially old data
        purge(None, None, &crs_req_id.to_string(), 1).await;
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
                .get_crs_gen_result(tonic::Request::new(request_id.clone()))
                .await;
        }

        let resp = get_response.unwrap().into_inner();
        let rvcd_req_id = resp.request_id.unwrap();

        // // check that the received request id matches the one we sent in the request
        assert_eq!(rvcd_req_id, client_request_id);

        let crs_info = resp.crs_results.unwrap();
        let pub_storage = FileStorage::new(None, StorageType::PUB, None).unwrap();
        let mut crs_path = pub_storage
            .compute_url(&request_id.to_string(), &PubDataType::CRS.to_string())
            .unwrap()
            .to_string();

        assert!(crs_path.starts_with("file://"));
        crs_path.replace_range(0..7, ""); // remove leading "file:/" from URI, so we can read the file

        // check that CRS signature is verified correctly for the current version
        let crs_unversioned: CompactPkeCrs = safe_read_element_versioned(&crs_path).await.unwrap();
        let client_handle = compute_handle(&crs_unversioned).unwrap();
        assert_eq!(&client_handle, &crs_info.key_handle);

        // try verification with each of the server keys; at least one must pass
        let crs_sig: Signature = bincode::deserialize(&crs_info.signature).unwrap();
        let mut verified = false;
        let server_pks = internal_client.get_server_pks().unwrap();
        for vk in server_pks {
            let v = BaseKmsStruct::verify_sig(&client_handle, &crs_sig, vk).is_ok();
            verified = verified || v;
        }

        // check that verification (with at least 1 server key) worked
        assert!(verified);

        kms_server.assert_shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_crs_gen_centralized() {
        let crs_req_id = RequestId::derive("test_crs_gen_centralized").unwrap();
        // Delete potentially old data
        purge(None, None, &crs_req_id.to_string(), 1).await;
        crs_gen_centralized(&TEST_PARAM, &crs_req_id, Some(FheParameter::Test), false).await;
    }

    #[cfg(feature = "insecure")]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_insecure_crs_gen_centralized() {
        let crs_req_id = RequestId::derive("test_insecure_crs_gen_centralized").unwrap();
        // Delete potentially old data
        purge(None, None, &crs_req_id.to_string(), 1).await;
        crs_gen_centralized(&TEST_PARAM, &crs_req_id, Some(FheParameter::Test), true).await;
    }

    /// test centralized crs generation via client interface
    async fn crs_gen_centralized(
        dkg_params: &DKGParams,
        crs_req_id: &RequestId,
        params: Option<FheParameter>,
        insecure: bool,
    ) {
        let rate_limiter_conf = RateLimiterConfig {
            bucket_size: 100,
            dec: 1,
            reenc: 1,
            crsgen: 100,
            preproc: 1,
            keygen: 1,
            verify_proven_ct: 1,
        };
        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
        let (kms_server, mut kms_client, internal_client) =
            super::test_tools::centralized_handles(dkg_params, Some(rate_limiter_conf)).await;

        let max_num_bits = if params.unwrap() == FheParameter::Test {
            Some(1)
        } else {
            // The default is 2048 which is too slow for tests, so we switch to 256
            Some(256)
        };
        let gen_req = internal_client
            .crs_gen_request(crs_req_id, max_num_bits, params, None)
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

        // Try to do another request during crs,
        // the request should be rejected due to rate limiter
        {
            let req_id = RequestId::derive("test rate limiter").unwrap();
            let req = internal_client
                .crs_gen_request(&req_id, Some(1), Some(FheParameter::Test), None)
                .unwrap();
            let e = kms_client.crs_gen(req).await.unwrap_err();
            assert_eq!(e.code(), tonic::Code::ResourceExhausted);
        }

        let mut response = Err(tonic::Status::not_found(""));
        let mut ctr = 0;
        while response.is_err() && ctr < 5 {
            response = kms_client
                .get_crs_gen_result(tonic::Request::new(crs_req_id.clone()))
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
        verify_pp(dkg_params, &pp).await;

        kms_server.assert_shutdown().await;
    }

    #[rstest::rstest]
    #[case(vec![TestingPlaintext::Bool(true)])]
    #[case(vec![TestingPlaintext::U4(12)])]
    #[case(vec![TestingPlaintext::U8(u8::MAX)])]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_verify_proven_ct_centralized(#[case] msgs: Vec<TestingPlaintext>) {
        let proven_ct_id = RequestId::derive("test_verify_proven_ct_centralized").unwrap();
        verify_proven_ct_centralized(
            msgs,
            &TEST_PARAM,
            &proven_ct_id,
            &crate::consts::TEST_CENTRAL_CRS_ID,
            &crate::consts::TEST_CENTRAL_KEY_ID.to_string(),
        )
        .await;
    }

    /// test centralized ZK probing via client interface
    pub(crate) async fn verify_proven_ct_centralized(
        msgs: Vec<TestingPlaintext>,
        dkg_params: &DKGParams,
        proven_ct_id: &RequestId,
        crs_req_id: &RequestId,
        key_handle: &str,
    ) {
        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
        let (kms_server, mut kms_client, internal_client) =
            super::test_tools::centralized_handles(dkg_params, None).await;

        // next use the verify endpoint to check the proof
        // for this we need to read the key
        tracing::info!("Starting zk verification");
        let key_id = RequestId {
            request_id: key_handle.to_owned(),
        };
        let pub_storage = FileStorage::new(None, StorageType::PUB, None).unwrap();

        // try to make a proof and check that it works
        let dummy_contract_address =
            alloy_primitives::address!("d8da6bf26964af9d7eed9e03e53415d37aa96045");

        let dummy_acl_address =
            alloy_primitives::address!("01da6bf26964af9d7eed9e03e53415d37aa960ff");

        let metadata = assemble_metadata_alloy(
            &dummy_contract_address,
            &internal_client.get_client_address(),
            &dummy_acl_address,
            &dummy_domain().chain_id.unwrap(),
        );

        let proven_ct = compute_proven_ct_from_stored_key(
            None,
            msgs,
            key_handle,
            &crs_req_id.request_id,
            &metadata,
        )
        .await;
        // Sanity check that the proof is valid
        let pk = load_pk_from_storage(None, key_handle).await;
        let pp = internal_client
            .get_crs(crs_req_id, &pub_storage)
            .await
            .unwrap();
        assert!(tfhe::zk::ZkVerificationOutcome::Valid == proven_ct.verify(&pp, &pk, &metadata));

        let verify_proven_ct_req = internal_client
            .verify_proven_ct_request(
                crs_req_id,
                &key_id,
                &dummy_contract_address,
                &proven_ct,
                &dummy_domain(),
                &dummy_acl_address,
                proven_ct_id,
            )
            .unwrap();

        let _ = kms_client
            .verify_proven_ct(tonic::Request::new(verify_proven_ct_req))
            .await
            .unwrap();

        let mut ctr = 0;
        let mut verify_proven_ct_response = kms_client
            .get_verify_proven_ct_result(proven_ct_id.clone())
            .await;
        while verify_proven_ct_response.is_err() && ctr < 1000 {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            verify_proven_ct_response = kms_client
                .get_verify_proven_ct_result(tonic::Request::new(proven_ct_id.clone()))
                .await;
            ctr += 1;
        }

        let verify_proven_ct_response_inner = verify_proven_ct_response.unwrap().into_inner();
        let sigs = internal_client
            .process_verify_proven_ct_resp(&[verify_proven_ct_response_inner], 1)
            .unwrap();
        assert_eq!(sigs.len(), 1);

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
    #[rstest::rstest]
    #[case(4)]
    #[serial]
    async fn test_insecure_crs_gen_threshold(#[case] amount_parties: usize) {
        crs_gen(
            amount_parties,
            FheParameter::Test,
            Some(16),
            true, // insecure
            1,
            false,
        )
        .await;
    }

    // Poll the client method function `f_to_poll` until there is a result
    // or error out until some timeout.
    // The requests from the `reqs` argument need to implement `RequestIdGetter`.
    #[macro_export]
    macro_rules! par_poll_responses {
        ($parallelism:expr,$kms_clients:expr,$reqs:expr,$f_to_poll:ident,$amount_parties:expr) => {{
            use $crate::consts::MAX_TRIES;
            let mut joined_responses = vec![];
            for count in 0..MAX_TRIES {
                joined_responses = vec![];
                tokio::time::sleep(tokio::time::Duration::from_secs(5 * $parallelism as u64)).await;

                let mut tasks_get = JoinSet::new();
                for req in $reqs {
                    for i in 1..=$amount_parties as u32 {
                        // Make sure we only consider clients for which
                        // we haven't killed the corresponding server
                        if let Some(cur_client) = $kms_clients.get(&i) {
                            let mut cur_client = cur_client.clone();
                            let req_id_cloned = req.request_id().unwrap();
                            tasks_get.spawn(async move {
                                (
                                    i,
                                    req_id_cloned.clone(),
                                    cur_client
                                        .$f_to_poll(tonic::Request::new(req_id_cloned))
                                        .await,
                                )
                            });
                        }
                    }
                }
                let mut responses_get = Vec::new();
                while let Some(Ok((j, req_id, Ok(resp)))) = tasks_get.join_next().await {
                    responses_get.push((j, req_id, resp.into_inner()));
                }

                // add the responses in this iteration to the bigger vector
                joined_responses.append(&mut responses_get);
                if joined_responses.len() == $kms_clients.len() * $parallelism {
                    break;
                }

                // fail if we can't find a response
                if count == MAX_TRIES - 1 {
                    panic!("could not get crs after {} tries", count);
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
            let req_crs: RequestId = RequestId::derive(&format!(
                "full_crs_{amount_parties}_{:?}_{:?}_{i}_{insecure}",
                max_bits, parameter
            ))
            .unwrap();
            purge(None, None, &req_crs.to_string(), amount_parties).await;
        }
        let dkg_param: WrappedDKGParams = parameter.into();

        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
        // The threshold handle should only be started after the storage is purged
        // since the threshold parties will load the CRS from private storage
        let rate_limiter_conf = RateLimiterConfig {
            bucket_size: 100 * iterations,
            dec: 1,
            reenc: 1,
            crsgen: 100,
            preproc: 1,
            keygen: 1,
            verify_proven_ct: 1,
        };

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
            let mut crs_set = JoinSet::new();
            for i in 0..iterations {
                let cur_id: RequestId = RequestId::derive(&format!(
                    "full_crs_{amount_parties}_{:?}_{:?}_{i}_{insecure}",
                    max_bits, parameter
                ))
                .unwrap();
                // let parameter_clone = parameter.clone();
                // let max_bits = max_bits.clone();
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
                            iterations,
                        )
                        .await
                    }
                });
            }
        } else {
            for i in 0..iterations {
                let cur_id: RequestId = RequestId::derive(&format!(
                    "full_crs_{amount_parties}_{:?}_{:?}_{i}_{insecure}",
                    max_bits, parameter
                ))
                .unwrap();
                run_crs(
                    parameter,
                    &kms_clients,
                    &internal_client,
                    insecure,
                    &cur_id,
                    max_bits,
                    iterations,
                )
                .await;
            }
        }
    }

    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    async fn run_crs(
        parameter: FheParameter,
        kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
        internal_client: &Client,
        insecure: bool,
        crs_req_id: &RequestId,
        max_bits: Option<u32>,
        parallelism: usize,
    ) {
        let dkg_param: WrappedDKGParams = parameter.into();
        let crs_req = internal_client
            .crs_gen_request(crs_req_id, max_bits, Some(parameter), None)
            .unwrap();

        let responses = launch_crs(&vec![crs_req.clone()], kms_clients, insecure).await;
        for response in responses {
            assert!(response.is_ok());
        }
        wait_for_crsgen_result(
            &vec![crs_req],
            kms_clients,
            internal_client,
            &dkg_param,
            parallelism,
        )
        .await;
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
        parallelism: usize,
    ) {
        let amount_parties = kms_clients.len();
        // wait a bit for the crs generation to finish
        let joined_responses = par_poll_responses!(
            parallelism,
            kms_clients,
            reqs,
            get_crs_gen_result,
            amount_parties
        );

        // first check the happy path
        // the public parameter is checked in ddec tests, so we don't specifically check _pp
        for req in reqs {
            let req_id = req.clone().request_id.unwrap();
            let joined_responses: Vec<_> = joined_responses
                .iter()
                .cloned()
                .filter_map(
                    |(i, rid, resp)| {
                        if rid == req_id {
                            Some((i, resp))
                        } else {
                            None
                        }
                    },
                )
                .collect();

            // we need to setup the storage devices in the right order
            // so that the client can read the CRS
            let (storage_readers, final_responses): (Vec<_>, Vec<_>) = joined_responses
                .into_iter()
                .map(|(i, res)| {
                    (
                        { FileStorage::new(None, StorageType::PUB, Some(i as usize)).unwrap() },
                        res,
                    )
                })
                .unzip();
            // Compute threshold < amount_parties/3
            let threshold = max_threshold(amount_parties);
            let min_count_agree = (threshold + 1) as u32;

            let pp = internal_client
                .process_distributed_crs_result(
                    &req_id,
                    final_responses.clone(),
                    &storage_readers,
                    min_count_agree,
                )
                .await
                .unwrap();
            verify_pp(param, &pp).await;

            // if there are [THRESHOLD] result missing, we can still recover the result
            let _pp = internal_client
                .process_distributed_crs_result(
                    &req_id,
                    final_responses[0..final_responses.len() - threshold].to_vec(),
                    &storage_readers,
                    min_count_agree,
                )
                .await
                .unwrap();

            // if there are only THRESHOLD results then we do not have consensus as at least THRESHOLD+1 is needed
            assert!(internal_client
                .process_distributed_crs_result(
                    &req_id,
                    final_responses[0..threshold].to_vec(),
                    &storage_readers,
                    min_count_agree
                )
                .await
                .is_err());

            // if the request_id is wrong, we get nothing
            let bad_request_id = RequestId::derive("bad_request_id").unwrap();
            assert!(internal_client
                .process_distributed_crs_result(
                    &bad_request_id,
                    final_responses.clone(),
                    &storage_readers,
                    min_count_agree
                )
                .await
                .is_err());

            // test that having [THRESHOLD] wrong signatures still works
            let mut final_responses_with_bad_sig = final_responses.clone();
            let client_sk = internal_client.client_sk.clone().unwrap();
            let bad_sig = bincode::serialize(
                &crate::cryptography::signcryption::sign(&"wrong msg".to_string(), &client_sk)
                    .unwrap(),
            )
            .unwrap();
            set_signatures(&mut final_responses_with_bad_sig, threshold, &bad_sig);

            let _pp = internal_client
                .process_distributed_crs_result(
                    &req_id,
                    final_responses_with_bad_sig.clone(),
                    &storage_readers,
                    min_count_agree,
                )
                .await
                .unwrap();

            // having [amount_parties-threshold] wrong signatures won't work
            set_signatures(
                &mut final_responses_with_bad_sig,
                amount_parties - threshold,
                &bad_sig,
            );
            assert!(internal_client
                .process_distributed_crs_result(
                    &req_id,
                    final_responses_with_bad_sig,
                    &storage_readers,
                    min_count_agree
                )
                .await
                .is_err());

            // having [amount_parties-(threshold+1)] wrong digests still works
            let mut final_responses_with_bad_digest = final_responses.clone();
            set_digests(
                &mut final_responses_with_bad_digest,
                amount_parties - (threshold + 1),
                "9fdca770403e2eed9dacb4cdd405a14fc6df7226",
            );
            let _pp = internal_client
                .process_distributed_crs_result(
                    &req_id,
                    final_responses_with_bad_digest.clone(),
                    &storage_readers,
                    min_count_agree,
                )
                .await
                .unwrap();

            // having [amount_parties-threshold] wrong digests will fail
            set_digests(
                &mut final_responses_with_bad_digest,
                amount_parties - threshold,
                "9fdca770403e2eed9dacb4cdd405a14fc6df7226",
            );
            assert!(internal_client
                .process_distributed_crs_result(
                    &req_id,
                    final_responses_with_bad_digest,
                    &storage_readers,
                    min_count_agree
                )
                .await
                .is_err());
        }
    }

    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    fn set_signatures(
        crs_gen_results: &mut [crate::client::CrsGenResult],
        count: usize,
        sig: &[u8],
    ) {
        for crs_gen_result in crs_gen_results.iter_mut().take(count) {
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
        crs_gen_results: &mut [crate::client::CrsGenResult],
        count: usize,
        digest: &str,
    ) {
        for crs_gen_result in crs_gen_results.iter_mut().take(count) {
            match &mut crs_gen_result.crs_results {
                Some(info) => {
                    // each hex-digit is 4 bits, 160 bits is 40 characters
                    assert_eq!(40, info.key_handle.len());
                    // it's unlikely that we generate the same signature more than once
                    info.key_handle = digest.to_string();
                }
                None => panic!("missing SignedPubDataHandle"),
            }
        }
    }

    /////////////////////////////////
    //
    //        END OF CRS SECTION
    //
    /////////////////////////////////

    #[tokio::test(flavor = "multi_thread")]
    #[rstest::rstest]
    #[case(vec![TestingPlaintext::U8(u8::MAX)], 7, &TEST_THRESHOLD_KEY_ID_7P, &TEST_THRESHOLD_CRS_ID_7P)]
    #[case(vec![TestingPlaintext::U8(u8::MAX)], 4, &TEST_THRESHOLD_KEY_ID_4P, &TEST_THRESHOLD_CRS_ID_4P)]
    #[case(vec![TestingPlaintext::Bool(true)], 4, &TEST_THRESHOLD_KEY_ID_4P, &TEST_THRESHOLD_CRS_ID_4P)]
    #[serial]
    async fn test_verify_proven_ct_threshold(
        #[case] msgs: Vec<TestingPlaintext>,
        #[case] amount_parties: usize,
        #[case] key_id: &RequestId,
        #[case] crs_id: &RequestId,
    ) {
        verify_proven_ct_threshold(msgs, 1, crs_id, key_id, TEST_PARAM, amount_parties, None).await
    }

    #[cfg(feature = "slow_tests")]
    #[rstest::rstest]
    #[case(vec![TestingPlaintext::U8(u8::MAX)], 1, 7, &DEFAULT_THRESHOLD_KEY_ID_7P, &DEFAULT_THRESHOLD_CRS_ID_7P)]
    #[case(vec![TestingPlaintext::U8(u8::MAX)], 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P, &DEFAULT_THRESHOLD_CRS_ID_4P)]
    #[case(vec![TestingPlaintext::Bool(true)], 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P, &DEFAULT_THRESHOLD_CRS_ID_4P)]
    #[case(vec![TestingPlaintext::U8(u8::MAX)], 4, 4, &DEFAULT_THRESHOLD_KEY_ID_4P, &DEFAULT_THRESHOLD_CRS_ID_4P)]
    #[case(vec![TestingPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32]))], 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P, &DEFAULT_THRESHOLD_CRS_ID_4P)]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn default_verify_proven_ct_threshold(
        #[case] msgs: Vec<TestingPlaintext>,
        #[case] parallelism: usize,
        #[case] amount_parties: usize,
        #[case] key_id: &RequestId,
        #[case] crs_id: &RequestId,
    ) {
        verify_proven_ct_threshold(
            msgs,
            parallelism,
            crs_id,
            key_id,
            crate::consts::DEFAULT_PARAM,
            amount_parties,
            None,
        )
        .await
    }

    #[cfg(feature = "slow_tests")]
    #[rstest::rstest]
    #[case(vec![TestingPlaintext::U8(u8::MAX)], 1, 7,Some(vec![3,6]), &DEFAULT_THRESHOLD_KEY_ID_7P, &DEFAULT_THRESHOLD_CRS_ID_7P)]
    #[case(vec![TestingPlaintext::U8(u8::MAX)],1, 4, Some(vec![1]), &DEFAULT_THRESHOLD_KEY_ID_4P, &DEFAULT_THRESHOLD_CRS_ID_4P)]
    #[case(vec![TestingPlaintext::Bool(true)],1, 4, Some(vec![1]), &DEFAULT_THRESHOLD_KEY_ID_4P, &DEFAULT_THRESHOLD_CRS_ID_4P)]
    #[case(vec![TestingPlaintext::U8(u8::MAX)],4, 4,Some(vec![2]), &DEFAULT_THRESHOLD_KEY_ID_4P, &DEFAULT_THRESHOLD_CRS_ID_4P)]
    #[case(vec![TestingPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32]))],1, 4, Some(vec![1]), &DEFAULT_THRESHOLD_KEY_ID_4P, &DEFAULT_THRESHOLD_CRS_ID_4P)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn default_verify_proven_ct_threshold_with_crash(
        #[case] msgs: Vec<TestingPlaintext>,
        #[case] parallelism: usize,
        #[case] amount_parties: usize,
        #[case] party_ids_to_crash: Option<Vec<usize>>,
        #[case] key_id: &RequestId,
        #[case] crs_id: &RequestId,
    ) {
        verify_proven_ct_threshold(
            msgs,
            parallelism,
            crs_id,
            key_id,
            crate::consts::DEFAULT_PARAM,
            amount_parties,
            party_ids_to_crash,
        )
        .await
    }

    pub(crate) async fn verify_proven_ct_threshold(
        msgs: Vec<TestingPlaintext>,
        parallelism: usize,
        crs_handle: &RequestId,
        key_handle: &RequestId,
        dkg_params: DKGParams,
        amount_parties: usize,
        party_ids_to_crash: Option<Vec<usize>>,
    ) {
        assert!(parallelism > 0);

        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
        // The threshold handle should only be started after the storage is purged
        // since the threshold parties will load the CRS from private storage
        let (mut kms_servers, mut kms_clients, internal_client) =
            threshold_handles(dkg_params, amount_parties, true, None, None).await;

        let pub_storage = FileStorage::new(None, StorageType::PUB, Some(1)).unwrap();
        let pp = internal_client
            .get_crs(crs_handle, &pub_storage)
            .await
            .unwrap();
        // Sanity check the pp
        verify_pp(&dkg_params, &pp).await;

        let dummy_contract_address =
            alloy_primitives::address!("d8da6bf26964af9d7eed9e03e53415d37aa96045");

        let dummy_acl_address =
            alloy_primitives::address!("EEdA6bf26964aF9D7Eed9e03e53415D37aa960EE");

        let metadata = assemble_metadata_alloy(
            &dummy_contract_address,
            &internal_client.get_client_address(),
            &dummy_acl_address,
            &dummy_domain().chain_id.unwrap(),
        );

        let proven_ct = compute_proven_ct_from_stored_key(
            None,
            msgs,
            &key_handle.to_string(),
            &crs_handle.request_id,
            &metadata,
        )
        .await;
        // Sanity check that the proof is valid
        let pk = load_pk_from_storage(None, &key_handle.to_string()).await;
        assert!(tfhe::zk::ZkVerificationOutcome::Valid == proven_ct.verify(&pp, &pk, &metadata));

        let reqs: Vec<_> = (0..parallelism)
            .map(|j| {
                let request_id =
                    RequestId::derive(&format!("verify_proven_ct_threshold_{amount_parties}_{j}"))
                        .unwrap();
                internal_client
                    .verify_proven_ct_request(
                        crs_handle,
                        key_handle,
                        &dummy_contract_address,
                        &proven_ct,
                        &dummy_domain(),
                        &dummy_acl_address,
                        &request_id,
                    )
                    .unwrap()
            })
            .collect();

        // Either send the request, or crash the party if it's in
        // party_ids_to_crash
        let mut tasks_gen = JoinSet::new();
        let party_ids_to_crash = party_ids_to_crash.unwrap_or_default();
        for req in &reqs {
            for i in 1..=amount_parties as u32 {
                if party_ids_to_crash.contains(&(i as usize)) {
                    // After the first "parallel" iteration the party is already crashed
                    if let Some(server_handle) = kms_servers.remove(&i) {
                        server_handle.server.shutdown().await.unwrap();
                        check_port_is_closed(server_handle.service_port).await;
                        let _kms_client = kms_clients.remove(&i).unwrap();
                    }
                } else {
                    let mut cur_client = kms_clients.get(&i).unwrap().clone();
                    let req_clone = req.clone();
                    tasks_gen.spawn(async move {
                        cur_client
                            .verify_proven_ct(tonic::Request::new(req_clone))
                            .await
                    });
                }
            }
        }
        let mut responses_gen = Vec::new();
        while let Some(inner) = tasks_gen.join_next().await {
            let resp = inner.unwrap().unwrap();
            responses_gen.push(resp.into_inner());
        }
        assert_eq!(
            responses_gen.len(),
            (amount_parties - party_ids_to_crash.len()) * parallelism
        );

        // wait a bit for the validation to finish
        let joined_responses = par_poll_responses!(
            parallelism,
            kms_clients,
            &reqs,
            get_verify_proven_ct_result,
            amount_parties
        );

        for req in reqs {
            let req_id = req.request_id.unwrap();
            let joined_responses: Vec<_> = joined_responses
                .iter()
                .cloned()
                .filter_map(
                    |(_i, rid, resp)| {
                        if rid == req_id {
                            Some(resp)
                        } else {
                            None
                        }
                    },
                )
                .collect();
            // Compute threshold < amount_parties/3
            let threshold = max_threshold(amount_parties);
            let min_count_agree = (threshold + 1) as u32;

            let verify_proven_ct_sigs = internal_client
                .process_verify_proven_ct_resp(&joined_responses, min_count_agree)
                .unwrap();

            assert_eq!(
                verify_proven_ct_sigs.len(),
                (amount_parties - party_ids_to_crash.len())
            );
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_decryption_central() {
        decryption_centralized(
            &TEST_PARAM,
            &crate::consts::TEST_CENTRAL_KEY_ID.to_string(),
            vec![
                TestingPlaintext::U8(42),
                TestingPlaintext::U32(9876),
                TestingPlaintext::U16(420),
                TestingPlaintext::Bool(true),
            ],
            3, // 3 parallel requests
            true,
        )
        .await;
    }

    #[tokio::test]
    #[serial]
    async fn test_decryption_central_no_decompression() {
        decryption_centralized(
            &TEST_PARAM,
            &crate::consts::TEST_CENTRAL_KEY_ID.to_string(),
            vec![
                TestingPlaintext::U8(42),
                TestingPlaintext::U32(9876),
                TestingPlaintext::U16(420),
                TestingPlaintext::Bool(true),
            ],
            3, // 3 parallel requests
            false,
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
            &DEFAULT_CENTRAL_KEY_ID.to_string(),
            msgs,
            parallelism,
            false,
        )
        .await;
    }

    pub(crate) async fn decryption_centralized(
        dkg_params: &DKGParams,
        key_id: &str,
        msgs: Vec<TestingPlaintext>,
        parallelism: usize,
        compression: bool,
    ) {
        assert!(parallelism > 0);
        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
        let (kms_server, kms_client, mut internal_client) =
            super::test_tools::centralized_handles(dkg_params, None).await;
        let req_key_id = key_id.to_owned().try_into().unwrap();

        let mut cts = Vec::new();
        for (i, msg) in msgs.clone().into_iter().enumerate() {
            let (ct, fhe_type) = if compression {
                compute_compressed_cipher_from_stored_key(None, msg, key_id).await
            } else {
                compute_cipher_from_stored_key(None, msg, key_id).await
            };
            let ctt = TypedCiphertext {
                ciphertext: ct,
                fhe_type: fhe_type.into(),
                external_handle: i.to_be_bytes().to_vec(),
            };
            cts.push(ctt);
        }

        let dummy_acl_address =
            alloy_primitives::address!("d8da6bf26964af9d7eed9e03e53415d37aa96045");

        // build parallel requests
        let reqs: Vec<_> = (0..parallelism)
            .map(|j: usize| {
                let request_id = RequestId::derive(&format!("TEST_DEC_ID_{j}")).unwrap();

                internal_client
                    .decryption_request(
                        cts.clone(),
                        &dummy_domain(),
                        &request_id,
                        &dummy_acl_address,
                        &req_key_id,
                    )
                    .unwrap()
            })
            .collect();

        // send all decryption requests simultaneously
        let mut req_tasks = JoinSet::new();
        for j in 0..parallelism {
            let req_cloned = reqs.get(j).unwrap().clone();
            let mut cur_client = kms_client.clone();
            req_tasks
                .spawn(async move { cur_client.decrypt(tonic::Request::new(req_cloned)).await });
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
                    .get_decrypt_result(tonic::Request::new(req_id_clone.clone()))
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
                        .get_decrypt_result(tonic::Request::new(req_id_clone.clone()))
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
                assert_eq!(FheType::from(msgs[i]), plaintext.fhe_type());

                match msgs[i] {
                    TestingPlaintext::Bool(x) => assert_eq!(x, plaintext.as_bool()),
                    TestingPlaintext::U4(x) => assert_eq!(x, plaintext.as_u4()),
                    TestingPlaintext::U8(x) => assert_eq!(x, plaintext.as_u8()),
                    TestingPlaintext::U16(x) => assert_eq!(x, plaintext.as_u16()),
                    TestingPlaintext::U32(x) => assert_eq!(x, plaintext.as_u32()),
                    TestingPlaintext::U64(x) => assert_eq!(x, plaintext.as_u64()),
                    TestingPlaintext::U128(x) => assert_eq!(x, plaintext.as_u128()),
                    TestingPlaintext::U160(x) => assert_eq!(x, plaintext.as_u160()),
                    TestingPlaintext::U256(x) => assert_eq!(x, plaintext.as_u256()),
                    TestingPlaintext::U512(x) => assert_eq!(x, plaintext.as_u512()),
                    TestingPlaintext::U1024(x) => assert_eq!(x, plaintext.as_u1024()),
                    TestingPlaintext::U2048(x) => assert_eq!(x, plaintext.as_u2048()),
                }
            }
        }

        kms_server.assert_shutdown().await;
    }

    #[rstest::rstest]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_reencryption_centralized(#[values(true, false)] secure: bool) {
        reencryption_centralized(
            &TEST_PARAM,
            &crate::consts::TEST_CENTRAL_KEY_ID.to_string(),
            false,
            TestingPlaintext::U8(48),
            4,
            secure,
        )
        .await;
    }

    #[cfg(feature = "wasm_tests")]
    #[rstest::rstest]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn test_reencryption_centralized_and_write_transcript(
        #[values(true, false)] secure: bool,
    ) {
        reencryption_centralized(
            &TEST_PARAM,
            &TEST_CENTRAL_KEY_ID.to_string(),
            true,
            TestingPlaintext::U8(48),
            1, // wasm tests are single-threaded
            secure,
        )
        .await;
    }

    #[cfg(all(feature = "wasm_tests", feature = "slow_tests"))]
    #[rstest::rstest]
    #[case(TestingPlaintext::Bool(true))]
    #[case(TestingPlaintext::U8(u8::MAX))]
    #[case(TestingPlaintext::U16(u16::MAX))]
    #[case(TestingPlaintext::U32(u32::MAX))]
    #[case(TestingPlaintext::U64(u64::MAX))]
    // #[case(TestingPlaintext::U128(u128::MAX))]
    // #[case(TestingPlaintext::U160(tfhe::integer::U256::from((u128::MAX, u32::MAX as u128))))]
    // #[case(TestingPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX))))]
    // #[case(TestingPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32])))]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn default_reencryption_centralized_and_write_transcript(
        #[case] msg: TestingPlaintext,
        #[values(true, false)] secure: bool,
    ) {
        use crate::consts::DEFAULT_PARAM;

        reencryption_centralized(
            &DEFAULT_PARAM,
            &DEFAULT_CENTRAL_KEY_ID.to_string(),
            true,
            msg,
            1, // wasm tests are single-threaded
            secure,
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[rstest::rstest]
    #[case(TestingPlaintext::U8(u8::MAX), 1)]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn default_reencryption_centralized(
        #[case] msg: TestingPlaintext,
        #[case] parallelism: usize,
        #[values(true, false)] secure: bool,
    ) {
        use crate::consts::DEFAULT_PARAM;

        reencryption_centralized(
            &DEFAULT_PARAM,
            &DEFAULT_CENTRAL_KEY_ID.to_string(),
            false,
            msg,
            parallelism,
            secure,
        )
        .await;
    }

    pub(crate) async fn reencryption_centralized(
        dkg_params: &DKGParams,
        key_id: &str,
        _write_transcript: bool,
        msg: TestingPlaintext,
        parallelism: usize,
        secure: bool,
    ) {
        assert!(parallelism > 0);
        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
        let (kms_server, kms_client, mut internal_client) =
            super::test_tools::centralized_handles(dkg_params, None).await;
        let (ct, fhe_type) = compute_compressed_cipher_from_stored_key(None, msg, key_id).await;
        let req_key_id = key_id.to_owned().try_into().unwrap();

        internal_client.convert_to_addresses();

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
                    fhe_type: fhe_type.into(),
                    external_handle: j.to_be_bytes().to_vec(),
                }];
                let request_id = RequestId::derive(&format!("TEST_REENC_ID_{j}")).unwrap();
                internal_client
                    .reencryption_request(
                        &dummy_domain(),
                        typed_ciphertexts,
                        &request_id,
                        &req_key_id,
                    )
                    .unwrap()
            })
            .collect();

        // send all reencryption requests simultaneously
        let mut req_tasks = JoinSet::new();
        for j in 0..parallelism {
            let req_cloned = reqs.get(j).unwrap().0.clone();
            let mut cur_client = kms_client.clone();
            req_tasks
                .spawn(async move { cur_client.reencrypt(tonic::Request::new(req_cloned)).await });
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

        // query for reencryption responses
        let mut resp_tasks = JoinSet::new();
        for req in &reqs {
            let req_id_clone = req.0.request_id.as_ref().unwrap().clone();
            let mut cur_client = kms_client.clone();
            resp_tasks.spawn(async move {
                // Sleep initially to give the server some time to complete the reencryption
                tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

                // send query
                let mut response = cur_client
                    .get_reencrypt_result(tonic::Request::new(req_id_clone.clone()))
                    .await;

                // retry counter
                let mut ctr = 0_u64;

                // retry while reencryption is not finished, wait between retries and only up to a maximum number of retries
                while response.is_err()
                    && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
                {
                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                    // we may wait up to 50s for tests (include slow profiles), for big ciphertexts
                    if ctr >= 1000 {
                        panic!("timeout while waiting for reencryption result");
                    }
                    ctr += 1;
                    response = cur_client
                        .get_reencrypt_result(tonic::Request::new(req_id_clone.clone()))
                        .await;
                }

                // we have a valid response or some error happened, return this
                (req_id_clone, response.unwrap().into_inner())
            });
        }

        // collect reencryption outputs
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
                let transcript = TestingReencryptionTranscript {
                    server_addrs: internal_client.get_server_addrs().unwrap().clone(),
                    client_address: internal_client.client_address,
                    client_sk: internal_client.client_sk.clone(),
                    degree: 0,
                    params: internal_client.params,
                    fhe_types: vec![FheType::from(msg)],
                    pts: vec![TypedPlaintext::from(msg).bytes.clone()],
                    cts: reqs[0]
                        .0
                        .payload
                        .as_ref()
                        .unwrap()
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
            let client_request = ParsedReencryptionRequest::try_from(req).unwrap();
            let plaintexts = if secure {
                internal_client
                    .process_reencryption_resp(
                        &client_request,
                        &eip712_domain,
                        &responses,
                        enc_pk,
                        enc_sk,
                    )
                    .unwrap()
            } else {
                internal_client.server_identities =
                    // one dummy address is needed to force insecure_process_reencryption_resp
                    // in the centralized mode
                    ServerIdentities::Addrs(vec![alloy_primitives::address!(
                        "d8da6bf26964af9d7eed9e03e53415d37aa96045"
                    )]);
                internal_client
                    .insecure_process_reencryption_resp(&responses, enc_pk, enc_sk)
                    .unwrap()
            };

            for plaintext in plaintexts {
                assert_eq!(FheType::from(msg), plaintext.fhe_type());
                match msg {
                    TestingPlaintext::Bool(x) => assert_eq!(x, plaintext.as_bool()),
                    TestingPlaintext::U4(x) => assert_eq!(x, plaintext.as_u4()),
                    TestingPlaintext::U8(x) => assert_eq!(x, plaintext.as_u8()),
                    TestingPlaintext::U16(x) => assert_eq!(x, plaintext.as_u16()),
                    TestingPlaintext::U32(x) => assert_eq!(x, plaintext.as_u32()),
                    TestingPlaintext::U64(x) => assert_eq!(x, plaintext.as_u64()),
                    TestingPlaintext::U128(x) => assert_eq!(x, plaintext.as_u128()),
                    TestingPlaintext::U160(x) => assert_eq!(x, plaintext.as_u160()),
                    TestingPlaintext::U256(x) => assert_eq!(x, plaintext.as_u256()),
                    TestingPlaintext::U512(x) => assert_eq!(x, plaintext.as_u512()),
                    TestingPlaintext::U1024(x) => assert_eq!(x, plaintext.as_u1024()),
                    TestingPlaintext::U2048(x) => assert_eq!(x, plaintext.as_u2048()),
                }
            }
        }

        kms_server.assert_shutdown().await;
    }

    #[tokio::test(flavor = "multi_thread")]
    #[rstest::rstest]
    #[case(7, &TEST_THRESHOLD_KEY_ID_7P.to_string(), DecryptionMode::NoiseFloodSmall)]
    #[case(4, &TEST_THRESHOLD_KEY_ID_4P.to_string(), DecryptionMode::NoiseFloodSmall)]
    #[case(4, &TEST_THRESHOLD_KEY_ID_4P.to_string(), DecryptionMode::BitDecSmall)]
    #[serial]
    async fn test_decryption_threshold_no_decompression(
        #[case] amount_parties: usize,
        #[case] key_id: &str,
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
            2,
            false,
            amount_parties,
            None,
            Some(decryption_mode),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread")]
    #[rstest::rstest]
    #[case(7, &TEST_THRESHOLD_KEY_ID_7P.to_string(), DecryptionMode::NoiseFloodSmall)]
    #[case(4, &TEST_THRESHOLD_KEY_ID_4P.to_string(), DecryptionMode::NoiseFloodSmall)]
    #[case(4, &TEST_THRESHOLD_KEY_ID_4P.to_string(), DecryptionMode::BitDecSmall)]
    #[serial]
    async fn test_decryption_threshold_with_decompression(
        #[case] amount_parties: usize,
        #[case] key_id: &str,
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
            2,
            true,
            amount_parties,
            None,
            Some(decryption_mode),
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[rstest::rstest]
    #[case(vec![TestingPlaintext::U8(u8::MAX)], 1, 7, &DEFAULT_THRESHOLD_KEY_ID_7P.to_string())]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn default_decryption_threshold(
        #[case] msg: Vec<TestingPlaintext>,
        #[case] parallelism: usize,
        #[case] amount_parties: usize,
        #[case] key_id: &str,
    ) {
        use crate::consts::DEFAULT_PARAM;

        decryption_threshold(
            DEFAULT_PARAM,
            key_id,
            msg,
            parallelism,
            true,
            amount_parties,
            None,
            None,
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[rstest::rstest]
    #[case(vec![TestingPlaintext::U8(u8::MAX)], 1, 4,Some(vec![1]), &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn default_decryption_threshold_with_crash(
        #[case] msg: Vec<TestingPlaintext>,
        #[case] parallelism: usize,
        #[case] amount_parties: usize,
        #[case] party_ids_to_crash: Option<Vec<usize>>,
        #[case] key_id: &str,
    ) {
        use crate::consts::DEFAULT_PARAM;

        decryption_threshold(
            DEFAULT_PARAM,
            key_id,
            msg,
            parallelism,
            true,
            amount_parties,
            party_ids_to_crash,
            None,
        )
        .await;
    }

    #[expect(clippy::too_many_arguments)]
    pub(crate) async fn decryption_threshold(
        dkg_params: DKGParams,
        key_id: &str,
        msgs: Vec<TestingPlaintext>,
        parallelism: usize,
        compression: bool,
        amount_parties: usize,
        party_ids_to_crash: Option<Vec<usize>>,
        decryption_mode: Option<DecryptionMode>,
    ) {
        assert!(parallelism > 0);
        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
        let rate_limiter_conf = RateLimiterConfig {
            bucket_size: 100 * parallelism,
            dec: 100,
            reenc: 1,
            crsgen: 1,
            preproc: 1,
            keygen: 1,
            verify_proven_ct: 1,
        };
        let (mut kms_servers, mut kms_clients, mut internal_client) = threshold_handles(
            dkg_params,
            amount_parties,
            true,
            Some(rate_limiter_conf),
            decryption_mode,
        )
        .await;
        let key_id_req = key_id.to_string().try_into().unwrap();

        let mut cts = Vec::new();
        let mut bits = 0;
        for (i, msg) in msgs.clone().into_iter().enumerate() {
            let (ct, fhe_type) = if compression {
                compute_compressed_cipher_from_stored_key(None, msg, key_id).await
            } else {
                compute_cipher_from_stored_key(None, msg, key_id).await
            };
            let ctt = TypedCiphertext {
                ciphertext: ct,
                fhe_type: fhe_type.into(),
                external_handle: i.to_be_bytes().to_vec(),
            };
            cts.push(ctt);
            bits += msg.bits() as u64;
        }

        let dummy_acl_address =
            alloy_primitives::address!("d8da6bf26964af9d7eed9e03e53415d37aa96045");

        // make parallel requests by calling [decrypt] in a thread
        let mut req_tasks = JoinSet::new();
        let reqs: Vec<_> = (0..parallelism)
            .map(|j| {
                let request_id = RequestId::derive(&format!("TEST_DEC_ID_{j}")).unwrap();

                internal_client
                    .decryption_request(
                        cts.clone(),
                        &dummy_domain(),
                        &request_id,
                        &dummy_acl_address,
                        &key_id_req,
                    )
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
                        cur_client.decrypt(tonic::Request::new(req_cloned)).await
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
                        .get_decrypt_result(tonic::Request::new(req_id_clone.clone()))
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
                            .get_decrypt_result(tonic::Request::new(req_id_clone.clone()))
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
                assert_eq!(FheType::from(msgs[i]), FheType::from(plaintext.clone()));

                match msgs[i] {
                    TestingPlaintext::Bool(x) => assert_eq!(x, plaintext.as_bool()),
                    TestingPlaintext::U4(x) => assert_eq!(x, plaintext.as_u4()),
                    TestingPlaintext::U8(x) => assert_eq!(x, plaintext.as_u8()),
                    TestingPlaintext::U16(x) => assert_eq!(x, plaintext.as_u16()),
                    TestingPlaintext::U32(x) => assert_eq!(x, plaintext.as_u32()),
                    TestingPlaintext::U64(x) => assert_eq!(x, plaintext.as_u64()),
                    TestingPlaintext::U128(x) => assert_eq!(x, plaintext.as_u128()),
                    TestingPlaintext::U160(x) => assert_eq!(x, plaintext.as_u160()),
                    TestingPlaintext::U256(x) => assert_eq!(x, plaintext.as_u256()),
                    TestingPlaintext::U512(x) => assert_eq!(x, plaintext.as_u512()),
                    TestingPlaintext::U1024(x) => assert_eq!(x, plaintext.as_u1024()),
                    TestingPlaintext::U2048(x) => assert_eq!(x, plaintext.as_u2048()),
                }
            }
        }
    }

    #[rstest::rstest]
    #[case(true, 7, &TEST_THRESHOLD_KEY_ID_7P.to_string(), DecryptionMode::NoiseFloodSmall)]
    #[case(true, 4, &TEST_THRESHOLD_KEY_ID_4P.to_string(), DecryptionMode::NoiseFloodSmall)]
    #[case(false, 4, &TEST_THRESHOLD_KEY_ID_4P.to_string(), DecryptionMode::NoiseFloodSmall)]
    #[case(true, 4, &TEST_THRESHOLD_KEY_ID_4P.to_string(), DecryptionMode::BitDecSmall)]
    #[case(false, 4, &TEST_THRESHOLD_KEY_ID_4P.to_string(), DecryptionMode::BitDecSmall)]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_reencryption_threshold(
        #[case] secure: bool,
        #[case] amount_parties: usize,
        #[case] key_id: &str,
        #[case] decryption_mode: DecryptionMode,
    ) {
        reencryption_threshold(
            TEST_PARAM,
            key_id,
            false,
            TestingPlaintext::U8(42),
            4,
            secure,
            amount_parties,
            None,
            Some(decryption_mode),
        )
        .await;
    }

    #[cfg(feature = "wasm_tests")]
    #[rstest::rstest]
    #[case(true, 7, &TEST_THRESHOLD_KEY_ID_7P.to_string())]
    #[case(true, 4, &TEST_THRESHOLD_KEY_ID_4P.to_string())]
    #[case(false, 4, &TEST_THRESHOLD_KEY_ID_4P.to_string())]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_reencryption_threshold_and_write_transcript(
        #[case] secure: bool,
        #[case] amount_parties: usize,
        #[case] key_id: &str,
    ) {
        reencryption_threshold(
            TEST_PARAM,
            key_id,
            true,
            TestingPlaintext::U8(42),
            1,
            secure,
            amount_parties,
            None,
            None,
        )
        .await;
    }

    #[cfg(all(feature = "wasm_tests", feature = "slow_tests"))]
    #[rstest::rstest]
    #[case(TestingPlaintext::U8(u8::MAX), 7, &DEFAULT_THRESHOLD_KEY_ID_7P.to_string())]
    #[case(TestingPlaintext::Bool(true), 4, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
    #[case(TestingPlaintext::U8(u8::MAX), 4, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
    #[case(TestingPlaintext::U16(u16::MAX), 4, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
    #[case(TestingPlaintext::U32(u32::MAX), 4, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
    #[case(TestingPlaintext::U64(u64::MAX), 4, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
    // #[case(TestingPlaintext::U128(u128::MAX))]
    // #[case(TestingPlaintext::U160(tfhe::integer::U256::from((u128::MAX, u32::MAX as u128))))]
    // #[case(TestingPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX))))]
    // #[case(TestingPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32])))]
    #[ignore]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn default_reencryption_threshold_and_write_transcript(
        #[case] msg: TestingPlaintext,
        #[case] amount_parties: usize,
        #[case] key_id: &str,
        #[values(true, false)] secure: bool,
    ) {
        use crate::consts::DEFAULT_PARAM;

        reencryption_threshold(
            DEFAULT_PARAM,
            key_id,
            true,
            msg,
            1, // wasm tests are single-threaded
            secure,
            amount_parties,
            None,
            None,
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[rstest::rstest]
    #[case(TestingPlaintext::U8(u8::MAX), 1, 4, &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn default_reencryption_threshold(
        #[case] msg: TestingPlaintext,
        #[case] parallelism: usize,
        #[case] amount_parties: usize,
        #[case] key_id: &str,
        #[values(true)] secure: bool,
    ) {
        use crate::consts::DEFAULT_PARAM;

        reencryption_threshold(
            DEFAULT_PARAM,
            key_id,
            false,
            msg,
            parallelism,
            secure,
            amount_parties,
            None,
            None,
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[rstest::rstest]
    #[case(TestingPlaintext::U8(u8::MAX), 1, 7, Some(vec![2,6]), &DEFAULT_THRESHOLD_KEY_ID_7P.to_string())]
    #[case(TestingPlaintext::Bool(true), 4, 4, Some(vec![1]), &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
    #[case(TestingPlaintext::U8(u8::MAX), 1, 4,Some(vec![2]), &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
    #[case(TestingPlaintext::U16(u16::MAX), 1, 4,Some(vec![3]), &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
    #[case(TestingPlaintext::U32(u32::MAX), 1, 4,Some(vec![4]), &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
    #[case(TestingPlaintext::U64(u64::MAX), 1, 4,Some(vec![1]), &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
    #[case(TestingPlaintext::U128(u128::MAX), 1, 4,Some(vec![2]), &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
    #[case(TestingPlaintext::U160(tfhe::integer::U256::from((u128::MAX, u32::MAX as u128))), 1, 4,Some(vec![3]), &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
    #[case(TestingPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX))), 1, 4,Some(vec![4]), &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
    // TODO: this takes approx. 300 secs locally.
    // #[case(TestingPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32])), 1, 4, Some(vec![1]), &DEFAULT_THRESHOLD_KEY_ID_4P.to_string())]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn default_reencryption_threshold_with_crash(
        #[case] msg: TestingPlaintext,
        #[case] parallelism: usize,
        #[case] amount_parties: usize,
        #[case] party_ids_to_crash: Option<Vec<usize>>,
        #[case] key_id: &str,
        #[values(true, false)] secure: bool,
    ) {
        use crate::consts::DEFAULT_PARAM;

        reencryption_threshold(
            DEFAULT_PARAM,
            key_id,
            false,
            msg,
            parallelism,
            secure,
            amount_parties,
            party_ids_to_crash,
            None,
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn reencryption_threshold(
        dkg_params: DKGParams,
        key_id: &str,
        write_transcript: bool,
        msg: TestingPlaintext,
        parallelism: usize,
        secure: bool,
        amount_parties: usize,
        party_ids_to_crash: Option<Vec<usize>>,
        decryption_mode: Option<DecryptionMode>,
    ) {
        assert!(parallelism > 0);
        _ = write_transcript;

        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
        let (mut kms_servers, mut kms_clients, mut internal_client) =
            threshold_handles(dkg_params, amount_parties, true, None, decryption_mode).await;
        let (ct, fhe_type) = compute_cipher_from_stored_key(None, msg, key_id).await;

        internal_client.convert_to_addresses();

        // make requests
        let reqs: Vec<_> = (0..parallelism)
            .map(|j| {
                let request_id = RequestId::derive(&format!("TEST_REENC_ID_{j}")).unwrap();
                let typed_ciphertexts = vec![TypedCiphertext {
                    ciphertext: ct.clone(),
                    fhe_type: fhe_type.into(),
                    external_handle: j.to_be_bytes().to_vec(),
                }];
                let (req, enc_pk, enc_sk) = internal_client
                    .reencryption_request(
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
                        cur_client.reencrypt(tonic::Request::new(req_clone)).await
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
                    // Sleep to give the server some time to complete reencryption
                    tokio::time::sleep(tokio::time::Duration::from_millis(
                        100 * bits * parallelism as u64,
                    ))
                    .await;
                    let mut response = cur_client
                        .get_reencrypt_result(tonic::Request::new(req_id_clone.clone()))
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
                            panic!("timeout while waiting for reencryption");
                        }
                        ctr += 1;
                        response = cur_client
                            .get_reencrypt_result(tonic::Request::new(req_id_clone.clone()))
                            .await;
                    }

                    (req_id_clone, response)
                });
            }
        }
        let mut response_map: HashMap<RequestId, Vec<ReencryptionResponse>> = HashMap::new();
        while let Some(res) = resp_tasks.join_next().await {
            let res = res.unwrap();
            tracing::info!("Client got a response from {}", res.0);
            let (req_id, resp) = res;
            if let Entry::Vacant(e) = response_map.entry(req_id.clone()) {
                e.insert(vec![resp.unwrap().into_inner()]);
            } else {
                response_map
                    .get_mut(&req_id)
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

                let transcript = TestingReencryptionTranscript {
                    server_addrs: internal_client.get_server_addrs().unwrap().clone(),
                    client_address: internal_client.client_address,
                    client_sk: internal_client.client_sk.clone(),
                    degree: threshold as u32,
                    params: internal_client.params,
                    fhe_types: vec![FheType::from(msg)],
                    pts: vec![TypedPlaintext::from(msg).bytes.clone()],
                    cts: reqs[0]
                        .0
                        .payload
                        .as_ref()
                        .unwrap()
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

        for req in &reqs {
            let (req, enc_pk, enc_sk) = req;
            let responses = response_map.get(req.request_id.as_ref().unwrap()).unwrap();
            let domain = protobuf_to_alloy_domain(req.domain.as_ref().unwrap()).unwrap();
            let client_req = ParsedReencryptionRequest::try_from(req).unwrap();
            let threshold = responses.first().unwrap().payload.as_ref().unwrap().degree as usize;
            // NOTE: throw away one response and it should still work.
            let plaintexts = if secure {
                // test with one fewer response if we haven't crashed too many parties already
                if threshold > party_ids_to_crash.len() {
                    internal_client
                        .process_reencryption_resp(
                            &client_req,
                            &domain,
                            &responses[1..],
                            enc_pk,
                            enc_sk,
                        )
                        .unwrap();
                }
                // test with all responses
                internal_client
                    .process_reencryption_resp(&client_req, &domain, responses, enc_pk, enc_sk)
                    .unwrap()
            } else {
                internal_client.server_identities = ServerIdentities::Addrs(Vec::new());
                // test with one fewer response if we haven't crashed too many parties already
                if threshold > party_ids_to_crash.len() {
                    internal_client
                        .insecure_process_reencryption_resp(&responses[1..], enc_pk, enc_sk)
                        .unwrap();
                }
                // test with all responses
                internal_client
                    .insecure_process_reencryption_resp(responses, enc_pk, enc_sk)
                    .unwrap()
            };
            for plaintext in plaintexts {
                assert_eq!(FheType::from(msg), FheType::from(plaintext.clone()));
                match msg {
                    TestingPlaintext::Bool(x) => assert_eq!(x, plaintext.as_bool()),
                    TestingPlaintext::U4(x) => assert_eq!(x, plaintext.as_u4()),
                    TestingPlaintext::U8(x) => assert_eq!(x, plaintext.as_u8()),
                    TestingPlaintext::U16(x) => assert_eq!(x, plaintext.as_u16()),
                    TestingPlaintext::U32(x) => assert_eq!(x, plaintext.as_u32()),
                    TestingPlaintext::U64(x) => assert_eq!(x, plaintext.as_u64()),
                    TestingPlaintext::U128(x) => assert_eq!(x, plaintext.as_u128()),
                    TestingPlaintext::U160(x) => assert_eq!(x, plaintext.as_u160()),
                    TestingPlaintext::U256(x) => assert_eq!(x, plaintext.as_u256()),
                    TestingPlaintext::U512(x) => assert_eq!(x, plaintext.as_u512()),
                    TestingPlaintext::U1024(x) => assert_eq!(x, plaintext.as_u1024()),
                    TestingPlaintext::U2048(x) => assert_eq!(x, plaintext.as_u2048()),
                }
            }
        }
    }

    // Validate bug-fix to ensure that the server fails gracefully when the ciphertext is too large
    #[cfg(feature = "slow_tests")]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_largecipher() {
        use crate::engine::centralized::central_kms::tests::{
            new_priv_ram_storage_from_existing_keys, new_pub_ram_storage_from_existing_keys,
        };

        let keys = get_default_keys().await;
        let rate_limiter_conf = RateLimiterConfig {
            bucket_size: 100,
            dec: 1,
            reenc: 100,
            crsgen: 1,
            preproc: 1,
            keygen: 1,
            verify_proven_ct: 1,
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
        let fhe_type = FheType::Euint32;
        let client_address = alloy_primitives::Address::from_public_key(keys.client_pk.pk());
        let mut internal_client = Client::new(
            keys.server_keys.clone(),
            client_address,
            Some(keys.client_sk.clone()),
            keys.params,
            None,
        );
        let request_id = RequestId::derive("TEST_REENC_ID_123").unwrap();
        let typed_ciphertexts = vec![TypedCiphertext {
            ciphertext: ct,
            fhe_type: fhe_type.into(),
            external_handle: vec![123],
        }];
        let (req, _enc_pk, _enc_sk) = internal_client
            .reencryption_request(
                &dummy_domain(),
                typed_ciphertexts,
                &request_id,
                &DEFAULT_CENTRAL_KEY_ID,
            )
            .unwrap();
        let response = kms_client
            .reencrypt(tonic::Request::new(req.clone()))
            .await
            .unwrap();
        assert_eq!(response.into_inner(), Empty {});

        let mut response = kms_client
            .get_reencrypt_result(req.request_id.clone().unwrap())
            .await;
        while response.is_err() && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
        {
            // Sleep to give the server some time to complete reencryption
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            response = kms_client
                .get_reencrypt_result(req.request_id.clone().unwrap())
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
        assert_eq!(FheType::Ebool.to_num_blocks(params), 1);
        // 2 bits per block, using Euint4 as internal representation
        assert_eq!(FheType::Euint4.to_num_blocks(params), 2);
        // 2 bits per block
        assert_eq!(FheType::Euint8.to_num_blocks(params), 4);
        // 2 bits per block
        assert_eq!(FheType::Euint16.to_num_blocks(params), 8);
        // 2 bits per block
        assert_eq!(FheType::Euint32.to_num_blocks(params), 16);
        // 2 bits per block
        assert_eq!(FheType::Euint64.to_num_blocks(params), 32);
        // 2 bits per block
        assert_eq!(FheType::Euint128.to_num_blocks(params), 64);
        // 2 bits per block
        assert_eq!(FheType::Euint160.to_num_blocks(params), 80);
    }

    #[cfg(feature = "insecure")]
    #[rstest::rstest]
    #[case(4)]
    #[case(7)]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_insecure_dkg(#[case] amount_parties: usize) {
        let key_id: RequestId = RequestId::derive(&format!(
            "test_inscure_dkg_key_{amount_parties}_{:?}",
            TEST_PARAM
        ))
        .unwrap();
        purge(None, None, &key_id.to_string(), amount_parties).await;
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
        let key_id: RequestId = RequestId::derive(&format!(
            "default_insecure_dkg_key_{amount_parties}_{:?}",
            DEFAULT_PARAM
        ))
        .unwrap();
        purge(None, None, &key_id.to_string(), amount_parties).await;
        let (_kms_servers, kms_clients, internal_client) =
            threshold_handles(DEFAULT_PARAM, amount_parties, true, None, None).await;
        let keys = run_keygen(
            FheParameter::Default,
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

    #[cfg(all(feature = "slow_tests", feature = "insecure"))]
    #[tokio::test(flavor = "multi_thread")]
    #[tracing_test::traced_test]
    #[serial]
    async fn test_insecure_threshold_decompression_keygen() {
        // Note that the first 2 key gens are insecure, but the last is secure as needed to generate decompression keys
        run_threshold_decompression_keygen(4, FheParameter::Test, true).await;
    }

    /// Note that the insecure flag means that the first two key gens will be insecure, but the last WILL still be secure
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
                RequestId::derive(&format!(
                    "decom_dkg_preproc_{amount_parties}_{:?}_1",
                    parameter
                ))
                .unwrap(),
            )
        };
        let key_id_1: RequestId =
            RequestId::derive(&format!("decom_dkg_key_{amount_parties}_{:?}_1", parameter))
                .unwrap();
        purge(None, None, &key_id_1.to_string(), amount_parties).await;

        let preproc_id_2 = if insecure {
            None
        } else {
            Some(
                RequestId::derive(&format!(
                    "decom_dkg_preproc_{amount_parties}_{:?}_2",
                    parameter
                ))
                .unwrap(),
            )
        };
        let key_id_2: RequestId =
            RequestId::derive(&format!("decom_dkg_key_{amount_parties}_{:?}_2", parameter))
                .unwrap();
        purge(None, None, &key_id_2.to_string(), amount_parties).await;

        let key_id_3: RequestId =
            RequestId::derive(&format!("decom_dkg_key_{amount_parties}_{:?}_3", parameter))
                .unwrap();
        purge(None, None, &key_id_3.to_string(), amount_parties).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(TIME_TO_SLEEP_MS)).await;
        // Preproc should use all the tokens in the bucket,
        // then they're returned to the bucket before keygen starts.
        // If something is wrong with the rate limiter logic
        // then the keygen step should fail since there are not enough tokens.
        let rate_limiter_conf = RateLimiterConfig {
            bucket_size: 100,
            dec: 1,
            reenc: 1,
            crsgen: 1,
            preproc: 100,
            keygen: 100,
            verify_proven_ct: 1,
        };
        let (kms_servers, kms_clients, internal_client) = threshold_handles(
            TEST_PARAM,
            amount_parties,
            true,
            Some(rate_limiter_conf),
            None,
        )
        .await;

        if !insecure {
            run_preproc(
                amount_parties,
                parameter,
                &kms_clients,
                &internal_client,
                &preproc_id_1.clone().unwrap(),
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
                &preproc_id_2.clone().unwrap(),
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

        // finally do the decompression keygen between the first and second keysets
        let decompression_key = run_keygen(
            parameter,
            &kms_clients,
            &internal_client,
            None,
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
    async fn preproc_and_keygen(
        amount_parties: usize,
        parameter: FheParameter,
        insecure: bool,
        iterations: usize,
        concurrent: bool,
    ) {
        for i in 0..iterations {
            let req_preproc: RequestId = RequestId::derive(&format!(
                "full_dkg_preproc_{amount_parties}_{:?}_{i}",
                parameter
            ))
            .unwrap();
            purge(None, None, &req_preproc.to_string(), amount_parties).await;
            let req_key: RequestId = RequestId::derive(&format!(
                "full_dkg_key_{amount_parties}_{:?}_{i}",
                parameter
            ))
            .unwrap();
            purge(None, None, &req_key.to_string(), amount_parties).await;
        }

        let dkg_param: WrappedDKGParams = parameter.into();
        // Preproc should use all the tokens in the bucket,
        // then they're returned to the bucket before keygen starts.
        // If something is wrong with the rate limiter logic
        // then the keygen step should fail since there are not enough tokens.
        let rate_limiter_conf = RateLimiterConfig {
            bucket_size: 100,
            dec: 1,
            reenc: 1,
            crsgen: 1,
            preproc: 100,
            keygen: 100,
            verify_proven_ct: 1,
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
                let cur_id: RequestId = RequestId::derive(&format!(
                    "full_dkg_preproc_{amount_parties}_{:?}_{i}",
                    parameter
                ))
                .unwrap();
                preproc_ids.insert(i, cur_id.clone());
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
            let mut keyset = JoinSet::new();
            for i in 0..iterations {
                let key_id: RequestId = RequestId::derive(&format!(
                    "full_dkg_key_{amount_parties}_{:?}_{i}",
                    parameter
                ))
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
            preprocset.join_all().await;
            keyset.join_all().await;
            tracing::info!("Finished concurrent preproc and keygen");
        } else {
            let mut preproc_ids = HashMap::new();
            for i in 0..iterations {
                let cur_id: RequestId = RequestId::derive(&format!(
                    "full_dkg_preproc_{amount_parties}_{:?}_{i}",
                    parameter
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
                let key_id: RequestId = RequestId::derive(&format!(
                    "full_dkg_key_{amount_parties}_{:?}_{i}",
                    parameter
                ))
                .unwrap();
                run_keygen(
                    parameter,
                    &kms_clients,
                    &internal_client,
                    Some(preproc_ids.get(&i).unwrap().to_owned()),
                    &key_id,
                    None,
                    insecure,
                )
                .await;
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
        assert_eq!(preproc_res.len(), amount_parties);

        // Try to do another request during preproc,
        // the request should be rejected due to rate limiter.
        // This should be done after the requests above start being
        // processed in the kms.
        {
            let req_id = RequestId::derive("test rate limiter").unwrap();
            let req = internal_client
                .crs_gen_request(&req_id, Some(1), Some(FheParameter::Test), None)
                .unwrap();
            let mut cur_client = kms_clients.get(&1).unwrap().clone();
            let e = cur_client.crs_gen(req).await.unwrap_err();
            assert_eq!(e.code(), tonic::Code::ResourceExhausted);
        }

        // Wait for preprocessing to be done
        for _i in 0..MAX_TRIES {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            let preproc_status = get_preproc_status(preproc_request.clone(), kms_clients).await;

            // Panic if we see an error
            if preproc_status.iter().any(|x| {
                KeyGenPreprocStatusEnum::try_from(x.result).unwrap()
                    != KeyGenPreprocStatusEnum::InProgress
                    && KeyGenPreprocStatusEnum::try_from(x.result).unwrap()
                        != KeyGenPreprocStatusEnum::Finished
            }) {
                panic!("Preprocessing failed with error: {:?}", preproc_status);
            }
            // Stop the loop if there is no longer a party that is still preprocessing
            if !preproc_status.iter().any(|x| {
                KeyGenPreprocStatusEnum::try_from(x.result).unwrap()
                    == KeyGenPreprocStatusEnum::InProgress
            }) {
                // All parties are finished so we check the result
                preproc_status.iter().for_each(|x| {
                    assert_eq!(
                        KeyGenPreprocStatusEnum::try_from(x.result).unwrap(),
                        KeyGenPreprocStatusEnum::Finished
                    );
                });
                return;
            }
        }
        panic!("Preprocessing did not finish in time");
    }

    //Check status of preproc request
    #[cfg(feature = "slow_tests")]
    async fn get_preproc_status(
        request: kms_grpc::kms::v1::KeyGenPreprocRequest,
        kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
    ) -> Vec<kms_grpc::kms::v1::KeyGenPreprocStatus> {
        let mut tasks = JoinSet::new();
        for i in 1..=kms_clients.len() as u32 {
            let req_id = request.request_id.clone().unwrap();
            let mut cur_client = kms_clients.get(&i).unwrap().clone();
            tasks.spawn(async move {
                cur_client
                    .get_preproc_status(tonic::Request::new(req_id))
                    .await
            });
        }
        let mut responses = Vec::new();
        while let Some(resp) = tasks.join_next().await {
            responses.push(resp.unwrap().unwrap().into_inner());
        }

        responses
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
        let keyset_added_info = decompression_keygen
            .clone()
            .map(|(from, to)| KeySetAddedInfo {
                compression_keyset_id: None,
                from_keyset_id_decompression_only: Some(from),
                to_keyset_id_decompression_only: Some(to),
            });

        let req_keygen = internal_client
            .key_gen_request(
                keygen_req_id,
                preproc_req_id.clone(),
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
            req_keygen.request_id.clone().unwrap(),
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
        use distributed_decryption::execution::{
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
                let req_clone = req_get_keygen.clone();
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
                let role = Role::indexed_by_one(idx as usize);
                let i = role.zero_based();
                let kg_res = kg_res.unwrap().into_inner();
                let storage = FileStorage::new(None, StorageType::PUB, Some(i + 1)).unwrap();
                let decompression_key: Option<DecompressionKey> = internal_client
                    .retrieve_key(&kg_res, PubDataType::DecompressionKey, &storage)
                    .await
                    .unwrap();
                assert!(decompression_key.is_some());
                if i == 0 {
                    serialized_ref_decompression_key =
                        bincode::serialize(decompression_key.as_ref().unwrap()).unwrap();
                } else {
                    assert_eq!(
                        serialized_ref_decompression_key,
                        bincode::serialize(decompression_key.as_ref().unwrap()).unwrap()
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
                let role = Role::indexed_by_one(idx as usize);
                let i = role.zero_based();
                let kg_res = kg_res.unwrap().into_inner();
                let storage = FileStorage::new(None, StorageType::PUB, Some(i + 1)).unwrap();
                let pk = internal_client
                    .retrieve_public_key(&kg_res, &storage)
                    .await
                    .unwrap();
                assert!(pk.is_some());
                if i == 0 {
                    serialized_ref_pk = bincode::serialize(pk.as_ref().unwrap()).unwrap();
                } else {
                    assert_eq!(
                        serialized_ref_pk,
                        bincode::serialize(pk.as_ref().unwrap()).unwrap()
                    )
                }
                let server_key: Option<tfhe::ServerKey> = internal_client
                    .retrieve_server_key(&kg_res, &storage)
                    .await
                    .unwrap();
                assert!(server_key.is_some());
                if i == 0 {
                    serialized_ref_server_key =
                        bincode::serialize(server_key.as_ref().unwrap()).unwrap();
                } else {
                    assert_eq!(
                        serialized_ref_server_key,
                        bincode::serialize(server_key.as_ref().unwrap()).unwrap()
                    )
                }

                let priv_storage = FileStorage::new(None, StorageType::PRIV, Some(i + 1)).unwrap();
                let sk_urls = priv_storage
                    .all_urls(&PrivDataType::FheKeyInfo.to_string())
                    .await
                    .unwrap();
                let sk_url = sk_urls.get(&kg_res.request_id.unwrap().request_id).unwrap();
                let threshold_fhe_keys: ThresholdFheKeys =
                    priv_storage.read_data(sk_url).await.unwrap();
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
            let (lwe_sk, glwe_sk) =
                try_reconstruct_shares(internal_client.params, threshold, all_threshold_fhe_keys);
            let regular_params = match internal_client.params {
                DKGParams::WithSnS(p) => p.regular_params,
                DKGParams::WithoutSnS(p) => p,
            };
            out = Some(TestKeyGenResult::Standard((
                to_hl_client_key(&regular_params, lwe_sk, glwe_sk, None, None),
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
            let other_key_gen_id = RequestId::derive("test_dkg other key id").unwrap();
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
        all_threshold_fhe_keys: HashMap<
            Role,
            crate::engine::threshold::service_real::ThresholdFheKeys,
        >,
    ) -> (
        tfhe::core_crypto::prelude::LweSecretKeyOwned<u64>,
        tfhe::core_crypto::prelude::GlweSecretKeyOwned<u64>,
    ) {
        use distributed_decryption::execution::{
            endpoints::keygen::GlweSecretKeyShareEnum, tfhe_internals::utils::reconstruct_bit_vec,
        };
        use tfhe::core_crypto::prelude::GlweSecretKeyOwned;

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
        (lwe_secret_key, glwe_sk)
    }
}

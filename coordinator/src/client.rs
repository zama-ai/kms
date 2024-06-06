use crate::cryptography::der_types::{
    PrivateEncKey, PrivateSigKey, PublicEncKey, PublicSigKey, SigncryptionPair,
    SigncryptionPrivKey, SigncryptionPubKey,
};
use crate::cryptography::signcryption::{
    decrypt_signcryption, encryption_key_generation, hash_element, sign_eip712, ReencryptSol,
    RND_SIZE,
};
use crate::kms::{
    AggregatedReencryptionResponse, FheType, ReencryptionRequest, ReencryptionRequestPayload,
    ReencryptionResponse, RequestId,
};
use crate::rpc::rpc_types::{
    allow_to_protobuf_domain, MetaResponse, Plaintext, CURRENT_FORMAT_VERSION,
};
use crate::{anyhow_error_and_log, some_or_err};
use aes_prng::AesRng;
use alloy_sol_types::Eip712Domain;
use distributed_decryption::algebra::base_ring::Z128;
use distributed_decryption::algebra::residue_poly::ResiduePoly;
use distributed_decryption::execution::endpoints::reconstruct::{combine128, reconstruct_message};
use distributed_decryption::execution::runtime::party::Role;
use distributed_decryption::execution::sharing::shamir::{
    fill_indexed_shares, reconstruct_w_errors_sync, ShamirSharings,
};
use distributed_decryption::execution::tfhe_internals::parameters::{
    AugmentedCiphertextParameters, NoiseFloodParameters,
};
use itertools::Itertools;
use rand::{RngCore, SeedableRng};
use serde_asn1_der::{from_bytes, to_vec};
use std::collections::{HashMap, HashSet};
use wasm_bindgen::prelude::*;

cfg_if::cfg_if! {
    if #[cfg(feature = "non-wasm")] {
        use anyhow::ensure;
        use crate::storage::read_all_data;
        use std::fmt;
        use tfhe::ServerKey;
        use crate::storage::PublicStorage;
        use serde::de::DeserializeOwned;
        use distributed_decryption::execution::zk::ceremony::PublicParameter;
        use crate::rpc::rpc_types::{
            DecryptionRequestSerializable, PubDataType,
        };
        use crate::{cryptography::central_kms::BaseKmsStruct, rpc::rpc_types::BaseKms};
        use crate::{storage::PublicStorageReader, util::key_setup::FhePublicKey};
        use crate::kms::{
            AggregatedDecryptionResponse, CrsGenRequest, CrsGenResult, DecryptionRequest,
            DecryptionResponsePayload, KeyGenPreprocRequest, KeyGenRequest, KeyGenResult,
        };
        use crate::cryptography::{central_kms::compute_handle, der_types::Signature};
        use crate::kms::ParamChoice;
        use crate::cryptography::signcryption::serialize_hash_element;
        use crate::util::file_handling::read_as_json;
    }
}

/// Helper method for combining reconstructed messages after decryption.
// TODO is this the right place for this function? Should probably be in ddec. Related to this issue https://github.com/zama-ai/distributed-decryption/issues/352
fn decrypted_blocks_to_raw_decryption(
    params: &NoiseFloodParameters,
    fhe_type: FheType,
    recon_blocks: Vec<Z128>,
) -> anyhow::Result<Plaintext> {
    let bits_in_block = params.ciphertext_parameters.message_modulus_log();
    let res = match combine128(bits_in_block, recon_blocks) {
        Ok(res) => res,
        Err(error) => {
            eprint!("Panicked in combining {error}");
            return Err(anyhow_error_and_log(format!(
                "Panicked in combining {error}"
            )));
        }
    };
    Ok(Plaintext::new(res, fhe_type))
}

/// Simple client to interact with the KMS servers. This can be seen as a proof-of-concept
/// and reference code for validating the KMS. The logic supplied by the client will be
/// distributed accross the aggregator/proxy and smart contracts.
/// TODO should probably aggregate the KmsEndpointClient to void having two client code bases
/// exposed in tests and MVP
///
/// client_sk is optional because sometimes the private signing key is kept
/// in a secure location, e.g., hardware wallet. Calling functions that requires
/// client_sk when it is None will return an error.
#[wasm_bindgen]
pub struct Client {
    rng: Box<AesRng>,
    server_pks: HashSet<PublicSigKey>,
    client_pk: PublicSigKey,
    client_sk: Option<PrivateSigKey>,
    shares_needed: u32,
    // we allow it because num_servers is used in only certain features
    #[allow(dead_code)]
    num_servers: u32,
    params: NoiseFloodParameters,
}

// This testing struct needs to be outside of js_api module
// since it is needed in the tests to generate the right files for js/wasm tests.
#[cfg(feature = "wasm_tests")]
#[wasm_bindgen]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct TestingReencryptionTranscript {
    // client
    server_pks: HashSet<PublicSigKey>,
    client_pk: PublicSigKey,
    shares_needed: u32,
    params: NoiseFloodParameters,
    // request
    request: Option<ReencryptionRequest>,
    eph_sk: PrivateEncKey,
    eph_pk: PublicEncKey,
    // response
    agg_resp: HashMap<u32, ReencryptionResponse>,
}

// TODO it would make sense to seperate the wasm specific stuff into a seperate file

/// This module is dedicated to making an re-encryption request
/// and reconstruction of the re-encryption results on a web client
/// in JavaScript.
///
/// We do not provide a specific method to create the re-encryption
/// request, it needs to be created manually by filling the fields
/// in [[ReencryptionRequest]].
/// This is because this request needs to be signed by the client's
/// signing key which is not available in the web client.
/// But it is typically stored in a wallet
/// (web extension or hardware wallet).
///
/// Development notes:
/// The JavaScript API is created from compiling
/// a part of the client code (along with other dependencies)
/// into wasm and then using wasm-pack to generate the JS bindings.
/// Care must be taken when new code is introduced to the coordinator
/// or core/threshold since wasm does not support every feature
/// that Rust supports. Specifically, for our use-case, we will not
/// try to compile async, multi-threaded or IO code.
///
/// If there is no need for a block to be used in wasm,
/// then we suggest to tag it with the "non-wasm" feature.
/// If a dependency does not need to be compiled to wasm,
/// then mark it as optional and place it under the list
/// of dependencies for feature "non-wasm".
///
/// Generating the JavaScript binding introduces another layer
/// of limitations on the Rust side. For example, HashMap,
/// HashSet, Option on custom types, tuple,
/// u128, anyhow::Result, and so on.
///
/// Testing:
/// Due to the way re-encryption is designed,
/// we cannot test everything directly in JS.
/// The strategy we use is to run Rust tests to
/// generate a transcript, and then load it into
/// the JS test (tests/js/test.js) to run the
/// actual tests.
/// The steps below must be followed for the JS tests to work.
///
/// 1. Install wasm-pack and node (version 20)
/// the preferred way is to use nvm (which is on homebrew)
/// and the node version must be 20
/// ```
/// cargo install wasm-pack
/// nvm install 20
/// ```
/// Observe that if you are using Brew you might also need to run the following command to get
/// access to nvm: ```
/// source ~/.nvm/nvm.sh
/// ```
///
/// 2. Build with wasm_tests feature
/// ```
/// wasm-pack build --target nodejs . --no-default-features -F wasm_tests
/// ```
///
/// 3. Generate the transcript
/// ```
/// cargo test test_reencryption_threshold_and_write_transcript -F wasm_tests --release
/// cargo test test_reencryption_centralized_and_write_transcript -F wasm_tests --release
/// ```
///
/// 4. Run the JS test
/// ```
/// node --test tests/js
/// ```
// Do not compile this module for grpc-client
#[cfg(all(not(feature = "non-wasm"), not(feature = "grpc-client")))]
pub mod js_api {
    use crate::kms::Eip712DomainMsg;
    use crypto_box::aead::{Aead, AeadCore};
    use crypto_box::{Nonce, SalsaBox};

    use super::*;

    #[wasm_bindgen]
    pub fn new_client(
        server_pks: Vec<PublicSigKey>,
        client_pk: PublicSigKey,
        shares_needed: u32,
        params_json: &str,
    ) -> Client {
        console_error_panic_hook::set_once();

        let server_pks = HashSet::from_iter(server_pks);
        // TODO: we just use parameters stored in json for now
        // think about how to instantiate different parameters later
        // when we have an enum that specifies parameters
        let params: NoiseFloodParameters =
            serde_json::from_str::<NoiseFloodParameters>(params_json).unwrap();
        // Note: This may fail if there are multiple possible signing keys for each server
        let num_servers = server_pks.len() as u32;
        Client {
            rng: Box::new(AesRng::from_entropy()),
            server_pks,
            client_pk,
            client_sk: None,
            shares_needed,
            num_servers,
            params,
        }
    }

    #[wasm_bindgen]
    #[cfg(feature = "wasm_tests")]
    pub fn new_reenc_transcript_from_bytes(buf: &[u8]) -> JsValue {
        let obj: TestingReencryptionTranscript = bincode::deserialize(buf).unwrap();
        serde_wasm_bindgen::to_value(&obj).unwrap()
    }

    #[wasm_bindgen(getter_with_clone)]
    #[cfg(feature = "wasm_tests")]
    pub struct DummyReencResponse {
        pub req: Option<ReencryptionRequest>,
        pub agg_resp: Vec<ReencryptionResponse>,
        pub agg_resp_ids: Vec<u32>,
        pub enc_pk: PublicEncKey,
        pub enc_sk: PrivateEncKey,
    }

    #[wasm_bindgen]
    #[cfg(feature = "wasm_tests")]
    pub fn centralized_reencryption_response_from_transcript(
        transcript: JsValue,
    ) -> DummyReencResponse {
        let transcript: TestingReencryptionTranscript =
            serde_wasm_bindgen::from_value(transcript).unwrap();
        DummyReencResponse {
            req: transcript.request,
            agg_resp: vec![transcript.agg_resp.get(&1).unwrap().clone()],
            agg_resp_ids: vec![1],
            enc_pk: transcript.eph_pk.clone(),
            enc_sk: transcript.eph_sk.clone(),
        }
    }

    #[wasm_bindgen]
    #[cfg(feature = "wasm_tests")]
    pub fn threshold_reencryption_response_from_transcript(
        transcript: JsValue,
    ) -> DummyReencResponse {
        let transcript: TestingReencryptionTranscript =
            serde_wasm_bindgen::from_value(transcript).unwrap();
        let agg_resp_ids: Vec<_> = (1..=transcript.agg_resp.len() as u32).collect();
        let agg_resp: Vec<_> = agg_resp_ids
            .iter()
            .map(|k| transcript.agg_resp.get(k).unwrap().clone())
            .collect();

        DummyReencResponse {
            req: transcript.request,
            agg_resp,
            agg_resp_ids,
            enc_pk: transcript.eph_pk.clone(),
            enc_sk: transcript.eph_sk.clone(),
        }
    }

    #[wasm_bindgen]
    #[cfg(feature = "wasm_tests")]
    pub fn client_from_transcript(transcript: JsValue) -> Client {
        console_error_panic_hook::set_once();
        let transcript: TestingReencryptionTranscript =
            serde_wasm_bindgen::from_value(transcript).unwrap();
        // Note: This may fail if there are multiple possible signing keys for each server
        let num_servers = transcript.server_pks.len() as u32;
        Client {
            rng: Box::new(AesRng::from_entropy()),
            server_pks: transcript.server_pks,
            client_pk: transcript.client_pk,
            client_sk: None,
            shares_needed: transcript.shares_needed,
            num_servers,
            params: transcript.params,
        }
    }

    #[wasm_bindgen]
    pub struct CryptoBoxCt {
        ct: Vec<u8>,
        nonce: Nonce,
    }

    #[wasm_bindgen]
    pub fn cryptobox_keygen() -> PrivateEncKey {
        let mut rng = AesRng::from_entropy();
        let sk = crypto_box::SecretKey::generate(&mut rng);
        PrivateEncKey(sk)
    }

    #[wasm_bindgen]
    pub fn cryptobox_get_pk(sk: &PrivateEncKey) -> PublicEncKey {
        PublicEncKey(sk.0.public_key())
    }

    #[wasm_bindgen]
    pub fn cryptobox_pk_to_u8vec(pk: &PublicEncKey) -> Result<Vec<u8>, JsError> {
        serde_asn1_der::to_vec(pk).map_err(|e| JsError::new(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn cryptobox_sk_to_u8vec(sk: &PrivateEncKey) -> Result<Vec<u8>, JsError> {
        serde_asn1_der::to_vec(sk).map_err(|e| JsError::new(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn u8vec_to_cryptobox_pk(v: &[u8]) -> Result<PublicEncKey, JsError> {
        serde_asn1_der::from_bytes(v).map_err(|e| JsError::new(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn u8vec_to_cryptobox_sk(v: &[u8]) -> Result<PrivateEncKey, JsError> {
        serde_asn1_der::from_bytes(v).map_err(|e| JsError::new(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn cryptobox_encrypt(
        msg: &[u8],
        their_pk: &PublicEncKey,
        my_sk: &PrivateEncKey,
    ) -> CryptoBoxCt {
        let salsa_box = SalsaBox::new(&their_pk.0, &my_sk.0);
        let mut rng = AesRng::from_entropy();
        let nonce = SalsaBox::generate_nonce(&mut rng);

        CryptoBoxCt {
            ct: salsa_box.encrypt(&nonce, msg).unwrap(),
            nonce,
        }
    }

    #[wasm_bindgen]
    pub fn cryptobox_decrypt(
        ct: &CryptoBoxCt,
        my_sk: &PrivateEncKey,
        their_pk: &PublicEncKey,
    ) -> Vec<u8> {
        let salsa_box = SalsaBox::new(&their_pk.0, &my_sk.0);

        salsa_box.decrypt(&ct.nonce, &ct.ct[..]).unwrap()
    }

    /// This function assembles [ReencryptionRequest]
    /// from a signature and other metadata.
    /// The signature is on the ephemeral public key
    /// signed by the client's private key
    /// following the EIP712 standard.
    #[wasm_bindgen]
    pub fn make_reencryption_req(
        client: &mut Client,
        signature: Vec<u8>,
        enc_pk: PublicEncKey,
        fhe_type: FheType,
        key_id: RequestId,
        ciphertext_digest: Vec<u8>,
        domain: Eip712DomainMsg,
    ) -> Result<ReencryptionRequest, JsError> {
        let mut randomness: Vec<u8> = vec![0; RND_SIZE];
        client.rng.fill_bytes(&mut randomness);
        let payload = ReencryptionRequestPayload {
            version: CURRENT_FORMAT_VERSION,
            randomness,
            servers_needed: client.shares_needed,
            enc_key: serde_asn1_der::to_vec(&enc_pk)?,
            verification_key: serde_asn1_der::to_vec(&client.client_pk)?,
            fhe_type: fhe_type as i32,
            key_id: Some(key_id),
            // this is None because the gateway needs to fill it
            ciphertext: None,
            ciphertext_digest,
        };
        Ok(ReencryptionRequest {
            signature: signature,
            payload: Some(payload),
            domain: Some(domain),
            // the request_id needs to be filled by the gateway/connector
            request_id: None,
        })
    }

    /// This function takes [AggregatedReencryptionResponse] normally
    /// but wasm does not support HashMap so we need to take two parameters:
    /// `agg_resp` and `agg_resp_id`.
    #[wasm_bindgen]
    pub fn process_reencryption_resp(
        client: &mut Client,
        request: Option<ReencryptionRequest>,
        agg_resp: Vec<ReencryptionResponse>,
        agg_resp_ids: Vec<u32>,
        enc_pk: &PublicEncKey,
        enc_sk: &PrivateEncKey,
    ) -> Result<u8, JsError> {
        let mut hm = AggregatedReencryptionResponse {
            responses: HashMap::new(),
        };
        for (k, v) in agg_resp_ids.into_iter().zip(agg_resp) {
            hm.responses.insert(k, v);
        }
        match client.process_reencryption_resp(request, &hm, enc_pk, enc_sk) {
            Ok(resp) => match resp {
                Some(out) => Ok(out.as_u8()),
                None => Err(JsError::new("no response")),
            },
            Err(e) => Err(JsError::new(&e.to_string())),
        }
    }
}

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
    /// from a [PublicStorage]
    pub fn new(
        server_pks: HashSet<PublicSigKey>,
        client_pk: PublicSigKey,
        client_sk: Option<PrivateSigKey>,
        shares_needed: u32,
        num_servers: u32,
        params: NoiseFloodParameters,
    ) -> Self {
        Client {
            rng: Box::new(AesRng::from_entropy()), // todo should be argument
            server_pks,
            client_pk,
            client_sk,
            shares_needed,
            num_servers,
            params,
        }
    }

    /// Helper method to create a client based on a specific type of storage for loading the keys.
    /// Observe that this method is decoupled from the [Client] to ensure wasm complience as wasm cannot handle
    /// file reading or generic traits.
    #[cfg(feature = "non-wasm")]
    pub async fn new_client<ClientS: PublicStorage, PubS: PublicStorageReader>(
        client_storage: ClientS,
        pub_storages: Vec<PubS>,
        param_path: &str,
        shares_needed: u32,
        num_servers: u32,
    ) -> anyhow::Result<Client> {
        let mut pks: HashMap<RequestId, PublicSigKey> = HashMap::new();
        for cur_storage in pub_storages {
            let cur_map = read_all_data(&cur_storage, &PubDataType::VerfKey.to_string()).await?;
            for (cur_req_id, cur_pk) in cur_map {
                // ensure that the inserted pk did not exist before / is not inserted twice
                ensure!(pks.insert(cur_req_id, cur_pk) == None);
            }
        }
        let server_keys = pks.values().cloned().collect_vec();
        let client_pk_map: HashMap<RequestId, PublicSigKey> =
            read_all_data(&client_storage, &ClientDataType::VerfKey.to_string()).await?;
        if client_pk_map.values().len() != 1 {
            return Err(anyhow_error_and_log(format!(
                "Client public key map should contain exactly one entry, but contained {} entries",
                client_pk_map.values().len(),
            )));
        }
        let client_pk = some_or_err(
            client_pk_map.values().next().cloned(),
            "Client public key map did not contain a key".to_string(),
        )?;
        let client_sk_map: HashMap<RequestId, PrivateSigKey> =
            read_all_data(&client_storage, &ClientDataType::SigningKey.to_string()).await?;
        if client_sk_map.values().len() != 1 {
            return Err(anyhow_error_and_log(
                "Client signing key map should only contain one entry",
            ));
        }
        let client_sk = client_sk_map.values().next().cloned();
        let params: NoiseFloodParameters = read_as_json(param_path).await?;
        Ok(Client::new(
            HashSet::from_iter(server_keys),
            client_pk,
            client_sk,
            shares_needed,
            num_servers,
            params,
        ))
    }

    /// Verify the signature received from the server on keys or other data objects.
    /// This verification will pass if one of the public keys can verify the signature.
    #[cfg(feature = "non-wasm")]
    pub fn verify_server_signature<T: serde::Serialize + AsRef<[u8]>>(
        &self,
        data: &T,
        signature: &[u8],
    ) -> bool {
        self.find_verifying_public_key(data, signature).is_some()
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
                tracing::warn!("Could not deserialize signature");
                return None;
            }
        };

        for verf_key in self.server_pks.iter() {
            let ok = BaseKmsStruct::verify_sig(&data, &signature_struct, verf_key);
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
    /// its [`RequestId`] it can be set to None in the centralised case
    #[cfg(feature = "non-wasm")]
    pub fn key_gen_request(
        &self,
        request_id: &RequestId,
        preproc_id: Option<RequestId>,
        param: Option<ParamChoice>,
    ) -> anyhow::Result<KeyGenRequest> {
        let parsed_param: i32 = match param {
            Some(parsed_param) => parsed_param.into(),
            None => ParamChoice::Default.into(),
        };
        if !request_id.is_valid() {
            return Err(anyhow_error_and_log(format!(
                "The request id format is not valid {request_id}"
            )));
        }
        Ok(KeyGenRequest {
            params: parsed_param,
            config: None,
            preproc_id,
            request_id: Some(request_id.clone()),
        })
    }

    #[cfg(feature = "non-wasm")]
    pub fn crs_gen_request(
        &self,
        request_id: &RequestId,
        param: Option<ParamChoice>,
    ) -> anyhow::Result<CrsGenRequest> {
        let parsed_param: i32 = match param {
            Some(parsed_param) => parsed_param.into(),
            None => ParamChoice::Default.into(),
        };
        if !request_id.is_valid() {
            return Err(anyhow_error_and_log(format!(
                "The request id format is not valid {request_id}"
            )));
        }
        Ok(CrsGenRequest {
            params: parsed_param,
            config: None,
            request_id: Some(request_id.clone()),
        })
    }

    #[cfg(feature = "non-wasm")]
    pub fn preproc_request(
        &self,
        request_id: &RequestId,
        param: Option<ParamChoice>,
    ) -> anyhow::Result<KeyGenPreprocRequest> {
        let parsed_param: i32 = match param {
            Some(parsed_param) => parsed_param.into(),
            None => ParamChoice::Default.into(),
        };

        if !request_id.is_valid() {
            return Err(anyhow_error_and_log(format!(
                "The request id format is not valid {request_id}"
            )));
        }

        Ok(KeyGenPreprocRequest {
            config: None,
            params: parsed_param,
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
    /// the majority. The majority value must be greater or equal to
    /// the number of honest parties, that is n - t, where n is the number
    /// of parties and t is the threshold.
    #[cfg(feature = "non-wasm")]
    pub async fn process_distributed_crs_result<S: PublicStorageReader>(
        &self,
        request_id: &RequestId,
        results: Vec<CrsGenResult>,
        storage_readers: &[S],
    ) -> anyhow::Result<PublicParameter> {
        let mut verifying_pks = HashSet::new();
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
            let (pp, info) = if let Some(info) = result.crs_results {
                let url =
                    storage.compute_url(&request_id.to_string(), &PubDataType::CRS.to_string())?;
                let pp: PublicParameter = storage.read_data(&url).await?;
                (pp, info)
            } else {
                tracing::warn!("empty FhePubKeyInfo");
                continue;
            };

            // check the result matches our request ID
            if request_id.request_id
                != result
                    .request_id
                    .ok_or(anyhow_error_and_log("request ID missing"))?
                    .request_id
            {
                tracing::warn!("request ID mismatch; discarding the CRS");
                continue;
            }

            // check the digest
            let ser = bincode::serialize(&pp)?;
            let hex_digest = compute_handle(&ser)?;
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
            pp_map.insert(hex_digest, pp);
        }

        // find the digest that has the most votes
        let (h, c) = hash_counter_map
            .into_iter()
            .max_by(|a, b| a.1.cmp(&b.1))
            .ok_or(anyhow_error_and_log(
                "logic error: hash_counter_map is empty",
            ))?;

        // shares_needed gives us t+1, enough to reconstruct
        // this means there are n - t honest parties, which should return the same result
        let honest_parties_count = self.num_servers - self.shares_needed + 1;
        if c < honest_parties_count as usize {
            return Err(anyhow_error_and_log(format!(
                "No consensus on CRS digest! {} >= {}",
                c, honest_parties_count
            )));
        }

        if verifying_pks.len() < honest_parties_count as usize {
            Err(anyhow_error_and_log(format!(
                "Not enough signatures on CRS results! {} >= {}",
                verifying_pks.len(),
                honest_parties_count
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
        ct: Vec<u8>,
        fhe_type: FheType,
        request_id: &RequestId,
        key_id: &RequestId,
    ) -> anyhow::Result<DecryptionRequest> {
        if !request_id.is_valid() {
            return Err(anyhow_error_and_log(format!(
                "The request id format is not valid {request_id}"
            )));
        }

        // Observe that this randomness can be reused across the servers since each server will have
        // a unique PK that is included in their response, hence it will still be validated
        // that each request contains a unique message to be signed hence ensuring CCA
        // security. TODO this argument should be validated
        let mut randomness: Vec<u8> = vec![0; RND_SIZE];
        self.rng.fill_bytes(&mut randomness);
        let serialized_req = DecryptionRequestSerializable {
            version: CURRENT_FORMAT_VERSION,
            servers_needed: self.shares_needed,
            fhe_type,
            ciphertext: ct,
            randomness,
            key_id: key_id.clone(),
            request_id: request_id.clone(),
        };
        Ok(serialized_req.into())
    }

    /// Creates a reencryption request to send to the KMS servers. This generates
    /// an ephemeral reencryption key pair, signature payload containing the ciphertext,
    /// required number of shares, and other metadata. It signs this payload with
    /// the users's wallet private key. Returns the full [ReencryptionRequest] containing
    /// the signed payload to send to the servers, along with the generated
    /// reencryption key pair.
    pub fn reencryption_request(
        &mut self,
        ciphertext: Vec<u8>,
        domain: &Eip712Domain,
        fhe_type: FheType,
        request_id: &RequestId,
        key_id: &RequestId,
    ) -> anyhow::Result<(ReencryptionRequest, PublicEncKey, PrivateEncKey)> {
        if !request_id.is_valid() {
            return Err(anyhow_error_and_log(format!(
                "The request id format is not valid {request_id}"
            )));
        }

        let ciphertext_digest = hash_element(&ciphertext);
        let (enc_pk, enc_sk) = encryption_key_generation(&mut self.rng);
        let mut randomness = vec![0; RND_SIZE];
        self.rng.fill_bytes(&mut randomness);
        let sig_payload = ReencryptionRequestPayload {
            version: CURRENT_FORMAT_VERSION,
            servers_needed: self.shares_needed,
            enc_key: to_vec(&enc_pk)?,
            verification_key: to_vec(&self.client_pk)?,
            fhe_type: fhe_type as i32,
            randomness,
            key_id: Some(key_id.clone()),
            ciphertext: Some(ciphertext),
            ciphertext_digest,
        };
        let sol_pk = ReencryptSol {
            pub_enc_key: sig_payload.enc_key.clone(),
        };
        let sig = match &self.client_sk {
            Some(sk) => sign_eip712(&sol_pk, domain, sk)?,
            None => return Err(anyhow_error_and_log("client signing key is None")),
        };
        let domain_msg = allow_to_protobuf_domain(domain)?;
        Ok((
            ReencryptionRequest {
                signature: to_vec(&sig)?,
                payload: Some(sig_payload),
                domain: Some(domain_msg),
                request_id: Some(request_id.clone()),
            },
            enc_pk,
            enc_sk,
        ))
    }

    // TODO do we need to linking to request?
    #[cfg(feature = "non-wasm")]
    pub async fn process_get_key_gen_resp<R: PublicStorageReader>(
        &self,
        resp: &KeyGenResult,
        storage: &R,
    ) -> anyhow::Result<(FhePublicKey, ServerKey)> {
        let pk: FhePublicKey = some_or_err(
            self.retrieve_key(resp, PubDataType::PublicKey, storage)
                .await?,
            "Could not validate public key".to_string(),
        )?;
        let server_key: ServerKey = match self
            .retrieve_key(resp, PubDataType::ServerKey, storage)
            .await?
        {
            Some(server_key) => server_key,
            None => {
                return Err(anyhow_error_and_log("Could not validate server key"));
            }
        };
        Ok((pk, server_key))
    }

    /// Retrieve and validate a public key based on the result from a server.
    /// The method will return the key if retrieval and validation is successful,
    /// but will return None in case the signature is invalid or does not match the actual key
    /// handle.
    #[cfg(feature = "non-wasm")]
    pub async fn retrieve_key<
        S: serde::Serialize + DeserializeOwned + Send,
        R: PublicStorageReader,
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
        let url = storage.compute_url(&request_id.to_string(), &key_type.to_string())?;
        let key: S = storage.read_data(&url).await?;
        let serialized_key = bincode::serialize(&key)?;
        let key_handle = compute_handle(&serialized_key)?;
        if key_handle != pki.key_handle {
            tracing::warn!(
                "Computed key handle {} of retrieved key does not match expected key handle {}",
                key_handle,
                pki.key_handle,
            );
            return Ok(None);
        }
        if !self.verify_server_signature(&key_handle, &pki.signature) {
            tracing::warn!(
                "Could not verify server signature for key handle {}",
                key_handle,
            );
            return Ok(None);
        }
        Ok(Some(key))
    }

    // TODO do we need to linking to request?
    #[cfg(feature = "non-wasm")]
    pub async fn process_get_crs_resp<R: PublicStorageReader>(
        &self,
        resp: &CrsGenResult,
        storage: &R,
    ) -> anyhow::Result<PublicParameter> {
        let crs: PublicParameter = some_or_err(
            self.retrieve_crs(resp, storage).await?,
            "Could not validate CRS".to_string(),
        )?;
        Ok(crs)
    }

    /// Retrieve and validate a public key based on the result from a server.
    /// The method will return the key if retrieval and validation is successful,
    /// but will return None in case the signature is invalid or does not match the actual key
    /// handle.
    #[cfg(feature = "non-wasm")]
    pub async fn retrieve_crs<R: PublicStorageReader>(
        &self,
        crs_gen_result: &CrsGenResult,
        storage: &R,
    ) -> anyhow::Result<Option<PublicParameter>> {
        let crs_info = some_or_err(
            crs_gen_result.crs_results.clone(),
            "Could not find CRS info".to_string(),
        )?;
        let request_id = some_or_err(
            crs_gen_result.request_id.clone(),
            "No request id".to_string(),
        )?;
        let url = storage.compute_url(&request_id.to_string(), &PubDataType::CRS.to_string())?;
        let crs: PublicParameter = storage.read_data(&url).await?;
        let serialized_crs = bincode::serialize(&crs)?;
        let crs_handle = compute_handle(&serialized_crs)?;
        if crs_handle != crs_info.key_handle {
            tracing::warn!(
                "Computed crs handle {} of retrieved crs does not match expected crs handle {}",
                crs_handle,
                crs_info.key_handle,
            );
            return Ok(None);
        }
        if !self.verify_server_signature(&crs_handle, &crs_info.signature) {
            tracing::warn!(
                "Could not verify server signature for crs handle {}",
                crs_handle,
            );
            return Ok(None);
        }
        Ok(Some(crs))
    }

    /// Validates the aggregated decryption response `agg_resp` against the
    /// original `DecryptionRequest` `request`, and returns the decrypted
    /// plaintext if valid. Returns `None` if validation fails.
    #[cfg(feature = "non-wasm")]
    pub fn process_decryption_resp(
        &self,
        request: Option<DecryptionRequest>,
        agg_resp: &AggregatedDecryptionResponse,
    ) -> anyhow::Result<Option<Plaintext>> {
        if !self.validate_decryption_resp(request, agg_resp)? {
            return Ok(None);
        }
        // TODO pivot should actually be picked as the most common response instead of just an
        // arbitrary one. The same in reencryption
        let pivot = some_or_err(
            agg_resp.responses.iter().last(),
            "No elements in decryption response".to_string(),
        )?;
        let pivot_payload = some_or_err(
            pivot.payload.to_owned(),
            "No payload in pivot response".to_string(),
        )?;
        for cur_resp in &agg_resp.responses {
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
                || cur_payload.fhe_type()? != pivot_payload.fhe_type()?
                || cur_payload.plaintext != pivot_payload.plaintext
                || cur_payload.servers_needed != pivot_payload.servers_needed
            {
                tracing::warn!("Some server did not provide the proper response!");
                return Ok(None);
            }
            // Observe that it has already been verified in [self.validate_meta_data] that server
            // verification key is in the set of permissble keys
            let cur_verf_key: PublicSigKey = from_bytes(&cur_payload.verification_key)?;
            if !BaseKmsStruct::verify_sig(&to_vec(&cur_payload)?, &sig, &cur_verf_key) {
                tracing::warn!("Signature on received response is not valid!");
                return Ok(None);
            }
        }
        let serialized_plaintext = some_or_err(
            pivot.payload.to_owned(),
            "No payload in pivot response for decryption".to_owned(),
        )?
        .plaintext;
        let plaintext: Plaintext = from_bytes(&serialized_plaintext)?;
        Ok(Some(plaintext))
    }

    /// Processes the aggregated reencryption response to attempt to decrypt
    /// the encryption of the secret shared plaintext and returns this. Validates the
    /// response matches the request, checks signatures, and handles both
    /// centralized and distributed cases.
    pub fn process_reencryption_resp(
        &self,
        request: Option<ReencryptionRequest>,
        agg_resp: &AggregatedReencryptionResponse,
        enc_pk: &PublicEncKey,
        enc_sk: &PrivateEncKey,
    ) -> anyhow::Result<Option<Plaintext>> {
        let client_keys = SigncryptionPair {
            sk: SigncryptionPrivKey {
                signing_key: self.client_sk.clone(),
                decryption_key: enc_sk.clone(),
            },
            pk: SigncryptionPubKey {
                verification_key: self.client_pk.clone(),
                enc_key: enc_pk.clone(),
            },
        };
        let request = request.ok_or(anyhow_error_and_log(
            "empty request while processing reencryption response",
        ))?;

        // Execute simplified and faster flow for the centralized case
        // Observe that we don't encode exactly the same in the centralized case and in the
        // distributed case. For the centralized case we directly encode the [Plaintext]
        // object whereas for the distributed we encode the plain text as a
        // Vec<ResiduePoly<Z128>>
        if agg_resp.responses.len() <= 1 {
            self.centralized_reencryption_resp(request, agg_resp, &client_keys)
        } else {
            self.distributed_reencryption_resp(request, agg_resp, &client_keys)
        }
    }

    /// Validates the aggregated decryption response by checking:
    /// - The responses agree on metadata like shares needed
    /// - The response matches the original request
    /// - Signatures on responses are valid
    ///
    /// Returns true if the response is valid, false otherwise
    #[cfg(feature = "non-wasm")]
    fn validate_decryption_resp(
        &self,
        request: Option<DecryptionRequest>,
        agg_resp: &AggregatedDecryptionResponse,
    ) -> anyhow::Result<bool> {
        match request {
            Some(req) => {
                let resp_parsed_payloads = some_or_err(
                    self.validate_individual_dec_resp(req.servers_needed, agg_resp)?,
                    "Could not validate the aggregated responses".to_string(),
                )?;
                let pivot_payload = resp_parsed_payloads[0].clone();
                if req.version != pivot_payload.version() {
                    tracing::warn!("Version in the decryption request is incorrect");
                    return Ok(false);
                }
                if req.fhe_type() != pivot_payload.fhe_type()? {
                    tracing::warn!("Fhe type in the decryption response is incorrect");
                    return Ok(false);
                }
                let sig_payload: DecryptionRequestSerializable = req.try_into()?;
                if serialize_hash_element(&to_vec(&sig_payload)?)? != pivot_payload.digest {
                    tracing::warn!("The decryption response is not linked to the correct request");
                    return Ok(false);
                }
                Ok(true)
            }
            None => {
                tracing::warn!("No payload in the decryption request!");
                Ok(false)
            }
        }
    }

    #[cfg(feature = "non-wasm")]
    fn validate_individual_dec_resp(
        &self,
        shares_needed: u32,
        agg_resp: &AggregatedDecryptionResponse,
    ) -> anyhow::Result<Option<Vec<DecryptionResponsePayload>>> {
        if agg_resp.responses.is_empty() {
            tracing::warn!("AggregatedDecryptionResponse is empty!");
            return Ok(None);
        }
        // Pick a pivot response, in this case the last one
        let mut option_pivot_payload: Option<DecryptionResponsePayload> = None;
        let mut resp_parsed_payloads = Vec::with_capacity(agg_resp.responses.len());
        for cur_resp in &agg_resp.responses {
            let cur_payload = match cur_resp.payload.clone() {
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
                    option_pivot_payload = Some(cur_payload.clone());
                    resp_parsed_payloads.push(cur_payload);
                    continue;
                }
            };
            let sig = Signature {
                sig: k256::ecdsa::Signature::from_slice(&cur_resp.signature)?,
            };
            // Validate the signature on the response
            // Observe that it has already been verified in [self.validate_meta_data] that server
            // verification key is in the set of permissble keys
            let cur_verf_key: PublicSigKey = from_bytes(&cur_payload.verification_key)?;
            if !BaseKmsStruct::verify_sig(&to_vec(&cur_payload)?, &sig, &cur_verf_key) {
                tracing::warn!("Signature on received response is not valid!");
                continue;
            }
            // Validate that all the responses agree with the pivot on the static parts of the
            // response
            if !self.validate_meta_data(pivot_payload, &cur_payload)? {
                tracing::warn!("Some server did not provide the proper response!");
                continue;
            }
            resp_parsed_payloads.push(cur_payload);
        }

        if resp_parsed_payloads.len() < shares_needed as usize {
            tracing::warn!("Not enough correct responses to decrypt the data!");
            return Ok(None);
        }
        Ok(Some(resp_parsed_payloads))
    }

    /// Validates the aggregated reencryption responses received from the servers
    /// against the given reencryption request. Returns the validated responses
    /// mapped to the server ID on success.
    fn validate_agg_reenc_resp(
        &self,
        request: ReencryptionRequest,
        agg_resp: &AggregatedReencryptionResponse,
    ) -> anyhow::Result<
        Option<(
            ReencryptionRequestPayload,
            HashMap<u32, ReencryptionResponse>,
        )>,
    > {
        let expected_link = request.compute_link_checked()?;
        match request.payload {
            Some(req_payload) => {
                let resp_parsed = some_or_err(
                    self.validate_individual_agg_reenc_resp(req_payload.servers_needed, agg_resp)?,
                    "Could not validate the aggregated responses".to_string(),
                )?;
                let pivot_resp = resp_parsed.values().collect_vec()[0];
                if req_payload.version != pivot_resp.version() {
                    tracing::warn!("Version in the reencryption request is incorrect");
                    return Ok(None);
                }
                if req_payload.fhe_type() != pivot_resp.fhe_type() {
                    tracing::warn!("Fhe type in the reencryption response is incorrect");
                    return Ok(None);
                }
                if expected_link != pivot_resp.digest {
                    tracing::warn!(
                        "The reencryption response is not linked to the correct request"
                    );
                    return Ok(None);
                }
                Ok(Some((req_payload, resp_parsed)))
            }
            None => {
                tracing::warn!("No payload in the reencryption request!");
                Ok(None)
            }
        }
    }

    fn validate_individual_agg_reenc_resp(
        &self,
        shares_needed: u32,
        agg_resp: &AggregatedReencryptionResponse,
    ) -> anyhow::Result<Option<HashMap<u32, ReencryptionResponse>>> {
        if agg_resp.responses.is_empty() {
            tracing::warn!("AggregatedDecryptionResponse is empty!");
            return Ok(None);
        }
        // Pick a pivot response, in this case the last one
        let mut option_pivot: Option<&ReencryptionResponse> = None;
        let mut resp_parsed = HashMap::with_capacity(agg_resp.responses.len());
        for (cur_role, cur_resp) in &agg_resp.responses {
            // Set the first existing element as pivot
            let pivot_resp = match option_pivot {
                Some(pivot_resp) => pivot_resp,
                None => {
                    option_pivot = Some(cur_resp);
                    resp_parsed.insert(*cur_role, cur_resp.clone());
                    continue;
                }
            };
            // Validate that all the responses agree with the pivot on the static parts of the
            // response
            if !self.validate_meta_data(pivot_resp, cur_resp)? {
                tracing::warn!("Server {cur_role} did not provide the proper response!");
                continue;
            }
            resp_parsed.insert(*cur_role, cur_resp.clone());
        }
        if resp_parsed.len() < shares_needed as usize {
            tracing::warn!("Not enough correct responses to reencrypt the data!");
            return Ok(None);
        }
        Ok(Some(resp_parsed))
    }

    fn centralized_reencryption_resp(
        &self,
        request: ReencryptionRequest,
        agg_resp: &AggregatedReencryptionResponse,
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Option<Plaintext>> {
        let resp = some_or_err(
            agg_resp.responses.values().last(),
            "Response does not exist".to_owned(),
        )?;

        let link = request.compute_link_checked()?;
        if link != resp.digest {
            return Err(anyhow_error_and_log("link mismatch"));
        }

        let cur_verf_key: PublicSigKey = from_bytes(&resp.verification_key)?;
        match decrypt_signcryption(
            &resp.signcrypted_ciphertext,
            &link,
            client_keys,
            &cur_verf_key,
        )? {
            Some(decryption_share) => Ok(Some(decryption_share.try_into()?)),
            None => {
                tracing::warn!("Could decrypt or validate signcrypted response");
                Ok(None)
            }
        }
    }

    fn distributed_reencryption_resp(
        &self,
        request: ReencryptionRequest,
        agg_resp: &AggregatedReencryptionResponse,
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Option<Plaintext>> {
        let (req_payload, validated_resps) = some_or_err(
            self.validate_agg_reenc_resp(request, agg_resp)?,
            "Could not validate request".to_owned(),
        )?;
        let sharings =
            self.recover_sharings(validated_resps, req_payload.fhe_type(), client_keys)?;
        let amount_shares = sharings.len();
        let mut decrypted_blocks = Vec::new();
        for cur_block_shares in sharings {
            // NOTE: this performs optimistic reconstruction
            if let Ok(Some(r)) = reconstruct_w_errors_sync(
                amount_shares,
                (req_payload.servers_needed - 1) as usize,
                (req_payload.servers_needed - 1) as usize,
                &cur_block_shares,
            ) {
                decrypted_blocks.push(r);
            } else {
                return Err(anyhow_error_and_log("Could not reconstruct all blocks"));
            }
        }
        let recon_blocks =
            reconstruct_message(Some(decrypted_blocks), &self.params.ciphertext_parameters)?;
        Ok(Some(decrypted_blocks_to_raw_decryption(
            &self.params,
            req_payload.fhe_type(),
            recon_blocks,
        )?))
    }

    /// Decrypts the reencryption responses and decodes the responses onto the Shamir shares
    /// that the servers should have encrypted.
    fn recover_sharings(
        &self,
        agg_resp: HashMap<u32, ReencryptionResponse>,
        fhe_type: FheType,
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Vec<ShamirSharings<ResiduePoly<Z128>>>> {
        let num_blocks = num_blocks(fhe_type, self.params);
        let mut sharings = Vec::new();
        for _i in 0..num_blocks {
            sharings.push(ShamirSharings::new());
        }
        for (cur_role_id, cur_resp) in &agg_resp {
            // Observe that it has already been verified in [validate_meta_data] that server
            // verification key is in the set of permissble keys
            //
            // Also it's ok to use [cur_resp.digest] as the link since we already checked
            // that it matches with the original request
            let cur_verf_key: PublicSigKey = from_bytes(&cur_resp.verification_key)?;
            match decrypt_signcryption(
                &cur_resp.signcrypted_ciphertext,
                &cur_resp.digest,
                client_keys,
                &cur_verf_key,
            )? {
                Some(decryption_share) => {
                    let cipher_blocks_share: Vec<ResiduePoly<Z128>> =
                        serde_asn1_der::from_bytes(&decryption_share.bytes)?;
                    let mut cur_blocks = Vec::with_capacity(cipher_blocks_share.len());
                    for cur_block_share in cipher_blocks_share {
                        cur_blocks.push(cur_block_share);
                    }
                    fill_indexed_shares(
                        &mut sharings,
                        cur_blocks,
                        num_blocks,
                        Role::indexed_by_one(*cur_role_id as usize),
                    )?;
                }
                None => {
                    tracing::warn!("Could decrypt or validate signcrypted response");
                    fill_indexed_shares(
                        &mut sharings,
                        Vec::new(),
                        num_blocks,
                        Role::indexed_by_one(*cur_role_id as usize),
                    )?;
                }
            };
        }
        Ok(sharings)
    }

    fn validate_meta_data<T: MetaResponse>(
        &self,
        pivot_resp: &T,
        other_resp: &T,
    ) -> anyhow::Result<bool> {
        if pivot_resp.version() != other_resp.version() {
            tracing::warn!(
                    "Response from server with verification key {:?} gave version {:?}, whereas the pivot server's version is {:?}, and its verification key is {:?}.",
                    pivot_resp.verification_key(),
                    pivot_resp.version(),
                    other_resp.version(),
                    other_resp.verification_key()
                );
            return Ok(false);
        }
        if pivot_resp.fhe_type()? != other_resp.fhe_type()? {
            tracing::warn!(
                    "Response from server with verification key {:?} gave fhe type {:?}, whereas the pivot server's fhe type is {:?} and its verification key is {:?}",
                    pivot_resp.verification_key(),
                    pivot_resp.fhe_type(),
                    other_resp.fhe_type(),
                    other_resp.verification_key()
                );
            return Ok(false);
        }
        if pivot_resp.servers_needed() != other_resp.servers_needed() {
            tracing::warn!(
                    "Response from server with verification key {:?} say {:?} shares are needed for reconstruction, whereas the pivot server says {:?} shares are needed for reconstruction, and its verification key is {:?}",
                    pivot_resp.verification_key(),
                    pivot_resp.servers_needed(),
                    other_resp.servers_needed(),
                    other_resp.verification_key()
                );
            return Ok(false);
        }
        if pivot_resp.digest() != other_resp.digest() {
            tracing::warn!(
                    "Response from server with verification key {:?} gave digest {:?}, whereas the pivot server gave digest {:?}, and its verification key is {:?}",
                    pivot_resp.verification_key(),
                    pivot_resp.servers_needed(),
                    other_resp.servers_needed(),
                    other_resp.verification_key()
                );
            return Ok(false);
        }
        let resp_verf_key: PublicSigKey = from_bytes(&other_resp.verification_key())?;
        if !&self.server_pks.contains(&resp_verf_key) {
            tracing::warn!("Server key is incorrect in reencryption request");
            return Ok(false);
        }
        if pivot_resp.servers_needed() != self.shares_needed {
            tracing::warn!("Response says only {:?} shares are needed for reconstruction, but client is setup to require {:?} shares", pivot_resp.servers_needed(), self.shares_needed);
            return Ok(false);
        }

        Ok(true)
    }
}

/// Calculates the number of blocks needed to encode a message of the given FHE
/// type, based on the usable message modulus log from the
/// parameters. Rounds up to ensure enough blocks.
pub fn num_blocks(fhe_type: FheType, params: NoiseFloodParameters) -> usize {
    match fhe_type {
        FheType::Bool => {
            8_usize.div_ceil(params.ciphertext_parameters.message_modulus_log() as usize)
        }
        FheType::Euint4 => {
            8_usize.div_ceil(params.ciphertext_parameters.message_modulus_log() as usize)
        }
        FheType::Euint8 => {
            8_usize.div_ceil(params.ciphertext_parameters.message_modulus_log() as usize)
        }
        FheType::Euint16 => {
            16_usize.div_ceil(params.ciphertext_parameters.message_modulus_log() as usize)
        }
        FheType::Euint32 => {
            32_usize.div_ceil(params.ciphertext_parameters.message_modulus_log() as usize)
        }
        FheType::Euint64 => {
            64_usize.div_ceil(params.ciphertext_parameters.message_modulus_log() as usize)
        }
        FheType::Euint128 => {
            128_usize.div_ceil(params.ciphertext_parameters.message_modulus_log() as usize)
        }
        FheType::Euint160 => {
            160_usize.div_ceil(params.ciphertext_parameters.message_modulus_log() as usize)
        }
    }
}

// TODO this module should be behind cfg(test) normally
// but we need it in other places such as the connector
// and cfg(test) is not compiled by tests in other crates.
// Consider putting this behind a test-specific crate.
#[cfg(feature = "non-wasm")]
pub mod test_tools {
    use super::*;
    use crate::consts::{BASE_PORT, DEC_CAPACITY, DEFAULT_PROT, DEFAULT_URL, MIN_DEC_CACHE};
    use crate::kms::coordinator_endpoint_client::CoordinatorEndpointClient;
    use crate::rpc::central_rpc::{
        default_param_file_map, server_handle, CentralizedConfigNoStorage,
    };
    use crate::storage::{FileStorage, PublicStorage, RamStorage, StorageType, StorageVersion};
    use crate::threshold::threshold_kms::{
        threshold_server_init, threshold_server_start, PeerConf, ThresholdConfigNoStorage,
    };
    use std::str::FromStr;
    use tokio::task::JoinHandle;
    use tonic::transport::{Channel, Uri};

    fn default_peer_configs(n: usize) -> Vec<PeerConf> {
        (1..=n)
            .map(|i| PeerConf {
                party_id: i,
                address: "127.0.0.1".to_string(),
                port: BASE_PORT + i as u16,
                tls_cert_path: None,
            })
            .collect_vec()
    }

    pub async fn setup_threshold_no_client<
        PubS: PublicStorage + Clone + Sync + Send + 'static,
        PrivS: PublicStorage + Clone + Sync + Send + 'static,
    >(
        threshold: u8,
        pub_storage: Vec<PubS>,
        priv_storage: Vec<PrivS>,
    ) -> HashMap<u32, JoinHandle<()>> {
        let mut handles = Vec::new();
        tracing::info!("Spawning servers...");
        let amount = priv_storage.len();
        let timeout_secs = 360u64;
        for i in 1..=amount {
            let cur_pub_storage = pub_storage[i - 1].to_owned();
            let cur_priv_storage = priv_storage[i - 1].to_owned();
            let peer_configs = default_peer_configs(amount);
            handles.push(tokio::spawn(async move {
                let config = ThresholdConfigNoStorage {
                    listen_address_client: DEFAULT_URL.to_owned(),
                    listen_port_client: BASE_PORT + i as u16 * 100,
                    listen_address_core: peer_configs[i - 1].address.clone(),
                    listen_port_core: peer_configs[i - 1].port,
                    threshold,
                    dec_capacity: DEC_CAPACITY,
                    min_dec_cache: MIN_DEC_CACHE,
                    my_id: i,
                    timeout_secs,
                    preproc_redis_conf: None,
                    num_sessions_preproc: None,
                    tls_cert_path: None,
                    tls_key_path: None,
                    peer_confs: peer_configs,
                    param_file_map: default_param_file_map(),
                };
                // TODO pass in cert_paths for testing TLS
                let server =
                    threshold_server_init(config.clone(), cur_pub_storage, cur_priv_storage, true)
                        .await;
                (i, server, config)
            }));
        }
        // Wait for the server to start
        tracing::info!("Client waiting for server");
        let mut servers = Vec::with_capacity(amount);
        for cur_handle in handles {
            let (i, kms_server_res, config) = cur_handle.await.unwrap();
            match kms_server_res {
                Ok(kms_server) => servers.push((i, kms_server, config)),
                Err(e) => tracing::warn!("Failed to start server {i} with error {:?}", e),
            }
        }
        tracing::info!("Servers initialized. Starting servers...");
        let mut server_handles = HashMap::new();
        for (i, cur_server, config) in servers {
            assert_eq!(i, cur_server.my_id());
            let handle = tokio::spawn(async move {
                let _ = threshold_server_start(
                    config.listen_address_client,
                    config.listen_port_client,
                    timeout_secs,
                    cur_server,
                )
                .await;
            });
            server_handles.insert(i as u32, handle);
        }
        // We need to sleep as the servers keep running in the background and hence do not return
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        server_handles
    }

    pub async fn setup_threshold<
        PubS: PublicStorage + Clone + Sync + Send + 'static,
        PrivS: PublicStorage + Clone + Sync + Send + 'static,
    >(
        threshold: u8,
        pub_storage: Vec<PubS>,
        priv_storage: Vec<PrivS>,
    ) -> (
        HashMap<u32, JoinHandle<()>>,
        HashMap<u32, CoordinatorEndpointClient<Channel>>,
    ) {
        let amount = priv_storage.len();
        let server_handles = setup_threshold_no_client(threshold, pub_storage, priv_storage).await;
        let mut client_handles = HashMap::new();
        for i in 1..=amount {
            // NOTE: calculation of port must match what's done in [setup_threshold_no_client]
            let port = BASE_PORT + i as u16 * 100;
            let url = format!("{DEFAULT_PROT}://{DEFAULT_URL}:{port}");
            let uri = Uri::from_str(&url).unwrap();
            let channel = Channel::builder(uri).connect().await.unwrap();
            client_handles.insert(i as u32, CoordinatorEndpointClient::new(channel));
        }
        tracing::info!("Client connected to servers");
        (server_handles, client_handles)
    }

    /// Setup a client and a server running with non-persistant storage.
    pub async fn setup_centralized_no_client<
        PubS: PublicStorage + Sync + Send + 'static,
        PrivS: PublicStorage + Sync + Send + 'static,
    >(
        pub_storage: PubS,
        priv_storage: PrivS,
    ) -> JoinHandle<()> {
        let server_handle = tokio::spawn(async move {
            let url = format!("{DEFAULT_PROT}://{DEFAULT_URL}:{}", BASE_PORT + 1);
            let config = CentralizedConfigNoStorage {
                url,
                param_file_map: default_param_file_map(),
            };
            let _ = server_handle(config, pub_storage, priv_storage).await;
        });
        // We have to wait for the server to start since it will keep running in the background
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        server_handle
    }

    pub(crate) async fn setup_centralized<
        PubS: PublicStorage + Sync + Send + 'static,
        PrivS: PublicStorage + Sync + Send + 'static,
    >(
        pub_storage: PubS,
        priv_storage: PrivS,
    ) -> (
        JoinHandle<()>,
        CoordinatorEndpointClient<tonic::transport::Channel>,
    ) {
        let server_handle = setup_centralized_no_client(pub_storage, priv_storage).await;
        let url = format!("{DEFAULT_PROT}://{DEFAULT_URL}:{}", BASE_PORT + 1);
        let uri = Uri::from_str(&url).unwrap();
        let channel = Channel::builder(uri).connect().await.unwrap();
        let client = CoordinatorEndpointClient::new(channel);
        (server_handle, client)
    }

    /// Read the centralized keys for testing from `centralized_key_path` and construct a KMS
    /// server, client end-point connection (which is needed to communicate with the server) and
    /// an internal client (for constructing requests and validating responses).
    pub async fn centralized_handles(
        storage_version: StorageVersion,
        param_path: &str,
    ) -> (JoinHandle<()>, CoordinatorEndpointClient<Channel>, Client) {
        let (kms_server, kms_client) = match storage_version {
            StorageVersion::Dev => {
                let priv_storage = FileStorage::new_centralized(None, StorageType::PRIV).unwrap();
                let pub_storage = FileStorage::new_centralized(None, StorageType::PUB).unwrap();
                setup_centralized(pub_storage, priv_storage).await
            }
            StorageVersion::Ram => {
                let pub_storage = RamStorage::new(StorageType::PUB);
                let priv_storage = RamStorage::new(StorageType::PRIV);
                setup_centralized(pub_storage, priv_storage).await
            }
        };
        let pub_storage = vec![FileStorage::new_centralized(None, StorageType::PUB).unwrap()];
        let client_storage = FileStorage::new_centralized(None, StorageType::CLIENT).unwrap();
        let internal_client = Client::new_client(client_storage, pub_storage, param_path, 1, 1)
            .await
            .unwrap();
        (kms_server, kms_client, internal_client)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::Client;
    #[cfg(feature = "wasm_tests")]
    use crate::client::TestingReencryptionTranscript;
    use crate::consts::TEST_CENTRAL_KEY_ID;
    use crate::consts::{
        AMOUNT_PARTIES, TEST_DEC_ID, TEST_FHE_TYPE, TEST_MSG, TEST_PARAM_PATH, TEST_REENC_ID,
        THRESHOLD,
    };
    #[cfg(feature = "slow_tests")]
    use crate::consts::{
        DEFAULT_CENTRAL_KEYS_PATH, DEFAULT_CENTRAL_KEY_ID, DEFAULT_PARAM_PATH,
        DEFAULT_THRESHOLD_KEY_ID,
    };
    #[cfg(feature = "wasm_tests")]
    use crate::consts::{TEST_CENTRAL_WASM_TRANSCRIPT_PATH, TEST_THRESHOLD_WASM_TRANSCRIPT_PATH};
    #[cfg(feature = "slow_tests")]
    use crate::cryptography::central_kms::CentralizedTestingKeys;
    use crate::cryptography::central_kms::{compute_handle, BaseKmsStruct};
    use crate::cryptography::der_types::Signature;
    use crate::kms::coordinator_endpoint_client::CoordinatorEndpointClient;
    #[cfg(feature = "slow_tests")]
    use crate::kms::CrsGenResult;
    use crate::kms::{
        AggregatedDecryptionResponse, AggregatedReencryptionResponse, FheType, ParamChoice,
    };
    use crate::rpc::central_rpc::default_param_file_map;
    use crate::rpc::rpc_types::{BaseKms, PubDataType};
    use crate::storage::PublicStorageReader;
    use crate::storage::{FileStorage, RamStorage, StorageType, StorageVersion};
    use crate::util::file_handling::read_element;
    #[cfg(feature = "wasm_tests")]
    use crate::util::file_handling::write_element;
    use crate::util::key_setup::purge;
    use crate::util::key_setup::{compute_cipher_from_storage, FhePublicKey};
    use crate::{
        client::num_blocks,
        kms::{Empty, RequestId},
    };
    use crate::{consts::TEST_THRESHOLD_KEY_ID, util::file_handling::read_as_json};
    use alloy_sol_types::Eip712Domain;
    use distributed_decryption::execution::tfhe_internals::parameters::NoiseFloodParameters;
    use distributed_decryption::execution::zk::ceremony::PublicParameter;
    use serial_test::serial;
    use std::collections::HashMap;
    #[cfg(feature = "slow_tests")]
    use std::collections::HashSet;
    use tokio::task::{JoinHandle, JoinSet};
    use tonic::transport::Channel;

    /// Reads the testing keys for the threshold servers and starts them up, and returns a hash map
    /// of the servers, based on their ID, which starts from 1. A smiliar map is also returned
    /// is the client endpoints needed to talk with each of the servers, finally the internal
    /// client is returned (which is responsible for constructing requests and validating
    /// responses).
    async fn threshold_handles(
        storage_version: StorageVersion,
        param_path: &str,
    ) -> (
        HashMap<u32, JoinHandle<()>>,
        HashMap<u32, CoordinatorEndpointClient<Channel>>,
        Client,
    ) {
        let (kms_servers, kms_clients) = match storage_version {
            StorageVersion::Dev => {
                let mut pub_storage = Vec::new();
                let mut priv_storage = Vec::new();
                for i in 1..=AMOUNT_PARTIES {
                    priv_storage
                        .push(FileStorage::new_threshold(None, StorageType::PRIV, i).unwrap());
                    pub_storage
                        .push(FileStorage::new_threshold(None, StorageType::PUB, i).unwrap());
                }
                super::test_tools::setup_threshold(THRESHOLD as u8, pub_storage, priv_storage).await
            }
            StorageVersion::Ram => {
                let mut pub_storage = Vec::new();
                let mut priv_storage = Vec::new();
                for _i in 1..=AMOUNT_PARTIES {
                    priv_storage.push(RamStorage::new(StorageType::PRIV));
                    pub_storage.push(RamStorage::new(StorageType::PUB));
                }
                super::test_tools::setup_threshold(THRESHOLD as u8, pub_storage, priv_storage).await
            }
        };
        let mut pub_storage = Vec::with_capacity(AMOUNT_PARTIES);
        for i in 1..=AMOUNT_PARTIES {
            pub_storage.push(FileStorage::new_threshold(None, StorageType::PUB, i).unwrap());
        }
        let client_storage = FileStorage::new_centralized(None, StorageType::CLIENT).unwrap();
        let internal_client = Client::new_client(
            client_storage,
            pub_storage,
            param_path,
            (THRESHOLD as u32) + 1,
            AMOUNT_PARTIES as u32,
        )
        .await
        .unwrap();
        (kms_servers, kms_clients, internal_client)
    }

    #[tokio::test]
    #[serial]
    async fn test_key_gen_centralized() {
        let request_id = RequestId::derive("test_key_gen_centralized").unwrap();
        // Delete potentially old data
        purge(None, None, &request_id.to_string()).await;
        key_gen_centralized(TEST_PARAM_PATH, &request_id, Some(ParamChoice::Test)).await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial]
    async fn default_key_gen_centralized() {
        let request_id = RequestId::derive("default_key_gen_centralized").unwrap();
        // Delete potentially old data
        purge(None, None, &request_id.to_string()).await;
        key_gen_centralized(DEFAULT_PARAM_PATH, &request_id, Some(ParamChoice::Default)).await;
    }

    async fn key_gen_centralized(
        param_path: &str,
        request_id: &RequestId,
        params: Option<ParamChoice>,
    ) {
        let (kms_server, mut kms_client, internal_client) =
            super::test_tools::centralized_handles(StorageVersion::Dev, param_path).await;

        let gen_req = internal_client
            .key_gen_request(request_id, None, params)
            .unwrap();
        let req_id = gen_req.request_id.clone().unwrap();
        let gen_response = kms_client
            .key_gen(tonic::Request::new(gen_req.clone()))
            .await
            .unwrap();
        assert_eq!(gen_response.into_inner(), Empty {});
        // TODO the `Client` struct should aggregate the `KmsEndpointClient` struct for simplicity.
        // This makes it easier to use the client for testing and validation.
        let mut response = kms_client
            .get_key_gen_result(tonic::Request::new(req_id.clone()))
            .await;
        while response.is_err() && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
        {
            // Sleep to give the server some time to complete key generation
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            response = kms_client
                .get_key_gen_result(tonic::Request::new(req_id.clone()))
                .await;
        }
        let inner_resp = response.unwrap().into_inner();

        let pub_storage = FileStorage::new_centralized(None, StorageType::PUB).unwrap();
        let pk: Option<FhePublicKey> = internal_client
            .retrieve_key(&inner_resp, PubDataType::PublicKey, &pub_storage)
            .await
            .unwrap();
        assert!(pk.is_some());
        let server_key: Option<tfhe::ServerKey> = internal_client
            .retrieve_key(&inner_resp, PubDataType::ServerKey, &pub_storage)
            .await
            .unwrap();
        assert!(server_key.is_some());
        kms_server.abort();
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial]
    async fn default_crs_gen_centralized() {
        let request_id = RequestId::derive("default_crs_gen_centralized").unwrap();
        // Delete potentially old data
        purge(None, None, &request_id.to_string()).await;
        crs_gen_centralized_client(DEFAULT_PARAM_PATH, &request_id, Some(ParamChoice::Default))
            .await;
    }

    #[tokio::test]
    #[serial]
    async fn test_crs_gen_centralized() {
        let request_id = RequestId::derive("test_crs_gen_centralized").unwrap();
        // Delete potentially old data
        purge(None, None, &request_id.to_string()).await;
        crs_gen_centralized_manual(TEST_PARAM_PATH, &request_id, Some(ParamChoice::Test)).await;

        purge(None, None, &request_id.to_string()).await;
        crs_gen_centralized_client(TEST_PARAM_PATH, &request_id, Some(ParamChoice::Test)).await;
    }

    /// test centralized crs generation and do all the reading, processing and verification manually
    async fn crs_gen_centralized_manual(
        param_path: &str,
        request_id: &RequestId,
        params: Option<ParamChoice>,
    ) {
        let (kms_server, mut kms_client, internal_client) =
            super::test_tools::centralized_handles(StorageVersion::Dev, param_path).await;

        let ceremony_req = internal_client.crs_gen_request(request_id, params).unwrap();

        let client_request_id = ceremony_req.request_id.clone().unwrap();

        // response is currently empty
        let gen_response = kms_client
            .crs_gen(tonic::Request::new(ceremony_req.clone()))
            .await
            .unwrap();
        assert_eq!(gen_response.into_inner(), Empty {});
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        // Check that we can retrieve the CRS under that request id
        let mut get_response = kms_client
            .get_crs_gen_result(tonic::Request::new(client_request_id.clone()))
            .await;
        while get_response.is_err() {
            // Sleep to give the server some time to complete CRS generation
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            get_response = kms_client
                .get_crs_gen_result(tonic::Request::new(request_id.clone()))
                .await;
        }

        let resp = get_response.unwrap().into_inner();
        let rvcd_req_id = resp.request_id.unwrap();

        // // check that the received request id matches the one we sent in the request
        assert_eq!(rvcd_req_id, client_request_id);

        let crs_info = resp.crs_results.unwrap();
        let pub_storage = FileStorage::new_centralized(None, StorageType::PUB).unwrap();
        let mut crs_path = pub_storage
            .compute_url(&request_id.to_string(), &PubDataType::CRS.to_string())
            .unwrap()
            .to_string();

        assert!(crs_path.starts_with("file://"));
        crs_path.replace_range(0..7, ""); // remove leading "file:/" from URI, so we can read the file

        // check that CRS signature is verified correctly
        let crs_raw = read_element::<PublicParameter>(&crs_path).await.unwrap();
        let crs_serialized = bincode::serialize(&crs_raw).unwrap();
        let client_handle = compute_handle(&crs_serialized).unwrap();
        assert_eq!(&client_handle, &crs_info.key_handle);

        // try verification with each of the server keys; at least one must pass
        let crs_sig: Signature = bincode::deserialize(&crs_info.signature).unwrap();
        let mut verified = false;
        for vk in internal_client.server_pks {
            let v = BaseKmsStruct::verify_sig(&client_handle, &crs_sig, &vk);
            verified = verified || v;
        }

        // check that verification (with at least 1 server key) worked
        assert!(verified);

        kms_server.abort();
    }

    /// test centralized crs generation via client interface
    async fn crs_gen_centralized_client(
        param_path: &str,
        request_id: &RequestId,
        params: Option<ParamChoice>,
    ) {
        let (kms_server, mut kms_client, internal_client) =
            super::test_tools::centralized_handles(StorageVersion::Dev, param_path).await;
        let gen_req = internal_client.crs_gen_request(request_id, params).unwrap();

        // response is currently empty
        let gen_response = kms_client
            .crs_gen(tonic::Request::new(gen_req.clone()))
            .await
            .unwrap();
        assert_eq!(gen_response.into_inner(), Empty {});

        let mut response = kms_client.get_crs_gen_result(request_id.clone()).await;
        while response.is_err() {
            // Sleep to give the server some time to complete CRS generation
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            response = kms_client
                .get_crs_gen_result(tonic::Request::new(request_id.clone()))
                .await;
        }
        let inner_resp = response.unwrap().into_inner();
        let pub_storage = FileStorage::new_centralized(None, StorageType::PUB).unwrap();
        let crs = internal_client
            .retrieve_crs(&inner_resp, &pub_storage)
            .await
            .unwrap();
        assert!(crs.is_some());
        kms_server.abort();

        // try to make a proof and check that it works
        let param_file_map = HashMap::from_iter(
            default_param_file_map()
                .into_iter()
                .filter_map(|(k, v)| ParamChoice::from_str_name(&k).map(|x| (x, v))),
        );
        let fhe_params =
            crate::rpc::central_rpc::retrieve_parameters(params.unwrap().into(), &param_file_map)
                .await
                .unwrap()
                .ciphertext_parameters;
        let pp = crs.unwrap().try_into_tfhe_zk_pok_pp(&fhe_params).unwrap();
        let cks = tfhe::shortint::ClientKey::new(fhe_params);
        let pk = tfhe::shortint::CompactPublicKey::new(&cks);

        let max_msg_len = if params.unwrap() == ParamChoice::Test {
            1
        } else {
            4 * 64
        };
        let msgs = (0..max_msg_len)
            .map(|i| i % fhe_params.message_modulus.0 as u64)
            .collect::<Vec<_>>();

        let proven_ct = pk
            .encrypt_and_prove_slice(&msgs, &pp, tfhe::zk::ZkComputeLoad::Proof)
            .unwrap();
        assert!(proven_ct.verify(&pp, &pk).is_valid());

        let expanded = proven_ct.verify_and_expand(&pp, &pk).unwrap();
        let decrypted = expanded
            .iter()
            .map(|ciphertext| cks.decrypt(ciphertext))
            .collect::<Vec<_>>();
        assert_eq!(msgs, decrypted);
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial]
    async fn test_crs_gen_threshold() {
        // NOTE: the test parameter has 300 witness size
        // so we set this as a slow test

        let request_id = RequestId::derive("test_crs_gen_threshold").unwrap();
        // Ensure the test is idempotent
        purge(None, None, &request_id.to_string()).await;
        crs_gen_threshold(&request_id).await
    }

    #[cfg(feature = "slow_tests")]
    fn set_signatures(crs_gen_results: &mut [CrsGenResult], count: usize, sig: &[u8]) {
        for crs_gen_result in crs_gen_results.iter_mut().take(count) {
            match &mut crs_gen_result.crs_results {
                Some(info) => {
                    info.signature = sig.to_vec();
                }
                None => panic!("missing FhePubKeyInfo"),
            };
        }
    }

    #[cfg(feature = "slow_tests")]
    fn set_digests(crs_gen_results: &mut [CrsGenResult], count: usize, digest: &str) {
        for crs_gen_result in crs_gen_results.iter_mut().take(count) {
            match &mut crs_gen_result.crs_results {
                Some(info) => {
                    // each hex-digit is 4 bits, 160 bits is 40 characters
                    assert_eq!(40, info.key_handle.len());
                    // it's unlikely that we generate the same signature more than once
                    info.key_handle = digest.to_string();
                }
                None => panic!("missing FhePubKeyInfo"),
            }
        }
    }

    #[cfg(feature = "slow_tests")]
    async fn crs_gen_threshold(req_id: &RequestId) {
        let (kms_servers, kms_clients, internal_client) =
            threshold_handles(StorageVersion::Dev, TEST_PARAM_PATH).await;
        let req_gen = internal_client
            .crs_gen_request(req_id, Some(ParamChoice::Test))
            .unwrap();

        let mut tasks_gen = JoinSet::new();
        for i in 1..=AMOUNT_PARTIES as u32 {
            let mut cur_client = kms_clients.get(&i).unwrap().clone();
            let req_clone = req_gen.clone();
            tasks_gen
                .spawn(async move { cur_client.crs_gen(tonic::Request::new(req_clone)).await });
        }
        let mut responses_gen = Vec::new();
        while let Some(inner) = tasks_gen.join_next().await {
            let resp = inner.unwrap().unwrap();
            responses_gen.push(resp.into_inner());
        }
        assert_eq!(responses_gen.len(), AMOUNT_PARTIES);

        // wait a bit for the crs generation to finish
        const TRIES: usize = 20;
        let mut joined_responses = vec![];
        for i in 0..TRIES {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;

            let mut tasks_get = JoinSet::new();
            for j in 1..=AMOUNT_PARTIES as u32 {
                let mut cur_client = kms_clients.get(&j).unwrap().clone();
                let req_id_cloned = req_id.clone();
                tasks_get.spawn(async move {
                    (
                        j,
                        cur_client
                            .get_crs_gen_result(tonic::Request::new(req_id_cloned))
                            .await,
                    )
                });
            }
            let mut responses_get = Vec::new();
            while let Some(Ok((j, Ok(resp)))) = tasks_get.join_next().await {
                responses_get.push((j, resp.into_inner()));
            }

            // fail if we can't find a response
            if i == TRIES - 1 {
                panic!("could not get crs after {} tries", i);
            }
            if !responses_get.is_empty() {
                // i.e., not empty
                joined_responses = responses_get;
                break;
            }
            // if there are no reponses then we try again
        }
        kms_servers
            .into_iter()
            .for_each(|(_id, handle)| handle.abort());

        // first check the happy path
        // the public parameter is checked in ddec tests, so we don't specifically check _pp
        assert_eq!(joined_responses.len(), AMOUNT_PARTIES);

        // we need to setup the storage devices in the right order
        // so that the client can read the CRS
        let (storage_readers, final_responses): (Vec<_>, Vec<_>) = joined_responses
            .into_iter()
            .map(|(i, res)| {
                (
                    { FileStorage::new_threshold(None, StorageType::PUB, i as usize).unwrap() },
                    res,
                )
            })
            .unzip();

        let _pp = internal_client
            .process_distributed_crs_result(req_id, final_responses.clone(), &storage_readers)
            .await
            .unwrap();

        // if there's [THRESHOLD] result missing, we can still recover the result
        let _pp = internal_client
            .process_distributed_crs_result(
                req_id,
                final_responses[0..final_responses.len() - THRESHOLD].to_vec(),
                &storage_readers,
            )
            .await
            .unwrap();

        // if there are [THRESHOLD+1] results missing, then we do not have consensus
        assert!(internal_client
            .process_distributed_crs_result(
                req_id,
                final_responses[0..final_responses.len() - (THRESHOLD + 1)].to_vec(),
                &storage_readers
            )
            .await
            .is_err());

        // if the request_id is wrong, we get nothing
        let bad_request_id = RequestId::derive("bad_request_id").unwrap();
        assert!(internal_client
            .process_distributed_crs_result(
                &bad_request_id,
                final_responses.clone(),
                &storage_readers
            )
            .await
            .is_err());

        // test that having [THRESHOLD] wrong signatures still works
        let mut final_responses_with_bad_sig = final_responses.clone();
        let client_sk = internal_client.client_sk.clone().unwrap();
        let bad_sig = bincode::serialize(
            &crate::cryptography::signcryption::sign(&"wrong msg".to_string(), &client_sk).unwrap(),
        )
        .unwrap();
        set_signatures(&mut final_responses_with_bad_sig, THRESHOLD, &bad_sig);

        let _pp = internal_client
            .process_distributed_crs_result(
                req_id,
                final_responses_with_bad_sig.clone(),
                &storage_readers,
            )
            .await
            .unwrap();

        // having [THRESHOLD+1] wrong signatures won't work
        set_signatures(&mut final_responses_with_bad_sig, THRESHOLD + 1, &bad_sig);
        assert!(internal_client
            .process_distributed_crs_result(req_id, final_responses_with_bad_sig, &storage_readers)
            .await
            .is_err());

        // having [THRESHOLD] wrong digest still works
        let mut final_responses_with_bad_digest = final_responses.clone();
        set_digests(
            &mut final_responses_with_bad_digest,
            THRESHOLD,
            "9fdca770403e2eed9dacb4cdd405a14fc6df7226",
        );
        let _pp = internal_client
            .process_distributed_crs_result(
                req_id,
                final_responses_with_bad_digest.clone(),
                &storage_readers,
            )
            .await
            .unwrap();

        // having [THRESHOLD+1] wrong digests will fail
        set_digests(
            &mut final_responses_with_bad_digest,
            THRESHOLD + 1,
            "9fdca770403e2eed9dacb4cdd405a14fc6df7226",
        );
        assert!(internal_client
            .process_distributed_crs_result(
                req_id,
                final_responses_with_bad_digest,
                &storage_readers
            )
            .await
            .is_err());
    }

    #[tokio::test]
    #[serial]
    async fn test_decryption_central() {
        decryption_centralized(TEST_PARAM_PATH, &TEST_CENTRAL_KEY_ID.to_string()).await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial]
    async fn default_decryption_centralized() {
        decryption_centralized(DEFAULT_PARAM_PATH, &DEFAULT_CENTRAL_KEY_ID.to_string()).await;
    }

    async fn decryption_centralized(param_path: &str, key_id: &str) {
        // TODO refactor with setup and teardown setting up servers that can be used to run tests in
        // parallel
        let (kms_server, mut kms_client, mut internal_client) =
            super::test_tools::centralized_handles(StorageVersion::Dev, param_path).await;
        let (ct, fhe_type) = compute_cipher_from_storage(None, TEST_MSG, key_id).await;
        let req_key_id = key_id.to_owned().try_into().unwrap();
        let req = internal_client
            .decryption_request(ct.clone(), fhe_type, &TEST_DEC_ID, &req_key_id)
            .unwrap();
        let response = kms_client
            .decrypt(tonic::Request::new(req.clone()))
            .await
            .unwrap();
        assert_eq!(response.into_inner(), Empty {});

        let mut response = kms_client
            .get_decrypt_result(req.request_id.clone().unwrap())
            .await;
        while response.is_err() && response.as_ref().unwrap_err().code() == tonic::Code::Unavailable
        {
            // Sleep to give the server some time to complete decryption
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            response = kms_client
                .get_decrypt_result(req.request_id.clone().unwrap())
                .await;
        }
        let responses = AggregatedDecryptionResponse {
            responses: vec![response.unwrap().into_inner()],
        };
        let plaintext = internal_client
            .process_decryption_resp(Some(req), &responses)
            .unwrap()
            .unwrap();
        assert_eq!(TEST_FHE_TYPE, plaintext.fhe_type());
        assert_eq!(TEST_MSG, plaintext.as_u8());

        kms_server.abort();
    }

    #[tokio::test]
    #[serial]
    async fn test_reencryption_centralized() {
        reencryption_centralized(TEST_PARAM_PATH, &TEST_CENTRAL_KEY_ID.to_string(), false).await;
    }

    #[cfg(feature = "wasm_tests")]
    #[tokio::test]
    #[serial]
    async fn test_reencryption_centralized_and_write_transcript() {
        reencryption_centralized(TEST_PARAM_PATH, &TEST_CENTRAL_KEY_ID.to_string(), true).await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial]
    async fn default_reencryption_centralized() {
        reencryption_centralized(
            DEFAULT_PARAM_PATH,
            &DEFAULT_CENTRAL_KEY_ID.to_string(),
            false,
        )
        .await;
    }

    fn dummy_domain() -> Eip712Domain {
        alloy_sol_types::eip712_domain!(
            name: "dummy",
            version: "1",
            chain_id: 1,
            verifying_contract: alloy_primitives::Address::ZERO,
        )
    }

    async fn reencryption_centralized(param_path: &str, key_id: &str, write_transcript: bool) {
        _ = write_transcript;

        let (kms_server, mut kms_client, mut internal_client) =
            super::test_tools::centralized_handles(StorageVersion::Dev, param_path).await;
        let (ct, fhe_type) = compute_cipher_from_storage(None, TEST_MSG, key_id).await;
        let request_id = &TEST_REENC_ID;
        let (req, enc_pk, enc_sk) = internal_client
            .reencryption_request(
                ct,
                &dummy_domain(),
                fhe_type,
                request_id,
                &key_id.to_string().try_into().unwrap(),
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
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            response = kms_client
                .get_reencrypt_result(req.request_id.clone().unwrap())
                .await;
        }

        let inner_response = response.unwrap().into_inner();
        let responses = AggregatedReencryptionResponse {
            responses: HashMap::from([(1, inner_response.clone())]),
        };

        #[cfg(feature = "wasm_tests")]
        {
            if write_transcript {
                let transcript = TestingReencryptionTranscript {
                    server_pks: internal_client.server_pks.clone(),
                    client_pk: internal_client.client_pk.clone(),
                    shares_needed: 0,
                    params: internal_client.params,
                    request: Some(req.clone()),
                    eph_sk: enc_sk.clone(),
                    eph_pk: enc_pk.clone(),
                    agg_resp: HashMap::from([(1, inner_response.clone())]),
                };
                write_element(TEST_CENTRAL_WASM_TRANSCRIPT_PATH, &transcript)
                    .await
                    .unwrap();
            }
        }

        let plaintext = internal_client
            .process_reencryption_resp(Some(req), &responses, &enc_pk, &enc_sk)
            .unwrap()
            .unwrap();
        assert_eq!(TEST_FHE_TYPE, plaintext.fhe_type());
        assert_eq!(TEST_MSG, plaintext.as_u8());

        kms_server.abort();
    }

    #[tracing_test::traced_test]
    #[tokio::test]
    #[serial]
    async fn test_decryption_threshold() {
        decryption_threshold(TEST_PARAM_PATH, &TEST_THRESHOLD_KEY_ID.to_string()).await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn default_decryption_threshold() {
        decryption_threshold(DEFAULT_PARAM_PATH, &DEFAULT_THRESHOLD_KEY_ID.to_string()).await;
    }

    async fn decryption_threshold(params: &str, key_id: &str) {
        let (kms_servers, kms_clients, mut internal_client) =
            threshold_handles(StorageVersion::Dev, params).await;
        let (ct, fhe_type) = compute_cipher_from_storage(None, TEST_MSG, key_id).await;
        let key_id_req = key_id.to_string().try_into().unwrap();

        let request_id = &TEST_DEC_ID;
        let req = internal_client
            .decryption_request(ct, fhe_type, request_id, &key_id_req)
            .unwrap();
        let mut req_tasks = JoinSet::new();
        for i in 1..=AMOUNT_PARTIES as u32 {
            let mut cur_client = kms_clients.get(&i).unwrap().clone();
            let req_clone = req.clone();
            req_tasks
                .spawn(async move { cur_client.decrypt(tonic::Request::new(req_clone)).await });
        }
        let mut req_response_vec = Vec::new();
        while let Some(inner) = req_tasks.join_next().await {
            req_response_vec.push(inner.unwrap().unwrap().into_inner());
        }
        assert_eq!(req_response_vec.len(), AMOUNT_PARTIES);

        let mut resp_tasks = JoinSet::new();
        for i in 1..=AMOUNT_PARTIES as u32 {
            let mut cur_client = kms_clients.get(&i).unwrap().clone();
            let req_clone = req.clone();
            resp_tasks.spawn(async move {
                // Sleep to give the server some time to complete decryption
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                cur_client
                    .get_decrypt_result(tonic::Request::new(req_clone.request_id.unwrap()))
                    .await
            });
        }
        let mut resp_response_vec = Vec::new();
        while let Some(resp) = resp_tasks.join_next().await {
            resp_response_vec.push(resp.unwrap().unwrap().into_inner());
        }
        let agg = AggregatedDecryptionResponse {
            responses: resp_response_vec,
        };
        let plaintext = internal_client
            .process_decryption_resp(Some(req), &agg)
            .unwrap()
            .unwrap();
        assert_eq!(TEST_FHE_TYPE, plaintext.fhe_type());
        assert_eq!(TEST_MSG, plaintext.as_u8());
        kms_servers
            .into_iter()
            .for_each(|(_id, handle)| handle.abort());
    }

    #[tokio::test]
    #[serial]
    async fn test_reencryption_threshold() {
        reencryption_threshold(TEST_PARAM_PATH, &TEST_THRESHOLD_KEY_ID.to_string(), false).await;
    }

    #[tokio::test]
    #[serial]
    #[cfg(feature = "wasm_tests")]
    async fn test_reencryption_threshold_and_write_transcript() {
        reencryption_threshold(TEST_PARAM_PATH, &TEST_THRESHOLD_KEY_ID.to_string(), true).await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn default_reencryption_threshold() {
        reencryption_threshold(
            DEFAULT_PARAM_PATH,
            &DEFAULT_THRESHOLD_KEY_ID.to_string(),
            false,
        )
        .await;
    }

    async fn reencryption_threshold(param: &str, key_id: &str, write_transcript: bool) {
        _ = write_transcript;

        let (kms_servers, kms_clients, mut internal_client) =
            threshold_handles(StorageVersion::Dev, param).await;
        let (ct, fhe_type) = compute_cipher_from_storage(None, TEST_MSG, key_id).await;

        let request_id = &TEST_REENC_ID;
        let (req, enc_pk, enc_sk) = internal_client
            .reencryption_request(
                ct,
                &dummy_domain(),
                fhe_type,
                request_id,
                &key_id.to_string().try_into().unwrap(),
            )
            .unwrap();
        let mut req_tasks = JoinSet::new();
        tracing::info!("Client did reencryption request");
        for i in 1..=AMOUNT_PARTIES as u32 {
            let mut cur_client = kms_clients.get(&i).unwrap().clone();
            let req_clone = req.clone();
            req_tasks
                .spawn(async move { cur_client.reencrypt(tonic::Request::new(req_clone)).await });
        }
        let mut req_response_vec = Vec::new();
        while let Some(resp) = req_tasks.join_next().await {
            req_response_vec.push(resp.unwrap().unwrap().into_inner());
        }
        assert_eq!(req_response_vec.len(), AMOUNT_PARTIES);

        let mut resp_tasks = JoinSet::new();
        for i in 1..=AMOUNT_PARTIES as u32 {
            let mut cur_client = kms_clients.get(&i).unwrap().clone();
            let req_clone = req.clone();
            resp_tasks.spawn(async move {
                // Sleep to give the server some time to complete reencryption
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                (
                    i,
                    cur_client
                        .get_reencrypt_result(tonic::Request::new(req_clone.request_id.unwrap()))
                        .await,
                )
            });
        }
        let mut response_map = HashMap::new();
        while let Some(res) = resp_tasks.join_next().await {
            let res = res.unwrap();
            tracing::info!("Client got a response from {}", res.0);
            let (i, resp) = res;
            response_map.insert(i, resp.unwrap().into_inner());
        }

        #[cfg(feature = "wasm_tests")]
        {
            if write_transcript {
                let transcript = TestingReencryptionTranscript {
                    server_pks: internal_client.server_pks.clone(),
                    client_pk: internal_client.client_pk.clone(),
                    shares_needed: THRESHOLD as u32 + 1,
                    params: internal_client.params,
                    request: Some(req.clone()),
                    eph_sk: enc_sk.clone(),
                    eph_pk: enc_pk.clone(),
                    agg_resp: response_map.clone(),
                };
                write_element(TEST_THRESHOLD_WASM_TRANSCRIPT_PATH, &transcript)
                    .await
                    .unwrap();
            }
        }

        let agg = AggregatedReencryptionResponse {
            responses: response_map,
        };
        let plaintext = internal_client
            .process_reencryption_resp(Some(req), &agg, &enc_pk, &enc_sk)
            .unwrap()
            .unwrap();
        assert_eq!(TEST_FHE_TYPE, plaintext.fhe_type());
        assert_eq!(TEST_MSG, plaintext.as_u8());
        kms_servers
            .into_iter()
            .for_each(|(_id, handle)| handle.abort());
    }

    // Validate bug-fix to ensure that the server fails gracefully when the ciphertext is too large
    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial]
    async fn test_largecipher() {
        let keys: CentralizedTestingKeys = read_element(DEFAULT_CENTRAL_KEYS_PATH).await.unwrap();
        let (kms_server, mut kms_client) = super::test_tools::setup_centralized(
            RamStorage::new(StorageType::PUB),
            RamStorage::from_existing_keys(&keys.software_kms_keys)
                .await
                .unwrap(),
        )
        .await;
        let ct = Vec::from([1_u8; 100000]);
        let fhe_type = FheType::Euint32;
        let mut internal_client = Client::new(
            HashSet::from_iter(keys.server_keys.iter().cloned()),
            keys.client_pk,
            Some(keys.client_sk),
            1,
            1,
            keys.params,
        );
        let request_id = &TEST_REENC_ID;
        let (req, _enc_pk, _enc_sk) = internal_client
            .reencryption_request(
                ct,
                &dummy_domain(),
                fhe_type,
                request_id,
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
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
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
        kms_server.abort();
    }

    #[tokio::test]
    async fn num_blocks_sunshine() {
        let params: NoiseFloodParameters = read_as_json(TEST_PARAM_PATH).await.unwrap();
        // 2 bits per block, using Euint8 as internal representation
        assert_eq!(num_blocks(FheType::Bool, params), 4);
        // 2 bits per block, using Euint8 as internal representation
        assert_eq!(num_blocks(FheType::Euint4, params), 4);
        // 2 bits per block
        assert_eq!(num_blocks(FheType::Euint8, params), 4);
        // 2 bits per block
        assert_eq!(num_blocks(FheType::Euint16, params), 8);
        // 2 bits per block
        assert_eq!(num_blocks(FheType::Euint32, params), 16);
        // 2 bits per block
        assert_eq!(num_blocks(FheType::Euint64, params), 32);
        // 2 bits per block
        assert_eq!(num_blocks(FheType::Euint128, params), 64);
        // 2 bits per block
        assert_eq!(num_blocks(FheType::Euint160, params), 80);
    }

    //Check status of preproc request
    #[cfg(feature = "slow_tests")]
    async fn get_preproc_status(
        request: crate::kms::KeyGenPreprocRequest,
        kms_clients: &HashMap<u32, CoordinatorEndpointClient<Channel>>,
    ) -> Vec<crate::kms::KeyGenPreprocStatus> {
        let mut tasks = JoinSet::new();
        for i in 1..=AMOUNT_PARTIES as u32 {
            let req_clone = request.clone();
            let mut cur_client = kms_clients.get(&i).unwrap().clone();
            tasks.spawn(async move {
                cur_client
                    .get_preproc_status(tonic::Request::new(req_clone))
                    .await
            });
        }
        let mut responses = Vec::new();
        while let Some(resp) = tasks.join_next().await {
            responses.push(resp.unwrap().unwrap().into_inner());
        }

        responses
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_preproc() {
        use crate::kms::{KeyGenPreprocRequest, KeyGenPreprocStatusEnum};

        let (kms_servers, kms_clients, internal_client) =
            threshold_handles(StorageVersion::Dev, TEST_PARAM_PATH).await;

        let request_id = RequestId::derive("test_preproc").unwrap();
        let request_id_nok = RequestId::derive("not ok").unwrap();
        let req_gen = internal_client
            .preproc_request(&request_id, Some(ParamChoice::Test))
            .unwrap();

        let mut tasks_gen = JoinSet::new();
        for i in 1..=AMOUNT_PARTIES as u32 {
            let mut cur_client = kms_clients.get(&i).unwrap().clone();
            let req_clone = req_gen.clone();
            tasks_gen.spawn(async move {
                cur_client
                    .key_gen_preproc(tonic::Request::new(req_clone))
                    .await
            });
        }

        let mut responses_gen = Vec::new();
        while let Some(resp) = tasks_gen.join_next().await {
            responses_gen.push(resp.unwrap().unwrap().into_inner());
        }
        assert_eq!(responses_gen.len(), AMOUNT_PARTIES);

        //Check status of preproc request
        async fn test_preproc_status(
            request: KeyGenPreprocRequest,
            expected_res: KeyGenPreprocStatusEnum,
            kms_clients: &HashMap<u32, CoordinatorEndpointClient<Channel>>,
        ) {
            let responses = get_preproc_status(request, kms_clients).await;

            for resp in responses {
                let expected: i32 = expected_res.into();
                assert_eq!(resp.result, expected);
            }
        }

        //This request should give us the correct status
        let req_status_ok = internal_client
            .preproc_request(&request_id, Some(ParamChoice::Test))
            .unwrap();
        test_preproc_status(
            req_status_ok.clone(),
            KeyGenPreprocStatusEnum::InProgress,
            &kms_clients,
        )
        .await;

        //This request is not ok because no preproc was ever started for this session id
        let req_status_nok_sid = internal_client
            .preproc_request(&request_id_nok, Some(ParamChoice::Test))
            .unwrap();
        test_preproc_status(
            req_status_nok_sid,
            KeyGenPreprocStatusEnum::Missing,
            &kms_clients,
        )
        .await;

        //Wait for 5 min max (should be plenty of time for the test params)
        let mut finished: Vec<_> = Vec::new();
        let finished_enum: i32 = KeyGenPreprocStatusEnum::Finished.into();
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
            let preproc_status = get_preproc_status(req_status_ok.clone(), &kms_clients).await;
            finished = preproc_status
                .into_iter()
                .filter(|x| x.result == finished_enum)
                .collect();

            if finished.len() == AMOUNT_PARTIES {
                break;
            }
        }

        //Make sure we did break because preproc is finished and not because of timeout
        assert_eq!(finished.len(), AMOUNT_PARTIES);

        for kms_server in kms_servers {
            kms_server.1.abort();
        }
    }

    //Helper function to launch dkg
    #[cfg(feature = "slow_tests")]
    async fn launch_dkg(
        req_keygen: crate::kms::KeyGenRequest,
        kms_clients: &HashMap<u32, CoordinatorEndpointClient<Channel>>,
    ) -> Vec<Result<tonic::Response<Empty>, tonic::Status>> {
        let mut tasks_gen = JoinSet::new();
        for i in 1..=AMOUNT_PARTIES as u32 {
            //Send kg request
            let mut cur_client = kms_clients.get(&i).unwrap().clone();
            let req_clone = req_keygen.clone();
            tasks_gen
                .spawn(async move { cur_client.key_gen(tonic::Request::new(req_clone)).await });
        }

        let mut responses_gen = Vec::new();
        while let Some(resp) = tasks_gen.join_next().await {
            responses_gen.push(resp.unwrap());
        }
        responses_gen
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_dkg() {
        use crate::kms::KeyGenPreprocStatusEnum;
        use itertools::Itertools;

        let req_preproc = RequestId::derive("test_dkg-preproc").unwrap();
        let req_key = RequestId::derive("test_dkg-key").unwrap();
        purge(None, None, &req_key.to_string()).await;

        let (kms_servers, kms_clients, internal_client) =
            threshold_handles(StorageVersion::Dev, TEST_PARAM_PATH).await;

        let preprocessing_req_data = internal_client
            .preproc_request(&req_preproc, Some(ParamChoice::Test))
            .unwrap();

        let mut tasks_gen = JoinSet::new();
        for i in 1..=AMOUNT_PARTIES as u32 {
            let mut cur_client = kms_clients.get(&i).unwrap().clone();
            let req_clone = preprocessing_req_data.clone();
            tasks_gen.spawn(async move {
                cur_client
                    .key_gen_preproc(tonic::Request::new(req_clone))
                    .await
            });
        }

        let mut responses_gen = Vec::new();
        while let Some(resp) = tasks_gen.join_next().await {
            responses_gen.push(resp.unwrap().unwrap().into_inner());
        }
        assert_eq!(responses_gen.len(), AMOUNT_PARTIES);

        //Wait for 5 min max (should be plenty of time for the test params)
        let finished_enum: i32 = KeyGenPreprocStatusEnum::Finished.into();
        let mut finished = Vec::new();
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;

            let status = get_preproc_status(preprocessing_req_data.clone(), &kms_clients).await;
            finished = status
                .into_iter()
                .filter(|x| x.result == finished_enum)
                .collect_vec();
            if finished.len() == AMOUNT_PARTIES {
                break;
            }
        }

        //Make sure we broke for loop because we indeed have finished preproc
        assert_eq!(finished.len(), AMOUNT_PARTIES);
        //Preproc is now ready, start legitimate dkg
        let req_keygen = internal_client
            .key_gen_request(&req_key, Some(req_preproc.clone()), Some(ParamChoice::Test))
            .unwrap();
        let responses = launch_dkg(req_keygen.clone(), &kms_clients).await;
        for response in responses {
            assert!(response.is_ok());
        }

        //Wait 5 min max (should be enough here too)
        let req_get_keygen = req_keygen.request_id.clone().unwrap();
        let mut finished = Vec::new();
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;

            let mut tasks = JoinSet::new();
            for i in 1..=AMOUNT_PARTIES as u32 {
                let req_clone = req_get_keygen.clone();
                let mut cur_client = kms_clients.get(&i).unwrap().clone();
                tasks.spawn(async move {
                    (
                        i,
                        cur_client
                            .get_key_gen_result(tonic::Request::new(req_clone))
                            .await,
                    )
                });
            }
            let mut responses = Vec::new();
            while let Some(resp) = tasks.join_next().await {
                responses.push(resp.unwrap());
            }

            finished = responses.into_iter().filter(|x| x.1.is_ok()).collect_vec();
            if finished.len() == AMOUNT_PARTIES {
                break;
            }
        }

        let finished = finished
            .into_iter()
            .map(|x| x.1.unwrap().into_inner())
            .collect_vec();

        let mut serialized_ref_pk = Vec::new();
        let mut serialized_ref_server_key = Vec::new();
        for (idx, kg_res) in finished.into_iter().enumerate() {
            let storage = FileStorage::new_threshold(None, StorageType::PUB, idx + 1).unwrap();
            let pk: Option<FhePublicKey> = internal_client
                .retrieve_key(&kg_res, PubDataType::PublicKey, &storage)
                .await
                .unwrap();
            assert!(pk.is_some());
            if idx == 0 {
                serialized_ref_pk = bincode::serialize(&(pk.unwrap())).unwrap();
            } else {
                assert_eq!(
                    serialized_ref_pk,
                    bincode::serialize(&(pk.unwrap())).unwrap()
                )
            }
            let server_key: Option<tfhe::ServerKey> = internal_client
                .retrieve_key(&kg_res, PubDataType::ServerKey, &storage)
                .await
                .unwrap();
            assert!(server_key.is_some());
            if idx == 0 {
                serialized_ref_server_key = bincode::serialize(&(server_key.unwrap())).unwrap();
            } else {
                assert_eq!(
                    serialized_ref_server_key,
                    bincode::serialize(&(server_key.unwrap())).unwrap()
                )
            }
        }

        //Try to request another kg with the same preproc but another request id
        let other_key_gen_id = RequestId::derive("test_dkg other key id").unwrap();
        let keygen_req_data = internal_client
            .key_gen_request(
                &other_key_gen_id,
                Some(req_preproc),
                Some(ParamChoice::Test),
            )
            .unwrap();
        let responses = launch_dkg(keygen_req_data.clone(), &kms_clients).await;
        for response in responses {
            assert_eq!(response.unwrap_err().code(), tonic::Code::NotFound);
        }

        for kms_server in kms_servers {
            kms_server.1.abort();
        }
    }
}

use crate::anyhow_error_and_log;
use crate::consts::TEST_KEY_ID;
use crate::cryptography::der_types::{
    PrivateEncKey, PrivateSigKey, PublicEncKey, PublicSigKey, SigncryptionPair,
    SigncryptionPrivKey, SigncryptionPubKey,
};
#[cfg(feature = "non-wasm")]
use crate::cryptography::signcryption::serialize_hash_element;
use crate::cryptography::signcryption::{
    decrypt_signcryption, encryption_key_generation, sign_eip712, RND_SIZE,
};
#[cfg(feature = "non-wasm")]
use crate::cryptography::{central_kms::compute_handle, der_types::Signature};
#[cfg(feature = "non-wasm")]
use crate::kms::{
    AggregatedDecryptionResponse, CrsGenRequest, CrsGenResult, DecryptionRequest,
    DecryptionResponsePayload, KeyGenRequest, KeyGenResult,
};
use crate::kms::{
    AggregatedReencryptionResponse, FheType, ReencryptionRequest, ReencryptionRequestPayload,
    ReencryptionResponse,
};
#[cfg(feature = "non-wasm")]
use crate::kms::{ParamChoice, RequestId};
use crate::rpc::rpc_types::{
    allow_to_protobuf_domain, protobuf_to_alloy_domain, MetaResponse, Plaintext,
    ReencryptionRequestSigPayload, CURRENT_FORMAT_VERSION,
};
#[cfg(feature = "non-wasm")]
use crate::rpc::rpc_types::{
    DecryptionRequestSerializable, DecryptionResponseSigPayload, PubDataType, KEY_GEN_REQUEST_NAME,
};
#[cfg(feature = "non-wasm")]
use crate::{cryptography::central_kms::BaseKmsStruct, rpc::rpc_types::BaseKms};
#[cfg(feature = "non-wasm")]
use crate::{storage::PublicStorageReader, util::key_setup::FhePublicKey};
use aes_prng::AesRng;
use alloy_sol_types::{Eip712Domain, SolStruct};
use distributed_decryption::execution::endpoints::reconstruct::combine128;
use distributed_decryption::execution::sharing::shamir::reconstruct_w_errors_sync;
use distributed_decryption::execution::sharing::shamir::{fill_indexed_shares, ShamirSharings};
#[cfg(feature = "non-wasm")]
use distributed_decryption::execution::zk::ceremony::PublicParameter;
use distributed_decryption::execution::{
    endpoints::reconstruct::reconstruct_message, runtime::party::Role,
};
use distributed_decryption::{
    algebra::base_ring::Z128, execution::tfhe_internals::parameters::NoiseFloodParameters,
};
use distributed_decryption::{
    algebra::residue_poly::ResiduePoly,
    execution::tfhe_internals::parameters::AugmentedCiphertextParameters,
};
use itertools::Itertools;
use rand::{RngCore, SeedableRng};
#[cfg(feature = "non-wasm")]
use serde::de::DeserializeOwned;
use serde_asn1_der::{from_bytes, to_vec};
use std::collections::{HashMap, HashSet};
use std::fmt;
#[cfg(feature = "non-wasm")]
use tfhe::ServerKey;
use wasm_bindgen::prelude::*;

fn some_or_err<T: fmt::Debug>(input: Option<T>, error: String) -> anyhow::Result<T> {
    input.ok_or_else(|| {
        tracing::warn!(error);
        anyhow::Error::msg("Invalid request")
    })
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
    params: NoiseFloodParameters,
    seq_no: u64, // Note that in production this number will come from the blockchain
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
    seq_no: u64, // Note that in production this number will come from the blockchain
    // request
    request: Option<ReencryptionRequest>,
    eph_sk: PrivateEncKey,
    eph_pk: PublicEncKey,
    // response
    agg_resp: HashMap<u32, ReencryptionResponse>,
}

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
#[cfg(not(feature = "non-wasm"))]
pub mod js_api {
    use crypto_box::{
        aead::{Aead, AeadCore},
        Nonce, SalsaBox,
    };

    use super::*;

    #[wasm_bindgen]
    pub fn new_client(
        server_pks: Vec<PublicSigKey>,
        client_pk: PublicSigKey,
        shares_needed: u32,
        seq_no: u64,
        params_json: &str,
    ) -> Client {
        console_error_panic_hook::set_once();

        let server_pks = HashSet::from_iter(server_pks);
        // TODO: we just use parameters stored in json for now
        // think about how to instantiate different parameters later
        // when we have an enum that specifies parameters
        let params: NoiseFloodParameters =
            serde_json::from_str::<NoiseFloodParameters>(params_json).unwrap();
        Client {
            rng: Box::new(AesRng::from_entropy()),
            server_pks,
            client_pk,
            client_sk: None,
            shares_needed,
            params,
            seq_no,
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
            req: None,
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

        Client {
            rng: Box::new(AesRng::from_entropy()),
            server_pks: transcript.server_pks,
            client_pk: transcript.client_pk,
            client_sk: None,
            shares_needed: transcript.shares_needed,
            params: transcript.params,
            seq_no: transcript.seq_no,
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
    pub fn cryptobox_pk_to_vec(pk: &PublicEncKey) -> Vec<u8> {
        to_vec(pk).unwrap()
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

    /// This function takes `AggregatedReencryptionResponse` normally
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
        match client.process_reencryption_resp(request, hm, enc_pk, enc_sk) {
            Ok(resp) => match resp {
                Some(out) => Ok(out.as_u8()),
                None => Err(JsError::new("no response")),
            },
            Err(e) => Err(JsError::new(&e.to_string())),
        }
    }
}

impl Client {
    pub fn new(
        server_pks: HashSet<PublicSigKey>,
        client_pk: PublicSigKey,
        client_sk: Option<PrivateSigKey>,
        shares_needed: u32,
        params: NoiseFloodParameters,
    ) -> Self {
        Client {
            rng: Box::new(AesRng::from_entropy()),
            server_pks,
            client_pk,
            client_sk,
            shares_needed,
            params,
            seq_no: 0,
        }
    }

    /// Verify the signature received from the server on keys or other data objects.
    #[cfg(feature = "non-wasm")]
    pub fn verify_server_signature<T: serde::Serialize + AsRef<[u8]>>(
        &self,
        data: &T,
        signature: &[u8],
    ) -> bool {
        let signature_struct: Signature = match bincode::deserialize(signature) {
            Ok(signature_struct) => signature_struct,
            Err(_) => {
                tracing::warn!("Could not deserialize signature");
                return false;
            }
        };
        let mut res = false;
        for verf_key in self.server_pks.iter() {
            res = res || BaseKmsStruct::verify_sig(&data, &signature_struct, verf_key);
        }
        res
    }

    #[cfg(feature = "non-wasm")]
    pub fn key_gen_request(
        &mut self,
        key_handle: &str,
        param: Option<ParamChoice>,
    ) -> anyhow::Result<KeyGenRequest> {
        let parsed_param: i32 = match param {
            Some(parsed_param) => parsed_param.into(),
            None => ParamChoice::Default.into(),
        };
        // TODO generate handle from request data
        self.seq_no += 1;
        Ok(KeyGenRequest {
            params: parsed_param,
            config: None,
            seq_no: self.seq_no,
            request_id: Some(RequestId::new(
                &key_handle.to_string(),
                KEY_GEN_REQUEST_NAME.to_string(),
            )?),
        })
    }

    #[cfg(feature = "non-wasm")]
    pub fn crs_gen_request(
        &self,
        crs_handle: &str,
        param: Option<ParamChoice>,
    ) -> anyhow::Result<CrsGenRequest> {
        use crate::rpc::rpc_types::CRS_GEN_REQUEST_NAME;

        let parsed_param: i32 = match param {
            Some(parsed_param) => parsed_param.into(),
            None => ParamChoice::Default.into(),
        };
        Ok(CrsGenRequest {
            params: parsed_param,
            config: None,
            request_id: Some(RequestId::new(
                &crs_handle.to_string(),
                CRS_GEN_REQUEST_NAME.to_string(),
            )?),
        })
    }

    #[cfg(feature = "non-wasm")]
    pub fn get_crs_request(&self, request_id: &str) -> anyhow::Result<RequestId> {
        Ok(RequestId {
            request_id: request_id.to_string(),
        })
    }

    /// Creates a decryption request to send to the KMS servers.
    #[cfg(feature = "non-wasm")]
    pub fn decryption_request(
        &mut self,
        ct: Vec<u8>,
        fhe_type: FheType,
        key_id: Option<String>,
    ) -> anyhow::Result<DecryptionRequest> {
        // Observe that this randomness can be reused across the servers since each server will have
        // a unique PK that is included in their response, hence it will still be validated
        // that each request contains a unique message to be signed hence ensuring CCA
        // security. TODO this argument should be validated
        let mut randomness: Vec<u8> = Vec::with_capacity(RND_SIZE);
        let key_id = key_id.unwrap_or(TEST_KEY_ID.to_string());
        self.rng.fill_bytes(&mut randomness);
        let serialized_req = DecryptionRequestSerializable {
            version: CURRENT_FORMAT_VERSION,
            servers_needed: self.shares_needed,
            fhe_type,
            ciphertext: ct,
            randomness,
            key_id,
        };
        Ok(serialized_req.into())
    }

    /// Creates a reencryption request to send to the KMS servers. This generates
    /// an ephemeral reencryption key pair, signature payload containing the ciphertext,
    /// required number of shares, and other metadata. It signs this payload with
    /// the users's wallet private key. Returns the full ReencryptionRequest containing
    /// the signed payload to send to the servers, along with the generated
    /// reencryption key pair.
    pub fn reencyption_request(
        &mut self,
        ct: Vec<u8>,
        domain: &Eip712Domain,
        fhe_type: FheType,
        key_id: Option<String>,
    ) -> anyhow::Result<(ReencryptionRequest, PublicEncKey, PrivateEncKey)> {
        let (enc_pk, enc_sk) = encryption_key_generation(&mut self.rng);
        let mut randomness = Vec::with_capacity(RND_SIZE);
        let key_id = key_id.unwrap_or(TEST_KEY_ID.to_string());
        self.rng.fill_bytes(&mut randomness);
        let sig_payload = ReencryptionRequestSigPayload {
            version: CURRENT_FORMAT_VERSION,
            servers_needed: self.shares_needed,
            enc_key: to_vec(&enc_pk)?,
            verification_key: to_vec(&self.client_pk)?,
            fhe_type: fhe_type as u8,
            ciphertext: ct,
            randomness,
            key_id,
        };
        let sig = match &self.client_sk {
            Some(sk) => sign_eip712(&sig_payload, domain, sk)?,
            None => return Err(anyhow_error_and_log("client signing key is None")),
        };
        let domain_msg = allow_to_protobuf_domain(domain)?;
        Ok((
            ReencryptionRequest {
                signature: to_vec(&sig)?,
                payload: Some(sig_payload.into()),
                domain: Some(domain_msg),
            },
            enc_pk,
            enc_sk,
        ))
    }

    // TODO do we need to linking to request?
    #[cfg(feature = "non-wasm")]
    pub fn process_get_key_gen_resp<R: PublicStorageReader>(
        &self,
        resp: KeyGenResult,
        storage: &R,
    ) -> anyhow::Result<(FhePublicKey, ServerKey)> {
        let pk: FhePublicKey = some_or_err(
            self.retrieve_key(&resp, PubDataType::PublicKey, storage)?,
            "Could not validate public key".to_string(),
        )?;
        let server_key: ServerKey =
            match self.retrieve_key(&resp, PubDataType::ServerKey, storage)? {
                Some(server_key) => server_key,
                None => {
                    return Err(anyhow_error_and_log("Could not validate server key"));
                }
            };
        Ok((pk, server_key))
    }

    /// Retrieve and validate a public key based on the result from a server.
    /// The method will return the key if retrieval and validation is successful,
    /// but will return None in case the signature is invalid or does not match the actual key handle.
    #[cfg(feature = "non-wasm")]
    pub fn retrieve_key<S: serde::Serialize + DeserializeOwned, R: PublicStorageReader>(
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
        let url = storage.compute_url(request_id, pki, key_type)?;
        let key: S = storage.read_data(url)?;
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
    pub fn process_get_crs_resp<R: PublicStorageReader>(
        &self,
        resp: CrsGenResult,
        storage: &R,
    ) -> anyhow::Result<PublicParameter> {
        let crs: PublicParameter = some_or_err(
            self.retrieve_crs(&resp, storage)?,
            "Could not validate CRS".to_string(),
        )?;
        Ok(crs)
    }

    /// Retrieve and validate a public key based on the result from a server.
    /// The method will return the key if retrieval and validation is successful,
    /// but will return None in case the signature is invalid or does not match the actual key handle.
    #[cfg(feature = "non-wasm")]
    pub fn retrieve_crs<R: PublicStorageReader>(
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
        let url = storage.compute_url(request_id, &crs_info, PubDataType::CRS)?;
        let crs: PublicParameter = storage.read_data(url)?;
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
        agg_resp: AggregatedDecryptionResponse,
    ) -> anyhow::Result<Option<Plaintext>> {
        if !self.validate_decryption_resp(request, &agg_resp)? {
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
            let sig_payload: DecryptionResponseSigPayload = cur_payload.into();
            // Observe that it has already been verified in [validate_meta_data] that server
            // verification key is in the set of permissble keys
            let cur_verf_key: PublicSigKey = from_bytes(&sig_payload.verification_key)?;
            if !BaseKmsStruct::verify_sig(&to_vec(&sig_payload)?, &sig, &cur_verf_key) {
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
        agg_resp: AggregatedReencryptionResponse,
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
        // Execute simplified and faster flow for the centralized case
        // Observe that we don't encode exactly the same in the centralized case and in the
        // distributed case. For the centralized case we directly encode the [Plaintext]
        // object whereas for the distributed we encode the plain text as a
        // Vec<ResiduePoly<Z128>>
        if agg_resp.responses.len() <= 1 {
            self.centralized_reencryption_resp(&agg_resp, &client_keys)
        } else {
            self.distributed_reencryption_resp(request, &agg_resp, &client_keys)
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
            let sig_payload: DecryptionResponseSigPayload = cur_payload.clone().into();
            // Validate the signature on the response
            // Observe that it has already been verified in [validate_meta_data] that server
            // verification key is in the set of permissble keys
            let cur_verf_key: PublicSigKey = from_bytes(&sig_payload.verification_key)?;
            if !BaseKmsStruct::verify_sig(&to_vec(&sig_payload)?, &sig, &cur_verf_key) {
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
    fn validate_reencryption_resp(
        &self,
        request: Option<ReencryptionRequest>,
        agg_resp: &AggregatedReencryptionResponse,
    ) -> anyhow::Result<
        Option<(
            ReencryptionRequestPayload,
            HashMap<u32, ReencryptionResponse>,
        )>,
    > {
        match request {
            Some(req) => match req.payload {
                Some(req_payload) => {
                    let resp_parsed = some_or_err(
                        self.validate_individual_reenc_resp(req_payload.servers_needed, agg_resp)?,
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
                    let sig_payload: ReencryptionRequestSigPayload = req_payload.try_into()?;
                    let domain = protobuf_to_alloy_domain(&some_or_err(
                        req.domain,
                        "domain not found".to_string(),
                    )?)?;
                    let req_digest = sig_payload.eip712_signing_hash(&domain).to_vec();
                    if req_digest != pivot_resp.digest {
                        tracing::warn!(
                            "The reencryption response is not linked to the correct request"
                        );
                        return Ok(None);
                    }
                    Ok(Some((sig_payload.into(), resp_parsed)))
                }
                None => {
                    tracing::warn!("No payload in the reencryption request!");
                    Ok(None)
                }
            },
            None => {
                tracing::warn!("No reencryption request!");
                Ok(None)
            }
        }
    }

    fn validate_individual_reenc_resp(
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
        agg_resp: &AggregatedReencryptionResponse,
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Option<Plaintext>> {
        let resp = some_or_err(
            agg_resp.responses.values().last(),
            "Response does not exist".to_owned(),
        )?;
        let cur_verf_key: PublicSigKey = from_bytes(&resp.verification_key)?;
        match decrypt_signcryption(
            &resp.signcrypted_ciphertext,
            &resp.digest,
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
        request: Option<ReencryptionRequest>,
        agg_resp: &AggregatedReencryptionResponse,
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Option<Plaintext>> {
        let (req_payload, validated_resps) = some_or_err(
            self.validate_reencryption_resp(request, agg_resp)?,
            "Could not validate request".to_owned(),
        )?;
        let sharings =
            self.recover_sharings(validated_resps, req_payload.fhe_type(), client_keys)?;
        let amount_shares = sharings.len();
        let mut decrypted_blocks = Vec::new();
        for cur_block_shares in sharings {
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

#[cfg(test)]
pub(crate) mod tests {
    use super::Client;
    #[cfg(feature = "wasm_tests")]
    use crate::client::TestingReencryptionTranscript;
    use crate::consts::{
        AMOUNT_PARTIES, BASE_PORT, DEFAULT_PROT, DEFAULT_URL, KEY_PATH_PREFIX,
        TEST_CENTRAL_CRS_PATH, TEST_CENTRAL_CT_PATH, TEST_CENTRAL_KEYS_PATH, TEST_FHE_TYPE,
        TEST_MSG, TEST_PARAM_PATH, TEST_THRESHOLD_CT_PATH, TEST_THRESHOLD_KEYS_PATH, THRESHOLD,
    };
    #[cfg(feature = "slow_tests")]
    use crate::consts::{
        DEFAULT_CENTRAL_CRS_PATH, DEFAULT_CENTRAL_CT_PATH, DEFAULT_CENTRAL_KEYS_PATH,
        DEFAULT_THRESHOLD_CT_PATH, DEFAULT_THRESHOLD_KEYS_PATH,
    };
    #[cfg(feature = "wasm_tests")]
    use crate::consts::{TEST_CENTRAL_WASM_TRANSCRIPT_PATH, TEST_THRESHOLD_WASM_TRANSCRIPT_PATH};
    use crate::cryptography::central_kms::{
        compute_handle, BaseKmsStruct, CrsHashMap, SoftwareKmsKeys,
    };
    use crate::cryptography::der_types::Signature;
    use crate::kms::coordinator_endpoint_client::CoordinatorEndpointClient;
    use crate::kms::RequestId;
    use crate::kms::{
        AggregatedDecryptionResponse, AggregatedReencryptionResponse, FheType, ParamChoice,
    };
    use crate::rpc::central_rpc::server_handle;
    use crate::rpc::rpc_types::BaseKms;
    use crate::storage::PublicStorageReader;
    use crate::threshold::threshold_kms::{threshold_server_init, threshold_server_start};
    #[cfg(feature = "wasm_tests")]
    use crate::util::file_handling::write_element;
    use crate::util::file_handling::{read_as_json, read_element, read_element_async};
    use crate::util::key_setup::{CentralizedTestingKeys, ThresholdTestingKeys};
    use crate::util::key_setup::{CrsHandleStore, FhePublicKey};
    use crate::{client::num_blocks, rpc::rpc_types::PubDataType};
    use crate::{kms::Empty, storage::DevStorage};
    use alloy_sol_types::Eip712Domain;
    use distributed_decryption::execution::tfhe_internals::parameters::NoiseFloodParameters;
    use distributed_decryption::execution::zk::ceremony::PublicParameter;
    use serial_test::serial;
    use std::collections::{HashMap, HashSet};
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::{env, fs};
    use tokio::task::{JoinHandle, JoinSet};
    use tonic::transport::{Channel, Uri};

    async fn setup(
        kms_keys: SoftwareKmsKeys,
        crs_store: Option<CrsHashMap>,
    ) -> (JoinHandle<()>, CoordinatorEndpointClient<Channel>) {
        let server_handle = tokio::spawn(async move {
            let url = format!("{DEFAULT_URL}:{}", BASE_PORT + 1);
            let add = SocketAddr::from_str(url.as_str()).unwrap();
            let _ = server_handle(add, kms_keys, crs_store).await;
        });
        // We have to wait for the server to start since it will keep running in the background
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let url = format!("{DEFAULT_PROT}://{DEFAULT_URL}:{}", BASE_PORT + 1);
        let uri = Uri::from_str(&url).unwrap();
        let channel = Channel::builder(uri).connect().await.unwrap();
        let client = CoordinatorEndpointClient::new(channel);
        (server_handle, client)
    }

    /// Read the centralized keys for testing from `centralized_key_path` and construct a KMS
    /// server, client end-point connection (which is needed to communicate with the server) and
    /// an internal client (for constructing requests and validating responses).
    async fn centralized_handles(
        centralized_key_path: &str,
        centralized_crs_path: Option<&str>,
    ) -> (JoinHandle<()>, CoordinatorEndpointClient<Channel>, Client) {
        let keys: CentralizedTestingKeys = read_element(centralized_key_path).unwrap();

        // set crs_store if path is provided, else set it to None
        let crs_info = centralized_crs_path
            .map(|crs_path| read_element::<CrsHandleStore>(crs_path).unwrap())
            .map(|ccc| ccc.crs_info);

        let (kms_server, kms_client) = setup(keys.software_kms_keys, crs_info).await;
        let internal_client = Client::new(
            HashSet::from_iter(keys.server_keys.iter().cloned()),
            keys.client_pk,
            Some(keys.client_sk),
            1,
            keys.params,
        );
        (kms_server, kms_client, internal_client)
    }

    async fn setup_threshold(
        amount: usize,
        threshold: u8,
        threshold_key_path_prefix: &str,
    ) -> (
        HashMap<u32, JoinHandle<()>>,
        HashMap<u32, CoordinatorEndpointClient<Channel>>,
    ) {
        let mut handles = Vec::new();
        tracing::info!("Spawning servers...");
        for i in 1..=amount {
            let key_path = format!("{threshold_key_path_prefix}-{i}.bin");
            handles.push(tokio::spawn(async move {
                tracing::info!("Server {i} reading keys..");
                let keys: ThresholdTestingKeys =
                    read_element_async(key_path.to_string()).await.unwrap();
                tracing::info!("Server {i} read keys..");
                let server = threshold_server_init(
                    DEFAULT_URL.to_owned(),
                    BASE_PORT,
                    amount,
                    threshold,
                    i,
                    keys.kms_keys,
                )
                .await;
                (i, server)
            }));
        }
        // Wait for the server to start
        tracing::info!("Client waiting for server");
        let mut servers = Vec::with_capacity(amount);
        for cur_handle in handles {
            let (i, kms_server_res) = cur_handle.await.unwrap();
            match kms_server_res {
                Ok(kms_server) => servers.push((i, kms_server)),
                Err(e) => tracing::warn!("Failed to start server {i} with error {:?}", e),
            }
        }
        tracing::info!("Servers initialized. Starting servers...");
        let mut server_handles = HashMap::new();
        for (i, cur_server) in servers {
            let handle = tokio::spawn(async move {
                let _ =
                    threshold_server_start(DEFAULT_URL.to_owned(), BASE_PORT, i, cur_server).await;
            });
            server_handles.insert(i as u32, handle);
        }
        // We need to sleep as the servers keep running in the background and hence do not return
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let mut client_handles = HashMap::new();
        for i in 1..=amount {
            let port = BASE_PORT + i as u16;
            let url = format!("{DEFAULT_PROT}://{DEFAULT_URL}:{port}");
            let uri = Uri::from_str(&url).unwrap();
            let channel = Channel::builder(uri).connect().await.unwrap();
            client_handles.insert(i as u32, CoordinatorEndpointClient::new(channel));
        }
        tracing::info!("Client connected to servers");
        (server_handles, client_handles)
    }

    /// Reads the testing keys for the threshold servers and starts them up, and returns a hash map
    /// of the servers, based on their ID, which starts from 1. A smiliar map is also returned
    /// is the client endpoints needed to talk with each of the servers, finally the internal
    /// client is returned (which is responsible for constructing requests and validating
    /// responses).
    async fn threshold_handles(
        threshold_key_path: &str,
    ) -> (
        HashMap<u32, JoinHandle<()>>,
        HashMap<u32, CoordinatorEndpointClient<Channel>>,
        Client,
    ) {
        let (kms_servers, kms_clients) =
            setup_threshold(AMOUNT_PARTIES, THRESHOLD as u8, threshold_key_path).await;
        let keys: ThresholdTestingKeys = read_element_async(format!("{threshold_key_path}-1.bin"))
            .await
            .unwrap();
        let server_keys: Vec<_> = keys.server_keys.to_vec();
        let internal_client = Client::new(
            HashSet::from_iter(server_keys.into_iter()),
            keys.client_pk,
            Some(keys.client_sk),
            (THRESHOLD as u32) + 1,
            keys.params.to_noiseflood_parameters(),
        );

        (kms_servers, kms_clients, internal_client)
    }

    #[tokio::test]
    #[serial]
    async fn test_key_gen_centralized() {
        key_gen_centralized(
            TEST_CENTRAL_KEYS_PATH,
            "someHandle",
            Some(ParamChoice::Test),
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial]
    async fn default_key_gen_centralized() {
        key_gen_centralized(DEFAULT_CENTRAL_KEYS_PATH, "someHandle", None).await;
    }

    async fn key_gen_centralized(
        centralized_key_path: &str,
        key_handle: &str,
        params: Option<ParamChoice>,
    ) {
        let (kms_server, mut kms_client, mut internal_client) =
            centralized_handles(centralized_key_path, None).await;
        // Remove exisiting keys to make the test idempotent
        let storage = DevStorage::default();
        let _ = fs::remove_dir_all(storage.root_dir());

        let gen_req = internal_client.key_gen_request(key_handle, params).unwrap();
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
        while response.is_err() {
            // Sleep to give the server some time to complete key generation
            std::thread::sleep(std::time::Duration::from_millis(100));
            response = kms_client
                .get_key_gen_result(tonic::Request::new(req_id.clone()))
                .await;
        }
        let inner_resp = response.unwrap().into_inner();
        let pk: Option<FhePublicKey> = internal_client
            .retrieve_key(&inner_resp, PubDataType::PublicKey, &storage)
            .unwrap();
        assert!(pk.is_some());
        let server_key: Option<tfhe::ServerKey> = internal_client
            .retrieve_key(&inner_resp, PubDataType::ServerKey, &storage)
            .unwrap();
        assert!(server_key.is_some());
        kms_server.abort();
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial]
    async fn default_crs_gen_centralized() {
        crs_gen_centralized_client(
            DEFAULT_CENTRAL_CRS_PATH,
            DEFAULT_CENTRAL_KEYS_PATH,
            "default_crs_test_handle",
            Some(ParamChoice::Default),
        )
        .await;
    }

    #[tokio::test]
    #[serial]
    async fn test_crs_gen_centralized() {
        crs_gen_centralized_manual(
            TEST_CENTRAL_CRS_PATH,
            TEST_CENTRAL_KEYS_PATH,
            "small_crs_test_handle_manual",
            Some(ParamChoice::Test),
        )
        .await;

        crs_gen_centralized_client(
            TEST_CENTRAL_CRS_PATH,
            TEST_CENTRAL_KEYS_PATH,
            "small_crs_test_handle",
            Some(ParamChoice::Test),
        )
        .await;
    }

    /// test centralized crs generation and do all the reading, processing and verification manually
    async fn crs_gen_centralized_manual(
        centralized_crs_path: &str,
        centralized_key_path: &str,
        crs_handle: &str,
        params: Option<ParamChoice>,
    ) {
        let (kms_server, mut kms_client, internal_client) =
            centralized_handles(centralized_key_path, Some(centralized_crs_path)).await;

        let ceremony_req = internal_client.crs_gen_request(crs_handle, params).unwrap();

        // remove existing CRS under that request id to ensure that the test is idempotent
        let client_request_id = ceremony_req.request_id.clone().unwrap();
        let raw_dir = env::current_dir().unwrap();
        let cur_dir = raw_dir.to_str().unwrap();
        let path = format!(
            "{}/{}/dev/{}-{}.key",
            cur_dir,
            KEY_PATH_PREFIX,
            client_request_id,
            PubDataType::CRS
        );
        let _ = fs::remove_file(path);

        // response is currently empty
        let gen_response = kms_client
            .crs_gen(tonic::Request::new(ceremony_req.clone()))
            .await
            .unwrap();
        assert_eq!(gen_response.into_inner(), Empty {});

        // Check that we can retrieve the CRS under that request id
        let get_req = RequestId {
            request_id: client_request_id.to_string(),
        };
        let get_response = kms_client
            .get_crs_gen_result(tonic::Request::new(get_req.clone()))
            .await
            .unwrap();

        let resp = get_response.into_inner();
        let rvcd_req_id = resp.request_id.unwrap();

        // // check that the received request id matches the one we sent in the request
        assert_eq!(rvcd_req_id, client_request_id);

        let crs_info = resp.crs_results.unwrap();

        let storage = DevStorage::default();
        let mut crs_path = storage
            .compute_url(client_request_id, &crs_info, PubDataType::CRS)
            .unwrap()
            .to_string();

        assert!(crs_path.starts_with("file://"));
        crs_path.replace_range(0..7, ""); // remove leading "file:/" from URI, so we can read the file

        // check that CRS signature is verified correctly
        let crs_raw = read_element::<PublicParameter>(&crs_path).unwrap();
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
        centralized_crs_path: &str,
        centralized_key_path: &str,
        crs_handle: &str,
        params: Option<ParamChoice>,
    ) {
        let (kms_server, mut kms_client, internal_client) =
            centralized_handles(centralized_key_path, Some(centralized_crs_path)).await;

        let storage = DevStorage::default();
        let _ = fs::remove_dir_all(storage.root_dir());
        let gen_req = internal_client.crs_gen_request(crs_handle, params).unwrap();

        let req_id = gen_req.request_id.clone().unwrap();

        // response is currently empty
        let gen_response = kms_client
            .crs_gen(tonic::Request::new(gen_req.clone()))
            .await
            .unwrap();
        assert_eq!(gen_response.into_inner(), Empty {});

        let mut response = kms_client
            .get_crs_gen_result(tonic::Request::new(req_id.clone()))
            .await;
        while response.is_err() {
            // Sleep to give the server some time to complete CRS generation
            std::thread::sleep(std::time::Duration::from_millis(200));
            response = kms_client
                .get_crs_gen_result(tonic::Request::new(req_id.clone()))
                .await;
        }
        let inner_resp = response.unwrap().into_inner();
        let storage = DevStorage::default();
        let crs = internal_client.retrieve_crs(&inner_resp, &storage).unwrap();
        assert!(crs.is_some());

        kms_server.abort();
    }

    #[tokio::test]
    #[serial]
    async fn test_decryption_central() {
        decryption_centralized(TEST_CENTRAL_KEYS_PATH, TEST_CENTRAL_CT_PATH).await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial]
    async fn default_decryption_centralized() {
        decryption_centralized(DEFAULT_CENTRAL_KEYS_PATH, DEFAULT_CENTRAL_CT_PATH).await;
    }

    // TODO speed up
    async fn decryption_centralized(centralized_key_path: &str, cipher_path: &str) {
        // TODO refactor with setup and teardown setting up servers that can be used to run tests in
        // parallel
        let (kms_server, mut kms_client, mut internal_client) =
            centralized_handles(centralized_key_path, None).await;
        let (ct, fhe_type): (Vec<u8>, FheType) = read_element(cipher_path).unwrap();

        let req = internal_client
            .decryption_request(ct.clone(), fhe_type, None)
            .unwrap();
        let response = kms_client
            .decrypt(tonic::Request::new(req.clone()))
            .await
            .unwrap();

        let responses = AggregatedDecryptionResponse {
            responses: vec![response.into_inner()],
        };
        let plaintext = internal_client
            .process_decryption_resp(Some(req), responses)
            .unwrap()
            .unwrap();
        assert_eq!(TEST_FHE_TYPE, plaintext.fhe_type());
        assert_eq!(TEST_MSG, plaintext.as_u8());

        kms_server.abort();
    }

    #[tokio::test]
    #[serial]
    async fn test_reencryption_centralized() {
        reencryption_centralized(TEST_CENTRAL_KEYS_PATH, TEST_CENTRAL_CT_PATH, false).await;
    }

    #[cfg(feature = "wasm_tests")]
    #[tokio::test]
    #[serial]
    async fn test_reencryption_centralized_and_write_transcript() {
        reencryption_centralized(TEST_CENTRAL_KEYS_PATH, TEST_CENTRAL_CT_PATH, true).await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test]
    #[serial]
    async fn default_reencryption_centralized() {
        reencryption_centralized(DEFAULT_CENTRAL_KEYS_PATH, DEFAULT_CENTRAL_CT_PATH, false).await;
    }

    fn dummy_domain() -> Eip712Domain {
        alloy_sol_types::eip712_domain!(
            name: "dummy",
            version: "1",
            chain_id: 1,
            verifying_contract: alloy_primitives::Address::ZERO,
        )
    }

    async fn reencryption_centralized(
        centralized_key_path: &str,
        cipher_path: &str,
        write_transcript: bool,
    ) {
        _ = write_transcript;

        let (kms_server, mut kms_client, mut internal_client) =
            centralized_handles(centralized_key_path, None).await;
        let (ct, fhe_type): (Vec<u8>, FheType) = read_element(cipher_path).unwrap();
        let (req, enc_pk, enc_sk) = internal_client
            .reencyption_request(ct, &dummy_domain(), fhe_type, None)
            .unwrap();
        let response = kms_client
            .reencrypt(tonic::Request::new(req.clone()))
            .await
            .unwrap();
        let response = response.into_inner();

        #[cfg(feature = "wasm_tests")]
        {
            if write_transcript {
                let transcript = TestingReencryptionTranscript {
                    server_pks: internal_client.server_pks.clone(),
                    client_pk: internal_client.client_pk.clone(),
                    shares_needed: 0,
                    params: internal_client.params,
                    request: None,
                    eph_sk: enc_sk.clone(),
                    eph_pk: enc_pk.clone(),
                    seq_no: internal_client.seq_no,
                    agg_resp: HashMap::from([(1, response.clone())]),
                };
                write_element(TEST_CENTRAL_WASM_TRANSCRIPT_PATH.to_string(), &transcript).unwrap();
            }
        }

        let responses = AggregatedReencryptionResponse {
            responses: HashMap::from([(1, response)]),
        };
        let plaintext = internal_client
            .process_reencryption_resp(Some(req), responses, &enc_pk, &enc_sk)
            .unwrap()
            .unwrap();
        assert_eq!(TEST_FHE_TYPE, plaintext.fhe_type());
        assert_eq!(TEST_MSG, plaintext.as_u8());

        kms_server.abort();
    }

    #[tokio::test]
    #[serial]
    async fn test_decryption_threshold() {
        decryption_threshold(TEST_THRESHOLD_KEYS_PATH, TEST_THRESHOLD_CT_PATH).await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn default_decryption_threshold() {
        decryption_threshold(DEFAULT_THRESHOLD_KEYS_PATH, DEFAULT_THRESHOLD_CT_PATH).await;
    }

    async fn decryption_threshold(threshold_key_path: &str, cipher_path: &str) {
        let (kms_servers, kms_clients, mut internal_client) =
            threshold_handles(threshold_key_path).await;
        let (ct, fhe_type): (Vec<u8>, FheType) =
            read_element_async(cipher_path.to_string()).await.unwrap();

        let req = internal_client
            .decryption_request(ct, fhe_type, None)
            .unwrap();
        let mut tasks = JoinSet::new();
        for i in 1..=AMOUNT_PARTIES as u32 {
            let mut cur_client = kms_clients.get(&i).unwrap().clone();
            let req_clone = req.clone();
            tasks.spawn(async move { cur_client.decrypt(tonic::Request::new(req_clone)).await });
        }
        let mut response_vec = Vec::new();
        while let Some(Ok(Ok(resp))) = tasks.join_next().await {
            response_vec.push(resp.into_inner());
        }
        let agg = AggregatedDecryptionResponse {
            responses: response_vec,
        };
        let plaintext = internal_client
            .process_decryption_resp(Some(req), agg)
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
        reencryption_threshold(TEST_THRESHOLD_KEYS_PATH, TEST_THRESHOLD_CT_PATH, false).await;
    }

    #[tokio::test]
    #[serial]
    #[cfg(feature = "wasm_tests")]
    async fn test_reencryption_threshold_and_write_transcript() {
        reencryption_threshold(TEST_THRESHOLD_KEYS_PATH, TEST_THRESHOLD_CT_PATH, true).await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn default_reencryption_threshold() {
        reencryption_threshold(
            DEFAULT_THRESHOLD_KEYS_PATH,
            DEFAULT_THRESHOLD_CT_PATH,
            false,
        )
        .await;
    }

    async fn reencryption_threshold(
        threshold_key_path: &str,
        cipher_path: &str,
        write_transcript: bool,
    ) {
        _ = write_transcript;

        let (kms_servers, kms_clients, mut internal_client) =
            threshold_handles(threshold_key_path).await;
        let (ct, fhe_type): (Vec<u8>, FheType) =
            read_element_async(cipher_path.to_string()).await.unwrap();

        let (req, enc_pk, enc_sk) = internal_client
            .reencyption_request(ct, &dummy_domain(), fhe_type, None)
            .unwrap();
        let mut tasks = JoinSet::new();
        tracing::info!("Client did reencryption request");
        for i in 1..=AMOUNT_PARTIES as u32 {
            let mut cur_client = kms_clients.get(&i).unwrap().clone();
            let req_clone = req.clone();
            tasks.spawn(async move {
                (
                    i,
                    cur_client.reencrypt(tonic::Request::new(req_clone)).await,
                )
            });
        }
        tracing::info!("Client issued reencrypt queries");
        let mut response_map = HashMap::new();
        while let Some(Ok(res)) = tasks.join_next().await {
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
                    seq_no: internal_client.seq_no,
                    agg_resp: response_map.clone(),
                };
                write_element(TEST_THRESHOLD_WASM_TRANSCRIPT_PATH.to_string(), &transcript)
                    .unwrap();
            }
        }

        let agg = AggregatedReencryptionResponse {
            responses: response_map,
        };
        let plaintext = internal_client
            .process_reencryption_resp(Some(req), agg, &enc_pk, &enc_sk)
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
        let keys: CentralizedTestingKeys = read_element(DEFAULT_CENTRAL_KEYS_PATH).unwrap();
        let (kms_server, mut kms_client) = setup(keys.software_kms_keys, None).await;
        let ct = Vec::from([1_u8; 1000000]);
        let fhe_type = FheType::Euint32;
        let mut internal_client = Client::new(
            HashSet::from_iter(keys.server_keys.iter().cloned()),
            keys.client_pk,
            Some(keys.client_sk),
            1,
            keys.params,
        );

        let (req, _enc_pk, _enc_sk) = internal_client
            .reencyption_request(ct, &dummy_domain(), fhe_type, None)
            .unwrap();
        let response = kms_client.reencrypt(tonic::Request::new(req.clone())).await;
        assert!(response.is_err());
        assert!(response
            .err()
            .unwrap()
            .message()
            .contains("Internal server error"));
        kms_server.abort();
    }

    #[test]
    fn num_blocks_sunshine() {
        let params: NoiseFloodParameters = read_as_json(TEST_PARAM_PATH.to_owned()).unwrap();
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
}

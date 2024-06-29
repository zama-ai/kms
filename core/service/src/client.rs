use crate::cryptography::der_types::{
    PrivateEncKey, PrivateSigKey, PublicEncKey, PublicSigKey, SigncryptionPair,
    SigncryptionPrivKey, SigncryptionPubKey,
};
use crate::cryptography::signcryption::{
    decrypt_signcryption, encryption_key_generation, hash_element,
    insecure_decrypt_ignoring_signature, Reencrypt, RND_SIZE,
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
use alloy_primitives::Bytes;
use alloy_signer::SignerSync;
use alloy_sol_types::Eip712Domain;
use alloy_sol_types::SolStruct;
use bincode::{deserialize, serialize};
use distributed_decryption::algebra::base_ring::Z128;
use distributed_decryption::algebra::residue_poly::ResiduePoly;
use distributed_decryption::execution::endpoints::reconstruct::{
    combine_decryptions, reconstruct_message,
};
use distributed_decryption::execution::runtime::party::Role;
use distributed_decryption::execution::sharing::shamir::{
    fill_indexed_shares, reconstruct_w_errors_sync, ShamirSharings,
};
use distributed_decryption::execution::tfhe_internals::parameters::AugmentedCiphertextParameters;
use itertools::Itertools;
use rand::{RngCore, SeedableRng};
use std::collections::HashMap;
use tfhe::shortint::ClassicPBSParameters;
use wasm_bindgen::prelude::*;

cfg_if::cfg_if! {
    if #[cfg(feature = "non-wasm")] {
        use crate::cryptography::{central_kms::compute_handle, der_types::Signature};
        use crate::kms::ParamChoice;
        use crate::kms::{
            AggregatedDecryptionResponse, CrsGenRequest, CrsGenResult, DecryptionRequest,
            DecryptionResponsePayload, KeyGenPreprocRequest, KeyGenRequest, KeyGenResult,
        };
        use crate::rpc::rpc_types::{DecryptionRequestSerializable, PubDataType};
        use crate::storage::read_all_data;
        use crate::storage::Storage;
        use crate::util::file_handling::read_as_json;
        use crate::{cryptography::central_kms::BaseKmsStruct, rpc::rpc_types::BaseKms};
        use crate::{storage::StorageReader, util::key_setup::FhePublicKey};
        use anyhow::ensure;
        use distributed_decryption::execution::zk::ceremony::PublicParameter;
        use serde::de::DeserializeOwned;
        use std::fmt;
        use tfhe::ServerKey;
    }
}

/// Helper method for combining reconstructed messages after decryption.
// TODO is this the right place for this function? Should probably be in ddec. Related to this issue https://github.com/zama-ai/distributed-decryption/issues/352
fn decrypted_blocks_to_plaintext(
    params: &ClassicPBSParameters,
    fhe_type: FheType,
    recon_blocks: Vec<Z128>,
) -> anyhow::Result<Plaintext> {
    let bits_in_block = params.message_modulus_log();
    let res_pt = match fhe_type {
        FheType::Euint2048 => {
            combine_decryptions::<tfhe::integer::bigint::U2048>(bits_in_block, recon_blocks)
                .map(Plaintext::from_u2048)
        }
        FheType::Euint1024 => {
            todo!("Implement Euint1024")
        }
        FheType::Euint512 => {
            todo!("Implement Euint512")
        }
        FheType::Euint256 => {
            combine_decryptions::<tfhe::integer::U256>(bits_in_block, recon_blocks)
                .map(Plaintext::from_u256)
        }
        FheType::Euint160 => {
            combine_decryptions::<tfhe::integer::U256>(bits_in_block, recon_blocks)
                .map(Plaintext::from_u160)
        }
        FheType::Euint128 => combine_decryptions::<u128>(bits_in_block, recon_blocks)
            .map(|x| Plaintext::new(x, fhe_type)),
        FheType::Ebool
        | FheType::Euint4
        | FheType::Euint8
        | FheType::Euint16
        | FheType::Euint32
        | FheType::Euint64 => combine_decryptions::<u64>(bits_in_block, recon_blocks)
            .map(|x| Plaintext::new(x as u128, fhe_type)),
    };
    res_pt.map_err(|error| anyhow_error_and_log(format!("Panicked in combining {error}")))
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
    server_pks: HashMap<PublicSigKey, u8>,
    client_pk: PublicSigKey,
    client_sk: Option<PrivateSigKey>,
    shares_needed: u32,
    // we allow it because num_servers is used in only certain features
    #[allow(dead_code)]
    num_servers: u32,
    params: ClassicPBSParameters,
}

// This testing struct needs to be outside of js_api module
// since it is needed in the tests to generate the right files for js/wasm tests.
#[cfg(feature = "wasm_tests")]
#[wasm_bindgen]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct TestingReencryptionTranscript {
    // client
    server_pks: HashMap<PublicSigKey, u8>,
    client_pk: PublicSigKey,
    client_sk: Option<PrivateSigKey>,
    shares_needed: u32,
    params: ClassicPBSParameters,
    // example pt and ct
    fhe_type: FheType,
    pt: Vec<u8>,
    ct: Vec<u8>,
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
/// Care must be taken when new code is introduced to the core/service
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
    use crate::kms::ParamChoice;
    use crypto_box::aead::{Aead, AeadCore};
    use crypto_box::{Nonce, SalsaBox};
    use distributed_decryption::execution::tfhe_internals::parameters::NoiseFloodParameters;

    use super::*;

    #[wasm_bindgen]
    pub fn public_sig_key_to_u8vec(pk: &PublicSigKey) -> Vec<u8> {
        pk.pk.to_sec1_bytes().to_vec()
    }

    #[wasm_bindgen]
    pub fn u8vec_to_public_sig_key(v: &[u8]) -> Result<PublicSigKey, JsError> {
        Ok(PublicSigKey {
            pk: k256::ecdsa::VerifyingKey::from_sec1_bytes(v)
                .map_err(|e| JsError::new(&e.to_string()))?,
        })
    }

    #[wasm_bindgen]
    pub fn private_sig_key_to_u8vec(sk: &PrivateSigKey) -> Result<Vec<u8>, JsError> {
        serialize(sk).map_err(|e| JsError::new(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn u8vec_to_private_sig_key(v: &[u8]) -> Result<PrivateSigKey, JsError> {
        deserialize(v).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Instantiate a new client for use with the centralized KMS.
    #[wasm_bindgen]
    pub fn default_client_for_centralized_kms() -> Result<Client, JsError> {
        console_error_panic_hook::set_once();
        // TODO: we're just using a dummy public key here
        // since it should not be used by wasm at the moment
        // when using the insecure way of doing reconstruction
        let clinet_pk_buf = vec![
            2u8, 190, 131, 237, 176, 0, 13, 171, 152, 220, 41, 77, 205, 59, 208, 48, 37, 75, 0,
            159, 68, 39, 28, 30, 76, 96, 11, 61, 38, 66, 2, 129, 0,
        ];
        let client_pk = u8vec_to_public_sig_key(&clinet_pk_buf)?;
        new_client(vec![], None, client_pk, 1, "default")
    }

    /// Instantiate a new client.
    ///
    /// * `server_pks` - a list of KMS server signature public keys,
    /// which can parsed using [u8vec_to_public_sig_key].
    ///
    /// * `server_pks_ids` - a list of the IDs that are associated to the
    /// server public keys. If None is given, then the IDs default to
    /// 1..n, where n is the length of `server_pks`.
    ///
    /// * `client_pk` - the client (wallet) public key,
    /// which can parsed using [u8vec_to_public_sig_key] also.
    ///
    /// * `shares_needed` - number of shares needed for reconstruction.
    /// In the centralized setting this is 1.
    ///
    /// * `param_choice` - the parameter choice, which can be either `"test"` or `"default"`.
    /// The "default" parameter choice is selected if no matching string is found.
    #[wasm_bindgen]
    pub fn new_client(
        server_pks: Vec<PublicSigKey>,
        server_pks_ids: Option<Vec<u8>>,
        client_pk: PublicSigKey,
        shares_needed: u32,
        param_choice: &str,
    ) -> Result<Client, JsError> {
        console_error_panic_hook::set_once();

        // TODO: we cannot use the consts like TEST_PARAM_PATH
        // here because include_str! only accepts literals.
        let default_params = include_str!("../parameters/default_params.json");
        let test_params = include_str!("../parameters/small_test_params.json");

        let params_json = match ParamChoice::from_str_name(param_choice) {
            Some(choice) => match choice {
                ParamChoice::Default => default_params,
                ParamChoice::Test => test_params,
            },
            None => default_params,
        };
        let params: NoiseFloodParameters =
            serde_json::from_str::<NoiseFloodParameters>(params_json)
                .map_err(|e| JsError::new(&e.to_string()))?;

        let server_pks_ids = match server_pks_ids {
            Some(inner) => inner,
            None => (1..=server_pks.len() as u8).collect_vec(),
        };

        if server_pks.len() != server_pks_ids.len() {
            return Err(JsError::new("server_pks.len() != server_pks_ids.len()"));
        }

        let server_pks = HashMap::from_iter(server_pks.into_iter().zip(server_pks_ids));

        // Note: This may fail if there are multiple possible signing keys for each server
        let num_servers = server_pks.len() as u32;

        Ok(Client {
            rng: Box::new(AesRng::from_entropy()),
            server_pks,
            client_pk,
            client_sk: None,
            shares_needed,
            num_servers,
            params: params.ciphertext_parameters,
        })
    }

    #[wasm_bindgen]
    pub fn get_server_public_keys(client: &Client) -> Vec<PublicSigKey> {
        client.server_pks.keys().cloned().collect()
    }

    #[wasm_bindgen]
    pub fn get_client_public_key(client: &Client) -> PublicSigKey {
        client.client_pk.clone()
    }

    #[wasm_bindgen]
    pub fn get_client_secret_key(client: &Client) -> Option<PrivateSigKey> {
        client.client_sk.clone()
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
    pub fn agg_resp_to_json(agg_resp: Vec<ReencryptionResponse>) -> Result<JsValue, JsError> {
        resp_to_json(agg_resp)
    }

    #[wasm_bindgen]
    #[cfg(feature = "wasm_tests")]
    pub fn centralized_reencryption_response_from_transcript(buf: &[u8]) -> DummyReencResponse {
        let transcript: TestingReencryptionTranscript = bincode::deserialize(buf).unwrap();
        DummyReencResponse {
            req: transcript.request,
            agg_resp: vec![transcript.agg_resp.get(&1).unwrap().clone()],
            agg_resp_ids: vec![1],
            enc_pk: transcript.eph_pk.clone(),
            enc_sk: transcript.eph_sk.clone(),
        }
    }

    #[cfg(feature = "wasm_tests")]
    #[wasm_bindgen(getter_with_clone)]
    pub struct DummyReencRequest {
        pub inner: ReencryptionRequest,
        pub inner_str: String,
        pub enc_pk: PublicEncKey,
        pub enc_sk: PrivateEncKey,
        pub pt: Vec<u8>,
    }

    #[cfg(feature = "wasm_tests")]
    #[wasm_bindgen]
    pub fn centralized_reencryption_request_from_transcript(
        client: &mut Client,
        buf: &[u8],
    ) -> DummyReencRequest {
        reencryption_request_from_transcript(client, buf, &crate::consts::DEFAULT_CENTRAL_KEY_ID)
    }

    #[cfg(feature = "wasm_tests")]
    #[wasm_bindgen]
    pub fn threshold_reencryption_request_from_transcript(
        client: &mut Client,
        buf: &[u8],
    ) -> DummyReencRequest {
        reencryption_request_from_transcript(client, buf, &crate::consts::DEFAULT_THRESHOLD_KEY_ID)
    }

    #[cfg(feature = "wasm_tests")]
    fn reencryption_request_from_transcript(
        client: &mut Client,
        buf: &[u8],
        key_id: &RequestId,
    ) -> DummyReencRequest {
        console_error_panic_hook::set_once();
        let transcript: TestingReencryptionTranscript = bincode::deserialize(buf).unwrap();

        let domain = alloy_sol_types::eip712_domain!(
            name: "Authorization token",
            version: "1",
            chain_id: 8006,
            verifying_contract: alloy_primitives::Address::ZERO,
        );
        let request_id = RequestId::derive("REENC_ID").unwrap();
        let (req, enc_pk, enc_sk) = client
            .reencryption_request(
                transcript.ct.clone(),
                &domain,
                transcript.fhe_type,
                &request_id,
                key_id,
            )
            .unwrap();

        let json = reencryption_request_to_flat_json_string(&req);

        DummyReencRequest {
            inner: req,
            inner_str: json.to_string(),
            enc_pk,
            enc_sk,
            pt: transcript.pt,
        }
    }

    #[wasm_bindgen]
    #[cfg(feature = "wasm_tests")]
    pub fn threshold_reencryption_response_from_transcript(buf: &[u8]) -> DummyReencResponse {
        let transcript: TestingReencryptionTranscript = bincode::deserialize(buf).unwrap();

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
    pub fn client_from_transcript(buf: &[u8]) -> Client {
        console_error_panic_hook::set_once();
        let transcript: TestingReencryptionTranscript = bincode::deserialize(buf).unwrap();
        // Note: This may fail if there are multiple possible signing keys for each server
        let num_servers = transcript.server_pks.len() as u32;
        Client {
            rng: Box::new(AesRng::from_entropy()),
            server_pks: transcript.server_pks,
            client_pk: transcript.client_pk,
            client_sk: transcript.client_sk,
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
        serialize(pk).map_err(|e| JsError::new(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn cryptobox_sk_to_u8vec(sk: &PrivateEncKey) -> Result<Vec<u8>, JsError> {
        serialize(sk).map_err(|e| JsError::new(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn u8vec_to_cryptobox_pk(v: &[u8]) -> Result<PublicEncKey, JsError> {
        deserialize(v).map_err(|e| JsError::new(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn u8vec_to_cryptobox_sk(v: &[u8]) -> Result<PrivateEncKey, JsError> {
        deserialize(v).map_err(|e| JsError::new(&e.to_string()))
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

    #[wasm_bindgen]
    pub fn new_eip712_domain(
        name: String,
        version: String,
        chain_id: Vec<u8>,
        verifying_contract: String,
        salt: Vec<u8>,
    ) -> Eip712DomainMsg {
        Eip712DomainMsg {
            name,
            version,
            chain_id,
            verifying_contract,
            salt,
        }
    }

    #[wasm_bindgen]
    pub fn new_request_id(request_id: String) -> RequestId {
        RequestId { request_id }
    }

    #[wasm_bindgen]
    pub fn new_fhe_type(mut type_str: String) -> Result<FheType, JsError> {
        make_ascii_titlecase(&mut type_str);
        let out = FheType::from_str_name(&type_str).ok_or(JsError::new("invalid fhe type"))?;
        Ok(out)
    }

    /// This function assembles a reencryption request
    /// from a signature and other metadata.
    /// The signature is on the ephemeral public key
    /// signed by the client's private key
    /// following the EIP712 standard.
    ///
    /// The result value needs to convert to the following JSON
    /// for the gateway.
    /// ```
    /// { "signature": "010203",                  // HEX
    ///   "verification_key": "010203",           // HEX
    ///   "enc_key": "010203",                    // HEX
    ///   "ciphertext_digest": "010203",          // HEX
    ///   "eip712_verifying_contract": "0x1234",  // String
    /// }
    /// ```
    /// This can be done using [reencryption_request_to_flat_json_string].
    #[wasm_bindgen]
    pub fn make_reencryption_req(
        client: &mut Client,
        signature: Vec<u8>,
        enc_pk: PublicEncKey,
        fhe_type: FheType,
        key_id: RequestId,
        ciphertext: Option<Vec<u8>>,
        ciphertext_digest: Vec<u8>,
        domain: Eip712DomainMsg,
    ) -> Result<ReencryptionRequest, JsError> {
        let mut randomness: Vec<u8> = vec![0; RND_SIZE];
        client.rng.fill_bytes(&mut randomness);
        let payload = ReencryptionRequestPayload {
            version: CURRENT_FORMAT_VERSION,
            randomness,
            servers_needed: client.shares_needed,
            enc_key: serialize(&enc_pk)?,
            verification_key: serialize(&client.client_pk)?,
            fhe_type: fhe_type as i32,
            key_id: Some(key_id),
            ciphertext,
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

    #[wasm_bindgen]
    pub fn reencryption_request_to_flat_json_string(req: &ReencryptionRequest) -> String {
        let domain = req.domain.as_ref().unwrap();
        let mut json = serde_json::json!(
        {
            "signature": hex::encode(&req.signature),
            "verification_key": hex::encode(&req.payload.as_ref().unwrap().verification_key),
            "enc_key": hex::encode(&req.payload.as_ref().unwrap().enc_key),
            "ciphertext_digest": hex::encode(&req.payload.as_ref().unwrap().ciphertext_digest),
            "eip712_verifying_contract": domain.verifying_contract,
        });

        // optionally include the full ciphertext for testing
        let ciphertext = req.payload.as_ref().unwrap().ciphertext.clone();
        if let Some(ct) = ciphertext {
            json.as_object_mut().unwrap().insert(
                "ciphertext".to_string(),
                serde_json::Value::String(hex::encode(ct)),
            );
        }
        json.to_string()
    }

    fn make_ascii_titlecase(s: &mut str) {
        if let Some(r) = s.get_mut(0..1) {
            r.make_ascii_uppercase();
        }
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    struct ReencryptionResponseHex {
        version: u32,
        servers_needed: u32,
        verification_key: String,
        digest: String,
        fhe_type: String, // this is euint8, for example
        signcrypted_ciphertext: String,
    }

    #[cfg(feature = "wasm_tests")]
    fn resp_to_json(agg_resp: Vec<ReencryptionResponse>) -> Result<JsValue, JsError> {
        let mut out = vec![];
        for resp in agg_resp {
            let r = ReencryptionResponseHex {
                version: resp.version,
                servers_needed: resp.servers_needed,
                verification_key: hex::encode(&resp.verification_key),
                digest: hex::encode(&resp.digest),
                fhe_type: "unimplemented".to_string(),
                signcrypted_ciphertext: hex::encode(&resp.signcrypted_ciphertext),
            };
            out.push(r);
        }

        let res = serde_wasm_bindgen::to_value(&out).map_err(|e| JsError::new(&e.to_string()))?;
        Ok(res)
    }

    fn json_to_resp(json: JsValue) -> Result<Vec<ReencryptionResponse>, JsError> {
        // first read the hex type
        let hex_resps: Vec<ReencryptionResponseHex> =
            serde_wasm_bindgen::from_value(json).map_err(|e| JsError::new(&e.to_string()))?;

        // then convert the hex type into the type we need
        let mut out = vec![];
        for hex_resp in hex_resps {
            // convert fhe_type String into an i32
            let mut fhe_type_str = hex_resp.fhe_type.clone();
            make_ascii_titlecase(&mut fhe_type_str);
            let fhe_type = FheType::from_str_name(&fhe_type_str).ok_or(JsError::new(&format!(
                "fhe_type conversion failed for {fhe_type_str}"
            )))?;
            out.push(ReencryptionResponse {
                version: hex_resp.version,
                servers_needed: hex_resp.servers_needed,
                verification_key: hex::decode(&hex_resp.verification_key)
                    .map_err(|e| JsError::new(&e.to_string()))?,
                digest: hex::decode(&hex_resp.digest).map_err(|e| JsError::new(&e.to_string()))?,
                fhe_type: fhe_type as i32,
                signcrypted_ciphertext: hex::decode(&hex_resp.signcrypted_ciphertext)
                    .map_err(|e| JsError::new(&e.to_string()))?,
            });
        }
        Ok(out)
    }

    /// Process the reencryption response from a JSON object.
    /// The result is a byte array representing a plaintext of any length.
    ///
    /// * `client` - client that wants to perform reencryption.
    ///
    /// * `request` - the initial reencryption request.
    ///
    /// * `agg_resp - the response JSON object from the gateway.
    ///
    /// * `agg_resp_ids - the KMS server identities that correspond to each request.
    /// If this is not given, the initial configuration is used
    /// from when the client is instantiated.
    ///
    /// * `enc_pk` - The ephemeral public key.
    ///
    /// * `enc_sk` - The ephemeral secret key.
    ///
    /// * `verify` - Whether to perform signature verification for the response.
    /// It is insecure if `verify = false`!
    #[wasm_bindgen]
    pub fn process_reencryption_resp_from_json(
        client: &mut Client,
        request: Option<ReencryptionRequest>,
        agg_resp: JsValue,
        agg_resp_ids: Option<Vec<u32>>,
        enc_pk: &PublicEncKey,
        enc_sk: &PrivateEncKey,
        verify: bool,
    ) -> Result<Vec<u8>, JsError> {
        let agg_resp = json_to_resp(agg_resp)?;
        process_reencryption_resp(
            client,
            request,
            agg_resp,
            agg_resp_ids,
            enc_pk,
            enc_sk,
            verify,
        )
    }

    /// Process the reencryption response from a JSON object.
    /// The result is a byte array representing a plaintext of any length.
    ///
    /// * `client` - client that wants to perform reencryption.
    ///
    /// * `request` - the initial reencryption request.
    ///
    /// * `agg_resp - the vector of reencryption responses.
    ///
    /// * `agg_resp_ids - the KMS server identities that correspond to each request.
    /// If this is not given, the initial configuration is used
    /// from when the client is instantiated.
    ///
    /// * `enc_pk` - The ephemeral public key.
    ///
    /// * `enc_sk` - The ephemeral secret key.
    ///
    /// * `verify` - Whether to perform signature verification for the response.
    /// It is insecure if `verify = false`!
    #[wasm_bindgen]
    pub fn process_reencryption_resp(
        client: &mut Client,
        request: Option<ReencryptionRequest>,
        agg_resp: Vec<ReencryptionResponse>,
        agg_resp_ids: Option<Vec<u32>>,
        enc_pk: &PublicEncKey,
        enc_sk: &PrivateEncKey,
        verify: bool,
    ) -> Result<Vec<u8>, JsError> {
        // In the centralized case, agg_resp_ids is ignored and is always set to vec![1]
        // in the threshold case, if agg_resp_ids is given then we use it,
        // otherwise we derive it from the client's knowledge of the public keys.
        let agg_resp_ids = if agg_resp.len() == 1 {
            vec![1u32]
        } else {
            match agg_resp_ids {
                Some(ids) => ids,
                None => {
                    unimplemented!()
                }
            }
        };

        let mut hm = AggregatedReencryptionResponse {
            responses: HashMap::new(),
        };
        for (k, v) in agg_resp_ids.into_iter().zip(agg_resp) {
            hm.responses.insert(k, v);
        }
        let reenc_resp = if verify {
            client.process_reencryption_resp(request, &hm, enc_pk, enc_sk)
        } else {
            client.insecure_process_reencryption_resp(&hm, enc_pk, enc_sk)
        };
        match reenc_resp {
            Ok(resp) => match resp {
                Some(out) => Ok(out.bytes),
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
        server_pks: HashMap<PublicSigKey, u8>,
        client_pk: PublicSigKey,
        client_sk: Option<PrivateSigKey>,
        shares_needed: u32,
        num_servers: u32,
        params: ClassicPBSParameters,
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
    /// Observe that this method is decoupled from the [Client] to ensure wasm compliance as wasm cannot handle
    /// file reading or generic traits.
    #[cfg(feature = "non-wasm")]
    pub async fn new_client<ClientS: Storage, PubS: StorageReader>(
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

        // This import need to be within this scope otherwise
        // it is considered unused with certain features
        use distributed_decryption::execution::tfhe_internals::parameters::NoiseFloodParameters;
        let params: NoiseFloodParameters = read_as_json(param_path).await?;

        let n = server_keys.len() as u8;
        Ok(Client::new(
            HashMap::from_iter(server_keys.into_iter().zip(1..=n)),
            client_pk,
            client_sk,
            shares_needed,
            num_servers,
            params.ciphertext_parameters,
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

        for verf_key in self.server_pks.keys() {
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
    /// its [`RequestId`] it can be set to None in the centralized case
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
    pub async fn process_distributed_crs_result<S: StorageReader>(
        &self,
        request_id: &RequestId,
        results: Vec<CrsGenResult>,
        storage_readers: &[S],
    ) -> anyhow::Result<PublicParameter> {
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
            let (pp, info) = if let Some(info) = result.crs_results {
                let url =
                    storage.compute_url(&request_id.to_string(), &PubDataType::CRS.to_string())?;
                let pp: PublicParameter = storage.read_data(&url).await?;
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
            .ok_or_else(|| anyhow_error_and_log("logic error: hash_counter_map is empty"))?;

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
            enc_key: serialize(&enc_pk)?,
            verification_key: serialize(&self.client_pk)?,
            fhe_type: fhe_type as i32,
            randomness,
            key_id: Some(key_id.clone()),
            ciphertext: Some(ciphertext),
            ciphertext_digest,
        };
        let message = Reencrypt {
            publicKey: Bytes::copy_from_slice(&sig_payload.enc_key),
        };
        // Derive the EIP-712 signing hash.
        let message_hash = message.eip712_signing_hash(domain);
        let signer = alloy_signer_local::PrivateKeySigner::from_signing_key(
            self.client_sk.clone().unwrap().sk,
        );

        let signature = signer.sign_hash_sync(&message_hash)?;

        let domain_msg = allow_to_protobuf_domain(domain)?;
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

    // TODO do we need to linking to request?
    #[cfg(feature = "non-wasm")]
    pub async fn process_get_key_gen_resp<R: StorageReader>(
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
    pub async fn retrieve_key<S: serde::Serialize + DeserializeOwned + Send, R: StorageReader>(
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
    pub async fn process_get_crs_resp<R: StorageReader>(
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
    pub async fn retrieve_crs<R: StorageReader>(
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
            // verification key is in the set of permissible keys
            let cur_verf_key: PublicSigKey = deserialize(&cur_payload.verification_key)?;
            if !BaseKmsStruct::verify_sig(&bincode::serialize(&cur_payload)?, &sig, &cur_verf_key) {
                tracing::warn!("Signature on received response is not valid!");
                return Ok(None);
            }
        }
        let serialized_plaintext = some_or_err(
            pivot.payload.to_owned(),
            "No payload in pivot response for decryption".to_owned(),
        )?
        .plaintext;
        let plaintext: Plaintext = deserialize(&serialized_plaintext)?;
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
        let request = request.ok_or_else(|| {
            anyhow_error_and_log("empty request while processing reencryption response")
        })?;

        // Execute simplified and faster flow for the centralized case
        // Observe that we don't encode exactly the same in the centralized case and in the
        // distributed case. For the centralized case we directly encode the [Plaintext]
        // object whereas for the distributed we encode the plain text as a
        // Vec<ResiduePoly<Z128>>
        if agg_resp.responses.len() <= 1 {
            self.centralized_reencryption_resp(request, agg_resp, &client_keys)
        } else {
            self.threshold_reencryption_resp(request, agg_resp, &client_keys)
        }
    }

    /// Processes the aggregated reencryption response to attempt to decrypt
    /// the encryption of the secret shared plaintext and returns this.
    /// This function does *not* do any verification and is thus insecure and should be used only for testing.
    /// TODO hide behind flag for insecure function?
    pub fn insecure_process_reencryption_resp(
        &self,
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

        // Execute simplified and faster flow for the centralized case
        // Observe that we don't encode exactly the same in the centralized case and in the
        // distributed case. For the centralized case we directly encode the [Plaintext]
        // object whereas for the distributed we encode the plain text as a
        // Vec<ResiduePoly<Z128>>
        if agg_resp.responses.len() <= 1 {
            self.insecure_centralized_reencryption_resp(agg_resp, &client_keys)
        } else {
            self.insecure_threshold_reencryption_resp(agg_resp, &client_keys)
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
                if BaseKmsStruct::digest(&bincode::serialize(&sig_payload)?)?
                    != pivot_payload.digest
                {
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
            // verification key is in the set of permissible keys
            let cur_verf_key: PublicSigKey = deserialize(&cur_payload.verification_key)?;
            if !BaseKmsStruct::verify_sig(&bincode::serialize(&cur_payload)?, &sig, &cur_verf_key) {
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

    /// Decrypt the reencryption response from the centralized KMS and verify that the signatures are valid
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
            return Err(anyhow_error_and_log(format!(
                "link mismatch ({} != {}) for domain {:?}",
                hex::encode(&link),
                hex::encode(&resp.digest),
                request.domain
            )));
        }

        let cur_verf_key: PublicSigKey = deserialize(&resp.verification_key)?;
        match decrypt_signcryption(
            &resp.signcrypted_ciphertext,
            &link,
            client_keys,
            &cur_verf_key,
        )? {
            Some(decryption_share) => Ok(Some(decryption_share)),
            None => {
                tracing::warn!("Could decrypt or validate signcrypted response");
                Ok(None)
            }
        }
    }

    /// Decrypt the reencryption response from the centralized KMS.
    /// This function does *not* do any verification and is thus insecure and should be used only for testing.
    /// TODO hide behind flag for insecure function?
    fn insecure_centralized_reencryption_resp(
        &self,
        agg_resp: &AggregatedReencryptionResponse,
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Option<Plaintext>> {
        let resp = some_or_err(
            agg_resp.responses.values().last(),
            "Response does not exist".to_owned(),
        )?;

        match crate::cryptography::signcryption::insecure_decrypt_ignoring_signature(
            &resp.signcrypted_ciphertext,
            client_keys,
        )? {
            Some(decryption_share) => Ok(Some(decryption_share)),
            None => {
                tracing::warn!("Could decrypt or validate signcrypted response");
                Ok(None)
            }
        }
    }

    /// Decrypt the reencryption responses from the threshold KMS and verify that the signatures are valid
    fn threshold_reencryption_resp(
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
        let recon_blocks = reconstruct_message(Some(decrypted_blocks), &self.params)?;
        Ok(Some(decrypted_blocks_to_plaintext(
            &self.params,
            req_payload.fhe_type(),
            recon_blocks,
        )?))
    }

    /// Decrypt the reencryption response from the threshold KMS.
    /// This function does *not* do any verification and is thus insecure and should be used only for testing.
    /// TODO hide behind flag for insecure function?
    fn insecure_threshold_reencryption_resp(
        &self,
        agg_resp: &AggregatedReencryptionResponse,
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Option<Plaintext>> {
        //Do not actually validate responses
        let validated_resps = &agg_resp.responses;

        //Recover sharings
        let mut opt_sharings = None;

        //Trust all responses have all expected blocks
        for (cur_role_id, cur_resp) in validated_resps {
            let shares =
                insecure_decrypt_ignoring_signature(&cur_resp.signcrypted_ciphertext, client_keys)?;
            if let Some(shares) = shares {
                let cipher_blocks_share: Vec<ResiduePoly<Z128>> = deserialize(&shares.bytes)?;
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
                    Role::indexed_by_one(*cur_role_id as usize),
                )?;
            }
        }
        let sharings = opt_sharings.unwrap();
        let num_parties = validated_resps.len();
        let mut decrypted_blocks = Vec::new();
        let degree = num_parties / 3;
        for cur_block_shares in sharings {
            // NOTE: this performs optimistic reconstruction
            if let Ok(Some(r)) =
                reconstruct_w_errors_sync(num_parties, degree, degree, &cur_block_shares)
            {
                decrypted_blocks.push(r);
            } else {
                return Err(anyhow_error_and_log("Could not reconstruct all blocks"));
            }
        }
        let recon_blocks = reconstruct_message(Some(decrypted_blocks), &self.params)?;

        //Deduce fhe_type from recon_blocks and message_modulus
        let bits_in_block = self.params.message_modulus_log() as usize;
        let num_blocks = recon_blocks.len();

        let total_num_bits = bits_in_block * num_blocks;

        let fhe_type = if total_num_bits == bits_in_block {
            FheType::Ebool
        } else if total_num_bits == 4 {
            FheType::Euint4
        } else if total_num_bits == 8 {
            FheType::Euint8
        } else if total_num_bits == 16 {
            FheType::Euint16
        } else if total_num_bits == 32 {
            FheType::Euint32
        } else if total_num_bits == 64 {
            FheType::Euint64
        } else if total_num_bits == 128 {
            FheType::Euint128
        } else if total_num_bits == 160 {
            FheType::Euint160
        } else if total_num_bits == 256 {
            FheType::Euint256
        } else if total_num_bits == 2048 {
            FheType::Euint2048
        } else {
            panic!("Unexpected type: total_num_bits {total_num_bits}")
        };

        Ok(Some(decrypted_blocks_to_plaintext(
            &self.params,
            fhe_type,
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
        let num_blocks = num_blocks(fhe_type, &self.params);
        let mut sharings = Vec::new();
        for _i in 0..num_blocks {
            sharings.push(ShamirSharings::new());
        }
        for (cur_role_id, cur_resp) in &agg_resp {
            // Observe that it has already been verified in [validate_meta_data] that server
            // verification key is in the set of permissible keys
            //
            // Also it's ok to use [cur_resp.digest] as the link since we already checked
            // that it matches with the original request
            let cur_verf_key: PublicSigKey = deserialize(&cur_resp.verification_key)?;
            match decrypt_signcryption(
                &cur_resp.signcrypted_ciphertext,
                &cur_resp.digest,
                client_keys,
                &cur_verf_key,
            )? {
                Some(decryption_share) => {
                    let cipher_blocks_share: Vec<ResiduePoly<Z128>> =
                        deserialize(&decryption_share.bytes)?;
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
        let resp_verf_key: PublicSigKey = deserialize(&other_resp.verification_key())?;
        if !&self.server_pks.keys().contains(&resp_verf_key) {
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
pub fn num_blocks(fhe_type: FheType, params: &ClassicPBSParameters) -> usize {
    match fhe_type {
        FheType::Ebool => 8_usize.div_ceil(params.message_modulus_log() as usize),
        FheType::Euint4 => 8_usize.div_ceil(params.message_modulus_log() as usize),
        FheType::Euint8 => 8_usize.div_ceil(params.message_modulus_log() as usize),
        FheType::Euint16 => 16_usize.div_ceil(params.message_modulus_log() as usize),
        FheType::Euint32 => 32_usize.div_ceil(params.message_modulus_log() as usize),
        FheType::Euint64 => 64_usize.div_ceil(params.message_modulus_log() as usize),
        FheType::Euint128 => 128_usize.div_ceil(params.message_modulus_log() as usize),
        FheType::Euint160 => 160_usize.div_ceil(params.message_modulus_log() as usize),
        FheType::Euint256 => 256_usize.div_ceil(params.message_modulus_log() as usize),
        FheType::Euint512 => 512_usize.div_ceil(params.message_modulus_log() as usize),
        FheType::Euint1024 => 1024_usize.div_ceil(params.message_modulus_log() as usize),
        FheType::Euint2048 => 2048_usize.div_ceil(params.message_modulus_log() as usize),
    }
}

pub fn ecdsa_public_key_to_address(pk: &PublicSigKey) -> anyhow::Result<Vec<u8>> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let affine = pk.pk.as_ref();
    let encoded = affine.to_encoded_point(false);
    let pk_buf = &encoded.as_bytes()[1..];
    if pk_buf.len() != 64 {
        return Err(anyhow::anyhow!("incorrect public key buffer size"));
    }
    let digest = alloy_primitives::keccak256(pk_buf);
    Ok(digest[12..].to_vec())
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

    let signature = alloy_primitives::Signature::try_from(sig)?;

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
    Ok(PublicSigKey {
        pk: signature.recover_from_prehash(&message_hash)?,
    })
}

// TODO this module should be behind cfg(test) normally
// but we need it in other places such as the connector
// and cfg(test) is not compiled by tests in other crates.
// Consider putting this behind a test-specific crate.
#[cfg(any(test, feature = "testing"))]
#[cfg(feature = "non-wasm")]
pub mod test_tools {
    use super::*;
    use crate::conf::centralized::CentralizedConfigNoStorage;
    use crate::conf::threshold::{PeerConf, ThresholdConfigNoStorage};
    use crate::consts::{BASE_PORT, DEC_CAPACITY, DEFAULT_PROT, DEFAULT_URL, MIN_DEC_CACHE};
    use crate::kms::core_service_endpoint_client::CoreServiceEndpointClient;
    use crate::rpc::central_rpc::{default_param_file_map, server_handle};
    use crate::storage::{FileStorage, RamStorage, Storage, StorageType, StorageVersion};
    use crate::threshold::threshold_kms::{threshold_server_init, threshold_server_start};
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
        PubS: Storage + Clone + Sync + Send + 'static,
        PrivS: Storage + Clone + Sync + Send + 'static,
    >(
        threshold: u8,
        pub_storage: Vec<PubS>,
        priv_storage: Vec<PrivS>,
        run_prss: bool,
    ) -> HashMap<u32, JoinHandle<()>> {
        let mut handles = Vec::new();
        tracing::info!("Spawning servers...");
        let amount = priv_storage.len();
        let timeout_secs = 60u64;
        let grpc_max_message_size = 10 * 1024 * 1024; // 10 MiB
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
                    grpc_max_message_size,
                    preproc_redis_conf: None,
                    num_sessions_preproc: None,
                    tls_cert_path: None,
                    tls_key_path: None,
                    peer_confs: peer_configs,
                    core_to_core_net_conf: None,
                    param_file_map: default_param_file_map(),
                };
                // TODO pass in cert_paths for testing TLS
                let server = threshold_server_init(
                    config.clone(),
                    cur_pub_storage,
                    cur_priv_storage,
                    run_prss,
                )
                .await;
                (i, server, config)
            }));
        }
        assert_eq!(handles.len(), amount);
        // Wait for the server to start
        tracing::info!("Client waiting for server");
        let mut servers = Vec::with_capacity(amount);
        for cur_handle in handles {
            let (i, kms_server_res, config) = cur_handle.await.unwrap();
            match kms_server_res {
                Ok(kms_server) => servers.push((i, kms_server, config)),
                Err(e) => panic!("Failed to start server {i} with error {:?}", e),
            }
        }
        tracing::info!("Servers initialized. Starting servers...");
        let mut server_handles = HashMap::new();
        for (i, cur_server, config) in servers {
            let handle = tokio::spawn(async move {
                let _ = threshold_server_start(
                    config.listen_address_client,
                    config.listen_port_client,
                    timeout_secs,
                    config.grpc_max_message_size,
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
        PubS: Storage + Clone + Sync + Send + 'static,
        PrivS: Storage + Clone + Sync + Send + 'static,
    >(
        threshold: u8,
        pub_storage: Vec<PubS>,
        priv_storage: Vec<PrivS>,
    ) -> (
        HashMap<u32, JoinHandle<()>>,
        HashMap<u32, CoreServiceEndpointClient<Channel>>,
    ) {
        let amount = priv_storage.len();
        let server_handles =
            setup_threshold_no_client(threshold, pub_storage, priv_storage, true).await;
        let mut client_handles = HashMap::new();
        for i in 1..=amount {
            // NOTE: calculation of port must match what's done in [setup_threshold_no_client]
            let port = BASE_PORT + i as u16 * 100;
            let url = format!("{DEFAULT_PROT}://{DEFAULT_URL}:{port}");
            let uri = Uri::from_str(&url).unwrap();
            let channel = Channel::builder(uri).connect().await.unwrap();
            client_handles.insert(i as u32, CoreServiceEndpointClient::new(channel));
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
    ) -> JoinHandle<()> {
        let server_handle = tokio::spawn(async move {
            let url = format!("{DEFAULT_PROT}://{DEFAULT_URL}:{}", BASE_PORT + 1);
            let config = CentralizedConfigNoStorage {
                url,
                param_file_map: default_param_file_map(),
                grpc_max_message_size: 10 * 1024 * 1024, // 10 MiB to allow for 2048 bit encryptions
            };
            let _ = server_handle(config, pub_storage, priv_storage).await;
        });
        // We have to wait for the server to start since it will keep running in the background
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        server_handle
    }

    pub(crate) async fn setup_centralized<
        PubS: Storage + Sync + Send + 'static,
        PrivS: Storage + Sync + Send + 'static,
    >(
        pub_storage: PubS,
        priv_storage: PrivS,
    ) -> (
        JoinHandle<()>,
        CoreServiceEndpointClient<tonic::transport::Channel>,
    ) {
        let server_handle = setup_centralized_no_client(pub_storage, priv_storage).await;
        let url = format!("{DEFAULT_PROT}://{DEFAULT_URL}:{}", BASE_PORT + 1);
        let uri = Uri::from_str(&url).unwrap();
        let channel = Channel::builder(uri).connect().await.unwrap();
        let client = CoreServiceEndpointClient::new(channel);
        (server_handle, client)
    }

    /// Read the centralized keys for testing from `centralized_key_path` and construct a KMS
    /// server, client end-point connection (which is needed to communicate with the server) and
    /// an internal client (for constructing requests and validating responses).
    pub async fn centralized_handles(
        storage_version: StorageVersion,
        param_path: &str,
    ) -> (JoinHandle<()>, CoreServiceEndpointClient<Channel>, Client) {
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
        // TODO why are these FileStorage and not depend on the StorageVersion?
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
    use super::{recover_ecdsa_public_key_from_signature, Client};
    #[cfg(feature = "wasm_tests")]
    use crate::client::TestingReencryptionTranscript;
    #[cfg(feature = "wasm_tests")]
    use crate::consts::TEST_CENTRAL_KEY_ID;
    use crate::consts::{AMOUNT_PARTIES, TEST_PARAM_PATH, THRESHOLD};
    #[cfg(feature = "slow_tests")]
    use crate::consts::{
        DEFAULT_CENTRAL_KEYS_PATH, DEFAULT_CENTRAL_KEY_ID, DEFAULT_PARAM_PATH,
        DEFAULT_THRESHOLD_KEY_ID,
    };
    #[cfg(feature = "slow_tests")]
    use crate::cryptography::central_kms::CentralizedTestingKeys;
    use crate::cryptography::central_kms::{compute_handle, gen_sig_keys, BaseKmsStruct};
    use crate::cryptography::der_types::Signature;
    use crate::cryptography::signcryption::Reencrypt;
    use crate::kms::core_service_endpoint_client::CoreServiceEndpointClient;
    #[cfg(feature = "slow_tests")]
    use crate::kms::CrsGenResult;
    use crate::kms::{
        AggregatedDecryptionResponse, AggregatedReencryptionResponse, FheType, ParamChoice,
    };
    use crate::rpc::central_rpc::default_param_file_map;
    use crate::rpc::rpc_types::{BaseKms, PubDataType};
    use crate::storage::StorageReader;
    use crate::storage::{FileStorage, RamStorage, StorageType, StorageVersion};
    use crate::util::file_handling::read_element;
    #[cfg(feature = "wasm_tests")]
    use crate::util::file_handling::write_element;
    use crate::util::key_setup::test_tools::{compute_cipher_from_storage, purge, TypedPlaintext};
    use crate::util::key_setup::FhePublicKey;
    use crate::{
        client::num_blocks,
        kms::{Empty, RequestId},
    };
    use crate::{consts::TEST_THRESHOLD_KEY_ID, util::file_handling::read_as_json};
    use alloy_primitives::Bytes;
    use alloy_signer::Signer;
    use alloy_signer_local::PrivateKeySigner;
    use alloy_sol_types::Eip712Domain;
    use alloy_sol_types::SolStruct;
    use distributed_decryption::execution::tfhe_internals::parameters::NoiseFloodParameters;
    use distributed_decryption::execution::zk::ceremony::PublicParameter;
    use rand::SeedableRng;
    use serial_test::serial;
    use std::collections::HashMap;
    use tokio::task::{JoinHandle, JoinSet};
    use tonic::transport::Channel;

    /// Reads the testing keys for the threshold servers and starts them up, and returns a hash map
    /// of the servers, based on their ID, which starts from 1. A similar map is also returned
    /// is the client endpoints needed to talk with each of the servers, finally the internal
    /// client is returned (which is responsible for constructing requests and validating
    /// responses).
    async fn threshold_handles(
        storage_version: StorageVersion,
        param_path: &str,
    ) -> (
        HashMap<u32, JoinHandle<()>>,
        HashMap<u32, CoreServiceEndpointClient<Channel>>,
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
    async fn test_public_key_from_signature() {
        let domain = dummy_domain();
        let pub_enc_key = b"408d8cbaa51dece7f782fe04ba0b1c1d017b1088";
        let message = Reencrypt {
            publicKey: Bytes::from(pub_enc_key),
        };
        let mut rng = aes_prng::AesRng::seed_from_u64(12);
        let (client_pk, client_sk) = gen_sig_keys(&mut rng);
        //let target_address = ecdsa_public_key_to_address(&client_pk).unwrap();

        let signer = PrivateKeySigner::from_signing_key(client_sk.sk);
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
        assert!(kms_server.await.unwrap_err().is_cancelled());
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
        for vk in internal_client.server_pks.keys() {
            let v = BaseKmsStruct::verify_sig(&client_handle, &crs_sig, vk);
            verified = verified || v;
        }

        // check that verification (with at least 1 server key) worked
        assert!(verified);

        kms_server.abort();
        assert!(kms_server.await.unwrap_err().is_cancelled());
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
        assert!(kms_server.await.unwrap_err().is_cancelled());

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
    #[rstest::rstest]
    #[case(4)]
    #[case(1)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    #[tracing_test::traced_test]
    async fn test_crs_gen_threshold(#[case] parallelism: usize) {
        // NOTE: the test parameter has 300 witness size
        // so we set this as a slow test
        crs_gen_threshold(parallelism).await
    }

    #[cfg(feature = "slow_tests")]
    fn set_signatures(crs_gen_results: &mut [CrsGenResult], count: usize, sig: &[u8]) {
        for crs_gen_result in crs_gen_results.iter_mut().take(count) {
            match &mut crs_gen_result.crs_results {
                Some(info) => {
                    info.signature = sig.to_vec();
                }
                None => panic!("missing SignedPubDataHandle"),
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
                None => panic!("missing SignedPubDataHandle"),
            }
        }
    }

    #[cfg(feature = "slow_tests")]
    async fn crs_gen_threshold(parallelism: usize) {
        assert!(parallelism > 0);
        let req_ids: Vec<RequestId> = (0..parallelism)
            .map(|j| RequestId::derive(&format!("test_crs_gen_threshold_{j}")).unwrap())
            .collect();

        // Ensure the test is idempotent
        for req_id in &req_ids {
            purge(None, None, &req_id.request_id).await;
        }

        // The threshold handle should only be started after the storage is purged
        // since the threshold parties will load the CRS from private storage
        let (kms_servers, kms_clients, internal_client) =
            threshold_handles(StorageVersion::Dev, TEST_PARAM_PATH).await;

        let reqs: Vec<_> = (0..parallelism)
            .map(|j| {
                let request_id = RequestId::derive(&format!("test_crs_gen_threshold_{j}")).unwrap();
                internal_client
                    .crs_gen_request(&request_id, Some(ParamChoice::Test))
                    .unwrap()
            })
            .collect();

        let mut tasks_gen = JoinSet::new();
        for req in &reqs {
            for i in 1..=AMOUNT_PARTIES as u32 {
                let mut cur_client = kms_clients.get(&i).unwrap().clone();
                let req_clone = req.clone();
                tasks_gen
                    .spawn(async move { cur_client.crs_gen(tonic::Request::new(req_clone)).await });
            }
        }
        let mut responses_gen = Vec::new();
        while let Some(inner) = tasks_gen.join_next().await {
            let resp = inner.unwrap().unwrap();
            responses_gen.push(resp.into_inner());
        }
        assert_eq!(responses_gen.len(), AMOUNT_PARTIES * parallelism);

        // wait a bit for the crs generation to finish
        const TRIES: usize = 60;
        let mut joined_responses = vec![];
        for count in 0..TRIES {
            joined_responses = vec![];
            tokio::time::sleep(std::time::Duration::from_secs(5 * parallelism as u64)).await;

            let mut tasks_get = JoinSet::new();
            for req in &reqs {
                for i in 1..=AMOUNT_PARTIES as u32 {
                    let mut cur_client = kms_clients.get(&i).unwrap().clone();
                    let req_id_cloned = req.request_id.as_ref().unwrap().clone();
                    tasks_get.spawn(async move {
                        (
                            i,
                            req_id_cloned.clone(),
                            cur_client
                                .get_crs_gen_result(tonic::Request::new(req_id_cloned))
                                .await,
                        )
                    });
                }
            }
            let mut responses_get = Vec::new();
            while let Some(Ok((j, req_id, Ok(resp)))) = tasks_get.join_next().await {
                responses_get.push((j, req_id, resp.into_inner()));
            }

            // add the responses in this iteration to the bigger vector
            joined_responses.append(&mut responses_get);
            if joined_responses.len() == AMOUNT_PARTIES * parallelism {
                break;
            }

            // fail if we can't find a response
            if count == TRIES - 1 {
                panic!("could not get crs after {} tries", count);
            }
        }

        for handle in kms_servers.values() {
            handle.abort()
        }
        for (_, handle) in kms_servers {
            assert!(handle.await.unwrap_err().is_cancelled());
        }

        // first check the happy path
        // the public parameter is checked in ddec tests, so we don't specifically check _pp
        for req in reqs {
            let req_id = req.request_id.unwrap();
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
                        { FileStorage::new_threshold(None, StorageType::PUB, i as usize).unwrap() },
                        res,
                    )
                })
                .unzip();

            let _pp = internal_client
                .process_distributed_crs_result(&req_id, final_responses.clone(), &storage_readers)
                .await
                .unwrap();

            // if there are [THRESHOLD] result missing, we can still recover the result
            let _pp = internal_client
                .process_distributed_crs_result(
                    &req_id,
                    final_responses[0..final_responses.len() - THRESHOLD].to_vec(),
                    &storage_readers,
                )
                .await
                .unwrap();

            // if there are [THRESHOLD+1] results missing, then we do not have consensus
            assert!(internal_client
                .process_distributed_crs_result(
                    &req_id,
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
                &crate::cryptography::signcryption::sign(&"wrong msg".to_string(), &client_sk)
                    .unwrap(),
            )
            .unwrap();
            set_signatures(&mut final_responses_with_bad_sig, THRESHOLD, &bad_sig);

            let _pp = internal_client
                .process_distributed_crs_result(
                    &req_id,
                    final_responses_with_bad_sig.clone(),
                    &storage_readers,
                )
                .await
                .unwrap();

            // having [THRESHOLD+1] wrong signatures won't work
            set_signatures(&mut final_responses_with_bad_sig, THRESHOLD + 1, &bad_sig);
            assert!(internal_client
                .process_distributed_crs_result(
                    &req_id,
                    final_responses_with_bad_sig,
                    &storage_readers
                )
                .await
                .is_err());

            // having [THRESHOLD] wrong digests still works
            let mut final_responses_with_bad_digest = final_responses.clone();
            set_digests(
                &mut final_responses_with_bad_digest,
                THRESHOLD,
                "9fdca770403e2eed9dacb4cdd405a14fc6df7226",
            );
            let _pp = internal_client
                .process_distributed_crs_result(
                    &req_id,
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
                    &req_id,
                    final_responses_with_bad_digest,
                    &storage_readers
                )
                .await
                .is_err());
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_decryption_central() {
        decryption_centralized(
            TEST_PARAM_PATH,
            &crate::consts::TEST_CENTRAL_KEY_ID.to_string(),
            TypedPlaintext::U8(42),
            9,
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[rstest::rstest]
    #[case(TypedPlaintext::Bool(true), 5)]
    #[case(TypedPlaintext::U8(u8::MAX), 4)]
    #[case(TypedPlaintext::U8(0), 4)]
    #[case(TypedPlaintext::U16(u16::MAX), 2)]
    #[case(TypedPlaintext::U16(0), 1)]
    #[case(TypedPlaintext::U32(u32::MAX), 1)]
    #[case(TypedPlaintext::U32(1234567), 1)]
    #[case(TypedPlaintext::U64(u64::MAX), 1)]
    #[case(TypedPlaintext::U128(u128::MAX), 1)]
    #[case(TypedPlaintext::U128(0), 1)]
    #[case(TypedPlaintext::U160(tfhe::integer::U256::from((u128::MAX, u32::MAX as u128))), 1)]
    #[case(TypedPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX))), 1)]
    #[case(TypedPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32])), 1)]
    #[tokio::test]
    #[serial]
    async fn default_decryption_centralized(
        #[case] msg: TypedPlaintext,
        #[case] parallelism: usize,
    ) {
        decryption_centralized(
            DEFAULT_PARAM_PATH,
            &DEFAULT_CENTRAL_KEY_ID.to_string(),
            msg,
            parallelism,
        )
        .await;
    }

    async fn decryption_centralized(
        param_path: &str,
        key_id: &str,
        msg: TypedPlaintext,
        parallelism: usize,
    ) {
        assert!(parallelism > 0);
        let (kms_server, kms_client, mut internal_client) =
            super::test_tools::centralized_handles(StorageVersion::Dev, param_path).await;
        let (ct, fhe_type) = compute_cipher_from_storage(None, msg, key_id).await;
        let req_key_id = key_id.to_owned().try_into().unwrap();

        // build parallel requests
        let reqs: Vec<_> = (0..parallelism)
            .map(|j| {
                let request_id = RequestId::derive(&format!("TEST_DEC_ID_{j}")).unwrap();
                internal_client
                    .decryption_request(ct.clone(), fhe_type, &request_id, &req_key_id)
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
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;

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
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    // we may wait up to 5s, for big ciphertexts
                    if ctr >= 100 {
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
            let responses = AggregatedDecryptionResponse { responses };

            let plaintext = internal_client
                .process_decryption_resp(Some(req.clone()), &responses)
                .unwrap()
                .unwrap();

            assert_eq!(msg.to_fhe_type(), plaintext.fhe_type());

            match msg {
                TypedPlaintext::Bool(x) => assert_eq!(x, plaintext.as_bool()),
                TypedPlaintext::U8(x) => assert_eq!(x, plaintext.as_u8()),
                TypedPlaintext::U16(x) => assert_eq!(x, plaintext.as_u16()),
                TypedPlaintext::U32(x) => assert_eq!(x, plaintext.as_u32()),
                TypedPlaintext::U64(x) => assert_eq!(x, plaintext.as_u64()),
                TypedPlaintext::U128(x) => assert_eq!(x, plaintext.as_u128()),
                TypedPlaintext::U160(x) => assert_eq!(x, plaintext.as_u160()),
                TypedPlaintext::U256(x) => assert_eq!(x, plaintext.as_u256()),
                TypedPlaintext::U2048(x) => assert_eq!(x, plaintext.as_u2048()),
            }
        }

        kms_server.abort();
        assert!(kms_server.await.unwrap_err().is_cancelled());
    }

    #[rstest::rstest]
    #[tokio::test]
    #[serial]
    async fn test_reencryption_centralized(#[values(true, false)] secure: bool) {
        reencryption_centralized(
            TEST_PARAM_PATH,
            &crate::consts::TEST_CENTRAL_KEY_ID.to_string(),
            false,
            TypedPlaintext::U8(48),
            7,
            secure,
        )
        .await;
    }

    #[cfg(feature = "wasm_tests")]
    #[rstest::rstest]
    #[tokio::test]
    #[serial]
    async fn test_reencryption_centralized_and_write_transcript(
        #[values(true, false)] secure: bool,
    ) {
        reencryption_centralized(
            TEST_PARAM_PATH,
            &TEST_CENTRAL_KEY_ID.to_string(),
            true,
            TypedPlaintext::U8(48),
            1, // wasm tests are single-threaded
            secure,
        )
        .await;
    }

    #[cfg(all(feature = "wasm_tests", feature = "slow_tests"))]
    #[rstest::rstest]
    #[case(TypedPlaintext::Bool(true))]
    #[case(TypedPlaintext::U8(u8::MAX))]
    #[case(TypedPlaintext::U16(u16::MAX))]
    #[case(TypedPlaintext::U32(u32::MAX))]
    #[case(TypedPlaintext::U64(u64::MAX))]
    // #[case(TypedPlaintext::U128(u128::MAX))]
    // #[case(TypedPlaintext::U160(tfhe::integer::U256::from((u128::MAX, u32::MAX as u128))))]
    // #[case(TypedPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX))))]
    // #[case(TypedPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32])))]
    #[tokio::test]
    #[serial]
    async fn default_reencryption_centralized_and_write_transcript(
        #[case] msg: TypedPlaintext,
        #[values(true, false)] secure: bool,
    ) {
        reencryption_centralized(
            DEFAULT_PARAM_PATH,
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
    #[case(TypedPlaintext::Bool(true), 2)]
    #[case(TypedPlaintext::U8(u8::MAX), 1)]
    #[case(TypedPlaintext::U8(0), 1)]
    #[case(TypedPlaintext::U16(u16::MAX), 1)]
    #[case(TypedPlaintext::U16(0), 1)]
    #[case(TypedPlaintext::U32(u32::MAX), 1)]
    #[case(TypedPlaintext::U32(1234567), 1)]
    #[case(TypedPlaintext::U64(u64::MAX), 1)]
    #[case(TypedPlaintext::U128(u128::MAX), 1)]
    #[case(TypedPlaintext::U128(0), 1)]
    #[case(TypedPlaintext::U160(tfhe::integer::U256::from((u128::MAX, u32::MAX as u128))), 1)]
    #[case(TypedPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX))), 1)]
    #[case(TypedPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32])), 1)]
    #[tokio::test]
    #[serial]
    async fn default_reencryption_centralized(
        #[case] msg: TypedPlaintext,
        #[case] parallelism: usize,
        #[values(true, false)] secure: bool,
    ) {
        reencryption_centralized(
            DEFAULT_PARAM_PATH,
            &DEFAULT_CENTRAL_KEY_ID.to_string(),
            false,
            msg,
            parallelism,
            secure,
        )
        .await;
    }

    fn dummy_domain() -> Eip712Domain {
        alloy_sol_types::eip712_domain!(
            name: "Authorization token",
            version: "1",
            chain_id: 8006,
            verifying_contract: alloy_primitives::Address::ZERO,
        )
    }

    async fn reencryption_centralized(
        param_path: &str,
        key_id: &str,
        _write_transcript: bool,
        msg: TypedPlaintext,
        parallelism: usize,
        secure: bool,
    ) {
        assert!(parallelism > 0);
        let (kms_server, kms_client, mut internal_client) =
            super::test_tools::centralized_handles(StorageVersion::Dev, param_path).await;
        let (ct, fhe_type) = compute_cipher_from_storage(None, msg, key_id).await;
        let req_key_id = key_id.to_owned().try_into().unwrap();

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
                let request_id = RequestId::derive(&format!("TEST_REENC_ID_{j}")).unwrap();
                internal_client
                    .reencryption_request(
                        ct.clone(),
                        &dummy_domain(),
                        fhe_type,
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

        // check that initial request responsed are all Empty
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
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;

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
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    // we may wait up to 5s, for big ciphertexts
                    if ctr >= 100 {
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
                    server_pks: internal_client.server_pks.clone(),
                    client_pk: internal_client.client_pk.clone(),
                    client_sk: internal_client.client_sk.clone(),
                    shares_needed: 0,
                    params: internal_client.params,
                    fhe_type: msg.to_fhe_type(),
                    pt: msg.to_plaintext().bytes.clone(),
                    ct: reqs[0].0.payload.as_ref().unwrap().ciphertext().to_vec(),
                    request: Some(reqs[0].clone().0),
                    eph_sk: reqs[0].clone().2,
                    eph_pk: reqs[0].clone().1,
                    agg_resp: HashMap::from([(1, resp_response_vec.first().unwrap().1.clone())]),
                };

                let path_prefix = if param_path.contains("default") {
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
            let responses = AggregatedReencryptionResponse {
                responses: HashMap::from([(1, inner_response.clone())]),
            };

            let plaintext = if secure {
                internal_client
                    .process_reencryption_resp(Some(req.clone()), &responses, enc_pk, enc_sk)
                    .unwrap()
                    .unwrap()
            } else {
                internal_client.server_pks = HashMap::new();
                internal_client
                    .insecure_process_reencryption_resp(&responses, enc_pk, enc_sk)
                    .unwrap()
                    .unwrap()
            };

            assert_eq!(msg.to_fhe_type(), plaintext.fhe_type());

            match msg {
                TypedPlaintext::Bool(x) => assert_eq!(x, plaintext.as_bool()),
                TypedPlaintext::U8(x) => assert_eq!(x, plaintext.as_u8()),
                TypedPlaintext::U16(x) => assert_eq!(x, plaintext.as_u16()),
                TypedPlaintext::U32(x) => assert_eq!(x, plaintext.as_u32()),
                TypedPlaintext::U64(x) => assert_eq!(x, plaintext.as_u64()),
                TypedPlaintext::U128(x) => assert_eq!(x, plaintext.as_u128()),
                TypedPlaintext::U160(x) => assert_eq!(x, plaintext.as_u160()),
                TypedPlaintext::U256(x) => assert_eq!(x, plaintext.as_u256()),
                TypedPlaintext::U2048(x) => assert_eq!(x, plaintext.as_u2048()),
            }
        }

        kms_server.abort();
        assert!(kms_server.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    #[serial]
    #[tracing_test::traced_test]
    async fn test_decryption_threshold() {
        decryption_threshold(
            TEST_PARAM_PATH,
            &TEST_THRESHOLD_KEY_ID.to_string(),
            TypedPlaintext::U8(42),
            4,
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[rstest::rstest]
    #[case(TypedPlaintext::Bool(true), 4)]
    #[case(TypedPlaintext::U8(u8::MAX), 1)]
    #[case(TypedPlaintext::U16(u16::MAX), 1)]
    #[case(TypedPlaintext::U32(u32::MAX), 1)]
    #[case(TypedPlaintext::U64(u64::MAX), 1)]
    #[case(TypedPlaintext::U128(u128::MAX), 1)]
    #[case(TypedPlaintext::U160(tfhe::integer::U256::from((u128::MAX, u32::MAX as u128))), 1)]
    #[case(TypedPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX))), 1)]
    // TODO: this takes approx. 138 secs locally.
    // #[case(TypedPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32])), 1)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    #[tracing_test::traced_test]
    async fn default_decryption_threshold(#[case] msg: TypedPlaintext, #[case] parallelism: usize) {
        decryption_threshold(
            DEFAULT_PARAM_PATH,
            &DEFAULT_THRESHOLD_KEY_ID.to_string(),
            msg,
            parallelism,
        )
        .await;
    }

    async fn decryption_threshold(
        params: &str,
        key_id: &str,
        msg: TypedPlaintext,
        parallelism: usize,
    ) {
        assert!(parallelism > 0);
        let (kms_servers, kms_clients, mut internal_client) =
            threshold_handles(StorageVersion::Dev, params).await;
        let (ct, fhe_type) = compute_cipher_from_storage(None, msg, key_id).await;
        let key_id_req = key_id.to_string().try_into().unwrap();

        // make parallel requests by calling [decrypt] in a thread
        let mut req_tasks = JoinSet::new();
        let reqs: Vec<_> = (0..parallelism)
            .map(|j| {
                let request_id = RequestId::derive(&format!("TEST_DEC_ID_{j}")).unwrap();
                internal_client
                    .decryption_request(ct.clone(), fhe_type, &request_id, &key_id_req)
                    .unwrap()
            })
            .collect();
        for i in 1..=AMOUNT_PARTIES as u32 {
            for j in 0..parallelism {
                let req_cloned = reqs.get(j).unwrap().clone();
                let mut cur_client = kms_clients.get(&i).unwrap().clone();
                req_tasks.spawn(async move {
                    cur_client.decrypt(tonic::Request::new(req_cloned)).await
                });
            }
        }

        let mut req_response_vec = Vec::new();
        while let Some(inner) = req_tasks.join_next().await {
            req_response_vec.push(inner.unwrap().unwrap().into_inner());
        }
        assert_eq!(req_response_vec.len(), AMOUNT_PARTIES * parallelism);

        // get all responses
        let mut resp_tasks = JoinSet::new();
        for i in 1..=AMOUNT_PARTIES as u32 {
            for req in &reqs {
                let mut cur_client = kms_clients.get(&i).unwrap().clone();
                let req_id_clone = req.request_id.as_ref().unwrap().clone();
                let bits = msg.bits() as u64;
                resp_tasks.spawn(async move {
                    // Sleep to give the server some time to complete decryption
                    tokio::time::sleep(std::time::Duration::from_millis(
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
                        tokio::time::sleep(std::time::Duration::from_millis(
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

        for handle in kms_servers.values() {
            handle.abort()
        }
        for (_, handle) in kms_servers {
            assert!(handle.await.unwrap_err().is_cancelled());
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
            let agg = AggregatedDecryptionResponse { responses };
            let plaintext = internal_client
                .process_decryption_resp(Some(req.clone()), &agg)
                .unwrap()
                .unwrap();
            assert_eq!(msg.to_fhe_type(), plaintext.fhe_type());
            match msg {
                TypedPlaintext::Bool(x) => assert_eq!(x, plaintext.as_bool()),
                TypedPlaintext::U8(x) => assert_eq!(x, plaintext.as_u8()),
                TypedPlaintext::U16(x) => assert_eq!(x, plaintext.as_u16()),
                TypedPlaintext::U32(x) => assert_eq!(x, plaintext.as_u32()),
                TypedPlaintext::U64(x) => assert_eq!(x, plaintext.as_u64()),
                TypedPlaintext::U128(x) => assert_eq!(x, plaintext.as_u128()),
                TypedPlaintext::U160(x) => assert_eq!(x, plaintext.as_u160()),
                TypedPlaintext::U256(x) => assert_eq!(x, plaintext.as_u256()),
                TypedPlaintext::U2048(x) => assert_eq!(x, plaintext.as_u2048()),
            }
        }
    }

    #[rstest::rstest]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn test_reencryption_threshold(#[values(true, false)] secure: bool) {
        reencryption_threshold(
            TEST_PARAM_PATH,
            &TEST_THRESHOLD_KEY_ID.to_string(),
            false,
            TypedPlaintext::U8(42),
            4,
            secure,
        )
        .await;
    }

    #[cfg(feature = "wasm_tests")]
    #[rstest::rstest]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn test_reencryption_threshold_and_write_transcript(#[values(true, false)] secure: bool) {
        reencryption_threshold(
            TEST_PARAM_PATH,
            &TEST_THRESHOLD_KEY_ID.to_string(),
            true,
            TypedPlaintext::U8(42),
            1,
            secure,
        )
        .await;
    }

    #[cfg(all(feature = "wasm_tests", feature = "slow_tests"))]
    #[rstest::rstest]
    #[case(TypedPlaintext::Bool(true))]
    #[case(TypedPlaintext::U8(u8::MAX))]
    #[case(TypedPlaintext::U16(u16::MAX))]
    #[case(TypedPlaintext::U32(u32::MAX))]
    #[case(TypedPlaintext::U64(u64::MAX))]
    // #[case(TypedPlaintext::U128(u128::MAX))]
    // #[case(TypedPlaintext::U160(tfhe::integer::U256::from((u128::MAX, u32::MAX as u128))))]
    // #[case(TypedPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX))))]
    // #[case(TypedPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32])))]
    #[ignore]
    #[tokio::test]
    #[serial]
    async fn default_reencryption_threshold_and_write_transcript(
        #[case] msg: TypedPlaintext,
        #[values(true, false)] secure: bool,
    ) {
        reencryption_threshold(
            DEFAULT_PARAM_PATH,
            &DEFAULT_THRESHOLD_KEY_ID.to_string(),
            true,
            msg,
            1, // wasm tests are single-threaded
            secure,
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[rstest::rstest]
    #[case(TypedPlaintext::Bool(true), 4)]
    #[case(TypedPlaintext::U8(u8::MAX), 1)]
    #[case(TypedPlaintext::U16(u16::MAX), 1)]
    #[case(TypedPlaintext::U32(u32::MAX), 1)]
    #[case(TypedPlaintext::U64(u64::MAX), 1)]
    #[case(TypedPlaintext::U128(u128::MAX), 1)]
    #[case(TypedPlaintext::U160(tfhe::integer::U256::from((u128::MAX, u32::MAX as u128))), 1)]
    #[case(TypedPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX))), 1)]
    // TODO: this takes approx. 300 secs locally.
    // #[case(TypedPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32])), 1)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    #[tracing_test::traced_test]
    async fn default_reencryption_threshold(
        #[case] msg: TypedPlaintext,
        #[case] parallelism: usize,
        #[values(true, false)] secure: bool,
    ) {
        reencryption_threshold(
            DEFAULT_PARAM_PATH,
            &DEFAULT_THRESHOLD_KEY_ID.to_string(),
            false,
            msg,
            parallelism,
            secure,
        )
        .await;
    }

    async fn reencryption_threshold(
        param_path: &str,
        key_id: &str,
        write_transcript: bool,
        msg: TypedPlaintext,
        parallelism: usize,
        secure: bool,
    ) {
        assert!(parallelism > 0);
        _ = write_transcript;

        let (kms_servers, kms_clients, mut internal_client) =
            threshold_handles(StorageVersion::Dev, param_path).await;
        let (ct, fhe_type) = compute_cipher_from_storage(None, msg, key_id).await;

        // make requests
        let reqs: Vec<_> = (0..parallelism)
            .map(|j| {
                let request_id = RequestId::derive(&format!("TEST_REENC_ID_{j}")).unwrap();
                let (req, enc_pk, enc_sk) = internal_client
                    .reencryption_request(
                        ct.clone(),
                        &dummy_domain(),
                        fhe_type,
                        &request_id,
                        &key_id.to_string().try_into().unwrap(),
                    )
                    .unwrap();
                (req, enc_pk, enc_sk)
            })
            .collect();

        // make queries to clients in parallel
        let mut req_tasks = JoinSet::new();
        for j in 0..parallelism {
            for i in 1..=AMOUNT_PARTIES as u32 {
                let mut cur_client = kms_clients.get(&i).unwrap().clone();
                let req_clone = reqs.get(j).as_ref().unwrap().0.clone();
                req_tasks.spawn(async move {
                    cur_client.reencrypt(tonic::Request::new(req_clone)).await
                });
            }
        }

        let mut req_response_vec = Vec::new();
        while let Some(resp) = req_tasks.join_next().await {
            req_response_vec.push(resp.unwrap().unwrap().into_inner());
        }
        assert_eq!(req_response_vec.len(), AMOUNT_PARTIES * parallelism);

        let mut resp_tasks = JoinSet::new();
        for j in 0..parallelism {
            for i in 1..=AMOUNT_PARTIES as u32 {
                let mut cur_client = kms_clients.get(&i).unwrap().clone();
                let req_id_clone = reqs.get(j).as_ref().unwrap().0.clone().request_id.unwrap();
                let bits = msg.bits() as u64;
                resp_tasks.spawn(async move {
                    // Sleep to give the server some time to complete reencryption
                    tokio::time::sleep(std::time::Duration::from_millis(
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
                        tokio::time::sleep(std::time::Duration::from_millis(
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

                    (i, req_id_clone, response)
                });
            }
        }
        let mut response_map = HashMap::new();
        while let Some(res) = resp_tasks.join_next().await {
            let res = res.unwrap();
            tracing::info!("Client got a response from {}", res.0);
            let (i, req_id, resp) = res;
            response_map.insert((i, req_id), resp.unwrap().into_inner());
        }

        for handle in kms_servers.values() {
            handle.abort()
        }
        for (_, handle) in kms_servers {
            assert!(handle.await.unwrap_err().is_cancelled());
        }

        #[cfg(feature = "wasm_tests")]
        {
            assert_eq!(parallelism, 1);
            if write_transcript {
                // We write a plaintext/ciphertext to file as a workaround
                // for tfhe encryption on the wasm side since it cannot
                // be instantiated easily without a seeder and we don't
                // want to introduce extra npm dependency.
                let agg_resp =
                    HashMap::from_iter(response_map.iter().map(|((i, _req), v)| (*i, v.clone())));

                let transcript = TestingReencryptionTranscript {
                    server_pks: internal_client.server_pks.clone(),
                    client_pk: internal_client.client_pk.clone(),
                    client_sk: internal_client.client_sk.clone(),
                    shares_needed: THRESHOLD as u32 + 1,
                    params: internal_client.params,
                    fhe_type: msg.to_fhe_type(),
                    pt: msg.to_plaintext().bytes.clone(),
                    ct: reqs[0].0.payload.as_ref().unwrap().ciphertext().to_vec(),
                    request: Some(reqs[0].clone().0),
                    eph_sk: reqs[0].clone().2,
                    eph_pk: reqs[0].clone().1,
                    agg_resp,
                };
                let path_prefix = if param_path.contains("default") {
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
            let responses =
                HashMap::from_iter(response_map.iter().filter_map(|((i, req_id), v)| {
                    if req_id == req.request_id.as_ref().unwrap() {
                        Some((*i, v.clone()))
                    } else {
                        None
                    }
                }));
            let agg = AggregatedReencryptionResponse { responses };

            let plaintext = if secure {
                internal_client
                    .process_reencryption_resp(Some(req.clone()), &agg, enc_pk, enc_sk)
                    .unwrap()
                    .unwrap()
            } else {
                internal_client.server_pks = HashMap::new();
                internal_client
                    .insecure_process_reencryption_resp(&agg, enc_pk, enc_sk)
                    .unwrap()
                    .unwrap()
            };
            assert_eq!(msg.to_fhe_type(), plaintext.fhe_type());
            match msg {
                TypedPlaintext::Bool(x) => assert_eq!(x, plaintext.as_bool()),
                TypedPlaintext::U8(x) => assert_eq!(x, plaintext.as_u8()),
                TypedPlaintext::U16(x) => assert_eq!(x, plaintext.as_u16()),
                TypedPlaintext::U32(x) => assert_eq!(x, plaintext.as_u32()),
                TypedPlaintext::U64(x) => assert_eq!(x, plaintext.as_u64()),
                TypedPlaintext::U128(x) => assert_eq!(x, plaintext.as_u128()),
                TypedPlaintext::U160(x) => assert_eq!(x, plaintext.as_u160()),
                TypedPlaintext::U256(x) => assert_eq!(x, plaintext.as_u256()),
                TypedPlaintext::U2048(x) => assert_eq!(x, plaintext.as_u2048()),
            }
        }
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
        let n = keys.server_keys.len() as u8;
        let mut internal_client = Client::new(
            HashMap::from_iter(keys.server_keys.iter().cloned().zip(0..n)),
            keys.client_pk,
            Some(keys.client_sk),
            1,
            1,
            keys.params.ciphertext_parameters,
        );
        let request_id = RequestId::derive("TEST_REENC_ID_123").unwrap();
        let (req, _enc_pk, _enc_sk) = internal_client
            .reencryption_request(
                ct,
                &dummy_domain(),
                fhe_type,
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
        assert!(kms_server.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn num_blocks_sunshine() {
        let params: NoiseFloodParameters = read_as_json(TEST_PARAM_PATH).await.unwrap();
        let params = &params.ciphertext_parameters;
        // 2 bits per block, using Euint8 as internal representation
        assert_eq!(num_blocks(FheType::Ebool, params), 4);
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
        kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
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

    // TODO parallel preproc needs to be investigated, there are two issues
    // 1. for parallelism=4, it took 700, parallelism=2 is 300s, but parallelism=1 is 100s,
    // so running preproc in parallel is slower than sequential
    // 2. for parallelism=4, sometimes (not always) it fails with
    // kms_lib-9439e559ff01deb4(86525,0x16e223000) malloc: Heap corruption detected, free list is damaged at 0x600000650510
    // *** Incorrect guard value: 0
    // issue: https://github.com/zama-ai/kms-core/issues/663
    #[cfg(feature = "slow_tests")]
    #[rstest::rstest]
    #[case(1)]
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn test_preproc(#[case] parallelism: usize) {
        assert!(parallelism > 0);
        use crate::kms::{KeyGenPreprocRequest, KeyGenPreprocStatusEnum};

        let (kms_servers, kms_clients, internal_client) =
            threshold_handles(StorageVersion::Dev, TEST_PARAM_PATH).await;

        let request_ids: Vec<_> = (0..parallelism)
            .map(|j| RequestId::derive(&format!("test_preproc_{j}")).unwrap())
            .collect();
        let request_id_nok = RequestId::derive("not ok").unwrap();

        let reqs: Vec<_> = request_ids
            .iter()
            .map(|req_id| {
                internal_client
                    .preproc_request(req_id, Some(ParamChoice::Test))
                    .unwrap()
            })
            .collect();

        let mut tasks_gen = JoinSet::new();
        for req in &reqs {
            for i in 1..=AMOUNT_PARTIES as u32 {
                let mut cur_client = kms_clients.get(&i).unwrap().clone();
                let req_clone = req.clone();
                tasks_gen.spawn(async move {
                    cur_client
                        .key_gen_preproc(tonic::Request::new(req_clone))
                        .await
                });
            }
        }

        let mut responses_gen = Vec::new();
        while let Some(resp) = tasks_gen.join_next().await {
            responses_gen.push(resp.unwrap().unwrap().into_inner());
        }
        assert_eq!(responses_gen.len(), AMOUNT_PARTIES * parallelism);

        // Check status of preproc request
        async fn test_preproc_status(
            request: KeyGenPreprocRequest,
            expected_res: KeyGenPreprocStatusEnum,
            kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
        ) {
            let responses = get_preproc_status(request, kms_clients).await;

            for resp in responses {
                let expected: i32 = expected_res.into();
                assert_eq!(resp.result, expected);
            }
        }

        // This request should give us the correct status
        for request_id in &request_ids {
            let req_status_ok = internal_client
                .preproc_request(request_id, Some(ParamChoice::Test))
                .unwrap();
            test_preproc_status(
                req_status_ok.clone(),
                KeyGenPreprocStatusEnum::InProgress,
                &kms_clients,
            )
            .await;
        }

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
            tokio::time::sleep(std::time::Duration::from_secs(15 * parallelism as u64)).await;

            let mut done = true;
            for req in &reqs {
                let preproc_status = get_preproc_status(req.clone(), &kms_clients).await;
                finished = preproc_status
                    .into_iter()
                    .filter(|x| x.result == finished_enum)
                    .collect();

                if finished.len() != AMOUNT_PARTIES {
                    done = false;
                }
            }

            if done {
                break;
            }
        }

        //Make sure we did break because preproc is finished and not because of timeout
        assert_eq!(finished.len(), AMOUNT_PARTIES * parallelism);

        for handle in kms_servers.values() {
            handle.abort()
        }
        for (_, handle) in kms_servers {
            assert!(handle.await.unwrap_err().is_cancelled());
        }
    }

    //Helper function to launch dkg
    #[cfg(feature = "slow_tests")]
    async fn launch_dkg(
        req_keygen: crate::kms::KeyGenRequest,
        kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
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

        for handle in kms_servers.values() {
            handle.abort()
        }
        for (_, handle) in kms_servers {
            assert!(handle.await.unwrap_err().is_cancelled());
        }
    }
}

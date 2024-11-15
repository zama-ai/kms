use crate::cryptography::internal_crypto_types::{
    PrivateEncKey, PrivateSigKey, PublicEncKey, PublicSigKey, SigncryptionPair,
    SigncryptionPrivKey, SigncryptionPubKey,
};
use crate::cryptography::signcryption::{
    decrypt_signcryption, ephemeral_encryption_key_generation, hash_element,
    insecure_decrypt_ignoring_signature, internal_verify_sig, Reencrypt,
};
use crate::cryptography::{internal_crypto_types::Signature, signcryption::check_normalized};
use crate::kms::{
    FheType, ReencryptionRequest, ReencryptionRequestPayload, ReencryptionResponse,
    ReencryptionResponsePayload, RequestId,
};
use crate::rpc::rpc_types::{
    alloy_to_protobuf_domain, FheTypeResponse, MetaResponse, Plaintext, CURRENT_FORMAT_VERSION,
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
use distributed_decryption::execution::tfhe_internals::parameters::{
    AugmentedCiphertextParameters, DKGParams,
};
use rand::SeedableRng;
use std::collections::HashSet;
use tfhe::shortint::ClassicPBSParameters;
use wasm_bindgen::prelude::*;

cfg_if::cfg_if! {
    if #[cfg(feature = "non-wasm")] {
        use tfhe::zk::CompactPkePublicParams;
        use crate::cryptography::central_kms::{compute_handle, BaseKmsStruct};
        use crate::get_exactly_one;
        use crate::kms::DecryptionResponse;
        use crate::kms::ParamChoice;
        use crate::kms::{
            CrsGenRequest, CrsGenResult, TypedCiphertext, DecryptionRequest, DecryptionResponsePayload,
            KeyGenPreprocRequest, KeyGenRequest, KeyGenResult, VerifyProvenCtRequest, VerifyProvenCtResponse,
        };
        use crate::rpc::rpc_types::BaseKms;
        use crate::rpc::rpc_types::PubDataType;
        use crate::rpc::rpc_types::{
            PublicKeyType, WrappedPublicKeyOwned,
        };
        use crate::storage::read_all_data_versioned;
        use crate::storage::Storage;
        use crate::{storage::StorageReader};
        use std::collections::HashMap;
        use std::fmt;
        use std::str::FromStr;
        use tfhe::ProvenCompactCiphertextList;
        use tfhe::ServerKey;
        use tfhe_versionable::{Versionize, Unversionize};
    }
}

/// Helper method for combining reconstructed messages after decryption.
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
    fhe_type: FheType,
    pt: Vec<u8>,
    ct: Vec<u8>,
    // request
    request: Option<ReencryptionRequest>,
    eph_sk: PrivateEncKey,
    eph_pk: PublicEncKey,
    // response
    agg_resp: Vec<ReencryptionResponse>,
}

// TODO it would make sense to separate the wasm specific stuff into a separate file

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
/// Care must be taken when new code is introduced to core/service
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
/// u128, anyhow::Result, and so on cannot be used.
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
/// access to nvm:
/// ```
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
// Rather complicated cfg so that we do not compile this module for grpc-client.
#[cfg(all(not(feature = "non-wasm"), not(feature = "grpc-client")))]
pub mod js_api {
    use crate::kms::Eip712DomainMsg;
    use crate::kms::ParamChoice;
    use crate::rpc::rpc_types::protobuf_to_alloy_domain;
    use crypto_box::aead::{Aead, AeadCore};
    use crypto_box::{Nonce, SalsaBox};
    use distributed_decryption::execution::tfhe_internals::parameters::BC_PARAMS_SAM_SNS;

    use super::*;

    #[wasm_bindgen]
    pub fn public_sig_key_to_u8vec(pk: &PublicSigKey) -> Vec<u8> {
        pk.pk().to_sec1_bytes().to_vec()
    }

    #[wasm_bindgen]
    pub fn u8vec_to_public_sig_key(v: &[u8]) -> Result<PublicSigKey, JsError> {
        Ok(PublicSigKey::new(
            k256::ecdsa::VerifyingKey::from_sec1_bytes(v)
                .map_err(|e| JsError::new(&e.to_string()))?,
        ))
    }

    #[wasm_bindgen]
    pub fn private_sig_key_to_u8vec(sk: &PrivateSigKey) -> Result<Vec<u8>, JsError> {
        serialize(sk).map_err(|e| JsError::new(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn u8vec_to_private_sig_key(v: &[u8]) -> Result<PrivateSigKey, JsError> {
        deserialize(v).map_err(|e| JsError::new(&e.to_string()))
    }

    /// Instantiate a new client.
    ///
    /// * `server_addrs` - a list of KMS server EIP-55 addresses,
    /// must be prefixed with "0x".
    ///
    /// * `client_address_hex` - the client (wallet) address in hex,
    /// must be prefixed with "0x".
    ///
    /// * `param_choice` - the parameter choice, which can be either `"test"` or `"default"`.
    /// The "default" parameter choice is selected if no matching string is found.
    #[wasm_bindgen]
    pub fn new_client(
        server_addrs: Vec<String>,
        client_address_hex: &str,
        param_choice: &str,
    ) -> Result<Client, JsError> {
        console_error_panic_hook::set_once();

        let params = match ParamChoice::from_str_name(param_choice) {
            Some(choice) => choice.into(),
            None => BC_PARAMS_SAM_SNS,
        };

        let client_address = alloy_primitives::Address::parse_checksummed(client_address_hex, None)
            .map_err(|e| JsError::new(&e.to_string()))?;

        let server_identities = ServerIdentities::Addrs(
            server_addrs
                .into_iter()
                .map(|s| {
                    alloy_primitives::Address::parse_checksummed(s, None)
                        .map_err(|e| JsError::new(&e.to_string()))
                })
                .collect::<Result<Vec<_>, JsError>>()?,
        );

        Ok(Client {
            rng: Box::new(AesRng::from_entropy()),
            server_identities,
            client_address,
            client_sk: None,
            params: params,
        })
    }

    #[wasm_bindgen]
    pub fn get_server_addrs(client: &Client) -> Vec<String> {
        client
            .get_server_addrs()
            .unwrap()
            .iter()
            .map(|addr| addr.to_string())
            .collect()
    }

    #[wasm_bindgen]
    pub fn get_client_secret_key(client: &Client) -> Option<PrivateSigKey> {
        client.client_sk.clone()
    }

    #[wasm_bindgen]
    pub fn get_client_address(client: &Client) -> String {
        let checksummed = client.client_address.to_checksum_buffer(None);
        checksummed.to_string()
    }

    #[wasm_bindgen]
    #[cfg(feature = "wasm_tests")]
    pub fn buf_to_transcript(buf: &[u8]) -> TestingReencryptionTranscript {
        console_error_panic_hook::set_once();
        bincode::deserialize(buf).unwrap()
    }

    #[wasm_bindgen]
    #[cfg(feature = "wasm_tests")]
    pub fn transcript_to_parsed_req(
        transcript: &TestingReencryptionTranscript,
    ) -> ParsedReencryptionRequest {
        ParsedReencryptionRequest::try_from(transcript.request.as_ref().unwrap()).unwrap()
    }

    #[wasm_bindgen]
    #[cfg(feature = "wasm_tests")]
    pub fn transcript_to_parsed_req_js(transcript: &TestingReencryptionTranscript) -> JsValue {
        let parsed = transcript_to_parsed_req(&transcript);
        let parsed_hex = ParsedReencryptionRequestHex::from(&parsed);
        serde_wasm_bindgen::to_value(&parsed_hex).unwrap()
    }

    #[wasm_bindgen]
    #[cfg(feature = "wasm_tests")]
    pub fn transcript_to_eip712domain(
        transcript: &TestingReencryptionTranscript,
    ) -> Eip712DomainMsg {
        transcript.request.as_ref().unwrap().domain.clone().unwrap()
    }

    #[wasm_bindgen]
    #[cfg(feature = "wasm_tests")]
    pub fn transcript_to_eip712domain_js(transcript: &TestingReencryptionTranscript) -> JsValue {
        let domain = transcript_to_eip712domain(transcript);
        serde_wasm_bindgen::to_value(&domain).unwrap()
    }

    #[wasm_bindgen]
    #[cfg(feature = "wasm_tests")]
    pub fn transcript_to_response(
        transcript: &TestingReencryptionTranscript,
    ) -> Vec<ReencryptionResponse> {
        transcript.agg_resp.clone()
    }

    #[wasm_bindgen]
    #[cfg(feature = "wasm_tests")]
    pub fn transcript_to_response_js(transcript: &TestingReencryptionTranscript) -> JsValue {
        let agg_resp = transcript_to_response(transcript);
        resp_to_js(agg_resp)
    }

    #[wasm_bindgen]
    #[cfg(feature = "wasm_tests")]
    pub fn transcript_to_enc_sk(transcript: &TestingReencryptionTranscript) -> PrivateEncKey {
        transcript.eph_sk.clone()
    }

    #[wasm_bindgen]
    #[cfg(feature = "wasm_tests")]
    pub fn transcript_to_enc_pk(transcript: &TestingReencryptionTranscript) -> PublicEncKey {
        transcript.eph_pk.clone()
    }

    #[wasm_bindgen]
    #[cfg(feature = "wasm_tests")]
    pub fn transcript_to_pt_js(transcript: &TestingReencryptionTranscript) -> JsValue {
        serde_wasm_bindgen::to_value(&transcript.pt).unwrap()
    }

    #[wasm_bindgen]
    #[cfg(feature = "wasm_tests")]
    pub fn transcript_to_client(transcript: &TestingReencryptionTranscript) -> Client {
        Client {
            rng: Box::new(AesRng::from_entropy()),
            server_identities: ServerIdentities::Addrs(transcript.server_addrs.clone()),
            client_address: transcript.client_address,
            client_sk: transcript.client_sk.clone(),
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

    #[derive(serde::Deserialize, serde::Serialize)]
    struct ReencryptionResponseHex {
        signature: String,
        payload: Option<String>,
    }

    #[cfg(feature = "wasm_tests")]
    fn resp_to_js(agg_resp: Vec<ReencryptionResponse>) -> JsValue {
        let mut out = vec![];
        for resp in agg_resp {
            let r = ReencryptionResponseHex {
                signature: hex::encode(&resp.signature),
                payload: match resp.payload {
                    Some(inner) => Some(hex::encode(serialize(&inner).unwrap())),
                    None => None,
                },
            };
            out.push(r);
        }

        serde_wasm_bindgen::to_value(&out).unwrap()
    }

    // Note: normally the result type should be a JsError
    // but JsError is very limited, it cannot be printed,
    // so it's difficult to append information to the error.
    // This is why we're using anyhow::Error.
    fn js_to_resp(json: JsValue) -> anyhow::Result<Vec<ReencryptionResponse>> {
        // first read the hex type
        let hex_resps: Vec<ReencryptionResponseHex> = serde_wasm_bindgen::from_value(json)
            .map_err(|e| anyhow::anyhow!("from_value error {e:?}"))?;

        // then convert the hex type into the type we need
        let mut out = vec![];
        for hex_resp in hex_resps {
            out.push(ReencryptionResponse {
                signature: hex::decode(&hex_resp.signature)?,
                payload: match hex_resp.payload {
                    Some(inner) => {
                        let buf = hex::decode(&inner)?;
                        Some(deserialize(&buf)?)
                    }
                    None => None,
                },
            });
        }
        Ok(out)
    }

    /// Process the reencryption response from JavaScript objects.
    /// The returned result is a byte array representing a plaintext of any length,
    /// postprocessing is returned to turn it into an integer.
    ///
    /// * `client` - client that wants to perform reencryption.
    ///
    /// * `request` - the initial reencryption request JS object.
    /// It can be set to null if `verify` is false.
    /// Otherwise the caller needs to give the following JS object.
    /// Note that `client_address` and `eip712_verifying_contract` follow EIP-55.
    /// ```
    /// {
    ///   signature: '15a4f9a8eb61459cfba7d103d8f911fb04ce91ecf841b34c49c0d56a70b896d20cbc31986188f91efc3842b7df215cee8acb40178daedb8b63d0ba5d199bce121c',
    ///   client_address: '0x17853A630aAe15AED549B2B874de08B73C0F59c5',
    ///   enc_key: '2000000000000000df2fcacb774f03187f3802a27259f45c06d33cefa68d9c53426b15ad531aa822',
    ///   ciphertext_handle: '0748b542afe2353c86cb707e3d21044b0be1fd18efc7cbaa6a415af055bfb358',
    ///   eip712_verifying_contract: '0x66f9664f97F2b50F62D13eA064982f936dE76657'
    /// }
    /// ```
    ///
    /// * `eip712_domain` - the EIP-712 domain JS object.
    /// It can be set to null if `verify` is false.
    /// Otherwise the caller needs to give the following JS object.
    /// Note that `salt` is optional and `verifying_contract` follows EIP-55,
    /// additionally, `chain_id` is an array of u8.
    /// ```
    /// {
    ///   name: 'Authorization token',
    ///   version: '1',
    ///   chain_id: [
    ///     70, 31, 0, 0, 0, 0, 0, 0, 0,
    ///      0,  0, 0, 0, 0, 0, 0, 0, 0,
    ///      0,  0, 0, 0, 0, 0, 0, 0, 0,
    ///      0,  0, 0, 0, 0
    ///   ],
    ///   verifying_contract: '0x66f9664f97F2b50F62D13eA064982f936dE76657',
    ///   salt: []
    /// }
    /// ```
    ///
    /// * `agg_resp` - the response JS object from the gateway.
    /// It has two fields like so, both are hex encoded byte arrays.
    /// ```
    /// [
    ///   {
    ///     signature: '69e7e040cab157aa819015b321c012dccb1545ffefd325b359b492653f0347517e28e66c572cdc299e259024329859ff9fcb0096e1ce072af0b6e1ca1fe25ec6',
    ///     payload: '0100000029...'
    ///   }
    /// ]
    /// ```
    ///
    /// * `enc_pk` - The ephemeral public key.
    ///
    /// * `enc_sk` - The ephemeral secret key.
    ///
    /// * `verify` - Whether to perform signature verification for the response.
    /// It is insecure if `verify = false`!
    #[wasm_bindgen]
    pub fn process_reencryption_resp_from_js(
        client: &mut Client,
        request: JsValue,
        eip712_domain: JsValue,
        agg_resp: JsValue,
        enc_pk: &PublicEncKey,
        enc_sk: &PrivateEncKey,
        verify: bool,
    ) -> Result<Vec<u8>, JsError> {
        let agg_resp = js_to_resp(agg_resp)
            .map_err(|e| JsError::new(&format!("response parsing failed with error {}", e)))?;
        let eip712_domain = if eip712_domain.is_null() || eip712_domain.is_undefined() {
            None
        } else {
            let pb_domain = serde_wasm_bindgen::from_value(eip712_domain)
                .map_err(|e| JsError::new(&format!("domain parsing failed with error {}", e)))?;
            Some(pb_domain)
        };
        let request = if request.is_null() || request.is_undefined() {
            None
        } else {
            Some(ParsedReencryptionRequest::try_from(request)?)
        };
        process_reencryption_resp(
            client,
            request,
            eip712_domain,
            agg_resp,
            enc_pk,
            enc_sk,
            verify,
        )
    }

    /// Process the reencryption response from Rust objects.
    /// Consider using [process_reencryption_resp_from_js]
    /// when using the JS API.
    /// The result is a byte array representing a plaintext of any length.
    ///
    /// * `client` - client that wants to perform reencryption.
    ///
    /// * `request` - the initial reencryption request.
    /// Must be given if `verify` is true.
    ///
    /// * `eip712_domain` - the EIP-712 domain.
    /// Must be given if `verify` is true.
    ///
    /// * `agg_resp` - the vector of reencryption responses.
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
        request: Option<ParsedReencryptionRequest>,
        eip712_domain: Option<Eip712DomainMsg>,
        agg_resp: Vec<ReencryptionResponse>,
        enc_pk: &PublicEncKey,
        enc_sk: &PrivateEncKey,
        verify: bool,
    ) -> Result<Vec<u8>, JsError> {
        // if verify is true, then request and eip712 domain must exist
        let reenc_resp = if verify {
            let request = request.ok_or(JsError::new("missing request"))?;
            let pb_domain = eip712_domain.ok_or(JsError::new("missing eip712 domain"))?;
            let eip712_domain =
                protobuf_to_alloy_domain(&pb_domain).map_err(|e| JsError::new(&e.to_string()))?;
            client.process_reencryption_resp(&request, &eip712_domain, &agg_resp, enc_pk, enc_sk)
        } else {
            client.insecure_process_reencryption_resp(&agg_resp, enc_pk, enc_sk)
        };
        match reenc_resp {
            Ok(resp) => Ok(resp.bytes),
            Err(e) => Err(JsError::new(&e.to_string())),
        }
    }
}

/// Validity of this struct is not checked.
#[wasm_bindgen]
pub struct ParsedReencryptionRequest {
    // We allow dead_code because these are required to parse from JSON
    #[allow(dead_code)]
    signature: alloy_primitives::Signature,
    #[allow(dead_code)]
    client_address: alloy_primitives::Address,
    enc_key: Vec<u8>,
    ciphertext_digest: Vec<u8>,
    eip712_verifying_contract: alloy_primitives::Address,
}

impl ParsedReencryptionRequest {
    pub fn new(
        signature: alloy_primitives::Signature,
        client_address: alloy_primitives::Address,
        enc_key: Vec<u8>,
        ciphertext_digest: Vec<u8>,
        eip712_verifying_contract: alloy_primitives::Address,
    ) -> Self {
        Self {
            signature,
            client_address,
            enc_key,
            ciphertext_digest,
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
    ciphertext_digest: String,
    eip712_verifying_contract: String,
}

impl TryFrom<&ParsedReencryptionRequestHex> for ParsedReencryptionRequest {
    type Error = JsError;

    fn try_from(req_hex: &ParsedReencryptionRequestHex) -> Result<Self, Self::Error> {
        let signature_buf = hex_decode_js_err(&req_hex.signature)?;
        let signature = alloy_primitives::Signature::try_from(signature_buf.as_slice())
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
            ciphertext_digest: hex_decode_js_err(&req_hex.ciphertext_digest)?,
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
            ciphertext_digest: hex::encode(&value.ciphertext_digest),
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

        let signature = alloy_primitives::Signature::try_from(value.signature.as_slice())?;

        let client_address =
            alloy_primitives::Address::parse_checksummed(&payload.client_address, None)?;

        let eip712_verifying_contract =
            alloy_primitives::Address::parse_checksummed(domain.verifying_contract.clone(), None)?;

        let out = Self {
            signature,
            client_address,
            enc_key: payload.enc_key.clone(),
            ciphertext_digest: payload.ciphertext_digest.clone(),
            eip712_verifying_contract,
        };
        Ok(out)
    }
}

/// Compute the link as (eip712_signing_hash(pk, domain) || ciphertext digest).
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

    Ok([pk_digest, req.ciphertext_digest.clone()].concat())
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
    /// from a [PublicStorage].
    ///
    /// * `server_pks` - a set of tkms core public keys.
    ///
    /// * `client_address` - the client wallet address.
    ///
    /// * `client_sk` - client private key.
    ///   This is optional because sometimes the private signing key is kept
    ///   in a secure location, e.g., hardware wallet or web extension.
    ///   Calling functions that requires `client_sk` when it is None will return an error.
    ///
    /// * `params` - the FHE parameters.
    pub fn new(
        server_pks: Vec<PublicSigKey>,
        client_address: alloy_primitives::Address,
        client_sk: Option<PrivateSigKey>,
        params: DKGParams,
    ) -> Self {
        Client {
            rng: Box::new(AesRng::from_entropy()), // todo should be argument
            server_identities: ServerIdentities::Pks(server_pks),
            client_address,
            client_sk,
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
        params: &DKGParams,
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

        Ok(Client::new(pks, client_address, Some(client_sk), *params))
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
        param: Option<ParamChoice>,
        eip712_domain: Option<Eip712Domain>,
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

        let domain = match eip712_domain {
            Some(eip712_domain) => Some(alloy_to_protobuf_domain(&eip712_domain)?),
            None => None,
        };

        Ok(KeyGenRequest {
            params: parsed_param,
            preproc_id,
            request_id: Some(request_id.clone()),
            domain,
        })
    }

    #[cfg(feature = "non-wasm")]
    pub fn crs_gen_request(
        &self,
        request_id: &RequestId,
        max_num_bits: Option<u32>,
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
            max_num_bits,
            request_id: Some(request_id.clone()),
            domain: None,
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
    /// the majority and ensuring that this involves agreement by at least
    /// `min_agree_count` of the parties.
    #[cfg(feature = "non-wasm")]
    pub async fn process_distributed_crs_result<S: StorageReader>(
        &self,
        request_id: &RequestId,
        results: Vec<CrsGenResult>,
        storage_readers: &[S],
        min_agree_count: u32,
    ) -> anyhow::Result<CompactPkePublicParams> {
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
                let pp: CompactPkePublicParams = storage.read_data(&url).await?;
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
            version: CURRENT_FORMAT_VERSION,
            ciphertexts,
            key_id: Some(key_id.clone()),
            domain: Some(domain_msg),
            request_id: Some(request_id.clone()),
            acl_address: Some(hex::encode(acl_address)),
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
        let client_sk = some_or_err(
            self.client_sk.clone(),
            "missing client signing key".to_string(),
        )?;

        let ciphertext_digest = hash_element(&ciphertext);
        let (enc_pk, enc_sk) = ephemeral_encryption_key_generation(&mut self.rng);
        let sig_payload = ReencryptionRequestPayload {
            version: CURRENT_FORMAT_VERSION,
            enc_key: serialize(&enc_pk)?,
            client_address: self.client_address.to_checksum(None),
            fhe_type: fhe_type as i32,
            key_id: Some(key_id.clone()),
            ciphertext: Some(ciphertext),
            ciphertext_digest,
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
        let pk_type: PublicKeyType = crate::storage::read_versioned_at_request_id(
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
    ) -> anyhow::Result<Option<CompactPkePublicParams>> {
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
    ) -> anyhow::Result<CompactPkePublicParams> {
        let url = storage.compute_url(&crs_id.to_string(), &PubDataType::CRS.to_string())?;
        let pp: CompactPkePublicParams = storage.read_data(&url).await?;
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
    ) -> anyhow::Result<Vec<Plaintext>> {
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
        let serialized_plaintexts = some_or_err(
            pivot.payload.to_owned(),
            "No payload in pivot response for decryption".to_owned(),
        )?
        .plaintexts;

        let pts = serialized_plaintexts
            .into_iter()
            .map(|pt| deserialize(&pt))
            .collect::<Result<Vec<Plaintext>, _>>()?;

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
    ) -> anyhow::Result<Plaintext> {
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
            // Vec<ResiduePoly<Z128>>.
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
    ) -> anyhow::Result<Plaintext> {
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
                if req.version != pivot_payload.version() {
                    return Err(anyhow_error_and_log(
                        "Version in the decryption request is incorrect",
                    ));
                }
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
    ) -> anyhow::Result<Option<(FheType, Vec<ReencryptionResponsePayload>)>> {
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

        // resp_parsed is guaranteed to be non empty since [validate_reenc_resp] passed
        Ok(Some((resp_parsed[0].fhe_type(), resp_parsed)))
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
    ) -> anyhow::Result<Plaintext> {
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

        decrypt_signcryption(
            &payload.signcrypted_ciphertext,
            &link,
            client_keys,
            &cur_verf_key,
        )
    }

    /// Decrypt the reencryption response from the centralized KMS.
    /// This function does *not* do any verification and is thus insecure and should be used only for testing.
    /// TODO hide behind flag for insecure function?
    fn insecure_centralized_reencryption_resp(
        &self,
        agg_resp: &[ReencryptionResponse],
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Plaintext> {
        let resp = some_or_err(agg_resp.last(), "Response does not exist".to_owned())?;
        let payload = some_or_err(resp.payload.clone(), "Payload does not exist".to_owned())?;

        crate::cryptography::signcryption::insecure_decrypt_ignoring_signature(
            &payload.signcrypted_ciphertext,
            client_keys,
        )
    }

    /// Decrypt the reencryption responses from the threshold KMS and verify that the signatures are valid
    fn threshold_reencryption_resp(
        &self,
        client_request: &ParsedReencryptionRequest,
        eip712_domain: &Eip712Domain,
        agg_resp: &[ReencryptionResponse],
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Plaintext> {
        let (fhe_type, validated_resps) = some_or_err(
            self.validate_reenc_req_resp(client_request, eip712_domain, agg_resp)?,
            "Could not validate request".to_owned(),
        )?;
        let degree = some_or_err(
            validated_resps.first(),
            "No valid responses parsed".to_string(),
        )?
        .degree as usize;
        let sharings = self.recover_sharings(&validated_resps, fhe_type, client_keys)?;
        let amount_shares = validated_resps.len();
        // TODO: in general this is not true, degree isn't a perfect proxy for num_parties
        let num_parties = 3 * degree + 1;
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
        let pbs_params = self
            .params
            .get_params_basics_handle()
            .to_classic_pbs_parameters();

        let recon_blocks = reconstruct_message(Some(decrypted_blocks), &pbs_params)?;
        decrypted_blocks_to_plaintext(&pbs_params, fhe_type, recon_blocks)
    }

    /// Decrypt the reencryption response from the threshold KMS.
    /// This function does *not* do any verification and is thus insecure and should be used only for testing.
    /// TODO hide behind flag for insecure function?
    fn insecure_threshold_reencryption_resp(
        &self,
        agg_resp: &[ReencryptionResponse],
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Plaintext> {
        // Recover sharings
        let mut opt_sharings = None;
        let degree = some_or_err(
            some_or_err(agg_resp.first().as_ref(), "empty responses".to_owned())?
                .payload
                .as_ref(),
            "empty payload".to_owned(),
        )?
        .degree as usize;

        // Trust all responses have all expected blocks
        for cur_resp in agg_resp {
            let payload = some_or_err(
                cur_resp.payload.clone(),
                "Payload does not exist".to_owned(),
            )?;
            let shares =
                insecure_decrypt_ignoring_signature(&payload.signcrypted_ciphertext, client_keys)?;

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
        let pbs_params = self
            .params
            .get_params_basics_handle()
            .to_classic_pbs_parameters();
        let recon_blocks = reconstruct_message(Some(decrypted_blocks), &pbs_params)?;

        //Deduce fhe_type from recon_blocks and message_modulus
        let bits_in_block = pbs_params.message_modulus_log() as usize;
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

        decrypted_blocks_to_plaintext(&pbs_params, fhe_type, recon_blocks)
    }

    /// Decrypts the reencryption responses and decodes the responses onto the Shamir shares
    /// that the servers should have encrypted.
    fn recover_sharings(
        &self,
        agg_resp: &[ReencryptionResponsePayload],
        fhe_type: FheType,
        client_keys: &SigncryptionPair,
    ) -> anyhow::Result<Vec<ShamirSharings<ResiduePoly<Z128>>>> {
        let num_blocks = num_blocks(
            fhe_type,
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
                &cur_resp.signcrypted_ciphertext,
                &cur_resp.digest,
                client_keys,
                &cur_verf_key,
            ) {
                Ok(decryption_share) => {
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
        Ok(sharings)
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
    let contract_address = alloy_primitives::Address::from_str(&req.contract_address)?;
    let client_address = alloy_primitives::Address::from_str(&req.client_address)?;
    let acl_address = alloy_primitives::Address::from_str(&req.acl_address)?;

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
    let affine = pk.pk().as_ref();
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

// TODO this module should be behind cfg(test) normally
// but we need it in other places such as the connector
// and cfg(test) is not compiled by tests in other crates.
// Consider putting this behind a test-specific crate.
#[cfg(any(test, feature = "testing"))]
#[cfg(feature = "non-wasm")]
pub mod test_tools {
    use super::*;
    use crate::conf::centralized::CentralizedConfig;
    use crate::conf::threshold::{PeerConf, ThresholdConfig};
    use crate::consts::{BASE_PORT, DEC_CAPACITY, DEFAULT_PROT, DEFAULT_URL, MIN_DEC_CACHE};
    use crate::kms::core_service_endpoint_client::CoreServiceEndpointClient;
    use crate::rpc::central_rpc::server_handle;
    use crate::storage::{FileStorage, RamStorage, Storage, StorageType, StorageVersion};
    use crate::threshold::threshold_kms::{threshold_server_init, threshold_server_start};
    use crate::util::key_setup::test_tools::setup::ensure_testing_material_exists;
    use distributed_decryption::execution::tfhe_internals::parameters::DKGParams;
    use itertools::Itertools;
    use std::str::FromStr;
    use tokio::task::JoinHandle;
    use tonic::transport::{Channel, Uri};

    #[cfg(feature = "slow_tests")]
    use crate::util::key_setup::test_tools::setup::ensure_default_material_exists;

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
        ensure_testing_material_exists().await;
        #[cfg(feature = "slow_tests")]
        ensure_default_material_exists().await;

        let mut handles = Vec::new();
        tracing::info!("Spawning servers...");
        let amount = priv_storage.len();
        let timeout_secs = 60u64;
        let grpc_max_message_size = 2 * 10 * 1024 * 1024; // 20 MiB
        for i in 1..=amount {
            let cur_pub_storage = pub_storage[i - 1].to_owned();
            let cur_priv_storage = priv_storage[i - 1].to_owned();
            let peer_configs = default_peer_configs(amount);
            handles.push(tokio::spawn(async move {
                let config = ThresholdConfig {
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

    /// try to connect to a URI and retry every 200ms for 25 times before giving up after 5 seconds.
    async fn connect_with_retry(uri: Uri) -> Channel {
        tracing::info!("Client connecting to {}", uri);
        const RETRY_COUNT: usize = 25;
        let mut channel = Channel::builder(uri.clone()).connect().await;
        let mut tries = 0usize;
        loop {
            match channel {
                Ok(_) => {
                    break;
                }
                Err(_) => {
                    tracing::info!("Retrying: Client connection to {}", uri);
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    channel = Channel::builder(uri.clone()).connect().await;
                    tries += 1;
                    if tries > RETRY_COUNT {
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
            let channel = connect_with_retry(uri).await;
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
        ensure_testing_material_exists().await;
        #[cfg(feature = "slow_tests")]
        ensure_default_material_exists().await;

        let server_handle = tokio::spawn(async move {
            let url = format!("{DEFAULT_PROT}://{DEFAULT_URL}:{}", BASE_PORT + 1);
            let config = CentralizedConfig {
                url,
                grpc_max_message_size: 2 * 10 * 1024 * 1024, // 20 MiB to allow for 2048 bit encryptions
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
        let channel = connect_with_retry(uri).await;
        let client = CoreServiceEndpointClient::new(channel);
        (server_handle, client)
    }

    /// Read the centralized keys for testing from `centralized_key_path` and construct a KMS
    /// server, client end-point connection (which is needed to communicate with the server) and
    /// an internal client (for constructing requests and validating responses).
    pub async fn centralized_handles(
        storage_version: StorageVersion,
        param: &DKGParams,
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
        let internal_client = Client::new_client(client_storage, pub_storage, param)
            .await
            .unwrap();
        (kms_server, kms_client, internal_client)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{recover_ecdsa_public_key_from_signature, Client};
    use crate::client::assemble_metadata_alloy;
    #[cfg(feature = "wasm_tests")]
    use crate::client::TestingReencryptionTranscript;
    use crate::client::{ParsedReencryptionRequest, ServerIdentities};
    #[cfg(feature = "wasm_tests")]
    use crate::consts::TEST_CENTRAL_KEY_ID;
    use crate::consts::TEST_PARAM;
    use crate::consts::TEST_THRESHOLD_KEY_ID;
    #[cfg(feature = "slow_tests")]
    use crate::consts::{DEFAULT_CENTRAL_KEY_ID, DEFAULT_THRESHOLD_KEY_ID};
    #[cfg(feature = "slow_tests")]
    use crate::cryptography::central_kms::tests::get_default_keys;
    use crate::cryptography::central_kms::{compute_handle, gen_sig_keys, BaseKmsStruct};
    use crate::cryptography::internal_crypto_types::Signature;
    use crate::cryptography::signcryption::Reencrypt;
    use crate::kms::core_service_endpoint_client::CoreServiceEndpointClient;
    use crate::kms::{FheType, ParamChoice, TypedCiphertext};
    use crate::rpc::rpc_types::RequestIdGetter;
    use crate::rpc::rpc_types::{protobuf_to_alloy_domain, BaseKms, PubDataType};
    use crate::storage::StorageReader;
    use crate::storage::{FileStorage, RamStorage, StorageType, StorageVersion};
    use crate::util::file_handling::safe_read_element_versioned;
    #[cfg(feature = "wasm_tests")]
    use crate::util::file_handling::write_element;
    use crate::util::key_setup::test_tools::{
        compute_cipher_from_stored_key, compute_compressed_cipher_from_stored_key,
        load_pk_from_storage, purge, TypedPlaintext,
    };
    use crate::{
        client::num_blocks,
        kms::{Empty, RequestId},
    };
    use crate::{
        consts::{AMOUNT_PARTIES, THRESHOLD},
        kms::ReencryptionResponse,
    };
    use alloy_primitives::Bytes;
    use alloy_signer::Signer;
    use alloy_signer_local::PrivateKeySigner;
    use alloy_sol_types::SolStruct;
    use distributed_decryption::execution::tfhe_internals::parameters::DKGParams;
    #[cfg(feature = "wasm_tests")]
    use distributed_decryption::execution::tfhe_internals::parameters::PARAMS_TEST_BK_SNS;
    use rand::SeedableRng;
    use serial_test::serial;
    use std::collections::{hash_map::Entry, HashMap};
    use tfhe::zk::CompactPkePublicParams;
    use tfhe::ProvenCompactCiphertextList;
    use tfhe::Tag;
    use tokio::task::{JoinHandle, JoinSet};
    use tonic::transport::Channel;

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
        storage_version: StorageVersion,
        params: DKGParams,
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
        let internal_client = Client::new_client(client_storage, pub_storage, &params)
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn test_key_gen_centralized() {
        let request_id = RequestId::derive("test_key_gen_centralized").unwrap();
        // Delete potentially old data
        purge(None, None, &request_id.to_string()).await;
        key_gen_centralized(TEST_PARAM, &request_id, Some(ParamChoice::Test)).await;
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn default_key_gen_centralized() {
        use crate::consts::DEFAULT_PARAM;

        let request_id = RequestId::derive("default_key_gen_centralized").unwrap();
        // Delete potentially old data
        purge(None, None, &request_id.to_string()).await;
        key_gen_centralized(DEFAULT_PARAM, &request_id, Some(ParamChoice::Default)).await;
    }

    async fn key_gen_centralized(
        dkg_params: DKGParams,
        request_id: &RequestId,
        params: Option<ParamChoice>,
    ) {
        let (kms_server, mut kms_client, internal_client) =
            super::test_tools::centralized_handles(StorageVersion::Dev, &dkg_params).await;

        let gen_req = internal_client
            .key_gen_request(request_id, None, params, None)
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
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            response = kms_client
                .get_key_gen_result(tonic::Request::new(req_id.clone()))
                .await;
        }
        let inner_resp = response.unwrap().into_inner();
        let pub_storage = FileStorage::new_centralized(None, StorageType::PUB).unwrap();
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
        kms_server.abort();
        assert!(kms_server.await.unwrap_err().is_cancelled());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn test_crs_gen_manual() {
        let crs_req_id = RequestId::derive("test_crs_gen_manual").unwrap();
        // Delete potentially old data
        purge(None, None, &crs_req_id.to_string()).await;
        crs_gen_centralized_manual(&TEST_PARAM, &crs_req_id, Some(ParamChoice::Test)).await;
    }

    /// test centralized crs generation and do all the reading, processing and verification manually
    async fn crs_gen_centralized_manual(
        dkg_params: &DKGParams,
        request_id: &RequestId,
        params: Option<ParamChoice>,
    ) {
        let (kms_server, mut kms_client, internal_client) =
            super::test_tools::centralized_handles(StorageVersion::Dev, dkg_params).await;

        let max_num_bits = if params.unwrap() == ParamChoice::Test {
            Some(1)
        } else {
            // The default is 2048 which is too slow for tests, so we switch to 256
            Some(256)
        };
        let ceremony_req = internal_client
            .crs_gen_request(request_id, max_num_bits, params)
            .unwrap();

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

        // check that CRS signature is verified correctly for the current version
        let crs_unversioned: CompactPkePublicParams =
            safe_read_element_versioned(&crs_path).await.unwrap();
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

        kms_server.abort();
        assert!(kms_server.await.unwrap_err().is_cancelled());
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn default_crs_gen_centralized() {
        let crs_req_id = RequestId::derive("default_crs_gen_centralized").unwrap();
        // Delete potentially old data
        purge(None, None, &crs_req_id.to_string()).await;
        crs_gen_centralized(
            &crate::consts::DEFAULT_PARAM,
            &crs_req_id,
            Some(ParamChoice::Default),
            false,
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn test_crs_gen_centralized() {
        let crs_req_id = RequestId::derive("test_crs_gen_centralized").unwrap();
        // Delete potentially old data
        purge(None, None, &crs_req_id.to_string()).await;
        crs_gen_centralized(&TEST_PARAM, &crs_req_id, Some(ParamChoice::Test), false).await;
    }

    #[cfg(feature = "insecure")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn test_insecure_crs_gen_centralized() {
        let crs_req_id = RequestId::derive("test_insecure_crs_gen_centralized").unwrap();
        // Delete potentially old data
        purge(None, None, &crs_req_id.to_string()).await;
        crs_gen_centralized(&TEST_PARAM, &crs_req_id, Some(ParamChoice::Test), true).await;
    }

    #[cfg(feature = "insecure")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn default_insecure_crs_gen_centralized() {
        let crs_req_id = RequestId::derive("default_insecure_crs_gen_centralized").unwrap();
        // Delete potentially old data
        purge(None, None, &crs_req_id.to_string()).await;
        crs_gen_centralized(
            &crate::consts::DEFAULT_PARAM,
            &crs_req_id,
            Some(ParamChoice::Default),
            true,
        )
        .await;
    }

    /// test centralized crs generation via client interface
    async fn crs_gen_centralized(
        dkg_params: &DKGParams,
        crs_req_id: &RequestId,
        params: Option<ParamChoice>,
        insecure: bool,
    ) {
        let (kms_server, mut kms_client, internal_client) =
            super::test_tools::centralized_handles(StorageVersion::Dev, dkg_params).await;

        let max_num_bits = if params.unwrap() == ParamChoice::Test {
            Some(1)
        } else {
            // The default is 2048 which is too slow for tests, so we switch to 256
            Some(256)
        };
        let gen_req = internal_client
            .crs_gen_request(crs_req_id, max_num_bits, params)
            .unwrap();

        // response is currently empty
        tracing::debug!("making crs request, insecure? {insecure}");
        let mut response = match insecure {
            true => {
                #[cfg(feature = "insecure")]
                {
                    let gen_response = kms_client
                        .insecure_crs_gen(tonic::Request::new(gen_req.clone()))
                        .await
                        .unwrap();
                    assert_eq!(gen_response.into_inner(), Empty {});
                    kms_client
                        .get_insecure_crs_gen_result(crs_req_id.clone())
                        .await
                }
                #[cfg(not(feature = "insecure"))]
                {
                    panic!("cannot perform insecure crs gen")
                }
            }
            false => {
                let gen_response = kms_client
                    .crs_gen(tonic::Request::new(gen_req.clone()))
                    .await
                    .unwrap();
                assert_eq!(gen_response.into_inner(), Empty {});
                kms_client.get_crs_gen_result(crs_req_id.clone()).await
            }
        };

        let mut ctr = 0;
        while response.is_err() && ctr < 200 {
            // Sleep to give the server some time to complete CRS generation
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            response = kms_client
                .get_crs_gen_result(tonic::Request::new(crs_req_id.clone()))
                .await;
            ctr += 1;
        }
        let inner_resp = response.unwrap().into_inner();
        let pub_storage = FileStorage::new_centralized(None, StorageType::PUB).unwrap();
        let pp = internal_client
            .process_get_crs_resp(&inner_resp, &pub_storage)
            .await
            .unwrap()
            .unwrap();

        // Validate the CRS as a sanity check
        verify_pp(dkg_params, &pp).await;

        kms_server.abort();
        assert!(kms_server.await.unwrap_err().is_cancelled());
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn default_verify_proven_ct_centralized() {
        let proven_ct_id = RequestId::derive("default_verify_proven_ct_centralized").unwrap();
        verify_proven_ct_centralized(
            &crate::consts::DEFAULT_PARAM,
            &proven_ct_id,
            &crate::consts::DEFAULT_CRS_ID,
            &DEFAULT_CENTRAL_KEY_ID.to_string(),
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn test_verify_proven_ct_centralized() {
        let proven_ct_id = RequestId::derive("test_verify_proven_ct_centralized").unwrap();
        verify_proven_ct_centralized(
            &TEST_PARAM,
            &proven_ct_id,
            &crate::consts::TEST_CRS_ID,
            &crate::consts::TEST_CENTRAL_KEY_ID.to_string(),
        )
        .await;
    }

    /// test centralized ZK probing via client interface
    async fn verify_proven_ct_centralized(
        dkg_params: &DKGParams,
        proven_ct_id: &RequestId,
        crs_req_id: &RequestId,
        key_handle: &str,
    ) {
        let message = 32;
        let (kms_server, mut kms_client, internal_client) =
            super::test_tools::centralized_handles(StorageVersion::Dev, dkg_params).await;

        // next use the verify endpoint to check the proof
        // for this we need to read the key
        tracing::info!("Starting zk verification");
        let key_id = RequestId {
            request_id: key_handle.to_owned(),
        };
        let pub_storage = FileStorage::new_centralized(None, StorageType::PUB).unwrap();
        let pp = internal_client
            .get_crs(crs_req_id, &pub_storage)
            .await
            .unwrap();

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

        let proven_ct = encrypt_and_prove(message, &pp, key_handle, &metadata).await;
        // Sanity check that the proof is valid
        let pk = load_pk_from_storage(None, key_handle).await;
        assert!(tfhe::zk::ZkVerificationOutCome::Valid == proven_ct.verify(&pp, &pk, &metadata));

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
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
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

        kms_server.abort();
        assert!(kms_server.await.unwrap_err().is_cancelled());
    }

    async fn verify_pp(dkg_params: &DKGParams, pp: &CompactPkePublicParams) {
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

        let max_msg_len = pp.k;
        let msgs = (0..max_msg_len)
            .map(|i| (i % dkg_params_handle.get_message_modulus().0) as u64)
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

    async fn encrypt_and_prove(
        msg: u8,
        pp: &CompactPkePublicParams,
        key_id: &str,
        metadata: &[u8],
    ) -> ProvenCompactCiphertextList {
        let pk = load_pk_from_storage(None, key_id).await;

        let mut compact_list_builder = ProvenCompactCiphertextList::builder(&pk);
        compact_list_builder.push_with_num_bits(msg, 8).unwrap();
        compact_list_builder
            .build_with_proof_packed(pp, metadata, tfhe::zk::ZkComputeLoad::Proof)
            .unwrap()
    }

    #[cfg(feature = "slow_tests")]
    #[rstest::rstest]
    #[case(1)]
    #[case(4)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn test_crs_gen_threshold(#[case] parallelism: usize) {
        // CRS generation is slow
        // so we set this as a slow test
        crs_gen_threshold(parallelism, &TEST_PARAM, Some(ParamChoice::Test), false).await
    }

    #[cfg(feature = "insecure")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn test_insecure_crs_gen_threshold() {
        crs_gen_threshold(1, &TEST_PARAM, Some(ParamChoice::Test), true).await
    }

    #[cfg(feature = "slow_tests")]
    #[cfg(feature = "insecure")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn default_insecure_crs_gen_threshold() {
        use crate::consts::DEFAULT_PARAM;

        crs_gen_threshold(1, &DEFAULT_PARAM, Some(ParamChoice::Default), true).await
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

    // Poll the client method function `f_to_poll` until there is a result
    // or error out until some timeout.
    // The requests from the `reqs` argument need to implement `RequestIdGetter`.
    macro_rules! par_poll_responses {
        ($parallelism:expr,$kms_clients:expr,$reqs:expr,$f_to_poll:ident) => {{
            const TRIES: usize = 20;
            let mut joined_responses = vec![];
            for count in 0..TRIES {
                joined_responses = vec![];
                tokio::time::sleep(std::time::Duration::from_secs(5 * $parallelism as u64)).await;

                let mut tasks_get = JoinSet::new();
                for req in &$reqs {
                    for i in 1..=AMOUNT_PARTIES as u32 {
                        let mut cur_client = $kms_clients.get(&i).unwrap().clone();
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
                let mut responses_get = Vec::new();
                while let Some(Ok((j, req_id, Ok(resp)))) = tasks_get.join_next().await {
                    responses_get.push((j, req_id, resp.into_inner()));
                }

                // add the responses in this iteration to the bigger vector
                joined_responses.append(&mut responses_get);
                if joined_responses.len() == AMOUNT_PARTIES * $parallelism {
                    break;
                }

                // fail if we can't find a response
                if count == TRIES - 1 {
                    panic!("could not get crs after {} tries", count);
                }
            }

            joined_responses
        }};
    }

    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    async fn crs_gen_threshold(
        parallelism: usize,
        param: &DKGParams,
        params: Option<ParamChoice>,
        insecure: bool,
    ) {
        assert!(parallelism > 0);
        let req_ids: Vec<RequestId> = (0..parallelism)
            .map(|j| RequestId::derive(&format!("crs_gen_threshold_{j}_{insecure}")).unwrap())
            .collect();

        // Ensure the test is idempotent
        for req_id in &req_ids {
            purge(None, None, &req_id.request_id).await;
        }

        // The threshold handle should only be started after the storage is purged
        // since the threshold parties will load the CRS from private storage
        let (kms_servers, kms_clients, internal_client) =
            threshold_handles(StorageVersion::Dev, *param).await;

        let max_num_bits = if params.unwrap() == ParamChoice::Test {
            Some(1)
        } else {
            // The default is 2048 which is too slow for tests, so we switch to 256
            Some(256)
        };
        let reqs: Vec<_> = (0..parallelism)
            .map(|j| {
                let request_id =
                    RequestId::derive(&format!("crs_gen_threshold_{j}_{insecure}")).unwrap();
                internal_client
                    .crs_gen_request(&request_id, max_num_bits, params)
                    .unwrap()
            })
            .collect();

        let mut tasks_gen = JoinSet::new();
        for req in &reqs {
            for i in 1..=AMOUNT_PARTIES as u32 {
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
            let resp = inner.unwrap().unwrap();
            responses_gen.push(resp.into_inner());
        }
        assert_eq!(responses_gen.len(), AMOUNT_PARTIES * parallelism);

        // wait a bit for the crs generation to finish
        let joined_responses =
            par_poll_responses!(parallelism, kms_clients, reqs, get_crs_gen_result);

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

            let min_count_agree = (THRESHOLD + 1) as u32;

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
                    final_responses[0..final_responses.len() - THRESHOLD].to_vec(),
                    &storage_readers,
                    min_count_agree,
                )
                .await
                .unwrap();

            // if there are only THRESHOLD results then we do not have consensus as at least THRESHOLD+1 is needed
            assert!(internal_client
                .process_distributed_crs_result(
                    &req_id,
                    final_responses[0..THRESHOLD].to_vec(),
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
            set_signatures(&mut final_responses_with_bad_sig, THRESHOLD, &bad_sig);

            let _pp = internal_client
                .process_distributed_crs_result(
                    &req_id,
                    final_responses_with_bad_sig.clone(),
                    &storage_readers,
                    min_count_agree,
                )
                .await
                .unwrap();

            // having [AMOUNT-THRESHOLD] wrong signatures won't work
            set_signatures(
                &mut final_responses_with_bad_sig,
                AMOUNT_PARTIES - THRESHOLD,
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

            // having [AMOUNT_PARTIES-(THRESHOLD+1)] wrong digests still works
            let mut final_responses_with_bad_digest = final_responses.clone();
            set_digests(
                &mut final_responses_with_bad_digest,
                AMOUNT_PARTIES - (THRESHOLD + 1),
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

            // having [AMOUNT_PARTIES-THRESHOLD] wrong digests will fail
            set_digests(
                &mut final_responses_with_bad_digest,
                AMOUNT_PARTIES - THRESHOLD,
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
        for handle in kms_servers.values() {
            handle.abort()
        }
        for (_, handle) in kms_servers {
            assert!(handle.await.unwrap_err().is_cancelled());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn test_verify_proven_ct_threshold() {
        verify_proven_ct_threshold(
            1,
            &crate::consts::TEST_CRS_ID,
            &crate::consts::TEST_THRESHOLD_KEY_ID,
            TEST_PARAM,
        )
        .await
    }

    #[cfg(feature = "slow_tests")]
    #[rstest::rstest]
    #[case(1)]
    #[case(4)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn default_verify_proven_ct_threshold(#[case] parallelism: usize) {
        verify_proven_ct_threshold(
            parallelism,
            &crate::consts::DEFAULT_CRS_ID,
            &crate::consts::DEFAULT_THRESHOLD_KEY_ID,
            crate::consts::DEFAULT_PARAM,
        )
        .await
    }

    async fn verify_proven_ct_threshold(
        parallelism: usize,
        crs_handle: &RequestId,
        key_handle: &RequestId,
        dkg_params: DKGParams,
    ) {
        assert!(parallelism > 0);

        // The threshold handle should only be started after the storage is purged
        // since the threshold parties will load the CRS from private storage
        let (kms_servers, kms_clients, internal_client) =
            threshold_handles(StorageVersion::Dev, dkg_params).await;

        let pub_storage = FileStorage::new_threshold(None, StorageType::PUB, 1).unwrap();
        let pp = internal_client
            .get_crs(crs_handle, &pub_storage)
            .await
            .unwrap();
        // Sanity check the pp
        verify_pp(&dkg_params, &pp).await;

        let message = 42;
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

        let proven_ct = encrypt_and_prove(message, &pp, &key_handle.to_string(), &metadata).await;
        // Sanity check that the proof is valid
        let pk = load_pk_from_storage(None, &key_handle.to_string()).await;
        assert!(tfhe::zk::ZkVerificationOutCome::Valid == proven_ct.verify(&pp, &pk, &metadata));

        let reqs: Vec<_> = (0..parallelism)
            .map(|j| {
                let request_id =
                    RequestId::derive(&format!("verify_proven_ct_threshold_{j}")).unwrap();
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

        let mut tasks_gen = JoinSet::new();
        for req in &reqs {
            for i in 1..=AMOUNT_PARTIES as u32 {
                let mut cur_client = kms_clients.get(&i).unwrap().clone();
                let req_clone = req.clone();
                tasks_gen.spawn(async move {
                    cur_client
                        .verify_proven_ct(tonic::Request::new(req_clone))
                        .await
                });
            }
        }
        let mut responses_gen = Vec::new();
        while let Some(inner) = tasks_gen.join_next().await {
            let resp = inner.unwrap().unwrap();
            responses_gen.push(resp.into_inner());
        }
        assert_eq!(responses_gen.len(), AMOUNT_PARTIES * parallelism);

        // wait a bit for the validation to finish
        let joined_responses =
            par_poll_responses!(parallelism, kms_clients, reqs, get_verify_proven_ct_result);

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

            let min_count_agree = (THRESHOLD + 1) as u32;

            let verify_proven_ct_sigs = internal_client
                .process_verify_proven_ct_resp(&joined_responses, min_count_agree)
                .unwrap();

            assert_eq!(verify_proven_ct_sigs.len(), AMOUNT_PARTIES);
        }
        for handle in kms_servers.values() {
            handle.abort()
        }
        for (_, handle) in kms_servers {
            assert!(handle.await.unwrap_err().is_cancelled());
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_decryption_central() {
        decryption_centralized(
            &TEST_PARAM,
            &crate::consts::TEST_CENTRAL_KEY_ID.to_string(),
            vec![
                TypedPlaintext::U8(42),
                TypedPlaintext::U32(9876),
                TypedPlaintext::U16(420),
                TypedPlaintext::U8(1),
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
                TypedPlaintext::U8(42),
                TypedPlaintext::U32(9876),
                TypedPlaintext::U16(420),
                TypedPlaintext::U8(1),
            ],
            3, // 3 parallel requests
            false,
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[rstest::rstest]
    #[case(vec![TypedPlaintext::Bool(true)], 5)]
    #[case(vec![TypedPlaintext::U8(u8::MAX)], 4)]
    #[case(vec![TypedPlaintext::U8(0)], 4)]
    #[case(vec![TypedPlaintext::U16(u16::MAX)], 2)]
    #[case(vec![TypedPlaintext::U16(0)], 1)]
    #[case(vec![TypedPlaintext::U32(u32::MAX)], 1)]
    #[case(vec![TypedPlaintext::U32(1234567)], 1)]
    #[case(vec![TypedPlaintext::U64(u64::MAX)], 1)]
    #[case(vec![TypedPlaintext::U128(u128::MAX)], 1)]
    #[case(vec![TypedPlaintext::U128(0)], 1)]
    #[case(vec![TypedPlaintext::U160(tfhe::integer::U256::from((u128::MAX, u32::MAX as u128)))], 1)]
    #[case(vec![TypedPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX)))], 1)]
    #[case(vec![TypedPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32]))], 1)]
    #[case(vec![TypedPlaintext::U8(0), TypedPlaintext::U64(999), TypedPlaintext::U32(32),TypedPlaintext::U128(99887766)], 1)] // test mixed types in batch
    #[case(vec![TypedPlaintext::U8(0), TypedPlaintext::U64(999), TypedPlaintext::U32(32)], 3)] // test mixed types in batch and in parallel
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn default_decryption_centralized(
        #[case] msgs: Vec<TypedPlaintext>,
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

    async fn decryption_centralized(
        dkg_params: &DKGParams,
        key_id: &str,
        msgs: Vec<TypedPlaintext>,
        parallelism: usize,
        compression: bool,
    ) {
        assert!(parallelism > 0);
        let (kms_server, kms_client, mut internal_client) =
            super::test_tools::centralized_handles(StorageVersion::Dev, dkg_params).await;
        let req_key_id = key_id.to_owned().try_into().unwrap();

        let mut cts = Vec::new();
        for msg in msgs.clone() {
            let (ct, fhe_type) = if compression {
                compute_compressed_cipher_from_stored_key(None, msg, key_id).await
            } else {
                compute_cipher_from_stored_key(None, msg, key_id).await
            };
            let ctt = TypedCiphertext {
                ciphertext: ct,
                fhe_type: fhe_type.into(),
                external_handle: None,
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
                assert_eq!(msgs[i].to_fhe_type(), plaintext.fhe_type());

                match msgs[i] {
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

        kms_server.abort();
        assert!(kms_server.await.unwrap_err().is_cancelled());
    }

    #[rstest::rstest]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn test_reencryption_centralized(#[values(true, false)] secure: bool) {
        reencryption_centralized(
            &TEST_PARAM,
            &crate::consts::TEST_CENTRAL_KEY_ID.to_string(),
            false,
            TypedPlaintext::U8(48),
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
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn default_reencryption_centralized_and_write_transcript(
        #[case] msg: TypedPlaintext,
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
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn default_reencryption_centralized(
        #[case] msg: TypedPlaintext,
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

    async fn reencryption_centralized(
        dkg_params: &DKGParams,
        key_id: &str,
        _write_transcript: bool,
        msg: TypedPlaintext,
        parallelism: usize,
        secure: bool,
    ) {
        assert!(parallelism > 0);
        let (kms_server, kms_client, mut internal_client) =
            super::test_tools::centralized_handles(StorageVersion::Dev, dkg_params).await;
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
                    fhe_type: msg.to_fhe_type(),
                    pt: msg.to_plaintext().bytes.clone(),
                    ct: reqs[0].0.payload.as_ref().unwrap().ciphertext().to_vec(),
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
            let plaintext = if secure {
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn test_decryption_threshold_no_decompression() {
        decryption_threshold(
            TEST_PARAM,
            &TEST_THRESHOLD_KEY_ID.to_string(),
            vec![
                TypedPlaintext::U8(42),
                TypedPlaintext::U8(2),
                TypedPlaintext::U16(444),
            ],
            2,
            false,
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn test_decryption_threshold_with_decompression() {
        decryption_threshold(
            TEST_PARAM,
            &TEST_THRESHOLD_KEY_ID.to_string(),
            vec![
                TypedPlaintext::U8(42),
                TypedPlaintext::U8(2),
                TypedPlaintext::U16(444),
            ],
            2,
            true,
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[rstest::rstest]
    #[case(vec![TypedPlaintext::Bool(true)], 4)]
    #[case(vec![TypedPlaintext::U8(u8::MAX)], 1)]
    #[case(vec![TypedPlaintext::U16(u16::MAX)], 1)]
    #[case(vec![TypedPlaintext::U32(u32::MAX)], 1)]
    #[case(vec![TypedPlaintext::U64(u64::MAX)], 1)]
    #[case(vec![TypedPlaintext::U128(u128::MAX)], 1)]
    #[case(vec![TypedPlaintext::U160(tfhe::integer::U256::from((u128::MAX, u32::MAX as u128)))], 1)]
    #[case(vec![TypedPlaintext::U256(tfhe::integer::U256::from((u128::MAX, u128::MAX)))], 1)]
    // TODO: this takes approx. 138 secs locally.
    // #[case(vec![TypedPlaintext::U2048(tfhe::integer::bigint::U2048::from([u64::MAX; 32]))], 1)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn default_decryption_threshold(
        #[case] msg: Vec<TypedPlaintext>,
        #[case] parallelism: usize,
    ) {
        use crate::consts::DEFAULT_PARAM;

        decryption_threshold(
            DEFAULT_PARAM,
            &DEFAULT_THRESHOLD_KEY_ID.to_string(),
            msg,
            parallelism,
            true,
        )
        .await;
    }

    async fn decryption_threshold(
        dkg_params: DKGParams,
        key_id: &str,
        msgs: Vec<TypedPlaintext>,
        parallelism: usize,
        compression: bool,
    ) {
        assert!(parallelism > 0);
        let (kms_servers, kms_clients, mut internal_client) =
            threshold_handles(StorageVersion::Dev, dkg_params).await;
        let key_id_req = key_id.to_string().try_into().unwrap();

        let mut cts = Vec::new();
        let mut bits = 0;
        for msg in msgs.clone() {
            let (ct, fhe_type) = if compression {
                compute_compressed_cipher_from_stored_key(None, msg, key_id).await
            } else {
                compute_cipher_from_stored_key(None, msg, key_id).await
            };
            let ctt = TypedCiphertext {
                ciphertext: ct,
                fhe_type: fhe_type.into(),
                external_handle: None,
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
            let min_count_agree = (THRESHOLD + 1) as u32;
            let received_plaintexts = internal_client
                .process_decryption_resp(Some(req.clone()), &responses, min_count_agree)
                .unwrap();

            // we need 1 plaintext for each ciphertext in the batch
            assert_eq!(received_plaintexts.len(), msgs.len());

            // check that the plaintexts are correct
            for (i, plaintext) in received_plaintexts.iter().enumerate() {
                assert_eq!(msgs[i].to_fhe_type(), plaintext.fhe_type());

                match msgs[i] {
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
    }

    #[rstest::rstest]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn test_reencryption_threshold(#[values(true, false)] secure: bool) {
        reencryption_threshold(
            TEST_PARAM,
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
            TEST_PARAM,
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
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn default_reencryption_threshold_and_write_transcript(
        #[case] msg: TypedPlaintext,
        #[values(true, false)] secure: bool,
    ) {
        use crate::consts::DEFAULT_PARAM;

        reencryption_threshold(
            DEFAULT_PARAM,
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
    async fn default_reencryption_threshold(
        #[case] msg: TypedPlaintext,
        #[case] parallelism: usize,
        #[values(true, false)] secure: bool,
    ) {
        use crate::consts::DEFAULT_PARAM;

        reencryption_threshold(
            DEFAULT_PARAM,
            &DEFAULT_THRESHOLD_KEY_ID.to_string(),
            false,
            msg,
            parallelism,
            secure,
        )
        .await;
    }

    async fn reencryption_threshold(
        dkg_params: DKGParams,
        key_id: &str,
        write_transcript: bool,
        msg: TypedPlaintext,
        parallelism: usize,
        secure: bool,
    ) {
        assert!(parallelism > 0);
        _ = write_transcript;

        let (kms_servers, kms_clients, mut internal_client) =
            threshold_handles(StorageVersion::Dev, dkg_params).await;
        let (ct, fhe_type) = compute_cipher_from_stored_key(None, msg, key_id).await;

        internal_client.convert_to_addresses();

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

                // Observe there should only be one element in `response_map`
                let agg_resp = response_map.values().last().unwrap().clone();

                let transcript = TestingReencryptionTranscript {
                    server_addrs: internal_client.get_server_addrs().unwrap().clone(),
                    client_address: internal_client.client_address,
                    client_sk: internal_client.client_sk.clone(),
                    degree: THRESHOLD as u32,
                    params: internal_client.params,
                    fhe_type: msg.to_fhe_type(),
                    pt: msg.to_plaintext().bytes.clone(),
                    ct: reqs[0].0.payload.as_ref().unwrap().ciphertext().to_vec(),
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
            // NOTE: throw away one response and it should still work.
            let plaintext = if secure {
                // test with one fewer response
                internal_client
                    .process_reencryption_resp(
                        &client_req,
                        &domain,
                        &responses[1..],
                        enc_pk,
                        enc_sk,
                    )
                    .unwrap();
                // test with all responses
                internal_client
                    .process_reencryption_resp(&client_req, &domain, responses, enc_pk, enc_sk)
                    .unwrap()
            } else {
                internal_client.server_identities = ServerIdentities::Addrs(Vec::new());
                // test with one fewer response
                internal_client
                    .insecure_process_reencryption_resp(&responses[1..], enc_pk, enc_sk)
                    .unwrap();
                // test with all responses
                internal_client
                    .insecure_process_reencryption_resp(responses, enc_pk, enc_sk)
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
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn test_largecipher() {
        let keys = get_default_keys().await;
        let (kms_server, mut kms_client) = super::test_tools::setup_centralized(
            RamStorage::new(StorageType::PUB),
            RamStorage::from_existing_keys(&keys.software_kms_keys)
                .await
                .unwrap(),
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
        let params: DKGParams = TEST_PARAM;
        let params = &params
            .get_params_basics_handle()
            .to_classic_pbs_parameters();
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
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn test_preproc(#[case] parallelism: usize) {
        assert!(parallelism > 0);
        use crate::kms::{KeyGenPreprocRequest, KeyGenPreprocStatusEnum};

        let (kms_servers, kms_clients, internal_client) =
            threshold_handles(StorageVersion::Dev, TEST_PARAM).await;

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
    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    async fn launch_dkg(
        req_keygen: crate::kms::KeyGenRequest,
        kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
        insecure: bool,
    ) -> Vec<Result<tonic::Response<Empty>, tonic::Status>> {
        let mut tasks_gen = JoinSet::new();
        for i in 1..=AMOUNT_PARTIES as u32 {
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
                        panic!("cannot perform insecure keygen")
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

    #[cfg(feature = "insecure")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn test_insecure_dkg() {
        let req_preproc = RequestId::derive("test_dkg-preproc").unwrap();
        let req_key = RequestId::derive("test_dkg-key").unwrap();
        purge(None, None, &req_key.to_string()).await;

        let (kms_servers, kms_clients, internal_client) =
            threshold_handles(StorageVersion::Dev, TEST_PARAM).await;

        let req_keygen = internal_client
            .key_gen_request(
                &req_key,
                Some(req_preproc.clone()),
                Some(ParamChoice::Test),
                None,
            )
            .unwrap();
        let responses = launch_dkg(req_keygen.clone(), &kms_clients, true).await;
        for response in responses {
            assert!(response.is_ok());
        }

        wait_for_keygen_result(
            req_keygen.request_id.clone().unwrap(),
            req_preproc,
            &kms_clients,
            &internal_client,
            true,
        )
        .await;

        for handle in kms_servers.values() {
            handle.abort()
        }
        for (_, handle) in kms_servers {
            assert!(handle.await.unwrap_err().is_cancelled());
        }
    }

    #[cfg(feature = "slow_tests")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    #[serial]
    async fn test_dkg() {
        use crate::kms::KeyGenPreprocStatusEnum;
        use itertools::Itertools;

        let req_preproc = RequestId::derive("test_dkg-preproc").unwrap();
        let req_key = RequestId::derive("test_dkg-key").unwrap();
        purge(None, None, &req_key.to_string()).await;

        let (kms_servers, kms_clients, internal_client) =
            threshold_handles(StorageVersion::Dev, TEST_PARAM).await;

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
            .key_gen_request(
                &req_key,
                Some(req_preproc.clone()),
                Some(ParamChoice::Test),
                None,
            )
            .unwrap();
        let responses = launch_dkg(req_keygen.clone(), &kms_clients, false).await;
        for response in responses {
            assert!(response.is_ok());
        }

        let req_get_keygen = req_keygen.request_id.clone().unwrap();
        wait_for_keygen_result(
            req_get_keygen,
            req_preproc,
            &kms_clients,
            &internal_client,
            false,
        )
        .await;

        for handle in kms_servers.values() {
            handle.abort()
        }
        for (_, handle) in kms_servers {
            assert!(handle.await.unwrap_err().is_cancelled());
        }
    }

    #[cfg(any(feature = "slow_tests", feature = "insecure"))]
    async fn wait_for_keygen_result(
        req_get_keygen: RequestId,
        req_preproc: RequestId,
        kms_clients: &HashMap<u32, CoreServiceEndpointClient<Channel>>,
        internal_client: &Client,
        insecure: bool,
    ) {
        //Wait 5 min max (should be enough here too)
        let mut finished = Vec::new();
        for _ in 0..20 {
            tokio::time::sleep(std::time::Duration::from_secs(if insecure {
                1
            } else {
                15
            }))
            .await;

            let mut tasks = JoinSet::new();
            for i in 1..=AMOUNT_PARTIES as u32 {
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
            if finished.len() == AMOUNT_PARTIES {
                break;
            }
        }

        let finished = finished
            .into_iter()
            .map(|x| x.1.unwrap().into_inner())
            .collect::<Vec<_>>();

        let mut serialized_ref_pk = Vec::new();
        let mut serialized_ref_server_key = Vec::new();
        for (idx, kg_res) in finished.into_iter().enumerate() {
            let storage = FileStorage::new_threshold(None, StorageType::PUB, idx + 1).unwrap();
            let pk = internal_client
                .retrieve_public_key(&kg_res, &storage)
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
                .retrieve_server_key(&kg_res, &storage)
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
                    Some(req_preproc),
                    Some(ParamChoice::Test),
                    None,
                )
                .unwrap();
            let responses = launch_dkg(keygen_req_data.clone(), kms_clients, insecure).await;
            for response in responses {
                assert_eq!(response.unwrap_err().code(), tonic::Code::NotFound);
            }
        }
    }
}

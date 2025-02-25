//! This module is dedicated to making an re-encryption request
//! and reconstruction of the re-encryption results on a web client
//! in JavaScript.
//!
//! We do not provide a specific method to create the re-encryption
//! request, it needs to be created manually by filling the fields
//! in [[ReencryptionRequest]].
//! This is because this request needs to be signed by the client's
//! signing key which is not available in the web client.
//! But it is typically stored in a wallet
//! (web extension or hardware wallet).
//!
//! Development notes:
//! The JavaScript API is created from compiling
//! a part of the client code (along with other dependencies)
//! into wasm and then using wasm-pack to generate the JS bindings.
//! Care must be taken when new code is introduced to core/service
//! or core/threshold since wasm does not support every feature
//! that Rust supports. Specifically, for our use-case, we will not
//! try to compile async, multi-threaded or IO code.
//!
//! If there is no need for a block to be used in wasm,
//! then we suggest to tag it with the "non-wasm" feature.
//! If a dependency does not need to be compiled to wasm,
//! then mark it as optional and place it under the list
//! of dependencies for feature "non-wasm".
//!
//! Generating the JavaScript binding introduces another layer
//! of limitations on the Rust side. For example, HashMap,
//! HashSet, Option on custom types, tuple,
//! u128, anyhow::Result, and so on cannot be used.
//!
//! Testing:
//! Due to the way re-encryption is designed,
//! we cannot test everything directly in JS.
//! The strategy we use is to run Rust tests to
//! generate a transcript, and then load it into
//! the JS test (tests/js/test.js) to run the
//! actual tests.
//! The steps below must be followed for the JS tests to work.
//!
//! 1. Install wasm-pack and node (version 20)
//!    the preferred way is to use nvm (which is on homebrew)
//!    and the node version must be 20
//! ```
//! cargo install wasm-pack
//! nvm install 20
//! ```
//! Observe that if you are using Brew you might also need to run the following command to get
//! access to nvm:
//! ```
//! source ~/.nvm/nvm.sh
//! ```
//!
//! 2. Build with wasm_tests feature
//! ```
//! wasm-pack build --target nodejs . --no-default-features -F wasm_tests
//! ```
//!
//! 3. Generate the transcript
//! ```
//! cargo test test_reencryption_threshold_and_write_transcript -F wasm_tests --release
//! cargo test test_reencryption_centralized_and_write_transcript -F wasm_tests --release
//! ```
//!
//! 4. Run the JS test
//! ```
//! node --test tests/js
//! ```
use crypto_box::aead::{Aead, AeadCore};
use crypto_box::{Nonce, SalsaBox};
use distributed_decryption::execution::tfhe_internals::parameters::BC_PARAMS_SAM_SNS;
use kms_grpc::kms::v1::Eip712DomainMsg;
use kms_grpc::kms::v1::FheParameter;
use kms_grpc::rpc_types::protobuf_to_alloy_domain;

use super::*;

#[wasm_bindgen]
pub fn public_sig_key_to_u8vec(pk: &PublicSigKey) -> Vec<u8> {
    pk.pk().to_sec1_bytes().to_vec()
}

#[wasm_bindgen]
pub fn u8vec_to_public_sig_key(v: &[u8]) -> Result<PublicSigKey, JsError> {
    Ok(PublicSigKey::new(
        k256::ecdsa::VerifyingKey::from_sec1_bytes(v).map_err(|e| JsError::new(&e.to_string()))?,
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
/// * `fhe_parameter` - the parameter choice, which can be either `"test"` or `"default"`.
/// The "default" parameter choice is selected if no matching string is found.
#[wasm_bindgen]
pub fn new_client(
    server_addrs: Vec<String>,
    client_address_hex: &str,
    fhe_parameter: &str,
) -> Result<Client, JsError> {
    console_error_panic_hook::set_once();

    let params = match FheParameter::from_str_name(fhe_parameter) {
        Some(choice) => {
            let p: crate::cryptography::internal_crypto_types::WrappedDKGParams = choice.into();
            *p
        }
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
        params,
        decryption_mode: DecryptionMode::default(),
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
pub fn transcript_to_eip712domain(transcript: &TestingReencryptionTranscript) -> Eip712DomainMsg {
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
pub fn transcript_to_client(transcript: &TestingReencryptionTranscript) -> Client {
    Client {
        rng: Box::new(AesRng::from_entropy()),
        server_identities: ServerIdentities::Addrs(transcript.server_addrs.clone()),
        client_address: transcript.client_address,
        client_sk: transcript.client_sk.clone(),
        params: transcript.params,
        decryption_mode: DecryptionMode::default(),
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
) -> Result<Vec<TypedPlaintext>, JsError> {
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
    let le_res = process_reencryption_resp(
        client,
        request,
        eip712_domain,
        agg_resp,
        enc_pk,
        enc_sk,
        verify,
    );
    // Need to convert to BE for JS, evrerything is internally represented as LE
    match le_res {
        Ok(le_res) => Ok(le_res
            .into_iter()
            .map(|x| TypedPlaintext {
                bytes: x.bytes.into_iter().rev().collect(),
                fhe_type: x.fhe_type,
            })
            .collect()),
        Err(e) => Err(e),
    }
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
) -> Result<Vec<TypedPlaintext>, JsError> {
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
        Ok(resp) => Ok(resp),
        Err(e) => Err(JsError::new(&e.to_string())),
    }
}

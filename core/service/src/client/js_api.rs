//! This module is dedicated to making an user_decryption request
//! and reconstruction of the user_decryption results on a web client
//! in JavaScript.
//!
//! We do not provide a specific method to create the user_decryption
//! request, it needs to be created manually by filling the fields
//! in [[UserDecryptionRequest]].
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
//! or core/threshold-* since wasm does not support every feature
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
//! Due to the way user_decryption is designed, we cannot test everything
//! directly in JS. The strategy we use is to run Rust tests to generate a JSON
//! test vector (see
//! [crate::client::user_decryption_wasm::TestingUserDecryptionTranscript::to_stable_test_vector]),
//! and then load it into the JS test (tests/js/test.js) to run the actual
//! tests. The JSON vector only carries the stable public-API so an older
//! published `tkms`/`node-tkms` build can be used to test against a more recent
//! kms that generates the JSON test vector. The steps below must be followed
//! for the JS tests to work.
//!
//! 1. Install wasm-pack and node (version 24.16.0)
//!    the preferred way is to use nvm (which is on homebrew)
//!    and the node version must be 24.16.0
//! ```
//! cargo install wasm-pack
//! nvm install 24.16.0
//! ```
//! Observe that if you are using Brew you might also need to run the following command to get
//! access to nvm:
//! ```
//! source ~/.nvm/nvm.sh
//! ```
//!
//! 2. Generate the JSON test vector (this still needs `wasm_tests`)
//! ```
//! cargo test test_user_decryption_threshold_and_write_transcript -F wasm_tests --release
//! cargo test test_user_decryption_centralized_and_write_transcript -F wasm_tests --release
//! ```
//!
//! 3. Build the wasm package from the core/service directory (no `wasm_tests` needed)
//! ```
//! wasm-pack build --target nodejs . --no-default-features
//! ```
//!
//! 4. Run the JS test
//! ```
//! node --test tests/js
//! ```
use crate::client::client_wasm::{Client, ServerIdentities};
use crate::client::user_decryption_wasm::{ParsedUserDecryptionRequest, UserDecryptionResponseHex};
use crate::consts::SAFE_SER_SIZE_LIMIT;
use crate::cryptography::encryption::{
    PrivateEncKey, PublicEncKey, UnifiedPrivateEncKey, UnifiedPublicEncKey,
};
use crate::cryptography::hybrid_ml_kem;
use crate::cryptography::signatures::{PrivateSigKey, PublicSigKey};
use aes_prng::AesRng;
use bc2wrap::deserialize_safe;
use kms_grpc::kms::v1::FheParameter;
use kms_grpc::kms::v1::UserDecryptionResponse;
use kms_grpc::kms::v1::{Eip712DomainMsg, TypedPlaintext, UserDecryptionResponsePayload};
use kms_grpc::rpc_types::protobuf_to_alloy_domain;
use rand::SeedableRng;
use std::collections::HashMap;
use threshold_execution::endpoints::decryption::DecryptionMode;
use threshold_execution::tfhe_internals::parameters::BC_PARAMS_SNS;
use wasm_bindgen::{JsError, JsValue, prelude::wasm_bindgen};

// Since wasm_bindgen is limited, namely it says
// structs with #[wasm_bindgen] cannot have lifetime or type parameters currently
// we have no make a concrete type for the private encryption key.
#[wasm_bindgen]
pub struct PrivateEncKeyMlKem512(pub(crate) PrivateEncKey<ml_kem::MlKem512>);

#[wasm_bindgen]
pub struct PublicEncKeyMlKem512(pub(crate) PublicEncKey<ml_kem::MlKem512>);

// We can't wasm-bindgen consts, so we put it in a function instead.
#[wasm_bindgen]
pub fn ml_kem_pke_pk_len() -> usize {
    hybrid_ml_kem::ML_KEM_512_PK_LENGTH
}

#[wasm_bindgen]
pub fn ml_kem_pke_sk_len() -> usize {
    hybrid_ml_kem::ML_KEM_512_SK_LEN
}

#[wasm_bindgen]
pub fn public_sig_key_to_u8vec(pk: &PublicSigKey) -> Vec<u8> {
    #[allow(deprecated)]
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
    bc2wrap::serialize(sk).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn u8vec_to_private_sig_key(v: &[u8]) -> Result<PrivateSigKey, JsError> {
    deserialize_safe(v).map_err(|e| JsError::new(&e.to_string()))
}

// We cannot use a hashmap so use this struct as an alternative
#[wasm_bindgen]
pub struct ServerIdAddr {
    id: u32,
    addr: alloy_primitives::Address,
}

/// Create a new [ServerIdAddr] structure that holds an ID and an address
/// which must be a valid EIP-55 address, notably prefixed with "0x".
#[wasm_bindgen]
pub fn new_server_id_addr(id: u32, addr: String) -> Result<ServerIdAddr, JsError> {
    let addr = alloy_primitives::Address::parse_checksummed(addr, None)
        .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(ServerIdAddr { id, addr })
}

/// Instantiate a new client.
///
/// * `server_addrs` - a list of KMS server ID with EIP-55 addresses,
/// the elements in the list can be created using [new_server_id_addr].
///
/// * `client_address_hex` - the client (wallet) address in hex,
/// must be prefixed with "0x".
///
/// * `fhe_parameter` - the parameter choice, which can be either `"test"` or `"default"`.
/// The "default" parameter choice is selected if no matching string is found.
#[wasm_bindgen]
pub fn new_client(
    server_addrs: Vec<ServerIdAddr>,
    client_address_hex: &str,
    fhe_parameter: &str,
) -> Result<Client, JsError> {
    console_error_panic_hook::set_once();

    let params = match FheParameter::from_str_name(fhe_parameter) {
        Some(choice) => {
            let p: crate::cryptography::internal_crypto_types::WrappedDKGParams = choice.into();
            *p
        }
        None => BC_PARAMS_SNS,
    };

    let client_address = alloy_primitives::Address::parse_checksummed(client_address_hex, None)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let expected_server_count = server_addrs.len();
    let addrs_hash_map = HashMap::from_iter(
        server_addrs
            .into_iter()
            .map(|id_addr| (id_addr.id, id_addr.addr)),
    );

    if expected_server_count != addrs_hash_map.len() {
        return Err(JsError::new("some server IDs have duplicate keys"));
    }

    let server_identities = ServerIdentities::Addrs(addrs_hash_map);

    Ok(Client {
        server_identities,
        client_address,
        client_sk: None,
        params,
        decryption_mode: DecryptionMode::default(),
    })
}

#[wasm_bindgen]
pub fn get_server_addrs(client: &Client) -> Vec<ServerIdAddr> {
    client
        .get_server_addrs()
        .iter()
        .map(|(id, addr)| ServerIdAddr {
            id: *id,
            addr: *addr,
        })
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
pub fn ml_kem_pke_keygen() -> PrivateEncKeyMlKem512 {
    let mut rng = AesRng::from_entropy();
    let (dk, _ek) = hybrid_ml_kem::keygen::<ml_kem::MlKem512, _>(&mut rng);
    PrivateEncKeyMlKem512(PrivateEncKey(dk))
}

#[wasm_bindgen]
pub fn ml_kem_pke_get_pk(sk: &PrivateEncKeyMlKem512) -> PublicEncKeyMlKem512 {
    PublicEncKeyMlKem512(PublicEncKey(sk.0.0.encapsulation_key().clone()))
}

#[wasm_bindgen]
pub fn ml_kem_pke_pk_to_u8vec(pk: &PublicEncKeyMlKem512) -> Result<Vec<u8>, JsError> {
    let mut enc_key_buf = Vec::new();
    tfhe::safe_serialization::safe_serialize(
        &UnifiedPublicEncKey::MlKem512(pk.0.clone()),
        &mut enc_key_buf,
        SAFE_SER_SIZE_LIMIT,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;
    Ok(enc_key_buf)
}

#[wasm_bindgen]
pub fn ml_kem_pke_sk_to_u8vec(sk: &PrivateEncKeyMlKem512) -> Result<Vec<u8>, JsError> {
    bc2wrap::serialize(&sk.0).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn u8vec_to_ml_kem_pke_pk(v: &[u8]) -> Result<PublicEncKeyMlKem512, JsError> {
    tfhe::safe_serialization::safe_deserialize::<UnifiedPublicEncKey>(
        std::io::Cursor::new(v),
        SAFE_SER_SIZE_LIMIT,
    )
    .map(|x| PublicEncKeyMlKem512(x.unwrap_ml_kem_512()))
    .map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn u8vec_to_ml_kem_pke_sk(v: &[u8]) -> Result<PrivateEncKeyMlKem512, JsError> {
    deserialize_safe::<PrivateEncKey<ml_kem::MlKem512>>(v)
        .map(PrivateEncKeyMlKem512)
        .map_err(|e| JsError::new(&e.to_string()))
}

/// This function is *not* used by relayer-sdk because the encryption
/// happens on the KMS side. It's just here for completeness and tests.
#[wasm_bindgen]
pub fn ml_kem_pke_encrypt(msg: &[u8], their_pk: &PublicEncKeyMlKem512) -> Vec<u8> {
    let mut rng = AesRng::from_entropy();
    bc2wrap::serialize(
        &hybrid_ml_kem::enc::<ml_kem::MlKem512, _>(&mut rng, msg, &their_pk.0.0).unwrap(),
    )
    .unwrap()
}

/// This function is *not* used by relayer-sdk because the decryption
/// is handled by [process_user_decryption_resp].
/// It's just here for completeness and tests.
#[wasm_bindgen]
pub fn ml_kem_pke_decrypt(ct: &[u8], my_sk: &PrivateEncKeyMlKem512) -> Vec<u8> {
    let ct: hybrid_ml_kem::HybridKemCt = deserialize_safe(ct).unwrap();
    hybrid_ml_kem::dec::<ml_kem::MlKem512>(ct, &my_sk.0.0).unwrap()
}

// Note: normally the result type should be a JsError
// but JsError is very limited, it cannot be printed,
// so it's difficult to append information to the error.
// This is why we're using anyhow::Error.
fn js_to_resp(json: JsValue) -> anyhow::Result<Vec<UserDecryptionResponse>> {
    // first read the hex type
    let hex_resps: Vec<UserDecryptionResponseHex> = serde_wasm_bindgen::from_value(json)
        .map_err(|e| anyhow::anyhow!("from_value error {e:?}"))?;

    // then convert the hex type into the type we need
    let mut out = vec![];
    for hex_resp in hex_resps {
        out.push(UserDecryptionResponse {
            signature: vec![], // there is no ECDSA signature in the wasm use case
            external_signature: hex::decode(&hex_resp.signature)?,
            payload: match hex_resp.payload {
                Some(inner) => {
                    let buf = hex::decode(&inner)?;
                    Some(deserialize_safe::<UserDecryptionResponsePayload>(&buf)?)
                }
                None => None,
            },
            extra_data: match hex_resp.extra_data {
                Some(inner) => hex::decode(&inner)?,
                None => vec![],
            },
        });
    }
    Ok(out)
}

/// Process the user_decryption response from JavaScript objects.
/// The returned result is a byte array representing a plaintext of any length,
/// postprocessing is returned to turn it into an integer.
///
/// * `client` - client that wants to perform user_decryption.
///
/// * `request` - the initial user_decryption request JS object.
/// It can be set to null if `verify` is false.
/// Otherwise the caller needs to give the following JS object.
/// Note that `client_address` and `eip712_verifying_contract` follow EIP-55.
/// The signature field is not needed.
/// ```
/// {
///   signature: undefined,
///   client_address: '0x17853A630aAe15AED549B2B874de08B73C0F59c5',
///   enc_key: '2000000000000000df2fcacb774f03187f3802a27259f45c06d33cefa68d9c53426b15ad531aa822',
///   ciphertext_handles: [ '0748b542afe2353c86cb707e3d21044b0be1fd18efc7cbaa6a415af055bfb358' ]
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
///     payload: '0100000029...',
///     extra_data: '01234...',
///   }
/// ]
/// ```
///
/// * `enc_pk` - The ephemeral public key.
///
/// * `enc_sk` - The ephemeral secret key.
///
/// * `threshold` - Optional expected threshold/degree used during response validation.
/// Validation requires at least `threshold + 1` matching responses, and the selected pivot
/// response must have `degree == threshold`. If not provided, it is computed from the number
/// of server addresses as `(n - 1) / 3`.
///
/// * `verify` - Whether to perform signature verification for the response.
/// It is insecure if `verify = false`!
#[wasm_bindgen]
pub fn process_user_decryption_resp_from_js(
    client: &mut Client,
    request: JsValue,
    eip712_domain: JsValue,
    agg_resp: JsValue,
    enc_pk: &PublicEncKeyMlKem512,
    enc_sk: &PrivateEncKeyMlKem512,
    threshold: Option<usize>,
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
        Some(ParsedUserDecryptionRequest::try_from(request)?)
    };
    let le_res = process_user_decryption_resp(
        client,
        request,
        eip712_domain,
        agg_resp,
        enc_pk,
        enc_sk,
        threshold,
        verify,
    );
    // Need to convert to BE for JS, everything is internally represented as LE
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

/// Solana variant of [process_user_decryption_resp_from_js]. Self-contained: Solana has no
/// on-chain KMSVerifier, so the KMS verification key(s) are taken from the response payload(s) and
/// the client address is derived from the Solana user pubkey (`keccak256(pubkey)[12..]`). The
/// signed link is the keccak `compute_link_solana` digest (32-byte pubkey + host chain id), not the
/// EVM EIP-712 `UserDecryptionLinker`; de-signcryption is otherwise identical to the EVM path.
#[wasm_bindgen]
pub fn process_user_decryption_resp_solana_from_js(
    request: JsValue,
    solana_user_pubkey: Vec<u8>,
    host_chain_id: u64,
    agg_resp: JsValue,
    enc_pk: &PublicEncKeyMlKem512,
    enc_sk: &PrivateEncKeyMlKem512,
) -> Result<Vec<TypedPlaintext>, JsError> {
    console_error_panic_hook::set_once();
    let agg_resp = js_to_resp(agg_resp)
        .map_err(|e| JsError::new(&format!("response parsing failed with error {}", e)))?;
    let request = ParsedUserDecryptionRequest::try_from(request)?;
    let solana_user_pubkey: [u8; 32] = solana_user_pubkey
        .as_slice()
        .try_into()
        .map_err(|_| JsError::new("solana_user_pubkey must be 32 bytes"))?;

    // Build the client from the KMS verification key(s) carried in the response payload(s);
    // the client address is the Solana receiver id keccak256(pubkey)[12..].
    let mut server_pks = HashMap::new();
    for (i, resp) in agg_resp.iter().enumerate() {
        let payload = resp
            .payload
            .as_ref()
            .ok_or_else(|| JsError::new("response payload missing"))?;
        let vk: PublicSigKey = deserialize_safe(&payload.verification_key)
            .map_err(|e| JsError::new(&format!("verification key parse failed: {e}")))?;
        server_pks.insert((i + 1) as u32, vk);
    }
    let client_address =
        alloy_primitives::Address::from_slice(&alloy_primitives::keccak256(solana_user_pubkey)[12..]);
    let client = Client {
        server_identities: ServerIdentities::Pks(server_pks),
        client_address,
        client_sk: None,
        params: BC_PARAMS_SNS,
        decryption_mode: DecryptionMode::default(),
    };

    // Internally plaintexts are little-endian; JS expects big-endian (mirror the EVM wrapper).
    match client.process_user_decryption_resp_solana(
        &request,
        &solana_user_pubkey,
        host_chain_id,
        &UnifiedPublicEncKey::MlKem512(enc_pk.0.clone()),
        &UnifiedPrivateEncKey::MlKem512(enc_sk.0.clone()),
        &agg_resp,
    ) {
        Ok(le_res) => Ok(le_res
            .into_iter()
            .map(|x| TypedPlaintext {
                bytes: x.bytes.into_iter().rev().collect(),
                fhe_type: x.fhe_type,
            })
            .collect()),
        Err(e) => Err(JsError::new(&e.to_string())),
    }
}

/// Process the user_decryption response from Rust objects.
/// Consider using [process_user_decryption_resp_from_js]
/// when using the JS API.
/// The result is a byte array representing a plaintext of any length.
///
/// * `client` - client that wants to perform user_decryption.
///
/// * `request` - the initial user_decryption request.
/// Must be given if `verify` is true.
///
/// * `eip712_domain` - the EIP-712 domain.
/// Must be given if `verify` is true.
///
/// * `agg_resp` - the vector of user_decryption responses.
///
/// * `enc_pk` - The ephemeral public key.
///
/// * `enc_sk` - The ephemeral secret key.
///
/// * `threshold` - Optional threshold override for reconstruction.
/// If not provided, it is computed from the number of server addresses as `(n - 1) / 3`.
///
/// * `verify` - Whether to perform signature verification for the response.
/// It is insecure if `verify = false`!
pub fn process_user_decryption_resp(
    client: &mut Client,
    request: Option<ParsedUserDecryptionRequest>,
    eip712_domain: Option<Eip712DomainMsg>,
    agg_resp: Vec<UserDecryptionResponse>,
    enc_pk: &PublicEncKeyMlKem512,
    enc_sk: &PrivateEncKeyMlKem512,
    threshold: Option<usize>,
    verify: bool,
) -> Result<Vec<TypedPlaintext>, JsError> {
    // if verify is true, then request and eip712 domain must exist
    let user_decrypt_resp = if verify {
        let request = request.ok_or_else(|| JsError::new("missing request"))?;
        let pb_domain = eip712_domain.ok_or_else(|| JsError::new("missing eip712 domain"))?;
        let eip712_domain =
            protobuf_to_alloy_domain(&pb_domain).map_err(|e| JsError::new(&e.to_string()))?;
        client.process_user_decryption_resp(
            &request,
            &eip712_domain,
            &UnifiedPublicEncKey::MlKem512(enc_pk.0.clone()),
            &UnifiedPrivateEncKey::MlKem512(enc_sk.0.clone()),
            threshold,
            &agg_resp,
        )
    } else {
        client.insecure_process_user_decryption_resp(
            &UnifiedPrivateEncKey::MlKem512(enc_sk.0.clone()),
            &agg_resp,
        )
    };
    match user_decrypt_resp {
        Ok(resp) => Ok(resp),
        Err(e) => Err(JsError::new(&e.to_string())),
    }
}

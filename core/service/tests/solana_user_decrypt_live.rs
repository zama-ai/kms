//! Live RFC-021 Solana user-decryption client (the user-side SDK piece), as an `#[ignore]`d
//! integration test driven against a running fhevm-cli stack with the Solana user-decrypt path
//! deployed (gateway `userDecryptionRequestSolana`, relayer ed25519 seam, kms-connector Solana
//! vertical, kms-core `compute_link_solana`).
//!
//! Flow: ML-KEM keygen -> ed25519-sign the canonical request-binding message (mirrors the relayer's
//! `solana_user_decrypt_auth_message`) -> POST /v2/user-decrypt -> poll -> de-signcrypt via
//! `process_user_decryption_resp_solana` -> assert the cleartext.
//!
//! Run (after a handle is granted to the user pubkey):
//!   SOLANA_UD_HANDLE=0x... SOLANA_UD_EXPECTED=53 \
//!   cargo test -p kms --features non-wasm --test solana_user_decrypt_live -- --ignored --nocapture
#![cfg(feature = "non-wasm")]

use std::collections::HashMap;
use std::env;

use aes_prng::AesRng;
use alloy_primitives::{Address, U256};
use ed25519_dalek::{Signer, SigningKey};
use kms_grpc::kms::v1::{UserDecryptionResponse, UserDecryptionResponsePayload};
use kms_lib::client::client_wasm::Client;
use kms_lib::client::user_decryption_wasm::{CiphertextHandle, ParsedUserDecryptionRequest};
use kms_lib::consts::{DEFAULT_PARAM, SAFE_SER_SIZE_LIMIT};
use kms_lib::cryptography::encryption::{Encryption, PkeScheme, PkeSchemeType};
use kms_lib::cryptography::signatures::PublicSigKey;
use rand::SeedableRng;

const AUTH_DOMAIN: &[u8] = b"fhevm-solana-user-decryption-auth-v0";

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Reads a Solana CLI keypair file (`[u8; 64]` JSON: 32-byte seed || 32-byte pubkey).
fn load_solana_keypair(path: &str) -> (SigningKey, [u8; 32]) {
    let bytes: Vec<u8> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(bytes.len(), 64, "solana keypair must be 64 bytes");
    let signing = SigningKey::from_bytes(&bytes[..32].try_into().unwrap());
    let pubkey: [u8; 32] = bytes[32..].try_into().unwrap();
    assert_eq!(signing.verifying_key().to_bytes(), pubkey, "keypair seed/pubkey mismatch");
    (signing, pubkey)
}

/// Mirrors the relayer's `solana_user_decrypt_auth_message` byte-for-byte.
fn auth_message(
    contracts_chain_id: u64,
    public_key: &[u8],
    handles: &[[u8; 32]],
    start_timestamp: U256,
    duration_days: U256,
) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(AUTH_DOMAIN);
    m.extend_from_slice(&contracts_chain_id.to_le_bytes());
    m.extend_from_slice(&(public_key.len() as u32).to_le_bytes());
    m.extend_from_slice(public_key);
    m.extend_from_slice(&(handles.len() as u32).to_le_bytes());
    for h in handles {
        m.extend_from_slice(h);
    }
    m.extend_from_slice(&start_timestamp.to_be_bytes::<32>());
    m.extend_from_slice(&duration_days.to_be_bytes::<32>());
    m
}

#[tokio::test]
#[ignore = "requires a running fhevm-cli stack with the Solana user-decrypt path + a granted handle"]
async fn solana_user_decrypt_live() {
    let relayer = env_or("SOLANA_UD_RELAYER", "http://localhost:3000");
    let keypair_path =
        env_or("SOLANA_UD_KEYPAIR", &format!("{}/.config/solana/id.json", env_or("HOME", "")));
    let handle_hex = env::var("SOLANA_UD_HANDLE").expect("SOLANA_UD_HANDLE (0x..32 bytes) required");
    let expected: u64 = env_or("SOLANA_UD_EXPECTED", "0").parse().unwrap();
    let contracts_chain_id: u64 =
        env_or("SOLANA_UD_CHAIN_ID", "9223372036854788153").parse().unwrap();

    // 1. ML-KEM ephemeral keypair (non-wasm path). The serialized public key is the request's
    //    `publicKey`; kms-core validates it via `UnifiedPublicEncKey::deserialize_and_validate`.
    let mut rng = AesRng::from_entropy();
    let (unified_sk, unified_pk) =
        Encryption::new(PkeSchemeType::MlKem512, &mut rng).keygen().unwrap();
    let mut pk_bytes = Vec::new();
    tfhe::safe_serialization::safe_serialize(&unified_pk, &mut pk_bytes, SAFE_SER_SIZE_LIMIT)
        .unwrap();

    // 2. ed25519 user identity + auth signature over the canonical message.
    let (signing, pubkey) = load_solana_keypair(&keypair_path);
    let handle = alloy_primitives::hex::decode(handle_hex.trim_start_matches("0x")).unwrap();
    let handle32: [u8; 32] = handle.try_into().expect("handle must be 32 bytes");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let start_ts = U256::from(now - 60); // small buffer so startTimestamp <= block time
    let duration_days = U256::from(30u64);
    let msg = auth_message(contracts_chain_id, &pk_bytes, &[handle32], start_ts, duration_days);
    let signature = signing.sign(&msg);

    // extra_data v1 = 0x01 || context_id (32-byte BE): the KMS context the connector validates +
    // routes to (same versioned format the EVM user-decrypt path uses; plain 0x00 is rejected).
    let context_id = U256::from_str_radix(
        &env_or(
            "SOLANA_UD_CONTEXT_ID",
            "3166189940082864718613269121331309980362851143201109172953918312716374638593",
        ),
        10,
    )
    .unwrap();
    let mut extra_data = vec![0x01u8];
    extra_data.extend_from_slice(&context_id.to_be_bytes::<32>());
    let extra_data_hex = format!("0x{}", alloy_primitives::hex::encode(&extra_data));

    // 3. Build + POST the user-decrypt request.
    let user_b58 = bs58::encode(pubkey).into_string();
    let body = serde_json::json!({
        "handleContractPairs": [{ "handle": format!("0x{}", alloy_primitives::hex::encode(handle32)),
                                  "contractAddress": user_b58 }],
        "requestValidity": { "startTimestamp": start_ts.to_string(), "durationDays": duration_days.to_string() },
        "contractsChainId": contracts_chain_id.to_string(),
        "contractAddresses": [],
        "userAddress": user_b58,
        "signature": alloy_primitives::hex::encode(signature.to_bytes()),
        "publicKey": alloy_primitives::hex::encode(&pk_bytes),
        "extraData": extra_data_hex,
    });
    let http = reqwest::Client::new();
    let post = http.post(format!("{relayer}/v2/user-decrypt")).json(&body).send().await.unwrap();
    let post_status = post.status();
    let post_json: serde_json::Value = post.json().await.unwrap();
    println!("POST {post_status}: {post_json}");
    assert!(post_status.is_success(), "relayer rejected the request: {post_json}");
    let job_id = post_json["result"]["jobId"].as_str().expect("jobId").to_string();

    // 4. Poll for the response.
    let mut response_json = serde_json::Value::Null;
    for _ in 0..60 {
        let r = http.get(format!("{relayer}/v2/user-decrypt/{job_id}")).send().await.unwrap();
        let j: serde_json::Value = r.json().await.unwrap();
        match j["status"].as_str() {
            Some("succeeded") => {
                response_json = j;
                break;
            }
            Some("failed") => panic!("user-decrypt failed: {j}"),
            _ => tokio::time::sleep(std::time::Duration::from_secs(2)).await,
        }
    }
    assert!(!response_json.is_null(), "timed out waiting for user-decrypt result");
    println!("result: {response_json}");

    // 5. Parse the aggregated shares -> UserDecryptionResponse (external EIP-712 signature +
    //    bincode-serialized payload), then de-signcrypt via the Solana path.
    let shares = response_json["result"]["result"]
        .as_array()
        .expect("relayer response result.result[] array");
    let mut agg_resp = Vec::new();
    let mut kms_pk: Option<PublicSigKey> = None;
    for share in shares {
        let external_signature = alloy_primitives::hex::decode(
            share["signature"].as_str().unwrap_or("").trim_start_matches("0x"),
        )
        .unwrap();
        let payload_bytes = alloy_primitives::hex::decode(
            share["payload"].as_str().unwrap_or("").trim_start_matches("0x"),
        )
        .unwrap();
        let payload: UserDecryptionResponsePayload =
            bc2wrap::deserialize_safe(&payload_bytes).unwrap();
        if kms_pk.is_none() {
            kms_pk = Some(bc2wrap::deserialize_safe(&payload.verification_key).unwrap());
        }
        agg_resp.push(UserDecryptionResponse {
            signature: vec![],
            external_signature,
            payload: Some(payload),
            extra_data: vec![],
        });
    }

    // 6. Build a client bound to the KMS verification key and de-signcrypt.
    let derived = Address::from_slice(&alloy_primitives::keccak256(pubkey)[12..]);
    let mut server_pks = HashMap::new();
    server_pks.insert(1u32, kms_pk.expect("KMS verification key in response payload"));
    let client = Client::new(server_pks, derived, None, DEFAULT_PARAM, None);
    let request = ParsedUserDecryptionRequest::new(
        None,
        derived,
        pk_bytes.clone(),
        vec![CiphertextHandle::new(handle32.to_vec())],
        Address::ZERO,
        vec![0x00],
    );

    let plaintexts = client
        .process_user_decryption_resp_solana(
            &request,
            &pubkey,
            contracts_chain_id,
            &unified_pk,
            &unified_sk,
            &agg_resp,
        )
        .expect("solana de-signcryption failed");
    assert!(!plaintexts.is_empty(), "no plaintexts returned");

    let pt = &plaintexts[0];
    let mut le = [0u8; 8];
    let n = pt.bytes.len().min(8);
    le[..n].copy_from_slice(&pt.bytes[..n]);
    let value = u64::from_le_bytes(le);
    println!("[solana] decrypted user cleartext = {value} (expected {expected})");
    assert_eq!(value, expected, "cleartext mismatch");
}

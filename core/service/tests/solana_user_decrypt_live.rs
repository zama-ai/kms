//! Live RFC-021 Solana V2 user-decryption client (the user-side SDK piece), as an `#[ignore]`d
//! integration test driven against a running fhevm-cli stack with the Solana user-decrypt path
//! deployed (gateway V2 `userDecryptionRequest`, relayer `/v3/user-decrypt` ed25519 seam,
//! kms-connector Solana V2 arm, kms-core `compute_link_solana`).
//!
//! Flow:
//!   1. ML-KEM ephemeral keygen (Rust — this is also where the response is de-signcrypted).
//!   2. Sign the canonical `zama-solana-user-decrypt-v1` preimage via the js-sdk
//!      `buildSolanaUserDecryptRequest` (shelled out — the SDK is the single signer), binding the
//!      ML-KEM public key, handles, identity, nonce, allowed ACL domain keys, and validity window.
//!   3. POST the V2 request as the v3 typed-attestation envelope (`solana-ed25519-user-decrypt-v1`)
//!      to `/v3/user-decrypt`, poll the job.
//!   4. De-signcrypt via `process_user_decryption_resp_solana` and assert the cleartext.
//!
//! Run (after a handle is granted USE to the user's Solana pubkey on the host ACL):
//!   SOLANA_UD_HANDLE=0x... SOLANA_UD_EXPECTED=55 \
//!   cargo test -p kms --features non-wasm --test solana_user_decrypt_live -- --ignored --nocapture
#![cfg(feature = "non-wasm")]

use std::collections::HashMap;
use std::env;
use std::process::Command;

use aes_prng::AesRng;
use alloy_primitives::{Address, U256};
use kms_grpc::kms::v1::{UserDecryptionResponse, UserDecryptionResponsePayload};
use kms_lib::client::client_wasm::Client;
use kms_lib::client::user_decryption_wasm::{CiphertextHandle, ParsedUserDecryptionRequest};
use kms_lib::consts::{DEFAULT_PARAM, SAFE_SER_SIZE_LIMIT};
use kms_lib::cryptography::encryption::{Encryption, PkeScheme, PkeSchemeType};
use kms_lib::cryptography::signatures::PublicSigKey;
use rand::SeedableRng;

fn env_or(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Reads a Solana CLI keypair file (`[u8; 64]` JSON: 32-byte seed || 32-byte pubkey).
///
/// The seed↔pubkey consistency is verified downstream by the js-sdk signer
/// (`buildSolanaUserDecryptRequest` derives the pubkey from the seed and rejects a mismatch), so no
/// ed25519 derivation is done here — this keeps the harness off `ed25519-dalek`/`bs58`.
fn load_solana_keypair(path: &str) -> ([u8; 32], [u8; 32]) {
    let bytes: Vec<u8> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(bytes.len(), 64, "solana keypair must be 64 bytes");
    let seed: [u8; 32] = bytes[..32].try_into().unwrap();
    let pubkey: [u8; 32] = bytes[32..].try_into().unwrap();
    (seed, pubkey)
}

fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", alloy_primitives::hex::encode(bytes))
}

/// The V2 request object returned by the js-sdk `buildSolanaUserDecryptRequest`.
#[derive(serde::Deserialize)]
struct SignedRequest {
    #[serde(rename = "attestationType")]
    attestation_type: String,
    signature: String,
    #[serde(rename = "extraData")]
    extra_data: String,
    #[serde(rename = "publicKey")]
    public_key: String,
    handles: Vec<String>,
    #[serde(rename = "userAddress")]
    user_address: String,
    // RFC-021 typed Solana auth fields (no longer packed into extraData; extraData is context-only).
    #[serde(rename = "solanaUserIdentity")]
    solana_user_identity: String,
    #[serde(rename = "solanaNonce")]
    solana_nonce: String,
    #[serde(rename = "solanaAllowedAclDomainKeys")]
    solana_allowed_acl_domain_keys: Vec<String>,
}

/// Shells out to the js-sdk signer (`buildSolanaUserDecryptRequest`) to produce the canonical V2
/// ed25519 request. The SDK is the single source of truth for the signing preimage; the kms-worker
/// connector re-derives and verifies it byte-for-byte.
#[allow(clippy::too_many_arguments)]
fn sdk_sign_request(
    sdk_dir: &str,
    contracts_chain_id: u64,
    public_key: &[u8],
    handle: &[u8; 32],
    identity: &[u8; 32],
    secret_key: &[u8; 32],
    context_id: &[u8; 32],
    nonce: &[u8; 32],
    allowed_domain_keys: &[[u8; 32]],
    start_timestamp: u64,
    duration_seconds: u64,
) -> SignedRequest {
    let domain_keys_csv = allowed_domain_keys
        .iter()
        .map(|k| hex0x(k))
        .collect::<Vec<_>>()
        .join(",");

    let output = Command::new("node")
        .arg("solana-userdecrypt-sign.mjs")
        .current_dir(sdk_dir)
        .env("UD_CONTRACTS_CHAIN_ID", contracts_chain_id.to_string())
        .env("UD_PUBLIC_KEY", hex0x(public_key))
        .env("UD_HANDLE", hex0x(handle))
        .env("UD_IDENTITY", hex0x(identity))
        .env("UD_SECRET_KEY", hex0x(secret_key))
        .env("UD_CONTEXT_ID", hex0x(context_id))
        .env("UD_NONCE", hex0x(nonce))
        .env("UD_ALLOWED_DOMAIN_KEYS", domain_keys_csv)
        .env("UD_START_TIMESTAMP", start_timestamp.to_string())
        .env("UD_DURATION_SECONDS", duration_seconds.to_string())
        .output()
        .expect("failed to spawn the js-sdk signer (node solana-userdecrypt-sign.mjs)");

    assert!(
        output.status.success(),
        "js-sdk signer failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let line = String::from_utf8(output.stdout).unwrap();
    serde_json::from_str(line.trim()).unwrap_or_else(|e| panic!("bad signer JSON ({e}): {line}"))
}

/// Runs the full Solana user-decrypt REQUEST half through the PUBLIC `@fhevm/sdk/solana` client
/// (build the ed25519-signed v3 request, POST to `/v3/user-decrypt`, return the aggregated KMS
/// signcrypted shares). The launcher prints `{ "shares": [{signature,payload,extraData}, ...] }` on
/// stdout; de-signcryption stays here (the SDK's TKMS WASM does not expose the Solana keccak-link
/// path yet, so this caller owns the ML-KEM key pair and passes its public key in via UD_PUBLIC_KEY).
#[allow(clippy::too_many_arguments)]
fn run_solana_launcher(
    launcher_dir: &str,
    relayer: &str,
    contracts_chain_id: u64,
    public_key: &[u8],
    handle: &[u8; 32],
    secret_key: &[u8; 32],
    context_id: &[u8; 32],
    nonce: &[u8; 32],
    allowed_domain_keys: &[[u8; 32]],
    start_timestamp: u64,
    duration_seconds: u64,
) -> serde_json::Value {
    let domain_keys_csv = allowed_domain_keys
        .iter()
        .map(|k| hex0x(k))
        .collect::<Vec<_>>()
        .join(",");

    let output = Command::new("bun")
        .args(["run", "solana-userdecrypt.ts"])
        .current_dir(launcher_dir)
        .env("UD_RELAYER_URL", relayer)
        .env("UD_CONTRACTS_CHAIN_ID", contracts_chain_id.to_string())
        .env("UD_PUBLIC_KEY", hex0x(public_key))
        .env("UD_HANDLE", hex0x(handle))
        .env("UD_SECRET_KEY", hex0x(secret_key))
        .env("UD_CONTEXT_ID", hex0x(context_id))
        .env("UD_NONCE", hex0x(nonce))
        .env("UD_ALLOWED_DOMAIN_KEYS", domain_keys_csv)
        .env("UD_START_TIMESTAMP", start_timestamp.to_string())
        .env("UD_DURATION_SECONDS", duration_seconds.to_string())
        .output()
        .expect("failed to spawn the @fhevm/sdk/solana launcher (bun run solana-userdecrypt.ts)");

    assert!(
        output.status.success(),
        "solana launcher failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    // The launcher prints the JSON result as the last `{...}` line on stdout.
    let stdout = String::from_utf8(output.stdout).unwrap();
    let line = stdout
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .unwrap_or_else(|| panic!("no JSON line in launcher stdout: {stdout}"));
    serde_json::from_str(line.trim()).unwrap_or_else(|e| panic!("bad launcher JSON ({e}): {line}"))
}

#[tokio::test]
#[ignore = "requires a running fhevm-cli stack with the Solana V2 user-decrypt path + a granted handle"]
async fn solana_user_decrypt_live() {
    let relayer = env_or("SOLANA_UD_RELAYER", "http://localhost:3000");
    let sdk_dir = env_or(
        "SOLANA_UD_SDK_DIR",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../../fhevm/sdk/js-sdk"),
    );
    let keypair_path = env_or(
        "SOLANA_UD_KEYPAIR",
        &format!("{}/.config/solana/id.json", env_or("HOME", "")),
    );
    let handle_hex =
        env::var("SOLANA_UD_HANDLE").expect("SOLANA_UD_HANDLE (0x..32 bytes) required");
    let expected: u64 = env_or("SOLANA_UD_EXPECTED", "0").parse().unwrap();
    // The connector reads the host chain id from the handle bytes; the signed preimage must commit
    // to that same chain id.
    let contracts_chain_id: u64 = env_or("SOLANA_UD_CHAIN_ID", "9223372036854788153")
        .parse()
        .unwrap();

    // 1. ML-KEM ephemeral keypair (non-wasm path). The serialized public key is the request's
    //    `publicKey`; kms-core validates it via `UnifiedPublicEncKey::deserialize_and_validate`.
    let mut rng = AesRng::from_entropy();
    let (unified_sk, unified_pk) = Encryption::new(PkeSchemeType::MlKem512, &mut rng)
        .keygen()
        .unwrap();
    let mut pk_bytes = Vec::new();
    tfhe::safe_serialization::safe_serialize(&unified_pk, &mut pk_bytes, SAFE_SER_SIZE_LIMIT)
        .unwrap();

    // 2. ed25519 user identity. The handle's ACL on the host grants USE to this Solana pubkey, and
    //    the compute leg uses the same pubkey as the ACL domain key — so the request's allowed ACL
    //    domain-key scope is exactly `[identity]`.
    let (seed, pubkey) = load_solana_keypair(&keypair_path);
    let handle = alloy_primitives::hex::decode(handle_hex.trim_start_matches("0x")).unwrap();
    let handle32: [u8; 32] = handle.try_into().expect("handle must be 32 bytes");

    // context_id (32-byte BE): the KMS context the connector validates + routes to. Carried in the
    // context-only `extraData` (v0x01) the SDK builds; the ed25519 auth fields travel as typed fields.
    let context_u256 = U256::from_str_radix(
        &env_or(
            "SOLANA_UD_CONTEXT_ID",
            "3166189940082864718613269121331309980362851143201109172953918312716374638593",
        ),
        10,
    )
    .unwrap();
    let context_id: [u8; 32] = context_u256.to_be_bytes();
    let nonce: [u8; 32] = rand::random();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let start_ts = now - 60; // small buffer so startTimestamp <= block time
    let duration_seconds = 30u64 * 24 * 3600;

    // 3. Run the user-decrypt request half.
    let attack = env::var("SOLANA_UD_ATTACK").ok();

    // Adversarial L4 (a): publicKey-substitution / relayer-bypass. The public @fhevm/sdk/solana
    // client signs and POSTs atomically — it cannot desync the signed key from the posted key (that
    // is the security property), so the attack cannot route through it. Sign via the low-level
    // js-sdk signer, then POST a body whose `publicKey` was swapped AFTER signing: the ed25519
    // signature no longer binds it, the kms-connector rejects it, and NO plaintext is returned.
    if attack.as_deref() == Some("pubkey_substitution") {
        let signed = sdk_sign_request(
            &sdk_dir,
            contracts_chain_id,
            &pk_bytes,
            &handle32,
            &pubkey,
            &seed,
            &context_id,
            &nonce,
            &[pubkey],
            start_ts,
            duration_seconds,
        );
        assert_eq!(signed.attestation_type, "solana-ed25519-user-decrypt-v1");
        // The signer must echo back the publicKey it signed — the swap below changes it AFTER this.
        assert_eq!(
            signed.public_key,
            hex0x(&pk_bytes),
            "signer must return the publicKey it was given"
        );
        let (_atk_sk, atk_pk) = Encryption::new(PkeSchemeType::MlKem512, &mut rng)
            .keygen()
            .unwrap();
        let mut atk_bytes = Vec::new();
        tfhe::safe_serialization::safe_serialize(&atk_pk, &mut atk_bytes, SAFE_SER_SIZE_LIMIT)
            .unwrap();
        assert_ne!(
            atk_bytes, pk_bytes,
            "attacker key must differ from the signed key"
        );
        println!(
            "[L4-a] swapping publicKey AFTER signing (signature still binds the original key)"
        );
        let user_address = signed.user_address.clone();
        let body = serde_json::json!({
            "attestationType": signed.attestation_type,
            "attestedPayload": {
                "version": "2.0",
                "type": "user_decryption",
                "handles": [{
                    "ctHandle": signed.handles[0],
                    "contractAddress": user_address,
                    "ownerAddress": user_address,
                }],
                "userAddress": user_address,
                "allowedContracts": [],
                "requestValidity": {
                    "startTimestamp": start_ts.to_string(),
                    "durationSeconds": duration_seconds.to_string(),
                },
                "publicKey": hex0x(&atk_bytes),
                "extraData": signed.extra_data,
                "solanaUserIdentity": signed.solana_user_identity,
                "solanaNonce": signed.solana_nonce,
                "solanaAllowedAclDomainKeys": signed.solana_allowed_acl_domain_keys,
            },
            "signature": signed.signature,
        });
        let http = reqwest::Client::new();
        let post = http
            .post(format!("{relayer}/v3/user-decrypt"))
            .json(&body)
            .send()
            .await
            .unwrap();
        let post_status = post.status();
        let post_json: serde_json::Value = post.json().await.unwrap();
        println!("POST {post_status}: {post_json}");
        assert!(
            post_status.is_success(),
            "relayer rejected the request: {post_json}"
        );
        let job_id = post_json["result"]["jobId"]
            .as_str()
            .expect("jobId")
            .to_string();
        for _ in 0..45 {
            let r = http
                .get(format!("{relayer}/v3/user-decrypt/{job_id}"))
                .send()
                .await
                .unwrap();
            let j: serde_json::Value = r.json().await.unwrap();
            match j["status"].as_str() {
                Some("succeeded") => panic!(
                    "SECURITY: publicKey-substituted user-decrypt SUCCEEDED — plaintext re-encrypted \
                     to the attacker key: {j}"
                ),
                Some("failed") => {
                    println!("[L4-a] request REJECTED (job failed) — no plaintext returned: {j}");
                    return;
                }
                _ => tokio::time::sleep(std::time::Duration::from_secs(2)).await,
            }
        }
        println!(
            "[L4-a] request did NOT succeed within the poll window — no plaintext returned (rejected)"
        );
        return;
    }

    // Happy path: route the request through the PUBLIC @fhevm/sdk/solana client (build the v3
    // request, POST to /v3/user-decrypt, return the aggregated KMS signcrypted shares). The SDK's
    // TKMS WASM does not expose the Solana keccak-link de-signcryption yet, so this caller owns the
    // ML-KEM key pair (passing its public key to the launcher) and de-signcrypts the shares below.
    let launcher_dir = env_or(
        "SOLANA_UD_LAUNCHER_DIR",
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../fhevm/test-suite/fhevm"
        ),
    );
    let launcher_out = run_solana_launcher(
        &launcher_dir,
        &relayer,
        contracts_chain_id,
        &pk_bytes,
        &handle32,
        &seed,
        &context_id,
        &nonce,
        &[pubkey],
        start_ts,
        duration_seconds,
    );
    println!("launcher result: {launcher_out}");

    // 5. Parse the aggregated shares -> UserDecryptionResponse (external EIP-712 signature +
    //    bincode-serialized payload), then de-signcrypt via the Solana path.
    let shares = launcher_out["shares"]
        .as_array()
        .expect("launcher shares[] array");
    let mut agg_resp = Vec::new();
    let mut kms_pk: Option<PublicSigKey> = None;
    for share in shares {
        let external_signature = alloy_primitives::hex::decode(
            share["signature"]
                .as_str()
                .unwrap_or("")
                .trim_start_matches("0x"),
        )
        .unwrap();
        let payload_bytes = alloy_primitives::hex::decode(
            share["payload"]
                .as_str()
                .unwrap_or("")
                .trim_start_matches("0x"),
        )
        .unwrap();
        let payload: UserDecryptionResponsePayload =
            bc2wrap::deserialize_slice(&payload_bytes).unwrap();
        if kms_pk.is_none() {
            kms_pk = Some(bc2wrap::deserialize_slice(&payload.verification_key).unwrap());
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
    server_pks.insert(
        1u32,
        kms_pk.expect("KMS verification key in response payload"),
    );
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

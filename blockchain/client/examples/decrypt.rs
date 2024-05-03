use kms_blockchain_client::client::{Client, ClientBuilder};
use serde_json::json;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_line_number(true)
        .with_file(true)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .init();
    // Alice's mnemonic; ensure you use a secure way to handle the real mnemonic!
    // let alice_mnemonic_phrase = "bachelor similar spirit copper rely carbon web hobby conduct wrap conduct wire shine parrot erosion divert crucial balance lock reason price ignore educate open";
    let bob_mnemonic_phrase = "feel wife neither never floor volume express actor initial year throw hawk pink gaze deny prevent helmet clump hurt hour river behind employ ribbon";
    let mut client: Client = ClientBuilder::builder()
        .mnemonic_wallet(Some(bob_mnemonic_phrase))
        .grpc_addresses(vec!["http://localhost:9090"])
        .contract_address("wasm14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9s0phg4d")
        .build()
        .try_into()
        .unwrap();

    // Decrypt the ciphertext
    let ciphertext = vec![1, 2, 3, 4, 5];
    let fhe_type = "euint8";

    let msg_payload = json!({
      "decrypt": {
        "ciphertext": ciphertext,
        "fhe_type": fhe_type.to_string()
      }
    })
    .to_string();

    let response = client
        .execute_contract(msg_payload.as_bytes(), 100_000u64)
        .await
        .unwrap();
    tracing::info!("Response: {:?}", response.clone().tx_response.unwrap());
}

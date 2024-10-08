use events::kms::{DecryptValues, FheType, KmsMessage, OperationValue};
use kms_blockchain_client::client::{Client, ClientBuilder, ExecuteContractRequest};

#[tokio::main]
async fn main() {
    // Alice's mnemonic; ensure you use a secure way to handle the real mnemonic!
    // let alice_mnemonic_phrase = "bachelor similar spirit copper rely carbon web hobby conduct wrap conduct wire shine parrot erosion divert crucial balance lock reason price ignore educate open";
    let bob_mnemonic_phrase = "whisper stereo great helmet during hollow nominee skate frown daughter donor pool ozone few find risk cigar practice essay sketch rhythm novel dumb host";

    let client: Client = ClientBuilder::builder()
        .mnemonic_wallet(Some(bob_mnemonic_phrase))
        .grpc_addresses(vec!["http://localhost:9090"])
        .contract_address("wasm14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9s0phg4d")
        .kv_store_address("http://localhost:8088")
        .build()
        .try_into()
        .unwrap();

    // Decrypt the ciphertext
    let ciphertext = vec![1, 2, 3, 4, 5];

    let operation_response = OperationValue::Decrypt(DecryptValues::new(
        vec![1, 2, 3],
        vec![ciphertext.clone()],
        vec![FheType::Euint8],
        None::<Vec<Vec<u8>>>,
        1,
        "0xEEdA6bf26964aF9D7Eed9e03e53415D37aa960EE".to_string(),
        "some proof".to_string(),
        "eip712name".to_string(),
        "1".to_string(),
        vec![1],
        "0x33dA6bF26964af9d7eed9e03E53415D37aA960EE".to_string(),
        vec![],
    ));

    let msg = KmsMessage::builder().value(operation_response).build();

    let request = ExecuteContractRequest::builder()
        .message(msg)
        .gas_limit(100_000u64)
        .build();

    let response = client.execute_contract(request).await.unwrap();
    tracing::info!("Response: {:?}", response);
}

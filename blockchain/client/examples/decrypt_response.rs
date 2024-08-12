use clap::Parser;
use events::kms::{DecryptResponseValues, KmsMessage, OperationValue};
use kms_blockchain_client::client::{Client, ClientBuilder, ExecuteContractRequest};

#[derive(Debug, Parser)]
struct Params {
    #[clap(short, long)]
    txn_id: String,
}

#[tokio::main]
async fn main() {
    let params = Params::parse();
    // Alice's mnemonic; ensure you use a secure way to handle the real mnemonic!
    // let alice_mnemonic_phrase = "bachelor similar spirit copper rely carbon web hobby conduct wrap conduct wire shine parrot erosion divert crucial balance lock reason price ignore educate open";
    let bob_mnemonic_phrase = "whisper stereo great helmet during hollow nominee skate frown daughter donor pool ozone few find risk cigar practice essay sketch rhythm novel dumb host";
    let mut client: Client = ClientBuilder::builder()
        .mnemonic_wallet(Some(bob_mnemonic_phrase))
        .grpc_addresses(vec!["http://localhost:9090"])
        .contract_address("wasm14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9s0phg4d")
        .build()
        .try_into()
        .unwrap();

    let txn_id = hex::decode(params.txn_id).unwrap();
    let plaintext = vec![6, 7, 8, 9, 10];

    let operation_response = OperationValue::DecryptResponse(
        DecryptResponseValues::builder()
            .signature(vec![1, 2, 3])
            .payload(plaintext.clone())
            .build(),
    );
    let msg = KmsMessage::builder()
        .txn_id(Some(txn_id.into()))
        .value(operation_response)
        .build();

    let request = ExecuteContractRequest::builder()
        .message(msg)
        .gas_limit(100_000u64)
        .build();

    // send the decrypted response to the contract
    let response = client.execute_contract(request).await.unwrap();
    tracing::info!("Response: {:?}", response);
}

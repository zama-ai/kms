use client::client::{Client, Metadata};

#[tokio::main]
async fn main() {
    // Alice's mnemonic; ensure you use a secure way to handle the real mnemonic!
    // let alice_mnemonic_phrase = "bachelor similar spirit copper rely carbon web hobby conduct wrap conduct wire shine parrot erosion divert crucial balance lock reason price ignore educate open";
    let bob_mnemonic_phrase = "feel wife neither never floor volume express actor initial year throw hawk pink gaze deny prevent helmet clump hurt hour river behind employ ribbon";
    let key = Client::key_from_mnemonic(bob_mnemonic_phrase);
    let client = Client::new(
        "http://localhost:36657",
        "wasm1xr3rq8yvd7qplsw5yx90ftsr2zdhg4e9z60h5duusgxpv72hud3s0nakef",
        key,
        None,
        2,
    );
    // increment this by 1 for each request (so 2 in this case)
    let sequence_number = 5;

    // Decrypt the ciphertext
    let ciphertext = vec![1, 2, 3, 4, 5];
    let fhe_type = "euint8";
    let response = client
        .decrypt_request(
            ciphertext,
            fhe_type,
            &Metadata {
                sequence_number,
                gas_limit: 200_000u64,
            },
        )
        .await
        .unwrap();
    println!("Response: {:?}", response);
    println!("Tx hash: {}", response.hash);
    println!("Tx height: {}", response.height);

    // filter the wasm-decrypt event
    let wasm_decrypt_event = response
        .tx_result
        .events
        .iter()
        .find(|event| event.kind == "wasm-decrypt")
        .unwrap();

    println!(
        "Wasm Decrypt Event Attributes: {:?}",
        wasm_decrypt_event.attributes
    );

    let txn_id = hex::decode(wasm_decrypt_event.attributes[1].value.clone()).unwrap();
    let plaintext = vec![6, 7, 8, 9, 10];

    let sequence_number = sequence_number + 1;
    // send the decrypted response to the contract
    client
        .decrypt_response(
            txn_id,
            plaintext,
            &Metadata {
                sequence_number,
                gas_limit: 200_000u64,
            },
        )
        .await
        .unwrap();
}

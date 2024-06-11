use ethers::prelude::*;
use gateway::common::config::test_async_decrypt_address;
use std::process::{Command, Stdio};
use std::sync::Arc;

abigen!(
    TestAsyncDecrypt,
    "./artifacts/TestAsyncDecrypt.abi",
    event_derives(serde::Deserialize, serde::Serialize)
);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a new wallet with a random private key
    let wallet = LocalWallet::new(&mut rand::thread_rng());

    println!(
        "docker exec -i zama-chain-fevm-full-node-1 faucet {}",
        hex::encode(wallet.address().as_bytes())
    );

    Command::new("docker")
        .args([
            "exec",
            "-i",
            "zama-chain-fevm-full-node-1",
            "faucet",
            &hex::encode(wallet.address().as_bytes()),
        ])
        .stdout(Stdio::piped())
        .output()
        .expect("failed to execute process");

    // sleep for a bit to let the faucet complete
    std::thread::sleep(std::time::Duration::from_secs(5));

    let provider = Provider::<Ws>::connect("ws://0.0.0.0:8546").await?;

    let chain_id = provider.get_chainid().await?.as_u64();
    println!("Chain ID: {}", chain_id);
    let client = SignerMiddleware::new(provider.clone(), wallet.with_chain_id(chain_id));
    let client = Arc::new(client);
    let addr = test_async_decrypt_address();

    println!("Contract deployed at: {}", hex::encode(addr.as_bytes()));
    let contract = TestAsyncDecrypt::new(addr, client.clone());

    println!("Requesting uint8");
    let _receipt: TransactionReceipt = contract.request_uint_8().send().await?.await?.unwrap();
    let response = contract.y_uint_8().await?;
    println!("y_uint_8: {:#?}", response);

    Ok(())
}

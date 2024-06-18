use ethers::prelude::*;
use gateway::config::{GatewayConfig, Settings};
use std::process::{Command, Stdio};
use std::sync::Arc;

abigen!(
    TestAsyncDecrypt,
    "./artifacts/TestAsyncDecrypt.abi",
    event_derives(serde::Deserialize, serde::Serialize)
);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config: GatewayConfig = Settings::builder()
        .path(Some("config/gateway"))
        .build()
        .init_conf()
        .unwrap();

    // Generate a new wallet with a random private key
    let wallet = LocalWallet::new(&mut rand::thread_rng());

    println!(
        "docker exec -i ethermintnode0 faucet {}",
        hex::encode(wallet.address().as_bytes())
    );

    Command::new("docker")
        .args([
            "exec",
            "-i",
            "ethermintnode0",
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
    let addr = config.ethereum.test_async_decrypt_address;

    println!("Contract deployed at: {}", hex::encode(addr.as_bytes()));
    let contract = TestAsyncDecrypt::new(addr, client.clone());

    loop {
        //println!("Requesting bool");
        //let _receipt: TransactionReceipt = contract.request_bool().send().await?.await?.unwrap();
        //let response = contract.y_bool().await?;
        //println!("y_bool: {:#?}", response);

        println!("Requesting uint4");
        let _receipt: TransactionReceipt = contract.request_uint_4().send().await?.await?.unwrap();
        let response = contract.y_uint_4().await?;
        println!("y_uint_4: {:#?}", response);

        println!("Requesting uint8");
        let _receipt: TransactionReceipt = contract.request_uint_8().send().await?.await?.unwrap();
        let response = contract.y_uint_8().await?;
        println!("y_uint_8: {:#?}", response);

        /*
        println!("Requesting uint16");
        let _receipt: TransactionReceipt = contract.request_uint_16().send().await?.await?.unwrap();
        let response = contract.y_uint_16().await?;
        println!("y_uint_16: {:#?}", response);


        println!("Requesting uint32");
        let _receipt: TransactionReceipt = contract
            .request_uint_32(17, 13)
            .send()
            .await?
            .await?
            .unwrap();
        let response = contract.y_uint_32().await?;
        println!("y_uint_32: {:#?}", response);

        println!("Requesting uint64");
        let _receipt: TransactionReceipt = contract.request_uint_64().send().await?.await?.unwrap();
        let response = contract.y_uint_64().await?;
        println!("y_uint_64: {:#?}", response);

        println!("Requesting address");
        let _receipt: TransactionReceipt = contract.request_address().send().await?.await?.unwrap();
        let response = contract.y_address().await?;
        println!("y_address: {:#?}", response);
        */
    }
}

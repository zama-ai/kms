use crate::transactions::transaction::Payload::SetConfig as SetConfigPayload;
use crate::transactions::SetConfig;
use protocol::transactions;
use protocol::transactions::RawTransaction;
use protocol::wallet::Wallet;

#[tokio::main]
async fn main() {
    // capture number of iterations from command line or default to 5
    let args: Vec<String> = std::env::args().collect();
    let iterations = if args.len() > 1 {
        args[1].parse::<u64>().unwrap()
    } else {
        1000
    };

    let alice = Wallet::new();
    for i in 0..iterations {
        let config_txn = SetConfigPayload(SetConfig {
            raw: Some(RawTransaction {
                nonce: rand::random::<u64>(),
                to: None,
                value: 100,
                gas_price: 1,
                gas_limit: 100,
            }),
            key: format!("test-key-{}", i),
            value: format!("test-key-{}", rand::random::<u64>()),
        });
        let transaction = alice.sign_transaction(&config_txn);
        assert!(Wallet::verify_transaction(&transaction));
        let raw_txn = bincode::serialize(&transaction).unwrap();
        println!(
            "Sending transaction {}: 0x{}'",
            i,
            hex::encode(raw_txn.clone()).clone()
        );

        // use GET to send the transaction to the ABCI server
        // let response = reqwest::get(&format!("http://127.0.0.1:36657/broadcast_tx_commit?tx=0x{}", hex::encode(raw_txn))).await;
        let _ = reqwest::get(&format!(
            "http://127.0.0.1:36657/broadcast_tx_async?tx=0x{}",
            hex::encode(raw_txn)
        ))
        .await;
        //println!("{:?}", response);
    }
}

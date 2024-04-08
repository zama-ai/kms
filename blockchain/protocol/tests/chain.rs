//! chain application integration tests.

mod kvstore_app_integration {
    use protocol::adapter::ContractAdapter;
    use protocol::transactions;
    use protocol::transactions::transaction::Payload;
    use protocol::transactions::transaction::Payload::Decryption;
    use protocol::transactions::transaction::Payload::SetConfig;
    use protocol::transactions::RawTransaction;
    use protocol::wallet::Verify;
    use protocol::wallet::Wallet;
    use std::thread;
    use tendermint_abci::{ClientBuilder, ServerBuilder};
    use tendermint_proto::abci::{
        CheckTxType, RequestCheckTx, RequestFinalizeBlock, RequestInfo, RequestQuery,
    };

    fn prepare_transaction(payload: Option<Payload>) -> Vec<u8> {
        let wallet = Wallet::new();
        let transaction = wallet.sign_transaction(&payload.unwrap());
        println!("is_verified: {:?}", transaction.verify());
        assert!(transaction.verify());

        let txn_bytes = bincode::serialize(&transaction).unwrap();
        println!("txn_bytes: {:?}", hex::encode(txn_bytes.clone()));
        txn_bytes
    }

    #[test]
    #[ignore = "need to implement the decryption contract"]
    fn test_decryption_transaction() {
        let app = ContractAdapter::default();
        let server = ServerBuilder::default().bind("127.0.0.1:0", app).unwrap();
        let server_addr = server.local_addr();
        thread::spawn(move || server.listen());

        let mut client = ClientBuilder::default().connect(server_addr).unwrap();

        let info_request = client.info(RequestInfo::default()).unwrap();
        println!("info_request: {:?}", info_request);

        let txn_bytes = prepare_transaction(Some(Decryption(transactions::Decryption {
            raw: Some(RawTransaction {
                nonce: rand::random::<u64>(),
                to: None,
                value: 100,
                gas_price: 1,
                gas_limit: 100,
            }),
            ciphertext: vec![1, 2, 3, 4],
        })));

        // CheckTx - for debugging
        let check_tx_response = client
            .check_tx(RequestCheckTx {
                r#type: CheckTxType::New.into(),
                tx: txn_bytes.clone().into(),
            })
            .unwrap();
        println!("check_tx_response: {:?}", check_tx_response);

        // FinalizeBlock - commit the transaction to the chain
        let finalize_block_response = client
            .finalize_block(RequestFinalizeBlock {
                txs: vec![txn_bytes.into()],
                ..Default::default()
            })
            .unwrap();
        println!("finalize_block_response: {:?}", finalize_block_response);

        // Commit - commit the block to the chain
        let commit_response = client.commit().unwrap();
        println!("commit_response: {:?}", commit_response);

        // Query - get the transaction from the chain
        /*
        let query_response = client
            .query(RequestQuery {
                data: "test-key".into(),
                path: "".to_string(),
                height: 0,
                prove: false,
            })
            .unwrap();
        assert_eq!(query_response.value, "test-value".as_bytes());
        */
    }

    #[test]
    fn test_set_config_transaction() {
        let app = ContractAdapter::default();
        let server = ServerBuilder::default().bind("127.0.0.1:0", app).unwrap();
        let server_addr = server.local_addr();
        thread::spawn(move || server.listen());

        let mut client = ClientBuilder::default().connect(server_addr).unwrap();

        let info_request = client.info(RequestInfo::default()).unwrap();
        println!("info_request: {:?}", info_request);

        let txn_bytes = prepare_transaction(Some(SetConfig(transactions::SetConfig {
            raw: Some(RawTransaction {
                nonce: rand::random::<u64>(),
                to: None,
                value: 100,
                gas_price: 1,
                gas_limit: 100,
            }),
            key: "test-key".to_string(),
            value: "test-value".to_string(),
        })));

        // CheckTx - for debugging
        let check_tx_response = client
            .check_tx(RequestCheckTx {
                r#type: CheckTxType::New.into(),
                tx: txn_bytes.clone().into(),
            })
            .unwrap();
        println!("check_tx_response: {:?}", check_tx_response);

        // FinalizeBlock - commit the transaction to the chain
        let finalize_block_response = client
            .finalize_block(RequestFinalizeBlock {
                txs: vec![txn_bytes.into()],
                ..Default::default()
            })
            .unwrap();
        println!("finalize_block_response: {:?}", finalize_block_response);

        // Commit - commit the block to the chain
        let commit_response = client.commit().unwrap();
        println!("commit_response: {:?}", commit_response);

        // Query - get the transaction from the chain

        let query_response = client
            .query(RequestQuery {
                data: "test-key".into(),
                path: "/kms/config".to_string(),
                height: 0,
                prove: false,
            })
            .unwrap();
        println!("query_response: {:?}", query_response);
        assert_eq!(query_response.value, "test-value".as_bytes());
    }

    #[test]
    #[ignore = "end to end integration test"]
    fn test_belt() {
        let mut client = ClientBuilder::default().connect("127.0.0.1:36657").unwrap();
        let info_request = client.info(RequestInfo::default()).unwrap();
        println!("info_request: {:?}", info_request);

        let txn_bytes = prepare_transaction(Some(SetConfig(transactions::SetConfig {
            raw: Some(RawTransaction {
                nonce: rand::random::<u64>(),
                to: None,
                value: 100,
                gas_price: 1,
                gas_limit: 100,
            }),
            key: format!("test-key-{}", rand::random::<u64>()),
            value: format!("test-value-{}", rand::random::<u64>()),
        })));

        // CheckTx - for debugging
        let check_tx_response = client
            .check_tx(RequestCheckTx {
                r#type: CheckTxType::New.into(),
                tx: txn_bytes.clone().into(),
            })
            .unwrap();
        println!("check_tx_response: {:?}", check_tx_response);

        // FinalizeBlock - commit the transaction to the chain
        let finalize_block_response = client
            .finalize_block(RequestFinalizeBlock {
                txs: vec![txn_bytes.into()],
                ..Default::default()
            })
            .unwrap();
        println!("finalize_block_response: {:?}", finalize_block_response);

        // Commit - commit the block to the chain
        let commit_response = client.commit().unwrap();
        println!("commit_response: {:?}", commit_response);

        // Query - get the transaction from the chain

        let query_response = client
            .query(RequestQuery {
                data: "test-key".into(),
                path: "/kms/config".to_string(),
                height: 0,
                prove: false,
            })
            .unwrap();
        println!("query_response: {:?}", query_response);
        assert_eq!(query_response.value, "test-value".as_bytes());
    }
}

use crate::blockchain::Blockchain;
use crate::blockchain::KmsEventSubscriber;
use crate::config::GatewayConfig;
use crate::config::KmsMode;
use crate::util::conversion::TokenizableFrom;
use crate::util::footprint;
use alloy_primitives::Address;
use anyhow::anyhow;
use async_trait::async_trait;
use bincode::{deserialize, serialize};
use cosmos_proto::messages::cosmos::base::abci::v1beta1::TxResponse;
use ethers::abi::Token;
use ethers::prelude::*;
use events::kms::DecryptValues;
use events::kms::KmsEvent;
use events::kms::KmsOperation;
use events::kms::OperationValue;
use events::kms::ReencryptResponseValues;
use events::kms::ReencryptValues;
use events::kms::TransactionId;
use events::kms::{FheType, KmsMessage};
use events::HexVector;
use kms_blockchain_client::client::Client;
use kms_blockchain_client::client::ClientBuilder;
use kms_blockchain_client::client::ExecuteContractRequest;
use kms_blockchain_client::client::ProtoCoin;
use kms_blockchain_client::query_client::ContractQuery;
use kms_blockchain_client::query_client::OperationQuery;
use kms_blockchain_client::query_client::QueryClient;
use kms_blockchain_client::query_client::QueryClientBuilder;
use kms_blockchain_client::query_client::QueryContractRequest;
use kms_lib::client::recover_ecdsa_public_key_from_signature;
use kms_lib::kms::DecryptionResponsePayload;
use kms_lib::rpc::rpc_types::Plaintext;
use kms_lib::rpc::rpc_types::CURRENT_FORMAT_VERSION;
use sha3::Digest;
use sha3::Sha3_256;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use strum::IntoEnumIterator;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::RwLock;
use tracing::info;

#[derive(Clone)]
pub(crate) struct KmsBlockchainImpl {
    pub(crate) client: Arc<RwLock<Client>>,
    pub(crate) query_client: Arc<QueryClient>,
    pub(crate) responders: Arc<RwLock<HashMap<TransactionId, oneshot::Sender<KmsEvent>>>>,
    pub(crate) event_sender: mpsc::Sender<KmsEvent>,
    pub(crate) config: GatewayConfig,
}

#[async_trait]
impl KmsEventSubscriber for KmsBlockchainImpl {
    async fn receive(&self, event: KmsEvent) -> anyhow::Result<()> {
        tracing::debug!("🤠 Received KmsEvent: {:?}", event);
        self.event_sender
            .send(event)
            .await
            .map_err(|e| anyhow!(e.to_string()))
    }
}

impl<'a> KmsBlockchainImpl {
    fn new(
        mnemonic: Option<String>,
        addresses: Vec<&'a str>,
        contract_address: &'a str,
        config: GatewayConfig,
    ) -> Self {
        let (event_sender, mut event_receiver): (mpsc::Sender<KmsEvent>, mpsc::Receiver<KmsEvent>) =
            mpsc::channel(100);
        let responders = Arc::new(RwLock::new(HashMap::<
            TransactionId,
            oneshot::Sender<KmsEvent>,
        >::new()));
        let responders_clone = responders.clone();

        tokio::spawn(async move {
            while let Some(event) = event_receiver.recv().await {
                if let Some(tx) = responders_clone.write().await.remove(event.txn_id()) {
                    let _ = tx.send(event);
                }
            }
        });

        Self {
            client: Arc::new(RwLock::new(
                ClientBuilder::builder()
                    .mnemonic_wallet(mnemonic.as_deref())
                    .grpc_addresses(addresses.clone())
                    .contract_address(contract_address)
                    .build()
                    .try_into()
                    .unwrap(),
            )),
            query_client: Arc::new(
                QueryClientBuilder::builder()
                    .grpc_addresses(addresses.clone())
                    .build()
                    .try_into()
                    .unwrap(),
            ),
            responders,
            event_sender,
            config,
        }
    }

    pub(crate) fn new_from_config(config: GatewayConfig) -> Self {
        let mnemonic = Some(config.kms.mnemonic.to_string());
        let binding = config.kms.address.to_string();
        let addresses = vec![binding.as_str()];
        let contract_address = &config.kms.contract_address;
        Self::new(
            mnemonic,
            addresses,
            contract_address.to_string().as_str(),
            config,
        )
    }

    pub(crate) async fn wait_for_callback(
        &self,
        txn_id: &TransactionId,
    ) -> anyhow::Result<KmsEvent> {
        let (tx, rx) = oneshot::channel();
        self.responders.write().await.insert(txn_id.clone(), tx);

        match tokio::time::timeout(tokio::time::Duration::from_secs(100), rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(anyhow!("Failed to receive response")),
            Err(_) => Err(anyhow!("Request timed out")),
        }
    }

    //#[retrying::retry(stop=(attempts(5)|duration(10)),wait=fixed(0.25))]
    pub(crate) async fn call_execute_contract(
        &self,
        client: &mut Client,
        request: &ExecuteContractRequest,
    ) -> Result<TxResponse, kms_blockchain_client::errors::Error> {
        client.execute_contract(request.clone()).await
    }

    async fn make_req_to_kms_blockchain(
        &self,
        data_size: u32,
        operation: OperationValue,
        proof: Vec<u8>,
    ) -> anyhow::Result<Vec<KmsEvent>> {
        let request = ExecuteContractRequest::builder()
            .message(KmsMessage::builder().value(operation).proof(proof).build())
            .gas_limit(10_000_000u64)
            .funds(vec![ProtoCoin::builder()
                .denom("ucosm".to_string())
                .amount(data_size as u64)
                .build()])
            .build();

        let mut client = self.client.write().await;
        let response = self.call_execute_contract(&mut client, &request).await?;

        let resp;
        loop {
            let query_response = self.query_client.query_tx(response.txhash.clone()).await?;
            if let Some(qr) = query_response {
                resp = qr;
                break;
            } else {
                tracing::warn!("Waiting for transaction to be included in a block");
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                continue;
            }
        }
        resp.events
            .iter()
            .filter(|x| KmsOperation::iter().any(|attr| x.r#type == format!("wasm-{}", attr)))
            .map(to_event)
            .map(<cosmwasm_std::Event as TryInto<KmsEvent>>::try_into)
            .collect::<Result<Vec<KmsEvent>, _>>()
    }

    async fn store_ciphertext(&self, ctxt: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        // Convert the Vec<u8> to a hex string
        let hex_data = hex::encode(&ctxt);

        // Send the hex-encoded data to the kv_store
        let response = reqwest::Client::new()
            .post(format!("{}/store", self.config.storage.url))
            .body(hex_data)
            .send()
            .await?;

        // Print the response
        if response.status() != 200 {
            anyhow::bail!("Failed to store ciphertext: {}", response.text().await?);
        }

        let handle = response.text().await?;
        tracing::debug!("Response: {}", handle);
        tracing::info!("📦 Stored ciphertext, handle: {}", handle);

        let handle_bytes = hex::decode(handle).unwrap();
        Ok(handle_bytes)
    }
}

#[async_trait]
impl Blockchain for KmsBlockchainImpl {
    async fn decrypt(&self, ciphertext: Vec<u8>, fhe_type: FheType) -> anyhow::Result<Token> {
        let ctxt_handle = self.store_ciphertext(ciphertext.clone()).await?;

        let operation = events::kms::OperationValue::Decrypt(
            DecryptValues::builder()
                .version(CURRENT_FORMAT_VERSION)
                .key_id(hex::decode(self.config.kms.key_id.as_str()).unwrap())
                .ciphertext_handle(ctxt_handle.clone())
                .randomness(vec![6, 7, 8, 9, 0])
                .fhe_type(fhe_type)
                .build(),
        );

        // TODO: Proof should be generated by the client
        let proof = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0];

        // send coins 1:1 with the ciphertext size
        let data_size = footprint::extract_ciphertext_size(&ctxt_handle);
        tracing::info!("🍊 Decrypting ciphertext of size: {:?}", data_size);

        let evs = self
            .make_req_to_kms_blockchain(data_size, operation, proof)
            .await?;

        // TODO what if we have multiple events?
        let ev = evs[0].clone();

        tracing::info!(
            "✉️ TxId: {:?} - Proof: {:?}",
            ev.txn_id().to_hex(),
            ev.proof().to_hex()
        );

        tracing::info!(
            "🍊 Waiting for callback from KMS, txn_id: {:?}",
            ev.txn_id().to_hex()
        );
        let event = self.wait_for_callback(ev.txn_id()).await?;
        tracing::info!("🍊 Received callback from KMS: {:?}", event.txn_id());
        let request = QueryContractRequest::builder()
            .contract_address(self.config.kms.contract_address.to_string())
            .query(ContractQuery::GetOperationsValue(
                OperationQuery::builder().event(event.clone()).build(),
            ))
            .build();

        let results: Vec<OperationValue> = self.query_client.query_contract(request).await?;
        let ptxt = match self.config.mode {
            KmsMode::Centralized => match results.first().unwrap() {
                OperationValue::DecryptResponse(decrypt_response) => {
                    let payload: DecryptionResponsePayload = deserialize(
                        <&HexVector as Into<Vec<u8>>>::into(decrypt_response.payload()).as_slice(),
                    )
                    .unwrap();

                    tracing::info!(
                        "🍇🥐🍇🥐🍇🥐 Centralized Gateway decryption result payload: {:?}",
                        hex::encode(payload.plaintext.clone())
                    );
                    deserialize::<Plaintext>(&payload.plaintext)?
                }
                _ => return Err(anyhow::anyhow!("Invalid operation for request {:?}", event)),
            },
            KmsMode::Threshold => {
                let mut ptxts = Vec::new();
                // loop through the vector of results
                for value in results.iter() {
                    match value {
                        OperationValue::DecryptResponse(decrypt_response) => {
                            let payload: DecryptionResponsePayload = deserialize(
                                <&HexVector as Into<Vec<u8>>>::into(decrypt_response.payload())
                                    .as_slice(),
                            )
                            .unwrap();
                            tracing::info!(
                                "🥐🥐🥐🥐🥐🥐 Threshold Gateway decryption results payload: {:?}",
                                hex::encode(payload.plaintext.clone())
                            );
                            ptxts.push(deserialize::<Plaintext>(&payload.plaintext)?);
                        }
                        _ => {
                            return Err(anyhow::anyhow!(
                                "Invalid operation for request {:?}",
                                event
                            ))
                        }
                    };
                }

                // check that all received plaintexts are identical (optimistic case)
                // TODO: use majority vote to tolerate up to t malicious responses (unless we do that in an earlier step)
                let pivot = &ptxts[0];
                if ptxts.iter().all(|x| x == pivot) {
                    pivot.clone() // all plaintext are identical, return the first one
                } else {
                    return Err(anyhow::anyhow!(
                        "Threshold decryption failed: Received different plaintext values."
                    ));
                }
            }
        };

        tracing::info!("FheType: {:#?}", fhe_type);

        let res = match fhe_type {
            FheType::Ebool => ptxt.as_bool().to_token(),
            FheType::Euint4 => ptxt.as_u4().to_token(),
            FheType::Euint8 => ptxt.as_u8().to_token(),
            FheType::Euint16 => ptxt.as_u16().to_token(),
            FheType::Euint32 => ptxt.as_u32().to_token(),
            FheType::Euint64 => ptxt.as_u64().to_token(),
            FheType::Euint128 => ptxt.as_u128().to_token(),
            FheType::Euint160 => {
                let mut cake = vec![0u8; 32];
                ptxt.as_u160().copy_to_be_byte_slice(cake.as_mut_slice());
                ethers::types::Address::from_slice(&cake[12..]).to_token()
            }
            FheType::Euint256 => {
                let mut cake = vec![0u8; 32];
                ptxt.as_u256().copy_to_be_byte_slice(cake.as_mut_slice());
                U256::from_big_endian(&cake).to_token()
            }
            FheType::Euint512 => {
                todo!("Implement Euint512")
            }
            FheType::Euint1024 => {
                todo!("Implement Euint1024")
            }
            FheType::Euint2048 => {
                let mut cake = vec![0u8; 256];
                ptxt.as_u2048().copy_to_be_byte_slice(cake.as_mut_slice());
                let token = Token::Bytes(cake);
                info!(
                    "🍰 Euint2048 Token: {:#?}, ",
                    hex::encode(token.clone().into_bytes().unwrap())
                );
                token
            }
            FheType::Unknown => anyhow::bail!("Invalid ciphertext type"),
        };

        info!("🍊 plaintext: {:#?}", res);
        Ok(res)
    }

    #[allow(clippy::too_many_arguments)]
    async fn reencrypt(
        &self,
        signature: Vec<u8>,
        user_address: Vec<u8>,
        enc_key: Vec<u8>,
        fhe_type: FheType,
        ciphertext: Vec<u8>,
        eip712_verifying_contract: String,
        chain_id: U256,
    ) -> anyhow::Result<Vec<ReencryptResponseValues>> {
        tracing::info!(
            "🔒 Reencrypting ciphertext with signature: {:?}, user_address: {:?}, enc_key: {:?}, fhe_type: {:?}, eip712_verifying_contract: {:?}, chain_id: {:?}",
            hex::encode(&signature),
            hex::encode(&user_address),
            hex::encode(&enc_key),
            fhe_type,
            eip712_verifying_contract,
            chain_id
        );

        let ctxt_handle = self.store_ciphertext(ciphertext.clone()).await?;
        let mut hasher = Sha3_256::new();
        hasher.update(&ciphertext);
        let digest = hasher.finalize().to_vec();
        let ctxt_digest = digest.to_vec();

        let key_id = HexVector::from_hex(self.config.kms.key_id.as_str())?;
        tracing::info!(
            "🔒 Reencrypting ciphertext using key_id={:?}, ctxt_handle={}, ctxt_digest={}",
            key_id.to_hex(),
            hex::encode(&ctxt_handle),
            hex::encode(&ctxt_digest)
        );

        // TODO(later) check whether randomness is essential
        let randomness = vec![1, 2, 3, 4];
        let eip712_name = "Authorization token".to_string();
        let eip712_version = "1".to_string();
        let eip712_salt = HexVector(vec![]);

        // chain ID is 32 bytes
        let mut eip712_chain_id = vec![0u8; 32];
        chain_id.to_little_endian(&mut eip712_chain_id);

        // convert user_address to verification_key
        if user_address.len() != 20 {
            return Err(anyhow::anyhow!(
                "user_address {} bytes but 20 bytes is expected",
                user_address.len()
            ));
        }

        let domain = alloy_sol_types::eip712_domain! {
            name: eip712_name.clone(),
            version: eip712_version.clone(),
            chain_id: chain_id.as_u64(),
            verifying_contract: Address::from_str(eip712_verifying_contract.as_str()).unwrap(),
        };

        let verification_key =
            recover_ecdsa_public_key_from_signature(&signature, &enc_key, &domain, &user_address)?;

        // NOTE: the ciphertext digest must be the real SHA3 digest
        let reencrypt_values = ReencryptValues::builder()
            .signature(signature)
            .version(CURRENT_FORMAT_VERSION)
            .verification_key(serialize(&verification_key)?)
            .randomness(randomness)
            .enc_key(enc_key)
            .fhe_type(fhe_type)
            .key_id(key_id)
            .ciphertext_handle(ctxt_handle.clone())
            .ciphertext_digest(ctxt_digest)
            .eip712_name(eip712_name)
            .eip712_version(eip712_version)
            .eip712_chain_id(eip712_chain_id)
            .eip712_verifying_contract(eip712_verifying_contract)
            .eip712_salt(eip712_salt)
            .build();

        tracing::info!(
            "Reencryption EIP712 info: name={}, version={}, \
            chain_id={} (HEX), verifying_contract={}, salt={} (HEX)",
            reencrypt_values.eip712_name(),
            reencrypt_values.eip712_version(),
            reencrypt_values.eip712_chain_id().to_hex(),
            reencrypt_values.eip712_verifying_contract(),
            reencrypt_values.eip712_salt().to_hex(),
        );

        let operation = events::kms::OperationValue::Reencrypt(reencrypt_values);

        let proof = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0];
        // send coins 1:1 with the ciphertext size
        let data_size = footprint::extract_ciphertext_size(&ctxt_handle);
        tracing::info!("🍊 Reencrypting ciphertext of size: {:?}", data_size);
        let evs = self
            .make_req_to_kms_blockchain(data_size, operation, proof)
            .await?;

        // TODO what if we have multiple events?
        let ev = evs[0].clone();

        tracing::info!(
            "✉️ TxId: {:?} - Proof: {:?}",
            ev.txn_id().to_hex(),
            ev.proof().to_hex()
        );

        tracing::info!(
            "🍊 Waiting for callback from KMS, txn_id: {:?}",
            ev.txn_id().to_hex()
        );
        let event = self.wait_for_callback(ev.txn_id()).await?;
        tracing::info!("🍊 Received callback from KMS: {:?}", event.txn_id());
        let request = QueryContractRequest::builder()
            .contract_address(self.config.kms.contract_address.to_string())
            .query(ContractQuery::GetOperationsValue(
                OperationQuery::builder().event(event.clone()).build(),
            ))
            .build();

        let results: Vec<OperationValue> = self.query_client.query_contract(request).await?;

        match self.config.mode {
            KmsMode::Centralized => match results.first().unwrap() {
                OperationValue::ReencryptResponse(reencrypt_response) => {
                    tracing::info!(
                        "🍇🥐🍇🥐🍇🥐 Centralized Gateway signcrypted ct: {:?}",
                        reencrypt_response.signcrypted_ciphertext().to_hex()
                    );

                    // the output needs to have type Vec<ReencryptionResponse>
                    // in the centralized case there is only 1 element
                    let out = vec![reencrypt_response.clone()];
                    Ok(out)
                }
                _ => return Err(anyhow::anyhow!("Invalid operation for request {:?}", event)),
            },
            KmsMode::Threshold => {
                let mut out = vec![];
                for value in results.iter() {
                    match value {
                        OperationValue::ReencryptResponse(reencrypt_response) => {
                            // the output needs to have type Vec<ReencryptionResponse>
                            // in the centralized case there is only 1 element
                            out.push(reencrypt_response.clone());
                        }
                        _ => {
                            return Err(anyhow::anyhow!(
                                "Invalid operation for request {:?}",
                                event
                            ));
                        }
                    }
                }
                // NOTE: these results need to have some ordering
                // so that we can perform reconstruction.
                // The ordering can be determined using the verification key,
                // which the client holds.
                Ok(out)
            }
        }
    }
}

fn to_event(event: &cosmos_proto::messages::tendermint::abci::Event) -> cosmwasm_std::Event {
    let mut result = cosmwasm_std::Event::new(event.r#type.clone());
    for attribute in event.attributes.iter() {
        let key = attribute.key.clone();
        let value = attribute.value.clone();
        result = result.add_attribute(key, value);
    }
    result
}

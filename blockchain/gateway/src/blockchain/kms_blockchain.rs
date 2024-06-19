use crate::blockchain::Blockchain;
use crate::blockchain::KmsEventSubscriber;
use crate::config::GatewayConfig;
use crate::config::KmsMode;
use crate::util::conversion::TokenizableFrom;
use crate::util::footprint;
use anyhow::anyhow;
use async_trait::async_trait;
use cosmos_proto::messages::cosmos::base::abci::v1beta1::TxResponse;
use ethers::abi::Token;
use ethers::prelude::*;
use events::kms::DecryptValues;
use events::kms::KmsEvent;
use events::kms::KmsOperation;
use events::kms::OperationValue;
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
use kms_lib::kms::DecryptionResponsePayload;
use kms_lib::rpc::rpc_types::Plaintext;
use kms_lib::rpc::rpc_types::CURRENT_FORMAT_VERSION;
use std::collections::HashMap;
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
        tracing::info!("🤠 Received KmsEvent: {:?}", event);
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

    #[retrying::retry(stop=(attempts(5)|duration(10)),wait=fixed(0.25))]
    pub(crate) async fn call_execute_contract(
        &self,
        client: &mut Client,
        request: &ExecuteContractRequest,
    ) -> Result<TxResponse, kms_blockchain_client::errors::Error> {
        client.execute_contract(request.clone()).await
    }
}

#[async_trait]
impl Blockchain for KmsBlockchainImpl {
    async fn decrypt(&self, ctxt_handle: Vec<u8>, fhe_type: FheType) -> anyhow::Result<Token> {
        tracing::info!(
            "🔒 Decrypting ciphertext: {:?}",
            hex::encode(ctxt_handle.clone())
        );

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
        let evs: Vec<KmsEvent> = resp
            .events
            .iter()
            .filter(|x| KmsOperation::iter().any(|attr| x.r#type == format!("wasm-{}", attr)))
            .map(to_event)
            .map(<cosmwasm_std::Event as TryInto<KmsEvent>>::try_into)
            .collect::<Result<Vec<KmsEvent>, _>>()?;

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
                    let payload: DecryptionResponsePayload = serde_asn1_der::from_bytes(
                        <&HexVector as Into<Vec<u8>>>::into(decrypt_response.payload()).as_slice(),
                    )
                    .unwrap();

                    tracing::info!(
                        "🍇🥐🍇🥐🍇🥐 Centralized Gateway results payload: {:?}",
                        hex::encode(payload.plaintext.clone())
                    );
                    serde_asn1_der::from_bytes::<Plaintext>(&payload.plaintext)?
                }
                _ => return Err(anyhow::anyhow!("Invalid operation for request {:?}", event)),
            },
            KmsMode::Threshold => {
                // loop through the vector of results and print them
                for value in results.iter() {
                    match value {
                        OperationValue::DecryptResponse(decrypt_response) => {
                            let payload: DecryptionResponsePayload = serde_asn1_der::from_bytes(
                                <&HexVector as Into<Vec<u8>>>::into(decrypt_response.payload())
                                    .as_slice(),
                            )
                            .unwrap();
                            tracing::info!(
                                "🥐🥐🥐🥐🥐🥐 Threshold Gateway results payload: {:?}",
                                hex::encode(payload.plaintext)
                            );
                        }
                        _ => {
                            return Err(anyhow::anyhow!(
                                "Invalid operation for request {:?}",
                                event
                            ))
                        }
                    };
                }
                Plaintext::from_u8(21_u8)
            }
        };

        let res = match fhe_type {
            FheType::Ebool => ptxt.as_bool().to_token(),
            FheType::Euint4 => ptxt.as_u4().to_token(),
            FheType::Euint8 => ptxt.as_u8().to_token(),
            FheType::Euint16 => ptxt.as_u16().to_token(),
            FheType::Euint32 => ptxt.as_u32().to_token(),
            FheType::Euint64 => ptxt.as_u64().to_token(),
            FheType::Euint128 => ptxt.as_u128().to_token(),
            FheType::Euint160 => {
                let mut cake = vec![0u8; 20];
                ptxt.as_u160().copy_to_be_byte_slice(cake.as_mut_slice());
                Address::from_slice(&cake).to_token()
            }
            FheType::Euint256 => {
                let mut cake = vec![0u8; 32];
                ptxt.as_u256().copy_to_be_byte_slice(cake.as_mut_slice());
                Address::from_slice(&cake).to_token()
            }
            FheType::Euint2048 => {
                let mut cake = vec![0u8; 256];
                ptxt.as_u2048().copy_to_be_byte_slice(cake.as_mut_slice());
                Address::from_slice(&cake).to_token()
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
        version: u32,
        verification_key: Vec<u8>,
        randomness: Vec<u8>,
        enc_key: Vec<u8>,
        fhe_type: FheType,
        key_id: Vec<u8>,
        ciphertext: Vec<u8>,
        ciphertext_digest: Vec<u8>,
        eip712_name: String,
        eip712_version: String,
        eip712_chain_id: Vec<u8>,
        eip712_verifying_contract: String,
        eip712_salt: Vec<u8>,
    ) -> anyhow::Result<()> {
        let reencrypt_values = ReencryptValues::builder()
            .signature(signature)
            .version(version)
            .verification_key(verification_key)
            .randomness(randomness)
            .enc_key(enc_key)
            .fhe_type(fhe_type)
            .key_id(key_id)
            .ciphertext(ciphertext)
            .ciphertext_digest(ciphertext_digest)
            .eip712_name(eip712_name)
            .eip712_version(eip712_version)
            .eip712_chain_id(eip712_chain_id)
            .eip712_verifying_contract(eip712_verifying_contract)
            .eip712_salt(eip712_salt)
            .build();

        tracing::info!("🔒 Reencrypting ciphertext");
        tracing::info!("🔒 values: {:?}", reencrypt_values);
        todo!("Implement reencrypt")
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

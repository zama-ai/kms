use crate::blockchain::Blockchain;
use crate::blockchain::KmsEventSubscriber;
use crate::config::GatewayConfig;
use crate::config::KmsMode;
use crate::util::conversion::TokenizableFrom;
use crate::util::footprint;
use anyhow::anyhow;
use async_trait::async_trait;
use bincode::deserialize;
use cosmos_proto::messages::cosmos::base::abci::v1beta1::TxResponse;
use dashmap::DashMap;
use ethers::abi::Token;
use ethers::prelude::*;
use events::kms::DecryptValues;
use events::kms::KmsCoreConf;
use events::kms::KmsEvent;
use events::kms::KmsOperation;
use events::kms::OperationValue;
use events::kms::ReencryptResponseValues;
use events::kms::ReencryptValues;
use events::kms::TransactionId;
use events::kms::ZkpResponseValues;
use events::kms::ZkpValues;
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
use kms_lib::cryptography::signcryption::hash_element;
use kms_lib::kms::DecryptionResponsePayload;
use kms_lib::kms::Eip712DomainMsg;
use kms_lib::rpc::rpc_types::Plaintext;
use kms_lib::rpc::rpc_types::CURRENT_FORMAT_VERSION;
use std::collections::HashMap;
use std::sync::Arc;
use strum::IntoEnumIterator;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::RwLock;
use tracing::info;

pub(crate) struct KmsBlockchainImpl {
    pub(crate) client: Arc<RwLock<Client>>,
    pub(crate) query_client: Arc<QueryClient>,
    pub(crate) responders: Arc<DashMap<TransactionId, oneshot::Sender<KmsEvent>>>,
    pub(crate) event_sender: Arc<mpsc::Sender<KmsEvent>>,
    pub(crate) config: GatewayConfig,
    pub(crate) kms_core_conf: Option<KmsCoreConf>,
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
        let (tx, mut rx) = mpsc::channel::<KmsEvent>(100);
        let responders: Arc<DashMap<TransactionId, oneshot::Sender<KmsEvent>>> =
            Arc::new(DashMap::new());

        tokio::spawn({
            let responders_clone = responders.clone();
            async move {
                while let Some(event) = rx.recv().await {
                    tracing::info!("🤠🤠🤠 Received KmsEvent: {:?}", event);
                    let txn_id = event.txn_id.clone();
                    if let Some((_, sender)) = responders_clone.remove(&txn_id) {
                        tracing::info!("🤠🤠🤠 Notifying waiting task");
                        let _ = sender.send(event); // Notify the waiting task
                    }
                }
            }
        });

        Self {
            client: Arc::new(RwLock::new(
                ClientBuilder::builder()
                    .mnemonic_wallet(mnemonic.as_deref())
                    .grpc_addresses(addresses.clone())
                    .contract_address(contract_address)
                    .kv_store_address(Some(config.storage.url.as_str()))
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
            event_sender: tx.into(),
            config,
            kms_core_conf: None, // needs to be fetched later using [fetch_kms_core_conf], if needed
        }
    }

    pub(crate) async fn new_from_config(config: GatewayConfig) -> anyhow::Result<Self> {
        let mnemonic = Some(config.kms.mnemonic.to_string());
        let binding = config.kms.address.to_string();
        let addresses = vec![binding.as_str()];
        let contract_address = &config.kms.contract_address;
        let mut kms_bc_impl = Self::new(
            mnemonic,
            addresses,
            contract_address.to_string().as_str(),
            config,
        );

        kms_bc_impl.fetch_kms_core_conf().await?;

        Ok(kms_bc_impl)
    }

    // query KMS config contract to get/update KMS core conf (threshold values, etc.)
    pub(crate) async fn fetch_kms_core_conf(&mut self) -> anyhow::Result<()> {
        let query_client = Arc::clone(&self.query_client);
        let request = QueryContractRequest::builder()
            .contract_address(self.config.kms.contract_address.to_string())
            .query(ContractQuery::GetKmsCoreConf {})
            .build();
        let kms_core_conf: KmsCoreConf = query_client.query_contract(request).await?;
        self.kms_core_conf = Some(kms_core_conf);
        Ok(())
    }

    #[retrying::retry(stop=(attempts(5)|duration(30)),wait=fixed(1))]
    pub(crate) async fn wait_for_transaction(
        &self,
        txn_id: &TransactionId,
    ) -> anyhow::Result<KmsEvent> {
        let (tx, rx) = oneshot::channel();
        tracing::info!("🤠🤠🤠 Waiting for transaction: {:?}", txn_id);
        self.responders.insert(txn_id.clone(), tx);
        rx.await.map_err(|e| anyhow!(e.to_string()))
    }

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
        _proof: Option<Vec<u8>>,
    ) -> anyhow::Result<Vec<KmsEvent>> {
        let request = ExecuteContractRequest::builder()
            .message(KmsMessage::builder().value(operation).build())
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
    async fn decrypt(
        &self,
        typed_cts: Vec<(Vec<u8>, FheType, Vec<u8>)>,
        eip712_domain: Eip712DomainMsg,
        acl_address: String,
    ) -> anyhow::Result<(Vec<Token>, Vec<Vec<u8>>)> {
        let num_cts = typed_cts.len();
        let mut kv_ct_handles = Vec::with_capacity(num_cts);
        let mut fhe_types = Vec::with_capacity(num_cts);
        let mut external_ct_handles = Vec::with_capacity(num_cts);
        let mut total_size = 0;

        for (ct, fhe_type, external_ct_handle) in typed_cts {
            let ctxt_handle = self.store_ciphertext(ct.clone()).await?;
            let data_size = footprint::extract_ciphertext_size(&ctxt_handle);
            total_size += data_size;
            fhe_types.push(fhe_type);
            kv_ct_handles.push(ctxt_handle);
            external_ct_handles.push(external_ct_handle);
        }

        let decrypt_values = DecryptValues::new(
            hex::decode(self.config.kms.key_id.as_str()).unwrap(),
            kv_ct_handles.clone(),
            fhe_types.clone(),
            Some(external_ct_handles),
            CURRENT_FORMAT_VERSION,
            acl_address,
            eip712_domain.name,
            eip712_domain.version,
            eip712_domain.chain_id,
            eip712_domain.verifying_contract,
            eip712_domain.salt,
        );

        tracing::info!(
            "Decryption EIP712 info: name={}, version={}, \
            chain_id={} (HEX), verifying_contract={}, salt={} (HEX), ACL address={}",
            decrypt_values.eip712_name(),
            decrypt_values.eip712_version(),
            decrypt_values.eip712_chain_id().to_hex(),
            decrypt_values.eip712_verifying_contract(),
            decrypt_values.eip712_salt().to_hex(),
            decrypt_values.acl_address()
        );

        let operation = events::kms::OperationValue::Decrypt(decrypt_values);

        // TODO: Proof should be generated by the client
        let proof = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0];

        // send coins 1:1 with the ciphertext size
        tracing::info!("🍊 Decrypting ciphertexts of total size: {:?}", total_size);

        let evs = self
            .make_req_to_kms_blockchain(total_size, operation, Some(proof))
            .await?;

        // TODO what if we have multiple events?
        let ev = evs[0].clone();

        tracing::info!("✉️ TxId: {:?}", ev.txn_id().to_hex(),);

        tracing::info!(
            "🍊 Waiting for callback from KMS, txn_id: {:?}",
            ev.txn_id().to_hex()
        );
        let event = self.wait_for_transaction(ev.txn_id()).await?;
        tracing::info!("🍊 Received callback from KMS: {:?}", event.txn_id());
        let request = QueryContractRequest::builder()
            .contract_address(self.config.kms.contract_address.to_string())
            .query(ContractQuery::GetOperationsValue(
                OperationQuery::builder().event(event.clone()).build(),
            ))
            .build();

        let results: Vec<OperationValue> = self.query_client.query_contract(request).await?;
        let (ptxts, sigs) = match self.config.mode {
            KmsMode::Centralized => match results.first().unwrap() {
                OperationValue::DecryptResponse(decrypt_response) => {
                    let payload: DecryptionResponsePayload = deserialize(
                        <&HexVector as Into<Vec<u8>>>::into(decrypt_response.payload()).as_slice(),
                    )
                    .unwrap();

                    // the KMS-internal signature, for verification of the response (currently not used)
                    let _internal_sig = decrypt_response.signature().0.clone();

                    // the signature to be verified externally (e.g. by the fhevm)
                    let external_sig = payload.external_signature.unwrap_or_default();

                    tracing::info!(
                        "🍇🥐🍇🥐🍇🥐 Centralized KMS decrypted {} plaintext(s).",
                        payload.plaintexts.len()
                    );

                    // deserialize the individual plaintexts in this batch
                    let ptxts = payload
                        .plaintexts
                        .iter()
                        .map(|pt| deserialize::<Plaintext>(pt))
                        .collect::<Result<Vec<_>, _>>()?;

                    // 1 batch of plaintexts and a single signature for the batch from the centralized KMS
                    (ptxts, vec![external_sig])
                }
                _ => return Err(anyhow::anyhow!("Invalid operation for request {:?}", event)),
            },
            KmsMode::Threshold => {
                let mut ptxts = Vec::new();
                let mut sigs = Vec::new();

                // Fetch threshold KMS core config (the config is read at start once, currently)
                let threshold_kms_core_conf =
                    if let Some(KmsCoreConf::Threshold(conf)) = &self.kms_core_conf {
                        conf
                    } else {
                        return Err(anyhow::anyhow!(
                            "Error reading KMS core config (wrong config type or config not set)."
                        ));
                    };

                // We need at least 2t + 1 responses for secure majority voting (at most t could be malicious).
                // The reason ist that the KMS ASC simply counts responses without checking equality, so we might receive up to t malicious responses.
                // The value (2t + 1) comes from the KMS core config.
                if results.len() < threshold_kms_core_conf.response_count_for_majority_vote {
                    return Err(anyhow::anyhow!(
                        "Have not received enough decryption results: received {}, needed at least {}",
                        results.len(),
                        threshold_kms_core_conf.response_count_for_majority_vote
                    ));
                }

                // loop through the vector of results (one value (= 1 batch) from each party)
                for value in results.iter() {
                    match value {
                        OperationValue::DecryptResponse(decrypt_response) => {
                            let payload: DecryptionResponsePayload = deserialize(
                                <&HexVector as Into<Vec<u8>>>::into(decrypt_response.payload())
                                    .as_slice(),
                            )
                            .unwrap();
                            tracing::info!(
                                "🥐🥐🥐🥐🥐🥐 Threshold Gateway decrypted {} plaintext(s).",
                                payload.plaintexts.len()
                            );
                            ptxts.push(payload.plaintexts);

                            // the KMS-internal signature, for verification of the response (currently not used)
                            let _internal_sig = decrypt_response.signature().0.clone();

                            // the signature to be verified externally (e.g. by the fhevm)
                            let external_sig = payload.external_signature.unwrap_or_default();

                            sigs.push(external_sig);
                        }
                        _ => {
                            return Err(anyhow::anyhow!(
                                "Invalid operation for request {:?}",
                                event
                            ))
                        }
                    };
                }

                let (majority_pts, majority_count) = most_common_element(&ptxts)
                    .ok_or_else(|| anyhow::anyhow!("No plaintext found."))?; // this cannot happen, since we have some responses, but just to be sure

                // We need at least t + 1 identical batch responses as majority, so we can return the majority plaintext (at most t others were corrupted)
                let required_majority = threshold_kms_core_conf.degree_for_reconstruction + 1;
                if majority_count >= required_majority {
                    // deserialize the individual plaintexts in this batch
                    let ptxts = majority_pts
                        .iter()
                        .map(|pt| deserialize::<Plaintext>(pt))
                        .collect::<Result<Vec<_>, _>>()?;
                    // return the majority plaintext batch and all signatures by the threshold KMS parties
                    (ptxts, sigs)
                } else {
                    return Err(anyhow::anyhow!(
                        "Have not received a large enough majority of decryptions: majority size is {}, needed at least {}",
                        majority_count,
                        required_majority
                    ));
                }
            }
        };

        assert_eq!(ptxts.len(), fhe_types.len());

        let mut tokens = Vec::new();

        // turn Plaintexts into Tokens for the smart contract
        for (idx, ptxt) in ptxts.iter().enumerate() {
            tracing::info!("FheType: {:#?}", fhe_types[idx]);
            let res = match fhe_types[idx] {
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
            tokens.push(res);
        }

        info!("🍊 plaintexts: {:#?}", tokens);
        Ok((tokens, sigs))
    }

    #[allow(clippy::too_many_arguments)]
    async fn reencrypt(
        &self,
        signature: Vec<u8>,
        client_address: String,
        enc_key: Vec<u8>,
        fhe_type: FheType,
        ciphertext: Vec<u8>,
        eip712_verifying_contract: String,
        chain_id: U256,
        acl_address: String,
    ) -> anyhow::Result<Vec<ReencryptResponseValues>> {
        tracing::info!(
            "🔒 Reencrypting ciphertext with signature: {:?}, user_address: {:?}, enc_key: {:?}, fhe_type: {:?}, eip712_verifying_contract: {:?}, chain_id: {:?}, acl_address: {:?}",
            hex::encode(&signature),
            hex::encode(&client_address),
            hex::encode(&enc_key),
            fhe_type,
            eip712_verifying_contract,
            chain_id,
            acl_address
        );

        let ctxt_handle = self.store_ciphertext(ciphertext.clone()).await?;
        let ctxt_digest = hash_element(&ciphertext);

        let key_id = HexVector::from_hex(self.config.kms.key_id.as_str())?;
        tracing::info!(
            "🔒 Reencrypting ciphertext using key_id={:?}, ctxt_handle={}, ctxt_digest={}",
            key_id.to_hex(),
            hex::encode(&ctxt_handle),
            hex::encode(&ctxt_digest)
        );

        // TODO this is currently not set, but might be in the future
        let eip712_salt = HexVector(vec![]);

        // chain ID is 32 bytes
        let mut eip712_chain_id = vec![0u8; 32];
        chain_id.to_big_endian(&mut eip712_chain_id);

        // convert user_address to verification_key
        if client_address.len() != 20 {
            return Err(anyhow::anyhow!(
                "user_address {} bytes but 20 bytes is expected",
                client_address.len()
            ));
        }

        // NOTE: the ciphertext digest must be the real digest
        let reencrypt_values = ReencryptValues::new(
            signature,
            CURRENT_FORMAT_VERSION,
            client_address,
            enc_key,
            fhe_type,
            key_id,
            ctxt_handle.clone(),
            ctxt_digest,
            acl_address,
            self.config.ethereum.reenc_domain_name.clone(),
            self.config.ethereum.reenc_domain_version.clone(),
            eip712_chain_id,
            eip712_verifying_contract,
            eip712_salt,
        );

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
            .make_req_to_kms_blockchain(data_size, operation, Some(proof))
            .await?;

        // TODO what if we have multiple events?
        let ev = evs[0].clone();

        tracing::info!("✉️ TxId: {:?}", ev.txn_id().to_hex(),);

        tracing::info!(
            "🍊 Waiting for callback from KMS, txn_id: {:?}",
            ev.txn_id().to_hex()
        );
        let event = self.wait_for_transaction(ev.txn_id()).await?;
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
                    tracing::debug!(
                        "🍇🥐🍇🥐🍇🥐 Centralized KMS signature: {:?}",
                        reencrypt_response.signature().to_hex()
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

    async fn zkp(
        &self,
        client_address: String,
        contract_address: String,
        ct_proof: Vec<u8>,
        max_num_bits: u32,
        eip712_domain: Eip712DomainMsg,
        acl_address: String,
    ) -> anyhow::Result<Vec<ZkpResponseValues>> {
        tracing::info!(
            "🔒 ZKP ciphertext with client_address: {:?}, contract_address: {:?}, max_num_bits: {:?}, chain_id: {:?}",
            hex::encode(&client_address),
            hex::encode(&contract_address),
            max_num_bits,
            eip712_domain.chain_id
        );

        let ct_proof_handle = self.store_ciphertext(ct_proof.clone()).await?;

        let key_id = HexVector::from_hex(self.config.kms.key_id.as_str())?;
        let crs_id = match self.config.kms.crs_ids.get(&max_num_bits) {
            Some(crs_id) => HexVector::from_hex(crs_id.as_str())?,
            None => {
                return Err(anyhow::anyhow!(
                    "CRS max number of bits {} not found in config",
                    max_num_bits
                ))
            }
        };
        tracing::info!(
            "🔒 ZKP using key_id={:?}, crs_id={:?}, ct_proof_handle={}",
            key_id.to_hex(),
            crs_id.to_hex(),
            hex::encode(&ct_proof_handle),
        );

        // convert user_address to verification_key
        if client_address.len() != 20 {
            return Err(anyhow::anyhow!(
                "user_address {} bytes but 20 bytes is expected",
                client_address.len()
            ));
        }

        let zkp_values = ZkpValues::new(
            crs_id,
            key_id,
            contract_address,
            client_address,
            ct_proof_handle.clone(),
            acl_address,
            eip712_domain.name,
            eip712_domain.version,
            eip712_domain.chain_id,
            eip712_domain.verifying_contract,
            eip712_domain.salt,
        );

        let operation = events::kms::OperationValue::Zkp(zkp_values);

        // send coins 1:1 with the ciphertext size
        let data_size = footprint::extract_ciphertext_size(&ct_proof_handle);
        tracing::info!("🍊 Zkp ciphertext of size: {:?}", data_size);
        // TODO how do we handle payment of ZKP validation?
        let evs = self
            .make_req_to_kms_blockchain(data_size, operation, None)
            .await?;

        // TODO what if we have multiple events?
        let ev = evs[0].clone();

        tracing::info!("✉️ TxId: {:?}", ev.txn_id().to_hex(),);

        tracing::info!(
            "🍊 Waiting for callback from KMS, txn_id: {:?}",
            ev.txn_id().to_hex()
        );
        let event = self.wait_for_transaction(ev.txn_id()).await?;
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
                OperationValue::ZkpResponse(zkp_response) => {
                    tracing::debug!(
                        "🍇🥐🍇🥐🍇🥐 Centralized KMS signature: {:?}",
                        zkp_response.signature().to_hex()
                    );

                    // the output needs to have type Vec<ZkpResponse>
                    // in the centralized case there is only 1 element
                    let out = vec![zkp_response.clone()];
                    Ok(out)
                }
                _ => return Err(anyhow::anyhow!("Invalid operation for request {:?}", event)),
            },
            KmsMode::Threshold => {
                let mut out = vec![];
                for value in results.iter() {
                    match value {
                        OperationValue::ZkpResponse(zkp_response) => {
                            // the output needs to have type Vec<ZkpResponse>
                            // in the centralized case there is only 1 element
                            out.push(zkp_response.clone());
                        }
                        _ => {
                            return Err(anyhow::anyhow!(
                                "Invalid operation for request {:?}",
                                event
                            ));
                        }
                    }
                }
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

// Returns the most common element in the vector together with its count
fn most_common_element<T: Eq + std::hash::Hash + Clone>(vec: &[T]) -> Option<(T, usize)> {
    let mut counts = HashMap::new();

    // Count occurrences of each element
    for item in vec {
        *counts.entry(item).or_insert(0) += 1;
    }

    // Find the element with the maximum count and returnt that element, together with its count
    counts
        .into_iter()
        .max_by_key(|&(_, count)| count)
        .map(|(item, count)| (item.clone(), count))
}

#[cfg(test)]
mod tests {
    use crate::blockchain::kms_blockchain::most_common_element;

    #[test]
    fn test_most_common_element() {
        let (most_common_el, count) =
            most_common_element(&[1, 1, 2, 3, 4, 5, 6, 5, 5, 5, 1, 678]).unwrap();
        assert_eq!(most_common_el, 5);
        assert_eq!(count, 4);

        // empty vector returns None
        let none = most_common_element(&Vec::<usize>::new());
        assert_eq!(none, None);
    }
}

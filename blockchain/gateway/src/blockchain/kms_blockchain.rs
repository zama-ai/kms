use crate::blockchain::Blockchain;
use crate::blockchain::KmsEventSubscriber;
use crate::config::{
    FheKeyUrlInfo, GatewayConfig, KeyUrlInfo, KeyUrlResponseValues, KmsMode, VerfKeyUrlInfo,
};
use crate::util::conversion::TokenizableFrom;
use crate::util::footprint;
use alloy_primitives::Address;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use bincode::deserialize;
use cosmos_proto::messages::cosmos::base::abci::v1beta1::TxResponse;
use dashmap::DashMap;
use ethereum_inclusion_proofs::std_proof_handler::EthereumProofHandler;
use ethereum_inclusion_proofs::types::{
    DecryptProofParams, EVMProofParams, EthereumConfig, ReencryptProofParams,
};
use ethers::abi::Token;
use ethers::prelude::*;
use events::kms::{
    CrsGenResponseValues, DecryptValues, FheParameter, FheType, KeyGenResponseValues, KmsConfig,
    KmsEvent, KmsMessage, KmsOperation, OperationValue, ReencryptResponseValues, ReencryptValues,
    TransactionId, VerifyProvenCtResponseValues, VerifyProvenCtValues,
};
use events::{HexVector, HexVectorList};
use kms_blockchain_client::client::Client;
use kms_blockchain_client::client::ClientBuilder;
use kms_blockchain_client::client::ExecuteContractRequest;
use kms_blockchain_client::client::ProtoCoin;
use kms_blockchain_client::errors::Error;
use kms_blockchain_client::query_client::ContractQuery;
use kms_blockchain_client::query_client::EventQuery;
use kms_blockchain_client::query_client::GenCrsIdQuery;
use kms_blockchain_client::query_client::GenKeyIdQuery;
use kms_blockchain_client::query_client::QueryClient;
use kms_blockchain_client::query_client::QueryClientBuilder;
use kms_blockchain_client::query_client::QueryContractRequest;
use kms_lib::consts::SIGNING_KEY_ID;
use kms_lib::cryptography::signcryption::hash_element;
use kms_lib::kms::DecryptionResponsePayload;
use kms_lib::kms::Eip712DomainMsg;
use kms_lib::kms::VerifyProvenCtResponsePayload;
use kms_lib::rpc::rpc_types::Plaintext;
use kms_lib::rpc::rpc_types::PubDataType;
use kms_lib::rpc::rpc_types::CURRENT_FORMAT_VERSION;
use prost::Message;
use std::collections::HashMap;
use std::path::MAIN_SEPARATOR_STR;
use std::str::FromStr;
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
    pub(crate) kms_configuration: Option<KmsConfig>,
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
        asc_address: &'a str,
        csc_address: &'a str,
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
                    //Should we store the event in responders if it's a dec event and it wasn't in responders ? Might mean there was a reace condition (or current GW didn't initiate the decryption)
                }
            }
        });

        Self {
            client: Arc::new(RwLock::new(
                ClientBuilder::builder()
                    .mnemonic_wallet(mnemonic.as_deref())
                    .grpc_addresses(addresses.clone())
                    .asc_address(asc_address)
                    .csc_address(csc_address)
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
            kms_configuration: None, // needs to be fetched later using [fetch_kms_configuration], if needed
        }
    }

    pub(crate) async fn new_from_config(config: GatewayConfig) -> anyhow::Result<Self> {
        let mnemonic = Some(config.kms.mnemonic.to_string());
        let binding = config.kms.address.to_string();
        let addresses = vec![binding.as_str()];
        let asc_address = &config.kms.asc_address;
        let csc_address = &config.kms.csc_address;
        let mut kms_bc_impl = Self::new(
            mnemonic,
            addresses,
            asc_address.to_string().as_str(),
            csc_address.to_string().as_str(),
            config,
        );

        kms_bc_impl.fetch_kms_configuration().await?;

        Ok(kms_bc_impl)
    }

    // query KMS CSC to get/update KMS configuration (threshold values, etc.)
    pub(crate) async fn fetch_kms_configuration(&mut self) -> anyhow::Result<()> {
        let query_client = Arc::clone(&self.query_client);
        let request = QueryContractRequest::builder()
            .contract_address(self.config.kms.csc_address.to_string())
            .query(ContractQuery::GetKmsConfig {})
            .build();
        let kms_configuration: KmsConfig = query_client.query_contract(request).await?;
        self.kms_configuration = Some(kms_configuration);
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
    ) -> anyhow::Result<KmsEvent> {
        let request = ExecuteContractRequest::builder()
            .message(KmsMessage::builder().value(operation.clone()).build())
            .gas_limit(10_000_000u64)
            .funds(vec![ProtoCoin::builder()
                .denom("ucosm".to_string())
                .amount(data_size as u64)
                .build()])
            .build();

        let mut client = self.client.write().await;
        // Broadcast the transaction so it gets picked up by a validator
        let response = self.call_execute_contract(&mut client, &request).await?;

        let resp;
        loop {
            // Keep querying using the txhash to make sure it appeared on the blockchain
            let query_response = self.query_client.query_tx(response.txhash.clone()).await?;
            if let Some(qr) = query_response {
                resp = qr;
                break;
            } else {
                tracing::info!("Waiting for transaction to be included in a block");
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                continue;
            }
        }
        let events = resp
            .events
            .iter()
            .filter(|x| KmsOperation::iter().any(|attr| x.r#type == format!("wasm-{}", attr)))
            .map(to_event)
            .map(<cosmwasm_std::Event as TryInto<KmsEvent>>::try_into)
            .collect::<Result<Vec<KmsEvent>, _>>()?;

        // At this point evs should contain a single event
        if events.len() != 1 {
            return Err(anyhow!(
                "Expected a single KmsEvent, but received: {:?}",
                events
            ));
        }
        let ev = events[0].clone();
        let expected_kms_op = <OperationValue as std::convert::Into<KmsOperation>>::into(operation);
        // Make sure this is indeed the expected event
        if ev.operation != expected_kms_op {
            return Err(anyhow!(
                "Expected a {:?} , but received: {:?}",
                expected_kms_op,
                ev
            ));
        }
        Ok(ev)
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

        let handle_bytes = hex::decode(handle)?;
        Ok(handle_bytes)
    }

    /// Helper function to get all the KeyGenResponseValues from the KMS blockchain.
    async fn get_key_gen_response_values(
        &self,
        key_id: String,
    ) -> Result<Vec<KeyGenResponseValues>, Error> {
        let request = QueryContractRequest::builder()
            .contract_address(self.config.kms.asc_address.to_string())
            .query(ContractQuery::GetKeyGenResponseValues(
                GenKeyIdQuery::builder().key_id(key_id).build(),
            ))
            .build();
        let query_client = Arc::clone(&self.query_client);
        query_client.query_contract(request).await
    }

    /// Helper function to get all the CrsGenResponseValues from the KMS blockchain.
    async fn get_crs_gen_response_values(
        &self,
        crs_id: String,
    ) -> Result<Vec<CrsGenResponseValues>, Error> {
        let request = QueryContractRequest::builder()
            .contract_address(self.config.kms.asc_address.to_string())
            .query(ContractQuery::GetCrsGenResponseValues(
                GenCrsIdQuery::builder().crs_id(crs_id).build(),
            ))
            .build();
        let query_client = Arc::clone(&self.query_client);
        query_client.query_contract(request).await
    }

    /// Get the key id from the config.
    ///
    /// This is because, in case of multiple key generations, the ASC can return multiple
    /// key IDss and the client is not able to tell which ones should be used.
    /// This is temporary and will be removed once we properly handle public key IDs across
    /// the different components: https://github.com/zama-ai/kms-core/issues/1519
    async fn get_key_id(&self) -> anyhow::Result<String> {
        Ok(self.config.kms.key_id.clone())
    }

    /// Helper function to parse the KeyGenResponses from the KMS blockchain.
    /// Takes a vector of KeyGenResponses as input and returns a map of key IDs to a tuple of parameter choice, public key signatures followed by server signatures.
    fn parse_signed_key_data(
        vals: Vec<KeyGenResponseValues>,
    ) -> anyhow::Result<HashMap<String, (FheParameter, HexVectorList, HexVectorList)>> {
        let mut id_sig_map: HashMap<String, (FheParameter, HexVectorList, HexVectorList)> =
            HashMap::new();
        // Go through each operation value returned and branch into the keygen case.
        // Then combine all signatures on the same ID into a vector for that ID.
        for key_resp in vals.iter() {
            match id_sig_map.get_mut(&key_resp.request_id().to_hex()) {
                // First the case where the ID is already in the map
                Some((param, pk_sigs, server_sigs)) => {
                    if param != key_resp.param() {
                        tracing::error!("Discrepancy between the parties choice of parameter. Specifically the initial parameter choice is {:?} and the current one is {:?}", key_resp.param(), param);
                    }
                    // NOTE: This is just a sanity check and pretty slow, so can be removed if we end up with many MPC servers.
                    if pk_sigs.contains(key_resp.public_key_signature()) {
                        tracing::error!("The response from the blockchain on KeyGenResponse already contains duplicate signatures. Specifically the signature {:?}", key_resp.public_key_signature());
                    } else {
                        pk_sigs.0.push(key_resp.public_key_signature().to_owned());
                    }
                    // NOTE: This is just a sanity check and pretty slow, so can be removed if we end up with many MPC servers.
                    if server_sigs.contains(key_resp.server_key_signature()) {
                        tracing::error!("The response from the blockchain on KeyGenResponse already contains duplicate signatures. Specifically the signature {:?}", key_resp.public_key_signature());
                    } else {
                        server_sigs
                            .0
                            .push(key_resp.server_key_signature().to_owned());
                    }
                }
                // Then the case where it is the first time we see the ID
                None => {
                    id_sig_map.insert(
                        key_resp.request_id().to_hex(),
                        (
                            key_resp.param().to_owned(),
                            HexVectorList(vec![key_resp.public_key_signature().to_owned()]),
                            HexVectorList(vec![key_resp.server_key_signature().to_owned()]),
                        ),
                    );
                }
            }
        }
        Ok(id_sig_map)
    }

    /// Helper function to parse the CrsGenResponses from the KMS blockchain.
    /// Takes a vector of CrsGenResponses as input and returns a map of key IDs to a tuple of public key signatures followed by a tuple of the max number of bits and the list of signatures.
    fn parse_signed_crs_data(
        vals: Vec<CrsGenResponseValues>,
    ) -> anyhow::Result<HashMap<String, (u32, FheParameter, HexVectorList)>> {
        let mut id_sig_map: HashMap<String, (u32, FheParameter, HexVectorList)> = HashMap::new();
        // Go through each operation value returned and branch into the crsgen case.
        // Then combine all signatures on the same ID into a vector for that ID.
        for crs_resp in vals.iter() {
            match id_sig_map.get_mut(crs_resp.request_id()) {
                // First the case where the ID is already in the map
                Some((max_num_bits, fhe_param, sigs)) => {
                    if *max_num_bits != crs_resp.max_num_bits() {
                        tracing::error!("Discrepancy between the parties choice of max number of bits. Specifically the initial choice is {:?} and the current one is {:?}", max_num_bits, crs_resp.max_num_bits());
                    }
                    if fhe_param != crs_resp.param() {
                        tracing::error!("Discrepancy between the parties choice of parameter. Specifically the initial parameter choice is {:?} and the current one is {:?}", fhe_param, crs_resp.param());
                    }
                    // NOTE: This is just a sanity check and pretty slow, so can be removed if we end up with many MPC servers.
                    if sigs.contains(crs_resp.signature()) {
                        tracing::error!("The response from the blockchain on CrsGenResponse already contains duplicate signatures. Specifically the signature {:?}", crs_resp.signature());
                    } else {
                        sigs.0.push(crs_resp.signature().to_owned());
                    }
                }
                // Then the case where it is the first time we see the ID
                None => {
                    id_sig_map.insert(
                        crs_resp.request_id().to_owned(),
                        (
                            crs_resp.max_num_bits(),
                            crs_resp.param().to_owned(),
                            HexVectorList(vec![crs_resp.signature().to_owned()]),
                        ),
                    );
                }
            }
        }
        Ok(id_sig_map)
    }

    /// Construct a `KeyUrlResponseValues` object from the given parameters.
    /// This is used for different types of public key material such as both PublicKey and ServerKey.
    fn prepare_fhe_key_urls(
        storage_urls: &HashMap<u32, String>,
        key_id: &str,
        param: &FheParameter,
        pk_sig: HexVectorList,
        server_sig: HexVectorList,
    ) -> anyhow::Result<FheKeyUrlInfo> {
        let fhe_public_key =
            Self::get_fhe_key_info(PubDataType::PublicKey, storage_urls, key_id, param, pk_sig)?;
        let fhe_server_key = Self::get_fhe_key_info(
            PubDataType::ServerKey,
            storage_urls,
            key_id,
            param,
            server_sig,
        )?;
        Ok(FheKeyUrlInfo::builder()
            .fhe_public_key(fhe_public_key)
            .fhe_server_key(fhe_server_key)
            .build())
    }

    /// Construct a `KeyUrlInfo` object from the given parameters.
    fn get_fhe_key_info(
        key_type: PubDataType,
        storage_urls: &HashMap<u32, String>,
        key_id: &str,
        param: &FheParameter,
        sigs: HexVectorList,
    ) -> anyhow::Result<KeyUrlInfo> {
        let mut urls = Vec::new();
        for base_url in storage_urls.values() {
            let type_string = key_type.to_string();
            let parsed_base_url = base_url.trim().trim_end_matches(MAIN_SEPARATOR_STR);
            let url = format!(
                "{parsed_base_url}{MAIN_SEPARATOR_STR}{type_string}{MAIN_SEPARATOR_STR}{key_id}"
            );
            urls.push(url);
        }
        Ok(KeyUrlInfo::builder()
            .data_id(HexVector::from_hex(key_id)?)
            .param_choice(param.to_owned().into())
            .urls(urls)
            .signatures(sigs)
            .build())
    }

    /// Construct a `VerfKeyUrlInfo` object from the given parameters.
    /// This consists of all the URL information about the public verification keys of each of the MPC servers.
    fn get_verf_key_info(
        storage_urls: &HashMap<u32, String>,
        key_id: &str,
    ) -> anyhow::Result<Vec<VerfKeyUrlInfo>> {
        let mut res = Vec::new();
        for (i, base_url) in storage_urls {
            let parsed_base_url = base_url.trim().trim_end_matches(MAIN_SEPARATOR_STR);
            let verf_key = PubDataType::VerfKey.to_string();
            let verf_addr = PubDataType::VerfAddress.to_string();
            let key_url = format!(
                "{parsed_base_url}{MAIN_SEPARATOR_STR}{verf_key}{MAIN_SEPARATOR_STR}{key_id}"
            );
            let addr_url = format!(
                "{parsed_base_url}{MAIN_SEPARATOR_STR}{verf_addr}{MAIN_SEPARATOR_STR}{key_id}"
            );
            res.push(
                VerfKeyUrlInfo::builder()
                    .key_id(HexVector::from_hex(key_id)?)
                    .server_id(*i)
                    .verf_public_key_url(key_url)
                    .verf_public_key_address(addr_url)
                    .build(),
            )
        }
        Ok(res)
    }

    /// Construct a `CrsUrlInfo` map from the given parameters.
    /// The key in the resultant map is the maximum number of bits of the CRS and the value is the CRS information including the URL and signature.
    fn get_crs_info(
        storage_urls: &HashMap<u32, String>,
        crs_data: &HashMap<String, (u32, FheParameter, HexVectorList)>,
    ) -> anyhow::Result<HashMap<u32, KeyUrlInfo>> {
        let mut res = HashMap::new();
        for (crs_id, (max_bits, param, sigs)) in crs_data.iter() {
            let mut urls = Vec::new();
            for base_url in storage_urls.values() {
                let crs_type = PubDataType::CRS.to_string();
                let parsed_base_url = base_url.trim().trim_end_matches(MAIN_SEPARATOR_STR);
                let crs_url = format!(
                    "{parsed_base_url}{MAIN_SEPARATOR_STR}{crs_type}{MAIN_SEPARATOR_STR}{crs_id}"
                );
                urls.push(crs_url);
            }
            res.insert(
                *max_bits,
                KeyUrlInfo::builder()
                    .data_id(HexVector::from_hex(crs_id)?)
                    .param_choice(param.to_owned().into())
                    .urls(urls)
                    .signatures(sigs.to_owned())
                    .build(),
            );
        }
        Ok(res)
    }
}

async fn fetch_ethereum_proof(
    params: EVMProofParams,
    config: EthereumConfig,
) -> anyhow::Result<String> {
    let proof_handler = EthereumProofHandler::new(config)?;
    let proof = proof_handler.fetch_proof(params).await?;
    let mut proof_encoded = Vec::new();
    proof.encode(&mut proof_encoded)?;
    Ok(hex::encode(proof_encoded.clone()))
}

fn decrypt_proof_params(ciphertext_handles: Vec<Vec<u8>>) -> EVMProofParams {
    EVMProofParams::Decrypt(DecryptProofParams { ciphertext_handles })
}

fn reencrypt_proof_params(
    ciphertext_handles: Vec<Vec<u8>>,
    accounts: Vec<Vec<u8>>,
) -> EVMProofParams {
    EVMProofParams::Reencrypt(ReencryptProofParams {
        ciphertext_handles,
        accounts,
    })
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

        let config = EthereumConfig {
            json_rpc_url: self.config.ethereum.http_url.clone(),
            acl_contract_address: format!("0x{}", hex::encode(self.config.ethereum.acl_address.0)),
        };

        let proof =
            fetch_ethereum_proof(decrypt_proof_params(external_ct_handles.clone()), config).await?;

        // Stop-gap to allow for testing with a static key that has not been genereated using the kms
        // Should be removed as part of https://github.com/zama-ai/fhevm/issues/548
        let key_id_str = match self.get_key_id().await {
            Ok(key_id) => key_id,
            Err(e) => {
                // It is expected that the result will not be immidiately available after the request. Hence this is only logged as info.
                tracing::info!("Could not retrieve the key id from the blockchain: {}", e);
                self.config.kms.key_id.clone()
            }
        };
        let decrypt_values = DecryptValues::new(
            HexVector::from_hex(&key_id_str)?,
            kv_ct_handles.clone(),
            fhe_types.clone(),
            Some(external_ct_handles),
            CURRENT_FORMAT_VERSION,
            acl_address,
            proof,
            eip712_domain.name,
            eip712_domain.version,
            eip712_domain.chain_id,
            eip712_domain.verifying_contract,
            eip712_domain.salt,
        )?;

        tracing::info!(
            "Decryption EIP712 info: name={}, version={}, \
            chain_id={} (HEX), verifying_contract={}, salt={:?}, ACL address={}",
            decrypt_values.eip712_name(),
            decrypt_values.eip712_version(),
            decrypt_values.eip712_chain_id().to_hex(),
            decrypt_values.eip712_verifying_contract(),
            decrypt_values.eip712_salt(),
            decrypt_values.acl_address()
        );

        let operation = events::kms::OperationValue::Decrypt(decrypt_values);

        // send coins 1:1 with the ciphertext size
        tracing::info!("🍊 Decrypting ciphertexts of total size: {:?}", total_size);

        // Execute the smart contract and wait for the Tx to appear in a block.
        // Returns the corresponding KmsEvent of this transaction
        let ev = self
            .make_req_to_kms_blockchain(total_size, operation)
            .await?;

        tracing::info!("✉️ TxId: {:?}", ev.txn_id().to_hex(),);

        tracing::info!(
            "🍊 Waiting for callback from KMS, txn_id: {:?}",
            ev.txn_id().to_hex()
        );

        // NOTE: Might be an (unlikely) race condition between calls:
        // make_req_to_kms_blockchain and wait_for_transaction
        //
        // i.e. What if the response tx has already been emited
        // before we were monitoring for it ?
        // Why not decouple the way in from the way back ?
        // Should Any GW be allowed/able to pick up a dec event from the ASC even if
        // it didn't initiate this specific decryption ?
        //
        // (This isn't possible for e.g. reencryption as we need an open connection with the client though, but otoh, for reencryption client can always retry upon failure)

        // We now wait for an event to be emitted by the ASC that contains the same ID
        // our decryption event had.
        // i.e. We expect the corresponding DecryptResponse event
        let event = self.wait_for_transaction(ev.txn_id()).await?;
        if event.operation != KmsOperation::DecryptResponse {
            return Err(anyhow!(
                "Expected to receive a DecryptResponse, but received {:?}",
                event
            ));
        }
        tracing::info!("🍊 Received callback from KMS: {:?}", event.txn_id());
        // Because we have seen the event, we now know that the result is ready to be queried
        // so we query the GetOperationsValuesFromEvent endpoint of the ASC
        let request = QueryContractRequest::builder()
            .contract_address(self.config.kms.asc_address.to_string())
            .query(ContractQuery::GetOperationsValuesFromEvent(
                EventQuery::builder().event(event.clone()).build(),
            ))
            .build();

        let results: Vec<OperationValue> = self.query_client.query_contract(request).await?;
        let (ptxts, sigs) = match self.config.mode {
            KmsMode::Centralized => match results.first().unwrap() {
                OperationValue::DecryptResponse(decrypt_response) => {
                    let payload: DecryptionResponsePayload = deserialize(
                        <&HexVector as Into<Vec<u8>>>::into(decrypt_response.payload()).as_slice(),
                    )?;

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

                // Fetch threshold KMS configuration (the configuration is read at start once, currently)
                let threshold_kms_configuration = if let Some(conf) = &self.kms_configuration {
                    conf
                } else {
                    return Err(anyhow::anyhow!(
                        "Error reading KMS configuration (wrong config type or config not set)."
                    ));
                };

                // We need at least 2t + 1 responses for secure majority voting (at most t could be malicious).
                // The reason ist that the KMS ASC simply counts responses without checking equality, so we might receive up to t malicious responses.
                // The value (2t + 1) comes from the KMS configuration.
                if results.len() < threshold_kms_configuration.response_count_for_majority_vote {
                    return Err(anyhow::anyhow!(
                        "Have not received enough decryption results: received {}, needed at least {}",
                        results.len(),
                        threshold_kms_configuration.response_count_for_majority_vote
                    ));
                }

                // loop through the vector of results (one value (= 1 batch) from each party)
                for value in results.iter() {
                    match value {
                        OperationValue::DecryptResponse(decrypt_response) => {
                            let payload: DecryptionResponsePayload = deserialize(
                                <&HexVector as Into<Vec<u8>>>::into(decrypt_response.payload())
                                    .as_slice(),
                            )?;
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
                let required_majority = threshold_kms_configuration.degree_for_reconstruction + 1;
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
                    let mut cake = vec![0u8; 64];
                    ptxt.as_u512().copy_to_be_byte_slice(cake.as_mut_slice());
                    let token = Token::Bytes(cake);
                    info!(
                        "🍰 Euint512 Token: {:#?}, ",
                        hex::encode(token.clone().into_bytes().unwrap())
                    );
                    token
                }
                FheType::Euint1024 => {
                    let mut cake = vec![0u8; 128];
                    ptxt.as_u1024().copy_to_be_byte_slice(cake.as_mut_slice());
                    let token = Token::Bytes(cake);
                    info!(
                        "🍰 Euint1024 Token: {:#?}, ",
                        hex::encode(token.clone().into_bytes().unwrap())
                    );
                    token
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
        external_ct_handle: Vec<u8>,
        fhe_type: FheType,
        ciphertext: Vec<u8>,
        eip712_verifying_contract: String,
        chain_id: U256,
        eip712_salt: Option<Vec<u8>>,
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

        // Stop-gap to allow for testing with a static key that has not been genereated using the kms
        // Should be removed as part of https://github.com/zama-ai/fhevm/issues/548
        let key_id_str = match self.get_key_id().await {
            Ok(key_id) => key_id,
            Err(e) => {
                // It is expected that the result will not be immidiately available after the request. Hence this is only logged as info.
                tracing::info!("Could not retrieve the key id from the blockchain: {}", e);
                self.config.kms.key_id.clone()
            }
        };
        let key_id = HexVector::from_hex(&key_id_str)?;

        tracing::info!(
            "🔒 Reencrypting ciphertext using key_id={:?}, ctxt_handle={}, ctxt_digest={}",
            key_id.to_hex(),
            hex::encode(&ctxt_handle),
            hex::encode(&ctxt_digest)
        );

        let client_address =
            Address::from_str(&client_address).context("parsing client address")?;
        let config = EthereumConfig {
            json_rpc_url: self.config.ethereum.http_url.clone(),
            acl_contract_address: format!("0x{}", hex::encode(self.config.ethereum.acl_address.0)),
        };
        let proof = fetch_ethereum_proof(
            reencrypt_proof_params(
                vec![external_ct_handle.clone()],
                vec![client_address.to_vec()],
            ),
            config,
        )
        .await?;

        // chain ID is 32 bytes
        let mut eip712_chain_id = vec![0u8; 32];
        chain_id.to_big_endian(&mut eip712_chain_id);

        // NOTE: the ciphertext digest must be the real digest
        let reencrypt_values = ReencryptValues::new(
            signature,
            CURRENT_FORMAT_VERSION,
            client_address.to_string(),
            enc_key,
            fhe_type,
            key_id,
            external_ct_handle.clone(),
            ctxt_handle.clone(),
            ctxt_digest.clone(),
            acl_address,
            proof,
            self.config.ethereum.reenc_domain_name.clone(),
            self.config.ethereum.reenc_domain_version.clone(),
            eip712_chain_id,
            eip712_verifying_contract,
            eip712_salt,
        )?;

        tracing::info!(
            "Reencryption EIP712 info: name={}, version={}, \
            chain_id={} (HEX), verifying_contract={}, salt={:?}",
            reencrypt_values.eip712_name(),
            reencrypt_values.eip712_version(),
            reencrypt_values.eip712_chain_id().to_hex(),
            reencrypt_values.eip712_verifying_contract(),
            reencrypt_values.eip712_salt(),
        );

        let operation = events::kms::OperationValue::Reencrypt(reencrypt_values);

        // send coins 1:1 with the ciphertext size
        let data_size = footprint::extract_ciphertext_size(&ctxt_handle);
        tracing::info!("🍊 Reencrypting ciphertext of size: {:?}", data_size);
        let ev = self
            .make_req_to_kms_blockchain(data_size, operation)
            .await?;

        tracing::info!("✉️ TxId: {:?}", ev.txn_id().to_hex(),);

        tracing::info!(
            "🍊 Waiting for callback from KMS, txn_id: {:?}",
            ev.txn_id().to_hex()
        );
        let event = self.wait_for_transaction(ev.txn_id()).await?;
        if event.operation != KmsOperation::ReencryptResponse {
            return Err(anyhow!(
                "Expected to receive a ReencryptResponse, but received {:?}",
                event
            ));
        }

        tracing::info!("🍊 Received callback from KMS: {:?}", event.txn_id());
        let request = QueryContractRequest::builder()
            .contract_address(self.config.kms.asc_address.to_string())
            .query(ContractQuery::GetOperationsValuesFromEvent(
                EventQuery::builder().event(event.clone()).build(),
            ))
            .build();

        let results: Vec<OperationValue> = self.query_client.query_contract(request).await?;

        match self.config.mode {
            KmsMode::Centralized => match results.first().unwrap() {
                OperationValue::ReencryptResponse(reencrypt_response) => {
                    let mut reencrypt_response = reencrypt_response.clone();
                    reencrypt_response.set_ciphertext_digest(ctxt_digest.clone());

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
                            let mut reencrypt_response = reencrypt_response.clone();
                            reencrypt_response.set_ciphertext_digest(ctxt_digest.clone());

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

    /// * `client_address`: it has the EIP-55 format, prefixed with 0x
    /// * `contract_address`: it has the EIP-55 format, prefixed with 0x
    ///
    /// Returns a [`HexVectorList`]
    /// filled with the kms_signatures
    /// (as that is the only info the KMS Blockchain provides)
    async fn verify_proven_ct(
        &self,
        client_address: String,
        contract_address: String,
        key_id_str: String,
        crs_id_str: String,
        ct_proof: Vec<u8>,
        eip712_domain: Eip712DomainMsg,
        acl_address: String,
    ) -> anyhow::Result<HexVectorList> {
        tracing::info!(
            "🔒 Verify proven ct with client_address: {:?}, contract_address: {:?}, key_id: {:?}, crs_id: {:?}, chain_id: {:?}",
            &client_address,
            &contract_address,
            key_id_str,
            crs_id_str,
            eip712_domain.chain_id
        );

        let ct_proof_handle = self.store_ciphertext(ct_proof.clone()).await?;

        let key_id = HexVector::from_hex(&key_id_str)?;
        let crs_id = HexVector::from_hex(&crs_id_str)?;
        tracing::info!(
            "🔒 Verify proven ct using key_id={:?}, crs_id={:?}, ct_proof_handle={}",
            key_id.to_hex(),
            crs_id.to_hex(),
            hex::encode(&ct_proof_handle),
        );

        let proven_ct_values = VerifyProvenCtValues::new(
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
        )?;

        let operation = events::kms::OperationValue::VerifyProvenCt(proven_ct_values);

        // send coins 1:1 with the ciphertext size
        let data_size = footprint::extract_ciphertext_size(&ct_proof_handle);
        tracing::info!("🍊 Verify proven ciphertext of size: {:?}", data_size);
        // TODO how do we handle payment of verify proven ct validation?
        let ev = self
            .make_req_to_kms_blockchain(data_size, operation)
            .await?;

        tracing::info!("✉️ TxId: {:?}", ev.txn_id().to_hex(),);

        tracing::info!(
            "🍊 Waiting for callback from KMS, txn_id: {:?}",
            ev.txn_id().to_hex()
        );
        let event = self.wait_for_transaction(ev.txn_id()).await?;
        if event.operation != KmsOperation::VerifyProvenCtResponse {
            return Err(anyhow!(
                "Expected to receive a VerifyProvenCtResponse, but received {:?}",
                event
            ));
        }
        tracing::info!("🍊 Received callback from KMS: {:?}", event.txn_id());
        let request = QueryContractRequest::builder()
            .contract_address(self.config.kms.asc_address.to_string())
            .query(ContractQuery::GetOperationsValuesFromEvent(
                EventQuery::builder().event(event.clone()).build(),
            ))
            .build();

        let results: Vec<OperationValue> = self.query_client.query_contract(request).await?;

        let proven_ct_responses = match self.config.mode {
            KmsMode::Centralized => match results.first().unwrap() {
                OperationValue::VerifyProvenCtResponse(responses) => {
                    tracing::debug!(
                        "🍇🥐🍇🥐🍇🥐 Centralized KMS signature: {:?}",
                        responses.signature().to_hex()
                    );

                    // the output needs to have type Vec<VerifyProvenCtResponse>
                    // in the centralized case there is only 1 element
                    vec![responses.clone()]
                }
                _ => return Err(anyhow::anyhow!("Invalid operation for request {:?}", event)),
            },
            KmsMode::Threshold => {
                let mut out = vec![];
                for value in results.iter() {
                    match value {
                        OperationValue::VerifyProvenCtResponse(verify_proven_ct_response) => {
                            // the output needs to have type Vec<VerifyProvenCtResponse>
                            // in the centralized case there is only 1 element
                            out.push(verify_proven_ct_response.clone());
                        }
                        _ => {
                            return Err(anyhow::anyhow!(
                                "Invalid operation for request {:?}",
                                event
                            ));
                        }
                    }
                }
                out
            }
        };
        parse_verify_proven_ct_responses_to_client(proven_ct_responses)
    }

    async fn keyurl(&self) -> anyhow::Result<KeyUrlResponseValues> {
        // Only get the key url info for the key id that matches the one in the config
        // This is because, in case of multiple key generations, the ASC can return multiple
        // key url infos and the client is not able to tell which ones should be used.
        // This is temporary and will be removed once we properly handle public key IDs across
        // the different components: https://github.com/zama-ai/kms-core/issues/1519
        let key_values = self
            .get_key_gen_response_values(self.config.kms.key_id.clone())
            .await?;

        if key_values.is_empty() {
            tracing::warn!(
                "No key response values found associated with key ID {:?}. Please update the `key_id` parameter in the gateway's config.",
                self.config.kms.key_id
            );
        } else {
            tracing::info!(
                "Got {} key response values for key ID {:?}",
                key_values.len(),
                self.config.kms.key_id
            );
        }
        let key_data = KmsBlockchainImpl::parse_signed_key_data(key_values)?;
        let mut fhe_url_info = Vec::new();
        for (key_id, (param, pk_sigs, server_sigs)) in key_data.iter() {
            fhe_url_info.push(KmsBlockchainImpl::prepare_fhe_key_urls(
                &self.config.kms.public_storage,
                key_id,
                param,
                pk_sigs.to_owned(),
                server_sigs.to_owned(),
            )?);
        }

        let crs_values = self
            .get_crs_gen_response_values(self.config.kms.crs_id.clone())
            .await?;
        if crs_values.is_empty() {
            tracing::warn!("No crs response values found. Were CRS generated?");
        } else {
            tracing::info!("Got {} crs response values", crs_values.len());
        }
        let crs_data = KmsBlockchainImpl::parse_signed_crs_data(crs_values)?;
        let crs = KmsBlockchainImpl::get_crs_info(&self.config.kms.public_storage, &crs_data)?;

        let verf_key_info = KmsBlockchainImpl::get_verf_key_info(
            &self.config.kms.public_storage,
            &SIGNING_KEY_ID.to_string(),
        )?;
        Ok(KeyUrlResponseValues::builder()
            .fhe_key_info(fhe_url_info)
            .crs(crs)
            .verf_public_key(verf_key_info)
            .build())
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

/// Deserializes all verify_proven_ct_responses and extract the external signature
/// It then serializes the [`Vec`] of those signatures and returns
/// a partially completed [`VerifyProvenCtResponseToClient`] builder
///
/// __NOTE__: The [`VerifyProvenCtResponsePayload`] was serialized by
/// [`kms_blockchain_connector::infrastructure::core::VerifyProvenCtVal`]
fn parse_verify_proven_ct_responses_to_client(
    verify_proven_ct_responses: Vec<VerifyProvenCtResponseValues>,
) -> anyhow::Result<HexVectorList> {
    let mut external_signatures = Vec::new();
    for verify_proven_ct_response in verify_proven_ct_responses {
        let verify_proven_ct_payload: VerifyProvenCtResponsePayload =
            bincode::deserialize(verify_proven_ct_response.payload())?;
        external_signatures.push(HexVector(verify_proven_ct_payload.external_signature));
    }

    Ok(external_signatures.into())
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
    use crate::blockchain::kms_blockchain::{most_common_element, KmsBlockchainImpl};
    use events::{
        kms::{CrsGenResponseValues, FheParameter, KeyGenResponseValues},
        HexVector, HexVectorList,
    };
    use kms_lib::{
        kms::{ParamChoice, RequestId},
        rpc::rpc_types::PubDataType,
    };
    use std::collections::HashMap;

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

    #[test]
    fn sunshine_parse_key_sig() {
        let req_id = HexVector::from_hex(
            &RequestId::derive("sunshine_parse_key_sig")
                .unwrap()
                .to_string(),
        )
        .unwrap();
        let other_req_id = HexVector::from_hex(
            &RequestId::derive("sunshine_parse_key_sig_other_req_id")
                .unwrap()
                .to_string(),
        )
        .unwrap();
        let key_response_values = vec![
            // Server 1 response
            KeyGenResponseValues::new(
                req_id.clone(),
                "digest_pk_1".to_string(),
                HexVector::from_hex("111111111111111111111111111111111111111100").unwrap(), // pk_sig
                "digest_server_1".to_string(),
                HexVector::from_hex("111111111111111111111111111111111111111111").unwrap(), // server_sig
                FheParameter::Test,
            ),
            // Server 2 response
            KeyGenResponseValues::new(
                req_id.clone(),
                "digest_pk_2".to_string(),
                HexVector::from_hex("222222222222222222222222222222222222222200").unwrap(), // pk_sig
                "digest_server_2".to_string(),
                HexVector::from_hex("222222222222222222222222222222222222222211").unwrap(), // server_sig
                FheParameter::Test,
            ),
            // Server 1 response to other key
            KeyGenResponseValues::new(
                other_req_id.clone(),
                "digest_pk_1_other".to_string(),
                HexVector::from_hex("abcdef").unwrap(), // pk_sig
                "digest_server_1_other".to_string(),
                HexVector::from_hex("abcdef").unwrap(), // server_sig
                FheParameter::Test,
            ),
        ];
        let res = KmsBlockchainImpl::parse_signed_key_data(key_response_values).unwrap();
        assert_eq!(res.len(), 2);
        let (param, res_pk_sig, res_server_sig) = res.get(&req_id.to_hex()).unwrap();
        assert_eq!(param, &FheParameter::Test);
        // Check pk sigs
        assert_eq!(
            res_pk_sig.0,
            vec![
                HexVector::from_hex("111111111111111111111111111111111111111100").unwrap(),
                HexVector::from_hex("222222222222222222222222222222222222222200").unwrap()
            ]
        );
        // Check server sigs
        assert_eq!(
            res_server_sig.0,
            vec![
                HexVector::from_hex("111111111111111111111111111111111111111111").unwrap(),
                HexVector::from_hex("222222222222222222222222222222222222222211").unwrap()
            ]
        );
    }

    #[test]
    fn parse_signed_crs_data() {
        let req_id = RequestId::derive("sunshine_parse_key_sig")
            .unwrap()
            .to_string();
        let other_req_id = RequestId::derive("sunshine_parse_key_sig_other_req_id")
            .unwrap()
            .to_string();
        let max_bits = 256;
        let param = FheParameter::Test;
        let crs_response_values = vec![
            // Server 1 response
            CrsGenResponseValues::new(
                req_id.clone(),
                "digest_1".to_string(),
                HexVector::from_hex("111111111111111111111111111111111111111111").unwrap(),
                max_bits,
                param,
            ),
            // Server 2 response
            CrsGenResponseValues::new(
                req_id.clone(),
                "digest_pk_2".to_string(),
                HexVector::from_hex("222222222222222222222222222222222222222222").unwrap(),
                max_bits,
                param,
            ),
            // Server 1 response to other crs
            CrsGenResponseValues::new(
                other_req_id.clone(),
                "digest_1_other".to_string(),
                HexVector::from_hex("abcdef").unwrap(),
                max_bits,
                param,
            ),
        ];
        let res = KmsBlockchainImpl::parse_signed_crs_data(crs_response_values).unwrap();
        assert_eq!(res.len(), 2);
        let (retrieved_max_bits, retrieved_param, sig) = res.get(&req_id).unwrap();
        assert_eq!(max_bits, *retrieved_max_bits);
        assert_eq!(&param, retrieved_param);
        assert_eq!(
            sig.0,
            vec![
                HexVector::from_hex("111111111111111111111111111111111111111111").unwrap(),
                HexVector::from_hex("222222222222222222222222222222222222222222").unwrap()
            ]
        );
    }

    #[test]
    fn sunshine_fhe_key_info() {
        let key_id = "00112233445566778899aabbccddeeff0011223344";
        let base_sig = HexVector::from_hex("00112233445566778899aabbccddeeff0011223344").unwrap();
        let sigs = HexVectorList(vec![
            base_sig.clone(),
            base_sig.clone(),
            base_sig.clone(),
            base_sig.clone(),
        ]);
        let storages_urls: HashMap<u32, String> = HashMap::from([
            (1, "http://127.0.0.1:8081/PUB-p1/".to_string()),
            (2, "http://127.0.0.1:8082/PUB-p2".to_string()),
            (3, "http://127.0.0.1:8083/PUB-p3/".to_string()),
            (4, "http://127.0.0.1:8084/PUB-p4".to_string()), // Ensure that suffix / is not needed
        ]);
        let fhe_server_key = KmsBlockchainImpl::get_fhe_key_info(
            PubDataType::ServerKey,
            &storages_urls,
            key_id,
            &FheParameter::Test,
            sigs,
        )
        .unwrap();
        assert_eq!(fhe_server_key.data_id().to_hex(), key_id);
        assert_eq!(
            fhe_server_key.param_choice(),
            <FheParameter as Into<i32>>::into(FheParameter::Test),
        );
        assert_eq!(fhe_server_key.urls().len(), 4);
        assert!(fhe_server_key.urls().contains(
            &"http://127.0.0.1:8081/PUB-p1/ServerKey/00112233445566778899aabbccddeeff0011223344"
                .to_string()
        ));
        assert!(fhe_server_key.urls().contains(
            &"http://127.0.0.1:8082/PUB-p2/ServerKey/00112233445566778899aabbccddeeff0011223344"
                .to_string()
        ));
        assert!(fhe_server_key.urls().contains(
            &"http://127.0.0.1:8083/PUB-p3/ServerKey/00112233445566778899aabbccddeeff0011223344"
                .to_string()
        ));
        assert!(fhe_server_key.urls().contains(
            &"http://127.0.0.1:8084/PUB-p4/ServerKey/00112233445566778899aabbccddeeff0011223344"
                .to_string()
        ));
    }

    #[test]
    fn sunshine_verf_key_info() {
        let key_id = "00112233445566778899aabbccddeeff0011223344";
        let storages_urls: HashMap<u32, String> = HashMap::from([
            (1, "http://127.0.0.1:8081/PUB-p1/".to_string()),
            (2, "http://127.0.0.1:8082/PUB-p2".to_string()),
            (3, "http://127.0.0.1:8083/PUB-p3/".to_string()),
            (4, "http://127.0.0.1:8084/PUB-p4".to_string()), // Ensure that suffix / is not needed
        ]);
        let verf_key_info = KmsBlockchainImpl::get_verf_key_info(&storages_urls, key_id).unwrap();
        assert_eq!(verf_key_info.len(), storages_urls.len());
        for cur_info in verf_key_info {
            assert_eq!(cur_info.key_id().to_hex(), key_id);
            assert!(cur_info.server_id() >= 1);
            assert!(cur_info.server_id() <= storages_urls.len() as u32);
            assert_eq!(cur_info.verf_public_key_address(),
                &format!("http://127.0.0.1:808{}/PUB-p{}/VerfAddress/00112233445566778899aabbccddeeff0011223344", cur_info.server_id(), cur_info.server_id())
                    .to_string()
            );
            assert_eq!(cur_info.verf_public_key_url(),
                &format!("http://127.0.0.1:808{}/PUB-p{}/VerfKey/00112233445566778899aabbccddeeff0011223344", cur_info.server_id(), cur_info.server_id())
                    .to_string()
            );
        }
    }

    #[test]
    fn sunshine_crs_info() {
        let storages_urls: HashMap<u32, String> = HashMap::from([
            (1, "http://127.0.0.1:8081/PUB-p1/".to_string()),
            (2, "http://127.0.0.1:8082/PUB-p2".to_string()),
            (3, "http://127.0.0.1:8083/PUB-p3/".to_string()),
            (4, "http://127.0.0.1:8084/PUB-p4".to_string()), // Ensure that suffix / is not needed
        ]);
        let base_sig = HexVector::from_hex("00112233445566778899aabbccddeeff0011223344").unwrap();
        let sigs = HexVectorList(vec![
            base_sig.clone(),
            base_sig.clone(),
            base_sig.clone(),
            base_sig.clone(),
        ]);
        let crs_ids: HashMap<String, (u32, FheParameter, HexVectorList)> = HashMap::from([
            (
                "00112233445566778899aabbccddeeff0011223344".to_string(),
                (128, FheParameter::Test, sigs.clone()),
            ),
            (
                "9988776655443322110099887766554433221100aa".to_string(),
                (256, FheParameter::Default, sigs.clone()),
            ),
        ]);
        let crs_info = KmsBlockchainImpl::get_crs_info(&storages_urls, &crs_ids).unwrap();
        assert_eq!(crs_info.len(), crs_ids.len());
        for (max_bits, cur_info) in &crs_info {
            assert_eq!(storages_urls.len(), cur_info.signatures().len());
            if *max_bits == 128 {
                assert_eq!(
                    <ParamChoice as Into<i32>>::into(ParamChoice::Test),
                    cur_info.param_choice()
                );
            } else {
                assert_eq!(
                    <ParamChoice as Into<i32>>::into(ParamChoice::Default),
                    cur_info.param_choice()
                );
            }
            assert!(cur_info.signatures().contains(&base_sig.clone()));
        }
        for cur_server_id in storages_urls.keys() {
            assert!(crs_info[&128].urls().contains(
                &format!(
                    "http://127.0.0.1:808{}/PUB-p{}/CRS/00112233445566778899aabbccddeeff0011223344",
                    cur_server_id, cur_server_id
                )
                .to_string()
            ));
            assert!(crs_info[&256].urls().contains(
                &format!(
                    "http://127.0.0.1:808{}/PUB-p{}/CRS/9988776655443322110099887766554433221100aa",
                    cur_server_id, cur_server_id
                )
                .to_string()
            ));
        }
    }
}

use crate::events::manager::DecryptionEvent;
use crate::events::manager::KmsEventWithHeight;
use crate::state::file_state::GatewayState;
use crate::state::DecryptKmsEventState;
use crate::state::GatewayEventState;
use crate::state::GatewayInnerEvent;
use crate::state::KmsEventState;
use crate::{
    blockchain::{Blockchain, KmsEventSubscriber},
    config::{
        FheKeyUrlInfo, GatewayConfig, KeyUrlInfo, KeyUrlResponseValues, KmsMode, VerfKeyUrlInfo,
    },
    util::{conversion::TokenizableFrom, footprint},
};
use alloy_primitives::Address;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use bincode::deserialize;
use cosmos_proto::messages::cosmos::base::abci::v1beta1::TxResponse;
use dashmap::DashMap;
use ethereum_inclusion_proofs::{
    std_proof_handler::EthereumProofHandler,
    types::{DecryptProofParams, EVMProofParams, EthereumConfig, ReencryptProofParams},
};
use ethers::{abi::Token, prelude::*};
use events::{
    kms::{
        CrsGenResponseValues, DecryptValues, FheParameter, FheType, KeyGenResponseValues,
        KmsCoreParty, KmsEvent, KmsMessage, KmsOperation, OperationValue, ReencryptResponseValues,
        ReencryptValues, TransactionId, VerifyProvenCtResponseValues, VerifyProvenCtValues,
    },
    HexVector, HexVectorList,
};
use kms_blockchain_client::client::Client;
use kms_blockchain_client::client::ClientBuilder;
use kms_blockchain_client::client::ExecuteContractRequest;
use kms_blockchain_client::client::ProtoCoin;
use kms_blockchain_client::errors::Error;
use kms_blockchain_client::query_client::EventQuery;
use kms_blockchain_client::query_client::GenCrsIdQuery;
use kms_blockchain_client::query_client::GenKeyIdQuery;
use kms_blockchain_client::query_client::QueryClient;
use kms_blockchain_client::query_client::QueryClientBuilder;
use kms_blockchain_client::query_client::{AscQuery, CscQuery};
use kms_common::retry_loop;
use kms_grpc::{
    kms::v1::{DecryptionResponsePayload, Eip712DomainMsg, VerifyProvenCtResponsePayload},
    rpc_types::{hash_element, PubDataType},
};
use prost::Message;
use serde::de::DeserializeOwned;
use std::{collections::HashMap, path::MAIN_SEPARATOR_STR, str::FromStr, sync::Arc};
use strum::IntoEnumIterator;
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tracing::{info, Instrument};

pub(crate) struct KmsBlockchainImpl {
    pub(crate) client: Arc<RwLock<Client>>,
    pub(crate) query_client: Arc<QueryClient>,
    pub(crate) responders: Arc<DashMap<TransactionId, oneshot::Sender<KmsEventWithHeight>>>,
    pub(crate) event_sender: Arc<mpsc::Sender<KmsEventWithHeight>>,
    pub(crate) config: GatewayConfig,
    pub(crate) gw_state: GatewayState,
    // NOTE: We use the Mutex here to ensure atomicity of
    // the actions performed by the task spawned in new():
    // - look watchlsit
    // - insert uncaught
    // AND the actions performed in wait_for_transaction
    // - look uncaught
    // - insert watchlist
    pub(crate) uncaught_responses: Arc<Mutex<HashMap<TransactionId, KmsEventWithHeight>>>,
}

#[async_trait]
impl KmsEventSubscriber for KmsBlockchainImpl {
    async fn receive(&self, event: KmsEventWithHeight) -> anyhow::Result<()> {
        tracing::debug!("🤠 Received KmsEvent: {:?}", event);
        self.event_sender
            .send(event)
            .await
            .map_err(|e| anyhow!(e.to_string()))
    }
}

/// Tuple that holds parameter and signature information on a (public) key.
/// Fields are the parameter, the public key signature, the public key external signature, the server key signature, and the server key external signature
type KeyData = (
    FheParameter,
    HexVectorList,
    HexVectorList,
    HexVectorList,
    HexVectorList,
);

fn add_unless_duplicate(list: &mut HexVectorList, val: &HexVector, resp: &str) {
    if list.contains(val) {
        tracing::error!("The response from the blockchain on {resp} already contains the signature {:?}. Will not add again.", val);
    } else {
        list.0.push(val.to_owned());
    }
}

impl KmsBlockchainImpl {
    fn new(
        mnemonic: Option<String>,
        addresses: Vec<&str>,
        config: GatewayConfig,
        state: GatewayState,
    ) -> Self {
        let (tx, mut rx) = mpsc::channel::<KmsEventWithHeight>(100);
        let responders: Arc<DashMap<TransactionId, oneshot::Sender<KmsEventWithHeight>>> =
            Arc::new(DashMap::new());
        let uncaught_responses: Arc<Mutex<HashMap<TransactionId, KmsEventWithHeight>>> =
            Arc::new(Mutex::new(HashMap::new()));

        tokio::spawn({
            let responders_clone = responders.clone();
            let uncaught_responses_clone = uncaught_responses.clone();
            async move {
                // This channel is fed by the listen loop of the GW itself
                while let Some(event_with_height) = rx.recv().await {
                    let mut uncaught_responses_guard = uncaught_responses_clone.lock().await;
                    tracing::info!("🤠🤠🤠 Received KmsEvent: {:?}", event_with_height);
                    let txn_id = event_with_height.event.txn_id.clone();
                    if let Some((_, sender)) = responders_clone.remove(&txn_id) {
                        tracing::info!("🤠🤠🤠 Notifying waiting task");
                        let _ = sender.send(event_with_height); // Notify the waiting task
                    } else if event_with_height.event.operation().is_response() {
                        // We store all responses we weren't expecting
                        // as it may be due to some race condition

                        (*uncaught_responses_guard).insert(txn_id, event_with_height);
                    }
                    drop(uncaught_responses_guard);
                    //Should we store the event in responders if it's a dec event and it wasn't in responders ? Might mean there was a reace condition (or current GW didn't initiate the decryption)
                }
            }
        });

        Self {
            client: Arc::new(RwLock::new(
                ClientBuilder::builder()
                    .mnemonic_wallet(mnemonic.as_deref())
                    .grpc_addresses(addresses.clone())
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
            gw_state: state,
            uncaught_responses,
        }
    }

    pub(crate) async fn new_from_config(
        config: GatewayConfig,
        state: GatewayState,
    ) -> anyhow::Result<Self> {
        let mnemonic = Some(config.kms.mnemonic.to_string());
        let binding = config.kms.address.to_string();
        let addresses = vec![binding.as_str()];
        let kms_bc_impl = Self::new(mnemonic, addresses, config, state);

        Ok(kms_bc_impl)
    }

    // Search for the event we are looking for in the uncaught events,
    // if it doesn't exist there, insert the event we are looking for in the responders map
    // that is watched by a task spawned in Self::new
    #[tracing::instrument(skip(self))]
    pub(crate) async fn wait_for_transaction(
        &self,
        txn_id: &TransactionId,
    ) -> anyhow::Result<KmsEventWithHeight> {
        let mut uncaught_responses_guard = self.uncaught_responses.lock().await;
        if let Some(event) = (*uncaught_responses_guard).remove(txn_id) {
            Ok(event)
        } else {
            let (tx, rx) = oneshot::channel();
            tracing::info!("🤠🤠🤠 Waiting for transaction: {:?}", txn_id);
            self.responders.insert(txn_id.clone(), tx);
            //Drop the guard to allow for the task spawned in Self::new to make progress
            drop(uncaught_responses_guard);
            rx.await.map_err(|e| anyhow!(e.to_string()))
        }
    }

    pub(crate) async fn call_execute_contract(
        &self,
        client: &mut Client,
        request: &ExecuteContractRequest,
    ) -> Result<TxResponse, kms_blockchain_client::errors::Error> {
        client.execute_contract(request.clone()).await
    }

    #[allow(clippy::assign_op_pattern)]
    #[tracing::instrument(skip(self, operation), fields(op_name=operation.values_name()))]
    async fn make_req_to_kms_blockchain(
        &self,
        asc_address: String,
        data_size: u32,
        operation: OperationValue,
    ) -> anyhow::Result<KmsEventWithHeight> {
        let request = ExecuteContractRequest::builder()
            .contract_address(asc_address)
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

        // Loop until we get a query response
        let resp: anyhow::Result<TxResponse> = retry_loop!(|| async {
            // Keep querying using the txhash to make sure it appeared on the blockchain
            let query_response = self
                .query_client
                .query_tx(response.txhash.clone())
                .await
                .map_err(|e| {
                    let msg = format!("Error querying a response from the KMS blockchain {:?}", e);
                    tracing::error!(msg);
                    anyhow::anyhow!(msg)
                })?;
            if let Some(qr) = query_response {
                Ok(qr)
            } else {
                let msg = ("Waiting for transaction to be included in a block").to_string();
                tracing::info!(msg);
                Err(anyhow::anyhow!(msg))
            }
        }
        .instrument(tracing::Span::current()));

        let resp = resp?;
        let tx_height = resp.height as u64;
        let events = resp
            .events
            .iter()
            .filter(|x| KmsOperation::iter().any(|attr| x.r#type == format!("wasm-{}", attr)))
            .map(to_event)
            .map(|ev| {
                anyhow::Ok(KmsEventWithHeight::new(
                    <cosmwasm_std::Event as TryInto<KmsEvent>>::try_into(ev)?,
                    tx_height,
                ))
            })
            .collect::<Result<Vec<KmsEventWithHeight>, _>>()?;

        // At this point evs should contain a single event
        if events.len() != 1 {
            tracing::error!("Expected a single KmsEvent, but received: {:?}", events);
            return Err(anyhow::anyhow!(
                "Expected a single KmsEvent, but received: {:?}",
                events
            ));
        }
        let ev = events[0].clone();
        let expected_kms_op = <OperationValue as std::convert::Into<KmsOperation>>::into(operation);
        // Make sure this is indeed the expected event
        if ev.event.operation != expected_kms_op {
            tracing::error!("Expected a {:?} , but received: {:?}", expected_kms_op, ev);
            return Err(anyhow::anyhow!(
                "Expected a {:?} , but received: {:?}",
                expected_kms_op,
                ev
            ));
        }
        Ok(ev)
    }

    #[tracing::instrument(skip(self, ctxt), fields(ctxt_len = ctxt.len()))]
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

    /// Helper function to query the CSC.
    async fn query_csc<T: DeserializeOwned>(&self, contract_query: CscQuery) -> Result<T, Error> {
        let query_client = Arc::clone(&self.query_client);
        let values: T = query_client
            .query_csc(self.config.kms.csc_address.to_string(), contract_query)
            .await?;
        Ok(values)
    }

    /// Helper function to get the response count for majority vote.
    async fn get_response_count_for_majority_vote(&self) -> Result<usize, Error> {
        let csc_query = CscQuery::GetResponseCountForMajorityVote {};
        self.query_csc(csc_query).await
    }

    /// Helper function to get the degree for reconstruction.
    async fn get_degree_for_reconstruction(&self) -> Result<usize, Error> {
        let csc_query = CscQuery::GetDegreeForReconstruction {};
        self.query_csc(csc_query).await
    }

    /// Helper function to get the storage base URL.
    async fn get_storage_base_url(&self) -> Result<String, Error> {
        let csc_query = CscQuery::GetStorageBaseUrl {};
        self.query_csc(csc_query).await
    }

    /// Helper function to get the parties.
    async fn get_parties(&self) -> Result<HashMap<String, KmsCoreParty>, Error> {
        let csc_query = CscQuery::GetParties {};
        self.query_csc(csc_query).await
    }

    /// Helper function to query the ASC.
    async fn query_asc<T: DeserializeOwned>(&self, contract_query: AscQuery) -> Result<T, Error> {
        let query_client = Arc::clone(&self.query_client);
        let values: T = query_client
            .query_asc(self.config.kms.asc_address.to_string(), contract_query)
            .await?;
        Ok(values)
    }

    /// Helper function to get all the KeyGenResponseValues from the KMS blockchain.
    async fn get_key_gen_response_values(
        &self,
        key_id: String,
    ) -> Result<Vec<KeyGenResponseValues>, Error> {
        let asc_query = AscQuery::GetKeyGenResponseValues(GenKeyIdQuery { key_id });
        self.query_asc(asc_query).await
    }

    /// Helper function to get all the CrsGenResponseValues from the KMS blockchain.
    async fn get_crs_gen_response_values(
        &self,
        crs_id: String,
    ) -> Result<Vec<CrsGenResponseValues>, Error> {
        let asc_query = AscQuery::GetCrsGenResponseValues(GenCrsIdQuery { crs_id });
        self.query_asc(asc_query).await
    }

    /// Helper function to get the operations values from an event.
    async fn get_operations_values_from_event(
        &self,
        event: KmsEvent,
    ) -> Result<Vec<OperationValue>, Error> {
        let asc_query = AscQuery::GetOperationsValuesFromEvent(EventQuery {
            event: event.clone(),
        });
        self.query_asc(asc_query).await
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
    /// Takes a vector of KeyGenResponses as input and returns a map of key IDs to a tuple of parameter choice, public key signatures (internal and external) followed by server signatures (internal and external).
    fn parse_signed_key_data(
        vals: Vec<KeyGenResponseValues>,
    ) -> anyhow::Result<HashMap<String, KeyData>> {
        let mut id_sig_map: HashMap<String, KeyData> = HashMap::new();
        // Go through each operation value returned and branch into the keygen case.
        // Then combine all signatures on the same ID into a vector for that ID.
        for key_resp in vals.iter() {
            match id_sig_map.get_mut(&key_resp.request_id().to_hex()) {
                // First the case where the ID is already in the map
                Some((param, pk_sigs, pk_external_sigs, server_sigs, server_external_sigs)) => {
                    if param != key_resp.param() {
                        tracing::error!("Discrepancy between the parties choice of parameter. Specifically the initial parameter choice is {:?} and the current one is {:?}", key_resp.param(), param);
                    }
                    // NOTE: These are just  sanity checks and pretty slow, so can be removed if we end up with many MPC servers.
                    add_unless_duplicate(pk_sigs, key_resp.public_key_signature(), "KeyGen");
                    add_unless_duplicate(
                        pk_external_sigs,
                        key_resp.public_key_external_signature(),
                        "KeyGen",
                    );
                    add_unless_duplicate(server_sigs, key_resp.server_key_signature(), "KeyGen");
                    add_unless_duplicate(
                        server_external_sigs,
                        key_resp.server_key_external_signature(),
                        "KeyGen",
                    );
                }
                // Then the case where it is the first time we see the ID
                None => {
                    id_sig_map.insert(
                        key_resp.request_id().to_hex(),
                        (
                            key_resp.param().to_owned(),
                            HexVectorList(vec![key_resp.public_key_signature().to_owned()]),
                            HexVectorList(vec![key_resp
                                .public_key_external_signature()
                                .to_owned()]),
                            HexVectorList(vec![key_resp.server_key_signature().to_owned()]),
                            HexVectorList(vec![key_resp
                                .server_key_external_signature()
                                .to_owned()]),
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
    ) -> anyhow::Result<HashMap<String, (u32, FheParameter, HexVectorList, HexVectorList)>> {
        let mut id_sig_map: HashMap<String, (u32, FheParameter, HexVectorList, HexVectorList)> =
            HashMap::new();
        // Go through each operation value returned and branch into the crsgen case.
        // Then combine all signatures on the same ID into a vector for that ID.
        for crs_resp in vals.iter() {
            match id_sig_map.get_mut(crs_resp.request_id()) {
                // First the case where the ID is already in the map
                Some((max_num_bits, fhe_param, sigs, ext_sigs)) => {
                    if *max_num_bits != crs_resp.max_num_bits() {
                        tracing::error!("Discrepancy between the parties choice of max number of bits. Specifically the initial choice is {:?} and the current one is {:?}", max_num_bits, crs_resp.max_num_bits());
                    }
                    if fhe_param != crs_resp.param() {
                        tracing::error!("Discrepancy between the parties choice of parameter. Specifically the initial parameter choice is {:?} and the current one is {:?}", fhe_param, crs_resp.param());
                    }
                    // NOTE: This is just a sanity check and pretty slow, so can be removed if we end up with many MPC servers.
                    add_unless_duplicate(sigs, crs_resp.signature(), "CrsGen");
                    add_unless_duplicate(ext_sigs, crs_resp.external_signature(), "CrsGen");
                }
                // Then the case where it is the first time we see the ID
                None => {
                    id_sig_map.insert(
                        crs_resp.request_id().to_owned(),
                        (
                            crs_resp.max_num_bits(),
                            crs_resp.param().to_owned(),
                            HexVectorList(vec![crs_resp.signature().to_owned()]),
                            HexVectorList(vec![crs_resp.external_signature().to_owned()]),
                        ),
                    );
                }
            }
        }
        Ok(id_sig_map)
    }

    /// Construct a `KeyUrlResponseValues` object from the given parameters.
    /// This is used for different types of public key material such as both PublicKey and ServerKey.
    #[allow(clippy::too_many_arguments)]
    fn prepare_fhe_key_urls(
        storage_base_url: &str,
        parties: &HashMap<String, KmsCoreParty>,
        key_id: &str,
        param: &FheParameter,
        pk_sig: HexVectorList,
        pk_ext_sig: HexVectorList,
        server_sig: HexVectorList,
        server_ext_sig: HexVectorList,
    ) -> anyhow::Result<FheKeyUrlInfo> {
        let fhe_public_key = Self::get_fhe_key_info(
            PubDataType::PublicKey,
            storage_base_url,
            parties,
            key_id,
            param,
            pk_sig,
            pk_ext_sig,
        )?;
        let fhe_server_key = Self::get_fhe_key_info(
            PubDataType::ServerKey,
            storage_base_url,
            parties,
            key_id,
            param,
            server_sig,
            server_ext_sig,
        )?;
        Ok(FheKeyUrlInfo::builder()
            .fhe_public_key(fhe_public_key)
            .fhe_server_key(fhe_server_key)
            .build())
    }

    /// Construct a `KeyUrlInfo` object from the given parameters.
    fn get_fhe_key_info(
        key_type: PubDataType,
        storage_base_url: &str,
        parties: &HashMap<String, KmsCoreParty>,
        key_id: &str,
        param: &FheParameter,
        sigs: HexVectorList,
        ext_sigs: HexVectorList,
    ) -> anyhow::Result<KeyUrlInfo> {
        let key_type_string = key_type.to_string();

        let mut urls = Vec::new();
        for party in parties.values() {
            let party_url_label = party.public_storage_label.clone();
            let url = format!(
                "{storage_base_url}{MAIN_SEPARATOR_STR}{party_url_label}{MAIN_SEPARATOR_STR}{key_type_string}{MAIN_SEPARATOR_STR}{key_id}"
            );
            urls.push(url);
        }
        Ok(KeyUrlInfo::builder()
            .data_id(HexVector::from_hex(key_id)?)
            .fhe_parameter(param.to_owned().into())
            .urls(urls)
            .signatures(sigs)
            .external_signatures(ext_sigs)
            .build())
    }

    /// Construct a `VerfKeyUrlInfo` object from the given parameters.
    /// This consists of all the URL information about the public verification keys of each of the MPC servers.
    fn get_verf_key_info(
        storage_base_url: &str,
        parties: &HashMap<String, KmsCoreParty>,
        key_id: &str,
    ) -> anyhow::Result<Vec<VerfKeyUrlInfo>> {
        let verf_key = PubDataType::VerfKey.to_string();
        let verf_addr = PubDataType::VerfAddress.to_string();

        let mut res = Vec::new();
        for (signing_key_handle, party) in parties {
            let party_url_label = party.public_storage_label.clone();
            let key_url = format!(
                "{storage_base_url}{MAIN_SEPARATOR_STR}{party_url_label}{MAIN_SEPARATOR_STR}{verf_key}{MAIN_SEPARATOR_STR}{key_id}"
            );
            let addr_url = format!(
                "{storage_base_url}{MAIN_SEPARATOR_STR}{party_url_label}{MAIN_SEPARATOR_STR}{verf_addr}{MAIN_SEPARATOR_STR}{key_id}"
            );
            res.push(
                VerfKeyUrlInfo::builder()
                    .key_id(HexVector::from_hex(key_id)?)
                    .server_signing_key_handle(signing_key_handle.clone())
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
        storage_base_url: &str,
        parties: &HashMap<String, KmsCoreParty>,
        crs_data: &HashMap<String, (u32, FheParameter, HexVectorList, HexVectorList)>,
    ) -> anyhow::Result<HashMap<u32, KeyUrlInfo>> {
        let crs_type = PubDataType::CRS.to_string();

        let mut res = HashMap::new();
        for (crs_id, (max_bits, param, sigs, ext_sigs)) in crs_data.iter() {
            let mut urls = Vec::new();
            for party in parties.values() {
                let party_url_label = party.public_storage_label.clone();
                let crs_url = format!(
                    "{storage_base_url}{MAIN_SEPARATOR_STR}{party_url_label}{MAIN_SEPARATOR_STR}{crs_type}{MAIN_SEPARATOR_STR}{crs_id}"
                );
                urls.push(crs_url);
            }
            res.insert(
                *max_bits,
                KeyUrlInfo::builder()
                    .data_id(HexVector::from_hex(crs_id)?)
                    .fhe_parameter(param.to_owned().into())
                    .urls(urls)
                    .signatures(sigs.to_owned())
                    .external_signatures(ext_sigs.to_owned())
                    .build(),
            );
        }
        Ok(res)
    }
}

#[tracing::instrument]
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

impl KmsBlockchainImpl {
    async fn prepare_decrypt_request(
        &self,
        typed_cts: Vec<(Vec<u8>, FheType, Vec<u8>)>,
        eip712_domain: Eip712DomainMsg,
        acl_address: String,
    ) -> anyhow::Result<(OperationValue, Vec<FheType>, u32)> {
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
        Ok((operation, fhe_types, total_size))
    }

    async fn prepare_decrypt_answer(
        &self,
        event: KmsEventWithHeight,
        fhe_types: Vec<FheType>,
    ) -> anyhow::Result<(Vec<Token>, Vec<Vec<u8>>)> {
        tracing::info!("🍊 Received callback from KMS: {:?}", event.event.txn_id());
        // Because we have seen the event, we now know that the result is ready to be queried
        // so we query the GetOperationsValuesFromEvent endpoint of the ASC

        let results: Vec<OperationValue> = self
            .get_operations_values_from_event(event.event.clone())
            .await?;
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

                    // 1 batch of plaintexts and a single signature for the batch from the centralized KMS
                    (payload.plaintexts, vec![external_sig])
                }
                _ => return Err(anyhow::anyhow!("Invalid operation for request {:?}", event)),
            },
            KmsMode::Threshold => {
                let mut ptxts = Vec::new();
                let mut sigs = Vec::new();

                // Get the number of responses needed for a majority vote from the CSC
                let response_count_for_majority_vote: usize =
                    self.get_response_count_for_majority_vote().await?;

                // We need at least 2t + 1 responses for secure majority voting (at most t could be malicious).
                // The reason ist that the KMS ASC simply counts responses without checking equality, so we might receive up to t malicious responses.
                // The value (2t + 1) comes from the configuration set in the CSC.
                if results.len() < response_count_for_majority_vote {
                    return Err(anyhow::anyhow!(
                        "Have not received enough decryption results: received {}, needed at least {}",
                        results.len(),
                        response_count_for_majority_vote
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

                // Get the degree for reconstruction from the CSC
                let degree_for_reconstruction: usize = self.get_degree_for_reconstruction().await?;

                // We need at least t + 1 identical batch responses as majority, so we can return the majority plaintext (at most t others were corrupted)
                let required_majority = degree_for_reconstruction + 1;
                if majority_count >= required_majority {
                    // return the majority plaintext batch and all signatures by the threshold KMS parties
                    (majority_pts, sigs)
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
}

#[async_trait]
impl Blockchain for KmsBlockchainImpl {
    // TODO: Properly choose which parameters should be kept in the trace or not
    #[tracing::instrument(skip(self))]
    async fn decrypt(
        &self,
        decryption_event: DecryptionEvent,
        typed_cts: Vec<(Vec<u8>, FheType, Vec<u8>)>,
        eip712_domain: Eip712DomainMsg,
        asc_address: String,
        acl_address: String,
    ) -> anyhow::Result<(Vec<Token>, Vec<Vec<u8>>)> {
        let (operation, fhe_types, total_size) = self
            .prepare_decrypt_request(typed_cts, eip712_domain, acl_address)
            .await?;

        // Execute the smart contract and wait for the Tx to appear in a block.
        // Returns the corresponding KmsEvent of this transaction
        let ev = self
            .make_req_to_kms_blockchain(asc_address, total_size, operation)
            .await?;

        //Update the GW state
        let gateway_event = GatewayInnerEvent::Decryption(decryption_event);
        let event_state = DecryptKmsEventState {
            event: ev.clone(),
            fhe_types: fhe_types.clone(),
        };
        self.gw_state
            .update_event(
                &gateway_event,
                GatewayEventState::SentToKmsBc(KmsEventState::Decrypt(event_state)),
            )
            .await?;

        tracing::info!("✉️ TxId: {:?}", ev.event.txn_id().to_hex(),);

        tracing::info!(
            "🍊 Waiting for callback from KMS, txn_id: {:?}",
            ev.event.txn_id().to_hex()
        );

        let event = self.wait_for_transaction(ev.event.txn_id()).await?;
        if event.event.operation != KmsOperation::DecryptResponse {
            return Err(anyhow!(
                "Expected to receive a DecryptResponse, but received {:?}",
                event
            ));
        }

        // Update the state
        let event_state = DecryptKmsEventState {
            event: event.clone(),
            fhe_types: fhe_types.clone(),
        };
        self.gw_state
            .update_event(
                &gateway_event,
                GatewayEventState::ResultFromKmsBc(KmsEventState::Decrypt(event_state)),
            )
            .await?;

        self.prepare_decrypt_answer(event, fhe_types).await
    }

    async fn decrypt_catchup(
        &self,
        decryption_event: DecryptionEvent,
        event_state: GatewayEventState,
    ) -> anyhow::Result<(Vec<Token>, Vec<Vec<u8>>)> {
        match event_state {
            GatewayEventState::Received => Err(anyhow!(
                "Tried to catchup on an event that hasn't been sent to KMS yet"
            )),
            GatewayEventState::SentToKmsBc(kms_event) => {
                if let KmsEventState::Decrypt(decrypt_state) = kms_event {
                    let (kms_event, fhe_types) = (decrypt_state.event, decrypt_state.fhe_types);
                    // This work under the hypothesis that we started watching the KMS
                    // BC from a block height anterior to that of which the response event
                    // was emitted
                    let event = self.wait_for_transaction(kms_event.event.txn_id()).await?;
                    if event.event.operation != KmsOperation::DecryptResponse {
                        return Err(anyhow!(
                            "Expected to receive a DecryptResponse, but received {:?}",
                            event
                        ));
                    }

                    // Update the state
                    let event_state = DecryptKmsEventState {
                        event: event.clone(),
                        fhe_types: fhe_types.clone(),
                    };
                    let gateway_event = GatewayInnerEvent::Decryption(decryption_event);
                    self.gw_state
                        .update_event(
                            &gateway_event,
                            GatewayEventState::ResultFromKmsBc(KmsEventState::Decrypt(event_state)),
                        )
                        .await?;

                    self.prepare_decrypt_answer(event, fhe_types).await
                } else {
                    Err(anyhow!("Wrong type of State in catchup decrypt"))
                }
            }
            GatewayEventState::ResultFromKmsBc(kms_event) => {
                if let KmsEventState::Decrypt(decrypt_state) = kms_event {
                    let (event, fhe_types) = (decrypt_state.event, decrypt_state.fhe_types);
                    self.prepare_decrypt_answer(event, fhe_types).await
                } else {
                    Err(anyhow!("Wrong type of State in catchup decrypt"))
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(skip(self, signature, enc_key, ciphertext, eip712_salt))]
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
        asc_address: String,
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
            client_address.to_string(),
            enc_key,
            fhe_type,
            key_id,
            vec![external_ct_handle.clone()],
            vec![ctxt_handle.clone()],
            vec![ctxt_digest.clone()],
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
            .make_req_to_kms_blockchain(asc_address, data_size, operation)
            .await?
            .event;

        tracing::info!("✉️ TxId: {:?}", ev.txn_id().to_hex(),);

        tracing::info!(
            "🍊 Waiting for callback from KMS, txn_id: {:?}",
            ev.txn_id().to_hex()
        );
        let event = self.wait_for_transaction(ev.txn_id()).await?.event;
        if event.operation != KmsOperation::ReencryptResponse {
            return Err(anyhow!(
                "Expected to receive a ReencryptResponse, but received {:?}",
                event
            ));
        }

        tracing::info!("🍊 Received callback from KMS: {:?}", event.txn_id());

        let results: Vec<OperationValue> =
            self.get_operations_values_from_event(event.clone()).await?;

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
    #[tracing::instrument(skip(self, ct_proof, eip712_domain), fields(verifying_contract = eip712_domain.verifying_contract))]
    async fn verify_proven_ct(
        &self,
        client_address: String,
        contract_address: String,
        key_id_str: String,
        crs_id_str: String,
        ct_proof: Vec<u8>,
        eip712_domain: Eip712DomainMsg,
        asc_address: String,
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
            .make_req_to_kms_blockchain(asc_address, data_size, operation)
            .await?
            .event;

        tracing::info!("✉️ TxId: {:?}", ev.txn_id().to_hex(),);

        tracing::info!(
            "🍊 Waiting for callback from KMS, txn_id: {:?}",
            ev.txn_id().to_hex()
        );
        let event = self.wait_for_transaction(ev.txn_id()).await?.event;
        if event.operation != KmsOperation::VerifyProvenCtResponse {
            tracing::error!(
                "Expected to receive a VerifyProvenCtResponse, but received {:?}",
                event
            );
            return Err(anyhow!(
                "Expected to receive a VerifyProvenCtResponse, but received {:?}",
                event
            ));
        }
        tracing::info!("🍊 Received callback from KMS: {:?}", event.txn_id());

        let results: Vec<OperationValue> =
            self.get_operations_values_from_event(event.clone()).await?;

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

    #[tracing::instrument(skip(self))]
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

        // Get the storage base url and remove the trailing slash if it exists
        let storage_base_url = self.get_storage_base_url().await?;
        let storage_base_url = storage_base_url.trim().trim_end_matches(MAIN_SEPARATOR_STR);
        tracing::info!("🔗 Storage base URL: {:?}", storage_base_url);

        // Get the parties
        let parties = self.get_parties().await?;
        tracing::info!("🎉 Parties: {:?}", parties);

        let key_data = KmsBlockchainImpl::parse_signed_key_data(key_values)?;
        let mut fhe_url_info = Vec::new();
        for (key_id, (param, pk_sigs, pk_ext_sigs, server_sigs, server_ext_sigs)) in key_data.iter()
        {
            fhe_url_info.push(KmsBlockchainImpl::prepare_fhe_key_urls(
                storage_base_url,
                &parties,
                key_id,
                param,
                pk_sigs.to_owned(),
                pk_ext_sigs.to_owned(),
                server_sigs.to_owned(),
                server_ext_sigs.to_owned(),
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
        let crs = KmsBlockchainImpl::get_crs_info(storage_base_url, &parties, &crs_data)?;

        let verf_key_info = KmsBlockchainImpl::get_verf_key_info(
            storage_base_url,
            &parties,
            &kms_grpc::rpc_types::SIGNING_KEY_ID.to_string(),
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
        kms::{CrsGenResponseValues, FheParameter, KeyGenResponseValues, KmsCoreParty},
        HexVector, HexVectorList,
    };
    use kms_grpc::kms::v1::FheParameter as RPCFheParameter;
    use kms_grpc::{kms::v1::RequestId, rpc_types::PubDataType};
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
                HexVector::from_hex("1111111111111111111111111111111111111111FF").unwrap(), // pk_ext_sig
                "digest_server_1".to_string(),
                HexVector::from_hex("111111111111111111111111111111111111111111").unwrap(), // server_sig
                HexVector::from_hex("1111111111111111111111111111111111111111EE").unwrap(), // server_ext_sig
                FheParameter::Test,
            ),
            // Server 2 response
            KeyGenResponseValues::new(
                req_id.clone(),
                "digest_pk_2".to_string(),
                HexVector::from_hex("222222222222222222222222222222222222222200").unwrap(), // pk_sig
                HexVector::from_hex("2222222222222222222222222222222222222222FF").unwrap(), // pk_ext_sig
                "digest_server_2".to_string(),
                HexVector::from_hex("222222222222222222222222222222222222222211").unwrap(), // server_sig
                HexVector::from_hex("2222222222222222222222222222222222222222EE").unwrap(), // server_ext_sig
                FheParameter::Test,
            ),
            // Server 1 response to other key
            KeyGenResponseValues::new(
                other_req_id.clone(),
                "digest_pk_1_other".to_string(),
                HexVector::from_hex("abcdef").unwrap(), // pk_ext_sig
                HexVector::from_hex("abcdef").unwrap(), // pk_sig
                "digest_server_1_other".to_string(),
                HexVector::from_hex("abcdef").unwrap(), // server_sig
                HexVector::from_hex("abcdef").unwrap(), // server_ext_sig
                FheParameter::Test,
            ),
        ];
        let res = KmsBlockchainImpl::parse_signed_key_data(key_response_values).unwrap();
        assert_eq!(res.len(), 2);
        let (param, res_pk_sig, res_pk_ext_sig, res_server_sig, res_server_ext_sig) =
            res.get(&req_id.to_hex()).unwrap();
        assert_eq!(param, &FheParameter::Test);
        // Check pk sigs
        assert_eq!(
            res_pk_sig.0,
            vec![
                HexVector::from_hex("111111111111111111111111111111111111111100").unwrap(),
                HexVector::from_hex("222222222222222222222222222222222222222200").unwrap()
            ]
        );
        // Check pk external sigs
        assert_eq!(
            res_pk_ext_sig.0,
            vec![
                HexVector::from_hex("1111111111111111111111111111111111111111FF").unwrap(),
                HexVector::from_hex("2222222222222222222222222222222222222222FF").unwrap()
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
        // Check server sigs
        assert_eq!(
            res_server_ext_sig.0,
            vec![
                HexVector::from_hex("1111111111111111111111111111111111111111EE").unwrap(),
                HexVector::from_hex("2222222222222222222222222222222222222222EE").unwrap()
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
                HexVector::from_hex("F1111111111111111111111111111111111111111F").unwrap(),
                max_bits,
                param,
            ),
            // Server 2 response
            CrsGenResponseValues::new(
                req_id.clone(),
                "digest_crs_2".to_string(),
                HexVector::from_hex("222222222222222222222222222222222222222222").unwrap(),
                HexVector::from_hex("EE222222222222222222222222222222222222222E").unwrap(),
                max_bits,
                param,
            ),
            // Server 1 response to other crs
            CrsGenResponseValues::new(
                other_req_id.clone(),
                "digest_1_other".to_string(),
                HexVector::from_hex("abcdef").unwrap(),
                HexVector::from_hex("ffeedd").unwrap(),
                max_bits,
                param,
            ),
        ];
        let res = KmsBlockchainImpl::parse_signed_crs_data(crs_response_values).unwrap();
        assert_eq!(res.len(), 2);
        let (retrieved_max_bits, retrieved_param, sig, ext_sig) = res.get(&req_id).unwrap();
        assert_eq!(max_bits, *retrieved_max_bits);
        assert_eq!(&param, retrieved_param);
        assert_eq!(
            sig.0,
            vec![
                HexVector::from_hex("111111111111111111111111111111111111111111").unwrap(),
                HexVector::from_hex("222222222222222222222222222222222222222222").unwrap()
            ]
        );
        assert_eq!(
            ext_sig.0,
            vec![
                HexVector::from_hex("F1111111111111111111111111111111111111111F").unwrap(),
                HexVector::from_hex("EE222222222222222222222222222222222222222E").unwrap()
            ]
        );
    }

    fn build_parties(num_parties: usize) -> HashMap<String, KmsCoreParty> {
        let mut parties = HashMap::new();
        for i in 1..=num_parties {
            let signing_key_handle = hex::encode(rand::random::<[u8; 20]>());
            parties.insert(
                signing_key_handle,
                KmsCoreParty::builder()
                    .public_storage_label(format!("PUB-p{}", i))
                    .build(),
            );
        }
        parties
    }
    #[test]
    fn sunshine_fhe_key_info() {
        let key_id = "00112233445566778899aabbccddeeff0011223344";
        let base_sig = HexVector::from_hex(key_id).unwrap();
        let base_ext_sig =
            HexVector::from_hex("ffee2233445566778899aabbccddeeff001122DDEF").unwrap();
        let sigs = HexVectorList(vec![base_sig.clone(); 4]);
        let ext_sigs = HexVectorList(vec![base_ext_sig.clone(); 4]);
        let storage_base_url = "http://127.0.0.1:8081/";
        let parties = build_parties(4);

        let fhe_server_key = KmsBlockchainImpl::get_fhe_key_info(
            PubDataType::ServerKey,
            storage_base_url,
            &parties,
            key_id,
            &FheParameter::Test,
            sigs,
            ext_sigs,
        )
        .unwrap();
        assert_eq!(fhe_server_key.data_id().to_hex(), key_id);
        assert_eq!(
            fhe_server_key.fhe_parameter(),
            <FheParameter as Into<i32>>::into(FheParameter::Test),
        );
        assert_eq!(fhe_server_key.urls().len(), 4);
        assert!(fhe_server_key.urls().contains(&format!(
            "{}/{}/{}",
            storage_base_url, "PUB-p1/ServerKey", key_id
        )));
        assert!(fhe_server_key.urls().contains(&format!(
            "{}/{}/{}",
            storage_base_url, "PUB-p2/ServerKey", key_id
        )));
        assert!(fhe_server_key.urls().contains(&format!(
            "{}/{}/{}",
            storage_base_url, "PUB-p3/ServerKey", key_id
        )));
        assert!(fhe_server_key.urls().contains(&format!(
            "{}/{}/{}",
            storage_base_url, "PUB-p4/ServerKey", key_id
        )));
    }

    #[test]
    fn sunshine_verf_key_info() {
        let key_id = "00112233445566778899aabbccddeeff0011223344";
        let storage_base_url = "http://127.0.0.1:8081/";
        let parties = build_parties(4);

        let verf_key_info =
            KmsBlockchainImpl::get_verf_key_info(storage_base_url, &parties, key_id).unwrap();

        assert_eq!(verf_key_info.len(), parties.len());

        for cur_info in verf_key_info {
            assert_eq!(cur_info.key_id().to_hex(), key_id);

            // Check that the URLs follow the expected structure
            let verf_address_url = cur_info.verf_public_key_address();
            assert!(verf_address_url.starts_with(&format!("{}/PUB-p", storage_base_url)));
            assert!(verf_address_url.ends_with(&format!("/VerfAddress/{}", key_id)));

            let verf_key_url = cur_info.verf_public_key_url();
            assert!(verf_key_url.starts_with(&format!("{}/PUB-p", storage_base_url)));
            assert!(verf_key_url.ends_with(&format!("/VerfKey/{}", key_id)));
        }
    }

    #[test]
    fn sunshine_crs_info() {
        let crs_id_1 = "00112233445566778899aabbccddeeff0011223344";
        let crs_id_2 = "9988776655443322110099887766554433221100aa";
        let storage_base_url = "http://127.0.0.1:8081/";
        let parties = build_parties(4);
        let base_sig = HexVector::from_hex(crs_id_1).unwrap();
        let sigs = HexVectorList(vec![base_sig.clone(); 4]);

        let base_ext_sig =
            HexVector::from_hex("FFFF2233445566778899aabbccddeeff0011220000").unwrap();
        let ext_sigs = HexVectorList(vec![base_ext_sig.clone(); 4]);
        let crs_ids: HashMap<String, (u32, FheParameter, HexVectorList, HexVectorList)> =
            HashMap::from([
                (
                    crs_id_1.to_string(),
                    (128, FheParameter::Test, sigs.clone(), ext_sigs.clone()),
                ),
                (
                    crs_id_2.to_string(),
                    (256, FheParameter::Default, sigs.clone(), ext_sigs.clone()),
                ),
            ]);
        let crs_info =
            KmsBlockchainImpl::get_crs_info(storage_base_url, &parties, &crs_ids).unwrap();
        assert_eq!(crs_info.len(), crs_ids.len());
        for (max_bits, cur_info) in &crs_info {
            assert_eq!(parties.len(), cur_info.signatures().len());
            if *max_bits == 128 {
                assert_eq!(
                    <RPCFheParameter as Into<i32>>::into(RPCFheParameter::Test),
                    cur_info.fhe_parameter()
                );
            } else {
                assert_eq!(
                    <RPCFheParameter as Into<i32>>::into(RPCFheParameter::Default),
                    cur_info.fhe_parameter()
                );
            }
            assert!(cur_info.signatures().contains(&base_sig.clone()));
        }

        // Check that the URLs follow the expected structure
        for party in parties.values() {
            assert!(crs_info[&128].urls().contains(
                &format!(
                    "{}/{}/CRS/{}",
                    storage_base_url, party.public_storage_label, crs_id_1
                )
                .to_string()
            ));
            assert!(crs_info[&256].urls().contains(
                &format!(
                    "{}/{}/CRS/{}",
                    storage_base_url, party.public_storage_label, crs_id_2
                )
                .to_string()
            ));
        }
    }
}

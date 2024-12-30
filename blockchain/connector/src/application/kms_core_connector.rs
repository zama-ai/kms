use super::Connector;
use crate::config::{ConnectorConfig, ShardingConfig};
use crate::domain::blockchain::{Blockchain, KmsOperationResponse};
use crate::domain::kms::{CatchupResult, Kms};
use crate::infrastructure::blockchain::KmsBlockchain;
use crate::infrastructure::core::KmsCore;
use crate::infrastructure::metrics::{MetricType, Metrics, OpenTelemetryMetrics};
use crate::infrastructure::store::KVStore;
use anyhow::{anyhow, Result};
use cosmos_proto::messages::cosmwasm::wasm::v1::MsgExecuteContract;
use events::kms::{
    FheParameter, KmsEvent, KmsMessage, OperationValue, TransactionEvent, TransactionId,
};
use events::subscription::handler::{EventsMode, SubscriptionEventBuilder, SubscriptionHandler};
use events::subscription::Tx;
use kms_blockchain_client::crypto::pubkey::PublicKey;
use kms_blockchain_client::errors::Error;
use prost_types::Any;
use std::sync::Arc;
use tracing::Instrument;
use typed_builder::TypedBuilder;

#[derive(Clone, TypedBuilder)]
pub struct KmsCoreEventHandler<B, K, O> {
    blockchain: Arc<B>,
    kms: K,
    observability: Arc<O>,
    my_pk: PublicKey,
    sharding: ShardingConfig,
}

///__NOTE__: We have to enforce partial synchronicity here as
/// we __need__ the request from Core to Connector to arrive
/// __in the same order__ for all the cores in order to assis with rate-limiting.
/// https://github.com/zama-ai/kms-core/issues/1466
///
/// We thus need to be sync up until the request is sent
/// but can afford to wait for the answer and send back the
/// result to the KMS BC in an async manner.
impl<B, K, O> KmsCoreEventHandler<B, K, O>
where
    B: Blockchain + Send + Sync + 'static,
    K: Kms + Send + Sync + Clone + 'static,
    O: Metrics + Send + Sync + 'static,
{
    /// Query the KMS BC for the operation that corresponds to the given event
    async fn get_op_and_fhe_parameter(
        &self,
        event: &KmsEvent,
    ) -> Result<
        (OperationValue, Option<FheParameter>),
        Box<dyn std::error::Error + Send + Sync + 'static>,
    > {
        let operation_value = self
            .blockchain
            .get_operation_value(event)
            .await
            .inspect_err(|e| {
                self.observability
                    .increment(MetricType::TxError, 1, &[("error", &e.to_string())]);
            })?;

        // If necessary retrieve the configuration of the KMS from the contract
        // It seems to be used by some [`KmsEventHandler`] impl to retrieve
        // the [`FheParameter`]
        tracing::info!("Running KMS operation with value: {:?}", operation_value);

        // If this is a gen operation (key/crs generation), we need to get the param choice from the CSC
        let fhe_parameter = if operation_value.is_gen() {
            let fhe_parameter = self.blockchain.get_fhe_parameter().await?;
            tracing::info!(
                "Successfully retrieved param choice `{:?}` for operation `{:?}`",
                fhe_parameter,
                operation_value
            );
            Some(fhe_parameter)
        } else {
            tracing::info!(
                "No param choice needed for operation `{:?}`",
                operation_value
            );
            None
        };

        Ok((operation_value, fhe_parameter))
    }

    /// Answer back to the KMS BC by making a transaction containing the [`KmsOperationResponse`]
    async fn answer_back_to_kms_bc(
        result: KmsOperationResponse,
        blockchain: Arc<B>,
        observability: Arc<O>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        tracing::info!("Sending response to the blockchain: {}", result.to_string());
        let tx_id = result.txn_id_hex();
        blockchain.send_result(result).await.inspect_err(|e| {
            tracing::error!(
                "KMS connector error sending the response to the blockchain: {:?}",
                e
            );
            observability.increment(MetricType::TxError, 1, &[("error", &e.to_string())]);
        })?;
        observability.increment(MetricType::TxProcessed, 1, &[("tx_id", tx_id.as_str())]);
        tracing::info!("Result sent to blockchain");
        Ok(())
    }

    async fn dispatch_catchup_result(
        &self,
        catchup_result: CatchupResult,
        wanted_tx_id: TransactionId,
        message: TransactionEvent,
        past_events_responses: &[TransactionEvent],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let blockchain = Arc::clone(&self.blockchain);
        let observability = Arc::clone(&self.observability);
        match catchup_result {
            // The response was present in Core, we simply send it back to the KMS BC
            CatchupResult::Now(kms_operation_response) => {
                let result = kms_operation_response?;
                tokio::spawn(async move {
                    match Self::answer_back_to_kms_bc(result, blockchain, observability).await
                    {
                    Err(e) => tracing::error!(
                                "KMS connector error running catchup on event id {:?} trying to answer back to BC: {:?}",
                                wanted_tx_id,
                                e
                            ),
                    Ok(()) => tracing::info!(
                            "Successfully caught up on event {:?} with id {:?}. Core had the answer ready.",
                            message.event.operation.to_string(),
                            wanted_tx_id
                        ),
                    }
                }.instrument(tracing::Span::current()));
            }
            // The request existed in Core, but not yet available.
            // We will wait on the channel for the answer and send it back to the KMS BC.
            CatchupResult::Later(receiver) => {
                tokio::spawn(async move {
                    match receiver.await {
                        Ok(result) => match result {
                            Ok(result) => {
                                if let Err(e) =
                                    Self::answer_back_to_kms_bc(result, blockchain, observability)
                                        .await
                                {
                                    tracing::error!(
                                    "KMS connector error running catchup on event id {:?} trying to answer back to BC: {:?}",
                                    wanted_tx_id,
                                    e
                                );
                                } else {
                                    tracing::info!(
                                        "Successfully caught up on event {:?} with id {:?}.",
                                        message.event.operation.to_string(),
                                        wanted_tx_id
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::error!(
                                "KMS connector error running catchup on event id {:?} for kms operation: {:?}",
                                wanted_tx_id,
                                e
                            );
                            }
                        },
                        Err(e) => {
                            tracing::error!(
                            "KMS connector error running catchup on event id {:?} for kms operation: {:?}",
                            wanted_tx_id,
                            e
                        );
                        }
                    }
                }.instrument(tracing::Span::current()));
            }
            // The Core had never heard of the request.
            // If no response event exists, we treat it as we would for a new TransactionEvent
            CatchupResult::NotFound => {
                tracing::info!(
                    "Core had never heard of event {:?} with id {:?}. Will relaunch a new request if no response event exists.",
                    message.event.operation.to_string(),
                    wanted_tx_id
                );
                // The request has never been started on KMS Core
                // If the response event doesn't exist, treat it as a regular message
                let response_event_exists = past_events_responses
                    .iter()
                    .any(|event| event.event.txn_id() == &wanted_tx_id);
                if !response_event_exists {
                    self.on_message(message).await?;
                }
            }
        };
        Ok(())
    }
}

#[async_trait::async_trait]
impl<B, K, O> SubscriptionHandler<KmsMessage> for KmsCoreEventHandler<B, K, O>
where
    B: Blockchain + Send + Sync + 'static,
    K: Kms + Send + Sync + Clone + 'static,
    O: Metrics + Send + Sync + 'static,
{
    /// Treats messages on behalf of the blockchain subscriber
    /// i.e. interacts with the core and sends back response to KMS blockchain
    #[tracing::instrument(level = "info", skip(self))]
    async fn on_message(
        &self,
        message: TransactionEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        tracing::info!("Received message: {:?}", message);

        // answer this message only if this conector is in the right shard
        let target_shard = message.event.txn_id().to_u64() % self.sharding.total;
        if target_shard != self.sharding.index {
            tracing::info!("Message is for another shard ({target_shard}). I am in shard {} and will ignore it.", self.sharding.index);
        } else {
            let (operation_value, fhe_parameter) =
                self.get_op_and_fhe_parameter(&message.event).await?;

            // Interact with the KMS to resolve the query
            let result_receiver = self
                .kms
                .run(message.event, operation_value, fhe_parameter)
                .await
                .inspect_err(|e| {
                    tracing::error!("KMS connector error running kms operation: {:?}", e);
                    self.observability.increment(
                        MetricType::TxError,
                        1,
                        &[("error", &e.to_string())],
                    );
                })?;
            let blockchain = Arc::clone(&self.blockchain);
            let observability = Arc::clone(&self.observability);
            tokio::spawn(
                async move {
                    if let Ok(result) = result_receiver.await {
                        match result {
                            Ok(result) => {
                                if let Err(e) =
                                    Self::answer_back_to_kms_bc(result, blockchain, observability)
                                        .await
                                {
                                    tracing::error!(
                                        "KMS connector error trying to answer back to BC: {:?}",
                                        e
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::error!(
                                    "KMS connector error running kms operation: {:?}",
                                    e
                                );
                            }
                        }
                    } else {
                        tracing::error!(
                            "KMS connector error running kms operation, sender dropped"
                        );
                    }
                }
                .instrument(tracing::Span::current()),
            );
        }
        Ok(())
    }

    /// Performs catchup on the given `message``.
    ///
    /// During catchup phase, we first check whether we've
    /// already sent an answer for the corresponding event by looking through the given `past_txs``.
    ///
    /// If we haven't already answered, we interact with the Core.
    /// If the request is absent from the Core, and absent from [`past_events_responses`] we act as [`Self::on_message`].
    #[tracing::instrument(level = "info", skip(self))]
    async fn on_catchup(
        &self,
        message: TransactionEvent,
        past_txs: &mut Vec<KmsMessage>,
        past_events_responses: &mut Vec<TransactionEvent>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        // Thanks to the [`Self::filter_for_catchup`] we only have KmsMessage which match our
        // pk here (i.e messages we have sent)
        let wanted_tx_id = message.event.txn_id.clone();

        // answer this message only if this conector is in the right shard
        let target_shard = wanted_tx_id.to_u64() % self.sharding.total;
        if target_shard != self.sharding.index {
            tracing::info!("Catchup message is for another shard ({target_shard}). I am in shard {} and will ignore it.", self.sharding.index);
            Ok(())
        } else {
            tracing::info!(
                "Catching up on event {:?} with id {:?}",
                message.event.operation.to_string(),
                wanted_tx_id,
            );

            // Look over all the past responses for one with the wanted tx id
            // if it exists, we do not need to do anything else
            if has_response_with_wanted_id(past_txs, &wanted_tx_id) {
                tracing::info!(
                    "Successfully caught up on event {:?} with id {:?}. BC already has my answer.",
                    message.event.operation.to_string(),
                    wanted_tx_id
                );
                return Ok(());
            }

            let (operation_value, fhe_parameter) =
                self.get_op_and_fhe_parameter(&message.event).await?;
            // Then first try polling the KMS for existing requests
            let catchup_result = self
                .kms
                .run_catchup(
                    message.event.clone(),
                    operation_value.clone(),
                    fhe_parameter,
                )
                .await
                .inspect_err(|e| {
                    tracing::error!("KMS connector error running kms operation: {:?}", e);
                    self.observability.increment(
                        MetricType::TxError,
                        1,
                        &[("error", &e.to_string())],
                    );
                })?;

            self.dispatch_catchup_result(
                catchup_result,
                wanted_tx_id,
                message,
                past_events_responses,
            )
            .await
        }
    }

    /// Keep only the transactions that contain my signature
    /// and when it does, try and transform them into
    /// the corresponding [`KmsMessage`]
    fn filter_for_catchup(&self, tx: Tx) -> Option<KmsMessage> {
        if check_tx_pk_in_signers(&tx, &self.my_pk) {
            try_extract_kms_message_from_tx(&tx)
        } else {
            None
        }
    }
}

/// Try to extract a potential [`KmsMessage`] from the
/// given transaction
fn try_extract_kms_message_from_tx(tx: &Tx) -> Option<KmsMessage> {
    if let Some(body) = &tx.body {
        if let Some(message) = body.messages.first() {
            if let Ok(message) = Any::to_msg::<MsgExecuteContract>(message) {
                if let Ok(payload) = std::str::from_utf8(&message.msg) {
                    if let Ok(result) = KmsMessage::from_json(payload) {
                        return Some(result);
                    }
                }
            }
        }
    }
    None
}

/// Checks that the given transaction contains the given public key
/// in its [`cosmos_proto::messages::cosmos::tx::v1beta1::SignerInfo`] list
fn check_tx_pk_in_signers(tx: &Tx, pk: &PublicKey) -> bool {
    if let Some(auth_info) = &tx.auth_info {
        for signer_info in auth_info.signer_infos.iter() {
            if let Some(tx_pk) = &signer_info.public_key {
                let tx_pk: Result<PublicKey, Error> = tx_pk.try_into();
                if let Ok(tx_pk) = tx_pk {
                    return &tx_pk == pk;
                }
            }
        }
        false
    } else {
        false
    }
}

fn has_response_with_wanted_id(messages: &[KmsMessage], wanted_id: &TransactionId) -> bool {
    messages.iter().any(|tx| {
        if !tx.value().is_response() {
            return false;
        }
        if let Some(tx_id) = tx.txn_id() {
            if tx_id == wanted_id {
                tracing::info!("My answer was {:?}", tx);
                true
            } else {
                false
            }
        } else {
            false
        }
    })
}

/// The struct actually reflecting the Connector between the KMS Blockchain and the KMS Core.
/// (i.e. the relay between KMS BC and Core)
#[derive(Clone, TypedBuilder)]
pub struct KmsCoreConnector<B, K, O> {
    kms_connector_handler: KmsCoreEventHandler<B, K, O>,
    config: ConnectorConfig,
}

impl<B, K, O> KmsCoreConnector<B, K, O>
where
    B: Blockchain + Clone + 'static + Send + Sync,
    K: Kms + Clone + 'static + Send + Sync,
    O: Metrics + Clone + 'static + Send + Sync,
{
    pub async fn new(
        blockchain: B,
        kms: K,
        metrics: O,
        sharding: ShardingConfig,
    ) -> anyhow::Result<Self> {
        let my_pk = blockchain.get_public_key().await;
        let handler = KmsCoreEventHandler {
            blockchain: Arc::new(blockchain),
            kms,
            observability: Arc::new(metrics),
            my_pk,
            sharding,
        };
        Ok(Self {
            kms_connector_handler: handler,
            config: ConnectorConfig::default(),
        })
    }
}

impl KmsCoreConnector<KmsBlockchain, KmsCore<KVStore>, OpenTelemetryMetrics> {
    pub async fn new_with_config(config: ConnectorConfig) -> anyhow::Result<Self> {
        let metrics = OpenTelemetryMetrics::new();
        let blockchain = KmsBlockchain::new(config.blockchain.clone(), metrics.clone()).await?;
        let storage = KVStore::new(config.store.clone());
        // TODO the core should read the addresses from the blockchain
        // instead of the config
        let kms = KmsCore::new(config.core.clone(), storage, metrics.clone())?;
        let my_pk = blockchain.get_public_key().await;

        let sharding = match config.sharding.clone() {
            Some(s) => {
                if s.index >= s.total {
                    return Err(anyhow!(
                        "Shard index ({}) is bigger than total number of shards ({}). Must be in [0 ... {}]",
                        s.index,
                        s.total,
                        s.total - 1
                    ));
                }
                s
            }
            None => ShardingConfig::default(),
        };

        let handler = KmsCoreEventHandler {
            blockchain: Arc::new(blockchain),
            kms,
            observability: Arc::new(metrics),
            my_pk,
            sharding,
        };
        Ok(Self {
            kms_connector_handler: handler,
            config,
        })
    }
}

#[async_trait::async_trait]
impl<B, K, O> Connector for KmsCoreConnector<B, K, O>
where
    B: Blockchain + Send + Sync + Clone + 'static,
    K: Kms + Send + Sync + Clone + 'static,
    O: Metrics + Send + Sync + Clone + 'static,
{
    async fn listen_for_events(self, catch_up_num_blocks: Option<usize>) -> anyhow::Result<()> {
        let grpc_addresses = self.config.blockchain.grpc_addresses();

        let subscription = SubscriptionEventBuilder::builder()
            .contract_address(&self.config.blockchain.asc_address)
            .tick_time_in_sec(self.config.tick_interval_secs)
            .grpc_addresses(&grpc_addresses)
            .storage_path(&self.config.storage_path)
            .filter_events_mode(EventsMode::Request)
            .build()
            .subscription()
            .await?;

        tracing::info!(
            "Starting subscription to events from blockchain with {:?}",
            grpc_addresses
        );
        subscription
            .subscribe(self.kms_connector_handler.clone(), catch_up_num_blocks)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to subscribe: {:?}", e))
    }
}

use super::metrics::{Metrics, OpenTelemetryMetrics};
use super::{BlockchainService, GrpcBlockchainService};
use crate::kms::{KmsEvent, KmsOperation, TransactionEvent};
use async_trait::async_trait;
use cosmos_proto::messages::cosmos::{base::abci::v1beta1::TxResponse, tx::v1beta1::Tx};

use cosmwasm_std::Event;
use kms_common::{retry::LoopErr, retry_fatal_loop};
#[cfg(test)]
use mockall::{automock, mock, predicate::*};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use strum::IntoEnumIterator as _;
use strum_macros::EnumString;
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use typed_builder::TypedBuilder;

#[derive(Debug, Error)]
pub enum SubscriptionError {
    #[error("Error connecting to Event Server Subscription - {0}")]
    ConnectionError(String),
    #[error("Error calling GetTxsEvent message to Event Server - {0}")]
    ResponseTxsEventError(#[from] tonic::Status),
    #[error("Error receiving message from Event Server Subscription - {0}")]
    UnknownError(#[from] anyhow::Error),
    #[error("Error deserializing message from Event Server Subscription - {0}")]
    DeserializationError(String),
}

#[derive(Debug, Clone, Copy, EnumString, PartialEq, Eq, Deserialize, Serialize)]
pub enum EventsMode {
    /// Filter only events that are requests
    #[strum(serialize = "request")]
    Request,
    /// Filter only events that are responses
    #[strum(serialize = "response")]
    Response,
}

/// Subscription entry point for building a Subscription Service
/// The builder pattern is used to create a Subscription Service
#[derive(TypedBuilder)]
pub struct SubscriptionEventBuilder<'a> {
    grpc_addresses: &'a [&'a str],
    contract_address: &'a str,
    #[builder(default = 5)]
    tick_time_in_sec: u64,
    #[builder(default, setter(into))]
    filter_events_mode: Option<EventsMode>,
}

pub struct SubscriptionEventChannel<B, M>
where
    B: BlockchainService + Clone + 'static,
    M: Metrics + 'static,
{
    pub(crate) tick_time_in_sec: u64,
    pub(crate) blockchain: B,
    pub(crate) latest_height: Arc<Mutex<u64>>,
    pub(crate) metrics: M,
}

impl SubscriptionEventBuilder<'_> {
    pub async fn subscription(
        self,
    ) -> Result<
        SubscriptionEventChannel<Arc<GrpcBlockchainService>, OpenTelemetryMetrics>,
        SubscriptionError,
    > {
        let blockchain = GrpcBlockchainService::new(
            self.grpc_addresses,
            self.contract_address,
            self.filter_events_mode,
        )?;
        let metrics = OpenTelemetryMetrics::new();
        Ok(SubscriptionEventChannel {
            tick_time_in_sec: self.tick_time_in_sec,
            blockchain: Arc::new(blockchain),
            latest_height: Arc::new(Mutex::new(0)),
            metrics,
        })
    }
}

/// Subscription Handler Trait
///
/// This trait is used to define the behavior of the Subscription handler
/// The handler will be called when a message is received from the Event Server
#[cfg_attr(test, automock)]
#[async_trait]
pub trait SubscriptionHandler<T: 'static + Send + Sync> {
    /// Dictates what the handler does on receiving a message
    async fn on_message(
        &self,
        message: TransactionEvent,
        height_of_event: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>;

    /// Dictates what the handler does to catch up on passed messages
    async fn on_catchup(
        &self,
        message: TransactionEvent,
        height_of_event: u64,
        past_txs: &mut Vec<T>,
        past_events_responses: &mut Vec<TransactionEvent>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>;

    fn filter_for_catchup(&self, tx: Tx) -> Option<T>;
}

/// Enum to sepcify from when do we catchup
pub enum CatchupFrom {
    /// From this many blocks in the past starting from current block
    NumBlocksInPast(usize),
    /// From this specific block number
    BlockNumber(usize),
}

impl<B, M> SubscriptionEventChannel<B, M>
where
    B: BlockchainService + Clone + 'static,
    M: Metrics + 'static,
{
    /// Subscribe to the Event server
    /// The handler will be called when a message is received from the Event server
    ///
    /// # Arguments
    /// * `handler` - The handler that will be called when a message is received from the Event Server
    /// * `U` - The handler that will be called when a message is received from the Event server
    ///
    /// # Returns
    /// * `Result<(), SubscriptionError>` - The result of the Subscription
    /// * `SubscriptionError` - The error that occurred during the Subscription
    pub async fn subscribe<U, T>(
        self,
        handler: U,
        catchup_num_blocks: Option<CatchupFrom>,
    ) -> Result<(), SubscriptionError>
    where
        U: SubscriptionHandler<T> + Clone + Send + Sync + 'static,
        T: 'static + Send + Sync,
    {
        // Init once the block height
        let bc_height = self.blockchain.get_last_height().await?;
        let starting_height = if let Some(catchup_info) = catchup_num_blocks {
            match catchup_info {
                CatchupFrom::NumBlocksInPast(num) => {
                    if (num as u64) < bc_height {
                        bc_height - (num as u64)
                    } else {
                        1
                    }
                }
                CatchupFrom::BlockNumber(num) => num as u64,
            }
        } else {
            bc_height
        };
        self.update_last_seen_height(starting_height).await;
        tracing::info!("Starting polling Blockchain on block {starting_height}");
        let mut last_height = starting_height;
        let clonable_self = Arc::new(self);
        loop {
            //We don't sleep when catching up
            if last_height >= bc_height {
                tracing::trace!(
                    "Waiting {} secs for next tick before getting events",
                    clonable_self.tick_time_in_sec
                );
                sleep(Duration::from_secs(clonable_self.tick_time_in_sec)).await;
            }
            let cloned_handler = handler.clone();
            let cloned_self = Arc::clone(&clonable_self);
            // Spawn a task here, so in the event of a panic we catch it as a JoinError
            // but keep going
            let handler_handle = tokio::spawn(async move {
                cloned_self
                    .handle_events(cloned_handler, bc_height)
                    .await
                    .unwrap_or_else(|e| {
                        tracing::error!("Error handling events: {:?}", e);
                        last_height
                    })
            });
            last_height = match handler_handle.await {
                Ok(height) => height,
                Err(e) => {
                    tracing::error!("Error handling events: {:?}", e);
                    last_height
                }
            };
        }
    }

    /// Queries the KMS BC during catchup
    /// - `height` is the current minimum height we are looking for events
    /// - `catchup_until_height` is the maximum height until we want to use the catchup mechanism
    ///
    /// Returns
    /// - `Vec<TxResponse>` : The list of transactions we look for events to handle
    /// - `Option<(Vec<T>, Vec<TransactionEvent>)>` : Which is `Some` in the catchup case and contains respectively the past transactions (filtered with [`Self::get_all_tx_from_to_height_filter_map`]) and the past response events.
    pub async fn query_bc_during_catchup<T, U>(
        &self,
        height: u64,
        catchup_until_height: u64,
        handler: U,
    ) -> Result<(Vec<TxResponse>, Option<(Vec<T>, Vec<TransactionEvent>)>), SubscriptionError>
    where
        U: SubscriptionHandler<T> + Clone + Send + Sync + 'static,
        T: 'static + Send + Sync,
    {
        // Query for all txs emitted by the KMS BC
        let past_tx = tokio::spawn(Self::get_all_tx_from_to_height_filter_map(
            self.blockchain.clone(),
            height,
            catchup_until_height,
            handler,
        ));

        // Query for past response events
        let past_responses_events = tokio::spawn(Self::get_txs_events_responses(
            self.blockchain.clone(),
            height,
        ));

        // Query for all events emitted by the KMS BC with block height > height
        let txs_events_handler =
            tokio::spawn(Self::get_txs_events(self.blockchain.clone(), height));

        let results = tokio::join!(txs_events_handler, past_tx, past_responses_events);

        let tx_result = results
            .0
            .map_err(|e| SubscriptionError::UnknownError(e.into()))?
            .inspect_err(|e| {
                self.metrics
                    .increment_connection_errors(1, &[("error", &e.to_string())]);
            })?;
        let past_tx = results
            .1
            .map_err(|e| SubscriptionError::UnknownError(e.into()))?
            .inspect_err(|e| {
                self.metrics
                    .increment_connection_errors(1, &[("error", &e.to_string())]);
            })?;
        let past_responses_events = results
            .2
            .map_err(|e| SubscriptionError::UnknownError(e.into()))?
            .inspect_err(|e| {
                self.metrics
                    .increment_connection_errors(1, &[("error", &e.to_string())]);
            })?
            .iter()
            .map(|tx| {
                Self::try_from(tx)
                    .map_err(|e| SubscriptionError::DeserializationError(e.to_string()))
            })
            .collect::<Result<Vec<Vec<TransactionEvent>>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<TransactionEvent>>();

        Ok((tx_result, Some((past_tx, past_responses_events))))
    }

    async fn get_last_height(&self) -> u64 {
        let guarded_storage = self.latest_height.lock().await;
        *guarded_storage
    }

    /// Handle one round of events received from the Event Server.
    ///
    /// Uses the catchup mechanism of the `handler` until we reach the
    /// heigh `catchup_until_height`.
    pub async fn handle_events<U, T>(
        &self,
        handler: U,
        catchup_until_height: u64,
    ) -> Result<u64, SubscriptionError>
    where
        U: SubscriptionHandler<T> + Clone + Send + Sync + 'static,
        T: 'static + Send + Sync,
    {
        let enter = tracing::span!(
            tracing::Level::TRACE,
            "subscribe",
            "Loop Getting Event from Blockchain"
        );
        let _guard = enter.enter();
        let height = self.get_last_height().await;
        let handler = handler.clone();

        // Query the blockchain
        let (results, mut past_txs_and_responses) = if height < catchup_until_height {
            self.query_bc_during_catchup(height, catchup_until_height, handler.clone())
                .await?
        } else {
            // Query for all events emitted by the KMS BC with block height > height
            // this wil internally filter on request or answer depending on how the internal BlockchainService
            // was instantiated
            let results = Self::get_txs_events(self.blockchain.clone(), height)
                .await
                .inspect_err(|e| {
                    self.metrics
                        .increment_connection_errors(1, &[("error", &e.to_string())]);
                })?;
            (results, None)
        };
        tracing::debug!("Getting events from Blockchain from height {:?}", height);

        // Last seen height is the height of the most recent tx,
        // if no tx, the last height remains the same
        let last_height = results
            .iter()
            .map(|tx| tx.height as u64)
            .max()
            .unwrap_or(height);

        // Transform the TxResponses into TransactionEvents
        let events_with_height = results
            .iter()
            .map(|tx| {
                let event = Self::try_from(tx);
                match event {
                    Ok(event) => Ok((event, tx.height as u64)),
                    Err(e) => Err(SubscriptionError::DeserializationError(e.to_string())),
                }
            })
            .collect::<Result<Vec<(Vec<TransactionEvent>, u64)>, _>>()?
            .into_iter()
            .flat_map(|(event, height)| event.into_iter().map(move |event| (event, height)))
            .collect::<Vec<(TransactionEvent, u64)>>();

        let results_size = events_with_height.len();
        tracing::debug!(
            "Sending {} events to be processed to handler.",
            results_size
        );

        // For each Transaction event, let the handler deal with it
        // (NOTE: we leave it to the handler to decide whether it wants
        // to return async or sync as GW and Connector may have different behavior here)
        // Note: here the handler is either:
        // - the GatewayEventHandler if this is ran by the GW
        //  (which basically forwards stuff to KmsEventPublisher)
        // - the KmsCoreEventHandler if this is ran by the connector
        for (event, height_of_event) in events_with_height {
            let result = if height_of_event < catchup_until_height {
                tracing::debug!(
                    "Catching up on event: {:?} at height {}",
                    event,
                    height_of_event
                );
                if let Some((past_txs, past_events_responses)) = &mut past_txs_and_responses {
                    handler
                        .on_catchup(event, height_of_event, past_txs, past_events_responses)
                        .await
                } else {
                    tracing::error!(
                        "Unable to catch up {:?} due to unexpectedly missing past_txs_and_response",
                        event
                    );
                    // Continue anyway as we might be able to handle some other events
                    // that are not part of the catchup mechanism
                    continue;
                }
            } else {
                tracing::debug!(
                    "Processing event: {:?} at height {}",
                    event,
                    height_of_event
                );
                handler.on_message(event, height_of_event).await
            };
            if let Err(e) = &result {
                tracing::error!("Error processing message: {:?}", e);
            }
        }

        self.metrics
            .increment_tx_processed(results_size as u64, &[]);
        // We will now look for new tx not older than last_height
        self.update_last_seen_height(last_height).await;
        Ok(last_height)
    }

    async fn get_txs_events(
        blockchain: B,
        height: u64,
    ) -> Result<Vec<TxResponse>, SubscriptionError> {
        // Retry at most 4 times, waiting 10 seconds between each retry, but terminate in case of a non-transient error
        retry_fatal_loop!(
            || async {
                match blockchain.get_events(height).await {
                    Ok(resp) => Ok(resp),
                    Err(error) => match error {
                        SubscriptionError::ConnectionError(_) => Err(LoopErr::Transient(error)),
                        SubscriptionError::ResponseTxsEventError(_) => {
                            Err(LoopErr::Transient(error))
                        }
                        SubscriptionError::UnknownError(_) => Err(LoopErr::Fatal(error)),
                        SubscriptionError::DeserializationError(_) => Err(LoopErr::Fatal(error)),
                    },
                }
            },
            10000,
            4
        )
        // Return the inner error from `get_events_responses`
        .map_err(|error| match error {
            LoopErr::Termination(inner_error) => {
                // In case of termination, we instead return an unknown error

                SubscriptionError::UnknownError(inner_error)
            }
            LoopErr::Fatal(inner_error) => inner_error,
            LoopErr::Transient(inner_error) => inner_error,
        })
    }

    async fn get_txs_events_responses(
        blockchain: B,
        height: u64,
    ) -> Result<Vec<TxResponse>, SubscriptionError> {
        // Retry at most 4 times, waiting 10 seconds between each retry
        retry_fatal_loop!(
            || async {
                match blockchain.get_events_responses(height).await {
                    Ok(resp) => Ok(resp),
                    Err(error) => match error {
                        SubscriptionError::ConnectionError(_) => Err(LoopErr::Transient(error)),
                        SubscriptionError::ResponseTxsEventError(_) => {
                            Err(LoopErr::Transient(error))
                        }
                        SubscriptionError::UnknownError(_) => Err(LoopErr::Fatal(error)),
                        SubscriptionError::DeserializationError(_) => Err(LoopErr::Fatal(error)),
                    },
                }
            },
            10000,
            4
        )
        // Return the inner error from `get_events_responses`
        .map_err(|e| match e {
            LoopErr::Termination(error) => {
                // In case of termination, we instead return an unknown error
                tracing::error!(
                    "Loop iterations complete, but still receiving a transient error: {}",
                    error
                );
                SubscriptionError::UnknownError(error)
            }
            LoopErr::Fatal(error) => error,
            LoopErr::Transient(error) => error,
        })
    }

    async fn get_all_tx_from_to_height_filter_map<U, T>(
        blockchain: B,
        from_height: u64,
        to_height: u64,
        handler: U,
    ) -> Result<Vec<T>, SubscriptionError>
    where
        T: 'static + Send + Sync,
        U: SubscriptionHandler<T> + Clone + Send + Sync + 'static,
    {
        // Retry at most 4 times, waiting 10 seconds between each retry, but terminate in case of a non-transient error
        retry_fatal_loop!(
            || async {
                let handler = handler.clone();
                match blockchain
                    .get_all_tx_from_to_height_filter_map(from_height, to_height, move |tx| {
                        handler.filter_for_catchup(tx)
                    })
                    .await
                {
                    Ok(resp) => Ok(resp),
                    Err(error) => match error {
                        SubscriptionError::ConnectionError(_) => Err(LoopErr::Transient(error)),
                        SubscriptionError::ResponseTxsEventError(_) => {
                            Err(LoopErr::Transient(error))
                        }
                        SubscriptionError::UnknownError(_) => Err(LoopErr::Fatal(error)),
                        SubscriptionError::DeserializationError(_) => Err(LoopErr::Fatal(error)),
                    },
                }
            },
            10000,
            4
        )
        // Return the inner error from `get_all_tx_from_to_height_filter_map`
        .map_err(|error| match error {
            LoopErr::Termination(inner_error) => {
                // In case of termination, we instead return an unknown error
                tracing::error!(
                    "Loop iterations complete, but still receiving a transient error: {}",
                    inner_error
                );
                SubscriptionError::UnknownError(inner_error)
            }
            LoopErr::Fatal(inner_error) => inner_error,
            LoopErr::Transient(inner_error) => inner_error,
        })
    }

    async fn update_last_seen_height(&self, last_height: u64) {
        let mut guarded_storage = self.latest_height.lock().await;
        *guarded_storage = last_height;
    }

    fn to_event(event: &cosmos_proto::messages::tendermint::abci::Event) -> Event {
        let mut result = Event::new(event.r#type.clone());
        for attribute in event.attributes.iter() {
            let key = attribute.key.clone();
            let value = attribute.value.clone();
            result = result.add_attribute(key, value);
        }
        result
    }

    fn try_from(tx: &TxResponse) -> anyhow::Result<Vec<TransactionEvent>> {
        tx.events
            .iter()
            .filter(|x| KmsOperation::iter().any(|attr| x.r#type == format!("wasm-{}", attr)))
            .map(|x| Self::to_event(x))
            .map(<Event as TryInto<KmsEvent>>::try_into)
            .map(|e| {
                e.map(|ev| TransactionEvent {
                    tx_hash: tx.txhash.clone(),
                    event: ev,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kms::{KmsEvent, KmsOperation};
    use crate::subscription::blockchain::*;
    use cosmwasm_std::{Attribute, Event};
    use test_context::{test_context, AsyncTestContext};
    use tokio::sync::oneshot;

    mock! {
        NeverCalledSubscriptionHandler {}
        impl Clone for NeverCalledSubscriptionHandler {
            fn clone(&self) -> Self;
        }

        #[async_trait::async_trait]
        impl SubscriptionHandler<Tx> for NeverCalledSubscriptionHandler {
            async fn on_message(&self, _message: TransactionEvent, _height_of_event: u64) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>;
            async fn on_catchup(&self, _message: TransactionEvent, _height_of_event: u64, _past_tx: &mut Vec<Tx>, _past_events_responses: &mut Vec<TransactionEvent>) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>;
            fn filter_for_catchup(&self, tx: Tx) -> Option<Tx>;
        }

    }

    mock! {
        MetricService {}
        impl Metrics for MetricService {
            fn increment_tx_processed<'a>(&self, amount: u64, tags: &[(&'a str, &'a str)]);
            fn increment_tx_error<'a>(&self, amount: u64, tags: &[(&'a str, &'a str)]);
            fn increment_connection_errors<'a>(&self, amount: u64, tags: &[(&'a str, &'a str)]);
        }
    }

    mock! {
        GrpcBlockchainService {}
        impl Clone for GrpcBlockchainService {
            fn clone(&self) -> Self;
        }

        #[async_trait]
        impl BlockchainService for GrpcBlockchainService {
            async fn get_events(&self, from_height: u64) -> Result<Vec<TxResponse>, SubscriptionError>;
            async fn get_events_requests(
                &self,
                from_height: u64,
            ) -> Result<Vec<TxResponse>, SubscriptionError>;
            async fn get_events_responses(
                &self,
                from_height: u64,
            ) -> Result<Vec<TxResponse>, SubscriptionError>;
            async fn get_last_height(&self) -> Result<u64, SubscriptionError>;
            async fn get_all_tx_from_to_height(
                &self,
                from_height: u64,
                to_height: u64,
            ) -> Result<Vec<Tx>, SubscriptionError>;

            async fn get_all_tx_from_to_height_filter_map<
                T: 'static + Send,
                F: Fn(Tx) -> Option<T> + Send + 'static,
            >(
                &self,
                from_height: u64,
                to_height: u64,
                filter: F,
            ) -> Result<Vec<T>, SubscriptionError>;
        }
    }

    struct SubscriptionContext {
        subscription: SubscriptionEventChannel<MockGrpcBlockchainService, MockMetricService>,
    }

    impl AsyncTestContext for SubscriptionContext {
        async fn setup() -> SubscriptionContext {
            async {
                let blockchain = MockGrpcBlockchainService::new();
                let storage = Arc::new(Mutex::new(0));
                SubscriptionContext {
                    subscription: SubscriptionEventChannel {
                        blockchain,
                        latest_height: storage,
                        metrics: MockMetricService::new(),
                        tick_time_in_sec: 1,
                    },
                }
            }
            .await
        }

        async fn teardown(self) {}
    }

    #[derive(Clone)]
    struct TestHandler {
        sender: tokio::sync::mpsc::Sender<()>,
    }

    #[async_trait::async_trait]
    impl crate::subscription::handler::SubscriptionHandler<Tx> for TestHandler {
        async fn on_message(
            &self,
            message: TransactionEvent,
            _height_of_event: u64,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
            tracing::info!("Received message: {:?}", message);
            self.sender.send(()).await?;
            Ok(())
        }
        async fn on_catchup(
            &self,
            message: TransactionEvent,
            _height_of_event: u64,
            _past_tx: &mut Vec<Tx>,
            _past_events_responses: &mut Vec<TransactionEvent>,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
            tracing::info!("Catching up on message: {:?}", message);
            self.sender.send(()).await?;
            Ok(())
        }
        fn filter_for_catchup(&self, tx: Tx) -> Option<Tx> {
            Some(tx)
        }
    }

    #[test_context(SubscriptionContext)]
    #[tokio::test]
    async fn test_successfull_subscription_with_one_message(
        server: &mut SubscriptionContext,
    ) -> Result<(), Box<dyn std::error::Error>> {
        test_subscription_messages_common(server, 1).await
    }

    #[test_context(SubscriptionContext)]
    #[tokio::test]
    async fn test_successfull_subscription_with_multiple_messages(
        server: &mut SubscriptionContext,
    ) -> Result<(), Box<dyn std::error::Error>> {
        test_subscription_messages_common(server, 10).await
    }

    #[test_context(SubscriptionContext)]
    #[tokio::test]
    async fn test_on_error_message(
        server: &mut SubscriptionContext,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut on_message_mock = MockNeverCalledSubscriptionHandler::new();
        on_message_mock.expect_clone().returning(|| {
            let mut mock = MockNeverCalledSubscriptionHandler::new();
            mock.expect_on_message().never();
            mock
        });
        on_message_mock.expect_on_message().never();

        server
            .subscription
            .blockchain
            .expect_clone()
            .once()
            .returning(|| {
                let mut new_mock = MockGrpcBlockchainService::new();
                new_mock
                    .expect_get_events()
                    .withf(|_| true)
                    .times(1)
                    .returning(move |_| Ok(vec![]));
                new_mock
            });

        server
            .subscription
            .metrics
            .expect_increment_tx_processed()
            .times(1)
            .returning(|_, _| ());

        let result = server.subscription.handle_events(on_message_mock, 0).await;
        assert!(result.is_ok());
        Ok(())
    }

    async fn test_subscription_messages_common(
        server: &mut SubscriptionContext,
        amount: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (tx, mut rx) = tokio::sync::mpsc::channel(amount as usize);
        let on_message = TestHandler { sender: tx };

        let mut tx_response = TxResponse::default();
        let event = KmsEvent::builder()
            .operation(KmsOperation::Decrypt)
            .txn_id(vec![1])
            .build();
        let attrs: Vec<Attribute> = <KmsEvent as Into<Event>>::into(event).attributes;
        tx_response
            .events
            .push(cosmos_proto::messages::tendermint::abci::Event {
                r#type: format!("wasm-{}", KmsOperation::Decrypt),
                attributes: attrs
                    .iter()
                    .map(
                        |x| cosmos_proto::messages::tendermint::abci::EventAttribute {
                            key: x.key.to_string(),
                            value: x.value.to_string(),
                            index: true,
                        },
                    )
                    .collect(),
            });

        server
            .subscription
            .blockchain
            .expect_clone()
            .once()
            .returning(move || {
                let tx_response = tx_response.clone();
                let mut new_mock = MockGrpcBlockchainService::new();
                new_mock
                    .expect_get_events()
                    .withf(|_| true)
                    .times(1)
                    .returning(move |_| Ok(vec![tx_response.clone(); amount as usize]));
                new_mock
            });

        server
            .subscription
            .metrics
            .expect_increment_tx_processed()
            .times(1)
            .withf(|_, _| true)
            .returning(|_, _| ());

        let result = server.subscription.handle_events(on_message, 0).await;
        assert!(result.is_ok());
        let counter = std::sync::atomic::AtomicUsize::new(0);
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        let (timeout_tx, timeout_rx) = oneshot::channel();
        let timeout_task = async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            timeout_tx.send(()).unwrap();
        };
        tokio::spawn(timeout_task);
        tokio::select! {
            _ = timeout_rx => {
                panic!("Timeout");
            }
            _ = async {
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                        }
                        _ = rx.recv() => {
                            let count = counter.fetch_add(1, std::sync::atomic::Ordering::Release);
                            if count == amount as usize - 1 {
                                break;
                            }
                        }
                    }
                }
            } => { }
        }

        assert_eq!(
            counter.load(std::sync::atomic::Ordering::Acquire),
            amount as usize
        );
        Ok(())
    }
}

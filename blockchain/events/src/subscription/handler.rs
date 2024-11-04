use super::metrics::{Metrics, OpenTelemetryMetrics};
use super::{BlockchainService, GrpcBlockchainService, StorageService, TomlStorageServiceImpl};
use crate::kms::{KmsEvent, KmsOperation, TransactionEvent};
use async_trait::async_trait;
use cosmos_proto::messages::cosmos::base::abci::v1beta1::TxResponse;
use cosmwasm_std::Event;
use koit_toml::KoitError;
#[cfg(test)]
use mockall::{automock, mock, predicate::*};
use retrying::retry;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
use strum::IntoEnumIterator as _;
use strum_macros::EnumString;
use thiserror::Error;
use tokio::time::sleep;
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
    #[error("Error loading storage with sync point - {0}")]
    StorageError(#[from] KoitError),
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
    #[builder(setter(transform = |x: &str| PathBuf::from(x)))]
    storage_path: PathBuf,
    #[builder(setter(into), default)]
    height: Option<u64>,
    contract_address: &'a str,
    #[builder(default = 5)]
    tick_time_in_sec: u64,
    #[builder(default, setter(into))]
    filter_events_mode: Option<EventsMode>,
}

pub struct SubscriptionEventChannel<B, S, M> {
    blockchain: B,
    storage: S,
    metrics: M,
    tick_time_in_sec: u64,
}

impl<'a, 'b> SubscriptionEventBuilder<'a>
where
    'a: 'b,
{
    pub async fn subscription(
        self,
    ) -> Result<
        SubscriptionEventChannel<
            GrpcBlockchainService<'b>,
            TomlStorageServiceImpl,
            OpenTelemetryMetrics,
        >,
        SubscriptionError,
    > {
        let blockchain = GrpcBlockchainService::new(
            self.grpc_addresses,
            self.contract_address,
            self.filter_events_mode,
        )?;
        let storage = TomlStorageServiceImpl::new(&self.storage_path, self.height).await?;
        let metrics = OpenTelemetryMetrics::new();
        Ok(SubscriptionEventChannel {
            tick_time_in_sec: self.tick_time_in_sec,
            blockchain,
            storage,
            metrics,
        })
    }
}

/// Subscription Handler Trait
/// This trait is used to define the behavior of the Subscription handler
/// The handler will be called when a message is received from the Event Server
#[cfg_attr(test, automock)]
#[async_trait]
pub trait SubscriptionHandler {
    async fn on_message(
        &self,
        message: TransactionEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>;
}

impl<B, S, M> SubscriptionEventChannel<B, S, M>
where
    B: BlockchainService,
    S: StorageService,
    M: Metrics,
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
    ///
    ///
    ///
    pub async fn subscribe<U>(self, handler: U) -> Result<(), SubscriptionError>
    where
        U: SubscriptionHandler + Clone + Send + Sync + 'static,
    {
        //Init once the block height
        let bc_height = self.blockchain.get_last_height().await;
        let height = bc_height.unwrap_or(0);
        self.update_last_seen_height(height).await?;
        tracing::info!("Starting polling Blockchain on block {height}");
        loop {
            tracing::trace!(
                "Waiting {} secs for next tick before getting events",
                self.tick_time_in_sec
            );
            sleep(Duration::from_secs(self.tick_time_in_sec)).await;
            self.handle_events(handler.clone())
                .await
                .unwrap_or_else(|e| {
                    tracing::error!("Error handling events: {:?}", e);
                });
        }
    }

    /// Handle one round of events received from the Event Server
    pub async fn handle_events<U>(&self, handler: U) -> Result<(), SubscriptionError>
    where
        U: SubscriptionHandler + Clone + Send + Sync + 'static,
    {
        let enter = tracing::span!(
            tracing::Level::TRACE,
            "subscribe",
            "Loop Getting Event from Blockchain"
        );
        let _guard = enter.enter();
        let height = self.storage.get_last_height().await?;
        tracing::info!("Getting events from Blockchain from height {:?}", height);
        let results = self.get_txs_events(height).await.inspect_err(|e| {
            self.metrics
                .increment_connection_errors(1, &[("error", &e.to_string())]);
        })?;
        if results.is_empty() {
            tracing::debug!("No events received from Blockchain. Incrementing height by one.");
            self.update_last_seen_height(height + 1).await?;
            return Ok(());
        } else {
            tracing::debug!("Received {:?} events from Blockchain", results.len());
        }
        let last_height = results.iter().map(|tx| tx.height).max().unwrap_or(0) as u64;
        let events = results
            .iter()
            .map(|tx| {
                Self::try_from(tx)
                    .map_err(|e| SubscriptionError::DeserializationError(e.to_string()))
            })
            .collect::<Result<Vec<Vec<TransactionEvent>>, _>>()?;
        let events = events
            .into_iter()
            .flatten()
            .collect::<Vec<TransactionEvent>>();
        let results_size = events.len();
        tracing::debug!("Sending events to be processed to handler {}", results_size);
        for result in events {
            let handler = handler.clone();
            let handle = async move {
                let enter = tracing::span!(
                    tracing::Level::DEBUG,
                    "on_message",
                    payload = ?result,
                    "Received message from Event Server"
                );
                let _guard = enter.enter();
                let result = handler.on_message(result).await;
                if let Err(e) = &result {
                    tracing::error!("Error processing message: {:?}", e);
                }
                drop(_guard);
                result
            };
            tokio::spawn(handle);
        }

        self.metrics
            .increment_tx_processed(results_size as u64, &[]);
        self.update_last_seen_height(last_height).await
    }

    #[retry(stop=(attempts(4)|duration(5)),wait=fixed(10))]
    async fn get_txs_events(&self, height: u64) -> Result<Vec<TxResponse>, SubscriptionError> {
        self.blockchain.get_events(height).await
    }

    async fn update_last_seen_height(&self, last_height: u64) -> Result<(), SubscriptionError> {
        self.storage.save_last_height(last_height).await
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
    use crate::subscription::storage::MockStorageService;
    use cosmwasm_std::{Attribute, Event};
    use std::sync::Arc;
    use test_context::{test_context, AsyncTestContext};
    use tokio::sync::oneshot;

    mock! {
        NeverCalledSubscriptionHandler {}
        impl Clone for NeverCalledSubscriptionHandler {
            fn clone(&self) -> Self;
        }

        #[async_trait::async_trait]
        impl SubscriptionHandler for NeverCalledSubscriptionHandler {
            async fn on_message(&self, _message: TransactionEvent) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>;
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

    struct SubscriptionContext {
        subscription:
            SubscriptionEventChannel<MockBlockchainService, MockStorageService, MockMetricService>,
    }

    impl AsyncTestContext for SubscriptionContext {
        async fn setup() -> SubscriptionContext {
            async {
                let blockchain = MockBlockchainService::new();
                let storage = MockStorageService::new();
                SubscriptionContext {
                    subscription: SubscriptionEventChannel {
                        blockchain,
                        storage,
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
    impl crate::subscription::handler::SubscriptionHandler for TestHandler {
        async fn on_message(
            &self,
            message: TransactionEvent,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
            tracing::info!("Received message: {:?}", message);
            self.sender.send(()).await?;
            Ok(())
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
        server
            .subscription
            .blockchain
            .expect_get_events()
            .withf(|_| true)
            .times(1)
            .returning(move |_| Ok(vec![]));

        server
            .subscription
            .storage
            .expect_get_last_height()
            .times(1)
            .returning(|| Ok(0));

        server
            .subscription
            .storage
            .expect_save_last_height()
            .withf(|_| true)
            .times(1)
            .returning(|_| Ok(()));

        let mut on_message_mock = MockNeverCalledSubscriptionHandler::new();
        on_message_mock.expect_on_message().never();

        server.subscription.handle_events(on_message_mock).await?;
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
            .expect_get_events()
            .withf(|_| true)
            .times(1)
            .returning(move |_| Ok(vec![tx_response.clone(); amount as usize]));

        server
            .subscription
            .storage
            .expect_get_last_height()
            .times(1)
            .returning(|| Ok(0));

        server
            .subscription
            .storage
            .expect_save_last_height()
            .withf(|_| true)
            .times(1)
            .returning(|_| Ok(()));

        server
            .subscription
            .metrics
            .expect_increment_tx_processed()
            .times(1)
            .withf(|_, _| true)
            .returning(|_, _| ());

        let result = server.subscription.handle_events(on_message.clone()).await;
        assert!(result.is_ok());

        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
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

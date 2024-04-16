use core::slice;
use std::time::Duration;

use async_trait::async_trait;
use fast_websocket_client::{client, connect, OpCode};
use serde::Deserialize;
use simd_json::serde as sim_serde;
use tokio::task;
use typed_builder::TypedBuilder;

use crate::query::SubQuery;

/// Subscription entry point for building a Subscription Service
/// The builder pattern is used to create a Subscription Service
#[derive(TypedBuilder)]
pub struct SubscriptionWebSocketBuilder<'a> {
    ws_address: &'a str,

    query: &'a SubQuery<'a>,

    // Default waiting time for reconnection is 10 seconds
    #[builder(default = Duration::from_secs(10))]
    recon_waiting_time: Duration,
}

/// Subscription Handler Trait
/// This trait is used to define the behavior of the Subscription handler
/// The handler will be called when a message is received from the WebSocket Server
#[async_trait]
pub trait SubscriptionHandler<D> {
    async fn on_message(
        &self,
        message: D,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>;
}

impl<'a> SubscriptionWebSocketBuilder<'a> {
    /// Subscribe to the WebSocket server
    /// The handler will be called when a message is received from the WebSocket server
    ///
    /// # Arguments
    /// * `handler` - The handler that will be called when a message is received from the WebSocket Server
    /// * `D` - The type of the message that will be received from the WebSocket server
    /// * `U` - The handler that will be called when a message is received from the WebSocket server
    ///
    pub async fn subscribe<U, D>(self, handler: &U)
    where
        U: SubscriptionHandler<D> + Clone + Send + Sync + 'static,
        D: for<'de> Deserialize<'de> + std::fmt::Debug + Send + Sync + 'static,
    {
        'reconnect_loop: loop {
            let mut client: client::Online = match connect(self.ws_address).await {
                Ok(mut client) => {
                    tracing::info!(
                        "Connected to WebSocket Server Subscription at {}",
                        self.ws_address
                    );
                    client.set_auto_pong(true);
                    client
                }
                Err(e) => {
                    tracing::error!("Error connecting to WebSocket Server Subscription at {} - Error: {e:?}. Wating 10 seconds before reconnecting again.", self.ws_address);
                    tokio::time::sleep(self.recon_waiting_time).await;
                    continue;
                }
            };

            // add one more example subscription here after connect
            if let Err(e) = Self::send_subscribe_message(&mut client, self.query).await {
                tracing::error!("Error subscribing to WebSocket Server Subscription at {} with message {:?} - Error: {e:?}. Wating 10 seconds before reconnecting again.", self.ws_address, self.query);
                let _ = client.send_close(&[]).await;
                tokio::time::sleep(self.recon_waiting_time).await;
                continue;
            };

            // message processing loop
            loop {
                if let Ok(result) =
                    tokio::time::timeout(Duration::from_millis(100), client.receive_frame()).await
                {
                    match result {
                        Ok(mut message) => {
                            match message.opcode {
                                OpCode::Text => {
                                    let slice = message.payload.to_mut();
                                    let ptr = slice.as_mut_ptr();
                                    let slice_mut =
                                        unsafe { slice::from_raw_parts_mut(ptr, slice.len()) };
                                    let payload = match sim_serde::from_slice(slice_mut) {
                                        Ok(payload) => payload,
                                        Err(e) => {
                                            tracing::error!("Error deserializing message from WebSocket Server Subscription at {} - Error: {e:?}", self.ws_address);
                                            let _ = client.send_close(&[]).await;
                                            break; // break the message loop then reconnect
                                        }
                                    };

                                    let handler = handler.clone();
                                    task::spawn(async move {
                                        let enter = tracing::span!(tracing::Level::INFO, "on_message", payload = ?payload);
                                        let _guard = enter.enter();
                                        let p = format!("{:?}", payload);
                                        handler.on_message(payload).await.unwrap_or_else(|e| {
                                            tracing::error!("Error processing message from WebSocket Server - Message: {p} - Error: {e:?}");
                                        });
                                        drop(_guard);
                                    });
                                }
                                OpCode::Close => {
                                    tracing::error!("Error Received Close message from WebSocket Server Subscription at {} - Error: {}", self.ws_address, String::from_utf8_lossy(message.payload.as_ref()));
                                    break 'reconnect_loop;
                                }
                                _ => {}
                            }
                        }
                        Err(e) => {
                            tracing::error!("Error receiving message from WebSocket Server Subscription at {} - Error: {e:?}", self.ws_address);
                            let _ = client.send_close(&[]).await;
                            break; // break the message loop then reconnect
                        }
                    }
                } else {
                    tracing::warn!(
                        "Timeout receiving message from WebSocket Server Subscription at {}",
                        self.ws_address
                    );
                    continue;
                };
            }
        }
    }

    async fn send_subscribe_message(
        client: &mut client::Online,
        handler: &SubQuery<'_>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tokio::time::timeout(
            Duration::from_millis(0),
            client.send_json(handler.to_subscription_msg()),
        )
        .await??;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::sync::Arc;
    use std::time::Duration;

    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use tokio::sync::mpsc;
    use tokio::sync::oneshot;
    use tokio::time::interval;
    use ws_mock::matchers::JsonExact;
    use ws_mock::ws_mock_server::{WsMock, WsMockServer};

    use crate::query::SubQuery;
    use crate::subscription::SubscriptionWebSocketBuilder;

    use test_context::{test_context, AsyncTestContext};

    struct WebSocketTestAsyncContext<'a> {
        ws_server: WsMockServer,
        query: SubQuery<'a>,
    }

    fn init_tracing() -> Result<(), Box<dyn Error + Sync + Send>> {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_line_number(true)
            .with_file(true)
            .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
            .try_init()
    }

    impl AsyncTestContext for WebSocketTestAsyncContext<'static> {
        async fn setup() -> WebSocketTestAsyncContext<'static> {
            init_tracing().unwrap_or(());
            let handler = SubQuery::builder()
                .contract_address("0x0d6ae2a429df13e44a07cd2969e085e4833f64a0")
                .event_type(events::EventType::KmsOperation)
                .attributes(vec![events::EventAttribute::builder()
                    .key(events::KmsEventAttribute::OperationType)
                    .value("my-type".to_string())
                    .build()])
                .build();
            WebSocketTestAsyncContext {
                ws_server: WsMockServer::start().await,
                query: handler,
            }
        }

        async fn teardown(self) {
            self.ws_server.verify().await;
            drop(self.ws_server);
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct TestStruct {
        number: u32,
        test: String,
    }

    #[derive(Clone)]
    struct TestHandler {
        tx: Arc<mpsc::Sender<()>>,
    }

    #[async_trait::async_trait]
    impl crate::subscription::SubscriptionHandler<TestStruct> for TestHandler {
        async fn on_message(
            &self,
            message: TestStruct,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
            tracing::info!("Received message: {:?}", message);
            assert_eq!(message.test, "test");
            self.tx.send(()).await?;
            Ok(())
        }
    }

    #[test_context(WebSocketTestAsyncContext)]
    #[tokio::test]
    async fn test_successfull_subscription_with_one_message(
        server: &mut WebSocketTestAsyncContext<'static>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        test_subscription_messages_common(server, 1).await
    }

    #[test_context(WebSocketTestAsyncContext)]
    #[tokio::test]
    async fn test_successfull_subscription_with_multiple_messages(
        server: &mut WebSocketTestAsyncContext<'static>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        test_subscription_messages_common(server, 10).await
    }

    async fn test_subscription_messages_common(
        server: &mut WebSocketTestAsyncContext<'static>,
        amount: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json_sub_msg_str = serde_json::to_string(&server.query.to_subscription_msg())
            .expect("Failed to serialize message");
        let json_sub_msg = serde_json::from_str::<Value>(&json_sub_msg_str)?;

        let (mpsc_send, mpsc_recv) = mpsc::channel::<String>(32);

        WsMock::new()
            .matcher(JsonExact::new(json_sub_msg))
            .forward_from_channel(mpsc_recv)
            .mount(&server.ws_server)
            .await;

        let uri = server.ws_server.uri().await;

        let (tx, mut rx) = mpsc::channel(32);

        let on_message = TestHandler { tx: Arc::new(tx) };

        let query = server.query.clone();

        let handle = tokio::spawn(async move {
            let subscription = SubscriptionWebSocketBuilder::builder()
                .ws_address(&uri)
                .query(&query)
                .recon_waiting_time(Duration::from_secs(10))
                .build();

            subscription.subscribe(&on_message).await
        });

        for i in 0..amount {
            let expected_json = json!({
              "number": i,
              "test": "test",
            });

            let expected_json_str = serde_json::to_string(&expected_json)?;

            mpsc_send.send(expected_json_str.clone()).await?;
        }

        let mut interval = interval(Duration::from_secs(1));

        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (timeout_tx, timeout_rx) = oneshot::channel();
        let timeout_task = async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            timeout_tx.send(()).unwrap();
        };

        tokio::spawn(timeout_task);
        tokio::select! {
            _ = timeout_rx => {
                handle.abort();
                panic!("Timeout");
            }
            _ = async {
                loop {
                    tokio::select! {
                        _ = interval.tick() => {
                        }
                        _ = rx.recv() => {
                            let count = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            if count == amount as usize - 1 {
                                handle.abort();
                                break;
                            }
                        }
                    }
                }
            } => {}
        }

        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            amount as usize
        );
        Ok(())
    }
}

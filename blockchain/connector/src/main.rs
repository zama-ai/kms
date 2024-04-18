use cosmwasm_std::Event;
use events::subscription::handler::{SubscriptionHandler, SubscriptionWebSocketBuilder};
use events::subscription::query::SubQuery;

#[derive(Clone)]
struct TestHandler {}

#[async_trait::async_trait]
impl SubscriptionHandler for TestHandler {
    async fn on_message(
        &self,
        message: Event,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        tracing::info!("Received message: {:?}", message);
        Ok(())
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_line_number(true)
        .with_file(true)
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::CLOSE)
        .init();

    let handler = TestHandler {};
    let query = SubQuery::builder()
        .contract_address("wasm14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9s0phg4d")
        .attributes(vec![])
        .build();

    let subscription = SubscriptionWebSocketBuilder::builder()
        .ws_address("ws://localhost:36657/websocket")
        .query(&query)
        .build();
    subscription.subscribe(&handler).await;
}

use std::time::Instant;

use events::EventType;
use serde::Serialize;
use typed_builder::TypedBuilder;

#[derive(Serialize)]
pub(crate) struct Subscription<'a> {
    jsonrpc: &'a str,
    method: &'a str,
    params: Query,
    id: u128,
}

#[derive(serde::Serialize)]
pub(crate) struct Query {
    query: String,
}

#[derive(TypedBuilder, Debug, Clone)]
pub struct SubQuery<'a> {
    contract_address: &'a str,
    event_type: EventType,
    attributes: Vec<events::EventAttribute>,
}

impl SubQuery<'_> {
    pub fn contract_address(&self) -> &str {
        self.contract_address
    }

    pub fn event_type(&self) -> EventType {
        self.event_type
    }

    pub fn attributes(&self) -> &Vec<events::EventAttribute> {
        &self.attributes
    }

    /// Converts the subscription query to a JSON-RPC message
    pub fn to_subscription_msg(&self) -> impl Serialize {
        let mut query = format!(
            "tm.event='Tx' AND wasm._contract_address='{}' AND execute._contract_address='{}' AND wasm-{} EXISTS",
            self.contract_address,
            self.contract_address,
            self.event_type
        );
        self.attributes.iter().for_each(|attribute| {
            query.push_str(&format!(" AND {}='{}'", attribute.key, attribute.value));
        });
        Subscription {
            jsonrpc: "2.0",
            method: "subscribe",
            params: Query { query },
            id: Instant::now().elapsed().as_nanos(),
        }
    }
}

use std::time::Instant;

use serde::Serialize;
use typed_builder::TypedBuilder;

use crate::kms::EventAttribute;

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
    attributes: Vec<EventAttribute>,
}

impl SubQuery<'_> {
    pub fn contract_address(&self) -> &str {
        self.contract_address
    }

    pub fn attributes(&self) -> &Vec<EventAttribute> {
        &self.attributes
    }

    /// Converts the subscription query to a JSON-RPC message
    pub fn to_subscription_msg(&self) -> impl Serialize {
        let mut query = format!(
            "tm.event='Tx' AND execute._contract_address='{}'",
            self.contract_address
        );
        self.attributes.iter().for_each(|attribute| {
            query.push_str(&format!(
                " AND execute.{} EXISTS AND execute.{}='{}'",
                attribute.key, attribute.key, attribute.value
            ));
        });
        Subscription {
            jsonrpc: "2.0",
            method: "subscribe",
            params: Query { query },
            id: Instant::now().elapsed().as_nanos(),
        }
    }
}

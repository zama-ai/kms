//! Networking traits and implementations.

use crate::computation::SessionId;
use crate::execution::player::Identity;
use crate::value::Value;
use async_trait::async_trait;

pub mod constants;
pub mod grpc;
pub mod local;

/// Requirements for networking interface.
#[async_trait]
pub trait Networking {
    async fn send(
        &self,
        value: Value,
        receiver: &Identity,
        session_id: &SessionId,
    ) -> anyhow::Result<()>;

    async fn receive(&self, sender: &Identity, session_id: &SessionId) -> anyhow::Result<Value>;

    async fn increase_round_counter(&self) -> anyhow::Result<()>;
}

//! Networking traits and implementations.

use crate::computation::SessionId;
use crate::execution::party::Identity;
use crate::value::NetworkValue;
use async_trait::async_trait;

pub mod constants;
pub mod grpc;
pub mod local;

/// Requirements for networking interface.
#[async_trait]
pub trait Networking {
    async fn send(
        &self,
        value: NetworkValue,
        receiver: &Identity,
        session_id: &SessionId,
    ) -> anyhow::Result<()>;

    async fn receive(
        &self,
        sender: &Identity,
        session_id: &SessionId,
    ) -> anyhow::Result<NetworkValue>;

    async fn increase_round_counter(&self) -> anyhow::Result<()>;
}

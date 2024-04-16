//! Networking traits and implementations.

use crate::execution::runtime::party::Identity;
use crate::session_id::SessionId;
use async_trait::async_trait;
use tokio::time::Instant;

pub mod constants;
pub mod grpc;
pub mod local;
pub mod value;

/// Requirements for networking interface.
#[async_trait]
pub trait Networking {
    async fn send(
        &self,
        value: Vec<u8>,
        receiver: &Identity,
        session_id: &SessionId,
    ) -> anyhow::Result<()>;

    async fn receive(&self, sender: &Identity, session_id: &SessionId) -> anyhow::Result<Vec<u8>>;

    fn increase_round_counter(&self) -> anyhow::Result<()>;

    ///Used to compute the timeout in network functions
    fn get_timeout_current_round(&self) -> anyhow::Result<Instant>;

    fn get_current_round(&self) -> anyhow::Result<usize>;
}

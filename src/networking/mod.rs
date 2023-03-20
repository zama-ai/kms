//! Networking traits and implementations.

use crate::computation::SessionId;
use crate::execution::Identity;
use crate::poly_shamir::Value;
use async_trait::async_trait;

pub mod local;

/// Requirements for asynchronous networking.
///
/// An implementation of this trait must be provided when using DDec
/// for asynchronous (blocking) execution.
#[async_trait]
pub trait Networking {
    async fn send(&self, value: &Value, receiver: &Identity) -> Result<(), anyhow::Error>;

    async fn receive(&self, sender: &Identity) -> Result<Value, anyhow::Error>;
}

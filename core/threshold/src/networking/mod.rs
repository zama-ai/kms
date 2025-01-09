//! Networking traits and implementations.

use tokio::time::Duration;

use crate::execution::runtime::party::Identity;
use crate::execution::runtime::party::RoleAssignment;
use crate::execution::runtime::session::NetworkingImpl;
use crate::session_id::SessionId;
use async_trait::async_trait;
use tokio::time::Instant;

pub mod constants;
pub mod grpc;
pub mod local;
pub mod sending_service;
pub mod thread_handle;
pub mod value;

pub type NetworkingStrategy =
    Box<dyn Fn(SessionId, RoleAssignment, NetworkMode) -> NetworkingImpl + Send + Sync>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NetworkMode {
    Sync,
    Async,
}

/// Requirements for networking interface.
#[async_trait]
pub trait Networking {
    async fn send(&self, value: Vec<u8>, receiver: &Identity) -> anyhow::Result<()>;

    async fn receive(&self, sender: &Identity) -> anyhow::Result<Vec<u8>>;

    /// Increase the round counter
    ///
    /// __NOTE__: We always assume this is called right before sending happens
    fn increase_round_counter(&self) -> anyhow::Result<()>;

    ///Used to compute the timeout in network functions
    fn get_timeout_current_round(&self) -> anyhow::Result<Instant>;

    fn get_current_round(&self) -> anyhow::Result<usize>;

    /// Method to set a different timeout than the one set at construction, effective for the next round.
    ///
    /// __NOTE__: If the network mode is Async, this has no effect
    fn set_timeout_for_next_round(&self, timeout: Duration) -> anyhow::Result<()>;

    /// Method to set the timeout for distributed generation of the TFHE bootstrapping key
    ///
    /// Useful mostly to use parameters given by config file in grpc networking
    /// Rely on [`Networking::set_timeout_for_next_round`]
    fn set_timeout_for_bk(&self) -> anyhow::Result<()>;

    /// Method to set the timeout for distributed generation of the TFHE switch and squash bootstrapping key
    ///
    /// Useful mostly to use parameters given by config file in grpc networking
    /// Rely on [`Networking::set_timeout_for_next_round`]
    fn set_timeout_for_bk_sns(&self) -> anyhow::Result<()>;

    fn get_network_mode(&self) -> NetworkMode;
}

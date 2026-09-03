use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::role::RoleTrait;
use async_trait::async_trait;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NetworkMode {
    Sync,
    Async,
}

/// Snapshot of a network's round-clock *progress*: the state that determines how
/// far a session has advanced and how much per-round timeout budget it has
/// accumulated. Copied between sessions by [`Networking::synchronize_from`].
#[derive(Clone, Copy, Debug)]
pub struct RoundClock {
    pub init_time: Instant,
    /// Current round counter (tags outgoing messages).
    pub round: usize,
    /// Accumulated elapsed-time budget (see [`Networking::increase_round_counter`]).
    pub max_elapsed_time: Duration,
    /// Current round's network timeout.
    pub current_network_timeout: Duration,
}

/// Requirements for networking interface.
#[async_trait]
pub trait Networking<R: RoleTrait> {
    async fn send(&self, value: Arc<Vec<u8>>, receiver: &R) -> anyhow::Result<()>;

    async fn receive(&self, sender: &R) -> anyhow::Result<Vec<u8>>;

    /// Increase the round counter
    ///
    /// __NOTE__: We always assume this is called right before sending happens
    async fn increase_round_counter(&self);

    ///Used to compute the timeout in network functions
    async fn get_timeout_current_round(&self) -> Instant;

    async fn get_current_round(&self) -> usize;

    /// Snapshot this network's [`RoundClock`]. Used to implement
    /// [`Networking::synchronize_from`]; not usually called directly.
    async fn round_clock_snapshot(&self) -> RoundClock;

    /// Overwrite this network's round-clock *progress* (init_time, round counter, accumulated
    /// timeout budget and current-round timeout).
    ///
    /// Panics if `clock.round` is behind the current round: a round clock only ever
    /// moves forward, and rewinding it would reuse round tags and corrupt message
    /// delivery.
    async fn restore_round_clock(&self, clock: RoundClock);

    /// Synchronize this network's round-clock progress to `other`'s: adopt its
    /// round counter, accumulated timeout budget and current-round timeout.
    ///
    /// Blanket implementation provided by [`Networking::round_clock_snapshot`] and
    /// [`Networking::restore_round_clock`].
    async fn synchronize_from(&self, other: &(dyn Networking<R> + Send + Sync)) {
        self.restore_round_clock(other.round_clock_snapshot().await)
            .await;
    }

    async fn get_num_byte_sent(&self) -> usize;

    async fn get_num_byte_received(&self) -> anyhow::Result<usize>;

    /// Method to set a different timeout than the one set at construction, effective for the next round.
    ///
    /// __NOTE__: If the network mode is Async, this has no effect
    async fn set_timeout_for_next_round(&self, timeout: Duration);

    /// Method to set the timeout for distributed generation of the TFHE bootstrapping key
    ///
    /// Useful mostly to use parameters given by config file in grpc networking
    /// Rely on [`Networking::set_timeout_for_next_round`]
    async fn set_timeout_for_bk(&self);

    /// Method to set the timeout for distributed generation of the TFHE switch and squash bootstrapping key
    ///
    /// Useful mostly to use parameters given by config file in grpc networking
    /// Rely on [`Networking::set_timeout_for_next_round`]
    async fn set_timeout_for_bk_sns(&self);

    fn get_network_mode(&self) -> NetworkMode;
}

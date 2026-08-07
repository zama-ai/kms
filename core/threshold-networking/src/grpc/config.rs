//! Core-to-core network configuration and its default-resolving accessors.

use crate::constants::{
    DISCARD_INACTIVE_SESSION_INTERVAL_SECS, INITIAL_INTERVAL_MS, MAX_BUFFERED_FUTURE_MSGS,
    MAX_ELAPSED_TIME, MAX_EN_DECODE_MESSAGE_SIZE, MAX_INTERVAL,
    MAX_OPENED_INACTIVE_SESSIONS_PER_PARTY, MAX_WAITING_TIME_MESSAGE_QUEUE, MESSAGE_LIMIT,
    MULTIPLIER, NETWORK_TIMEOUT_BK, NETWORK_TIMEOUT_BK_SNS, NETWORK_TIMEOUT_LONG,
    SESSION_CLEANUP_INTERVAL_SECS, SESSION_STATUS_UPDATE_INTERVAL_SECS,
};
use serde::{Deserialize, Serialize};
use tokio::time::Duration;

/// Network configuration for core-to-core communication.
///
/// Every field is optional: an absent field falls back to the corresponding
/// default in [`crate::constants`] via the `get_*` accessors below. This means
/// a fully-absent config (`CoreToCoreNetworkConfig::default()`, all `None`) is
/// equivalent to "use all defaults", and a partial config overrides only the
/// fields it sets. Callers should always read through the `get_*` accessors
/// rather than the raw fields so the defaulting stays in one place.
///
/// WARNING: this may be printed for debugging and hence should NOT contain any secrets, such as private keys.
/// If minor secrets needs to be added, then ensure fields are annotated with `#[serde(skip_serializing)]` to avoid accidentally diclosing them.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct CoreToCoreNetworkConfig {
    pub message_limit: Option<u64>,
    pub multiplier: Option<f64>,
    pub max_interval: Option<u64>,
    pub max_elapsed_time: Option<u64>,
    /// Initial interval for exponential backoff in milliseconds
    pub initial_interval_ms: Option<u64>,
    pub network_timeout: Option<u64>,
    pub network_timeout_bk: Option<u64>,
    pub network_timeout_bk_sns: Option<u64>,
    pub max_en_decode_message_size: Option<u64>,
    /// Background interval for updating session status
    pub session_update_interval_secs: Option<u64>,
    /// Background interval for cleaning up completed sessions
    pub session_cleanup_interval_secs: Option<u64>,
    /// Background interval for discarding inactive sessions
    pub discard_inactive_sessions_interval: Option<u64>,
    /// Maximum waiting time for trying to push the message in the queue
    pub max_waiting_time_for_message_queue: Option<u64>,
    /// Maximum number of "Inactive" sessions a party can open before I refuse to open more
    pub max_opened_inactive_sessions_per_party: Option<u64>,
    /// Look-ahead window (in rounds) for buffering future-round messages from a
    /// peer that is ahead of us: a message more than this many rounds ahead of
    /// our current round is dropped rather than buffered. Larger tolerates more
    /// benign reordering/asynchrony but lets a peer make us reserve more memory.
    /// Should be `>= 1`; `0` disables future buffering and drops legitimate
    /// reordered messages.
    pub max_future_rounds: Option<u64>,
    /// Hard cap on the number of distinct future-round messages buffered per
    /// sender, independent of `max_future_rounds`. Bounds reordering-buffer
    /// memory against a peer flooding many distinct future round numbers.
    /// Should be `>= 1` to tolerate any reordering.
    pub max_buffered_future_msgs: Option<u64>,
}

impl CoreToCoreNetworkConfig {
    pub fn get_message_limit(&self) -> usize {
        self.message_limit
            .map(|v| v as usize)
            .unwrap_or(MESSAGE_LIMIT)
    }

    pub fn get_multiplier(&self) -> f64 {
        self.multiplier.unwrap_or(MULTIPLIER)
    }

    pub fn get_max_interval(&self) -> Duration {
        self.max_interval
            .map(Duration::from_secs)
            .unwrap_or(MAX_INTERVAL)
    }

    pub fn get_max_elapsed_time(&self) -> Option<Duration> {
        // Always bounded: an unset value falls back to MAX_ELAPSED_TIME rather
        // than "retry forever". (The old two-level wrapper returned `None` when
        // a config was supplied but this field omitted; that partial-config
        // corner is now defaulted like every other field.)
        Some(
            self.max_elapsed_time
                .map(Duration::from_secs)
                .unwrap_or(MAX_ELAPSED_TIME),
        )
    }

    pub fn get_network_timeout(&self) -> Duration {
        self.network_timeout
            .map(Duration::from_secs)
            .unwrap_or(NETWORK_TIMEOUT_LONG)
    }

    pub fn get_network_timeout_bk(&self) -> Duration {
        self.network_timeout_bk
            .map(Duration::from_secs)
            .unwrap_or(NETWORK_TIMEOUT_BK)
    }

    pub fn get_network_timeout_bk_sns(&self) -> Duration {
        self.network_timeout_bk_sns
            .map(Duration::from_secs)
            .unwrap_or(NETWORK_TIMEOUT_BK_SNS)
    }

    pub fn get_max_en_decode_message_size(&self) -> usize {
        self.max_en_decode_message_size
            .map(|v| v as usize)
            .unwrap_or(*MAX_EN_DECODE_MESSAGE_SIZE)
    }

    pub fn get_initial_interval(&self) -> Duration {
        Duration::from_millis(self.initial_interval_ms.unwrap_or(INITIAL_INTERVAL_MS))
    }

    pub fn get_session_update_interval(&self) -> Duration {
        Duration::from_secs(
            self.session_update_interval_secs
                .unwrap_or(SESSION_STATUS_UPDATE_INTERVAL_SECS),
        )
    }

    pub fn get_session_cleanup_interval(&self) -> Duration {
        Duration::from_secs(
            self.session_cleanup_interval_secs
                .unwrap_or(SESSION_CLEANUP_INTERVAL_SECS),
        )
    }

    pub fn get_discard_inactive_sessions_interval(&self) -> Duration {
        Duration::from_secs(
            self.discard_inactive_sessions_interval
                .unwrap_or(DISCARD_INACTIVE_SESSION_INTERVAL_SECS),
        )
    }

    pub fn get_max_opened_inactive_sessions_per_party(&self) -> u64 {
        self.max_opened_inactive_sessions_per_party
            .unwrap_or(MAX_OPENED_INACTIVE_SESSIONS_PER_PARTY)
    }

    pub fn get_max_waiting_time_for_message_queue(&self) -> Duration {
        Duration::from_secs(
            self.max_waiting_time_for_message_queue
                .unwrap_or(MAX_WAITING_TIME_MESSAGE_QUEUE),
        )
    }

    pub fn get_max_buffered_future_msgs(&self) -> usize {
        self.max_buffered_future_msgs
            .map(|v| v as usize)
            .unwrap_or(MAX_BUFFERED_FUTURE_MSGS)
    }
}

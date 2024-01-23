//! Constants for the exponential backoff policy for gRPC
use lazy_static::lazy_static;
use std::time::Duration;

/// The default incoming messages limit per party
pub(crate) const MESSAGE_LIMIT: usize = 70;

/// The default multiplier to determine the next interval between retries
pub(crate) const MULTIPLIER: f64 = 1.1;

lazy_static! {
    /// The default maximum internal between retries
    pub(crate) static ref MAX_INTERVAL: Duration = Duration::from_secs(5);

    /// The default maximum elapsed time before giving up on retrying
    pub(crate) static ref MAX_ELAPSED_TIME: Option<Duration> = Some(Duration::from_secs(5 * 60));

    /// maximum number of seconds that a party waits for a network message during a protocol
    pub(crate) static ref NETWORK_TIMEOUT: Duration = Duration::from_secs(5);

    /// maximum number of seconds that a party waits for a network message during a protocol
    pub(crate) static ref NETWORK_TIMEOUT_LONG: Duration = Duration::from_secs(60);

    // max message size for decoding - enconding message on gRPC protocol
    pub(crate) static ref MAX_EN_DECODE_MESSAGE_SIZE: usize = 1024 * 1024 * 1024;
}

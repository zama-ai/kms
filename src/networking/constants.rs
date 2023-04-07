//! Constants for the exponential backoff policy for gRPC
use lazy_static::lazy_static;
use std::time::Duration;

/// The default multiplier to determine the next interval between retries
pub(crate) const MULTIPLIER: f64 = 1.1;

lazy_static! {
    /// The default maximum internal between retries
    pub(crate) static ref MAX_INTERVAL: Duration = Duration::from_secs(5);

    /// The default maximum elapsed time before giving up on retrying
    pub(crate) static ref MAX_ELAPSED_TIME: Option<Duration> = Some(Duration::from_secs(5 * 60));
}

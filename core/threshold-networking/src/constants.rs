//! Constants for the exponential backoff policy for gRPC
use lazy_static::lazy_static;
use tokio::time::Duration;

/// The default incoming messages limit per party per session
pub(crate) const MESSAGE_LIMIT: usize = 70;

/// The default multiplier to determine the next interval between retries
pub(crate) const MULTIPLIER: f64 = 1.1;

/// The default maximum number of "Inactive" sessions a party can open
pub(crate) const MAX_OPENED_INACTIVE_SESSIONS_PER_PARTY: u64 = 2000;

/// The default initial interval for exponential backoff in milliseconds
pub(crate) const INITIAL_INTERVAL_MS: u64 = 100;

// The default time interval to update session status
pub(crate) const SESSION_STATUS_UPDATE_INTERVAL_SECS: u64 = 60;

// The default time interval after which we completely forget about completed sessions
pub(crate) const SESSION_CLEANUP_INTERVAL_SECS: u64 = 86400; // 24 hours

// The default time interval after which we discard inactive sessions, or active sessions that have not seen any activity
pub(crate) const DISCARD_INACTIVE_SESSION_INTERVAL_SECS: u64 = 15 * 60;

// The default maximum waiting time we wait for trying to push or fetch a message in the send/rec queue
pub(crate) const MAX_WAITING_TIME_MESSAGE_QUEUE: u64 = 60;

lazy_static! {
    /// The default maximum interval between retries (Cap at 60s intervals)
    pub static ref MAX_INTERVAL: Duration = Duration::from_secs(60);

    /// The default maximum elapsed time before giving up on retrying
    pub(crate) static ref MAX_ELAPSED_TIME: Option<Duration> = Some(Duration::from_secs(60));

    /// maximum number of seconds that a party waits for a network message during a protocol
    pub(crate) static ref NETWORK_TIMEOUT: Duration = Duration::from_secs(5);

    /// maximum number of seconds that a party waits for a network message during a protocol
    pub(crate) static ref NETWORK_TIMEOUT_LONG: Duration = Duration::from_secs(120);

    /// maximum number of seconds that a party waits for BK round in DKG
    ///
    /// __NOTE__ This value may need changing when running more parties (tested for (5,1))
    pub(crate) static ref NETWORK_TIMEOUT_BK: Duration = Duration::from_secs(300);

    /// Set artificial timeout of 1year for async network
    pub(crate) static ref NETWORK_TIMEOUT_ASYNC: Duration = Duration::from_secs(31536000);

    /// maximum number of seconds that a party waits for BK SNS round in DKG
    ///
    /// __NOTE__ This value may need changing when running more parties (tested for (5,1))
    pub(crate) static ref NETWORK_TIMEOUT_BK_SNS: Duration = Duration::from_secs(1200);

    // max message size for decoding - enconding message on gRPC protocol
    pub(crate) static ref MAX_EN_DECODE_MESSAGE_SIZE: usize = 2 * 1024 * 1024 * 1024;


}

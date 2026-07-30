//! Lock-free time helpers used by [`NetworkSession`](super::NetworkSession): a
//! monotonic activity clock and a [`Duration`] stored in an atomic.

use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Monotonic epoch for session activity timestamps.
///
/// Session activity times are stored as milliseconds elapsed since this instant
/// in an [`AtomicU64`], so they can be read and written without locking or
/// awaiting — notably from the session cleanup task, which must not hold a
/// `DashMap` shard guard across an `.await`.
static ACTIVITY_EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Milliseconds elapsed since [`ACTIVITY_EPOCH`].
pub(crate) fn now_activity_millis() -> u64 {
    ACTIVITY_EPOCH.elapsed().as_millis() as u64
}

/// A [`Duration`] stored as whole nanoseconds inside an [`AtomicU64`], so it can
/// be read and updated without holding a lock.
///
/// Network timeouts stay far below the u64 nanosecond ceiling (~584 years), so
/// the nanosecond encoding never truncates in practice. All operations use
/// [`Ordering::Relaxed`]: these values are only mutated while the owning
/// session's `round_counter` lock is held, and are otherwise best-effort timeout
/// hints that need no cross-variable ordering guarantees.
#[derive(Debug)]
pub(crate) struct AtomicDuration(AtomicU64);

impl AtomicDuration {
    /// Create a new [`AtomicDuration`] holding `d`.
    pub(crate) fn new(d: Duration) -> Self {
        Self(AtomicU64::new(d.as_nanos() as u64))
    }

    /// Read the current [`Duration`].
    pub(crate) fn load(&self) -> Duration {
        Duration::from_nanos(self.0.load(Ordering::Relaxed))
    }

    /// Overwrite the stored value with `d`.
    pub(crate) fn store(&self, d: Duration) {
        self.0.store(d.as_nanos() as u64, Ordering::Relaxed);
    }

    /// Add `d` to the stored value.
    pub(crate) fn fetch_add(&self, d: Duration) {
        self.0.fetch_add(d.as_nanos() as u64, Ordering::Relaxed);
    }
}

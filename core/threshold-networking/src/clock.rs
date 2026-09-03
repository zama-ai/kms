//! Lock-free time helpers shared by the networking implementations
//! ([`NetworkSession`](crate::sending_service::NetworkSession) and
//! [`LocalNetworking`](crate::local::LocalNetworking)): a [`Duration`] and an
//! [`Instant`] each stored in an atomic.

use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Monotonic epoch that atomically-stored [`Instant`]s ([`AtomicInstant`]) are
/// measured against.
///
/// Times are stored as a [`Duration`] elapsed since this instant inside an
/// [`AtomicU64`], so they can be read and written without locking or awaiting —
/// notably from the session cleanup task, which must not hold a `DashMap` shard
/// guard across an `.await`.
static ACTIVITY_EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

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

/// An [`Instant`] stored lock-free, as a [`Duration`] offset from
/// [`ACTIVITY_EPOCH`] inside an [`AtomicDuration`], so it can be read and
/// overwritten from `&self` without a lock or an `.await` — unlike a raw
/// `Instant`, which is immutable, or a `RwLock<Instant>`, which would force
/// `get_timeout_current_round` to await a lock.
///
/// Used as a session's round-clock anchor (`init_time`): stamped eagerly at
/// creation and, when the session synchronizes to another, overwritten with the
/// other's anchor. Nanosecond resolution.
#[derive(Debug)]
pub(crate) struct AtomicInstant(AtomicDuration);

impl AtomicInstant {
    /// An [`AtomicInstant`] holding the current time.
    pub(crate) fn now() -> Self {
        Self(AtomicDuration::new(ACTIVITY_EPOCH.elapsed()))
    }

    /// Read the current [`Instant`].
    pub(crate) fn load(&self) -> Instant {
        *ACTIVITY_EPOCH + self.0.load()
    }

    /// Overwrite the stored value with `t`. Saturates for any `t` before
    /// [`ACTIVITY_EPOCH`] — which cannot happen for instants taken after process
    /// start, but keeps the conversion total.
    pub(crate) fn store(&self, t: Instant) {
        self.0.store(t.saturating_duration_since(*ACTIVITY_EPOCH));
    }
}

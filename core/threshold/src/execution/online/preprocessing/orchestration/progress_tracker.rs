use std::{
    fmt::Display,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use crate::error::error_handler::anyhow_error_and_log;

struct InnerProgress {
    current: usize,
    next_reporting: usize,
    reporting_step: usize,
}

impl InnerProgress {
    /// Returns true if it's time to report
    fn update(&mut self, amount: usize) -> bool {
        self.current += amount;
        if self.current >= self.next_reporting {
            while self.next_reporting < self.current {
                self.next_reporting += self.reporting_step;
            }
            true
        } else {
            false
        }
    }

    fn get_current(&self) -> usize {
        self.current
    }
}

/// Tracks the progress of the offline phases.
///
/// NOTE: Can be cloned and sent accross threads as it uses
/// Arc underneath for the mutable part of its state.
#[derive(Clone)]
pub struct ProgressTracker {
    tracker_name: String,
    total: usize,
    current: Arc<RwLock<InnerProgress>>,
    creation_instant: Instant,
}

/// Reports progress at any given time
/// from the [`ProgressTracker`]
pub struct Progress {
    pub tracker_name: String,
    pub total: usize,
    pub current: usize,
    pub percentage_done: f64,
    pub duration_since_start: Duration,
}

impl Display for Progress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_finished() {
            write!(
                f,
                "\nFinished {}:
                \tTotal: {}
                \tTime elapsed (s): {}",
                self.tracker_name,
                self.total,
                self.duration_since_start.as_secs()
            )
        } else {
            let expected_time_remaining = (100f64 - self.percentage_done)
                * (self.duration_since_start.as_secs() as f64 / self.percentage_done);
            write!(
                f,
                "\nProgress {}:
                \tTotal: {}
                \tCurrent: {}
                \tPercentage done: {}
                \tTime elapsed (s): {}
                \tExpected time remaining (s): {}",
                self.tracker_name,
                self.total,
                self.current,
                self.percentage_done,
                self.duration_since_start.as_secs(),
                expected_time_remaining
            )
        }
    }
}

impl Progress {
    pub fn is_finished(&self) -> bool {
        self.current >= self.total
    }

    /// Logs the current progress at the info level
    pub fn log(&self) {
        tracing::info!("{}", self)
    }
}

impl ProgressTracker {
    /// Creates a new [`ProgressTracker`].
    /// - `tracker_name` is the name used when logging progress via [`Progress::log`]
    /// - `total` is the total amount of _things_ we need to generate
    /// - `reporting_interval_in_percentage` defines the interval (rounded up) at which a new call to [`Self::increment`]
    ///   triggers a [`Progress::log`] (must hold that 0 < `reporting_interval_in_percentage` <= 100)
    pub fn new(tracker_name: &str, total: usize, reporting_interval_in_percentage: usize) -> Self {
        assert!(reporting_interval_in_percentage > 0 && reporting_interval_in_percentage <= 100);
        let reporting_step = (total * reporting_interval_in_percentage).div_ceil(100);
        Self {
            tracker_name: tracker_name.to_string(),
            total,
            current: Arc::new(RwLock::new(InnerProgress {
                current: 0,
                next_reporting: reporting_step,
                reporting_step,
            })),
            creation_instant: Instant::now(),
        }
    }

    /// Increments the count of produced _things_ by `amount`.
    ///
    /// If incrementing causes to be in a new interval as defined by `reporting_interval_in_percentage`  
    /// in [`Self::new`], this automatically logs a [`Progress`].
    pub fn increment(&self, amount: usize) -> anyhow::Result<()> {
        let should_log = {
            let mut current_write = self
                .current
                .write()
                .map_err(|e| anyhow_error_and_log(format!("Locking Error: {e}")))?;
            current_write.update(amount)
        };
        if should_log {
            self.get_progress()?.log();
        }
        Ok(())
    }

    /// Reports current [`Progress`]
    pub fn get_progress(&self) -> anyhow::Result<Progress> {
        let total = self.total;
        let current = self
            .current
            .read()
            .map_err(|e| anyhow_error_and_log(format!("Locking Error: {e}")))?
            .get_current();
        let percentage_done = (current as f64 / total as f64) * 100.;
        Ok(Progress {
            tracker_name: self.tracker_name.to_string(),
            total,
            current,
            percentage_done,
            duration_since_start: self.creation_instant.elapsed(),
        })
    }
}

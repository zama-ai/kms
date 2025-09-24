//! Utilities for managing OS threads and Tokio tasks.

use anyhow::anyhow;
use futures::FutureExt;
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::error;

use crate::error::error_handler::anyhow_error_and_log;

#[derive(Debug, Default)]
pub struct ThreadHandleGroup {
    handles: Vec<JoinHandle<()>>,
}

impl ThreadHandleGroup {
    /// Create a new empty group of thread handles
    pub fn new() -> Self {
        tracing::info!(
            "Creating new ThreadHandleGroup. rayon::max_num_threads: {}, tokio::num_workers: {}.",
            rayon::max_num_threads(),
            tokio::runtime::Handle::current().metrics().num_workers()
        );
        Self {
            handles: Vec::new(),
        }
    }

    /// Add a new handle to the group
    pub fn add(&mut self, handle: JoinHandle<()>) {
        self.handles.push(handle);
    }

    /// Join all handles in the group, returning an error if any thread panicked
    pub async fn join_all(self) -> anyhow::Result<()> {
        for handle in self.handles {
            if let Err(e) = handle.await {
                if e.is_panic() {
                    // Get panic message if available
                    let panic_msg = e.into_panic();
                    if let Some(msg) = panic_msg.downcast_ref::<String>() {
                        error!("Task panicked: {}", msg);
                    } else {
                        error!("Task panicked with unknown message");
                    }
                    return Err(anyhow!("Task panicked"));
                }
                return Err(anyhow!("Task failed: {}", e));
            }
        }
        Ok(())
    }

    /// Join all handles in the group in a blocking manner
    /// This is useful when async context is not available, like in Drop implementations
    pub fn join_all_blocking(self) -> anyhow::Result<()> {
        // Simple blocking join with timeout using thread::sleep
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(20);

        'handle_loop: for handle in self.handles {
            while !handle.is_finished() {
                if start.elapsed() > timeout {
                    error!("Cleanup timed out, aborting the stalling task.");
                    handle.abort();
                    std::thread::sleep(Duration::from_secs(1));
                    continue 'handle_loop;
                }
                std::thread::sleep(Duration::from_millis(10));
            }

            // Handle is finished, we can safely wait on it
            match handle.now_or_never() {
                Some(Ok(_)) => (),
                Some(Err(e)) => {
                    if e.is_panic() {
                        error!("Task panicked during cleanup");
                        return Err(anyhow!("Task panicked during cleanup"));
                    }
                    if !e.is_cancelled() {
                        // Ignore cancellation errors from our abort
                        error!("Task failed during cleanup: {}", e);
                        return Err(anyhow!("Task failed during cleanup: {}", e));
                    }
                }
                None => {
                    error!("Task unexpectedly not finished after timeout check");
                    return Err(anyhow!("Task cleanup failed"));
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct OsThreadGroup<T> {
    handles: Vec<std::thread::JoinHandle<T>>,
}

impl<T> OsThreadGroup<T>
where
    T: Send + 'static,
{
    /// Create a new empty group of OS thread handles
    pub fn new() -> Self {
        Self {
            handles: Vec::new(),
        }
    }

    /// Add a new handle to the group
    pub fn add(&mut self, handle: std::thread::JoinHandle<T>) {
        self.handles.push(handle);
    }

    /// Join all handles in the group, returning an error if any thread panicked
    pub fn join_all(self) -> anyhow::Result<()> {
        for handle in self.handles {
            if let Err(e) = handle.join() {
                if let Some(msg) = e.downcast_ref::<String>() {
                    error!("Thread panicked: {}", msg);
                } else {
                    error!("Thread panicked with unknown message");
                }
                return Err(anyhow!("Thread panicked"));
            }
        }
        Ok(())
    }

    /// Join all handles in the group and collect their results
    pub fn join_all_with_results(self) -> anyhow::Result<Vec<T>> {
        let mut results = Vec::with_capacity(self.handles.len());
        for handle in self.handles {
            match handle.join() {
                Ok(result) => results.push(result),
                Err(e) => {
                    if let Some(msg) = e.downcast_ref::<String>() {
                        error!("Thread panicked: {}", msg);
                    } else {
                        error!("Thread panicked with unknown message");
                    }
                    return Err(anyhow!("Thread panicked"));
                }
            }
        }
        Ok(results)
    }
}

/// Spawn a compute task on rayon and returns its result.
///
/// This can be used to offload the tokio executor from CPU bound tasks.
pub async fn spawn_compute_bound<R: Send + 'static, F: FnOnce() -> R + Send + 'static>(
    compute_fn: F,
) -> anyhow::Result<R> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let current_span = tracing::Span::current();
    rayon::spawn(move || {
        let _guard = current_span.enter();
        let res = compute_fn();
        let _ = tx
            .send(res)
            .map_err(|_| ())
            .inspect_err(|_| tracing::warn!("compute task receiver dropped"));
    });

    rx.await
        .map_err(|_| anyhow_error_and_log("compute task sender dropped"))
}

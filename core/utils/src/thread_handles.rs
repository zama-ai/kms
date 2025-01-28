//! Utilities for managing OS threads and Tokio tasks.

use anyhow::anyhow;
use futures::FutureExt;
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::error;

#[derive(Debug, Default)]
pub struct ThreadHandleGroup {
    handles: Vec<JoinHandle<()>>,
}

impl ThreadHandleGroup {
    /// Create a new empty group of thread handles
    pub fn new() -> Self {
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
        // Try to abort handles first to prevent hanging
        for handle in &self.handles {
            handle.abort();
        }

        // Simple blocking join with timeout using thread::sleep
        let start = std::time::Instant::now();
        let timeout = Duration::from_secs(10);

        for handle in self.handles {
            while !handle.is_finished() {
                if start.elapsed() > timeout {
                    error!("Cleanup timed out");
                    return Err(anyhow!("Cleanup timed out"));
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

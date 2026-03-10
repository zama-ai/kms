//! Utilities for managing OS threads and Tokio tasks.

use anyhow::anyhow;
use rayon::ThreadPoolBuilder;
use tokio::sync::OnceCell;
use tracing::error;

use crate::error::error_handler::anyhow_error_and_log;

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

static MPC_RAYON_THREAD_POOL: OnceCell<rayon::ThreadPool> = OnceCell::const_new();

// Try to initialize the global rayon thread pool with the given number of threads.
// Returns the number of threads in the pool.
pub async fn init_rayon_thread_pool(num_threads: usize) -> anyhow::Result<usize> {
    if MPC_RAYON_THREAD_POOL.initialized() {
        return Err(anyhow!("Rayon thread pool already initialized"));
    }

    let pool = MPC_RAYON_THREAD_POOL
        .get_or_try_init(|| async { ThreadPoolBuilder::new().num_threads(num_threads).build() })
        .await?;

    tracing::info!(
        "Initialized rayon thread pool with {} threads",
        pool.current_num_threads()
    );

    Ok(pool.current_num_threads())
}

/// Spawn a compute task on rayon and returns its result.
///
/// This can be used to offload the tokio executor from CPU bound tasks.
pub async fn spawn_compute_bound<R: Send + 'static, F: FnOnce() -> R + Send + 'static>(
    compute_fn: F,
) -> anyhow::Result<R> {
    let pool = MPC_RAYON_THREAD_POOL
        .get_or_try_init(|| async { ThreadPoolBuilder::new().build() })
        .await?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let current_span = tracing::Span::current();
    pool.spawn(move || {
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

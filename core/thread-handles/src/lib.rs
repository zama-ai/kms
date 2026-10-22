//! Utilities for managing OS threads and Tokio tasks.

use std::any::Any;
use std::time::Instant;

use rayon::ThreadPoolBuilder;
use tokio::sync::OnceCell;

use error_utils::anyhow_error_and_log;

/// Thread-name prefix of the MPC rayon pool. The sys-metrics sampler groups per-thread CPU by
/// this prefix (`kms_thread_pool_cpu_usage{pool="rayon"}`), so keep it in sync with
/// `observability::sys_metrics::RAYON_THREAD_NAME_PREFIX`.
pub const RAYON_THREAD_NAME_PREFIX: &str = "mpc-rayon";

/// Extract a human-readable message from a panic payload.
fn panic_message(payload: Box<dyn Any + Send>) -> String {
    match payload.downcast::<String>() {
        Ok(s) => *s,
        Err(payload) => match payload.downcast::<&str>() {
            Ok(s) => (*s).to_owned(),
            Err(_) => "unknown cause".to_owned(),
        },
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
                let msg = panic_message(e);
                return Err(anyhow_error_and_log(format!("Thread panicked: {}", msg)));
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
                    let msg = panic_message(e);
                    return Err(anyhow_error_and_log(format!("Thread panicked: {}", msg)));
                }
            }
        }
        Ok(results)
    }
}

static MPC_RAYON_THREAD_POOL: OnceCell<rayon::ThreadPool> = OnceCell::const_new();

fn named_pool_builder() -> ThreadPoolBuilder {
    ThreadPoolBuilder::new().thread_name(|index| format!("{RAYON_THREAD_NAME_PREFIX}-{index}"))
}

/// Try to initialize the global rayon thread pool with the given number of threads.
/// Returns the number of threads in the pool.
pub async fn init_rayon_thread_pool(num_threads: usize) -> anyhow::Result<usize> {
    let pool = MPC_RAYON_THREAD_POOL
        .get_or_try_init(|| async { named_pool_builder().num_threads(num_threads).build() })
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
///
/// The setup overhead introduced by this call is ~25µs.
pub async fn spawn_compute_bound<R: Send + 'static, F: FnOnce() -> R + Send + 'static>(
    compute_fn: F,
) -> anyhow::Result<R> {
    spawn_compute_bound_deferred(compute_fn).await?.await
}

/// A rayon computation that has already been submitted; `.await` it to collect the result.
///
/// The work starts as soon as a rayon thread is free, whether or not the handle is polled, so
/// a caller can submit the work, do something else (typically wait on the network), and only
/// then await the result. Dropping the handle discards the result when it arrives.
pub struct ComputeHandle<R> {
    rx: tokio::sync::oneshot::Receiver<R>,
}

impl<R> std::future::Future for ComputeHandle<R> {
    type Output = anyhow::Result<R>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        // `oneshot::Receiver` is `Unpin`, so re-pinning the field is sound.
        std::future::Future::poll(std::pin::Pin::new(&mut self.rx), cx)
            .map(|res| res.map_err(|_| anyhow_error_and_log("compute task sender dropped")))
    }
}

/// Submit `compute_fn` to the rayon pool now and return a handle that yields its result when
/// awaited. See [`ComputeHandle`]; [`spawn_compute_bound`] is this followed by an immediate
/// await.
pub async fn spawn_compute_bound_deferred<R: Send + 'static, F: FnOnce() -> R + Send + 'static>(
    compute_fn: F,
) -> anyhow::Result<ComputeHandle<R>> {
    let pool = MPC_RAYON_THREAD_POOL
        .get_or_try_init(|| async { named_pool_builder().build() })
        .await?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let current_span = tracing::Span::current();
    let diagnostics = &*observability::diag_metrics::DIAG;
    let submitted = Instant::now();
    pool.spawn(move || {
        diagnostics.observe_detail("rayon_queue", submitted.elapsed());
        let _guard = current_span.enter();
        let execution_timer = diagnostics.time_detail("rayon_execute");
        let res = compute_fn();
        drop(execution_timer);
        // Benign: the awaiting future was cancelled, or a deferred result was no longer wanted
        // (e.g. the last PRSS prefetch of a session). Debug level so that it does not flood the
        // log at the end of a preprocessing run.
        let _ = tx
            .send(res)
            .map_err(|_| ())
            .inspect_err(|_| tracing::debug!("compute task receiver dropped"));
    });

    Ok(ComputeHandle { rx })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn deferred_work_starts_before_its_handle_is_awaited() {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let work = spawn_compute_bound_deferred(move || {
            started_tx.send(()).unwrap();
            42
        })
        .await
        .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), started_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(work.await.unwrap(), 42);
        assert_eq!(spawn_compute_bound(|| 7).await.unwrap(), 7);
    }
}

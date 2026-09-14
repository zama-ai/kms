//! Utilities for managing OS threads and Tokio tasks.

use std::any::Any;

use rayon::ThreadPoolBuilder;
use tokio::sync::OnceCell;

use error_utils::anyhow_error_and_log;

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

struct ComputePools {
    shared: rayon::ThreadPool,
    parties: Vec<rayon::ThreadPool>,
}

impl ComputePools {
    fn build(shared_threads: usize, party_threads: usize, parties: usize) -> anyhow::Result<Self> {
        let shared = ThreadPoolBuilder::new()
            .num_threads(shared_threads)
            .build()?;
        let parties = (0..if party_threads == 0 { 0 } else { parties })
            .map(|_| ThreadPoolBuilder::new().num_threads(party_threads).build())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { shared, parties })
    }

    fn for_party(&self, one_based_party: usize) -> &rayon::ThreadPool {
        one_based_party
            .checked_sub(1)
            .and_then(|index| self.parties.get(index))
            .unwrap_or(&self.shared)
    }
}

static MPC_RAYON_THREAD_POOL: OnceCell<ComputePools> = OnceCell::const_new();

fn pool_allocation(budget: usize, parties: usize) -> (usize, usize) {
    let per_party = budget / parties.saturating_add(1);
    (per_party, budget - parties * per_party)
}

/// Initializes party-specific PRSS pools for an in-process test cluster.
///
/// Reserves shared workers within `budget`, and uses only the shared pool when
/// the budget cannot provide one worker per party plus one shared worker.
/// The first initialization wins for the process; run different cluster sizes
/// in separate test processes to exercise their respective allocations.
/// Returns the actual party-pool count, workers per party, and shared workers.
/// Returns an error for zero inputs or if a worker pool cannot be created.
pub async fn init_partitioned_rayon_thread_pool(
    budget: usize,
    parties: usize,
) -> anyhow::Result<(usize, usize, usize)> {
    anyhow::ensure!(
        budget > 0 && parties > 0,
        "Thread budget and party count must be positive"
    );
    let (per_party, shared) = pool_allocation(budget, parties);
    let pools = MPC_RAYON_THREAD_POOL
        .get_or_try_init(|| async { ComputePools::build(shared, per_party, parties) })
        .await?;
    let actual = (
        pools.parties.len(),
        pools
            .parties
            .first()
            .map_or(0, rayon::ThreadPool::current_num_threads),
        pools.shared.current_num_threads(),
    );
    let expected = (if per_party == 0 { 0 } else { parties }, per_party, shared);
    if actual != expected {
        tracing::warn!(
            ?expected,
            ?actual,
            "Compute pools were already initialized with a different allocation"
        );
    }
    tracing::info!(
        party_pools = actual.0,
        threads_per_party = actual.1,
        shared_threads = actual.2,
        "Test compute pool allocation"
    );
    Ok(actual)
}

/// Try to initialize the global rayon thread pool with the given number of threads.
/// Returns the number of threads in the pool.
pub async fn init_rayon_thread_pool(num_threads: usize) -> anyhow::Result<usize> {
    let pool = MPC_RAYON_THREAD_POOL
        .get_or_try_init(|| async { ComputePools::build(num_threads, 0, 0) })
        .await?;

    tracing::info!(
        "Initialized rayon thread pool with {} threads",
        pool.shared.current_num_threads()
    );

    Ok(pool.shared.current_num_threads())
}

/// Spawn a compute task on rayon and returns its result.
///
/// This can be used to offload the tokio executor from CPU bound tasks.
///
/// The setup overhead introduced by this call is ~25µs.
pub async fn spawn_compute_bound<R: Send + 'static, F: FnOnce() -> R + Send + 'static>(
    compute_fn: F,
) -> anyhow::Result<R> {
    let pools = MPC_RAYON_THREAD_POOL
        .get_or_try_init(|| async { ComputePools::build(0, 0, 0) })
        .await?;
    spawn_on_pool(&pools.shared, compute_fn).await
}

/// Runs party-specific computation on its configured pool, or the shared pool.
///
/// `one_based_party` identifies a party within the test cluster. Without a
/// partitioned allocation, this has the same routing as [`spawn_compute_bound`].
/// Returns an error if pool creation or result delivery fails.
pub async fn spawn_compute_bound_for_party<R: Send + 'static, F: FnOnce() -> R + Send + 'static>(
    one_based_party: usize,
    compute_fn: F,
) -> anyhow::Result<R> {
    let pools = MPC_RAYON_THREAD_POOL
        .get_or_try_init(|| async { ComputePools::build(0, 0, 0) })
        .await?;
    spawn_on_pool(pools.for_party(one_based_party), compute_fn).await
}

async fn spawn_on_pool<R: Send + 'static, F: FnOnce() -> R + Send + 'static>(
    pool: &rayon::ThreadPool,
    compute_fn: F,
) -> anyhow::Result<R> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let current_span = tracing::Span::current();
    let queued_at = tracing::enabled!(target: "kms_timeout_probe", tracing::Level::DEBUG)
        .then(std::time::Instant::now);
    tracing::debug!(target: "kms_timeout_probe", "compute_queued");
    pool.spawn(move || {
        let _guard = current_span.enter();
        let started_at = queued_at.map(|_| std::time::Instant::now());
        tracing::debug!(target: "kms_timeout_probe",
            queue_ms = queued_at.map(|t| t.elapsed().as_millis() as u64), "compute_started");
        let res = compute_fn();
        tracing::debug!(target: "kms_timeout_probe",
            run_ms = started_at.map(|t| t.elapsed().as_millis() as u64), "compute_finished");
        let _ = tx
            .send(res)
            .map_err(|_| ())
            .inspect_err(|_| tracing::warn!("compute task receiver dropped"));
    });

    let result = rx
        .await
        .map_err(|_| anyhow_error_and_log("compute task sender dropped"));
    tracing::debug!(target: "kms_timeout_probe",
        total_ms = queued_at.map(|t| t.elapsed().as_millis() as u64), "compute_resumed");
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use rayon::prelude::*;
    use std::collections::HashSet;

    #[test]
    fn hardware_allocation_preserves_budget() {
        for (budget, parties, expected) in [
            (56, 13, (4, 4)),
            (28, 13, (2, 2)),
            (15, 13, (1, 2)),
            (13, 13, (0, 13)),
            (1, 13, (0, 1)),
        ] {
            let (per_party, shared) = pool_allocation(budget, parties);
            assert_eq!((per_party, shared), expected);
            assert_eq!(per_party * parties + shared, budget);
        }
    }

    fn worker_ids() -> HashSet<std::thread::ThreadId> {
        rayon::broadcast(|_| std::thread::current().id())
            .into_iter()
            .collect()
    }

    #[tokio::test]
    async fn party_computation_uses_separate_pools() {
        assert!(init_partitioned_rayon_thread_pool(0, 3).await.is_err());
        assert!(init_partitioned_rayon_thread_pool(8, 0).await.is_err());
        assert_eq!(
            init_partitioned_rayon_thread_pool(8, 3).await.unwrap(),
            (3, 2, 2)
        );
        // The harness initializes the shared pool again after selecting the allocation.
        assert_eq!(init_rayon_thread_pool(8).await.unwrap(), 2);
        let shared = spawn_compute_bound(worker_ids).await.unwrap();
        assert_eq!(shared.len(), 2);
        let mut all_workers = shared.clone();
        for party in 1..=3 {
            let (workers, sum) = spawn_compute_bound_for_party(party, || {
                let sum = (0..1000_u64).into_par_iter().sum::<u64>();
                (worker_ids(), sum)
            })
            .await
            .unwrap();
            assert_eq!(sum, 499500);
            assert_eq!(workers.len(), 2);
            assert!(all_workers.is_disjoint(&workers));
            all_workers.extend(workers);
        }
        assert_eq!(all_workers.len(), 8);
        for unknown_party in [0, 4] {
            assert_eq!(
                spawn_compute_bound_for_party(unknown_party, worker_ids)
                    .await
                    .unwrap(),
                shared
            );
        }
        assert_eq!(
            init_partitioned_rayon_thread_pool(56, 13).await.unwrap(),
            (3, 2, 2)
        );
    }

    #[tokio::test]
    async fn unpartitioned_computation_uses_shared_pool() {
        let pools = ComputePools::build(2, 0, 13).unwrap();
        let shared = spawn_on_pool(&pools.shared, worker_ids).await.unwrap();
        assert_eq!(
            spawn_on_pool(pools.for_party(13), worker_ids)
                .await
                .unwrap(),
            shared
        );
    }
}

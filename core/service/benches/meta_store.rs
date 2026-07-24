//! Benchmarks for request tracking in `MetaStore`.
//!
//! Run all groups with:
//!
//! ```text
//! cargo bench -p kms --bench meta_store --features testing
//! ```
//!
//! To save a Criterion baseline, add `-- --save-baseline <name>`.
//!
//! The suite measures request admission, completion, retrieval, eviction, deletion, collection by
//! status, and concurrent access. `MetaStoreBenchmark` is a small wrapper in the `testing` module.
//! Criterion benchmarks compile as separate crates and cannot call crate-private code, so the
//! wrapper exposes only the production metastore operations used here.
//!
//! These benchmarks cover the in-memory store only. They do not start a KMS service or include gRPC,
//! cryptography, persistence, or other request work. Each group creates a default Tokio runtime, so
//! the production Tokio/Rayon thread split is not applied.
//!
//! # Benchmark groups
//!
//! - `lifecycle`: admit and complete requests without eviction.
//! - `steady_state_eviction`: admit and complete requests after the store is full.
//! - `eviction_position`: evict entries from different positions in the completion queue.
//! - `retrieval`: retrieve a completed request's result.
//! - `retry_failed`: admit a request again after it has failed.
//! - `retry_position`: retry failed requests from different completion-queue positions.
//! - `tombstone_completed`: delete completed requests from stores of different sizes.
//! - `tombstone_position`: delete requests from different completion-queue positions.
//! - `scans`: collect all request IDs or only those with a given status.
//! - `contention`: admit and complete requests with and without readers.
//! - `status_scan_contention`: admit and complete while collecting IDs of processing requests.

use criterion::{
    BatchSize, BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main,
};
use kms_grpc::RequestId;
use kms_lib::{
    consts::{DEC_CAPACITY, MIN_DEC_CACHE},
    engine::base::derive_request_id,
    testing::meta_store::{MetaStoreBenchmark, MetaStoreScan},
    util::meta_store::MetaStorePermit,
};
use std::{
    cell::Cell,
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{runtime::Runtime, sync::Barrier};

/// Measures admission and successful completion when the store has room for every request.
/// No entries are evicted.
fn lifecycle(c: &mut Criterion) {
    // Matching the store capacity avoids eviction in this benchmark.
    const REQUESTS_PER_ITERATION: usize = 512;

    let runtime = Runtime::new().expect("the benchmark Tokio runtime should start");
    let request_ids = request_ids("lifecycle", REQUESTS_PER_ITERATION);
    let request_ids = request_ids.as_slice();

    let mut group = c.benchmark_group("meta_store/lifecycle");
    group.throughput(Throughput::Elements(REQUESTS_PER_ITERATION as u64));
    group.bench_function("admit_and_complete", |b| {
        b.to_async(&runtime).iter_batched(
            || MetaStoreBenchmark::new(REQUESTS_PER_ITERATION, 0),
            |store| async move {
                complete_requests(&store, request_ids).await;
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

/// Measures repeated admission and successful completion after the store is full.
/// Each admission evicts the oldest completed entry that is not locked.
fn steady_state_eviction(c: &mut Criterion) {
    let runtime = Runtime::new().expect("the benchmark Tokio runtime should start");
    let first_ids = request_ids("steady-state-first", DEC_CAPACITY);
    let second_ids = request_ids("steady-state-second", DEC_CAPACITY);
    let store = runtime.block_on(async {
        let store = MetaStoreBenchmark::new(DEC_CAPACITY, MIN_DEC_CACHE);
        complete_requests(&store, &first_ids).await;
        store
    });
    let mut use_first_ids = false;

    let mut group = c.benchmark_group("meta_store/steady_state");
    group.throughput(Throughput::Elements(DEC_CAPACITY as u64));
    group.bench_function("evict_admit_and_complete", |b| {
        b.to_async(&runtime).iter(|| {
            let request_ids = if use_first_ids {
                &first_ids
            } else {
                &second_ids
            };
            use_first_ids = !use_first_ids;
            async {
                complete_requests(&store, request_ids).await;
            }
        });
    });
    group.finish();
}

/// Compares eviction cost when the first unlocked completed entry is at different positions in the
/// completion queue.
fn eviction_position(c: &mut Criterion) {
    // Cover the front, near-front, midpoint, and back of a full queue.
    const POSITIONS: [usize; 7] = [0, 1, 10, 100, 1_000, 5_000, DEC_CAPACITY - 1];

    let runtime = Runtime::new().expect("the benchmark Tokio runtime should start");
    let initial_ids = request_ids("eviction-position-initial", DEC_CAPACITY);
    let mut group = c.benchmark_group("meta_store/eviction_position");
    group.throughput(Throughput::Elements(1));

    for position in POSITIONS {
        let (store, _held_permits) = runtime.block_on(async {
            let store = MetaStoreBenchmark::new(DEC_CAPACITY, 0);
            complete_requests(&store, &initial_ids).await;

            let mut held_permits = Vec::with_capacity(position);
            for request_id in &initial_ids[..position] {
                held_permits.push(
                    store
                        .hold(request_id)
                        .await
                        .expect("completed fixture entries should be holdable"),
                );
            }
            (store, held_permits)
        });

        // The queue has `DEC_CAPACITY - position` evictable entries. One extra
        // request ID ensures an ID has been evicted before the benchmark cycles
        // around and admits it again.
        let candidate_ids = request_ids(
            &format!("eviction-position-candidate-{position}"),
            DEC_CAPACITY - position + 1,
        );
        let next_candidate = Cell::new(0);

        group.bench_with_input(BenchmarkId::from_parameter(position), &position, |b, _| {
            b.to_async(&runtime).iter(|| {
                let candidate_index = next_candidate.get();
                next_candidate.set((candidate_index + 1) % candidate_ids.len());
                let request_id = candidate_ids[candidate_index];
                let store = store.clone();
                async move {
                    let permit = store
                        .admit(&request_id)
                        .await
                        .expect("the next candidate should already have been evicted");
                    assert!(store.complete(permit, candidate_index as u64).await);
                }
            });
        });
    }
    group.finish();
}

/// Measures repeated retrieval of one successful result.
/// The store does not change between retrievals.
fn retrieval(c: &mut Criterion) {
    let runtime = Runtime::new().expect("the benchmark Tokio runtime should start");
    let request_id = request_ids("retrieval", 1)[0];
    let store = runtime.block_on(async {
        let store = MetaStoreBenchmark::new(1, 1);
        let permit = store
            .admit(&request_id)
            .await
            .expect("the retrieval fixture should be admissible");
        assert!(store.complete(permit, 42_u64).await);
        store
    });

    c.bench_function("meta_store/retrieve_completed", |b| {
        b.to_async(&runtime).iter(|| async {
            black_box(
                store
                    .retrieve(&request_id)
                    .await
                    .expect("the completed fixture should be retrievable"),
            );
        });
    });
}

/// Measures admitting one failed request again in stores of different sizes.
/// Every other request has completed successfully.
fn retry_failed(c: &mut Criterion) {
    // Measure several separately allocated stores to average out noise from
    // memory placement and CPU-cache effects.
    const STORE_COUNT: usize = 4;

    let runtime = Runtime::new().expect("the benchmark Tokio runtime should start");
    let mut group = c.benchmark_group("meta_store/retry_failed");
    group.throughput(Throughput::Elements(1));

    for size in [100, 1_000, DEC_CAPACITY] {
        let successful_ids = request_ids(&format!("retry-successful-{size}"), size - 1);
        let failed_id = request_ids(&format!("retry-failed-{size}"), 1)[0];
        let stores = runtime.block_on(async {
            let mut stores = Vec::with_capacity(STORE_COUNT);
            for _ in 0..STORE_COUNT {
                let store = MetaStoreBenchmark::new(size, 0);
                complete_requests(&store, &successful_ids).await;
                let permit = store
                    .admit(&failed_id)
                    .await
                    .expect("the failed fixture should be admissible");
                assert!(store.fail(permit).await);
                stores.push(store);
            }
            stores
        });

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            let stores = &stores;
            b.to_async(&runtime).iter_custom(|iterations| async move {
                let mut measured = Duration::ZERO;
                let iterations_per_store = iterations / stores.len() as u64;
                let remainder = iterations % stores.len() as u64;
                for (index, store) in stores.iter().enumerate() {
                    let store_iterations =
                        iterations_per_store + u64::from(index < remainder as usize);
                    for _ in 0..store_iterations {
                        let start = Instant::now();
                        let permit = store
                            .admit(&failed_id)
                            .await
                            .expect("a failed benchmark request should be retryable");
                        measured += start.elapsed();

                        // Restore the failed fixture without including that work in
                        // the retry-admission measurement.
                        assert!(store.fail(permit).await);
                    }
                }
                measured
            });
        });
    }
    group.finish();
}

/// Compares retry cost when the failed request is at different positions in a full completion
/// queue. Every request is failed, so each position remains retryable as the queue rotates.
fn retry_position(c: &mut Criterion) {
    const POSITIONS: [usize; 7] = [0, 1, 10, 100, 1_000, 5_000, DEC_CAPACITY - 1];
    const STORE_COUNT: usize = 4;

    let runtime = Runtime::new().expect("the benchmark Tokio runtime should start");
    let failed_ids = request_ids("retry-position", DEC_CAPACITY);
    let mut group = c.benchmark_group("meta_store/retry_position");
    group.throughput(Throughput::Elements(1));

    for position in POSITIONS {
        let stores = runtime.block_on(async {
            let mut stores = Vec::with_capacity(STORE_COUNT);
            for _ in 0..STORE_COUNT {
                let store = MetaStoreBenchmark::new(DEC_CAPACITY, 0);
                fail_requests(&store, &failed_ids).await;
                stores.push(store);
            }
            stores
        });
        let completed_ids = Arc::new(Mutex::new(vec![
            failed_ids
                .iter()
                .copied()
                .collect::<VecDeque<_>>();
            STORE_COUNT
        ]));

        group.bench_with_input(BenchmarkId::from_parameter(position), &position, |b, _| {
            b.to_async(&runtime).iter_custom(|iterations| {
                let stores = &stores;
                let completed_ids = Arc::clone(&completed_ids);
                async move {
                    let mut measured = Duration::ZERO;
                    let iterations_per_store = iterations / stores.len() as u64;
                    let remainder = iterations % stores.len() as u64;

                    for (store_index, store) in stores.iter().enumerate() {
                        let store_iterations =
                            iterations_per_store + u64::from(store_index < remainder as usize);
                        for _ in 0..store_iterations {
                            let request_id = completed_ids
                                .lock()
                                .expect("the retry queue model lock should not be poisoned")
                                [store_index][position];
                            let start = Instant::now();
                            let permit = store
                                .admit(&request_id)
                                .await
                                .expect("the selected failed request should be retryable");
                            measured += start.elapsed();

                            assert!(store.fail(permit).await);
                            let mut completed_ids = completed_ids
                                .lock()
                                .expect("the retry queue model lock should not be poisoned");
                            let removed = completed_ids[store_index].remove(position).expect(
                                "the retried request should remain at the selected position",
                            );
                            assert_eq!(removed, request_id);
                            completed_ids[store_index].push_back(request_id);
                        }
                    }
                    measured
                }
            });
        });
    }
    group.finish();
}

/// Measures deleting the oldest completed requests from stores of different sizes.
/// Both the permit-based and permit-free production paths are covered.
fn tombstone_completed(c: &mut Criterion) {
    // Rebuild the store periodically to limit the number of tombstones kept in
    // storage without making setup a large part of each measured deletion.
    const DELETIONS_PER_STORE: usize = 512;

    let runtime = Runtime::new().expect("the benchmark Tokio runtime should start");
    let mut group = c.benchmark_group("meta_store/tombstone_completed");
    group.throughput(Throughput::Elements(1));

    for size in [100, 1_000, DEC_CAPACITY] {
        let initial_ids = request_ids(&format!("tombstone-initial-{size}"), size);
        let replacement_ids = request_ids(
            &format!("tombstone-replacement-{size}"),
            DELETIONS_PER_STORE,
        );

        group.bench_with_input(BenchmarkId::new("delete", size), &size, |b, _| {
            b.to_async(&runtime).iter_custom(|iterations| {
                measure_completed_deletions(
                    &initial_ids,
                    &replacement_ids,
                    DELETIONS_PER_STORE,
                    iterations,
                    true,
                    0,
                )
            });
        });
        group.bench_with_input(BenchmarkId::new("try_delete", size), &size, |b, _| {
            b.to_async(&runtime).iter_custom(|iterations| {
                measure_completed_deletions(
                    &initial_ids,
                    &replacement_ids,
                    DELETIONS_PER_STORE,
                    iterations,
                    false,
                    0,
                )
            });
        });
    }
    group.finish();
}

/// Compares permit-free deletion cost at different positions in a full completion queue.
/// Each deleted request is replaced so every measurement sees the same queue length and position.
fn tombstone_position(c: &mut Criterion) {
    const DELETIONS_PER_STORE: usize = 512;
    const POSITIONS: [usize; 7] = [0, 1, 10, 100, 1_000, 5_000, DEC_CAPACITY - 1];

    let runtime = Runtime::new().expect("the benchmark Tokio runtime should start");
    let initial_ids = request_ids("tombstone-position-initial", DEC_CAPACITY);
    let replacement_ids = request_ids("tombstone-position-replacement", DELETIONS_PER_STORE);
    let mut group = c.benchmark_group("meta_store/tombstone_position");
    group.throughput(Throughput::Elements(1));

    for position in POSITIONS {
        group.bench_with_input(BenchmarkId::from_parameter(position), &position, |b, _| {
            b.to_async(&runtime).iter_custom(|iterations| {
                measure_completed_deletions(
                    &initial_ids,
                    &replacement_ids,
                    DELETIONS_PER_STORE,
                    iterations,
                    false,
                    position,
                )
            });
        });
    }
    group.finish();
}

/// Measures collecting all request IDs or only successful, processing, failed, or deleted IDs.
/// The store size varies from 100 entries to its configured capacity.
fn scans(c: &mut Criterion) {
    // Measure several separately allocated stores to average out noise from
    // memory placement and CPU-cache effects.
    const STORE_COUNT: usize = 4;

    let runtime = Runtime::new().expect("the benchmark Tokio runtime should start");
    let mut group = c.benchmark_group("meta_store/scans");

    for size in [100, 1_000, DEC_CAPACITY] {
        let successful_ids = request_ids(&format!("scan-successful-{size}"), size);
        let successful_stores = runtime.block_on(async {
            let mut stores = Vec::with_capacity(STORE_COUNT);
            for _ in 0..STORE_COUNT {
                let store = MetaStoreBenchmark::new(size, 0);
                complete_requests(&store, &successful_ids).await;
                stores.push(store);
            }
            stores
        });

        let processing_ids = request_ids(&format!("scan-processing-{size}"), size);
        let (processing_stores, _processing_permits) = runtime.block_on(async {
            let mut stores = Vec::with_capacity(STORE_COUNT);
            let mut permit_sets = Vec::with_capacity(STORE_COUNT);
            for _ in 0..STORE_COUNT {
                let store: MetaStoreBenchmark<u64> = MetaStoreBenchmark::new(size, 0);
                let mut permits = Vec::with_capacity(size);
                for request_id in &processing_ids {
                    permits.push(
                        store
                            .admit(request_id)
                            .await
                            .expect("the processing fixture should be admissible"),
                    );
                }
                stores.push(store);
                permit_sets.push(permits);
            }
            (stores, permit_sets)
        });

        let failed_ids = request_ids(&format!("scan-failed-{size}"), size);
        let failed_stores = runtime.block_on(async {
            let mut stores = Vec::with_capacity(STORE_COUNT);
            for _ in 0..STORE_COUNT {
                let store = MetaStoreBenchmark::new(size, 0);
                fail_requests(&store, &failed_ids).await;
                stores.push(store);
            }
            stores
        });

        let deleted_ids = request_ids(&format!("scan-deleted-{size}"), size);
        let deleted_stores = runtime.block_on(async {
            let mut stores = Vec::with_capacity(STORE_COUNT);
            for _ in 0..STORE_COUNT {
                let store = MetaStoreBenchmark::new(size, 0);
                for request_id in &deleted_ids {
                    let permit = store
                        .admit(request_id)
                        .await
                        .expect("the deleted scan entry should be admissible");
                    assert!(store.delete(permit).await);
                }
                stores.push(store);
            }
            stores
        });

        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::new("all", size), &size, |b, _| {
            b.to_async(&runtime).iter_custom(|iterations| {
                measure_scan_pool(&successful_stores, MetaStoreScan::All, size, iterations)
            });
        });
        group.bench_with_input(BenchmarkId::new("successful", size), &size, |b, _| {
            b.to_async(&runtime).iter_custom(|iterations| {
                measure_scan_pool(
                    &successful_stores,
                    MetaStoreScan::Successful,
                    size,
                    iterations,
                )
            });
        });
        group.bench_with_input(BenchmarkId::new("processing", size), &size, |b, _| {
            b.to_async(&runtime).iter_custom(|iterations| {
                measure_scan_pool(
                    &processing_stores,
                    MetaStoreScan::Processing,
                    size,
                    iterations,
                )
            });
        });
        group.bench_with_input(BenchmarkId::new("failed", size), &size, |b, _| {
            b.to_async(&runtime).iter_custom(|iterations| {
                measure_scan_pool(&failed_stores, MetaStoreScan::Failed, size, iterations)
            });
        });
        group.bench_with_input(BenchmarkId::new("deleted", size), &size, |b, _| {
            b.to_async(&runtime).iter_custom(|iterations| {
                measure_scan_pool(&deleted_stores, MetaStoreScan::Deleted, size, iterations)
            });
        });
    }
    group.finish();
}

/// Measures admission and completion with 1, 8, or 32 concurrent writers.
/// Each case is repeated with the same number of readers retrieving one completed result.
fn contention(c: &mut Criterion) {
    // Repeating the operation makes task startup a smaller part of the result.
    const OPERATIONS_PER_WORKER: usize = 64;

    let runtime = Runtime::new().expect("the benchmark Tokio runtime should start");
    let mut group = c.benchmark_group("meta_store/contention");

    for workers in [1, 8, 32] {
        let writer_ops = workers * OPERATIONS_PER_WORKER;
        let request_ids = Arc::new(request_ids(
            &format!("contention-{workers}"),
            writer_ops + 1,
        ));

        group.throughput(Throughput::Elements(writer_ops as u64));
        group.bench_with_input(BenchmarkId::new("writers", workers), &workers, |b, _| {
            b.to_async(&runtime).iter_batched(
                || MetaStoreBenchmark::new(writer_ops, 0),
                |store| {
                    let request_ids = Arc::clone(&request_ids);
                    async move {
                        run_contention(store, request_ids, workers, OPERATIONS_PER_WORKER, false)
                            .await;
                    }
                },
                BatchSize::SmallInput,
            );
        });

        group.throughput(Throughput::Elements((writer_ops * 2) as u64));
        group.bench_with_input(
            BenchmarkId::new("writers_and_readers", workers),
            &workers,
            |b, _| {
                b.to_async(&runtime).iter_batched(
                    || MetaStoreBenchmark::new(writer_ops + 1, 0),
                    |store| {
                        let request_ids = Arc::clone(&request_ids);
                        async move {
                            run_contention(
                                store,
                                request_ids,
                                workers,
                                OPERATIONS_PER_WORKER,
                                true,
                            )
                            .await;
                        }
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}

/// Measures admission and completion with eight writers while another task collects IDs of requests
/// still processing. A writer-only case shows the added cost of collecting those IDs.
fn status_scan_contention(c: &mut Criterion) {
    // Eight writers split the 10,000 requests. When enabled, one task collects
    // the processing request IDs eight times while those writers are active.
    const WRITER_COUNT: usize = 8;
    const SCANS_PER_ITERATION: usize = 8;

    let runtime = Runtime::new().expect("the benchmark Tokio runtime should start");
    let processing_ids = request_ids("status-scan-processing", DEC_CAPACITY);
    let (writers_store, _writers_permits) = runtime.block_on(processing_store(&processing_ids));
    let (mixed_store, _mixed_permits) = runtime.block_on(processing_store(&processing_ids));
    let first_ids = Arc::new(request_ids("status-scan-first", DEC_CAPACITY));
    let second_ids = Arc::new(request_ids("status-scan-second", DEC_CAPACITY));
    let mut writers_use_first = true;
    let mut mixed_use_first = true;

    let mut group = c.benchmark_group("meta_store/status_scan_contention");
    group.throughput(Throughput::Elements(DEC_CAPACITY as u64));
    group.bench_function("writers", |b| {
        b.to_async(&runtime).iter(|| {
            let request_ids = Arc::clone(if writers_use_first {
                &first_ids
            } else {
                &second_ids
            });
            writers_use_first = !writers_use_first;
            async {
                run_status_scan_contention(
                    writers_store.clone(),
                    request_ids,
                    WRITER_COUNT,
                    SCANS_PER_ITERATION,
                    false,
                )
                .await;
            }
        });
    });
    group.bench_function("writers_and_processing_scans", |b| {
        b.to_async(&runtime).iter(|| {
            let request_ids = Arc::clone(if mixed_use_first {
                &first_ids
            } else {
                &second_ids
            });
            mixed_use_first = !mixed_use_first;
            async {
                run_status_scan_contention(
                    mixed_store.clone(),
                    request_ids,
                    WRITER_COUNT,
                    SCANS_PER_ITERATION,
                    true,
                )
                .await;
            }
        });
    });
    group.finish();
}

// ============================================================================
// HELPERS
// ============================================================================

/// Helper: builds deterministic request IDs for benchmark setup.
fn request_ids(prefix: &str, count: usize) -> Vec<RequestId> {
    (0..count)
        .map(|index| {
            derive_request_id(&format!("{prefix}-{index}"))
                .expect("benchmark request-id derivation should succeed")
        })
        .collect()
}

/// Helper: admits each request and stores a successful result for it.
async fn complete_requests(store: &MetaStoreBenchmark<u64>, request_ids: &[RequestId]) {
    for (value, request_id) in request_ids.iter().enumerate() {
        let permit = store
            .admit(request_id)
            .await
            .expect("benchmark request IDs should be admissible");
        assert!(store.complete(permit, value as u64).await);
    }
}

/// Helper: admits each request and stores a failure for it.
async fn fail_requests(store: &MetaStoreBenchmark<u64>, request_ids: &[RequestId]) {
    for request_id in request_ids {
        let permit = store
            .admit(request_id)
            .await
            .expect("benchmark request IDs should be admissible");
        assert!(store.fail(permit).await);
    }
}

/// Helper: times repeated request ID collection from several stores.
async fn measure_scan_pool(
    stores: &[MetaStoreBenchmark<u64>],
    scan: MetaStoreScan,
    expected_len: usize,
    iterations: u64,
) -> Duration {
    let start = Instant::now();
    let iterations_per_store = iterations / stores.len() as u64;
    let remainder = iterations % stores.len() as u64;
    for (index, store) in stores.iter().enumerate() {
        let store_iterations = iterations_per_store + u64::from(index < remainder as usize);
        for _ in 0..store_iterations {
            assert_eq!(black_box(store.scan_len(scan).await), expected_len);
        }
    }
    start.elapsed()
}

/// Helper: times completed-request deletion while keeping the completion queue full.
async fn measure_completed_deletions(
    initial_ids: &[RequestId],
    replacement_ids: &[RequestId],
    deletions_per_store: usize,
    iterations: u64,
    with_permit: bool,
    position: usize,
) -> Duration {
    let mut measured = Duration::ZERO;
    let mut remaining = iterations;

    while remaining > 0 {
        let deletion_count = remaining.min(deletions_per_store as u64) as usize;
        let store = MetaStoreBenchmark::new(initial_ids.len() + deletion_count, 0);
        complete_requests(&store, initial_ids).await;
        let mut completed_ids = initial_ids.iter().copied().collect::<VecDeque<_>>();

        for (value, replacement_id) in replacement_ids[..deletion_count].iter().enumerate() {
            let request_id = completed_ids[position];

            if with_permit {
                let permit = store
                    .hold(&request_id)
                    .await
                    .expect("the completed deletion entry should be holdable");
                let start = Instant::now();
                assert!(store.delete(permit).await);
                measured += start.elapsed();
            } else {
                let start = Instant::now();
                assert!(store.try_delete(&request_id).await);
                measured += start.elapsed();
            }

            let removed = completed_ids
                .remove(position)
                .expect("the deleted request should remain at the selected position");
            assert_eq!(removed, request_id);

            // Replace the tombstoned entry outside the measured interval so
            // every deletion sees the same completion-queue length.
            let permit = store
                .admit(replacement_id)
                .await
                .expect("the replacement deletion entry should be admissible");
            assert!(store.complete(permit, value as u64).await);
            completed_ids.push_back(*replacement_id);
        }

        remaining -= deletion_count as u64;
    }

    measured
}

/// Helper: runs concurrent admission and completion with optional result readers.
async fn run_contention(
    store: MetaStoreBenchmark<u64>,
    request_ids: Arc<Vec<RequestId>>,
    workers: usize,
    operations_per_worker: usize,
    with_readers: bool,
) {
    let seed_id = request_ids[request_ids.len() - 1];
    if with_readers {
        let permit = store
            .admit(&seed_id)
            .await
            .expect("the contention read fixture should be admissible");
        assert!(store.complete(permit, 0).await);
    }

    let mut tasks = Vec::with_capacity(if with_readers { workers * 2 } else { workers });
    for worker in 0..workers {
        let store = store.clone();
        let request_ids = Arc::clone(&request_ids);
        tasks.push(tokio::spawn(async move {
            let start = worker * operations_per_worker;
            let end = start + operations_per_worker;
            complete_requests(&store, &request_ids[start..end]).await;
        }));
    }
    if with_readers {
        for _ in 0..workers {
            let store = store.clone();
            tasks.push(tokio::spawn(async move {
                for _ in 0..operations_per_worker {
                    black_box(
                        store
                            .retrieve(&seed_id)
                            .await
                            .expect("the contention read fixture should remain retrievable"),
                    );
                }
            }));
        }
    }
    for task in tasks {
        task.await
            .expect("a metastore contention worker should not panic");
    }
}

/// Helper: builds a store in which every request is still processing.
async fn processing_store(
    request_ids: &[RequestId],
) -> (MetaStoreBenchmark<u64>, Vec<MetaStorePermit<u64>>) {
    let store = MetaStoreBenchmark::new(DEC_CAPACITY * 2, 0);
    let mut permits = Vec::with_capacity(request_ids.len());
    for request_id in request_ids {
        permits.push(
            store
                .admit(request_id)
                .await
                .expect("the processing contention fixture should be admissible"),
        );
    }
    (store, permits)
}

/// Helper: runs concurrent admission and completion with optional collection of processing request IDs.
async fn run_status_scan_contention(
    store: MetaStoreBenchmark<u64>,
    request_ids: Arc<Vec<RequestId>>,
    writer_count: usize,
    scans_per_iteration: usize,
    with_scanner: bool,
) {
    let task_count = writer_count + usize::from(with_scanner);
    let barrier = Arc::new(Barrier::new(task_count + 1));
    let mut tasks = Vec::with_capacity(task_count);
    let requests_per_worker = request_ids.len() / writer_count;

    for worker in 0..writer_count {
        let store = store.clone();
        let request_ids = Arc::clone(&request_ids);
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let start = worker * requests_per_worker;
            let end = if worker + 1 == writer_count {
                request_ids.len()
            } else {
                start + requests_per_worker
            };
            complete_requests(&store, &request_ids[start..end]).await;
        }));
    }
    if with_scanner {
        let store = store.clone();
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            for _ in 0..scans_per_iteration {
                black_box(store.scan_len(MetaStoreScan::Processing).await);
            }
        }));
    }

    barrier.wait().await;
    for task in tasks {
        task.await
            .expect("a status-scan contention worker should not panic");
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = lifecycle, steady_state_eviction, eviction_position, retrieval, retry_failed,
        retry_position, tombstone_completed, tombstone_position, scans, contention,
        status_scan_contention
}
criterion_main!(benches);

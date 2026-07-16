//! Small testing interface used by the metastore benchmark.
//!
//! It exposes selected production operations without making `MetaStore` itself public.

use crate::{
    engine::utils::MetricedError,
    util::meta_store::{
        MetaStore, MetaStorePermit, add_or_redo_failed_in_meta_store, delete_in_meta_store,
        lock_entry_in_meta_store, retrieve_from_meta_store_with_timeout, try_delete_in_meta_store,
        update_err_req_in_meta_store, update_ok_req_in_meta_store,
    },
};
use kms_grpc::RequestId;
use std::sync::Arc;
use tokio::sync::RwLock;

// Production helpers require a static metric label; benchmark calls use this one.
const BENCHMARK_METRIC: &str = "meta_store_benchmark";

/// Selects which request IDs [`MetaStoreBenchmark::scan_len`] counts.
#[derive(Clone, Copy, Debug)]
pub enum MetaStoreScan {
    /// Count every request in the store.
    All,
    /// Count requests that completed successfully.
    Successful,
    /// Count requests that are still processing.
    Processing,
    /// Count requests that failed.
    Failed,
    /// Count requests that were deleted.
    Deleted,
}

/// Owns the metastore used by a benchmark and exposes the operations being measured.
///
/// The inner store and its lock remain private.
pub struct MetaStoreBenchmark<T> {
    inner: Arc<RwLock<MetaStore<T>>>,
}

impl<T> Clone for MetaStoreBenchmark<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T: Send + Sync + 'static> MetaStoreBenchmark<T> {
    /// Creates a metastore with an entry limit and a minimum number of completed entries to keep.
    ///
    /// Call this within a Tokio runtime because the store starts a cleanup task for abandoned requests.
    pub fn new(capacity: usize, min_cache: usize) -> Self {
        Self {
            inner: MetaStore::new(capacity, min_cache),
        }
    }

    /// Starts a new request, or restarts one whose previous attempt failed.
    pub async fn admit(&self, request_id: &RequestId) -> Result<MetaStorePermit<T>, MetricedError> {
        add_or_redo_failed_in_meta_store(&self.inner, request_id, BENCHMARK_METRIC).await
    }

    /// Stores a successful result for the request represented by `permit`.
    pub async fn complete(&self, permit: MetaStorePermit<T>, value: T) -> bool {
        update_ok_req_in_meta_store(&self.inner, permit, value, BENCHMARK_METRIC).await
    }

    /// Stores a failure for the request represented by `permit`.
    pub async fn fail(&self, permit: MetaStorePermit<T>) -> bool {
        update_err_req_in_meta_store(
            &self.inner,
            permit,
            "metastore benchmark failure".to_owned(),
            BENCHMARK_METRIC,
        )
        .await
    }

    /// Returns the stored result of a request that completed successfully.
    pub async fn retrieve(&self, request_id: &RequestId) -> Result<Arc<T>, MetricedError> {
        retrieve_from_meta_store_with_timeout(&self.inner, request_id, BENCHMARK_METRIC, 0).await
    }

    /// Locks an existing entry so it cannot be evicted while the returned permit is held.
    pub async fn hold(&self, request_id: &RequestId) -> Result<MetaStorePermit<T>, MetricedError> {
        lock_entry_in_meta_store(&self.inner, request_id, BENCHMARK_METRIC).await
    }

    /// Deletes the entry represented by `permit`.
    pub async fn delete(&self, permit: MetaStorePermit<T>) -> bool {
        let guard = self.inner.write().await;
        delete_in_meta_store(
            guard,
            permit,
            "metastore benchmark deletion failed".to_owned(),
            BENCHMARK_METRIC,
        )
        .await
    }

    /// Deletes an unlocked entry without first acquiring a permit.
    pub async fn try_delete(&self, request_id: &RequestId) -> bool {
        try_delete_in_meta_store(&self.inner, request_id)
            .await
            .is_ok()
    }

    /// Collects the selected request IDs and returns how many were found.
    pub async fn scan_len(&self, scan: MetaStoreScan) -> usize {
        let guard = self.inner.read().await;
        match scan {
            MetaStoreScan::All => guard
                .get_any_seen_request_ids()
                .copied()
                .collect::<Vec<_>>()
                .len(),
            MetaStoreScan::Successful => guard.get_successful_completed_request_ids().count(),
            MetaStoreScan::Processing => guard.get_processing_request_ids().count(),
            MetaStoreScan::Failed => guard.get_failed_request_ids().count(),
            MetaStoreScan::Deleted => guard
                .get_deleted_request_ids()
                .copied()
                .collect::<Vec<_>>()
                .len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::base::derive_request_id;

    // Covers every operation exposed to external benchmarks.
    #[tokio::test]
    async fn benchmark_facade_exercises_each_supported_operation() {
        let store = MetaStoreBenchmark::new(5, 1);
        let successful_id = derive_request_id("benchmark-successful").unwrap();
        let failed_id = derive_request_id("benchmark-failed").unwrap();
        let processing_id = derive_request_id("benchmark-processing").unwrap();
        let deleted_id = derive_request_id("benchmark-deleted").unwrap();
        let try_deleted_id = derive_request_id("benchmark-try-deleted").unwrap();

        let permit = store.admit(&successful_id).await.unwrap();
        assert!(store.complete(permit, 42_u64).await);
        assert_eq!(*store.retrieve(&successful_id).await.unwrap(), 42);

        let held = store.hold(&successful_id).await.unwrap();
        assert!(store.hold(&successful_id).await.is_err());
        drop(held);
        assert!(store.hold(&successful_id).await.is_ok());

        let permit = store.admit(&failed_id).await.unwrap();
        assert!(store.fail(permit).await);
        assert_eq!(store.scan_len(MetaStoreScan::Failed).await, 1);

        let retry_permit = store.admit(&failed_id).await.unwrap();
        assert!(store.complete(retry_permit, 7).await);
        assert_eq!(store.scan_len(MetaStoreScan::Successful).await, 2);

        let processing_permit = store.admit(&processing_id).await.unwrap();
        assert_eq!(store.scan_len(MetaStoreScan::Processing).await, 1);
        assert_eq!(store.scan_len(MetaStoreScan::All).await, 3);
        let cloned_store = store.clone();
        assert_eq!(cloned_store.scan_len(MetaStoreScan::All).await, 3);
        assert!(cloned_store.complete(processing_permit, 9).await);

        let deleted_permit = store.admit(&deleted_id).await.unwrap();
        assert!(store.delete(deleted_permit).await);

        let try_deleted_permit = store.admit(&try_deleted_id).await.unwrap();
        assert!(store.complete(try_deleted_permit, 11).await);
        assert!(store.try_delete(&try_deleted_id).await);
        assert_eq!(store.scan_len(MetaStoreScan::Deleted).await, 2);
    }
}

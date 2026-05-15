use crate::{anyhow_error_and_log, consts::DURATION_WAITING_ON_RESULT_SECONDS, some_or_err};
use anyhow::bail;
use async_cell::sync::AsyncCell;
use kms_grpc::RequestId;
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};
#[cfg(feature = "non-wasm")]
use tokio::sync::RwLockReadGuard;
use tokio::sync::{Mutex, MutexGuard, Semaphore};
use tracing;
#[cfg(feature = "non-wasm")]
use wasm_bindgen::convert::Upcast;

cfg_if::cfg_if! {
    if #[cfg(feature = "non-wasm")] {
        use crate::engine::utils::MetricedError;
        use anyhow::anyhow;
        use std::fmt::{self};
        use tokio::sync::{RwLock, RwLockWriteGuard};
    }
}

pub struct MetaStorePermit<'a> {
    req_id: RequestId,
    mutex_guard: MutexGuard<'a, ()>,
}

enum EntryState<T> {
    Pending(Mutex<()>), // This is used to lock the entry for updates, e.g. to prevent deletion while an update is in progress.
    Deleted,
    Done((Result<T, String>, Mutex<()>)), // TODO should embed Arc, and require this at insertion time
}

/// Data structure that stores elements that are being processed and their status (Started, Done, Error).
/// It holds elements up to a given capacity, and once it is full, it will remove old elements that have status [Done]/[Error], if there are sufficiently many.
pub struct MetaStore<T> {
    // The maximum amount of entries in total (finished and unfinished)
    capacity: usize,
    // The minimum amount of entries that should be kept in the cache after completion and before old ones are evicted
    min_cache: usize,
    // Storage of all elements in the system
    storage: HashMap<RequestId, Arc<EntryState<T>>>,
    // Queue of all elements that have been completed
    complete_queue: VecDeque<RequestId>,
    // TODO should we embed a semaphore to allow parallel usage of meta store? and have limititation
}

impl<T: Clone> MetaStore<T> {
    /// Creates a new MetaStore with a given capacity and minimal cache size.
    /// In more detail, this means that the MetaStore will be able to hold [capacity] of total elements,
    /// of which we can be sure that at least [min_cache] elements are kept in the cache after completion
    /// (assuming that at least [min_cache] have been completed).
    /// The cache may be larger than [min_cache], but the total capacity will be limited to [capacity]
    pub fn new(capacity: usize, min_cache: usize) -> Self {
        Self {
            capacity,
            min_cache,
            storage: HashMap::with_capacity(capacity),
            complete_queue: VecDeque::with_capacity(min_cache),
        }
    }

    /// Creates a new MetaStore with unlimited capacity and cache size.
    pub fn new_unlimited() -> Self {
        Self {
            capacity: usize::MAX,
            min_cache: usize::MAX,
            storage: HashMap::new(),
            complete_queue: VecDeque::new(),
        }
    }

    // Creates a MetaStore with unlimited storage capacity and minimum cache size and populates it with the given map
    pub fn new_from_map(map: HashMap<RequestId, T>) -> Self {
        let mut completed_queue = VecDeque::new();
        let storage = map
            .into_iter()
            .map(|(key, value)| {
                completed_queue.push_back(key);
                (key, Arc::new(EntryState::Done((Ok(value), Mutex::new(())))))
            })
            .collect();

        Self {
            capacity: usize::MAX,
            min_cache: usize::MAX,
            storage,
            complete_queue: completed_queue,
        }
    }

    pub fn exists(&self, request_id: &RequestId) -> bool {
        self.storage.contains_key(request_id)
    }

    // /// Get cell reference for status checking without cloning Arc
    // /// Returns borrowed reference to avoid Arc::clone() overhead
    // pub fn get_cell(&self, request_id: &RequestId) -> Option<&Arc<AsyncCell<Result<T, String>>>> {
    //     self.storage.get(request_id)
    // }

    /// Verify the invariant that storage.len() >= complete_queue.len()
    /// This is critical for preventing underflow in get_processing_count()
    /// Logs error if invariant is violated but does not panic
    fn verify_invariant(&self) -> bool {
        let is_valid = self.storage.len() >= self.complete_queue.len();
        if !is_valid {
            tracing::error!(
                "INVARIANT VIOLATION: storage.len() ({}) < complete_queue.len() ({})",
                self.storage.len(),
                self.complete_queue.len()
            );
        }
        is_valid
    }

    // The non local effect warning is a false positive here, because we return an error only if the pop_front()
    // fails, which means that the queue is empty, and thus we do not have any non-local effects.
    #[allow(unknown_lints)]
    #[allow(non_local_effect_before_error_return)]
    /// Insert a new element, throwing an exception if the element already exists or if the system is fully loaded.
    ///
    /// Elements can trivially be inserted until the store reaches its [capacity].
    /// Once the store is full, we will remove old elements that have completed, but only once we have at least [min_cache] elements of them.
    /// This is to ensure that:
    /// 1. there are never more than [capacity] - [min_cache] elements currently being processed (id not in `complete_queue`) and
    /// 2. there is enough time to retrieve an element before it is removed. This timespan is the time it takes to process [min_cache] elements.
    ///
    /// If the store is at max capacity and not enough elements have been completed, we will not accept new elements to be inserted.
    pub fn insert(&mut self, request_id: &RequestId) -> anyhow::Result<MetaStorePermit> {
        if self.exists(request_id) {
            return Err(anyhow::anyhow!(
                "The element with ID {request_id} already stored exists. Can not insert it more than once.",
            ));
        }
        if self.storage.len() >= self.capacity {
            // We have reached the capacity limit. Delete an old element.
            if self.complete_queue.len() <= self.min_cache {
                return Err(anyhow_error_and_log(
                    "The system is fully loaded and the cache of finished elements is not at minimum size yet. Cannot insert new element.",
                ));
            } else {
                // Remove the first (oldest) element from the age queue
                let old_request_id = some_or_err(
                    self.complete_queue.pop_front(),
                    "Could not remove an old request from the cache".to_string(),
                )?;
                // and also remove it from the storage map
                // If storage removal fails, we need to restore the complete_queue to maintain invariant
                if self.storage.remove(&old_request_id).is_none() {
                    self.complete_queue.push_front(old_request_id);
                    return Err(anyhow_error_and_log(format!(
                        "Failed to remove old element {old_request_id} from storage, invariant preserved"
                    )));
                }
            }
        }
        let mutex = Mutex::new(());
        let permit = mutex
            .try_lock()
            .expect("Lock must be available after mutex construction");
        // Ignore the result since we have already checked that the element does not exist
        let _ = self
            .storage
            .insert(request_id.to_owned(), Arc::new(EntryState::Pending(mutex)));

        Ok(MetaStorePermit {
            req_id: *request_id,
            mutex_guard: permit,
        })
    }

    /// Sets the value of an already existing element.
    ///
    /// Observe that this enforces the following possible transistions:
    /// Pending -> Done(Ok)  -> Deleted
    /// Pending -> Done(Err) -> Deleted
    /// Pending -> Deleted
    /// Returns an error if something goes wrong, like
    /// the element does not exist or the value was already set.
    pub fn update(
        &mut self,
        update: Result<T, String>,
        permit: MetaStorePermit,
    ) -> anyhow::Result<()> {
        let mut cell = if let Some(cell) = self.storage.get_mut(&permit.req_id) {
            cell
        } else {
            return Err(anyhow_error_and_log(format!(
                "The element with ID {} does not exist, update is not allowed",
                permit.req_id
            )));
        };
        match cell.as_ref() {
            EntryState::Pending(mutex) => {
                // Update state
                *cell = Arc::new(EntryState::Done((update, *mutex)));
            }
            _ => {
                return Err(anyhow_error_and_log(format!(
                    "The element with ID {} is not in a pending state, update is not allowed",
                    permit.req_id
                )));
            }
        }
        self.complete_queue.push_back(permit.req_id);
        // Observe the permit is dropped here, which releases the lock and allows deletion of this element if needed
        Ok(())
    }

    pub fn try_update(
        &mut self,
        request_id: &RequestId,
        update: Result<T, String>,
    ) -> anyhow::Result<()> {
        // Try to lock the entry for an update.
        let mut entry = match self.storage.get_mut(request_id) {
            Some(entry) => entry,
            None => anyhow::bail!(
                "The element with ID {request_id} does not exist, update is not allowed"
            ),
        };
        if let EntryState::Pending(mutex) = entry.as_ref() {
            if let Ok(permit) = mutex.try_lock() {
                // We have the permit, we can proceed with the update
                self.update(
                    update,
                    MetaStorePermit {
                        req_id: *request_id,
                        mutex_guard: permit,
                    },
                )
            } else {
                // The entry is currently locked for update by another thread, so we cannot update it right now
                anyhow::bail!("The element with ID {request_id} is currently locked for update");
            }
        } else {
            // The entry is not in a pending state, so we cannot update it
            anyhow::bail!(
                "The element with ID {request_id} is not in a pending state, update is not allowed"
            );
        }
    }

    /// Retrieve the cell of an element and return None if it does not exist
    pub fn retrieve(&self, request_id: &RequestId) -> Option<&Arc<EntryState<T>>> {
        self.storage.get(request_id)
    }

    /// Mark an existing entry in the meta store as deleted, regardless of its current state.
    /// Returns the removed entry if it existed, and None if it did not exist.
    pub fn delete(&mut self, permit: MetaStorePermit) -> anyhow::Result<Arc<EntryState<T>>> {
        let mut entry = match self.storage.get_mut(&permit.req_id) {
            Some(entry) => entry,
            None => anyhow::bail!(
                "The element with ID {} does not exist, deletion is not allowed",
                permit.req_id
            ),
        };

        match entry.as_ref() {
            EntryState::Pending(_) | EntryState::Done(_) => {
                let old_entry = Arc::clone(entry);
                // Update state
                *entry = Arc::new(EntryState::Deleted);
                return Ok(old_entry);
            }
            _ => {
                return Err(anyhow_error_and_log(format!(
                    "The element with ID {} is not in a pending or completed state, it is not possible to delete it",
                    permit.req_id
                )));
            }
        }
    }

    pub fn try_delete(&mut self, request_id: &RequestId) -> anyhow::Result<Arc<EntryState<T>>> {
        // Try to lock the entry for an update.
        let mut entry = match self.storage.get_mut(request_id) {
            Some(entry) => entry,
            None => anyhow::bail!(
                "The element with ID {request_id} does not exist, update is not allowed"
            ),
        };
        match entry.as_ref() {
            EntryState::Pending(mutex) => {
                if let Ok(permit) = mutex.try_lock() {
                    // We have the permit, we can proceed with the update
                    self.delete(MetaStorePermit {
                        req_id: *request_id,
                        mutex_guard: permit,
                    })
                } else {
                    // The entry is currently locked
                    anyhow::bail!(
                        "The element with ID {request_id} is currently locked and cannot be deleted right now"
                    );
                }
            }
            EntryState::Done((_, mutex)) => {
                if let Ok(permit) = mutex.try_lock() {
                    // We have the permit, we can proceed with the update
                    let _ = self.delete(MetaStorePermit {
                        req_id: *request_id,
                        mutex_guard: permit,
                    })?;
                    Ok(Arc::clone(entry))
                } else {
                    // The entry is currently locked
                    anyhow::bail!(
                        "The element with ID {request_id} is currently locked and cannot be deleted right now"
                    );
                }
            }
            _ => {
                // The entry is not in a pending or done state, so we cannot update it
                anyhow::bail!(
                    "The element with ID {request_id} is not in a pending or completed state, deletion is not allowed"
                );
            }
        }
    }

    /// Get the maximum capacity of this MetaStore
    pub fn get_capacity(&self) -> usize {
        self.capacity
    }

    /// Get the current number of items in the store
    pub fn get_current_count(&self) -> usize {
        self.storage.len()
    }

    /// Get the total number of items in the store (alias for get_current_count)
    pub fn get_total_count(&self) -> usize {
        self.get_current_count()
    }

    /// Get the number of completed items
    pub fn get_completed_count(&self) -> usize {
        self.complete_queue.len()
    }

    /// Get the number of items currently being processed
    pub fn get_processing_count(&self) -> usize {
        // Non-fallible invariant check that logs errors but doesn't panic
        self.verify_invariant();

        // Ensure invariant: storage.len() >= complete_queue.len() to prevent underflow
        self.storage.len().saturating_sub(self.complete_queue.len())
    }

    /// Get all request IDs in the store
    pub fn get_all_request_ids(&self) -> Vec<RequestId> {
        self.storage.keys().cloned().collect()
    }

    /// Get completed request IDs
    pub fn get_completed_request_ids(&self) -> Vec<RequestId> {
        self.complete_queue.iter().cloned().collect()
    }

    /// Get processing request IDs (not yet completed)
    pub fn get_processing_request_ids(&self) -> Vec<RequestId> {
        self.storage
            .keys()
            .filter(|id| !self.complete_queue.contains(id))
            .cloned()
            .collect()
    }

    /// Get failed request IDs (completed with errors)
    /// WARNING: This is a slow operation
    pub fn get_failed_request_ids(&self) -> Vec<RequestId> {
        self.complete_queue
            .iter()
            .filter_map(|id| {
                // Direct HashMap access - items in complete_queue should exist in storage
                match self.storage.get(id) {
                    Some(cell) => {
                        match cell.as_ref() {
                            EntryState::Pending(_) => None,
                            EntryState::Deleted => None,
                            EntryState::Done((done, _)) => {
                                match done {
                                    Ok(_) => None,
                                    Err(_) => Some(*id),
                                }
                            }
                        }
                    }
                    None => {
                        // This should never happen - indicates invariant violation
                        tracing::error!("INVARIANT VIOLATION: Completed item {id} not found in storage - data corruption detected");
                        None
                    }
                }
            })
            .collect()
    }
}

#[cfg(feature = "non-wasm")]
pub(crate) fn add_req_to_meta_store<T: Clone>(
    meta_store: &mut RwLockWriteGuard<'_, MetaStore<T>>,
    req_id: &RequestId,
    request_metric: &'static str,
) -> Result<MetaStorePermit, MetricedError> {
    if meta_store.exists(req_id) {
        return Err(MetricedError::new(
            request_metric,
            Some(*req_id),
            anyhow::anyhow!("Duplicate request ID in meta store"),
            tonic::Code::AlreadyExists,
        ));
    }
    let permit = meta_store.insert(req_id).map_err(|e| {
        // We likely reached capacity here
        MetricedError::new(request_metric, Some(*req_id), e, tonic::Code::Aborted)
    })?;
    Ok(permit)
}

#[cfg(feature = "non-wasm")]
pub(crate) fn update_req_in_meta_store<
    T: Clone,
    E: Into<Box<dyn std::error::Error + Send + Sync>> + fmt::Debug,
>(
    meta_store: &mut RwLockWriteGuard<'_, MetaStore<T>>,
    permit: MetaStorePermit,
    result: Result<T, E>,
    request_metric: &'static str,
) -> bool {
    match result {
        Ok(res) => update_ok_req_in_meta_store(meta_store, permit, res, request_metric),
        Result::Err(e) => {
            update_err_req_in_meta_store(meta_store, permit, format!("{e:?}"), request_metric)
        }
    }
}

#[cfg(feature = "non-wasm")]
pub(crate) fn update_ok_req_in_meta_store<T: Clone>(
    meta_store: &mut RwLockWriteGuard<'_, MetaStore<T>>,
    permit: MetaStorePermit,
    result: T,
    request_metric: &'static str,
) -> bool {
    let req_id = permit.req_id.clone();
    match meta_store.update(Ok(result), permit) {
        Ok(()) => true,
        Err(e) => {
            // Update error counter for meta-store update failure
            MetricedError::handle_unreturnable_error(request_metric, Some(req_id), e);
            false
        }
    }
}

#[cfg(feature = "non-wasm")]
pub(crate) async fn ensure_meta_store_request_pending<T: Clone>(
    meta_store: &Arc<RwLock<MetaStore<T>>>,
    req_id: &RequestId,
) -> anyhow::Result<()> {
    let guarded_meta_store = meta_store.read().await;
    match guarded_meta_store.retrieve(req_id) {
        Some(res) => {
            if matches!(res.as_ref(), EntryState::Pending(_)) {
                Ok(())
            } else {
                anyhow::bail!(
                    "Request with ID {req_id} is not pending in the meta store as required for this operation"
                )
            }
        }
        None => {
            anyhow::bail!(
                "Request with ID {req_id} is not pending in the meta store as required for this operation"
            )
        }
    }
}

/// Helper method for updating the meta store with an error result
/// The method gracefully handles potential update failures by logging and updating metrics
/// [req_id] is the request ID to update
/// [error] is the error message to store
/// [request_metric] is a free-form string used only for error logging the origin of the failure
/// Returns true if the update was successful, false otherwise
#[cfg(feature = "non-wasm")]
pub(crate) fn update_err_req_in_meta_store<T: Clone>(
    meta_store: &mut RwLockWriteGuard<'_, MetaStore<T>>,
    permit: MetaStorePermit,
    error: String,
    request_metric: &'static str,
) -> bool {
    let req_id = permit.req_id.clone();
    MetricedError::handle_unreturnable_error(request_metric, Some(req_id), error.clone());
    match meta_store.update(Err(error.clone()), permit) {
        Ok(()) => true,
        Err(e) => {
            // We already logged the original error, so just log the update failure here as there is not much else we can do
            tracing::error!(
                "Failed to update meta store on request ID {req_id} with error message \"{error}\" due to update error: {e}"
            );
            false
        }
    }
}

/// Helper method for retrieving the result of a request from an appropriate meta store
/// [req_id] is the request ID to retrieve
/// [request_type] is a free-form string used only for error logging the origin of the failure
#[cfg(feature = "non-wasm")]
pub(crate) async fn retrieve_from_meta_store<T: Clone>(
    meta_store: RwLockReadGuard<'_, MetaStore<T>>,
    req_id: &RequestId,
    metric_scope: &'static str,
) -> Result<T, MetricedError> {
    let handle = meta_store.retrieve(req_id);
    drop(meta_store); // Release the read lock early as we otherwise risk holding it for up to DURATION_WAITING_ON_RESULT_SECONDS!
    handle_res_metriced(handle, req_id, metric_scope).await
}

/// Like [`retrieve_from_meta_store`] but with a custom server-side wait duration.
/// Use this for operations (e.g. preprocessing) that are inherently slower than
/// the default 60-second window.
#[cfg(feature = "non-wasm")]
pub(crate) async fn retrieve_from_meta_store_with_timeout<T: Clone>(
    meta_store: RwLockReadGuard<'_, MetaStore<T>>,
    req_id: &RequestId,
    metric_scope: &'static str,
    wait_secs: u64,
) -> Result<T, MetricedError> {
    let handle = meta_store.retrieve(req_id);
    drop(meta_store); // Release the read lock early
    handle_res_metriced_with_timeout(handle, req_id, metric_scope, wait_secs).await
}

#[cfg(feature = "non-wasm")]
pub async fn handle_res<T: Clone>(
    handle: Option<Arc<AsyncCell<Result<T, String>>>>,
    req_id: &RequestId,
) -> anyhow::Result<T> {
    match handle {
        None => {
            bail!("Could not retrieve the result with request ID {req_id}. It does not exist")
        }
        Some(cell) => {
            let result = tokio::time::timeout(
                tokio::time::Duration::from_secs(DURATION_WAITING_ON_RESULT_SECONDS),
                cell.get(),
            )
            .await;
            // Peel off the potential errors
            if let Ok(result) = result {
                match result {
                    Ok(result) => Ok(result),
                    Err(e) => {
                        let msg = format!(
                            "Could not retrieve the result with request ID {req_id} since it finished with an error: {e}"
                        );
                        tracing::warn!(msg);
                        bail!(msg);
                    }
                }
            } else {
                let msg = format!(
                    "Could not retrieve the result with request ID {req_id} since it is not completed yet after waiting for {DURATION_WAITING_ON_RESULT_SECONDS} seconds"
                );
                tracing::info!(msg);
                bail!(msg);
            }
            // Note that this is not logged as an error as we expect calls to take some time to be completed
        }
    }
}

#[cfg(feature = "non-wasm")]
async fn handle_res_metriced<T: Clone>(
    handle: Option<Arc<EntryState<T>>>,
    req_id: &RequestId,
    metric_scope: &'static str,
) -> Result<T, MetricedError> {
    handle_res_metriced_with_timeout(
        handle,
        req_id,
        metric_scope,
        DURATION_WAITING_ON_RESULT_SECONDS,
    )
    .await
}

#[cfg(feature = "non-wasm")]
async fn handle_res_metriced_with_timeout<T: Clone>(
    handle: Option<Arc<EntryState<T>>>,
    req_id: &RequestId,
    metric_scope: &'static str,
    wait_secs: u64,
) -> Result<T, MetricedError> {
    match handle {
        None => {
            let msg = format!(
                "Could not retrieve the result in scope {metric_scope} with request ID {req_id}. It does not exist"
            );

            Err(MetricedError::new(
                metric_scope,
                Some(*req_id),
                anyhow!(msg),
                tonic::Code::NotFound,
            ))
        }
        Some(cell) => {
            let result =
                tokio::time::timeout(tokio::time::Duration::from_secs(wait_secs), cell.get()).await;
            // Peel off the potential errors
            if let Ok(result) = result {
                match result {
                    Ok(result) => Ok(result),
                    Err(e) => {
                        let msg = format!(
                            "Could not retrieve the result in scope {metric_scope} with request ID {req_id} since it finished with an error: {e}"
                        );
                        tracing::warn!(msg);
                        let code = if e.to_ascii_lowercase().contains("abort") {
                            tonic::Code::Aborted
                        } else {
                            tonic::Code::Internal
                        };
                        Err(MetricedError::new(
                            metric_scope,
                            Some(*req_id),
                            anyhow!(msg),
                            code,
                        ))
                    }
                }
            } else {
                let msg = format!(
                    "Could not retrieve the result in scope {metric_scope} with request ID {req_id} since it is not completed yet after waiting for {wait_secs} seconds"
                );
                tracing::info!(msg);
                Err(MetricedError::new(
                    metric_scope,
                    Some(*req_id),
                    anyhow!(msg),
                    tonic::Code::Unavailable,
                ))
            }
            // Note that this is not logged as an error as we expect calls to take some time to be completed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::base::derive_request_id;
    use kms_grpc::RequestId;
    use tokio::sync::RwLock;

    #[test]
    fn sunshine() {
        let mut meta_store: MetaStore<String> = MetaStore::new(2, 1);
        let request_id: RequestId = derive_request_id("meta_store").unwrap();
        // Data does not exist
        assert!(!meta_store.exists(&request_id));
        assert!(
            meta_store
                .update(&request_id, Ok("OK".to_string()))
                .is_err()
        );

        meta_store.insert(&request_id).unwrap();
        // Data exits
        assert!(meta_store.exists(&request_id));
        assert!(meta_store.update(&request_id, Ok("OK".to_string())).is_ok());

        // Re-update not allowed
        assert!(
            meta_store
                .update(&request_id, Ok("NOK".to_string()))
                .is_err()
        );
    }

    #[test]
    fn test_kickout_of_errors() {
        let mut meta_store: MetaStore<String> = MetaStore::new(2, 1);
        let request_id_1: RequestId = derive_request_id("1").unwrap();
        let request_id_2: RequestId = derive_request_id("2").unwrap();
        let request_id_3: RequestId = derive_request_id("3").unwrap();
        meta_store.insert(&request_id_1).unwrap();
        assert!(
            meta_store
                .update(&request_id_1, Err("Err1".to_string()))
                .is_ok()
        );
        meta_store.insert(&request_id_2).unwrap();
        assert!(
            meta_store
                .update(&request_id_2, Ok("OK2".to_string()))
                .is_ok()
        );
        // The storage is full so we should kick the oldest element out
        meta_store.insert(&request_id_3).unwrap();
        assert!(
            meta_store
                .update(&request_id_3, Err("Err3".to_string()))
                .is_ok()
        );

        // Validate the oldest element is removed
        assert!(!meta_store.exists(&request_id_1));
        // Validate the two newer elements are still there
        assert!(meta_store.exists(&request_id_2));
        assert!(meta_store.exists(&request_id_3));
    }

    #[test]
    fn double_insert() {
        let mut meta_store: MetaStore<String> = MetaStore::new(2, 1);
        let request_id: RequestId = derive_request_id("meta_store").unwrap();
        meta_store.insert(&request_id).unwrap();
        // We cannot insert the same request_id twice
        assert!(meta_store.insert(&request_id).is_err());
    }

    #[test]
    fn too_many_elements() {
        let mut meta_store: MetaStore<String> = MetaStore::new(2, 1);
        let req_1: RequestId = derive_request_id("1").unwrap();
        let req_2: RequestId = derive_request_id("2").unwrap();
        let req_3: RequestId = derive_request_id("3").unwrap();
        meta_store.insert(&req_1).unwrap();
        meta_store.insert(&req_2).unwrap();
        // Only room for 2 elements
        assert!(meta_store.insert(&req_3).is_err());
    }

    #[test]
    fn auto_remove() {
        let mut meta_store: MetaStore<String> = MetaStore::new(2, 1);
        let req_1: RequestId = derive_request_id("1").unwrap();
        let req_2: RequestId = derive_request_id("2").unwrap();
        let req_3: RequestId = derive_request_id("3").unwrap();
        meta_store.insert(&req_1).unwrap();
        assert!(meta_store.update(&req_1, Ok("OK".to_string())).is_ok());
        assert!(meta_store.retrieve(&req_1).is_some());
        meta_store.insert(&req_2).unwrap();
        assert!(meta_store.update(&req_2, Ok("OK".to_string())).is_ok());
        assert!(meta_store.retrieve(&req_1).is_some());
        assert!(meta_store.retrieve(&req_2).is_some());
        meta_store.insert(&req_3).unwrap();
        // Only room for 2 elements
        assert!(meta_store.retrieve(&req_3).is_some());
        assert!(meta_store.retrieve(&req_2).is_some());
        // The oldest element is removed
        assert!(meta_store.retrieve(&req_1).is_none());
        // But the other two elements are
    }

    #[tokio::test]
    async fn test_subscription() {
        let mut meta_store: MetaStore<String> = MetaStore::new(2, 1);
        let req_1: RequestId = derive_request_id("1").unwrap();
        meta_store.insert(&req_1).unwrap();
        let meta_store = Arc::new(RwLock::new(meta_store));

        let cloned_meta_store = Arc::clone(&meta_store);
        let handle = tokio::spawn(async move {
            let meta_store = Arc::clone(&cloned_meta_store);
            let handle = meta_store.read().await.retrieve(&req_1);
            handle_res_metriced(handle, &req_1, "test").await
        });
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        meta_store
            .write()
            .await
            .update(&req_1, Ok("OK".to_string()))
            .unwrap();

        let result = handle.await.unwrap().unwrap();
        assert_eq!(result, "OK".to_string());
    }

    #[test]
    fn delete() {
        let mut meta_store: MetaStore<String> = MetaStore::new(10, 2);
        let req_1: RequestId = derive_request_id("1").unwrap();
        let req_2: RequestId = derive_request_id("2").unwrap();
        let req_3: RequestId = derive_request_id("3").unwrap();
        let req_4: RequestId = derive_request_id("4").unwrap();

        meta_store.insert(&req_1).unwrap();
        meta_store.insert(&req_2).unwrap();
        meta_store.insert(&req_3).unwrap();
        meta_store.insert(&req_4).unwrap();

        assert_eq!(meta_store.complete_queue.len(), 0);

        // set req1 to Done and req2 to Error
        assert!(meta_store.update(&req_1, Ok("OK".to_string())).is_ok());
        assert!(meta_store.update(&req_2, Err("Err".to_string())).is_ok());
        assert_eq!(meta_store.complete_queue.len(), 2);

        // check that we can delete req_1 (Done)
        assert!(meta_store.delete(&req_1).is_some());
        // check that we cannot delete req_1 again
        assert!(meta_store.delete(&req_1).is_none());
        assert_eq!(meta_store.complete_queue.len(), 1);

        // check that we can delete req_2 (Err)
        assert!(meta_store.delete(&req_2).is_some());
        // check that we cannot delete req_2 again
        assert!(meta_store.delete(&req_2).is_none());
        assert_eq!(meta_store.complete_queue.len(), 0);

        // check that we can delete req_3 (Started)
        assert!(meta_store.delete(&req_3).is_some());
        // check that we cannot delete req_3 again
        assert!(meta_store.delete(&req_3).is_none());
        assert_eq!(meta_store.complete_queue.len(), 0);
    }
}

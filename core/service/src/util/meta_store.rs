use crate::{anyhow_error_and_log, some_or_err};
use kms_grpc::RequestId;
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};
use tracing;

cfg_if::cfg_if! {
    if #[cfg(feature = "non-wasm")] {
        use crate::consts::DURATION_WAITING_ON_RESULT_SECONDS;
        use crate::engine::utils::MetricedError;
        use anyhow::anyhow;
        use std::fmt::{self};
        use std::time::Duration;
        use tokio::sync::{RwLock, RwLockWriteGuard};
        use tokio::time::Instant;
    }
}

/// Cadence at which `retrieve_from_meta_store` re-checks a pending entry while
/// waiting for it to complete. Picked to keep worst-case lock acquisitions
/// bounded (60s / 250ms = 240 reads) while keeping latency-after-completion
/// well under half a second.
#[cfg(feature = "non-wasm")]
const META_STORE_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Token proving the holder is the rightful updater of a single MetaStore entry.
///
/// Returned by [`MetaStore::insert`]. Required by [`MetaStore::update`] and
/// [`MetaStore::delete`] to perform the mutation. If the holder drops the
/// permit without consuming it, the entry is left in `Pending`, and any
/// other caller can finish or remove it via [`MetaStore::try_delete`].
///
/// "Permit alive" is tracked by the strong count of an internal `Arc<()>`:
/// while the permit exists, `Arc::strong_count` of the entry's claim arc is
/// at least 2 (one held by the entry, one by the permit). `try_*` paths
/// check `strong_count == 1` to determine that no permit is outstanding.
pub struct MetaStorePermit {
    req_id: RequestId,
    _claim: Arc<()>,
}

impl MetaStorePermit {
    pub fn req_id(&self) -> &RequestId {
        &self.req_id
    }
}

impl Drop for MetaStorePermit {
    fn drop(&mut self) {
        tracing::debug!(
            "MetaStorePermit for request ID {} dropped; claim released",
            self.req_id
        );
    }
}

/// Public-facing snapshot of an entry's state.
pub enum EntryState<T> {
    /// Entry exists, but is being worked on (either being computed or being deleted)
    Pending,
    /// Entry finished processing with either a success or error result.
    Done(Result<Arc<T>, String>),
    /// The entry has been deleted.
    Deleted,
}

enum StoredEntry<T> {
    Pending(Arc<()>),
    Done(Result<Arc<T>, String>, Arc<()>),
    Deleted,
}

impl<T> StoredEntry<T> {
    fn done(value: Result<Arc<T>, String>) -> Self {
        StoredEntry::Done(value, Arc::new(()))
    }
}

impl<T> From<StoredEntry<T>> for EntryState<T> {
    fn from(stored: StoredEntry<T>) -> Self {
        match stored {
            StoredEntry::Pending(_claim) => EntryState::Pending,
            StoredEntry::Done(res, _claim) => EntryState::Done(res),
            StoredEntry::Deleted => EntryState::Deleted,
        }
    }
}

impl<T> From<&StoredEntry<T>> for EntryState<T> {
    fn from(stored: &StoredEntry<T>) -> Self {
        match stored {
            StoredEntry::Pending(_) => EntryState::Pending,
            StoredEntry::Done(Ok(arc), _) => EntryState::Done(Ok(Arc::clone(arc))),
            StoredEntry::Done(Err(e), _) => EntryState::Done(Err(e.clone())),
            StoredEntry::Deleted => EntryState::Deleted,
        }
    }
}

/// Data structure that stores elements that are being processed and their status (Pending, Done, Deleted).
/// It holds elements up to a given capacity, and once it is full, it will remove old elements that have status [Done], if there are sufficiently many.
pub struct MetaStore<T> {
    // The maximum amount of entries in total (finished and unfinished)
    capacity: usize,
    // The minimum amount of entries that should be kept in the cache after completion and before old ones are evicted
    min_cache: usize,
    // Storage of all elements in the system
    storage: HashMap<RequestId, StoredEntry<T>>,
    // Queue of all elements that have been completed
    complete_queue: VecDeque<RequestId>,
}

impl<T> MetaStore<T> {
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

    /// Creates a MetaStore with unlimited storage capacity and minimum cache size and populates it with the given map
    pub fn new_from_map(map: HashMap<RequestId, T>) -> Self {
        let mut completed_queue = VecDeque::new();
        let storage = map
            .into_iter()
            .map(|(key, value)| {
                completed_queue.push_back(key);
                (key, StoredEntry::done(Ok(Arc::new(value))))
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
    /// Insert a new element, throwing an error if the element already exists or if the system is fully loaded.
    ///
    /// On success, returns a [`MetaStorePermit`] granting the caller the right to
    /// later [`update`] or [`delete`] this entry. Hold the permit until the
    /// mutation; drop it if the work is abandoned (other callers can recover via
    /// `try_delete`).
    ///
    /// Elements can trivially be inserted until the store reaches its [capacity].
    /// Once the store is full, old completed elements are evicted, but only once we have at least [min_cache] of them.
    /// This ensures:
    /// 1. there are never more than [capacity] - [min_cache] elements currently being processed, and
    /// 2. there is enough time to retrieve an element before it is removed.
    pub fn insert(&mut self, request_id: &RequestId) -> anyhow::Result<MetaStorePermit> {
        // `Deleted` is a permanent tombstone: a request id, once deleted, may
        // not be reused for a fresh insert. Callers that need to overwrite an
        // existing entry should use [`replace_done`] instead.
        if self.storage.contains_key(request_id) {
            return Err(anyhow::anyhow!(
                "The element with ID {request_id} already stored exists. Can not insert it more than once.",
            ));
        }
        if self.storage.len() >= self.capacity {
            if self.complete_queue.len() <= self.min_cache {
                return Err(anyhow_error_and_log(
                    "The system is fully loaded and the cache of finished elements is not at minimum size yet. Cannot insert new element.",
                ));
            } else {
                let old_request_id = some_or_err(
                    self.complete_queue.pop_front(),
                    "Could not remove an old request from the cache".to_string(),
                )?;
                if self.storage.remove(&old_request_id).is_none() {
                    self.complete_queue.push_front(old_request_id);
                    return Err(anyhow_error_and_log(format!(
                        "Failed to remove old element {old_request_id} from storage, invariant preserved"
                    )));
                }
            }
        }
        let claim = Arc::new(());
        let permit = MetaStorePermit {
            req_id: *request_id,
            _claim: Arc::clone(&claim),
        };
        self.storage
            .insert(*request_id, StoredEntry::Pending(claim));
        Ok(permit)
    }

    pub fn lock_entry(&mut self, request_id: &RequestId) -> anyhow::Result<MetaStorePermit> {
        let claim = {
            let entry = self.storage.get(request_id).ok_or_else(|| {
                anyhow_error_and_log(format!(
                    "The element with ID {request_id} does not exist, locking is not allowed"
                ))
            })?;
            match entry {
                StoredEntry::Pending(arc) => {
                    if Arc::strong_count(arc) > 1 {
                        anyhow::bail!(
                            "The element with ID {request_id} is currently already locked"
                        );
                    }
                    Arc::clone(arc)
                }
                StoredEntry::Done(_, arc) => {
                    if Arc::strong_count(arc) > 1 {
                        anyhow::bail!(
                            "The element with ID {request_id} is currently already locked"
                        );
                    }
                    Arc::clone(arc)
                }
                StoredEntry::Deleted => {
                    return Err(anyhow_error_and_log(format!(
                        "The element with ID {request_id} has been deleted, locking is not allowed"
                    )));
                }
            }
        };
        Ok(MetaStorePermit {
            req_id: *request_id,
            _claim: claim,
        })
    }

    /// Sets the value of an already existing element. Consumes the permit.
    ///
    /// Enforces the state transitions:
    /// - Pending -> Done(Ok)
    /// - Pending -> Done(Err)
    ///
    /// Returns an error if the element does not exist, has already been
    /// completed, or has been deleted.
    pub fn update(
        &mut self,
        update: Result<T, String>,
        permit: MetaStorePermit,
    ) -> anyhow::Result<()> {
        let req_id = permit.req_id;
        let cell = self.storage.get_mut(&req_id).ok_or_else(|| {
            anyhow_error_and_log(format!(
                "The element with ID {req_id} does not exist, update is not allowed"
            ))
        })?;
        if !matches!(cell, StoredEntry::Pending(_)) {
            return Err(anyhow_error_and_log(format!(
                "The element with ID {req_id} is not in a pending state, update is not allowed"
            )));
        }
        *cell = StoredEntry::done(update.map(Arc::new));
        self.complete_queue.push_back(req_id);
        // `permit` (and its Arc<()>) dropped at end of scope.
        Ok(())
    }

    /// Set the entry at `request_id` directly to `Done(Ok(value))`, either by
    /// overwriting an existing `Done` entry or by inserting a fresh one if no
    /// entry exists. Returns an error if the entry is currently `Pending`
    /// (a live operation is in progress) or `Deleted` (tombstone).
    ///
    /// Intended for migration / admin flows that rewrite the metadata of an
    /// already-completed entry — or seed a fresh one — without going through
    /// the standard `insert → update` lifecycle. Bypasses the permit
    /// mechanism on purpose: no live permit can exist for a `Done` entry, and
    /// fresh inserts via this path are explicitly admin-scoped.
    // TODO should this actually be done with a permit?
    pub(crate) fn replace_done(&mut self, permit: MetaStorePermit, value: T) -> anyhow::Result<()> {
        let request_id = permit.req_id;
        match self.storage.get(&request_id) {
            Some(StoredEntry::Pending(_)) => {
                return Err(anyhow_error_and_log(format!(
                    "The element with ID {request_id} is currently pending, replace_done is not allowed"
                )));
            }
            Some(StoredEntry::Deleted) => {
                return Err(anyhow_error_and_log(format!(
                    "The element with ID {request_id} has been deleted, replace_done is not allowed"
                )));
            }
            Some(StoredEntry::Done(_, claim)) => {
                if Arc::strong_count(claim) > 1 {
                    return Err(anyhow_error_and_log(format!(
                        "The element with ID {request_id} is currently locked, replace_done is not allowed"
                    )));
                }
                // Existing Done entry — overwrite in place, keep complete_queue slot.
                self.storage
                    .insert(request_id, StoredEntry::done(Ok(Arc::new(value))));
            }
            None => {
                // Fresh insert — record completion.
                self.storage
                    .insert(request_id, StoredEntry::done(Ok(Arc::new(value))));
                self.complete_queue.push_back(request_id);
            }
        }
        Ok(())
    }

    /// Retrieve the state of an element and return None if it does not exist.
    ///
    /// Returns an [`EntryState`] snapshot by value; the internal claim arc on
    /// `Pending` / `Done` is intentionally hidden from external callers, who
    /// should not depend on locking state.
    pub fn retrieve(&self, request_id: &RequestId) -> Option<EntryState<T>> {
        self.storage.get(request_id).map(EntryState::from)
    }

    /// Mark an existing entry as deleted, regardless of whether it was Pending
    /// or Done. Consumes the permit. Returns the previous state. If the previous
    /// state was `Done`, the entry is also removed from the completion queue.
    pub fn delete(&mut self, permit: MetaStorePermit) -> anyhow::Result<EntryState<T>> {
        let req_id = permit.req_id;
        let cell = self.storage.get_mut(&req_id).ok_or_else(|| {
            anyhow::anyhow!("The element with ID {req_id} does not exist, deletion is not allowed")
        })?;
        if matches!(cell, StoredEntry::Deleted) {
            anyhow::bail!("The element with ID {req_id} has already been deleted");
        }
        // TODO don't use mem replace
        let old = std::mem::replace(cell, StoredEntry::Deleted);
        if matches!(old, StoredEntry::Done(_, _),) {
            self.complete_queue.retain(|id| id != &req_id);
        }
        Ok(old.into())
    }

    /// Like [`delete`], but for callers that do not hold a permit. Succeeds
    /// for any non-Deleted state when no live permit is outstanding. Returns
    /// the previous state.
    pub fn try_delete(&mut self, request_id: &RequestId) -> anyhow::Result<EntryState<T>> {
        {
            let entry = self.storage.get(request_id).ok_or_else(|| {
                anyhow_error_and_log(format!(
                    "The element with ID {request_id} does not exist, deletion is not allowed"
                ))
            })?;
            match entry {
                StoredEntry::Pending(arc) => {
                    if Arc::strong_count(arc) > 1 {
                        anyhow::bail!(
                            "The element with ID {request_id} is currently locked and cannot be deleted"
                        );
                    }
                }
                StoredEntry::Done(_, _) => { /* no permit possible on Done */ }
                StoredEntry::Deleted => {
                    anyhow::bail!("The element with ID {request_id} has already been deleted");
                }
            }
        }
        // Safe: we just verified the entry exists and is not Deleted.
        let cell = self.storage.get_mut(request_id).unwrap();
        // TODO ensure we can just clone the old entry
        let old = std::mem::replace(cell, StoredEntry::Deleted);
        if matches!(old, StoredEntry::Done(_, _)) {
            self.complete_queue.retain(|id| id != request_id);
        }
        Ok(old.into())
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
        self.verify_invariant();
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
            .filter_map(|id| match self.storage.get(id) {
                Some(StoredEntry::Done(Err(_), _)) => Some(*id),
                Some(_) => None,
                None => {
                    tracing::error!("INVARIANT VIOLATION: Completed item {id} not found in storage - data corruption detected");
                    None
                }
            })
            .collect()
    }

    /// Get deleted request IDs (requests that have been deleted)
    /// WARNING: This is a slow operation
    pub fn get_deleted_request_ids(&self) -> Vec<RequestId> {
        self.storage
            .iter()
            .filter_map(|(id, state)| match state {
                StoredEntry::Deleted => Some(*id),
                _ => None,
            })
            .collect()
    }
}

#[cfg(feature = "non-wasm")]
pub(crate) fn add_req_to_meta_store<T>(
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
    meta_store.insert(req_id).map_err(|e| {
        // We likely reached capacity here
        MetricedError::new(request_metric, Some(*req_id), e, tonic::Code::Aborted)
    })
}

#[cfg(feature = "non-wasm")]
pub(crate) fn update_req_in_meta_store<
    T,
    E: Into<Box<dyn std::error::Error + Send + Sync>> + fmt::Debug,
>(
    meta_store: &mut RwLockWriteGuard<'_, MetaStore<T>>,
    permit: MetaStorePermit,
    result: Result<T, E>,
    request_metric: &'static str,
) -> bool {
    match result {
        Ok(res) => update_ok_req_in_meta_store(meta_store, permit, res, request_metric),
        Err(e) => {
            update_err_req_in_meta_store(meta_store, permit, format!("{e:?}"), request_metric)
        }
    }
}

#[cfg(feature = "non-wasm")]
pub(crate) fn update_ok_req_in_meta_store<T>(
    meta_store: &mut RwLockWriteGuard<'_, MetaStore<T>>,
    permit: MetaStorePermit,
    result: T,
    request_metric: &'static str,
) -> bool {
    let req_id = permit.req_id;
    match meta_store.update(Ok(result), permit) {
        Ok(()) => true,
        Err(e) => {
            MetricedError::handle_unreturnable_error(request_metric, Some(req_id), e);
            false
        }
    }
}

/// Helper method for updating the meta store with an error result.
/// The method gracefully handles potential update failures by logging and updating metrics.
/// [permit] is consumed to mark the entry done.
/// [error] is the error message to store.
/// [request_metric] is a free-form string used only for error logging the origin of the failure.
/// Returns true if the update was successful, false otherwise.
#[cfg(feature = "non-wasm")]
pub(crate) fn update_err_req_in_meta_store<T>(
    meta_store: &mut RwLockWriteGuard<'_, MetaStore<T>>,
    permit: MetaStorePermit,
    error: String,
    request_metric: &'static str,
) -> bool {
    let req_id = permit.req_id;
    MetricedError::handle_unreturnable_error(request_metric, Some(req_id), error.clone());
    match meta_store.update(Err(error.clone()), permit) {
        Ok(()) => true,
        Err(e) => {
            tracing::error!(
                "Failed to update meta store on request ID {req_id} with error message \"{error}\" due to update error: {e}"
            );
            false
        }
    }
}

/// Helper for retrieving the result of a request from a meta store.
///
/// Polls the meta store every [`META_STORE_POLL_INTERVAL`] until either the
/// entry is `Done`, becomes unreachable, or the timeout expires.
///
/// Returns `Arc<T>` on success; `Unavailable` if the entry is still pending at
/// timeout; `NotFound` if missing or deleted; `Internal`/`Aborted` if the entry
/// completed with an error.
///
/// Each poll iteration acquires the read lock briefly and releases it before
/// sleeping, so other writers are not blocked.
#[cfg(feature = "non-wasm")]
pub(crate) async fn retrieve_from_meta_store<T>(
    meta_store: &Arc<RwLock<MetaStore<T>>>,
    req_id: &RequestId,
    metric_scope: &'static str,
) -> Result<Arc<T>, MetricedError> {
    let deadline = Instant::now() + Duration::from_secs(DURATION_WAITING_ON_RESULT_SECONDS);
    loop {
        match poll_entry(meta_store, req_id, metric_scope).await {
            PollOutcome::Done(res) => return res,
            PollOutcome::Pending => {
                if Instant::now() >= deadline {
                    let msg = format!(
                        "Result in scope {metric_scope} with request ID {req_id} not completed after {DURATION_WAITING_ON_RESULT_SECONDS} seconds"
                    );
                    tracing::info!(msg);
                    return Err(MetricedError::new(
                        metric_scope,
                        Some(*req_id),
                        anyhow!(msg),
                        tonic::Code::Unavailable,
                    ));
                }
                tokio::time::sleep(META_STORE_POLL_INTERVAL).await;
            }
        }
    }
}

#[cfg(feature = "non-wasm")]
enum PollOutcome<T> {
    Done(Result<Arc<T>, MetricedError>),
    Pending,
}

#[cfg(feature = "non-wasm")]
async fn poll_entry<T>(
    meta_store: &Arc<RwLock<MetaStore<T>>>,
    req_id: &RequestId,
    metric_scope: &'static str,
) -> PollOutcome<T> {
    let guard = meta_store.read().await;
    match guard.retrieve(req_id) {
        None | Some(EntryState::Deleted) => {
            let msg = format!(
                "Could not retrieve the result in scope {metric_scope} with request ID {req_id}. It does not exist"
            );
            PollOutcome::Done(Err(MetricedError::new(
                metric_scope,
                Some(*req_id),
                anyhow!(msg),
                tonic::Code::NotFound,
            )))
        }
        Some(EntryState::Pending) => PollOutcome::Pending,
        Some(EntryState::Done(Ok(arc))) => PollOutcome::Done(Ok(arc)),
        Some(EntryState::Done(Err(e))) => {
            let msg = format!(
                "Could not retrieve the result in scope {metric_scope} with request ID {req_id} since it finished with an error: {e}"
            );
            tracing::warn!(msg);
            let code = if e.to_ascii_lowercase().contains("abort") {
                tonic::Code::Aborted
            } else {
                tonic::Code::Internal
            };
            PollOutcome::Done(Err(MetricedError::new(
                metric_scope,
                Some(*req_id),
                anyhow!(msg),
                code,
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::base::derive_request_id;
    use kms_grpc::RequestId;

    fn assert_done_ok<T: PartialEq + std::fmt::Debug>(
        store: &MetaStore<T>,
        id: &RequestId,
        expected: &T,
    ) {
        match store.retrieve(id).expect("entry missing") {
            EntryState::Done(Ok(arc)) => assert_eq!(arc.as_ref(), expected),
            other => panic!(
                "expected Done(Ok), got {:?}",
                match other {
                    EntryState::Pending => "Pending",
                    EntryState::Done(Err(_)) => "Done(Err)",
                    EntryState::Deleted => "Deleted",
                    EntryState::Done(Ok(_)) => unreachable!(),
                }
            ),
        }
    }

    #[test]
    fn sunshine() {
        let mut meta_store: MetaStore<String> = MetaStore::new(2, 1);
        let request_id: RequestId = derive_request_id("meta_store").unwrap();
        assert!(!meta_store.exists(&request_id));

        let permit = meta_store.insert(&request_id).unwrap();
        assert!(meta_store.exists(&request_id));
        assert!(meta_store.update(Ok("OK".to_string()), permit).is_ok());
        assert_done_ok(&meta_store, &request_id, &"OK".to_string());
    }

    #[test]
    fn test_kickout_of_errors() {
        let mut meta_store: MetaStore<String> = MetaStore::new(2, 1);
        let id1: RequestId = derive_request_id("1").unwrap();
        let id2: RequestId = derive_request_id("2").unwrap();
        let id3: RequestId = derive_request_id("3").unwrap();
        let p1 = meta_store.insert(&id1).unwrap();
        assert!(meta_store.update(Err("Err1".to_string()), p1).is_ok());
        let p2 = meta_store.insert(&id2).unwrap();
        assert!(meta_store.update(Ok("OK2".to_string()), p2).is_ok());
        // storage full, eviction should kick id1 out
        let p3 = meta_store.insert(&id3).unwrap();
        assert!(meta_store.update(Err("Err3".to_string()), p3).is_ok());

        assert!(!meta_store.exists(&id1));
        assert!(meta_store.exists(&id2));
        assert!(meta_store.exists(&id3));
    }

    #[test]
    fn double_insert() {
        let mut meta_store: MetaStore<String> = MetaStore::new(2, 1);
        let id: RequestId = derive_request_id("meta_store").unwrap();
        let _p = meta_store.insert(&id).unwrap();
        assert!(meta_store.insert(&id).is_err());
    }

    #[test]
    fn too_many_elements() {
        let mut meta_store: MetaStore<String> = MetaStore::new(2, 1);
        let id1: RequestId = derive_request_id("1").unwrap();
        let id2: RequestId = derive_request_id("2").unwrap();
        let id3: RequestId = derive_request_id("3").unwrap();
        let _p1 = meta_store.insert(&id1).unwrap();
        let _p2 = meta_store.insert(&id2).unwrap();
        assert!(meta_store.insert(&id3).is_err());
    }

    #[test]
    fn auto_remove() {
        let mut meta_store: MetaStore<String> = MetaStore::new(2, 1);
        let id1: RequestId = derive_request_id("1").unwrap();
        let id2: RequestId = derive_request_id("2").unwrap();
        let id3: RequestId = derive_request_id("3").unwrap();
        let p1 = meta_store.insert(&id1).unwrap();
        assert!(meta_store.update(Ok("OK".to_string()), p1).is_ok());
        assert!(meta_store.retrieve(&id1).is_some());
        let p2 = meta_store.insert(&id2).unwrap();
        assert!(meta_store.update(Ok("OK".to_string()), p2).is_ok());
        assert!(meta_store.retrieve(&id1).is_some());
        assert!(meta_store.retrieve(&id2).is_some());
        let p3 = meta_store.insert(&id3).unwrap();
        assert!(meta_store.retrieve(&id3).is_some());
        assert!(meta_store.retrieve(&id2).is_some());
        // Oldest removed during insert's eviction step
        assert!(meta_store.retrieve(&id1).is_none());
        let _ = p3;
    }

    #[test]
    fn try_delete_blocked_by_live_permit() {
        let mut meta_store: MetaStore<String> = MetaStore::new(2, 1);
        let id: RequestId = derive_request_id("locked-del").unwrap();
        let permit = meta_store.insert(&id).unwrap();
        assert!(meta_store.try_delete(&id).is_err());
        drop(permit);
        assert!(meta_store.try_delete(&id).is_ok());
        assert!(matches!(
            meta_store.retrieve(&id),
            Some(EntryState::Deleted)
        ));
    }

    #[test]
    fn delete_consumes_permit() {
        let mut meta_store: MetaStore<String> = MetaStore::new(2, 1);
        let id: RequestId = derive_request_id("perm-del").unwrap();
        let permit = meta_store.insert(&id).unwrap();
        let prev = meta_store.delete(permit).unwrap();
        assert!(matches!(prev, EntryState::Pending));
        assert!(matches!(
            meta_store.retrieve(&id),
            Some(EntryState::Deleted)
        ));
        // Cannot delete twice.
        assert!(meta_store.try_delete(&id).is_err());
    }

    #[test]
    fn permit_send_across_spawn() {
        // Compile-time check: MetaStorePermit must be Send so it can be
        // moved into tokio::spawn closures.
        fn assert_send<T: Send>() {}
        assert_send::<MetaStorePermit>();
    }
}

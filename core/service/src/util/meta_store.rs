use kms_grpc::RequestId;
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};
use thiserror::Error;
use tracing;

cfg_if::cfg_if! {
    if #[cfg(feature = "non-wasm")] {
        use crate::consts::DURATION_WAITING_ON_RESULT_SECONDS;
        use crate::engine::utils::MetricedError;
        use anyhow::anyhow;
        use std::fmt::{self};
        use std::time::Duration;
        use tokio::sync::RwLock;
        use tokio::time::Instant;
    }
}

/// Errors returned by [`MetaStore`] operations.
///
/// Each variant has a stable `tonic::Code` mapping via [`MetaStoreError::code`]
/// (non-wasm only), so callers can convert into a `MetricedError` without
/// hand-coding the code per callsite.
#[derive(Error, Debug)]
pub(crate) enum MetaStoreError {
    /// `insert` saw an entry already stored at this request id.
    #[error("the element with ID {req_id} already exists; cannot insert twice")]
    AlreadyExists { req_id: RequestId },

    /// `insert` could not make room: the store is at capacity and the
    /// completed-cache is at or below its minimum size.
    #[error(
        "meta store is full and the completed cache is at its minimum size; cannot insert {req_id}"
    )]
    CapacityFull { req_id: RequestId },

    /// No entry exists for this request id.
    #[error("the element with ID {req_id} does not exist")]
    NotFound { req_id: RequestId },

    /// Entry is in an in-flight state: either still `Pending` or another
    /// caller holds a live `MetaStorePermit`. Both situations block mutation
    /// and the caller may want to retry once the holder is done.
    #[error("the element with ID {req_id} is locked (pending or held by another permit)")]
    Locked { req_id: RequestId },

    /// Entry is in a state from which the requested mutation cannot proceed:
    /// either already tombstoned (`Deleted`), or its value is already set
    /// (`Done`) when the caller expected `Pending`. Permanent — retrying
    /// will not unblock.
    #[error("the element with ID {req_id} cannot be updated (deleted or already set)")]
    CannotUpdate { req_id: RequestId },

    /// Storage / queue invariant breakage. Should be unreachable in correct
    /// execution; surfaced rather than panicked so the calling RPC can fail
    /// gracefully while we still log loudly at the construction site.
    #[error("meta store invariant violated: {0}")]
    Invariant(String),
}

#[cfg(feature = "non-wasm")]
impl MetaStoreError {
    /// gRPC code that best describes the failure to a remote caller.
    pub fn code(&self) -> tonic::Code {
        use MetaStoreError::*;
        match self {
            AlreadyExists { .. } => tonic::Code::AlreadyExists,
            CapacityFull { .. } => tonic::Code::ResourceExhausted,
            NotFound { .. } => tonic::Code::NotFound,
            Locked { .. } | CannotUpdate { .. } => tonic::Code::FailedPrecondition,
            Invariant(_) => tonic::Code::Internal,
        }
    }

    /// Request id this error is about, if it is request-scoped.
    pub fn req_id(&self) -> Option<RequestId> {
        use MetaStoreError::*;
        match self {
            AlreadyExists { req_id }
            | CapacityFull { req_id }
            | NotFound { req_id }
            | Locked { req_id }
            | CannotUpdate { req_id } => Some(*req_id),
            Invariant(_) => None,
        }
    }

    /// Convert into a [`MetricedError`] using the caller's operation metric.
    pub fn into_metriced(self, op_metric: &'static str) -> MetricedError {
        let code = self.code();
        let req_id = self.req_id();
        MetricedError::new(op_metric, req_id, self, code)
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

impl<T> std::fmt::Display for EntryState<T> {
    /// Render the state variant (without the contained value, which need not be
    /// `Display`), e.g. for diagnostics and assertion messages.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            EntryState::Pending => "Pending",
            EntryState::Done(Ok(_)) => "Done(Ok)",
            EntryState::Done(Err(_)) => "Done(Err)",
            EntryState::Deleted => "Deleted",
        };
        f.write_str(name)
    }
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

    #[allow(dead_code)]
    pub(crate) fn exists(&self, request_id: &RequestId) -> bool {
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
    pub(crate) fn insert(
        &mut self,
        request_id: &RequestId,
    ) -> Result<MetaStorePermit, MetaStoreError> {
        // `Deleted` is a permanent tombstone: a request id, once deleted, may
        // not be reused for a fresh insert. Callers that need to overwrite an
        // existing entry should use [`reserve`](MetaStore::reserve) +
        // [`finalize`](MetaStore::finalize) instead.
        if self.storage.contains_key(request_id) {
            return Err(MetaStoreError::AlreadyExists {
                req_id: *request_id,
            });
        }
        if self.storage.len() >= self.capacity {
            if self.complete_queue.len() <= self.min_cache {
                return Err(MetaStoreError::CapacityFull {
                    req_id: *request_id,
                });
            } else {
                let old_request_id = self.complete_queue.pop_front().ok_or_else(|| {
                    let msg = format!(
                        "complete_queue empty but len > min_cache while inserting {request_id}"
                    );
                    tracing::error!(msg);
                    MetaStoreError::Invariant(msg)
                })?;
                if self.storage.remove(&old_request_id).is_none() {
                    self.complete_queue.push_front(old_request_id);
                    let msg = format!(
                        "failed to remove old element {old_request_id} from storage while inserting {request_id}"
                    );
                    tracing::error!(msg);
                    return Err(MetaStoreError::Invariant(msg));
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

    /// Acquire a permit for an existing entry, returning an error if the entry does not exist, is already completed, or is currently held by another permit.
    ///
    /// This is intended for callers that need to update or delete an existing entry but do not hold its original insert permit.
    ///
    /// Note that acquiring a permit on an existing entry does not change its state: the entry remains `Pending` or `Done` as it was before.
    pub(crate) fn lock_entry(
        &mut self,
        request_id: &RequestId,
    ) -> Result<MetaStorePermit, MetaStoreError> {
        let claim = {
            let entry = self
                .storage
                .get(request_id)
                .ok_or(MetaStoreError::NotFound {
                    req_id: *request_id,
                })?;
            match entry {
                StoredEntry::Pending(arc) | StoredEntry::Done(_, arc) => {
                    if Arc::strong_count(arc) > 1 {
                        return Err(MetaStoreError::Locked {
                            req_id: *request_id,
                        });
                    }
                    Arc::clone(arc)
                }
                StoredEntry::Deleted => {
                    return Err(MetaStoreError::CannotUpdate {
                        req_id: *request_id,
                    });
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
    fn update(
        &mut self,
        update: Result<T, String>,
        permit: MetaStorePermit,
    ) -> Result<(), MetaStoreError> {
        let req_id = permit.req_id;
        let cell = self
            .storage
            .get_mut(&req_id)
            .ok_or(MetaStoreError::NotFound { req_id })?;
        if !matches!(cell, StoredEntry::Pending(_)) {
            return Err(MetaStoreError::CannotUpdate { req_id });
        }
        *cell = StoredEntry::done(update.map(Arc::new));
        self.complete_queue.push_back(req_id);
        // `permit` (and its Arc<()>) dropped at end of scope.
        Ok(())
    }

    /// Reserve `request_id` for an exclusive get-or-create write, returning a
    /// [`MetaStorePermit`] held for the duration of the caller's work.
    ///
    /// - Absent: a fresh `Pending` entry is inserted and its permit returned.
    /// - Existing `Pending`/`Done` with no live permit: locked in place (its
    ///   value, if any, is preserved) and a permit returned.
    /// - Already held by another permit: returns a [`MetaStoreError::Locked`] error.
    /// - `Deleted` tombstone: returns a [`MetaStoreError::CannotUpdate`] error.
    ///
    /// Complete the reservation with [`MetaStore::finalize`] or roll it back
    /// with [`MetaStore::abort_reservation`]; both consume the permit.
    ///
    /// Note: This method is not intended for general-purpose use; it is designed to support the specific edge-case when upgrading existing keys.
    pub(crate) fn reserve(
        &mut self,
        request_id: &RequestId,
    ) -> Result<MetaStorePermit, MetaStoreError> {
        match self.storage.get(request_id) {
            None => self.insert(request_id),
            Some(_) => self.lock_entry(request_id),
        }
    }

    /// Complete a reservation from [`MetaStore::reserve`] by setting the entry
    /// to `Done(Ok(value))`, consuming the permit. The held permit is the proof
    /// of ownership, so unlike [`reserve`](MetaStore::reserve) no strong-count
    /// check is performed.
    ///
    /// A freshly created (`Pending`) entry is recorded in the completion queue;
    /// an existing `Done` entry locked in place is overwritten while keeping its
    /// queue slot. Errors with [`MetaStoreError::NotFound`] if the entry was
    /// evicted while reserved, or [`MetaStoreError::CannotUpdate`] if it was
    /// concurrently tombstoned.
    pub(crate) fn finalize(
        &mut self,
        permit: MetaStorePermit,
        value: T,
    ) -> Result<(), MetaStoreError> {
        let req_id = permit.req_id;
        let cell = self
            .storage
            .get_mut(&req_id)
            .ok_or(MetaStoreError::NotFound { req_id })?;
        match cell {
            StoredEntry::Deleted => return Err(MetaStoreError::CannotUpdate { req_id }),
            StoredEntry::Pending(_) => {
                // First completion of this entry — record it as completed.
                *cell = StoredEntry::done(Ok(Arc::new(value)));
                self.complete_queue.push_back(req_id);
            }
            StoredEntry::Done(_, _) => {
                // Existing Done locked in place — overwrite, keep the queue slot.
                *cell = StoredEntry::done(Ok(Arc::new(value)));
            }
        }
        // `permit` (and its claim) dropped at end of scope.
        Ok(())
    }

    /// Roll back a reservation from [`MetaStore::reserve`] without completing
    /// it, consuming the permit.
    ///
    /// If the reserved entry is still `Pending` (a fresh create, or an adopted
    /// orphan from an earlier aborted attempt) it is **removed outright** — not
    /// tombstoned — so `request_id` stays reusable and a later
    /// [`reserve`](MetaStore::reserve) can recreate it. An existing `Done` entry
    /// that was merely locked in place is left untouched; only the permit's
    /// claim is released.
    ///
    /// Note: This is not the typical and desired usage, but is only added to support the tedious edge case of migrating existing keys.
    pub(crate) fn abort_reservation(&mut self, permit: MetaStorePermit) {
        let req_id = permit.req_id;
        if matches!(self.storage.get(&req_id), Some(StoredEntry::Pending(_))) {
            // Fresh/adopted reservation: drop it entirely. A `Pending` entry is
            // never in the completion queue, so no queue cleanup is needed.
            self.storage.remove(&req_id);
        }
        // `Done` (locked existing) or already gone: nothing to undo.
        // `permit` (and its claim) dropped at end of scope.
    }

    /// Retrieve the state of an element and return None if it does not exist.
    ///
    /// Returns an [`EntryState`] snapshot by value; the internal claim arc on
    /// `Pending` / `Done` is intentionally hidden from external callers, who
    /// should not depend on locking state.
    pub(crate) fn retrieve(&self, request_id: &RequestId) -> Option<EntryState<T>> {
        self.storage.get(request_id).map(EntryState::from)
    }

    /// Mark an existing entry as deleted, regardless of whether it was Pending
    /// or Done. Consumes the permit. Returns the previous state. If the previous
    /// state was `Done`, the entry is also removed from the completion queue.
    fn delete(&mut self, permit: MetaStorePermit) -> Result<EntryState<T>, MetaStoreError> {
        let req_id = permit.req_id;
        let cell = self
            .storage
            .get_mut(&req_id)
            .ok_or(MetaStoreError::NotFound { req_id })?;
        if matches!(cell, StoredEntry::Deleted) {
            return Err(MetaStoreError::CannotUpdate { req_id });
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
    pub(crate) fn try_delete(
        &mut self,
        request_id: &RequestId,
    ) -> Result<EntryState<T>, MetaStoreError> {
        {
            let entry = self
                .storage
                .get(request_id)
                .ok_or(MetaStoreError::NotFound {
                    req_id: *request_id,
                })?;
            match entry {
                StoredEntry::Pending(arc) => {
                    if Arc::strong_count(arc) > 1 {
                        return Err(MetaStoreError::Locked {
                            req_id: *request_id,
                        });
                    }
                }
                StoredEntry::Done(_, _) => { /* no permit possible on Done */ }
                StoredEntry::Deleted => {
                    return Err(MetaStoreError::CannotUpdate {
                        req_id: *request_id,
                    });
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
    pub(crate) fn get_capacity(&self) -> usize {
        self.capacity
    }

    /// Get the current number of items in the store
    pub(crate) fn get_current_count(&self) -> usize {
        self.storage.len()
    }

    /// Get the total number of items in the store (alias for get_current_count)
    pub(crate) fn get_total_count(&self) -> usize {
        self.get_current_count()
    }

    /// Get the number of completed items
    #[allow(dead_code)]
    pub(crate) fn get_completed_count(&self) -> usize {
        self.complete_queue.len()
    }

    /// Get the number of items currently being processed
    pub(crate) fn get_processing_count(&self) -> usize {
        self.verify_invariant();
        self.storage.len().saturating_sub(self.complete_queue.len())
    }

    /// Get all request IDs in the store
    pub(crate) fn get_all_request_ids(&self) -> Vec<RequestId> {
        self.storage.keys().cloned().collect()
    }

    /// Get completed request IDs. That is, this excludes request IDs that have been deleted or are pending.
    pub(crate) fn get_completed_request_ids(&self) -> Vec<RequestId> {
        self.complete_queue.iter().cloned().collect()
    }

    /// Get processing request IDs (not yet completed)
    pub(crate) fn get_processing_request_ids(&self) -> Vec<RequestId> {
        self.storage
            .keys()
            .filter(|id| !self.complete_queue.contains(id))
            .cloned()
            .collect()
    }

    /// Get failed request IDs (completed with errors)
    /// WARNING: This is a slow operation
    pub(crate) fn get_failed_request_ids(&self) -> Vec<RequestId> {
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
    pub(crate) fn get_deleted_request_ids(&self) -> Vec<RequestId> {
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
pub(crate) async fn add_req_to_meta_store<T>(
    meta_store: &RwLock<MetaStore<T>>,
    req_id: &RequestId,
    request_metric: &'static str,
) -> Result<MetaStorePermit, MetricedError> {
    meta_store
        .write()
        .await
        .insert(req_id)
        .map_err(|e| e.into_metriced(request_metric))
}

#[cfg(feature = "non-wasm")]
pub(crate) async fn update_req_in_meta_store<
    T,
    E: Into<Box<dyn std::error::Error + Send + Sync>> + fmt::Debug,
>(
    meta_store: &RwLock<MetaStore<T>>,
    permit: MetaStorePermit,
    result: Result<T, E>,
    request_metric: &'static str,
) -> bool {
    match result {
        Ok(res) => update_ok_req_in_meta_store(meta_store, permit, res, request_metric).await,
        Err(e) => {
            update_err_req_in_meta_store(meta_store, permit, format!("{e:?}"), request_metric).await
        }
    }
}

#[cfg(feature = "non-wasm")]
pub(crate) async fn update_ok_req_in_meta_store<T>(
    meta_store: &RwLock<MetaStore<T>>,
    permit: MetaStorePermit,
    result: T,
    request_metric: &'static str,
) -> bool {
    let req_id = permit.req_id;
    match meta_store.write().await.update(Ok(result), permit) {
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
pub(crate) async fn update_err_req_in_meta_store<T>(
    meta_store: &RwLock<MetaStore<T>>,
    permit: MetaStorePermit,
    error: String,
    request_metric: &'static str,
) -> bool {
    let req_id = permit.req_id;
    MetricedError::handle_unreturnable_error(request_metric, Some(req_id), error.clone());
    match meta_store.write().await.update(Err(error.clone()), permit) {
        Ok(()) => true,
        Err(e) => {
            tracing::error!(
                "Failed to update meta store on request ID {req_id} with error message \"{error}\" due to update error: {e}"
            );
            false
        }
    }
}

#[cfg(feature = "non-wasm")]
pub(crate) async fn delete_in_meta_store<T>(
    meta_store: &RwLock<MetaStore<T>>,
    permit: MetaStorePermit,
    error: String,
    request_metric: &'static str,
) -> bool {
    let req_id = permit.req_id;
    MetricedError::handle_unreturnable_error(request_metric, Some(req_id), error.clone());
    match meta_store.write().await.delete(permit) {
        Ok(_) => true,
        Err(e) => {
            tracing::error!(
                "Failed to delete request ID {req_id} from meta-store, with error message {e}"
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
    meta_store: &RwLock<MetaStore<T>>,
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
    meta_store: &RwLock<MetaStore<T>>,
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

    /// Insert `id` and immediately drive it to `Done(Ok(value))`, consuming the
    /// permit. Mirrors the common `insert -> update` lifecycle used by callers.
    fn insert_done_ok(store: &mut MetaStore<String>, id: &RequestId, value: &str) {
        let permit = store.insert(id).unwrap();
        store.update(Ok(value.to_string()), permit).unwrap();
    }

    /// Insert `id` and immediately drive it to `Done(Err(err))`, consuming the
    /// permit.
    fn insert_done_err(store: &mut MetaStore<String>, id: &RequestId, err: &str) {
        let permit = store.insert(id).unwrap();
        store.update(Err(err.to_string()), permit).unwrap();
    }

    fn assert_done_ok<T: PartialEq + std::fmt::Debug>(
        store: &MetaStore<T>,
        id: &RequestId,
        expected: &T,
    ) {
        match store.retrieve(id).expect("entry missing") {
            EntryState::Done(Ok(arc)) => assert_eq!(arc.as_ref(), expected),
            other => panic!("expected Done(Ok), got {other}"),
        }
    }

    fn assert_done_err<T>(store: &MetaStore<T>, id: &RequestId, expected: &str) {
        match store.retrieve(id).expect("entry missing") {
            EntryState::Done(Err(e)) => assert_eq!(e, expected),
            other => panic!("expected Done(Err), got {other}"),
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

    #[test]
    fn error_variants() {
        let mut store: MetaStore<String> = MetaStore::new(1, 1);
        let id = derive_request_id("err-variant").unwrap();
        let permit = store.insert(&id).unwrap();
        assert!(matches!(
            store.insert(&id),
            Err(MetaStoreError::AlreadyExists { .. })
        ));
        let id2 = derive_request_id("err-variant-2").unwrap();
        assert!(matches!(
            store.insert(&id2),
            Err(MetaStoreError::CapacityFull { .. })
        ));

        let missing = derive_request_id("err-missing").unwrap();
        assert!(matches!(
            store.lock_entry(&missing),
            Err(MetaStoreError::NotFound { .. })
        ));
        assert!(matches!(
            store.lock_entry(&id),
            Err(MetaStoreError::Locked { .. })
        ));
        assert!(matches!(
            store.try_delete(&id),
            Err(MetaStoreError::Locked { .. })
        ));

        // Drop the permit, mark id done, then attempt update again to hit CannotUpdate.
        store.update(Ok("OK".to_string()), permit).unwrap();
        let permit2 = store.lock_entry(&id).unwrap();
        assert!(matches!(
            store.update(Ok("again".to_string()), permit2),
            Err(MetaStoreError::CannotUpdate { .. })
        ));

        // After deletion, try_delete reports CannotUpdate.
        store.try_delete(&id).unwrap();
        assert!(matches!(
            store.try_delete(&id),
            Err(MetaStoreError::CannotUpdate { .. })
        ));
    }

    #[test]
    fn lock_entry_requires_released_insert_permit() {
        // The insert permit holds the claim, so the entry cannot be re-locked
        // until that permit is dropped.
        let mut store: MetaStore<String> = MetaStore::new(2, 1);
        let id = derive_request_id("lock-pending").unwrap();
        let insert_permit = store.insert(&id).unwrap();
        assert!(matches!(
            store.lock_entry(&id),
            Err(MetaStoreError::Locked { .. })
        ));
        drop(insert_permit);
        // Now lockable; the resulting permit again blocks a second lock.
        let lock_permit = store.lock_entry(&id).unwrap();
        assert!(matches!(
            store.lock_entry(&id),
            Err(MetaStoreError::Locked { .. })
        ));
        drop(lock_permit);
        assert!(store.lock_entry(&id).is_ok());
    }

    #[test]
    fn lock_then_update_completes_entry() {
        // A relocked Pending entry can be completed through the new permit.
        let mut store: MetaStore<String> = MetaStore::new(2, 1);
        let id = derive_request_id("lock-update").unwrap();
        drop(store.insert(&id).unwrap());
        let permit = store.lock_entry(&id).unwrap();
        assert!(matches!(store.retrieve(&id), Some(EntryState::Pending)));
        store.update(Ok("done".to_string()), permit).unwrap();
        assert_done_ok(&store, &id, &"done".to_string());
    }

    #[test]
    fn lock_entry_on_done_then_delete() {
        // A completed entry has a free claim and can be locked, then deleted
        // through that permit; deletion drops it from the completed queue.
        let mut store: MetaStore<String> = MetaStore::new(2, 1);
        let id = derive_request_id("lock-done-del").unwrap();
        insert_done_ok(&mut store, &id, "v");
        assert_eq!(store.get_completed_count(), 1);
        let permit = store.lock_entry(&id).unwrap();
        let prev = store.delete(permit).unwrap();
        assert!(matches!(prev, EntryState::Done(Ok(_))));
        assert!(matches!(store.retrieve(&id), Some(EntryState::Deleted)));
        assert_eq!(store.get_completed_count(), 0);
    }

    #[test]
    fn lock_entry_blocks_try_delete_until_released() {
        // A permit acquired via `lock_entry` on a still-Pending entry blocks a
        // permit-less `try_delete` just like the original insert permit does.
        let mut store: MetaStore<String> = MetaStore::new(2, 1);
        let id = derive_request_id("lock-blocks-del").unwrap();
        drop(store.insert(&id).unwrap());
        let permit = store.lock_entry(&id).unwrap();
        assert!(matches!(
            store.try_delete(&id),
            Err(MetaStoreError::Locked { .. })
        ));
        drop(permit);
        assert!(store.try_delete(&id).is_ok());
    }

    #[test]
    fn lock_entry_on_deleted_cannot_update() {
        let mut store: MetaStore<String> = MetaStore::new(2, 1);
        let id = derive_request_id("lock-deleted").unwrap();
        drop(store.insert(&id).unwrap());
        assert!(store.try_delete(&id).is_ok());
        assert!(matches!(
            store.lock_entry(&id),
            Err(MetaStoreError::CannotUpdate { .. })
        ));
    }

    #[test]
    fn try_delete_done_returns_previous_value() {
        let mut store: MetaStore<String> = MetaStore::new(2, 1);
        let id = derive_request_id("try-del-done").unwrap();
        insert_done_ok(&mut store, &id, "payload");
        assert_eq!(store.get_completed_count(), 1);
        let prev = store.try_delete(&id).unwrap();
        match prev {
            EntryState::Done(Ok(arc)) => assert_eq!(arc.as_ref(), "payload"),
            other => panic!("expected Done(Ok), got {other}"),
        }
        assert!(matches!(store.retrieve(&id), Some(EntryState::Deleted)));
        assert_eq!(store.get_completed_count(), 0);
    }

    #[test]
    fn reserve_creates_fresh_then_finalize_completes() {
        // No entry yet: reserve creates a Pending placeholder (not yet queued),
        // and finalize drives it to Done and records it as completed.
        let mut store: MetaStore<String> = MetaStore::new(2, 1);
        let id = derive_request_id("reserve-fresh").unwrap();
        let permit = store.reserve(&id).unwrap();
        assert!(matches!(store.retrieve(&id), Some(EntryState::Pending)));
        assert_eq!(store.get_completed_count(), 0);
        store.finalize(permit, "v1".to_string()).unwrap();
        assert_done_ok(&store, &id, &"v1".to_string());
        assert_eq!(store.get_completed_count(), 1);
    }

    #[test]
    fn reserve_locks_existing_done_then_finalize_overwrites() {
        // Existing Done: reserve locks it in place (value preserved), finalize
        // overwrites it while keeping the single completion-queue slot.
        let mut store: MetaStore<String> = MetaStore::new(2, 1);
        let id = derive_request_id("reserve-existing").unwrap();
        insert_done_ok(&mut store, &id, "v1");
        let permit = store.reserve(&id).unwrap();
        // Still Done with the old value while reserved.
        assert_done_ok(&store, &id, &"v1".to_string());
        store.finalize(permit, "v2".to_string()).unwrap();
        assert_done_ok(&store, &id, &"v2".to_string());
        assert_eq!(store.get_completed_count(), 1);
    }

    #[test]
    fn reserve_rejects_entry_held_by_other_permit() {
        // While one caller holds a permit (here from a prior reserve), a second
        // reserve is rejected — this is the cross-step mutual exclusion that
        // prevents two concurrent migrations from racing on the same id.
        let mut store: MetaStore<String> = MetaStore::new(2, 1);
        let id = derive_request_id("reserve-locked").unwrap();
        insert_done_ok(&mut store, &id, "v");
        let permit = store.reserve(&id).unwrap();
        assert!(matches!(
            store.reserve(&id),
            Err(MetaStoreError::Locked { .. })
        ));
        drop(permit);
        // Once released, a fresh reserve succeeds again.
        assert!(store.reserve(&id).is_ok());
    }

    #[test]
    fn reserve_rejects_deleted_entry() {
        let mut store: MetaStore<String> = MetaStore::new(2, 1);
        let id = derive_request_id("reserve-deleted").unwrap();
        insert_done_ok(&mut store, &id, "v");
        store.try_delete(&id).unwrap();
        assert!(matches!(
            store.reserve(&id),
            Err(MetaStoreError::CannotUpdate { .. })
        ));
    }

    #[test]
    fn abort_reservation_removes_fresh_entry_without_tombstoning() {
        // Aborting a freshly created reservation must remove the entry outright
        // (NOT tombstone it), so a retry can recreate it. This is the failure
        // path of copy_compressed_key_to_original.
        let mut store: MetaStore<String> = MetaStore::new(2, 1);
        let id = derive_request_id("abort-fresh").unwrap();
        let permit = store.reserve(&id).unwrap();
        store.abort_reservation(permit);
        // Gone entirely, not Deleted — so it is reservable/insertable again.
        assert!(store.retrieve(&id).is_none());
        let permit2 = store.reserve(&id).unwrap();
        store.finalize(permit2, "recovered".to_string()).unwrap();
        assert_done_ok(&store, &id, &"recovered".to_string());
    }

    #[test]
    fn abort_reservation_preserves_existing_done() {
        // Aborting a reservation that locked an existing Done leaves the prior
        // value and its completion-queue slot intact.
        let mut store: MetaStore<String> = MetaStore::new(2, 1);
        let id = derive_request_id("abort-existing").unwrap();
        insert_done_ok(&mut store, &id, "original");
        let permit = store.reserve(&id).unwrap();
        store.abort_reservation(permit);
        assert_done_ok(&store, &id, &"original".to_string());
        assert_eq!(store.get_completed_count(), 1);
        // Released: it can be reserved again afterwards.
        assert!(store.reserve(&id).is_ok());
    }

    #[test]
    fn reserve_after_failed_attempt_adopts_orphan_pending() {
        // Mirrors recovery when a prior migration created a Pending reservation
        // but its permit was dropped without finalize/abort (e.g. a task panic):
        // the orphan has no live permit, so a retry's reserve adopts it.
        let mut store: MetaStore<String> = MetaStore::new(2, 1);
        let id = derive_request_id("reserve-orphan").unwrap();
        drop(store.reserve(&id).unwrap()); // permit dropped, entry left Pending
        assert!(matches!(store.retrieve(&id), Some(EntryState::Pending)));
        let permit = store.reserve(&id).unwrap(); // adopts the orphan
        store.finalize(permit, "adopted".to_string()).unwrap();
        assert_done_ok(&store, &id, &"adopted".to_string());
        assert_eq!(store.get_completed_count(), 1);
    }

    #[test]
    fn new_from_map_seeds_completed_entries() {
        let a = derive_request_id("map-a").unwrap();
        let b = derive_request_id("map-b").unwrap();
        let mut map = HashMap::new();
        map.insert(a, "A".to_string());
        map.insert(b, "B".to_string());
        let store = MetaStore::new_from_map(map);

        assert_eq!(store.get_capacity(), usize::MAX);
        assert_eq!(store.get_current_count(), 2);
        assert_eq!(store.get_completed_count(), 2);
        assert_eq!(store.get_processing_count(), 0);
        assert!(store.exists(&a));
        assert!(store.exists(&b));
        assert_done_ok(&store, &a, &"A".to_string());
        assert_done_ok(&store, &b, &"B".to_string());

        let completed = store.get_completed_request_ids();
        assert_eq!(completed.len(), 2);
        assert!(completed.contains(&a) && completed.contains(&b));
    }

    #[test]
    fn count_and_listing_accessors() {
        let mut store: MetaStore<String> = MetaStore::new_unlimited();
        let pending1 = derive_request_id("c-p1").unwrap();
        let _p1 = store.insert(&pending1).unwrap();
        let pending2 = derive_request_id("c-p2").unwrap();
        let _p2 = store.insert(&pending2).unwrap();

        let ok = derive_request_id("c-ok").unwrap();
        insert_done_ok(&mut store, &ok, "ok-val");
        let err = derive_request_id("c-err").unwrap();
        insert_done_err(&mut store, &err, "boom");

        // Aggregate counts.
        assert_eq!(store.get_current_count(), 4);
        assert_eq!(store.get_total_count(), store.get_current_count());
        assert_eq!(store.get_completed_count(), 2);
        assert_eq!(store.get_processing_count(), 2);

        // Full id listing.
        let all = store.get_all_request_ids();
        assert_eq!(all.len(), 4);
        for id in [&ok, &err, &pending1, &pending2] {
            assert!(all.contains(id));
        }

        // Completed vs processing partition.
        let completed = store.get_completed_request_ids();
        assert_eq!(completed.len(), 2);
        assert!(completed.contains(&ok) && completed.contains(&err));

        let processing = store.get_processing_request_ids();
        assert_eq!(processing.len(), 2);
        assert!(processing.contains(&pending1) && processing.contains(&pending2));

        // Failed entries are the Done(Err) subset of the completed set.
        let failed = store.get_failed_request_ids();
        assert_eq!(failed, vec![err]);

        // No deletions yet.
        assert!(store.get_deleted_request_ids().is_empty());
        assert_done_err(&store, &err, "boom");
    }

    #[test]
    fn deleted_ids_are_listed_and_excluded_from_completed() {
        let mut store: MetaStore<String> = MetaStore::new_unlimited();
        let kept = derive_request_id("d-kept").unwrap();
        let gone = derive_request_id("d-gone").unwrap();
        insert_done_ok(&mut store, &kept, "keep");
        insert_done_ok(&mut store, &gone, "remove");
        store.try_delete(&gone).unwrap();

        let deleted = store.get_deleted_request_ids();
        assert_eq!(deleted, vec![gone]);
        // The deleted entry leaves the completed queue; the survivor stays.
        let completed = store.get_completed_request_ids();
        assert_eq!(completed, vec![kept]);
    }

    #[cfg(feature = "non-wasm")]
    #[test]
    fn error_code_mapping() {
        let id = RequestId::zeros();
        assert_eq!(
            MetaStoreError::AlreadyExists { req_id: id }.code(),
            tonic::Code::AlreadyExists
        );
        assert_eq!(
            MetaStoreError::CapacityFull { req_id: id }.code(),
            tonic::Code::ResourceExhausted
        );
        assert_eq!(
            MetaStoreError::NotFound { req_id: id }.code(),
            tonic::Code::NotFound
        );
        assert_eq!(
            MetaStoreError::Locked { req_id: id }.code(),
            tonic::Code::FailedPrecondition
        );
        assert_eq!(
            MetaStoreError::CannotUpdate { req_id: id }.code(),
            tonic::Code::FailedPrecondition
        );
        assert_eq!(
            MetaStoreError::Invariant("x".into()).code(),
            tonic::Code::Internal
        );
    }
}

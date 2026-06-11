//! Status store for in-flight and completed requests.
//!
//! # Two API layers
//!
//! Callers should prefer the **free helper functions** (`*_in_meta_store`) over
//! the inherent [`MetaStore`] methods. Each helper takes `&RwLock<MetaStore<T>>`,
//! acquires the lock internally for the shortest possible span, and releases it
//! before returning. A helper returns a [`MetricedError`] when the operation sits
//! on a gRPC request path (so the failure propagates to the client with metrics
//! recorded), and the raw [`MetaStoreError`] when the caller owns the outcome
//! (fire-and-forget completion paths, or internal `anyhow` flows).
//!
//! The **inherent `MetaStore` methods** are `pub(crate)` guard-level primitives:
//! the caller is assumed to already hold the appropriate `RwLock` guard, and they
//! do no metric bookkeeping. Reach for them directly only where the helper layer
//! does not fit — notably the key-migration path in
//! `copy_compressed_key_to_original`, which holds a single permit across a claim
//! on an existing entry ([`lock_entry`](MetaStore::lock_entry)) →
//! [`finalize`](MetaStore::finalize) /
//! [`abort_reservation`](MetaStore::abort_reservation) and is an `anyhow` flow.
//!
//! # Entry lifecycle
//!
//! `insert` → [`MetaStorePermit`] → (`update` to finish | `delete` to tombstone),
//! both consuming the permit. A dropped permit leaves the entry `Pending`;
//! [`try_delete`](MetaStore::try_delete) reclaims it.
//! [`lock_entry`](MetaStore::lock_entry) mints a permit for an existing entry
//! (used as a cross-lock sync point); pairing it with
//! [`finalize`](MetaStore::finalize) / [`abort_reservation`](MetaStore::abort_reservation)
//! supports in-place rewrites of an existing entry for key migration.
//!
//! Any meta store that is NOT used for decryption (user or public) should be unlimited and MUST ensure that all data elements are present.

use kms_grpc::RequestId;
use std::{
    collections::{HashMap, VecDeque},
    marker::PhantomData,
    sync::Arc,
};
use thiserror::Error;
use tracing;

cfg_if::cfg_if! {
    if #[cfg(feature = "non-wasm")] {
        use crate::engine::utils::MetricedError;
        use anyhow::anyhow;
        use std::fmt::{self};
        use tokio::sync::RwLock;
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
    pub(crate) fn code(&self) -> tonic::Code {
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
    pub(crate) fn req_id(&self) -> Option<RequestId> {
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
    pub(crate) fn into_metriced(self, op_metric: &'static str) -> MetricedError {
        let code = self.code();
        let req_id = self.req_id();
        MetricedError::new(op_metric, req_id, self, code)
    }
}

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
pub struct MetaStorePermit<T> {
    req_id: RequestId,
    _claim: Arc<()>,
    /// Needed to prevent permits of same `req_id` to be used across meta-stores.
    _phantom: PhantomData<T>,
}

impl<T> MetaStorePermit<T> {
    pub(crate) fn req_id(&self) -> &RequestId {
        &self.req_id
    }
}

/// Public-facing snapshot of an entry's state.
#[derive(Debug, Clone)]
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
    // Number of tombstoned (`Deleted`) entries still occupying `storage`.
    // Tombstones are permanent (never removed from `storage` nor evicted), so this
    // only ever grows. Tracked here so `get_processing_count` stays O(1) while
    // excluding tombstones (which are neither processing nor completed).
    deleted_count: usize,
}

impl<T> MetaStore<T> {
    /// Creates a new MetaStore with a given capacity and minimal cache size.
    /// In more detail, this means that the MetaStore will be able to hold [capacity] of total elements,
    /// of which we can be sure that at least [min_cache] elements are kept in the cache after completion
    /// (assuming that at least [min_cache] have been completed).
    /// The cache may be larger than [min_cache], but the total capacity will be limited to [capacity]
    pub(crate) fn new(capacity: usize, min_cache: usize) -> Self {
        Self {
            capacity,
            min_cache,
            storage: HashMap::with_capacity(capacity),
            complete_queue: VecDeque::with_capacity(min_cache),
            deleted_count: 0,
        }
    }

    /// Creates a new MetaStore with unlimited capacity and cache size.
    pub(crate) fn new_unlimited() -> Self {
        Self {
            capacity: usize::MAX,
            min_cache: usize::MAX,
            storage: HashMap::new(),
            complete_queue: VecDeque::new(),
            deleted_count: 0,
        }
    }

    /// Creates a MetaStore with unlimited storage capacity and minimum cache size and populates it with the given map
    pub(crate) fn new_from_map(map: HashMap<RequestId, T>) -> Self {
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
            deleted_count: 0,
        }
    }

    pub(crate) fn exists(&self, request_id: &RequestId) -> bool {
        self.storage.contains_key(request_id)
    }

    /// Verify the invariant that storage.len() >= complete_queue.len() + deleted_count
    /// (i.e. the processing count is non-negative). This is critical for preventing
    /// underflow in get_processing_count().
    /// Logs error if invariant is violated but does not panic
    fn verify_invariant(&self) -> bool {
        let is_valid = self.storage.len() >= self.complete_queue.len() + self.deleted_count;
        if !is_valid {
            tracing::error!(
                "INVARIANT VIOLATION: storage.len() ({}) < complete_queue.len() ({}) + deleted_count ({})",
                self.storage.len(),
                self.complete_queue.len(),
                self.deleted_count
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
    ) -> Result<MetaStorePermit<T>, MetaStoreError> {
        // `Deleted` is a permanent tombstone: a request id, once deleted, may
        // not be reused for a fresh insert. Callers that need to overwrite an
        // existing entry should use [`lock_entry`](MetaStore::lock_entry) +
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
                // Evict the oldest completed entry that has no outstanding
                // permit. A `Done` entry can be permit-held (via `reserve` /
                // `lock_entry`); evicting it would pull storage out from under
                // the holder, so we skip held entries (`strong_count > 1`).
                let evict_pos = {
                    let storage = &self.storage;
                    self.complete_queue.iter().position(|id| {
                        matches!(
                            storage.get(id),
                            Some(StoredEntry::Done(_, claim)) if Arc::strong_count(claim) == 1
                        )
                    })
                };
                let Some(pos) = evict_pos else {
                    // Every completed entry is currently reserved, so there is
                    // nothing safe to evict; treat the store as full.
                    return Err(MetaStoreError::CapacityFull {
                        req_id: *request_id,
                    });
                };
                let old_request_id = self.complete_queue.remove(pos).ok_or_else(|| {
                    let msg =
                        format!("complete_queue index {pos} vanished while inserting {request_id}");
                    tracing::error!(msg);
                    MetaStoreError::Invariant(msg)
                })?;
                if self.storage.remove(&old_request_id).is_none() {
                    self.complete_queue.insert(pos, old_request_id);
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
            _phantom: PhantomData,
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
    ///
    /// Lock: assumes the caller already holds the write guard. gRPC callers
    /// should instead use [`lock_entry_in_meta_store`], which locks internally
    /// and maps the error for propagation.
    pub(crate) fn lock_entry(
        &mut self,
        request_id: &RequestId,
    ) -> Result<MetaStorePermit<T>, MetaStoreError> {
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
            _phantom: PhantomData,
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
        permit: MetaStorePermit<T>,
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

    /// Complete a claim by setting the entry to `Done(Ok(value))`, consuming the
    /// permit. The held permit is the proof of ownership, so no strong-count
    /// check is performed.
    ///
    /// An existing `Done` entry is overwritten in place while keeping its queue
    /// slot; a `Pending` entry (e.g. an orphaned claim adopted via
    /// [`lock_entry`](MetaStore::lock_entry)) is recorded in the completion
    /// queue. Errors with [`MetaStoreError::NotFound`] if the entry is gone, or
    /// [`MetaStoreError::CannotUpdate`] if it was concurrently tombstoned.
    ///
    /// Deliberately **private**: overwriting an already-`Done` value is not a
    /// flow we want to expose. The sole sanctioned caller is
    /// [`with_overwriting_claim`], which pairs it with the claim and the
    /// matching rollback ([`abort_reservation`](MetaStore::abort_reservation)).
    fn finalize(&mut self, permit: MetaStorePermit<T>, value: T) -> Result<(), MetaStoreError> {
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

    /// Roll back a claim (see [`finalize`](MetaStore::finalize)) without
    /// completing it, consuming the permit.
    ///
    /// An existing `Done` entry that was merely locked in place via
    /// [`lock_entry`](MetaStore::lock_entry) is left untouched; only the permit's
    /// claim is released. If the claimed entry is instead `Pending` (an orphaned
    /// claim adopted via `lock_entry`) it is **removed outright** — not
    /// tombstoned — so `request_id` stays reusable.
    ///
    /// Deliberately **private**, like [`finalize`](MetaStore::finalize): reached
    /// only through [`with_overwriting_claim`], the migration-only entry point.
    fn abort_reservation(&mut self, permit: MetaStorePermit<T>) {
        let req_id = permit.req_id;
        if matches!(self.storage.get(&req_id), Some(StoredEntry::Pending(_))) {
            // Orphaned `Pending` claim: drop it entirely. A `Pending` entry is
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
    fn delete(&mut self, permit: MetaStorePermit<T>) -> Result<EntryState<T>, MetaStoreError> {
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
        // `old` is Pending or Done here (the Deleted case errored above), so this
        // is always a fresh transition into a tombstone.
        self.deleted_count += 1;
        if matches!(old, StoredEntry::Done(_, _),) {
            self.complete_queue.retain(|id| id != &req_id);
        }
        Ok(old.into())
    }

    /// Like [`delete`], but for callers that do not hold a permit. Succeeds
    /// for any non-Deleted state when no live permit is outstanding. Returns
    /// the previous state.
    ///
    /// Lock: assumes the caller already holds the write guard. Most callers
    /// should use [`try_delete_in_meta_store`], which locks internally and lets
    /// the caller inspect the returned [`EntryState`].
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
                StoredEntry::Done(_, arc) => {
                    // A `Done` entry can be permit-held (via `reserve` /
                    // `lock_entry`); block a permit-less delete while it is.
                    if Arc::strong_count(arc) > 1 {
                        return Err(MetaStoreError::Locked {
                            req_id: *request_id,
                        });
                    }
                }
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
        // `old` is Pending or Done here (the Deleted case errored above), so this
        // is always a fresh transition into a tombstone.
        self.deleted_count += 1;
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

    /// Get the number of items currently being processed (i.e. `Pending`).
    ///
    /// This excludes both completed entries and tombstoned (`Deleted`) entries;
    /// tombstones remain in `storage` permanently but are neither processing nor
    /// completed, so they are subtracted here to avoid an inflated count.
    pub(crate) fn get_processing_count(&self) -> usize {
        self.verify_invariant();
        self.storage
            .len()
            .saturating_sub(self.complete_queue.len())
            .saturating_sub(self.deleted_count)
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
) -> Result<MetaStorePermit<T>, MetricedError> {
    meta_store
        .write()
        .await
        .insert(req_id)
        .map_err(|e| e.into_metriced(request_metric))
}

/// Fail-fast, read-only existence check that mirrors [`MetaStore::insert`]'s
/// duplicate rejection: returns an `AlreadyExists` [`MetricedError`] if an entry
/// (pending, completed, or tombstoned) already occupies `req_id`.
///
/// Intended to be called *before* expensive setup/computation so a request for
/// an already-known id is rejected early, without claiming a permit. It only
/// takes the read lock and is advisory: the authoritative, race-closing claim is
/// still made later by [`add_req_to_meta_store`], whose `insert` re-checks under
/// the write lock. A caller therefore must not rely on this check alone for
/// mutual exclusion — it only avoids wasted work in the common case.
#[cfg(feature = "non-wasm")]
pub(crate) async fn ensure_not_in_meta_store<T>(
    meta_store: &RwLock<MetaStore<T>>,
    req_id: &RequestId,
    request_metric: &'static str,
) -> Result<(), MetricedError> {
    if meta_store.read().await.exists(req_id) {
        return Err(MetaStoreError::AlreadyExists { req_id: *req_id }.into_metriced(request_metric));
    }
    Ok(())
}

/// Acquire a permit for an *existing* entry, acquiring & releasing the write
/// lock internally and mapping the failure to a [`MetricedError`] for gRPC
/// propagation. The lock-an-existing-entry analogue of [`add_req_to_meta_store`].
#[cfg(feature = "non-wasm")]
pub(crate) async fn lock_entry_in_meta_store<T>(
    meta_store: &RwLock<MetaStore<T>>,
    req_id: &RequestId,
    request_metric: &'static str,
) -> Result<MetaStorePermit<T>, MetricedError> {
    meta_store
        .write()
        .await
        .lock_entry(req_id)
        .map_err(|e| e.into_metriced(request_metric))
}

#[cfg(feature = "non-wasm")]
pub(crate) async fn update_req_in_meta_store<
    T,
    E: Into<Box<dyn std::error::Error + Send + Sync>> + fmt::Debug,
>(
    meta_store: &RwLock<MetaStore<T>>,
    permit: MetaStorePermit<T>,
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
    permit: MetaStorePermit<T>,
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
    permit: MetaStorePermit<T>,
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
    permit: MetaStorePermit<T>,
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

/// Permit-free delete that acquires & releases the write lock internally and
/// returns the previous [`EntryState`]. Unlike [`delete_in_meta_store`], the
/// caller inspects the outcome itself (e.g. to log per prior state), so the raw
/// [`MetaStoreError`] is returned rather than being recorded here — letting
/// fire-and-forget callers map it through `handle_unreturnable_error` with their
/// own `ERR_ASYNC` semantics.
#[cfg(feature = "non-wasm")]
pub(crate) async fn try_delete_in_meta_store<T>(
    meta_store: &RwLock<MetaStore<T>>,
    req_id: &RequestId,
) -> Result<EntryState<T>, MetaStoreError> {
    meta_store.write().await.try_delete(req_id)
}

/// Run `work` while holding an exclusive claim on an **existing** `req_id`, then
/// commit its produced value into the store, overwriting the entry in place. If
/// `work` fails, the claim is rolled back without tombstoning, leaving the entry
/// untouched.
///
/// This is the **only** sanctioned path that overwrites an already-completed
/// entry: the underlying [`MetaStore::finalize`] / [`MetaStore::abort_reservation`]
/// are private, so a completed value can never be silently replaced through the
/// normal `insert → update` flow. It exists for the key-migration edge case
/// (`copy_compressed_key_to_original`), where storage keyed by `req_id` is
/// rewritten and must be atomic w.r.t. a concurrent migration or insert of the
/// same id — those bail with `Locked`/`AlreadyExists` against the held claim
/// before any of `work`'s side effects run.
///
/// The entry is required to exist: callers migrate a key whose data is already
/// present, so [`lock_entry`](MetaStore::lock_entry) is used rather than a
/// get-or-create (see the claim site below). A missing entry fails with
/// `NotFound`.
///
/// `work` returns `(value, payload)`: `value` is committed under `req_id`;
/// `payload` is returned to the caller (e.g. to update an out-of-store cache
/// only after the commit succeeds). The claim is acquired before `work` runs and
/// the lock is *not* held while `work` is in flight — only the per-entry permit.
#[cfg(feature = "non-wasm")]
pub(crate) async fn with_overwriting_claim<T, R, F>(
    meta_store: &RwLock<MetaStore<T>>,
    req_id: &RequestId,
    work: F,
) -> anyhow::Result<R>
where
    F: AsyncFnOnce() -> anyhow::Result<(T, R)>,
{
    // Claim the existing entry. We can assume it is always present: the sole
    // caller, `copy_compressed_key_to_original`, only migrates an `old_key_id`
    // whose `FheKeyInfo` lives in private storage, and the keygen meta store is
    // seeded at startup from exactly that set of keys (see `public_key_info` in
    // `kms_impl.rs`) and is unbounded (`new_from_map`, capacity `usize::MAX`), so
    // it never evicts. Any key that can be migrated therefore always has a `Done`
    // entry here; a missing entry means the migration target does not exist, and
    // failing with `NotFound` is the correct outcome (there is nothing to claim
    // or create).
    let permit = meta_store
        .write()
        .await
        .lock_entry(req_id)
        .map_err(|e| anyhow!("could not claim meta-store entry {req_id}: {e}"))?;

    match work().await {
        Ok((value, payload)) => {
            meta_store
                .write()
                .await
                .finalize(permit, value)
                .map_err(|e| anyhow!("could not commit meta-store entry {req_id}: {e}"))?;
            Ok(payload)
        }
        Err(e) => {
            meta_store.write().await.abort_reservation(permit);
            Err(e)
        }
    }
}

/// Helper for retrieving the result of a request from a meta store.
///
/// Performs a single, non-blocking read and returns immediately:
/// - `Done(Ok)`  → `Arc<T>`.
/// - `Pending`   → `Unavailable`; the result is not ready yet and the caller
///   (client) is expected to retry later.
/// - missing / `Deleted` → `NotFound`.
/// - `Done(Err)` → `Internal`, or `Aborted` if the stored error mentions
///   "abort".
///
/// Acquires the read lock only for the duration of the snapshot, so writers are
/// not blocked.
#[cfg(feature = "non-wasm")]
pub(crate) async fn retrieve_from_meta_store<T>(
    meta_store: &RwLock<MetaStore<T>>,
    req_id: &RequestId,
    metric_scope: &'static str,
) -> Result<Arc<T>, MetricedError> {
    let guard = meta_store.read().await;
    match guard.retrieve(req_id) {
        None | Some(EntryState::Deleted) => {
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
        Some(EntryState::Pending) => {
            let msg =
                format!("Result in scope {metric_scope} with request ID {req_id} is not ready yet");
            tracing::info!(msg);
            Err(MetricedError::new(
                metric_scope,
                Some(*req_id),
                anyhow!(msg),
                tonic::Code::Unavailable,
            ))
        }
        Some(EntryState::Done(Ok(arc))) => Ok(arc),
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
            Err(MetricedError::new(
                metric_scope,
                Some(*req_id),
                anyhow!(msg),
                code,
            ))
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

    /// Get-or-create claim used by `finalize`/`abort_reservation` callers,
    /// mirroring the inline pattern in `copy_compressed_key_to_original`: lock
    /// the existing entry if present, otherwise insert a fresh one.
    fn reserve(
        store: &mut MetaStore<String>,
        id: &RequestId,
    ) -> Result<MetaStorePermit<String>, MetaStoreError> {
        if store.exists(id) {
            store.lock_entry(id)
        } else {
            store.insert(id)
        }
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
        let permit = reserve(&mut store, &id).unwrap();
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
        let permit = reserve(&mut store, &id).unwrap();
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
        let permit = reserve(&mut store, &id).unwrap();
        assert!(matches!(
            reserve(&mut store, &id),
            Err(MetaStoreError::Locked { .. })
        ));
        drop(permit);
        // Once released, a fresh reserve succeeds again.
        assert!(reserve(&mut store, &id).is_ok());
    }

    #[test]
    fn reserve_rejects_deleted_entry() {
        let mut store: MetaStore<String> = MetaStore::new(2, 1);
        let id = derive_request_id("reserve-deleted").unwrap();
        insert_done_ok(&mut store, &id, "v");
        store.try_delete(&id).unwrap();
        assert!(matches!(
            reserve(&mut store, &id),
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
        let permit = reserve(&mut store, &id).unwrap();
        store.abort_reservation(permit);
        // Gone entirely, not Deleted — so it is reservable/insertable again.
        assert!(store.retrieve(&id).is_none());
        let permit2 = reserve(&mut store, &id).unwrap();
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
        let permit = reserve(&mut store, &id).unwrap();
        store.abort_reservation(permit);
        assert_done_ok(&store, &id, &"original".to_string());
        assert_eq!(store.get_completed_count(), 1);
        // Released: it can be reserved again afterwards.
        assert!(reserve(&mut store, &id).is_ok());
    }

    #[test]
    fn reserve_after_failed_attempt_adopts_orphan_pending() {
        // Mirrors recovery when a prior migration created a Pending reservation
        // but its permit was dropped without finalize/abort (e.g. a task panic):
        // the orphan has no live permit, so a retry's reserve adopts it.
        let mut store: MetaStore<String> = MetaStore::new(2, 1);
        let id = derive_request_id("reserve-orphan").unwrap();
        drop(reserve(&mut store, &id).unwrap()); // permit dropped, entry left Pending
        assert!(matches!(store.retrieve(&id), Some(EntryState::Pending)));
        let permit = reserve(&mut store, &id).unwrap(); // adopts the orphan
        store.finalize(permit, "adopted".to_string()).unwrap();
        assert_done_ok(&store, &id, &"adopted".to_string());
        assert_eq!(store.get_completed_count(), 1);
    }

    #[test]
    fn eviction_skips_reserved_entry_and_evicts_next() {
        // capacity 2, min_cache 1: two completed entries, the oldest reserved.
        // Inserting a third must evict the *younger* unreserved one, not the
        // reserved oldest, so the reservation's finalize still works.
        let mut store: MetaStore<String> = MetaStore::new(2, 1);
        let old = derive_request_id("evict-reserved-old").unwrap();
        let young = derive_request_id("evict-reserved-young").unwrap();
        insert_done_ok(&mut store, &old, "old");
        insert_done_ok(&mut store, &young, "young");

        // Reserve the oldest (locks the Done entry in place).
        let permit = reserve(&mut store, &old).unwrap();

        // Insert a third: eviction skips `old` (held) and removes `young`.
        let fresh = derive_request_id("evict-reserved-fresh").unwrap();
        let fresh_permit = store.insert(&fresh).unwrap();
        assert!(
            store.retrieve(&old).is_some(),
            "reserved oldest must survive"
        );
        assert!(store.retrieve(&young).is_none(), "younger entry evicted");

        // The reservation still commits.
        store.finalize(permit, "migrated".to_string()).unwrap();
        assert_done_ok(&store, &old, &"migrated".to_string());
        drop(fresh_permit);
    }

    #[test]
    fn insert_capacity_full_when_all_completed_reserved() {
        // capacity 2, min_cache 1. Two completed entries, both reserved, so the
        // store is full (len > min_cache) yet nothing is safe to evict ->
        // CapacityFull rather than corrupting a reserved entry.
        let mut store: MetaStore<String> = MetaStore::new(2, 1);
        let a = derive_request_id("full-a").unwrap();
        let b = derive_request_id("full-b").unwrap();
        insert_done_ok(&mut store, &a, "a");
        insert_done_ok(&mut store, &b, "b");
        let held_a = reserve(&mut store, &a).unwrap();
        let _held_b = reserve(&mut store, &b).unwrap();

        let third = derive_request_id("full-third").unwrap();
        assert!(matches!(
            store.insert(&third),
            Err(MetaStoreError::CapacityFull { .. })
        ));
        // Releasing one reservation makes that entry evictable again.
        drop(held_a);
        assert!(store.insert(&third).is_ok());
        assert!(store.retrieve(&a).is_none(), "released entry was evicted");
    }

    #[test]
    fn eviction_preserves_min_cache() {
        // capacity 2, min_cache 2: never evict, even when full.
        let mut store: MetaStore<String> = MetaStore::new(2, 2);
        let a = derive_request_id("mincache-a").unwrap();
        let b = derive_request_id("mincache-b").unwrap();
        insert_done_ok(&mut store, &a, "a");
        insert_done_ok(&mut store, &b, "b");
        let c = derive_request_id("mincache-c").unwrap();
        assert!(matches!(
            store.insert(&c),
            Err(MetaStoreError::CapacityFull { .. })
        ));
        assert!(store.retrieve(&a).is_some());
        assert!(store.retrieve(&b).is_some());
    }

    #[test]
    fn try_delete_blocked_on_reserved_done() {
        // A permit held on a Done entry (via reserve) blocks a permit-less
        // try_delete, just like it does for a Pending entry.
        let mut store: MetaStore<String> = MetaStore::new(2, 1);
        let id = derive_request_id("try-del-reserved").unwrap();
        insert_done_ok(&mut store, &id, "v");
        let permit = reserve(&mut store, &id).unwrap();
        assert!(matches!(
            store.try_delete(&id),
            Err(MetaStoreError::Locked { .. })
        ));
        drop(permit);
        // Released: try_delete succeeds and returns the prior Done value.
        let prev = store.try_delete(&id).unwrap();
        assert!(matches!(prev, EntryState::Done(Ok(_))));
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

    #[test]
    fn processing_count_excludes_deleted() {
        let mut store: MetaStore<String> = MetaStore::new_unlimited();
        let pending = derive_request_id("pc-pending").unwrap();
        let permit = store.insert(&pending).unwrap();
        let done = derive_request_id("pc-done").unwrap();
        insert_done_ok(&mut store, &done, "v");
        let gone = derive_request_id("pc-gone").unwrap();
        insert_done_ok(&mut store, &gone, "v");
        store.try_delete(&gone).unwrap();

        // storage holds pending + done + tombstone = 3, but only the single
        // Pending entry counts as processing (the tombstone is excluded).
        assert_eq!(store.get_current_count(), 3);
        assert_eq!(store.get_completed_count(), 1);
        assert_eq!(store.get_processing_count(), 1);

        // Deleting the remaining Pending entry drops processing to zero, while the
        // tombstones stay resident in storage.
        drop(permit);
        store.try_delete(&pending).unwrap();
        assert_eq!(store.get_processing_count(), 0);
        assert_eq!(store.get_current_count(), 3);
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

    #[cfg(feature = "non-wasm")]
    #[tokio::test]
    async fn with_overwriting_claim_overwrites_existing() {
        let mut ms = MetaStore::<String>::new(2, 1);
        let id = derive_request_id("woc-commit").unwrap();
        // The claim requires a pre-existing entry; seed one as the migration
        // target would already be present in the store.
        insert_done_ok(&mut ms, &id, "v0");
        let store = RwLock::new(ms);
        assert_eq!(store.read().await.get_completed_count(), 1);

        // Existing Done -> overwrite in place, keep the single completion slot.
        let payload = with_overwriting_claim(&store, &id, async || Ok(("v1".to_string(), 42u8)))
            .await
            .unwrap();
        assert_eq!(payload, 42);
        assert_done_ok(&*store.read().await, &id, &"v1".to_string());
        assert_eq!(store.read().await.get_completed_count(), 1);

        // A second overwrite still keeps the single completion slot.
        let payload = with_overwriting_claim(&store, &id, async || Ok(("v2".to_string(), 7u8)))
            .await
            .unwrap();
        assert_eq!(payload, 7);
        assert_done_ok(&*store.read().await, &id, &"v2".to_string());
        assert_eq!(store.read().await.get_completed_count(), 1);
    }

    #[cfg(feature = "non-wasm")]
    #[tokio::test]
    async fn with_overwriting_claim_absent_entry_errors_without_creating() {
        let store = RwLock::new(MetaStore::<String>::new(2, 1));
        let id = derive_request_id("woc-absent").unwrap();

        // No entry exists: the claim fails with NotFound and `work` never runs,
        // so nothing is created. (The migration target is always pre-seeded; an
        // absent entry means it genuinely does not exist.)
        let res: anyhow::Result<()> =
            with_overwriting_claim(&store, &id, async || Ok(("never".to_string(), ()))).await;
        assert!(res.is_err());
        assert!(
            store.read().await.retrieve(&id).is_none(),
            "claiming an absent id must not create an entry"
        );
    }

    #[cfg(feature = "non-wasm")]
    #[tokio::test]
    async fn with_overwriting_claim_preserves_existing_on_failure() {
        let mut ms = MetaStore::<String>::new(2, 1);
        let id = derive_request_id("woc-preserve").unwrap();
        insert_done_ok(&mut ms, &id, "original");
        let store = RwLock::new(ms);

        let res: anyhow::Result<()> =
            with_overwriting_claim(&store, &id, async || anyhow::bail!("boom")).await;
        assert!(res.is_err());
        // The pre-existing Done value is untouched by the aborted claim.
        assert_done_ok(&*store.read().await, &id, &"original".to_string());
        assert_eq!(store.read().await.get_completed_count(), 1);
    }

    #[cfg(feature = "non-wasm")]
    #[tokio::test]
    async fn ensure_not_in_meta_store_rejects_known_ids() {
        let store = RwLock::new(MetaStore::<String>::new(4, 1));
        let id = derive_request_id("ensure-known").unwrap();

        // Absent id: the fail-fast check passes.
        ensure_not_in_meta_store(&store, &id, "test").await.unwrap();

        // Pending (claimed) id: rejected, mirroring `insert`'s AlreadyExists.
        let permit = add_req_to_meta_store(&store, &id, "test").await.unwrap();
        let err = ensure_not_in_meta_store(&store, &id, "test")
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::AlreadyExists);

        // Completed id: still rejected.
        store
            .write()
            .await
            .update(Ok("v".to_string()), permit)
            .unwrap();
        assert!(ensure_not_in_meta_store(&store, &id, "test").await.is_err());

        // Tombstoned id: still rejected (the tombstone is permanent).
        store.write().await.try_delete(&id).unwrap();
        assert!(ensure_not_in_meta_store(&store, &id, "test").await.is_err());
    }
}

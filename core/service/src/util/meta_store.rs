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
//! # Entry lifecycle
//!
//! `insert` → [`MetaStorePermit`] → (`update` to finish | `delete` to tombstone),
//! both consuming the permit. A permit dropped without being consumed results in the
//! entry resolving with a failure and storing an appropriate error string as the result.
//! A failed entry can then be retried under the same id via
//! [`redo_failed`](MetaStore::redo_failed).
//! [`lock_entry`](MetaStore::lock_entry) mints a permit for an existing entry
//! (used as a cross-lock sync point); pairing it with
//! [`finalize`](MetaStore::finalize) / [`abort_reservation`](MetaStore::abort_reservation)
//! supports in-place rewrites of an existing entry for key migration.
//!
//! # Requirements
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
//! Any meta store that is NOT used for decryption (user or public) should be unlimited and MUST ensure that all data elements are present.

use crate::engine::utils::MetricedError;
use anyhow::anyhow;
use kms_grpc::RequestId;
use std::fmt::{self};
use std::sync::Weak;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    marker::PhantomData,
    sync::Arc,
};
use thiserror::Error;
use tokio::sync::{RwLock, RwLockWriteGuard, mpsc, watch};
use tracing;

/// Operation metric attached to a [`MetaStorePermit`] minted by the inherent
/// [`MetaStore`] methods. The helper layer (e.g. [`add_req_to_meta_store`])
/// overwrites it with the caller's per-request metric, so this default only
/// surfaces for permits created by direct inherent calls (tests, migration).
const OP_META_STORE_REAP: &str = "meta_store_reap";

/// Errors returned by [`MetaStore`] operations.
///
/// Each variant has a stable `tonic::Code` mapping via [`MetaStoreError::code`]
/// so callers can convert into a `MetricedError` without
/// hand-coding the code per callsite.
#[derive(Error, Debug)]
pub(crate) enum MetaStoreError {
    #[error("the element with ID {req_id} already exists; cannot insert twice")]
    AlreadyExists { req_id: RequestId },

    #[error(
        "meta store is full and the completed cache is at its minimum size; cannot insert {req_id}"
    )]
    CapacityFull { req_id: RequestId },

    #[error("the element with ID {req_id} does not exist")]
    NotFound { req_id: RequestId },

    /// Entry is in an in-flight state: either still `Pending` or another
    /// caller holds a live `MetaStorePermit`.
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
/// permit without consuming it, its `Drop` hands the entry to the store's
/// reaper, which resolves the orphaned `Pending` as `Done(Err)` (see
/// [`reaper_loop`]) rather than leaving it stuck `Pending`.
///
/// "Permit alive" is tracked by the strong count of an internal `Arc<()>`:
/// while the permit exists, `Arc::strong_count` of the entry's claim arc is
/// at least 2 (one held by the entry, one by the permit). `try_*` paths
/// check `strong_count == 1` to determine that no permit is outstanding.
pub struct MetaStorePermit<T> {
    req_id: RequestId,
    /// Lightweight type used to tracking the permit, automatically dropped when the permit is dropped.
    _claim: Arc<()>,
    /// Sender to the store's reaper task, cloned from [`MetaStore::reaper_tx`] at
    /// mint time.
    reaper: mpsc::UnboundedSender<(RequestId, &'static str)>,
    /// An initially false flag that the permit holder must set to true via [`defuse`] after consuming the permit, so the reaper knows not to fail the entry on drop.
    defused: bool,
    /// Operation metric reported by the reaper if this permit is dropped without
    /// recording an outcome. See [`OP_META_STORE_REAP`].
    op: &'static str,
    /// Needed to prevent permits of same `req_id` to be used in another MetaStore of different type `T`.
    _phantom: PhantomData<T>,
}

impl<T> MetaStorePermit<T> {
    fn new(
        req_id: RequestId,
        claim: Arc<()>,
        reaper: mpsc::UnboundedSender<(RequestId, &'static str)>,
    ) -> Self {
        Self {
            req_id,
            _claim: claim,
            reaper,
            defused: false,
            op: OP_META_STORE_REAP,
            _phantom: PhantomData,
        }
    }

    pub(crate) fn req_id(&self) -> &RequestId {
        &self.req_id
    }

    /// Disarm the drop-reaper after the holder has recorded (or is about to
    /// record) this entry's outcome, so dropping the permit does not enqueue a
    /// spurious abandonment failure. Called by every permit-consuming method.
    fn defuse(&mut self) {
        self.defused = true;
    }
}

/// On drop, a permit that was never consumed (i.e. not [`defuse`](MetaStorePermit::defuse)d)
/// asks the store's reaper to fail the now-orphaned `Pending` entry, so an
/// abandoned request surfaces as `Done(Err)` instead of being stuck `Pending`
/// forever.
impl<T> Drop for MetaStorePermit<T> {
    fn drop(&mut self) {
        if self.defused {
            return;
        }
        // Release our claim on the entry *before* notifying the reaper. The
        // reaper decides "orphaned" via `Arc::strong_count == 1`, so our
        // reference must already be gone when it looks.
        drop(std::mem::replace(&mut self._claim, Arc::new(())));
        let _ = self.reaper.send((self.req_id, self.op));
    }
}

/// Public-facing snapshot of an entry's state.
#[derive(Debug)]
pub enum EntryState<T> {
    /// Entry exists, but is being worked on (either being computed or being deleted)
    Pending,
    /// Entry finished processing with either a success or error result.
    Done(Result<Arc<T>, String>),
    /// The entry has been deleted.
    Deleted,
}

// Hand-written so cloning does not require `T: Clone`.
impl<T> Clone for EntryState<T> {
    fn clone(&self) -> Self {
        match self {
            EntryState::Pending => EntryState::Pending,
            EntryState::Done(result) => EntryState::Done(result.clone()),
            EntryState::Deleted => EntryState::Deleted,
        }
    }
}

impl<T> std::fmt::Display for EntryState<T> {
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

/// Lifecycle state of an entry.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum EntryStatus {
    Pending,
    Done,
    Deleted,
}

impl<T> From<&EntryState<T>> for EntryStatus {
    fn from(state: &EntryState<T>) -> Self {
        match state {
            EntryState::Pending => EntryStatus::Pending,
            EntryState::Done(_) => EntryStatus::Done,
            EntryState::Deleted => EntryStatus::Deleted,
        }
    }
}

/// A single meta-store entry, holding the locking `claim` and the result channel
/// `result_tx`.
///
/// `claim` is the locking primitive: an `Arc<()>` whose strong count reveals
/// whether a [`MetaStorePermit`] is outstanding (`> 1` ⇒ held). A tombstoned
/// (`Deleted`) entry keeps its claim, but the permit has been consumed by then so
/// its strong count is back to 1 (⇒ not held).
struct StoredEntry<T> {
    claim: Arc<()>,
    result_tx: watch::Sender<EntryState<T>>,
}

impl<T> StoredEntry<T> {
    /// A fresh `Pending` entry: a new claim arc (the locking primitive) paired
    /// with an empty result channel that waiters can await. Returns the claim so
    /// the caller can mint the matching [`MetaStorePermit`].
    fn new_pending() -> (Self, Arc<()>) {
        let claim = Arc::new(());

        let (result_tx, _) = watch::channel(EntryState::Pending);
        let entry = StoredEntry {
            claim: Arc::clone(&claim),
            result_tx,
        };
        (entry, claim)
    }

    /// An already-`Done` entry built directly (not through a permit), used to
    /// seed a store from a pre-existing map.
    fn new_done(value: Result<Arc<T>, String>) -> Self {
        let (result_tx, _) = watch::channel(EntryState::Done(value));
        StoredEntry {
            claim: Arc::new(()),
            result_tx,
        }
    }

    /// The entry's current lifecycle status, derived from the result channel.
    fn status(&self) -> EntryStatus {
        EntryStatus::from(&*self.result_tx.borrow())
    }

    /// Settle the entry to `Done(result)`, publishing the result on the channel
    /// (which both records it and wakes any waiter).
    fn set_complete(&mut self, result: Result<Arc<T>, String>) {
        self.result_tx.send_replace(EntryState::Done(result));
    }

    /// Tombstone the entry: publish `Deleted` on the result channel (waking any
    /// waiter, which maps it to `NotFound`). Valid from either `Pending` or
    /// `Done`; only a `Pending` entry can have a waiter, and it wakes with
    /// `Deleted`. The channel publish is a no-op when no waiter is subscribed.
    fn set_deleted(&mut self) {
        self.result_tx.send_replace(EntryState::Deleted);
    }

    /// Whether a [`MetaStorePermit`] is currently being held for this entry.
    fn is_permit_held(&self) -> bool {
        Arc::strong_count(&self.claim) > 1
    }
}

impl<T> From<&StoredEntry<T>> for EntryState<T> {
    fn from(stored: &StoredEntry<T>) -> Self {
        (*stored.result_tx.borrow()).clone()
    }
}

/// Data structure that stores elements that are being processed and their status (Pending, Done, Deleted).
/// It holds elements up to a given capacity, and once it is full, it will remove old elements that have status [Done], if there are sufficiently many.
pub struct MetaStore<T> {
    /// The maximum amount of entries in total (finished and unfinished)
    capacity: usize,
    /// The minimum amount of entries that should be kept in the cache after completion and before old ones are evicted
    min_cache: usize,
    /// Storage of all elements in the system
    storage: HashMap<RequestId, StoredEntry<T>>,
    /// Queue of all elements that have been completed, i.e. `Done(Ok(..))` or
    /// `Done(Err(..))`. The oldest completion is at the front for efficient eviction.
    /// `Deleted` elements are NOT included in this queue.
    complete_queue: VecDeque<RequestId>,
    /// The set of entries that has been `Deleted` (i.e. tombstoned).
    deleted_set: HashSet<RequestId>,
    /// Sender cloned into every minted [`MetaStorePermit`].
    reaper_tx: mpsc::UnboundedSender<(RequestId, &'static str)>,
}

impl<T> MetaStore<T> {
    fn inner_new(
        capacity: usize,
        min_cache: usize,
        complete_queue: VecDeque<RequestId>,
        storage: HashMap<RequestId, StoredEntry<T>>,
    ) -> (Self, mpsc::UnboundedReceiver<(RequestId, &'static str)>) {
        let (reaper_tx, reaper_rx) = mpsc::unbounded_channel();
        (
            Self {
                capacity,
                min_cache,
                storage,
                complete_queue,
                deleted_set: HashSet::new(),
                reaper_tx,
            },
            reaper_rx,
        )
    }
    /// Creates a new MetaStore with a given capacity and minimal cache size.
    /// This should be used for decryption types, i.e. where results don't need to be persistent permanently.
    /// Concretely the MetaStore will be able to hold [capacity] of total elements,
    /// of which we can be sure that at least [min_cache] elements are kept in the cache after completion
    /// (assuming that at least [min_cache] have been completed).
    /// The cache may be larger than [min_cache], but the total capacity will be limited to [capacity]
    pub(crate) fn new(capacity: usize, min_cache: usize) -> Arc<RwLock<Self>>
    where
        T: Send + Sync + 'static,
    {
        let (store, rx) = Self::inner_new(
            capacity,
            min_cache,
            VecDeque::with_capacity(min_cache),
            HashMap::with_capacity(capacity),
        );
        Self::spawn_reaper(store, rx)
    }

    /// Creates a new MetaStore with unlimited capacity and cache size.
    /// This should be used for non-decryption types of the MetaStore.
    /// That is, where we need to ensure all requests and results are persisted permanently.
    pub(crate) fn new_unlimited() -> Arc<RwLock<Self>>
    where
        T: Send + Sync + 'static,
    {
        let (store, rx) = Self::inner_new(usize::MAX, usize::MAX, VecDeque::new(), HashMap::new());
        Self::spawn_reaper(store, rx)
    }

    /// Creates a MetaStore with unlimited storage capacity and minimum cache size and populates it with the given map
    pub(crate) fn new_from_map(map: HashMap<RequestId, T>) -> Arc<RwLock<Self>>
    where
        T: Send + Sync + 'static,
    {
        let mut completed_queue = VecDeque::new();
        let storage = map
            .into_iter()
            .map(|(key, value)| {
                completed_queue.push_back(key);
                (key, StoredEntry::new_done(Ok(Arc::new(value))))
            })
            .collect();
        let (store, rx) = Self::inner_new(usize::MAX, usize::MAX, completed_queue, storage);
        Self::spawn_reaper(store, rx)
    }

    /// Wrap an already-built `MetaStore` in its shared `Arc<RwLock<..>>` and
    /// attach a drop-reaper, so that any [`MetaStorePermit`] dropped without
    /// recording an outcome fails its orphaned `Pending` entry (`Done(Err)`)
    /// instead of leaving it stuck `Pending` forever (see [`reaper_loop`]).
    ///
    /// Must be called from within a Tokio runtime (it spawns the reaper task).
    fn spawn_reaper(
        store: Self,
        rx: mpsc::UnboundedReceiver<(RequestId, &'static str)>,
    ) -> Arc<RwLock<Self>>
    where
        T: Send + Sync + 'static,
    {
        // Return the wrapped handle rather than a bare `MetaStore` because the
        // reaper needs a (weak) reference to the shared store, which only exists
        // once wrapped — so wiring it up at construction time is the only way to
        // guarantee no permit is ever minted before the reaper is in place.
        let store = Arc::new(RwLock::new(store));
        tokio::spawn(reaper_loop(Arc::downgrade(&store), rx));
        store
    }

    /// Check whether `request_id` has ever occupied a slot in the store, including
    /// a tombstoned (`Deleted`) entry.
    pub(crate) fn has_existed(&self, request_id: &RequestId) -> bool {
        self.storage.contains_key(request_id)
    }

    /// Verify the invariant that storage.len() >= complete_queue.len() + deleted_set.len()
    /// (i.e. the processing count is non-negative).
    fn verify_invariant(&self) -> bool {
        let is_valid = self.storage.len() >= self.complete_queue.len() + self.deleted_set.len();
        if !is_valid {
            tracing::error!(
                "INVARIANT VIOLATION: storage.len() ({}) < complete_queue.len() ({}) + deleted_set.len() ({})",
                self.storage.len(),
                self.complete_queue.len(),
                self.deleted_set.len()
            );
        }
        is_valid
    }

    /// Insert a new element, throwing an error if the element already exists or if the system is fully loaded.
    ///
    /// On success, returns a [`MetaStorePermit`] granting the caller the right to
    /// later [`update`] or [`delete`] this entry. Hold the permit until the
    /// mutation; if it is dropped with the work abandoned, the store's reaper
    /// resolves the orphaned entry as `Done(Err)` (see [`reaper_loop`]).
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
                        storage
                            .get(id)
                            .is_some_and(|e| e.status() == EntryStatus::Done && !e.is_permit_held())
                    })
                };
                let Some(pos) = evict_pos else {
                    // Every completed entry is currently reserved, so there is
                    // nothing safe to evict; treat the store as full.
                    return Err(MetaStoreError::CapacityFull {
                        req_id: *request_id,
                    });
                };
                let Some(old_request_id) = self.complete_queue.remove(pos) else {
                    let msg =
                        format!("complete_queue index {pos} vanished while inserting {request_id}");
                    tracing::error!(msg);
                    return Err(MetaStoreError::Invariant(msg));
                };
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
        let (entry, claim) = StoredEntry::new_pending();
        let permit = MetaStorePermit::new(*request_id, claim, self.reaper_tx.clone());
        self.storage.insert(*request_id, entry);
        Ok(permit)
    }

    /// Acquire a permit for an existing entry, returning an error if the entry does not exist, is tombstoned (`Deleted`), or is currently held by another permit.
    ///
    /// This is intended for callers that need to update or delete an existing entry but do not hold its original insert permit.
    ///
    /// Note that acquiring a permit on an existing entry does not change its state: the entry remains `Pending` or `Done` as it was before.
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
            match entry.status() {
                EntryStatus::Pending | EntryStatus::Done => {
                    if entry.is_permit_held() {
                        return Err(MetaStoreError::Locked {
                            req_id: *request_id,
                        });
                    }
                    Arc::clone(&entry.claim)
                }
                EntryStatus::Deleted => {
                    return Err(MetaStoreError::CannotUpdate {
                        req_id: *request_id,
                    });
                }
            }
        };
        Ok(MetaStorePermit::new(
            *request_id,
            claim,
            self.reaper_tx.clone(),
        ))
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
        mut permit: MetaStorePermit<T>,
    ) -> Result<(), MetaStoreError> {
        // We own the outcome from here on, so a later drop must not reap.
        permit.defuse();
        let req_id = permit.req_id;
        let entry = self
            .storage
            .get_mut(&req_id)
            .ok_or(MetaStoreError::NotFound { req_id })?;
        if entry.status() != EntryStatus::Pending {
            return Err(MetaStoreError::CannotUpdate { req_id });
        }
        entry.set_complete(update.map(Arc::new));
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
    fn finalize(&mut self, mut permit: MetaStorePermit<T>, value: T) -> Result<(), MetaStoreError> {
        // We own the outcome from here on, so a later drop must not reap.
        permit.defuse();
        let req_id = permit.req_id;
        let value = Arc::new(value);
        let entry = self
            .storage
            .get_mut(&req_id)
            .ok_or(MetaStoreError::NotFound { req_id })?;
        match entry.status() {
            EntryStatus::Deleted => return Err(MetaStoreError::CannotUpdate { req_id }),
            EntryStatus::Pending => {
                entry.set_complete(Ok(value));
                self.complete_queue.push_back(req_id);
            }
            EntryStatus::Done => {
                entry.set_complete(Ok(value));
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
    /// Note: this does not publish a new state, but removing a `Pending` entry drops its result channel,
    /// so any waiter in `retrieve_from_meta_store_with_timeout` will wake with `Unavailable`.
    /// Deliberately **private**, like [`finalize`](MetaStore::finalize): reached
    /// only through [`with_overwriting_claim`], the migration-only entry point.
    fn abort_reservation(&mut self, mut permit: MetaStorePermit<T>) {
        // The rollback is the recorded outcome, so a later drop must not reap.
        permit.defuse();
        let req_id = permit.req_id;
        if let Some(entry) = self.storage.get(&req_id)
            && entry.status() == EntryStatus::Pending
        {
            // Orphaned `Pending` claim: drop the entry entirely. A `Pending` entry
            // is never in the completion queue, so no queue cleanup is needed.
            //
            // Removing it drops the result channel without publishing, so a waiter
            // blocked in `retrieve_from_meta_store_with_timeout` would wake with
            // `Unavailable`.
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
    fn delete(&mut self, mut permit: MetaStorePermit<T>) -> Result<EntryState<T>, MetaStoreError> {
        // We own the outcome (tombstone) from here on, so a later drop must not reap.
        permit.defuse();
        let req_id = permit.req_id;
        let entry = self
            .storage
            .get_mut(&req_id)
            .ok_or(MetaStoreError::NotFound { req_id })?;
        if entry.status() == EntryStatus::Deleted {
            return Err(MetaStoreError::CannotUpdate { req_id });
        }
        let prev = EntryState::from(&*entry);
        let was_done = matches!(prev, EntryState::Done(_));
        entry.set_deleted();
        self.deleted_set.insert(req_id);
        if was_done {
            self.complete_queue.retain(|id| id != &req_id);
        }
        Ok(prev)
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
            match entry.status() {
                EntryStatus::Pending | EntryStatus::Done => {
                    if entry.is_permit_held() {
                        return Err(MetaStoreError::Locked {
                            req_id: *request_id,
                        });
                    }
                }
                EntryStatus::Deleted => {
                    return Err(MetaStoreError::CannotUpdate {
                        req_id: *request_id,
                    });
                }
            }
        }
        // Safe: we just verified the entry exists and is not Deleted.
        let entry = self.storage.get_mut(request_id).unwrap();
        let prev = EntryState::from(&*entry);
        let was_done = matches!(prev, EntryState::Done(_));
        entry.set_deleted();
        self.deleted_set.insert(*request_id);
        if was_done {
            self.complete_queue.retain(|id| id != request_id);
        }
        Ok(prev)
    }

    /// Reaper hook: if `req_id` names an *orphaned* `Pending` entry — one whose
    /// insert/lock permit was dropped without recording an outcome, so no live
    /// permit remains (`Arc::strong_count == 1`) — transition it to
    /// `Done(Err(reason))` while the store lock is held, keeping the completion
    /// queue and the processing/completed counts consistent. Returns `true` if it
    /// failed the entry.
    ///
    /// No-op (returns `false`) for any other state: already `Done`, `Deleted`,
    /// absent, or still permit-held — the last case guards against an id that was
    /// reclaimed and reused after the abandonment message was enqueued.
    fn fail_if_orphaned(&mut self, req_id: &RequestId, reason: String) -> bool {
        let is_orphaned_pending = self
            .storage
            .get(req_id)
            .is_some_and(|entry| entry.status() == EntryStatus::Pending && !entry.is_permit_held());
        if !is_orphaned_pending {
            return false;
        }
        // Safe: we just observed the entry as Pending under this same write lock,
        // and nothing else can mutate it while we hold the lock.
        let entry = self
            .storage
            .get_mut(req_id)
            .expect("entry observed as Pending under this lock cannot vanish");
        // `set_complete` records the failure and wakes any waiter via the channel.
        entry.set_complete(Err(reason));
        self.complete_queue.push_back(*req_id);
        true
    }

    /// Reset an already-failed (`Done(Err)`) entry back to `Pending` and hand
    /// back a fresh permit, so the request can be retried under the *same*
    /// request id.
    ///
    /// This is the decryption-store counterpart to a fresh [`insert`](Self::insert):
    /// a request that previously failed — including one failed by the reaper
    /// after its permit was dropped (see
    /// [`fail_if_orphaned`](Self::fail_if_orphaned)).
    pub(crate) fn redo_failed(
        &mut self,
        req_id: &RequestId,
    ) -> Result<MetaStorePermit<T>, MetaStoreError> {
        match self.storage.get(req_id) {
            None => return Err(MetaStoreError::NotFound { req_id: *req_id }),
            Some(entry) => match entry.status() {
                EntryStatus::Deleted => {
                    return Err(MetaStoreError::CannotUpdate { req_id: *req_id });
                }
                EntryStatus::Pending => {
                    return Err(MetaStoreError::Locked { req_id: *req_id });
                }
                EntryStatus::Done => {
                    // Only a previously *failed* entry may be retried; a
                    // successful `Done(Ok)` is not restartable.
                    if !matches!(&*entry.result_tx.borrow(), EntryState::Done(Err(_))) {
                        return Err(MetaStoreError::CannotUpdate { req_id: *req_id });
                    }
                    // A failed entry can still be permit-held (reserved via
                    // `lock_entry`); block the retry until that permit is released.
                    if entry.is_permit_held() {
                        return Err(MetaStoreError::Locked { req_id: *req_id });
                    }
                }
            },
        }
        // Reset to a fresh `Pending` (with a new, empty result channel): drop it
        // from the completion queue and install a new claim, then hand back a
        // permit (mirroring `insert`).
        self.complete_queue.retain(|id| id != req_id);
        let (entry, claim) = StoredEntry::new_pending();
        self.storage.insert(*req_id, entry);
        Ok(MetaStorePermit::new(*req_id, claim, self.reaper_tx.clone()))
    }

    /// Get the maximum capacity of this MetaStore
    pub(crate) fn get_capacity(&self) -> usize {
        self.capacity
    }

    /// Get the current number of items in the store
    pub(crate) fn get_total_count(&self) -> usize {
        self.storage.len()
    }

    /// Get the number of deleted (tombstoned) items
    #[allow(dead_code)]
    pub(crate) fn get_deleted_count(&self) -> usize {
        self.deleted_set.len()
    }

    /// Return an iterator over all request IDs that have ever been seen by this store, including deleted ones.
    pub(crate) fn get_any_seen_request_ids(&self) -> impl Iterator<Item = &RequestId> + '_ {
        self.storage.keys()
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
            .saturating_sub(self.complete_queue.len()) // including both OK and Err Done entries
            .saturating_sub(self.deleted_set.len())
    }

    /// Get successfully completed request IDs.
    /// That is, requests that have been processed correctly.
    /// This thus excludes request IDs that have been deleted, are pending, or have failed.
    /// WARNING: This is a slow operation
    pub(crate) fn get_successful_completed_request_ids(&self) -> Vec<RequestId> {
        self.complete_queue
            .iter()
            .filter_map(|id| match self.storage.get(id) {
                Some(entry) if matches!(&*entry.result_tx.borrow(), EntryState::Done(Ok(_))) => {
                    Some(*id)
                }
                Some(_) => None,
                None => {
                    tracing::error!("INVARIANT VIOLATION: Completed item {id} not found in storage - data corruption detected");
                    None
                }
            })
            .collect()
    }

    /// Get processing request IDs (not yet completed)
    /// WARNING: This is a slow operation
    pub(crate) fn get_processing_request_ids(&self) -> Vec<RequestId> {
        self.storage
            .iter()
            .filter(|(_, e)| e.status() == EntryStatus::Pending)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get failed request IDs (completed with errors)
    /// WARNING: This is a slow operation
    pub(crate) fn get_failed_request_ids(&self) -> Vec<RequestId> {
        self.complete_queue
            .iter()
            .filter_map(|id| match self.storage.get(id) {
                Some(entry) if matches!(&*entry.result_tx.borrow(), EntryState::Done(Err(_))) => Some(*id),
                Some(_) => None,
                None => {
                    tracing::error!("INVARIANT VIOLATION: Completed item {id} not found in storage - data corruption detected");
                    None
                }
            })
            .collect()
    }

    /// Get deleted request IDs (requests that have been tombstoned).
    pub(crate) fn get_deleted_request_ids(&self) -> impl Iterator<Item = &RequestId> + '_ {
        self.deleted_set.iter()
    }
}

pub(crate) async fn add_req_to_meta_store<T>(
    meta_store: &RwLock<MetaStore<T>>,
    req_id: &RequestId,
    request_metric: &'static str,
) -> Result<MetaStorePermit<T>, MetricedError> {
    let mut permit = meta_store
        .write()
        .await
        .insert(req_id)
        .map_err(|e| e.into_metriced(request_metric))?;
    // Report under the caller's metric if this request is later abandoned.
    permit.op = request_metric;
    Ok(permit)
}

/// Background task draining abandonment messages from dropped permits. For each
/// `(req_id, op_metric)` it fails the still-orphaned `Pending` entry under the
/// store lock (see [`MetaStore::fail_if_orphaned`]) and records an async error
/// metric. Exits when the store has been dropped (the [`Weak`] no longer
/// upgrades) or when every sender — the store's and all permits' — is gone.
async fn reaper_loop<T>(
    store: Weak<RwLock<MetaStore<T>>>,
    mut rx: mpsc::UnboundedReceiver<(RequestId, &'static str)>,
) {
    while let Some((req_id, op_metric)) = rx.recv().await {
        let Some(store) = store.upgrade() else {
            // Store gone: nothing left to reap.
            break;
        };
        let reason = "request abandoned: meta store permit dropped before an outcome was recorded"
            .to_string();
        if store
            .write()
            .await
            .fail_if_orphaned(&req_id, reason.clone())
        {
            MetricedError::handle_unreturnable_error(op_metric, Some(req_id), reason);
        }
    }
}

///////////// HELPER FUNCTIONS /////////////////////////////////////////////

/// Fail-fast, read-only existence check that mirrors [`MetaStore::insert`]'s
/// duplicate rejection: returns an `AlreadyExists` [`MetricedError`] if an entry
/// (pending, completed, or tombstoned) already occupies `req_id`.
///
/// Intended to be called *before* expensive setup/computation so a request for
/// an already-known id is rejected early, without claiming a permit.
pub(crate) async fn ensure_not_in_meta_store<T>(
    meta_store: &RwLock<MetaStore<T>>,
    req_id: &RequestId,
    request_metric: &'static str,
) -> Result<(), MetricedError> {
    if meta_store.read().await.has_existed(req_id) {
        return Err(MetaStoreError::AlreadyExists { req_id: *req_id }.into_metriced(request_metric));
    }
    Ok(())
}

/// Acquire a permit for an *existing* entry, acquiring & releasing the write
/// lock internally and mapping the failure to a [`MetricedError`] for gRPC
/// propagation. The lock-an-existing-entry analogue of [`add_req_to_meta_store`].
pub(crate) async fn lock_entry_in_meta_store<T>(
    meta_store: &RwLock<MetaStore<T>>,
    req_id: &RequestId,
    request_metric: &'static str,
) -> Result<MetaStorePermit<T>, MetricedError> {
    let mut permit = meta_store
        .write()
        .await
        .lock_entry(req_id)
        .map_err(|e| e.into_metriced(request_metric))?;
    // Report under the caller's metric if this lock is later abandoned.
    permit.op = request_metric;
    Ok(permit)
}

/// Acquire a permit to start — or restart — a request on `req_id`.
///
/// Inserts a fresh entry like [`add_req_to_meta_store`]; but if the id already
/// exists and its previous attempt *failed* (`Done(Err)`), the failed entry is
/// reset and retried via [`MetaStore::redo_failed`] instead of being rejected.
/// Any other existing state — an in-flight `Pending`, a successful `Done(Ok)`,
/// or a tombstone — keeps `insert`'s `AlreadyExists` rejection, so a successful
/// or in-progress request is never silently restarted.
///
/// Insert and retry happen under a single write-lock span, so the
/// check-and-reset is atomic. Intended for the decryption request paths, where a
/// client re-submitting an id whose prior attempt failed should be able to retry.
pub(crate) async fn add_or_redo_failed_in_meta_store<T>(
    meta_store: &RwLock<MetaStore<T>>,
    req_id: &RequestId,
    request_metric: &'static str,
) -> Result<MetaStorePermit<T>, MetricedError> {
    let mut guard = meta_store.write().await;
    let mut permit = match guard.insert(req_id) {
        Ok(permit) => permit,
        Err(MetaStoreError::AlreadyExists { .. }) => {
            // The id is known: only a previously-failed entry may be retried.
            // Map every non-retryable state back to `AlreadyExists` so callers
            // see the same rejection `add_req_to_meta_store` would have produced.
            guard
                .redo_failed(req_id)
                .map_err(|_| MetaStoreError::AlreadyExists { req_id: *req_id })
                .map_err(|e| e.into_metriced(request_metric))?
        }
        Err(e) => return Err(e.into_metriced(request_metric)),
    };
    // Report under the caller's metric if this request is later abandoned.
    permit.op = request_metric;
    Ok(permit)
}

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

pub(crate) async fn delete_in_meta_store<'a, T>(
    mut meta_store_guard: RwLockWriteGuard<'a, MetaStore<T>>,
    permit: MetaStorePermit<T>,
    error: String,
    request_metric: &'static str,
) -> bool {
    let req_id = permit.req_id;
    match meta_store_guard.delete(permit) {
        Ok(_) => true,
        Err(e) => {
            MetricedError::handle_unreturnable_error(request_metric, Some(req_id), error.clone());
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
/// entry.
/// It exists for the key-migration edge case (`copy_compressed_key_to_original`),
/// where storage keyed by `req_id` is rewritten and must be atomic.
///
/// The entry is required to exist.
///
/// `work` returns `(value, payload)`: `value` is stored under `req_id`;
/// `payload` is returned to the caller (e.g. to update an out-of-store cache
/// only after the commit succeeds).
pub(crate) async fn with_overwriting_claim<T, R, F>(
    meta_store: &RwLock<MetaStore<T>>,
    req_id: &RequestId,
    work: F,
) -> anyhow::Result<R>
where
    F: AsyncFnOnce() -> anyhow::Result<(T, R)>,
{
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

/// Map an absent / `Deleted` entry to the shared `NotFound` [`MetricedError`].
fn entry_not_found_or_deleted(req_id: &RequestId, metric_scope: &'static str) -> MetricedError {
    let msg = format!(
        "Could not retrieve the result in scope {metric_scope} with request ID {req_id}. It does not exist"
    );
    MetricedError::new(
        metric_scope,
        Some(*req_id),
        anyhow!(msg),
        tonic::Code::NotFound,
    )
}

/// Map a settled `Done` result (`Result<Arc<T>, String>`) to a caller-facing
/// outcome.
fn metriced_result<T>(
    result: Result<Arc<T>, String>,
    req_id: &RequestId,
    metric_scope: &'static str,
) -> Result<Arc<T>, MetricedError> {
    match result {
        Ok(arc) => Ok(arc),
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
pub(crate) async fn retrieve_from_meta_store<T>(
    meta_store: &RwLock<MetaStore<T>>,
    req_id: &RequestId,
    metric_scope: &'static str,
) -> Result<Arc<T>, MetricedError> {
    let guard = meta_store.read().await;
    match guard.retrieve(req_id) {
        None | Some(EntryState::Deleted) => Err(entry_not_found_or_deleted(req_id, metric_scope)),
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
        Some(EntryState::Done(result)) => metriced_result(result, req_id, metric_scope),
    }
}

/// Helper for retrieving the result of a request from a meta store.
/// Like [`retrieve_from_meta_store`] but blocking up to `wait_secs` for a
/// `Pending` entry to settle.
///
/// - `Done(Ok)`  → `Arc<T>`.
/// - `Pending`   → `Unavailable`; the result is not ready yet and the caller
///   (client) is expected to retry later.
/// - missing / `Deleted` → `NotFound`.
/// - `Done(Err)` → `Internal`, or `Aborted` if the stored error mentions
///   "abort".
///
/// Acquires the read lock only for the duration of the snapshot, so writers are
/// not blocked.
pub(crate) async fn retrieve_from_meta_store_with_timeout<T>(
    meta_store: &RwLock<MetaStore<T>>,
    req_id: &RequestId,
    metric_scope: &'static str,
    wait_secs: u64,
) -> Result<Arc<T>, MetricedError> {
    // Snapshot the entry under the read lock. A settled (or absent) entry is
    // classified and returned immediately; a `Pending` entry yields a receiver on
    // its result channel that we await below, after dropping the lock.
    let mut rx = {
        let guard = meta_store.read().await;
        match guard.storage.get(req_id) {
            // Absent or tombstoned: the same `NotFound` the snapshot path returns.
            None => return Err(entry_not_found_or_deleted(req_id, metric_scope)),
            Some(entry) => match &*entry.result_tx.borrow() {
                EntryState::Pending => {
                    // Still pending: take a receiver so we can await completion
                    // off-lock (subscribing under the lock, so no publish is missed).
                    entry.result_tx.subscribe()
                }
                EntryState::Done(res) => return metriced_result(res.clone(), req_id, metric_scope),
                EntryState::Deleted => {
                    return Err(entry_not_found_or_deleted(req_id, metric_scope));
                }
            },
        }
        // lock dropped here
    };

    let unavailable = |msg: String| {
        tracing::info!(msg);
        MetricedError::new(
            metric_scope,
            Some(*req_id),
            anyhow!(msg),
            tonic::Code::Unavailable,
        )
    };
    match tokio::time::timeout(
        tokio::time::Duration::from_secs(wait_secs),
        rx.wait_for(|state| !matches!(state, EntryState::Pending)),
    )
    .await
    {
        Ok(Ok(state)) => match &*state {
            EntryState::Done(result) => metriced_result(result.clone(), req_id, metric_scope),
            // Deleted/aborted while we waited — same outcome as the snapshot path.
            EntryState::Deleted => Err(entry_not_found_or_deleted(req_id, metric_scope)),
            // `wait_for`'s predicate excludes `Pending`, so this is unreachable.
            EntryState::Pending => Err(unavailable(format!(
                "Result in scope {metric_scope} with request ID {req_id} is not ready yet"
            ))),
        },
        // The sender was dropped before settling (e.g. the store is shutting
        // down); treat it as not-yet-available.
        Ok(Err(_recv_err)) => Err(unavailable(format!(
            "Could not retrieve the result in scope {metric_scope} with request ID {req_id} since its result channel closed before completion"
        ))),
        Err(_elapsed) => Err(unavailable(format!(
            "Could not retrieve the result in scope {metric_scope} with request ID {req_id} since it is not completed yet after waiting for {wait_secs} seconds"
        ))),
    }
}

/// Bare constructors for synchronous unit tests. Unlike the public constructors, these return the
/// `MetaStore` itself (not `Arc<RwLock<..>>`) and do **not** spawn a reaper task
/// — the channel receiver is dropped, so no Tokio runtime is required and a
/// dropped permit simply leaves an orphaned `Pending`. Reaper behavior is
/// exercised separately by the `#[tokio::test]` reaper tests.
#[cfg(test)]
impl<T> MetaStore<T> {
    fn new_inner(capacity: usize, min_cache: usize) -> Self {
        Self::inner_new(
            capacity,
            min_cache,
            VecDeque::with_capacity(min_cache),
            HashMap::with_capacity(capacity),
        )
        .0
    }

    fn new_unlimited_inner() -> Self {
        Self::inner_new(usize::MAX, usize::MAX, VecDeque::new(), HashMap::new()).0
    }

    fn new_from_map_inner(map: HashMap<RequestId, T>) -> Self {
        let mut complete_queue = VecDeque::new();
        let storage = map
            .into_iter()
            .map(|(key, value)| {
                complete_queue.push_back(key);
                (key, StoredEntry::new_done(Ok(Arc::new(value))))
            })
            .collect();
        Self::inner_new(usize::MAX, usize::MAX, complete_queue, storage).0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::base::derive_request_id;
    use kms_grpc::RequestId;
    use std::time::{Duration, Instant};

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
        if store.has_existed(id) {
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
        let mut meta_store: MetaStore<String> = MetaStore::new_inner(2, 1);
        let request_id: RequestId = derive_request_id("meta_store").unwrap();
        assert!(!meta_store.has_existed(&request_id));

        let permit = meta_store.insert(&request_id).unwrap();
        assert!(meta_store.has_existed(&request_id));
        assert!(meta_store.update(Ok("OK".to_string()), permit).is_ok());
        assert_done_ok(&meta_store, &request_id, &"OK".to_string());
    }

    #[test]
    fn test_kickout_of_errors() {
        let mut meta_store: MetaStore<String> = MetaStore::new_inner(2, 1);
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

        assert!(!meta_store.has_existed(&id1));
        assert!(meta_store.has_existed(&id2));
        assert!(meta_store.has_existed(&id3));
    }

    #[test]
    fn double_insert() {
        let mut meta_store: MetaStore<String> = MetaStore::new_inner(2, 1);
        let id: RequestId = derive_request_id("meta_store").unwrap();
        let _p = meta_store.insert(&id).unwrap();
        assert!(meta_store.insert(&id).is_err());
    }

    #[test]
    fn too_many_elements() {
        let mut meta_store: MetaStore<String> = MetaStore::new_inner(2, 1);
        let id1: RequestId = derive_request_id("1").unwrap();
        let id2: RequestId = derive_request_id("2").unwrap();
        let id3: RequestId = derive_request_id("3").unwrap();
        let _p1 = meta_store.insert(&id1).unwrap();
        let _p2 = meta_store.insert(&id2).unwrap();
        assert!(meta_store.insert(&id3).is_err());
    }

    #[test]
    fn auto_remove() {
        let mut meta_store: MetaStore<String> = MetaStore::new_inner(2, 1);
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
    fn try_delete_blocked_by_live_permit_on_pending() {
        // A live permit on a Pending entry blocks a permit-less `try_delete`
        let mut store: MetaStore<String> = MetaStore::new_inner(2, 1);
        let id: RequestId = derive_request_id("locked-del").unwrap();

        // Insert permit blocks until dropped.
        let insert_permit = store.insert(&id).unwrap();
        assert!(matches!(
            store.try_delete(&id),
            Err(MetaStoreError::Locked { .. })
        ));
        drop(insert_permit);

        // A fresh lock_entry permit on the same Pending entry blocks just the same.
        let lock_permit = store.lock_entry(&id).unwrap();
        assert!(matches!(
            store.try_delete(&id),
            Err(MetaStoreError::Locked { .. })
        ));
        drop(lock_permit);

        // Released: try_delete now tombstones the entry.
        assert!(store.try_delete(&id).is_ok());
        assert!(matches!(store.retrieve(&id), Some(EntryState::Deleted)));
    }

    #[test]
    fn delete_consumes_permit() {
        let mut meta_store: MetaStore<String> = MetaStore::new_inner(2, 1);
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
        let mut store: MetaStore<String> = MetaStore::new_inner(1, 1);
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
        let mut store: MetaStore<String> = MetaStore::new_inner(2, 1);
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
        let mut store: MetaStore<String> = MetaStore::new_inner(2, 1);
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
        let mut store: MetaStore<String> = MetaStore::new_inner(2, 1);
        let id = derive_request_id("lock-done-del").unwrap();
        insert_done_ok(&mut store, &id, "v");
        assert_eq!(store.get_successful_completed_request_ids().len(), 1);
        let permit = store.lock_entry(&id).unwrap();
        let prev = store.delete(permit).unwrap();
        assert!(matches!(prev, EntryState::Done(Ok(_))));
        assert!(matches!(store.retrieve(&id), Some(EntryState::Deleted)));
        assert_eq!(store.get_successful_completed_request_ids().len(), 0);
    }

    #[test]
    fn lock_entry_blocks_try_delete_until_released() {
        // A permit acquired via `lock_entry` on a still-Pending entry blocks a
        // permit-less `try_delete` just like the original insert permit does.
        let mut store: MetaStore<String> = MetaStore::new_inner(2, 1);
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
        let mut store: MetaStore<String> = MetaStore::new_inner(2, 1);
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
        let mut store: MetaStore<String> = MetaStore::new_inner(2, 1);
        let id = derive_request_id("try-del-done").unwrap();
        insert_done_ok(&mut store, &id, "payload");
        assert_eq!(store.get_successful_completed_request_ids().len(), 1);
        let prev = store.try_delete(&id).unwrap();
        match prev {
            EntryState::Done(Ok(arc)) => assert_eq!(arc.as_ref(), "payload"),
            other => panic!("expected Done(Ok), got {other}"),
        }
        assert!(matches!(store.retrieve(&id), Some(EntryState::Deleted)));
        assert_eq!(store.get_successful_completed_request_ids().len(), 0);
    }

    #[test]
    fn reserve_creates_fresh_then_finalize_completes() {
        // No entry yet: reserve creates a Pending placeholder (not yet queued),
        // and finalize drives it to Done and records it as completed.
        let mut store: MetaStore<String> = MetaStore::new_inner(2, 1);
        let id = derive_request_id("reserve-fresh").unwrap();
        let permit = reserve(&mut store, &id).unwrap();
        assert!(matches!(store.retrieve(&id), Some(EntryState::Pending)));
        assert_eq!(store.get_successful_completed_request_ids().len(), 0);
        store.finalize(permit, "v1".to_string()).unwrap();
        assert_done_ok(&store, &id, &"v1".to_string());
        assert_eq!(store.get_successful_completed_request_ids().len(), 1);
    }

    #[test]
    fn reserve_locks_existing_done_then_finalize_overwrites() {
        // Existing Done: reserve locks it in place (value preserved), finalize
        // overwrites it while keeping the single completion-queue slot.
        let mut store: MetaStore<String> = MetaStore::new_inner(2, 1);
        let id = derive_request_id("reserve-existing").unwrap();
        insert_done_ok(&mut store, &id, "v1");
        let permit = reserve(&mut store, &id).unwrap();
        // Still Done with the old value while reserved.
        assert_done_ok(&store, &id, &"v1".to_string());
        store.finalize(permit, "v2".to_string()).unwrap();
        assert_done_ok(&store, &id, &"v2".to_string());
        assert_eq!(store.get_successful_completed_request_ids().len(), 1);
    }

    #[test]
    fn reserve_rejects_entry_held_by_other_permit() {
        // While one caller holds a permit (here from a prior reserve), a second
        // reserve is rejected — this is the cross-step mutual exclusion that
        // prevents two concurrent migrations from racing on the same id.
        let mut store: MetaStore<String> = MetaStore::new_inner(2, 1);
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
        let mut store: MetaStore<String> = MetaStore::new_inner(2, 1);
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
        let mut store: MetaStore<String> = MetaStore::new_inner(2, 1);
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
        let mut store: MetaStore<String> = MetaStore::new_inner(2, 1);
        let id = derive_request_id("abort-existing").unwrap();
        insert_done_ok(&mut store, &id, "original");
        let permit = reserve(&mut store, &id).unwrap();
        store.abort_reservation(permit);
        assert_done_ok(&store, &id, &"original".to_string());
        assert_eq!(store.get_successful_completed_request_ids().len(), 1);
        // Released: it can be reserved again afterwards.
        assert!(reserve(&mut store, &id).is_ok());
    }

    #[test]
    fn reserve_after_failed_attempt_adopts_orphan_pending() {
        // Mirrors recovery when a prior migration created a Pending reservation
        // but its permit was dropped without finalize/abort (e.g. a task panic):
        // the orphan has no live permit, so a retry's reserve adopts it.
        let mut store: MetaStore<String> = MetaStore::new_inner(2, 1);
        let id = derive_request_id("reserve-orphan").unwrap();
        drop(reserve(&mut store, &id).unwrap()); // permit dropped, entry left Pending
        assert!(matches!(store.retrieve(&id), Some(EntryState::Pending)));
        let permit = reserve(&mut store, &id).unwrap(); // adopts the orphan
        store.finalize(permit, "adopted".to_string()).unwrap();
        assert_done_ok(&store, &id, &"adopted".to_string());
        assert_eq!(store.get_successful_completed_request_ids().len(), 1);
    }

    #[test]
    fn eviction_skips_reserved_entry_and_evicts_next() {
        // capacity 2, min_cache 1: two completed entries, the oldest reserved.
        // Inserting a third must evict the *younger* unreserved one, not the
        // reserved oldest, so the reservation's finalize still works.
        let mut store: MetaStore<String> = MetaStore::new_inner(2, 1);
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
        let mut store: MetaStore<String> = MetaStore::new_inner(2, 1);
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
        let mut store: MetaStore<String> = MetaStore::new_inner(2, 2);
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
        let mut store: MetaStore<String> = MetaStore::new_inner(2, 1);
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
        let store = MetaStore::new_from_map_inner(map);

        assert_eq!(store.get_capacity(), usize::MAX);
        assert_eq!(store.get_total_count(), 2);
        assert_eq!(store.get_successful_completed_request_ids().len(), 2);
        assert_eq!(store.get_processing_count(), 0);
        assert!(store.has_existed(&a));
        assert!(store.has_existed(&b));
        assert_done_ok(&store, &a, &"A".to_string());
        assert_done_ok(&store, &b, &"B".to_string());

        let completed = store.get_successful_completed_request_ids();
        assert_eq!(completed.len(), 2);
        assert!(completed.contains(&a) && completed.contains(&b));
    }

    #[test]
    fn count_and_listing_accessors() {
        let mut store: MetaStore<String> = MetaStore::new_unlimited_inner();
        let pending1 = derive_request_id("c-p1").unwrap();
        let _p1 = store.insert(&pending1).unwrap();
        let pending2 = derive_request_id("c-p2").unwrap();
        let _p2 = store.insert(&pending2).unwrap();

        let ok = derive_request_id("c-ok").unwrap();
        insert_done_ok(&mut store, &ok, "ok-val");
        let err = derive_request_id("c-err").unwrap();
        insert_done_err(&mut store, &err, "boom");

        // Aggregate counts.
        assert_eq!(store.get_total_count(), 4);
        // Only the `ok` entry is a success; the `err` entry is excluded.
        assert_eq!(store.get_successful_completed_request_ids().len(), 1);
        assert_eq!(store.get_processing_count(), 2);

        // Successful vs processing partition (failures are not successes).
        let completed = store.get_successful_completed_request_ids();
        assert_eq!(completed, vec![ok]);

        let processing = store.get_processing_request_ids();
        assert_eq!(processing.len(), 2);
        assert!(processing.contains(&pending1) && processing.contains(&pending2));

        // Failed entries are the Done(Err) subset of the completed set.
        let failed = store.get_failed_request_ids();
        assert_eq!(failed, vec![err]);

        // No deletions yet.
        assert_eq!(store.get_deleted_count(), 0);
        assert!(store.get_deleted_request_ids().next().is_none());
        assert_done_err(&store, &err, "boom");
    }

    #[test]
    fn deleted_ids_are_listed_and_excluded_from_completed() {
        let mut store: MetaStore<String> = MetaStore::new_unlimited_inner();
        let kept = derive_request_id("d-kept").unwrap();
        let gone = derive_request_id("d-gone").unwrap();
        insert_done_ok(&mut store, &kept, "keep");
        insert_done_ok(&mut store, &gone, "remove");
        store.try_delete(&gone).unwrap();

        assert_eq!(store.get_deleted_count(), 1);
        assert!(store.get_deleted_request_ids().any(|id| *id == gone));
        // The deleted entry leaves the completed queue; the survivor stays.
        let completed = store.get_successful_completed_request_ids();
        assert_eq!(completed, vec![kept]);
    }

    #[test]
    fn processing_count_excludes_deleted() {
        let mut store: MetaStore<String> = MetaStore::new_unlimited_inner();
        let pending = derive_request_id("pc-pending").unwrap();
        let permit = store.insert(&pending).unwrap();
        let done = derive_request_id("pc-done").unwrap();
        insert_done_ok(&mut store, &done, "v");
        let gone = derive_request_id("pc-gone").unwrap();
        insert_done_ok(&mut store, &gone, "v");
        store.try_delete(&gone).unwrap();

        // storage holds pending + done + tombstone = 3, but only the single
        // Pending entry counts as processing (the tombstone is excluded).
        assert_eq!(store.get_total_count(), 3);
        assert_eq!(store.get_successful_completed_request_ids().len(), 1);
        assert_eq!(store.get_processing_count(), 1);

        // Deleting the remaining Pending entry drops processing to zero, while the
        // tombstones stay resident in storage.
        drop(permit);
        store.try_delete(&pending).unwrap();
        assert_eq!(store.get_processing_count(), 0);
        assert_eq!(store.get_total_count(), 3);
    }

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

    #[tokio::test]
    async fn with_overwriting_claim_overwrites_existing() {
        let mut ms = MetaStore::<String>::new_inner(2, 1);
        let id = derive_request_id("woc-commit").unwrap();
        // The claim requires a pre-existing entry; seed one as the migration
        // target would already be present in the store.
        insert_done_ok(&mut ms, &id, "v0");
        let store = RwLock::new(ms);
        assert_eq!(
            store
                .read()
                .await
                .get_successful_completed_request_ids()
                .len(),
            1
        );

        // Existing Done -> overwrite in place, keep the single completion slot.
        let payload = with_overwriting_claim(&store, &id, async || Ok(("v1".to_string(), 42u8)))
            .await
            .unwrap();
        assert_eq!(payload, 42);
        assert_done_ok(&*store.read().await, &id, &"v1".to_string());
        assert_eq!(
            store
                .read()
                .await
                .get_successful_completed_request_ids()
                .len(),
            1
        );

        // A second overwrite still keeps the single completion slot.
        let payload = with_overwriting_claim(&store, &id, async || Ok(("v2".to_string(), 7u8)))
            .await
            .unwrap();
        assert_eq!(payload, 7);
        assert_done_ok(&*store.read().await, &id, &"v2".to_string());
        assert_eq!(
            store
                .read()
                .await
                .get_successful_completed_request_ids()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn with_overwriting_claim_absent_entry_errors_without_creating() {
        let store = RwLock::new(MetaStore::<String>::new_inner(2, 1));
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

    #[tokio::test]
    async fn with_overwriting_claim_preserves_existing_on_failure() {
        let mut ms = MetaStore::<String>::new_inner(2, 1);
        let id = derive_request_id("woc-preserve").unwrap();
        insert_done_ok(&mut ms, &id, "original");
        let store = RwLock::new(ms);

        let res: anyhow::Result<()> =
            with_overwriting_claim(&store, &id, async || anyhow::bail!("boom")).await;
        assert!(res.is_err());
        // The pre-existing Done value is untouched by the aborted claim.
        assert_done_ok(&*store.read().await, &id, &"original".to_string());
        assert_eq!(
            store
                .read()
                .await
                .get_successful_completed_request_ids()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn ensure_not_in_meta_store_rejects_known_ids() {
        let store = RwLock::new(MetaStore::<String>::new_inner(4, 1));
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

    /// An orphaned `Pending` entry (insert permit dropped without an outcome) is
    /// transitioned to `Done(Err)` and becomes a fully-fledged completed entry:
    /// queued and listed as failed.
    #[test]
    fn fail_if_orphaned_fails_dropped_pending() {
        let mut store: MetaStore<String> = MetaStore::new_inner(2, 1);
        let id = derive_request_id("orphan").unwrap();
        let permit = store.insert(&id).unwrap();
        drop(permit); // abandoned: claim strong_count drops back to 1
        assert!(store.fail_if_orphaned(&id, "abandoned".to_string()));
        assert_done_err(&store, &id, "abandoned");
        assert!(store.get_successful_completed_request_ids().is_empty());
        assert_eq!(store.get_processing_count(), 0);
        assert_eq!(store.get_failed_request_ids(), vec![id]);
    }

    /// While a permit is still live the entry must not be reaped: this guards an
    /// id that was reclaimed and reused after an abandonment message was enqueued.
    #[test]
    fn fail_if_orphaned_skips_live_permit() {
        let mut store: MetaStore<String> = MetaStore::new_inner(2, 1);
        let id = derive_request_id("live").unwrap();
        let _permit = store.insert(&id).unwrap(); // still held
        assert!(!store.fail_if_orphaned(&id, "nope".to_string()));
        assert!(matches!(store.retrieve(&id), Some(EntryState::Pending)));
    }

    /// Reaping is a no-op for any non-orphaned-`Pending` state: an already
    /// completed entry is not overwritten, and tombstoned / absent ids are left
    /// alone.
    #[test]
    fn fail_if_orphaned_skips_done_deleted_and_missing() {
        let mut store: MetaStore<String> = MetaStore::new_inner(2, 1);

        let done = derive_request_id("done").unwrap();
        insert_done_ok(&mut store, &done, "ok");
        assert!(!store.fail_if_orphaned(&done, "nope".to_string()));
        assert_done_ok(&store, &done, &"ok".to_string());

        let del = derive_request_id("del").unwrap();
        let permit = store.insert(&del).unwrap();
        store.delete(permit).unwrap();
        assert!(!store.fail_if_orphaned(&del, "nope".to_string()));
        assert!(matches!(store.retrieve(&del), Some(EntryState::Deleted)));

        let missing = derive_request_id("missing").unwrap();
        assert!(!store.fail_if_orphaned(&missing, "nope".to_string()));
    }

    /// Poll until `id` becomes `Done(Err)` or a ~1s budget elapses, giving the
    /// background reaper task time to run.
    async fn wait_for_done_err(store: &Arc<RwLock<MetaStore<String>>>, id: &RequestId) -> bool {
        for _ in 0..200 {
            if let Some(EntryState::Done(Err(_))) = store.read().await.retrieve(id) {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        false
    }

    /// End-to-end: with a reaper attached, dropping a permit without recording an
    /// outcome causes the orphaned entry to be failed asynchronously.
    #[tokio::test]
    async fn reaper_fails_orphaned_permit_on_drop() {
        let store = MetaStore::<String>::new(4, 1);
        let id = derive_request_id("reap-drop").unwrap();

        let permit = add_req_to_meta_store(&store, &id, "test").await.unwrap();
        drop(permit); // abandon without recording an outcome

        assert!(
            wait_for_done_err(&store, &id).await,
            "reaper did not fail the orphaned entry"
        );
    }

    /// A permit consumed normally is defused, so its drop must not reap: the
    /// recorded result survives.
    #[tokio::test]
    async fn reaper_leaves_completed_request_untouched() {
        let store = MetaStore::<String>::new(4, 1);
        let id = derive_request_id("reap-ok").unwrap();

        let permit = add_req_to_meta_store(&store, &id, "test").await.unwrap();
        store
            .write()
            .await
            .update(Ok("v".to_string()), permit)
            .unwrap();

        // Give any erroneously-enqueued reap a chance to run before asserting.
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert_done_ok(&*store.read().await, &id, &"v".to_string());
    }

    /// An unlimited store still fails orphaned entries on drop — the case where
    /// it matters most, since unlimited stores never evict.
    #[tokio::test]
    async fn unlimited_store_reaps_orphaned_on_drop() {
        let store = MetaStore::<String>::new_unlimited();
        let id = derive_request_id("unlimited-reap").unwrap();
        let permit = add_req_to_meta_store(&store, &id, "test").await.unwrap();
        drop(permit);
        assert!(
            wait_for_done_err(&store, &id).await,
            "reaper did not fail the orphaned entry in an unlimited store"
        );
    }

    /// A from-map store keeps its pre-seeded `Done(Ok)` entries and still reaps
    /// newly-orphaned ones.
    #[tokio::test]
    async fn from_map_store_preserves_seed_and_reaps_new() {
        let seeded = derive_request_id("seeded").unwrap();
        let mut map = HashMap::new();
        map.insert(seeded, "preset".to_string());
        let store = MetaStore::<String>::new_from_map(map);

        // Pre-seeded entry is intact.
        assert_done_ok(&*store.read().await, &seeded, &"preset".to_string());

        // A fresh, abandoned request is reaped...
        let fresh = derive_request_id("fresh").unwrap();
        let permit = add_req_to_meta_store(&store, &fresh, "test").await.unwrap();
        drop(permit);
        assert!(wait_for_done_err(&store, &fresh).await);
        // ...and the seed is still intact afterwards.
        assert_done_ok(&*store.read().await, &seeded, &"preset".to_string());
    }

    /// A failed entry can be reset to `Pending` via `redo_failed` and retried
    /// under the same id, then completed successfully.
    #[test]
    fn redo_failed_resets_and_allows_retry() {
        let mut store: MetaStore<String> = MetaStore::new_inner(2, 1);
        let id = derive_request_id("redo").unwrap();
        insert_done_err(&mut store, &id, "boom");
        assert_eq!(store.get_failed_request_ids(), vec![id]);

        let permit = store
            .redo_failed(&id)
            .expect("a failed entry should be retryable");
        // Back in flight: no longer completed/failed.
        assert!(matches!(store.retrieve(&id), Some(EntryState::Pending)));
        assert_eq!(store.get_successful_completed_request_ids().len(), 0);
        assert!(store.get_failed_request_ids().is_empty());

        // The retry can now complete.
        store.update(Ok("recovered".to_string()), permit).unwrap();
        assert_done_ok(&store, &id, &"recovered".to_string());
    }

    /// `redo_failed` refuses to discard a successful result and rejects
    /// in-flight, tombstoned, and absent ids.
    #[test]
    fn redo_failed_rejects_non_failed_states() {
        let mut store: MetaStore<String> = MetaStore::new_inner(3, 1);

        // Done(Ok): a good result must not be discarded.
        let ok = derive_request_id("ok").unwrap();
        insert_done_ok(&mut store, &ok, "v");
        assert!(matches!(
            store.redo_failed(&ok),
            Err(MetaStoreError::CannotUpdate { .. })
        ));

        // Pending with a live permit: still in flight.
        let pend = derive_request_id("pend").unwrap();
        let _permit = store.insert(&pend).unwrap();
        assert!(matches!(
            store.redo_failed(&pend),
            Err(MetaStoreError::Locked { .. })
        ));

        // Deleted: the tombstone is permanent.
        let del = derive_request_id("del").unwrap();
        let p = store.insert(&del).unwrap();
        store.delete(p).unwrap();
        assert!(matches!(
            store.redo_failed(&del),
            Err(MetaStoreError::CannotUpdate { .. })
        ));

        // Absent id.
        let missing = derive_request_id("missing").unwrap();
        assert!(matches!(
            store.redo_failed(&missing),
            Err(MetaStoreError::NotFound { .. })
        ));
    }

    /// `add_or_redo_failed_in_meta_store`: a first request inserts fresh; after it
    /// fails, re-submitting the same id retries it and the permit completes it;
    /// once it has succeeded, re-submitting is rejected with `AlreadyExists`.
    #[tokio::test]
    async fn add_or_redo_failed_in_meta_store_lifecycle() {
        let store = RwLock::new(MetaStore::<String>::new_inner(2, 1));
        let id = derive_request_id("redo-helper").unwrap();

        // First submission inserts a fresh entry, which then fails.
        let permit = add_or_redo_failed_in_meta_store(&store, &id, "test")
            .await
            .unwrap();
        update_err_req_in_meta_store(&store, permit, "boom".to_string(), "test").await;

        // Re-submitting the failed id retries it; the retry completes ok.
        let retry = add_or_redo_failed_in_meta_store(&store, &id, "test")
            .await
            .unwrap();
        update_ok_req_in_meta_store(&store, retry, "ok".to_string(), "test").await;
        assert_done_ok(&*store.read().await, &id, &"ok".to_string());

        // Now `Done(Ok)`: re-submitting must not restart it — rejected as
        // `AlreadyExists`. (`.err()` avoids the `MetaStorePermit: Debug` that
        // `.unwrap_err()` would require.)
        let err = add_or_redo_failed_in_meta_store(&store, &id, "test")
            .await
            .err()
            .expect("a successful entry must not be restarted");
        assert_eq!(err.code(), tonic::Code::AlreadyExists);
    }

    /// `add_or_redo_failed_in_meta_store` rejects re-submission of an in-flight
    /// (`Pending`) id with `AlreadyExists`, preserving `add_req_to_meta_store`'s
    /// behavior for non-failed states.
    #[tokio::test]
    async fn add_or_redo_failed_in_meta_store_rejects_in_flight() {
        let store = RwLock::new(MetaStore::<String>::new_inner(2, 1));
        let id = derive_request_id("redo-inflight").unwrap();
        let _permit = add_or_redo_failed_in_meta_store(&store, &id, "test")
            .await
            .unwrap();
        let err = add_or_redo_failed_in_meta_store(&store, &id, "test")
            .await
            .err()
            .expect("an in-flight id must not be restarted");
        assert_eq!(err.code(), tonic::Code::AlreadyExists);
    }

    /// A `Pending` entry that completes while a caller is waiting wakes the
    /// waiter as soon as the result is recorded (rather than timing out).
    #[tokio::test]
    async fn retrieve_with_timeout_wakes_when_result_arrives() {
        let store = MetaStore::<String>::new_unlimited();
        let id = derive_request_id("wait-wake").unwrap();
        let permit = add_req_to_meta_store(&store, &id, "test").await.unwrap();

        // Complete the entry shortly after the waiter starts blocking.
        let writer_store = Arc::clone(&store);
        let writer_id = id;
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            update_ok_req_in_meta_store(&writer_store, permit, "late".to_string(), "test").await;
        });

        let start = Instant::now();
        // Generous timeout: the wait should end on the result, not the deadline.
        let arc = retrieve_from_meta_store_with_timeout(&store, &id, "test", 60)
            .await
            .expect("waiter should observe the completed result");
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "took too long: {:?}",
            start.elapsed()
        );
        assert_eq!(arc.as_ref(), "late");
        // Sanity: the entry really is the one we waited on.
        assert!(matches!(
            store.read().await.retrieve(&writer_id),
            Some(EntryState::Done(Ok(_)))
        ));
    }

    /// A `Pending` entry that never completes yields `Unavailable` once the wait
    /// budget elapses.
    #[tokio::test]
    async fn retrieve_with_timeout_times_out_on_stuck_pending() {
        let store = MetaStore::<String>::new_unlimited();
        let id = derive_request_id("wait-stuck").unwrap();
        // Hold the permit for the whole test so the entry stays Pending.
        let _permit = add_req_to_meta_store(&store, &id, "test").await.unwrap();

        let err = retrieve_from_meta_store_with_timeout(&store, &id, "test", 0)
            .await
            .expect_err("a stuck pending entry should time out");
        assert_eq!(err.code(), tonic::Code::Unavailable);
    }

    /// A waiter on a `Pending` entry that gets deleted wakes promptly — and with
    /// `NotFound`, the same outcome the snapshot path gives for a deleted entry —
    /// rather than blocking until the timeout.
    #[tokio::test]
    async fn retrieve_with_timeout_wakes_on_delete() {
        let store = MetaStore::<String>::new_unlimited();
        let id = derive_request_id("wait-delete").unwrap();
        let permit = add_req_to_meta_store(&store, &id, "test").await.unwrap();

        let writer_store = Arc::clone(&store);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            delete_in_meta_store(
                writer_store.write().await,
                permit,
                "gone".to_string(),
                "test",
            )
            .await;
        });

        // A long budget proves we wake on the delete, not the deadline.
        let err = retrieve_from_meta_store_with_timeout(&store, &id, "test", 60)
            .await
            .expect_err("a deleted entry should surface an error to the waiter");
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    /// An absent id is `NotFound` on the wait path, just like the non-blocking one.
    #[tokio::test]
    async fn retrieve_with_timeout_missing_is_not_found() {
        let store = MetaStore::<String>::new_unlimited();
        let id = derive_request_id("wait-missing").unwrap();
        let err = retrieve_from_meta_store_with_timeout(&store, &id, "test", 60)
            .await
            .expect_err("an absent id must not be returned");
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    /// The non-blocking `retrieve_from_meta_store` helper maps each entry state to
    /// its caller-facing outcome: `Done(Ok)` returns the value, `Pending` is
    /// `Unavailable`, and both an absent and a tombstoned id are `NotFound`.
    #[tokio::test]
    async fn retrieve_from_meta_store_maps_states() {
        let store = RwLock::new(MetaStore::<String>::new_unlimited_inner());

        // Absent id -> NotFound.
        let missing = derive_request_id("ret-missing").unwrap();
        let err = retrieve_from_meta_store(&store, &missing, "test")
            .await
            .expect_err("an absent id must not be returned");
        assert_eq!(err.code(), tonic::Code::NotFound);

        // Pending id -> Unavailable. The permit keeps the entry Pending.
        let pending = derive_request_id("ret-pending").unwrap();
        let _permit = store.write().await.insert(&pending).unwrap();
        let err = retrieve_from_meta_store(&store, &pending, "test")
            .await
            .expect_err("a pending entry is not ready yet");
        assert_eq!(err.code(), tonic::Code::Unavailable);

        // Done(Ok) id -> the stored value.
        let ok = derive_request_id("ret-ok").unwrap();
        insert_done_ok(&mut *store.write().await, &ok, "value");
        let arc = retrieve_from_meta_store(&store, &ok, "test")
            .await
            .expect("a completed entry should be returned");
        assert_eq!(arc.as_ref(), "value");

        // Deleted id -> NotFound, the same outcome as an absent id.
        store.write().await.try_delete(&ok).unwrap();
        let err = retrieve_from_meta_store(&store, &ok, "test")
            .await
            .expect_err("a tombstoned id must not be returned");
        assert_eq!(err.code(), tonic::Code::NotFound);
    }

    /// A `Done(Err)` result surfaces through the retrieve helper as `Internal`,
    /// unless the stored error mentions "abort", which maps to `Aborted`.
    #[tokio::test]
    async fn retrieve_from_meta_store_maps_error_codes() {
        let store = RwLock::new(MetaStore::<String>::new_unlimited_inner());

        // Generic failure -> Internal.
        let boom = derive_request_id("ret-boom").unwrap();
        insert_done_err(&mut *store.write().await, &boom, "boom");
        let err = retrieve_from_meta_store(&store, &boom, "test")
            .await
            .expect_err("a failed entry must surface an error");
        assert_eq!(err.code(), tonic::Code::Internal);

        // Error mentioning "abort" -> Aborted.
        let aborted = derive_request_id("ret-abort").unwrap();
        insert_done_err(&mut *store.write().await, &aborted, "task was aborted");
        let err = retrieve_from_meta_store(&store, &aborted, "test")
            .await
            .expect_err("an aborted entry must surface an error");
        assert_eq!(err.code(), tonic::Code::Aborted);
    }

    /// End-to-end: a waiter blocked on a `Pending` entry whose permit is dropped
    /// is woken by the reaper with a failing status (`Done(Err)` -> `Internal`).
    #[tokio::test]
    async fn retrieve_with_timeout_wakes_when_reaper_fails_orphan() {
        let store = MetaStore::<String>::new_unlimited();
        let id = derive_request_id("wait-orphan").unwrap();

        let permit = add_req_to_meta_store(&store, &id, "test").await.unwrap();
        // Abandon the request shortly after the waiter starts blocking; the reaper
        // then fails the now-orphaned Pending entry.
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            drop(permit);
        });

        let start = Instant::now();
        // Generous budget: we should wake on the reaper's failure, not the deadline.
        let err = retrieve_from_meta_store_with_timeout(&store, &id, "test", 60)
            .await
            .expect_err("an abandoned request should surface an error to the waiter");
        assert_eq!(err.code(), tonic::Code::Internal);
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "took too long: {:?}",
            start.elapsed()
        );
    }
}

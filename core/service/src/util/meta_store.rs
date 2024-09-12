use crate::{anyhow_error_and_log, kms::RequestId, some_or_err};
use std::collections::{HashMap, VecDeque};
use tonic::Status;

// Meta store helper enum, that is used to keep the status of a request in a meta store
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum HandlerStatus<T> {
    Started,
    Error(String),
    Done(T),
}

impl<T> std::fmt::Debug for HandlerStatus<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Started => write!(f, "Started"),
            Self::Error(arg0) => f.debug_tuple("Error").field(arg0).finish(),
            Self::Done(_) => write!(f, "Done()"),
        }
    }
}

/// Data structure that stores elements that are being processed and their status (Started, Done, Error).
/// It holds elements up to a given capacity, and once it is full, it will remove old elements that have status [Done]/[Error], if there are sufficiently many.
pub(crate) struct MetaStore<T> {
    // The maximum amount of entries in total (finished and unfinished)
    capacity: usize,
    // The minimum amount of entries that should be kept in the cache after completion and before old ones are evicted
    min_cache: usize,
    // Storage of all elements in the system
    storage: HashMap<RequestId, HandlerStatus<T>>,
    // Queue of all elements that have been completed
    complete_queue: VecDeque<RequestId>,
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
        }
    }

    /// Creates a new MetaStore with unlimited capacity and cache size.
    pub(crate) fn new_unlimited() -> Self {
        Self {
            capacity: usize::MAX,
            min_cache: usize::MAX,
            storage: HashMap::new(),
            complete_queue: VecDeque::new(),
        }
    }

    // Creates a MetaStore with unlimited storage capacity and minimum cache size and populates it with the given map
    pub(crate) fn new_from_map(map: HashMap<RequestId, HandlerStatus<T>>) -> Self {
        let mut completed_queue = VecDeque::new();
        for (request_id, handle) in map.iter() {
            if let HandlerStatus::Done(_) = handle {
                completed_queue.push_back(request_id.clone());
            }
        }
        Self {
            capacity: usize::MAX,
            min_cache: usize::MAX,
            storage: map,
            complete_queue: completed_queue,
        }
    }

    pub(crate) fn exists(&self, request_id: &RequestId) -> bool {
        self.storage.contains_key(request_id)
    }

    /// Insert a new element, throwing an exception if the element already exists or if the system is fully loaded.
    ///
    /// Elements can trivially be inserted until the store reaches its [capacity].
    /// Once the store is full, we will remove old elements that have status [Done] or [Error], but only once we have at least [min_cache] elements of them.
    /// This is to ensure that:
    /// 1. there are never more than [capacity] - [min_cache] elements currently being processed (status [Started]) and
    /// 2. there is enough time to retrieve an element before it is removed. This timespan is the time it takes to process [min_cache] elements.
    ///
    /// If the store is at max capacity and not enough elements have been completed, we will not accept new elements to be inserted.
    pub(crate) fn insert(&mut self, request_id: &RequestId) -> anyhow::Result<()> {
        if self.exists(request_id) {
            return Err(anyhow::anyhow!(
                "The element with ID {request_id} is already stored and contains {:#?}",
                self.retrieve(request_id)
            ));
        }
        if self.storage.len() >= self.capacity {
            // We have reached the capacity limit. Delete an old element.
            if self.complete_queue.len() <= self.min_cache {
                return Err(anyhow_error_and_log("The system is fully loaded and the cache of finished elements is not at minimum size yet. Cannot insert new element."));
            } else {
                // Remove the first (oldest) element from the age queue
                let old_request_id = some_or_err(
                    self.complete_queue.pop_front(),
                    "Could not remove an old request from the cache".to_string(),
                )?;
                // and also remove it from the storage map
                let _ = self.storage.remove(&old_request_id);
            }
        }
        // Ignore the result since we have already checked that the element does not exist
        let _ = self
            .storage
            .insert(request_id.to_owned(), HandlerStatus::Started);
        Ok(())
    }

    /// Update the status of an already existing element. Returns an error if something goes wrong, like
    /// the element does not exist or the status is already Done or Error
    pub(crate) fn update(
        &mut self,
        request_id: &RequestId,
        status: HandlerStatus<T>,
    ) -> anyhow::Result<()> {
        if !self.exists(request_id) {
            return Err(anyhow_error_and_log(format!(
                "The element with ID {request_id} does not exist, update is not allowed"
            )));
        }
        if let HandlerStatus::Started = status {
            return Err(anyhow_error_and_log(format!("Cannot update the status of a request with ID {request_id} to Started since it is already in progress")));
        }
        // Ignore the old status since we already checked if the element is there
        let _ = self.storage.insert(request_id.to_owned(), status);
        self.complete_queue.push_back(request_id.clone());
        Ok(())
    }

    /// Retrieve the status of an element and return None if it does not exist
    pub(crate) fn retrieve(&self, request_id: &RequestId) -> Option<&HandlerStatus<T>> {
        self.storage.get(request_id)
    }

    /// Deletes an element from the meta store and returns the value.
    /// Warning: This is a slow operation if the request_id has been completed
    /// and should be avoided if possible, since values are automatically removed when running out of space
    #[allow(dead_code)]
    pub(crate) fn delete(&mut self, request_id: &RequestId) -> Option<HandlerStatus<T>> {
        match self.storage.remove(request_id) {
            Some(handle) => {
                match handle {
                    // remove element from complete_queue only if its status is Done or Error
                    HandlerStatus::Done(_) | HandlerStatus::Error(_) => {
                        for i in 0..self.complete_queue.len() {
                            if request_id == &self.complete_queue[i] {
                                let _ = self.complete_queue.remove(i);
                                break;
                            }
                        }
                    }
                    _ => (),
                };
                Some(handle)
            }
            None => None,
        }
    }
}

/// Helper method for retrieving the result of a request from an appropriate meta store
/// [req_id] is the request ID to retrieve
/// [request_type] is a free-form string used only for error logging the origin of the failure
pub(crate) fn handle_res_mapping<T>(
    handle: Option<HandlerStatus<T>>,
    req_id: &RequestId,
    request_type_info: &str,
) -> Result<T, Status> {
    match handle {
        None => {
            let msg = format!(
                "Could not retrieve {request_type_info} with request ID {}. It does not exist",
                req_id
            );
            tracing::warn!(msg);
            Err(tonic::Status::new(tonic::Code::NotFound, msg))
        }
        Some(HandlerStatus::Started) => {
            let msg = format!(
                    "Could not retrieve {request_type_info} with request ID {} since it is not completed yet",
                    req_id
                );
            tracing::warn!(msg);
            Err(tonic::Status::new(tonic::Code::Unavailable, msg))
        }
        Some(HandlerStatus::Error(e)) => {
            let msg = format!(
                    "Could not retrieve {request_type_info} with request ID {} since it finished with an error: {}",
                    req_id, e
                );
            tracing::warn!(msg);
            Err(tonic::Status::new(tonic::Code::Internal, msg))
        }
        Some(HandlerStatus::Done(res)) => Ok(res),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kms::RequestId;

    #[test]
    fn sunshine() {
        let mut meta_store: MetaStore<String> = MetaStore::new(2, 1);
        let request_id: RequestId = RequestId::derive("meta_store").unwrap();
        // Data does not exist
        assert!(!meta_store.exists(&request_id));
        assert!(meta_store
            .update(&request_id, HandlerStatus::Done("OK".to_string()))
            .is_err());

        meta_store.insert(&request_id).unwrap();
        // Data exits
        assert!(meta_store.exists(&request_id));
        assert!(meta_store
            .update(&request_id, HandlerStatus::Done("OK".to_string()))
            .is_ok());
        // Downgrade not allowed
        assert!(meta_store
            .update(&request_id, HandlerStatus::Started)
            .is_err());
    }

    #[test]
    fn double_insert() {
        let mut meta_store: MetaStore<String> = MetaStore::new(2, 1);
        let request_id: RequestId = RequestId::derive("meta_store").unwrap();
        meta_store.insert(&request_id).unwrap();
        // We cannot insert the same request_id twice
        assert!(meta_store.insert(&request_id).is_err());
    }

    #[test]
    fn too_many_elements() {
        let mut meta_store: MetaStore<String> = MetaStore::new(2, 1);
        let req_1: RequestId = RequestId::derive("1").unwrap();
        let req_2: RequestId = RequestId::derive("2").unwrap();
        let req_3: RequestId = RequestId::derive("3").unwrap();
        meta_store.insert(&req_1).unwrap();
        meta_store.insert(&req_2).unwrap();
        // Only room for 2 elements
        assert!(meta_store.insert(&req_3).is_err());
    }

    #[test]
    fn auto_remove() {
        let mut meta_store: MetaStore<String> = MetaStore::new(2, 1);
        let req_1: RequestId = RequestId::derive("1").unwrap();
        let req_2: RequestId = RequestId::derive("2").unwrap();
        let req_3: RequestId = RequestId::derive("3").unwrap();
        meta_store.insert(&req_1).unwrap();
        assert!(meta_store
            .update(&req_1, HandlerStatus::Done("OK".to_string()))
            .is_ok());
        assert!(meta_store.retrieve(&req_1).is_some());
        meta_store.insert(&req_2).unwrap();
        assert!(meta_store
            .update(&req_2, HandlerStatus::Done("OK".to_string()))
            .is_ok());
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

    #[test]
    fn delete() {
        let mut meta_store: MetaStore<String> = MetaStore::new(10, 2);
        let req_1: RequestId = RequestId::derive("1").unwrap();
        let req_2: RequestId = RequestId::derive("2").unwrap();
        let req_3: RequestId = RequestId::derive("3").unwrap();
        let req_4: RequestId = RequestId::derive("4").unwrap();

        meta_store.insert(&req_1).unwrap();
        meta_store.insert(&req_2).unwrap();
        meta_store.insert(&req_3).unwrap();
        meta_store.insert(&req_4).unwrap();

        assert_eq!(meta_store.complete_queue.len(), 0);

        // set req1 to Done and req2 to Error
        assert!(meta_store
            .update(&req_1, HandlerStatus::Done("OK".to_string()))
            .is_ok());
        assert!(meta_store
            .update(&req_2, HandlerStatus::Error("Err".to_string()))
            .is_ok());
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

use crate::{
    anyhow_error_and_log, consts::DURATION_WAITING_ON_RESULT_SECONDS, kms::RequestId, some_or_err,
};
use async_cell::sync::AsyncCell;
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};
use tonic::Status;

/// Data structure that stores elements that are being processed and their status (Started, Done, Error).
/// It holds elements up to a given capacity, and once it is full, it will remove old elements that have status [Done]/[Error], if there are sufficiently many.
pub(crate) struct MetaStore<T> {
    // The maximum amount of entries in total (finished and unfinished)
    capacity: usize,
    // The minimum amount of entries that should be kept in the cache after completion and before old ones are evicted
    min_cache: usize,
    // Storage of all elements in the system
    storage: HashMap<RequestId, Arc<AsyncCell<Result<T, String>>>>,
    // Queue of all elements that have been completed
    complete_queue: VecDeque<RequestId>,
}

impl<T: Clone> MetaStore<T> {
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
    pub(crate) fn new_from_map(map: HashMap<RequestId, T>) -> Self {
        let mut completed_queue = VecDeque::new();
        let storage = map
            .into_iter()
            .map(|(key, value)| {
                completed_queue.push_back(key.clone());
                (key, Arc::new(AsyncCell::new_with(Ok(value))))
            })
            .collect();

        Self {
            capacity: usize::MAX,
            min_cache: usize::MAX,
            storage,
            complete_queue: completed_queue,
        }
    }

    pub(crate) fn exists(&self, request_id: &RequestId) -> bool {
        self.storage.contains_key(request_id)
    }

    /// Insert a new element, throwing an exception if the element already exists or if the system is fully loaded.
    ///
    /// Elements can trivially be inserted until the store reaches its [capacity].
    /// Once the store is full, we will remove old elements that have completed, but only once we have at least [min_cache] elements of them.
    /// This is to ensure that:
    /// 1. there are never more than [capacity] - [min_cache] elements currently being processed (id not in `complete_queue`) and
    /// 2. there is enough time to retrieve an element before it is removed. This timespan is the time it takes to process [min_cache] elements.
    ///
    /// If the store is at max capacity and not enough elements have been completed, we will not accept new elements to be inserted.
    pub(crate) fn insert(&mut self, request_id: &RequestId) -> anyhow::Result<()> {
        if self.exists(request_id) {
            return Err(anyhow::anyhow!(
                "The element with ID {request_id} already stored exists. Can not insert it more than once.",
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
        let cell = AsyncCell::shared();
        let _ = self.storage.insert(request_id.to_owned(), cell);
        Ok(())
    }

    /// Sets the value of an already existing element. Returns an error if something goes wrong, like
    /// the element does not exist or the value was already set.
    pub(crate) fn update(
        &mut self,
        request_id: &RequestId,
        update: Result<T, String>,
    ) -> anyhow::Result<()> {
        let cell = if let Some(cell) = self.storage.get(request_id) {
            cell
        } else {
            return Err(anyhow_error_and_log(format!(
                "The element with ID {request_id} does not exist, update is not allowed"
            )));
        };

        // We only allow setting the result once
        if cell.is_set() {
            return Err(anyhow_error_and_log(format!(
                "The element with ID {request_id} is already done, update is not allowed"
            )));
        }

        cell.set(update);
        self.complete_queue.push_back(request_id.clone());

        Ok(())
    }

    /// Retrieve the cell of an element and return None if it does not exist
    pub(crate) fn retrieve(
        &self,
        request_id: &RequestId,
    ) -> Option<Arc<AsyncCell<Result<T, String>>>> {
        self.storage.get(request_id).cloned()
    }

    /// Deletes an element from the meta store and returns the value.
    /// Warning: This is a slow operation if the request_id has been completed
    /// and should be avoided if possible, since values are automatically removed when running out of space
    #[allow(dead_code)]
    pub(crate) fn delete(
        &mut self,
        request_id: &RequestId,
    ) -> Option<Arc<AsyncCell<Result<T, String>>>> {
        match self.storage.remove(request_id) {
            Some(handle) => {
                // If the cell is set, it means the task has been processed
                // and thus added to the complete queue
                if handle.is_set() {
                    for i in 0..self.complete_queue.len() {
                        if request_id == &self.complete_queue[i] {
                            let _ = self.complete_queue.remove(i);
                            break;
                        }
                    }
                }
                Some(handle)
            }
            None => None,
        }
    }
}

/// Helper method for retrieving the result of a request from an appropriate meta store
/// [req_id] is the request ID to retrieve
/// [request_type] is a free-form string used only for error logging the origin of the failure
pub(crate) async fn handle_res_mapping<T: Clone>(
    handle: Option<Arc<AsyncCell<Result<T, String>>>>,
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
                                "Could not retrieve {request_type_info} with request ID {} since it finished with an error: {}",
                                req_id, e
                            );
                        tracing::warn!(msg);
                        Err(tonic::Status::new(tonic::Code::Internal, msg))
                    }
                }
            } else {
                let msg = format!(
                    "Could not retrieve {request_type_info} with request ID {} since it is not completed yet after waiting for {DURATION_WAITING_ON_RESULT_SECONDS} seconds",
                    req_id
                );
                tracing::info!(msg);
                Err(tonic::Status::new(tonic::Code::Unavailable, msg))
            }
            // Note that this is not logged as an error as we expect calls to take some time to be completed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kms::RequestId;
    use tokio::sync::RwLock;

    #[test]
    fn sunshine() {
        let mut meta_store: MetaStore<String> = MetaStore::new(2, 1);
        let request_id: RequestId = RequestId::derive("meta_store").unwrap();
        // Data does not exist
        assert!(!meta_store.exists(&request_id));
        assert!(meta_store
            .update(&request_id, Ok("OK".to_string()))
            .is_err());

        meta_store.insert(&request_id).unwrap();
        // Data exits
        assert!(meta_store.exists(&request_id));
        assert!(meta_store.update(&request_id, Ok("OK".to_string())).is_ok());

        // Re-update not allowed
        assert!(meta_store
            .update(&request_id, Ok("NOK".to_string()))
            .is_err());
    }

    #[test]
    fn test_kickout_of_errors() {
        let mut meta_store: MetaStore<String> = MetaStore::new(2, 1);
        let request_id_1: RequestId = RequestId::derive("1").unwrap();
        let request_id_2: RequestId = RequestId::derive("2").unwrap();
        let request_id_3: RequestId = RequestId::derive("3").unwrap();
        meta_store.insert(&request_id_1).unwrap();
        assert!(meta_store
            .update(&request_id_1, Err("Err1".to_string()))
            .is_ok());
        meta_store.insert(&request_id_2).unwrap();
        assert!(meta_store
            .update(&request_id_2, Ok("OK2".to_string()))
            .is_ok());
        // The storage is full so we should kick the oldest element out
        meta_store.insert(&request_id_3).unwrap();
        assert!(meta_store
            .update(&request_id_3, Err("Err3".to_string()))
            .is_ok());

        // Validate the oldest element is removed
        assert!(!meta_store.exists(&request_id_1));
        // Validate the two newer elements are still there
        assert!(meta_store.exists(&request_id_2));
        assert!(meta_store.exists(&request_id_3));
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
        let req_1: RequestId = RequestId::derive("1").unwrap();
        meta_store.insert(&req_1).unwrap();
        let meta_store = Arc::new(RwLock::new(meta_store));

        let cloned_meta_store = Arc::clone(&meta_store);
        let cloned_req_1 = req_1.clone();
        let handle = tokio::spawn(async move {
            let meta_store = Arc::clone(&cloned_meta_store);
            let handle = meta_store.read().await.retrieve(&cloned_req_1);
            handle_res_mapping(handle, &cloned_req_1, "test").await
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

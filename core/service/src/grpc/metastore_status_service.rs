//! gRPC service implementation for monitoring and querying the status of meta-stores in the KMS.
//!
//! This module provides the [MetaStoreStatusService](MetaStoreStatusService) implementation which allows
//! querying the status of various meta-stores used in the KMS, including:
//! - Key Generation Store
//! - Public Decryption Store
//! - User Decryption Store
//! - CRS Generation Store
//! - Preprocessing Store
//!
//! The service provides three main RPC endpoints:
//! 1. `GetRequestStatuses` - Get status of specific request IDs
//! 2. `ListRequests` - List requests with filtering and pagination
//! 3. `GetMetaStoreInfo` - Get meta-store capacity and current counts

use std::{str::FromStr, sync::Arc};
use tokio::sync::RwLock;

use crate::{
    backup::custodian::InternalCustodianContext,
    engine::{
        base::{CrsGenCallValues, KeyGenMetadata, PubDecCallValues, UserDecryptCallValues},
        threshold::service::BucketMetaStore,
    },
    util::meta_store::MetaStore,
};
use kms_grpc::{
    kms::v1::Empty,
    metastore_status::v1::{
        meta_store_status_service_server::MetaStoreStatusService, GetMetaStoreInfoResponse,
        GetRequestStatusesRequest, GetRequestStatusesResponse, ListRequestsRequest,
        ListRequestsResponse, MetaStoreInfo, MetaStoreType, RequestProcessingStatus,
        RequestStatusInfo,
    },
};

// Type aliases for the different MetaStore types used in the system

/// MetaStore for Key Generation data, mapping request IDs to public data handles
pub type KeyGenMetaStore = MetaStore<KeyGenMetadata>;

/// MetaStore for Public Decryption data, storing (ciphertext, plaintext, signature) tuples
pub type PubDecMetaStore = MetaStore<PubDecCallValues>;

/// MetaStore for User Decryption responses, storing response payloads with signatures
pub type UserDecryptMetaStore = MetaStore<UserDecryptCallValues>;

/// MetaStore for CRS (Common Reference String) data
pub type CrsMetaStore = MetaStore<CrsGenCallValues>;

/// MetaStore for preprocessing data, wrapping the bucket store in an Arc<Mutex<>>
pub type PreprocMetaStore = MetaStore<BucketMetaStore>;

/// MetaStore for custodian context data, storing setup messages needed for backup operations.
pub type CustodianMetaStore = MetaStore<InternalCustodianContext>;

/// Implementation of the MetaStoreStatusService gRPC service.
///
/// This service provides monitoring and status information about various meta-stores
/// used in the KMS. It allows querying request statuses, listing active requests with
/// filtering, and retrieving store capacity information.
///
/// The service is thread-safe and can be shared across multiple gRPC connections.
pub struct MetaStoreStatusServiceImpl {
    /// Store for key generation metadata
    pub key_gen_store: Option<Arc<RwLock<KeyGenMetaStore>>>,
    /// Store for public decryption data
    pub pub_dec_store: Option<Arc<RwLock<PubDecMetaStore>>>,
    /// Store for user decryption responses
    pub user_dec_store: Option<Arc<RwLock<UserDecryptMetaStore>>>,
    /// Store for CRS (Common Reference String) data
    pub crs_store: Option<Arc<RwLock<CrsMetaStore>>>,
    /// Store for preprocessing data buckets
    pub preproc_store: Option<Arc<RwLock<PreprocMetaStore>>>,
    /// Store for custodian context data used for backup
    pub custodian_context_store: Option<Arc<RwLock<CustodianMetaStore>>>,
}

impl MetaStoreStatusServiceImpl {
    /// Creates a new MetaStoreStatusServiceImpl with the provided meta-stores.
    ///
    /// # Arguments
    /// * `key_gen_store` - Optional reference to the key generation meta-store
    /// * `pub_dec_store` - Optional reference to the public decryption meta-store
    /// * `user_dec_store` - Optional reference to the user decryption meta-store
    /// * `crs_store` - Optional reference to the CRS generation meta-store
    /// * `preproc_store` - Optional reference to the preprocessing meta-store
    ///
    /// # Returns
    /// A new instance of MetaStoreStatusServiceImpl
    pub fn new(
        key_gen_store: Option<Arc<RwLock<KeyGenMetaStore>>>,
        pub_dec_store: Option<Arc<RwLock<PubDecMetaStore>>>,
        user_dec_store: Option<Arc<RwLock<UserDecryptMetaStore>>>,
        crs_store: Option<Arc<RwLock<CrsMetaStore>>>,
        preproc_store: Option<Arc<RwLock<PreprocMetaStore>>>,
        custodian_context_store: Option<Arc<RwLock<CustodianMetaStore>>>,
    ) -> Self {
        Self {
            key_gen_store,
            pub_dec_store,
            user_dec_store,
            crs_store,
            preproc_store,
            custodian_context_store,
        }
    }

    /// Compile-time exhaustiveness check - ensures all MetaStoreType variants are handled.
    /// Adding a new MetaStoreType will cause a compile error here, forcing updates.
    #[allow(dead_code)]
    const fn ensure_all_store_types_handled() {
        match MetaStoreType::KeyGeneration {
            MetaStoreType::KeyGeneration => {}
            MetaStoreType::PublicDecryption => {}
            MetaStoreType::UserDecryption => {}
            MetaStoreType::CrsGeneration => {}
            MetaStoreType::Preprocessing => {}
            MetaStoreType::All => {}
        }
    }

    /// Retrieves the status of specific requests from a meta-store.
    ///
    /// # Arguments
    /// * `store` - The meta-store to query
    /// * `store_type` - The type of meta-store being queried
    /// * `request_ids` - List of request IDs to get status for
    ///
    /// # Returns
    /// A vector of `RequestStatusInfo` for the found requests
    ///
    /// # Errors
    /// Returns `tonic::Status` with appropriate error code if:
    /// - A request ID was not found in the store
    /// - There was an error accessing the store
    async fn get_store_status<T: Clone>(
        store: &Arc<RwLock<MetaStore<T>>>,
        store_type: MetaStoreType,
        request_ids: &[String],
    ) -> Result<Vec<RequestStatusInfo>, tonic::Status> {
        // Pre-parse request IDs without holding lock
        // Separates original IDs (client strings) from internal IDs (validated types) for type safety and performance
        let parsed_ids: Vec<_> = request_ids
            .iter()
            .filter_map(|id| match kms_grpc::RequestId::from_str(id) {
                Ok(parsed) => Some((id.clone(), parsed)),
                Err(e) => {
                    tracing::warn!(
                        "Invalid request ID format '{}': {} - store type: {:?}",
                        id,
                        e,
                        store_type
                    );
                    None
                }
            })
            .collect();

        // Batch collect all required data while holding lock
        let request_data = {
            let store_guard = store.read().await;
            let mut data = Vec::new();

            for (original_id, internal_id) in &parsed_ids {
                tracing::debug!(
                    "Looking up request {} in {:?} store",
                    internal_id,
                    store_type
                );

                let cell_data = store_guard.get_cell(internal_id).map(|cell| cell.try_get());

                data.push((original_id.clone(), *internal_id, cell_data));
            }

            data
        }; // Lock released here - minimal hold time achieved

        // Process results without holding lock (expensive operations)
        let mut statuses = Vec::new();
        for (original_id, internal_id, cell_data) in request_data {
            let (status, error_message) = match cell_data {
                Some(Some(Ok(_))) => {
                    tracing::debug!(
                        "Request {} in {:?} store has COMPLETED status",
                        internal_id,
                        store_type
                    );
                    (RequestProcessingStatus::Completed, None)
                }
                Some(Some(Err(err))) => {
                    tracing::debug!(
                        "Request {} in {:?} store has FAILED status: {}",
                        internal_id,
                        store_type,
                        err
                    );
                    (RequestProcessingStatus::Failed, Some(err.clone()))
                }
                Some(None) => {
                    tracing::debug!(
                        "Request {} in {:?} store has PROCESSING status",
                        internal_id,
                        store_type
                    );
                    (RequestProcessingStatus::Processing, None)
                }
                None => {
                    tracing::debug!(
                        "Request {} not found in {:?} store",
                        internal_id,
                        store_type
                    );
                    // Continue to search other stores
                    continue;
                }
            };

            statuses.push(RequestStatusInfo {
                request_id: original_id,
                meta_store_type: store_type as i32,
                status: status as i32,
                error_message,
            });
        }

        tracing::debug!(
            "Found {} statuses in {:?} store for {} request IDs",
            statuses.len(),
            store_type,
            request_ids.len()
        );

        // Always return Ok, even if no statuses found - this allows searching across multiple stores
        Ok(statuses)
    }

    /// Lists requests from a meta-store with optional filtering and pagination.
    ///
    /// # Arguments
    /// * `store` - The meta-store to query
    /// * `store_type` - The type of meta-store being queried
    /// * `status_filter` - Optional filter to only include requests with specific status
    /// * `max_results` - Maximum number of results to return (pagination)
    /// * `page_token` - Token for pagination, obtained from previous response
    ///
    /// # Returns
    /// A tuple containing:
    /// 1. Vector of `RequestStatusInfo` for matching requests
    /// 2. Optional next page token if more results are available
    ///
    /// # Errors
    /// Returns `tonic::Status` with appropriate error code if:
    /// - The page token is invalid
    /// - The store is not available
    async fn list_store_requests<T: Clone>(
        store: &Arc<RwLock<MetaStore<T>>>,
        store_type: MetaStoreType,
        status_filter: Option<RequestProcessingStatus>,
        max_results: Option<i32>,
        page_token: Option<String>,
    ) -> Result<(Vec<RequestStatusInfo>, Option<String>), tonic::Status> {
        let store_guard = store.read().await;

        let request_ids = match status_filter {
            Some(RequestProcessingStatus::Processing) => store_guard.get_processing_request_ids(),
            Some(RequestProcessingStatus::Completed) => store_guard.get_completed_request_ids(),
            Some(RequestProcessingStatus::Failed) => store_guard.get_failed_request_ids(),
            Some(RequestProcessingStatus::Any) | None => store_guard.get_all_request_ids(),
        };

        // Handle pagination
        let start_index = if let Some(token) = page_token {
            match token.parse::<usize>() {
                Ok(index) => {
                    tracing::debug!(
                        "Successfully parsed page token '{}' to index {}",
                        token,
                        index
                    );
                    index
                }
                Err(err) => {
                    tracing::warn!(
                        "Failed to parse page token '{}' as usize: {} - defaulting to 0",
                        token,
                        err
                    );
                    0
                }
            }
        } else {
            tracing::debug!("No page token provided - starting from index 0");
            0
        };

        let max_results = max_results.unwrap_or(100) as usize; // Kept small for early store_guard lock release
        let end_index = std::cmp::min(start_index + max_results, request_ids.len());

        // Monitor pagination bounds
        tracing::debug!(
            "Pagination for {:?} store: total_requests={}, start_index={}, end_index={}, max_results={}",
            store_type, request_ids.len(), start_index, end_index, max_results
        );

        let paginated_ids = if start_index < request_ids.len() {
            &request_ids[start_index..end_index]
        } else {
            // Edge case: pagination goes beyond available data
            tracing::warn!(
                "Pagination start_index ({}) >= total requests ({}) for {:?} store - returning empty slice",
                start_index, request_ids.len(), store_type
            );
            &[]
        };

        // Batch collect all request data while holding lock once
        let mut request_data = Vec::new();
        for request_id in paginated_ids {
            if let Some(cell) = store_guard.retrieve(request_id) {
                let status_result = cell.try_get();
                request_data.push((*request_id, Some(status_result)));
            } else {
                request_data.push((*request_id, None));
            }
        }
        drop(store_guard); // Explicitly release the read lock

        // Convert to RequestStatusInfo with enhanced status detection (without holding lock)
        let mut requests = Vec::new();
        let total_request_count = request_ids.len();
        for (request_id, cell_data) in request_data {
            let (status, error_message) = match cell_data {
                Some(Some(Ok(_))) => {
                    tracing::debug!(
                        "Request {} in {:?} store has COMPLETED status",
                        request_id,
                        store_type
                    );
                    (RequestProcessingStatus::Completed, None)
                }
                Some(Some(Err(err))) => {
                    tracing::debug!(
                        "Request {} in {:?} store has FAILED status: {}",
                        request_id,
                        store_type,
                        err
                    );
                    (RequestProcessingStatus::Failed, Some(err))
                }
                Some(None) => {
                    tracing::debug!(
                        "Request {} in {:?} store has PROCESSING status",
                        request_id,
                        store_type
                    );
                    (RequestProcessingStatus::Processing, None)
                }
                None => {
                    // INVARIANT VIOLATION: Request ID from store's own collection is not retrievable
                    // This indicates data corruption or race condition
                    tracing::error!(
                        "INVARIANT VIOLATION: Request {} found in {:?} store ID list but not retrievable - data corruption detected",
                        request_id,
                        store_type
                    );
                    // Mark as FAILED since this represents a system error
                    (
                        RequestProcessingStatus::Failed,
                        Some("Internal error: Request data corrupted".to_string()),
                    )
                }
            };

            requests.push(RequestStatusInfo {
                request_id: request_id.to_string(),
                meta_store_type: store_type as i32,
                status: status as i32,
                error_message,
            });
        }

        // Log summary for debugging
        tracing::debug!(
            "Listed {} requests from {:?} store (total available: {})",
            requests.len(),
            store_type,
            total_request_count
        );

        // Determine next page token
        let next_page_token = if end_index < total_request_count {
            Some(end_index.to_string())
        } else {
            None
        };

        Ok((requests, next_page_token))
    }

    /// Retrieves information about a meta-store's capacity and current state.
    ///
    /// # Arguments
    /// * `store` - The meta-store to get information about
    /// * `store_type` - The type of meta-store being queried
    ///
    /// # Returns
    /// A `MetaStoreInfo` containing the store's type, capacity, and current item count
    async fn get_store_info<T: Clone>(
        store: &Arc<RwLock<MetaStore<T>>>,
        store_type: MetaStoreType,
    ) -> MetaStoreInfo {
        let store_guard = store.read().await;

        MetaStoreInfo {
            r#type: store_type as i32,
            capacity: store_guard.get_capacity() as i32,
            current_count: store_guard.get_current_count() as i32,
        }
    }
}

#[tonic::async_trait]
/// Implementation of the gRPC MetaStoreStatusService trait.
///
/// This trait provides the actual gRPC endpoint implementations that are called
/// by clients. Each method handles the request/response serialization and
/// delegates to the appropriate helper methods.
impl MetaStoreStatusService for MetaStoreStatusServiceImpl {
    /// Get the status of specific request IDs across meta-stores.
    ///
    /// This RPC allows querying the status of one or more requests by their IDs.
    /// It can be filtered by meta-store type, and will return the current status
    /// (processing/completed/failed) for each request.
    ///
    /// # Arguments
    /// * `request` - The gRPC request containing the request IDs to look up
    ///
    /// # Returns
    /// A response containing the status of each requested ID
    ///
    /// # Errors
    /// Returns `tonic::Status` with appropriate error code if:
    /// - No request IDs were provided
    /// - A requested ID was not found
    /// - The specified meta-store is not available
    async fn get_request_statuses(
        &self,
        request: tonic::Request<GetRequestStatusesRequest>,
    ) -> Result<tonic::Response<GetRequestStatusesResponse>, tonic::Status> {
        let req = request.into_inner();
        let mut all_statuses = Vec::new();

        let store_type_filter = req
            .meta_store_type
            .and_then(|t| MetaStoreType::try_from(t).ok());

        // Compile-time safety check
        Self::ensure_all_store_types_handled();

        macro_rules! query_store {
            ($store:expr, $store_type:expr) => {
                if let Some(store) = &$store {
                    if store_type_filter.is_none()
                        || store_type_filter == Some($store_type)
                        || store_type_filter == Some(MetaStoreType::All)
                    {
                        let statuses =
                            Self::get_store_status(store, $store_type, &req.request_ids).await?;
                        all_statuses.extend(statuses);
                    }
                }
            };
        }

        query_store!(self.key_gen_store, MetaStoreType::KeyGeneration);
        query_store!(self.pub_dec_store, MetaStoreType::PublicDecryption);
        query_store!(self.user_dec_store, MetaStoreType::UserDecryption);
        query_store!(self.crs_store, MetaStoreType::CrsGeneration);
        query_store!(self.preproc_store, MetaStoreType::Preprocessing);

        // If no statuses were found across all stores, return an appropriate error
        if all_statuses.is_empty() && !req.request_ids.is_empty() {
            let store_types_searched = if let Some(filter) = store_type_filter {
                format!("{filter:?}")
            } else {
                "all".to_string()
            };

            tracing::warn!(
                "No requests found across {} stores for {} request IDs",
                store_types_searched,
                req.request_ids.len()
            );

            return Err(tonic::Status::not_found(format!(
                "No requests found in {store_types_searched} meta-stores"
            )));
        }

        Ok(tonic::Response::new(GetRequestStatusesResponse {
            statuses: all_statuses,
        }))
    }

    /// List requests with optional filtering and pagination.
    ///
    /// This RPC allows listing requests from a specific meta-store with various
    /// filtering options. It supports pagination for handling large result sets.
    ///
    /// # Arguments
    /// * `request` - The gRPC request containing filter and pagination parameters
    ///
    /// # Returns
    /// A paginated response containing matching requests and a token for the next page
    ///
    /// # Errors
    /// Returns `tonic::Status` with appropriate error code if:
    /// - The specified meta-store type is invalid
    /// - The requested meta-store is not available
    /// - The page token is invalid
    async fn list_requests(
        &self,
        request: tonic::Request<ListRequestsRequest>,
    ) -> Result<tonic::Response<ListRequestsResponse>, tonic::Status> {
        let req = request.into_inner();
        let store_type = MetaStoreType::try_from(req.meta_store_type)
            .map_err(|_| tonic::Status::invalid_argument("Invalid meta store type"))?;

        let status_filter = req
            .status_filter
            .and_then(|s| RequestProcessingStatus::try_from(s).ok());

        macro_rules! list_from_store {
            ($store:expr, $store_type:expr, $error_msg:expr) => {
                if let Some(store) = $store {
                    Self::list_store_requests(
                        store,
                        $store_type,
                        status_filter,
                        req.max_results,
                        req.page_token,
                    )
                    .await?
                } else {
                    return Err(tonic::Status::unavailable($error_msg));
                }
            };
        }

        let (requests, next_page_token) = match store_type {
            MetaStoreType::KeyGeneration => {
                list_from_store!(
                    &self.key_gen_store,
                    MetaStoreType::KeyGeneration,
                    "Key generation store not available"
                )
            }
            MetaStoreType::PublicDecryption => {
                list_from_store!(
                    &self.pub_dec_store,
                    MetaStoreType::PublicDecryption,
                    "Public decryption store not available"
                )
            }
            MetaStoreType::UserDecryption => {
                list_from_store!(
                    &self.user_dec_store,
                    MetaStoreType::UserDecryption,
                    "User decryption store not available"
                )
            }
            MetaStoreType::CrsGeneration => {
                list_from_store!(
                    &self.crs_store,
                    MetaStoreType::CrsGeneration,
                    "CRS generation store not available"
                )
            }
            MetaStoreType::Preprocessing => {
                list_from_store!(
                    &self.preproc_store,
                    MetaStoreType::Preprocessing,
                    "Preprocessing store not available"
                )
            }
            MetaStoreType::All => {
                return Err(tonic::Status::invalid_argument(
                    "Use specific store type for listing",
                ));
            }
        };

        Ok(tonic::Response::new(ListRequestsResponse {
            requests,
            next_page_token,
        }))
    }

    /// Get information about all meta-stores.
    ///
    /// This RPC returns capacity and current usage information for all
    /// available meta-stores in the system.
    ///
    /// # Arguments
    /// * `_request` - Empty request (no parameters needed)
    ///
    /// # Returns
    /// A response containing information about all meta-stores
    ///
    /// # Errors
    /// Returns `tonic::Status` with appropriate error code if:
    /// - There was an error collecting store information
    async fn get_meta_store_info(
        &self,
        _request: tonic::Request<Empty>,
    ) -> Result<tonic::Response<GetMetaStoreInfoResponse>, tonic::Status> {
        let mut meta_stores = Vec::new();

        // Compile-time safety check
        Self::ensure_all_store_types_handled();

        macro_rules! add_store_info {
            ($store:expr, $store_type:expr) => {
                if let Some(store) = &$store {
                    meta_stores.push(Self::get_store_info(store, $store_type).await);
                }
            };
        }

        add_store_info!(self.key_gen_store, MetaStoreType::KeyGeneration);
        add_store_info!(self.pub_dec_store, MetaStoreType::PublicDecryption);
        add_store_info!(self.user_dec_store, MetaStoreType::UserDecryption);
        add_store_info!(self.crs_store, MetaStoreType::CrsGeneration);
        add_store_info!(self.preproc_store, MetaStoreType::Preprocessing);
        Ok(tonic::Response::new(GetMetaStoreInfoResponse {
            meta_stores,
        }))
    }
}

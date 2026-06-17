use crate::grpc::metastore_status_service::MetaStoreStatusServiceImpl;
use crate::grpc::tests::test_helpers::*;
use kms_grpc::RequestId;
use kms_grpc::kms::v1::Empty;
use kms_grpc::metastore_status::v1::meta_store_status_service_server::MetaStoreStatusService;
use kms_grpc::metastore_status::v1::{ListRequestsRequest, MetaStoreType};
use std::str::FromStr;

/// Build a test service whose key-generation store holds `n` distinct request ids, so
/// pagination edge cases can be exercised against a non-empty store.
async fn populated_key_gen_service(n: usize) -> MetaStoreStatusServiceImpl {
    let service = create_test_service();
    {
        let store = service.key_gen_store.as_ref().unwrap();
        let mut guard = store.write().await;
        for i in 0..n {
            let rid = RequestId::from_str(&format!("{:064x}", i + 1)).unwrap();
            guard.insert(&rid).unwrap();
        }
    }
    service
}

#[tokio::test]
async fn test_list_requests_with_real_stores() {
    let service = create_test_service();

    let request = tonic::Request::new(ListRequestsRequest {
        meta_store_type: MetaStoreType::KeyGeneration as i32,
        max_results: Some(10),
        page_token: Some(String::new()),
        status_filter: None,
    });

    let response = service.list_requests(request).await;
    assert!(response.is_ok());

    let response = response.unwrap().into_inner();
    assert_eq!(response.requests.len(), 0); // Empty store initially
    assert!(response.next_page_token.is_none() || response.next_page_token == Some(String::new()));
}

#[tokio::test]
async fn test_list_requests_with_unavailable_stores() {
    let service = create_unavailable_service();

    let request = tonic::Request::new(ListRequestsRequest {
        meta_store_type: MetaStoreType::KeyGeneration as i32,
        max_results: Some(10),
        page_token: Some(String::new()),
        status_filter: None,
    });

    let response = service.list_requests(request).await;
    assert!(response.is_err());

    let status = response.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unavailable);
    assert!(
        status
            .message()
            .contains("Key generation store not available")
    );
}

#[tokio::test]
async fn test_list_requests_invalid_store_type() {
    let service = create_test_service();

    let request = tonic::Request::new(ListRequestsRequest {
        meta_store_type: 999, // Invalid store type
        max_results: Some(10),
        page_token: Some(String::new()),
        status_filter: None,
    });

    let response = service.list_requests(request).await;
    assert!(response.is_err());

    let status = response.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    let message = status.message();
    assert!(message.contains("Invalid") || message.contains("Unknown") || message.contains("999"));
    assert!(message.contains("Invalid meta store type"));
}

#[tokio::test]
async fn test_list_requests_pagination() {
    let service = create_test_service();

    let request = tonic::Request::new(ListRequestsRequest {
        meta_store_type: MetaStoreType::KeyGeneration as i32,
        max_results: Some(5),
        page_token: Some(String::new()),
        status_filter: None,
    });

    let response = service.list_requests(request).await;
    assert!(response.is_ok());

    let response = response.unwrap().into_inner();
    assert!(response.requests.len() <= 5); // Respects page size
}

#[tokio::test]
async fn test_list_requests_negative_max_results_does_not_panic() {
    // Regression: a negative max_results cast to ~usize::MAX and, with an in-range page
    // token, wrapped `start_index + max_results` to produce an inverted slice range that
    // panicked the handler task in release builds (no overflow-checks).
    let service = populated_key_gen_service(10).await;

    let request = tonic::Request::new(ListRequestsRequest {
        meta_store_type: MetaStoreType::KeyGeneration as i32,
        max_results: Some(-1),
        page_token: Some("5".to_string()),
        status_filter: None,
    });

    let response = service.list_requests(request).await;
    assert!(response.is_ok());
    // Negative is rejected, the default (100) applies, so entries from index 5 onward.
    assert_eq!(response.unwrap().into_inner().requests.len(), 5);
}

#[tokio::test]
async fn test_list_requests_zero_max_results_does_not_stall_pagination() {
    // Regression: max_results == 0 returned an empty page while still emitting a
    // next_page_token equal to start_index (non-advancing), so a token-following client
    // looped forever. It must now fall back to the default and advance.
    let service = populated_key_gen_service(10).await;

    let request = tonic::Request::new(ListRequestsRequest {
        meta_store_type: MetaStoreType::KeyGeneration as i32,
        max_results: Some(0),
        page_token: Some(String::new()),
        status_filter: None,
    });

    let response = service.list_requests(request).await;
    assert!(response.is_ok());
    let response = response.unwrap().into_inner();
    // Default (100) applies, so all 10 entries are returned and there is no next page.
    assert_eq!(response.requests.len(), 10);
    assert!(response.next_page_token.is_none());
}

#[tokio::test]
async fn test_list_requests_page_token_past_end_returns_empty() {
    // A page token beyond the end must yield an empty page, not an out-of-range slice panic.
    let service = populated_key_gen_service(10).await;

    let request = tonic::Request::new(ListRequestsRequest {
        meta_store_type: MetaStoreType::KeyGeneration as i32,
        max_results: Some(5),
        page_token: Some("999".to_string()),
        status_filter: None,
    });

    let response = service.list_requests(request).await;
    assert!(response.is_ok());
    assert_eq!(response.unwrap().into_inner().requests.len(), 0);
}

#[tokio::test]
async fn test_get_meta_store_info_with_real_stores() {
    let service = create_test_service();

    let request = tonic::Request::new(Empty {});

    let response = service.get_meta_store_info(request).await;
    assert!(response.is_ok());

    let response = response.unwrap().into_inner();
    assert_eq!(response.meta_stores.len(), 5); // All 5 store types

    // Check that all stores have correct capacity and min_cache
    for meta_store in response.meta_stores {
        assert_eq!(meta_store.capacity, 100);
        assert_eq!(meta_store.current_count, 0); // Empty stores initially
    }
}

#[tokio::test]
async fn test_get_meta_store_info_with_unavailable_stores() {
    let service = create_unavailable_service();

    let request = tonic::Request::new(Empty {});

    let response = service.get_meta_store_info(request).await;
    assert!(response.is_ok());

    let response = response.unwrap().into_inner();
    assert_eq!(response.meta_stores.len(), 0); // No stores available
}

#[tokio::test]
async fn test_service_with_mixed_store_availability() {
    let service = create_mixed_availability_service();

    let request = tonic::Request::new(Empty {});
    let response = service.get_meta_store_info(request).await;
    assert!(response.is_ok());

    let response = response.unwrap().into_inner();
    assert_eq!(response.meta_stores.len(), 3); // Only available stores

    // Check that returned stores have correct capacities
    let mut capacities: Vec<i32> = response.meta_stores.iter().map(|s| s.capacity).collect();
    capacities.sort();
    assert_eq!(capacities, vec![100, 200, 300]);
}

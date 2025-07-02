use crate::grpc::tests::test_helpers::*;
use kms_grpc::kms::v1::Empty;
use kms_grpc::metastore_status::v1::meta_store_status_service_server::MetaStoreStatusService;
use kms_grpc::metastore_status::v1::{ListRequestsRequest, MetaStoreType};

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
    assert!(status
        .message()
        .contains("Key generation store not available"));
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

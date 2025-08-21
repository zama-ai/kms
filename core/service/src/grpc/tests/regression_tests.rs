/// Regression tests to ensure RequestId structure consistency
///
/// These tests validate that the underlying RequestId type remains a [u8; 32] array
/// and that all conversion logic continues to work correctly. If RequestId changes
/// to a different type (e.g., u1024, String, etc.), these tests will fail.
use crate::grpc::tests::test_helpers::test_request_ids::*;
use kms_grpc::metastore_status::v1::{MetaStoreType, RequestProcessingStatus, RequestStatusInfo};
use kms_grpc::{IdentifierError, RequestId};
use std::str::FromStr;

#[test]
fn test_request_id_core_structure_and_api_consistency() {
    // This is the primary test - validates RequestId remains [u8; 32] and works with Status API

    let request_id = valid_request_id_1();

    // 1. Validate underlying structure is still [u8; 32]
    assert_eq!(std::mem::size_of::<RequestId>(), 32);
    let bytes: [u8; 32] = request_id.into_bytes();
    let reconstructed = RequestId::from_bytes(bytes);
    assert_eq!(request_id, reconstructed);

    // 2. Validate string conversion consistency (critical for Status API)
    let converted_back = request_id.to_string();
    assert_eq!(VALID_HEX_1, converted_back);
    let parsed_again = RequestId::from_str(&converted_back).expect("Should re-parse");
    assert_eq!(request_id, parsed_again);

    // 3. Validate protobuf conversion (Status API uses this)
    let proto_id: kms_grpc::kms::v1::RequestId = request_id.into();
    assert_eq!(proto_id.request_id, VALID_HEX_1);
    let from_proto = RequestId::try_from(proto_id).unwrap();
    assert_eq!(request_id, from_proto);

    // 4. Validate Status API response structure
    let status_info = RequestStatusInfo {
        request_id: VALID_HEX_1.to_string(), // API uses flat string representation
        meta_store_type: MetaStoreType::KeyGeneration as i32,
        status: RequestProcessingStatus::Completed as i32,
        error_message: None,
    };

    let parsed_from_response = RequestId::from_str(&status_info.request_id);
    assert!(
        parsed_from_response.is_ok(),
        "Should parse RequestId from API response"
    );
    assert_eq!(parsed_from_response.unwrap(), request_id);
}

#[test]
fn test_request_id_validation_and_error_handling() {
    // Validates that RequestId validation logic remains consistent for Status API

    // Test valid ID validation
    let valid_id = valid_request_id_1();
    assert!(
        valid_id.is_valid(),
        "Valid RequestId should pass validation"
    );

    // Test zero ID rejection (important for Status API)
    let zero_id = RequestId::zeros();
    assert!(!zero_id.is_valid(), "Zero RequestId should be invalid");

    // Test error cases that Status API must handle
    use crate::grpc::tests::test_helpers::test_error_cases::*;
    let error_cases = vec![
        (EMPTY_STRING, "empty string"),
        (TOO_SHORT, "too short"),
        (INVALID_HEX, "invalid hex"),
        (WRONG_LENGTH, "wrong length"),
    ];

    for (invalid_input, description) in error_cases {
        let result = RequestId::from_str(invalid_input);
        assert!(
            result.is_err(),
            "Should reject {description}: '{invalid_input}'"
        );
    }
}

#[test]
fn test_request_id_compile_time_interface_stability() {
    // Compile-time test - if RequestId changes interface, this won't compile

    let request_id = valid_request_id_1();

    // These operations must continue to work for Status API compatibility
    let _: Result<RequestId, IdentifierError> = RequestId::from_str(VALID_HEX_1);
    let _: String = request_id.to_string();
    let _: bool = request_id.is_valid();
    let _: [u8; 32] = request_id.into_bytes();
    let _: RequestId = RequestId::from_bytes([0u8; 32]);
    let _: &[u8; 32] = request_id.as_bytes();
    let _: RequestId = RequestId::zeros();

    // Status API protobuf conversions must work
    let _: kms_grpc::kms::v1::RequestId = request_id.into();
    let proto = kms_grpc::kms::v1::RequestId {
        request_id: VALID_HEX_1.to_string(),
    };
    let _: RequestId = RequestId::try_from(proto).unwrap();

    // Byte slice operations for internal use
    let slice_ref: &[u8] = request_id.as_ref();
    assert_eq!(slice_ref.len(), 32);
    let _: Result<RequestId, IdentifierError> = RequestId::try_from(slice_ref);

    // If RequestId becomes u1024 or another type, these lines will fail to compile
}

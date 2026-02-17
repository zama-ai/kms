// Constants for metric operation names to ensure consistency and prevent typos
// These match the gRPC method names for better correlation.
// Counters are incremented for each operation, and also used for error tracking.

// Preprocessing and generation related operations
pub const OP_KEYGEN_REQUEST: &str = "keygen_request";
pub const OP_KEYGEN_RESULT: &str = "keygen_result";
pub const OP_INSECURE_KEYGEN_REQUEST: &str = "insecure_keygen_request";
pub const OP_INSECURE_KEYGEN_RESULT: &str = "insecure_keygen_result";
pub const OP_KEYGEN_PREPROC_REQUEST: &str = "keygen_preproc_request";
pub const OP_KEYGEN_PREPROC_RESULT: &str = "keygen_preproc_result";
// More specific metrics for key generation, only used with counters
pub const OP_INSECURE_STANDARD_KEYGEN: &str = "insecure_standard_keygen";
pub const OP_INSECURE_COMPRESSED_KEYGEN: &str = "insecure_compressed_keygen";
pub const OP_INSECURE_DECOMPRESSION_KEYGEN: &str = "insecure_decompression_keygen";
pub const OP_STANDARD_KEYGEN: &str = "standard_keygen";
pub const OP_DECOMPRESSION_KEYGEN: &str = "decompression_keygen";
// the compressed versions of the above
pub const OP_INSECURE_STANDARD_COMPRESSED_KEYGEN: &str = "insecure_standard_compressed_keygen";
pub const OP_STANDARD_COMPRESSED_KEYGEN: &str = "standard_compressed_keygen";
pub const OP_DECOMPRESSION_COMPRESSED_KEYGEN: &str = "decompression_compressed_keygen";

// Public/User decryption Operations
// Corresponds to a request, a request may contain several ciphertexts
pub const OP_PUBLIC_DECRYPT_REQUEST: &str = "public_decrypt_request";
pub const OP_PUBLIC_DECRYPT_RESULT: &str = "public_decrypt_result";
pub const OP_USER_DECRYPT_REQUEST: &str = "user_decrypt_request";
pub const OP_USER_DECRYPT_RESULT: &str = "user_decrypt_result";
// Inner variants of the OP
// Corresponds to a single ciphertext
pub const OP_PUBLIC_DECRYPT_INNER: &str = "public_decrypt_inner";
pub const OP_USER_DECRYPT_INNER: &str = "user_decrypt_inner";

// CRS Operations
pub const OP_CRS_GEN_REQUEST: &str = "crs_gen_request";
pub const OP_CRS_GEN_RESULT: &str = "crs_gen_result";
pub const OP_INSECURE_CRS_GEN_REQUEST: &str = "insecure_crs_gen_request";
pub const OP_INSECURE_CRS_GEN_RESULT: &str = "insecure_crs_gen_result";

// Context operations
pub const OP_NEW_MPC_CONTEXT: &str = "new_mpc_context";
pub const OP_DESTROY_MPC_CONTEXT: &str = "destroy_mpc_context";
pub const OP_NEW_CUSTODIAN_CONTEXT: &str = "new_custodian_context";
pub const OP_DESTROY_CUSTODIAN_CONTEXT: &str = "destroy_custodian_context";
pub const OP_CUSTODIAN_BACKUP_RECOVERY: &str = "custodian_backup_recovery";
pub const OP_CUSTODIAN_RECOVERY_INIT: &str = "custodian_recovery_init";
pub const OP_RESTORE_FROM_BACKUP: &str = "restore_from_backup";
pub const OP_KEY_MATERIAL_AVAILABILITY: &str = "key_material_availability";

// Epoch operations
pub const OP_NEW_EPOCH: &str = "new_mpc_epoch";
pub const OP_DESTROY_EPOCH: &str = "destroy_mpc_epoch";
pub const OP_GET_EPOCH_RESULT: &str = "get_mpc_epoch_result";

// PK fetch
pub const OP_FETCH_PK: &str = "fetch_pk";

// Common metric tag keys
pub const TAG_OPERATION: &str = "operation";
pub const TAG_ERROR: &str = "error";
pub const TAG_KEY_ID: &str = "key_id";
pub const TAG_CRS_ID: &str = "crs_id";
pub const TAG_CONTEXT_ID: &str = "context_id";
pub const TAG_EPOCH_ID: &str = "epoch_id";
pub const TAG_ALGORITHM: &str = "algorithm"; // TODO not used yet
pub const TAG_OPERATION_TYPE: &str = "operation_type"; // TODO not used yet
pub const TAG_PARTY_ID: &str = "party_id";
pub const TAG_TFHE_TYPE: &str = "tfhe_type";
pub const TAG_PUBLIC_DECRYPTION_KIND: &str = "public_decryption_mode";
pub const TAG_USER_DECRYPTION_KIND: &str = "user_decryption_mode";
// Special tag used for the central party
pub const CENTRAL_TAG: &str = "central";

// gRPC errors
pub const ERR_FAILED_PRECONDITION: &str = "failed_precondition";
pub const ERR_RESOURCE_EXHAUSTED: &str = "resource_exhausted";
pub const ERR_CANCELLED: &str = "cancelled";
pub const ERR_INVALID_ARGUMENT: &str = "invalid_argument";
pub const ERR_ABORTED: &str = "aborted";
pub const ERR_ALREADY_EXISTS: &str = "already_exists";
pub const ERR_NOT_FOUND: &str = "not_found";
pub const ERR_INTERNAL: &str = "internal_error";
pub const ERR_UNAVAILABLE: &str = "unavailable";
pub const ERR_OTHER: &str = "other";
/// Specific non-grpc error used to indicate that failure happened in an async task, after a request has been returned
pub const ERR_ASYNC: &str = "async_call_error";

// Common operation type values
pub const OP_TYPE_TOTAL: &str = "total";
pub const OP_TYPE_LOAD_CRS_PK: &str = "load_crs_pk";
pub const OP_TYPE_PROOF_VERIFICATION: &str = "proof_verification";
pub const OP_TYPE_CT_PROOF: &str = "ct_proof";

pub fn map_tonic_code_to_metric_err_tag(code: tonic::Code) -> &'static str {
    match code {
        tonic::Code::FailedPrecondition => ERR_FAILED_PRECONDITION,
        tonic::Code::ResourceExhausted => ERR_RESOURCE_EXHAUSTED,
        tonic::Code::Cancelled => ERR_CANCELLED,
        tonic::Code::InvalidArgument => ERR_INVALID_ARGUMENT,
        tonic::Code::Aborted => ERR_ABORTED,
        tonic::Code::AlreadyExists => ERR_ALREADY_EXISTS,
        tonic::Code::NotFound => ERR_NOT_FOUND,
        tonic::Code::Internal => ERR_INTERNAL,
        tonic::Code::Unavailable => ERR_UNAVAILABLE,
        code => {
            tracing::warn!("Unexcepted grpc error code: {code}. Counted as {ERR_OTHER}");
            ERR_OTHER
        }
    }
}

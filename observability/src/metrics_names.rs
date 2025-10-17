/// Constants for metric operation names to ensure consistency and prevent typos
/// These match the gRPC method names for better correlation
//
// Key Generation Operations
pub const OP_KEYGEN_REQUEST: &str = "keygen_request";
pub const OP_KEYGEN_RESULT: &str = "keygen_result";
pub const OP_INSECURE_KEYGEN_REQUEST: &str = "insecure_keygen_request";
pub const OP_INSECURE_KEYGEN_RESULT: &str = "insecure_keygen_result";
pub const OP_INSECURE_KEYGEN: &str = "insecure_keygen";
pub const OP_INSECURE_DECOMPRESSION_KEYGEN: &str = "insecure_decompression_keygen";
pub const OP_INSECURE_SNS_COMPRESSION_KEYGEN: &str = "insecure_sns_compression_keygen";
pub const OP_KEYGEN: &str = "keygen";
pub const OP_DECOMPRESSION_KEYGEN: &str = "decompression_keygen";
pub const OP_SNS_COMPRESSION_KEYGEN: &str = "sns_compression_keygen";
pub const OP_KEYGEN_PREPROC_REQUEST: &str = "keygen_preproc_request";
pub const OP_KEYGEN_PREPROC_RESULT: &str = "keygen_preproc_result";

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

// PRSS init
pub const OP_INIT: &str = "init";

// Context operations
pub const OP_NEW_KMS_CONTEXT: &str = "new_kms_context";
pub const OP_DESTROY_KMS_CONTEXT: &str = "destroy_kms_context";
pub const OP_NEW_CUSTODIAN_CONTEXT: &str = "new_custodian_context";
pub const OP_DESTROY_CUSTODIAN_CONTEXT: &str = "destroy_custodian_context";
pub const OP_CUSTODIAN_BACKUP_RECOVERY: &str = "custodian_backup_recovery";
pub const OP_CUSTODIAN_RECOVERY_INIT: &str = "custodian_recovery_init";
pub const OP_RESTORE_FROM_BACKUP: &str = "restore_from_backup";

// PK fetch
pub const OP_FETCH_PK: &str = "fetch_pk";

// Common metric tag keys
pub const TAG_OPERATION: &str = "operation";
pub const TAG_ERROR: &str = "error";
pub const TAG_KEY_ID: &str = "key_id";
pub const TAG_ALGORITHM: &str = "algorithm";
pub const TAG_OPERATION_TYPE: &str = "operation_type";
pub const TAG_PARTY_ID: &str = "party_id";
pub const TAG_REQUEST_ID: &str = "request_id";
pub const TAG_TFHE_TYPE: &str = "tfhe_type";
pub const TAG_PUBLIC_DECRYPTION_KIND: &str = "public_decryption_mode";

// Common error values
pub const ERR_RATE_LIMIT_EXCEEDED: &str = "rate_limit_exceeded";
pub const ERR_KEY_EXISTS: &str = "key_already_exists";
pub const ERR_KEY_NOT_FOUND: &str = "key_not_found";
pub const ERR_PUBLIC_DECRYPTION_FAILED: &str = "public_decryption_failed";
pub const ERR_USER_DECRYPTION_FAILED: &str = "user_decryption_failed";
pub const ERR_USER_PREPROC_FAILED: &str = "preproc_failed";
pub const ERR_PREPROC_NOT_FOUND: &str = "preproc_not_found";
pub const ERR_KEYGEN_FAILED: &str = "keygen_failed";
pub const ERR_VERIFICATION_FAILED: &str = "verification_failed";
pub const ERR_CRS_GEN_FAILED: &str = "crs_gen_failed";
pub const ERR_WITH_META_STORAGE: &str = "meta_storage_error";
pub const ERR_INVALID_REQUEST: &str = "invalid_request";
pub const ERR_CANCELLED: &str = "cancelled";
pub const ERR_INVALID_ARGUMENT: &str = "invalid_argument";
pub const ERR_ABORTED: &str = "aborted";
pub const ERR_ALREADY_EXISTS: &str = "already_exists";
pub const ERR_NOT_FOUND: &str = "not_found";
pub const ERR_INTERNAL: &str = "internal_error";
pub const ERR_UNAVAILABLE: &str = "unavailable";
pub const ERR_OTHER: &str = "other";

// Common operation type values
pub const OP_TYPE_TOTAL: &str = "total";
pub const OP_TYPE_LOAD_CRS_PK: &str = "load_crs_pk";
pub const OP_TYPE_PROOF_VERIFICATION: &str = "proof_verification";
pub const OP_TYPE_CT_PROOF: &str = "ct_proof";

pub fn map_tonic_code_to_metric_tag(code: tonic::Code) -> &'static str {
    match code {
        tonic::Code::InvalidArgument => ERR_INVALID_ARGUMENT,
        tonic::Code::NotFound => ERR_NOT_FOUND,
        tonic::Code::Internal => ERR_INTERNAL,
        tonic::Code::Unavailable => ERR_UNAVAILABLE,
        tonic::Code::Aborted => ERR_ABORTED,
        tonic::Code::AlreadyExists => ERR_ALREADY_EXISTS,
        _ => ERR_OTHER,
    }
}

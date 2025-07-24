/// Constants for metric operation names to ensure consistency and prevent typos
/// These match the gRPC method names for better correlation
//
// Key Generation Operations
pub const OP_INSECURE_KEYGEN: &str = "insecure_keygen";
pub const OP_INSECURE_DECOMPRESSION_KEYGEN: &str = "insecure_decompression_keygen";
pub const OP_INSECURE_SNS_COMPRESSION_KEYGEN: &str = "insecure_sns_compression_keygen";
pub const OP_KEYGEN: &str = "keygen";
pub const OP_DECOMPRESSION_KEYGEN: &str = "decompression_keygen";
pub const OP_SNS_COMPRESSION_KEYGEN: &str = "sns_compression_keygen";
pub const OP_KEYGEN_PREPROC: &str = "keygen_preproc";

// Public/User decryption Operations
// Corresponds to a request, a request may contain several ciphertexts
pub const OP_PUBLIC_DECRYPT_REQUEST: &str = "public_decrypt_request";
pub const OP_USER_DECRYPT_REQUEST: &str = "user_decrypt_request";
// Inner variants of the OP
// Corresponds to a single ciphertext
pub const OP_PUBLIC_DECRYPT_INNER: &str = "public_decrypt_inner";
pub const OP_USER_DECRYPT_INNER: &str = "user_decrypt_inner";

// CRS Operations
pub const OP_CRS_GEN: &str = "crs_gen";
pub const OP_INSECURE_CRS_GEN: &str = "insecure_crs_gen";

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
pub const ERR_VERIFICATION_FAILED: &str = "verification_failed";
pub const ERR_CRS_GEN_FAILED: &str = "crs_gen_failed";

// Common operation type values
pub const OP_TYPE_TOTAL: &str = "total";
pub const OP_TYPE_LOAD_CRS_PK: &str = "load_crs_pk";
pub const OP_TYPE_PROOF_VERIFICATION: &str = "proof_verification";
pub const OP_TYPE_CT_PROOF: &str = "ct_proof";

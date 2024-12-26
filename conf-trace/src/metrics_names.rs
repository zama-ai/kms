/// Constants for metric operation names to ensure consistency and prevent typos
/// These match the gRPC method names for better correlation
//
// Key Generation Operations
pub const OP_KEYGEN: &str = "keygen";
pub const OP_KEYGEN_PREPROC: &str = "keygen_preproc";

// Decryption/Reencryption Operations
pub const OP_DECRYPT: &str = "decrypt";
pub const OP_REENCRYPT: &str = "reencrypt";

// Verification Operations
pub const OP_VERIFY_PROVEN_CT: &str = "verify_proven_ct";

// CRS Operations
pub const OP_CRS_GEN: &str = "crs_gen";

// Common metric tag keys
pub const TAG_OPERATION: &str = "operation";
pub const TAG_ERROR: &str = "error";
pub const TAG_KEY_ID: &str = "key_id";
pub const TAG_ALGORITHM: &str = "algorithm";
pub const TAG_OPERATION_TYPE: &str = "operation_type";
pub const TAG_PARTY_ID: &str = "party_id";
pub const TAG_CIPHERTEXT_ID: &str = "ciphertext_id";
pub const TAG_REQUEST_ID: &str = "request_id";

// Common error values
pub const ERR_RATE_LIMIT_EXCEEDED: &str = "rate_limit_exceeded";
pub const ERR_KEY_EXISTS: &str = "key_already_exists";
pub const ERR_KEY_NOT_FOUND: &str = "key_not_found";
pub const ERR_DECRYPTION_FAILED: &str = "decryption_failed";
pub const ERR_REENCRYPTION_FAILED: &str = "reencryption_failed";
pub const ERR_VERIFICATION_FAILED: &str = "verification_failed";
pub const ERR_CRS_GEN_FAILED: &str = "crs_gen_failed";

// Common operation type values
pub const OP_TYPE_TOTAL: &str = "total";
pub const OP_TYPE_LOAD_CRS_PK: &str = "load_crs_pk";
pub const OP_TYPE_PROOF_VERIFICATION: &str = "proof_verification";
pub const OP_TYPE_CT_PROOF: &str = "ct_proof";

// Ciphertext seeds for consistent hashing results
pub const HASH_CIPHERTEXT_SEEDS: (u64, u64, u64, u64) = (12345, 67890, 54321, 98765);

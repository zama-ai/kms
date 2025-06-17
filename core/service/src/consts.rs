#[cfg(feature = "non-wasm")]
use crate::engine::base::derive_request_id;
#[cfg(feature = "non-wasm")]
use kms_grpc::RequestId;
use threshold_fhe::execution::tfhe_internals::parameters::{
    DKGParams, BC_PARAMS_SNS, PARAMS_TEST_BK_SNS,
};

// The amount of bytes in an ID (key handle, request ID etc.)
pub const ID_LENGTH: usize = kms_grpc::rpc_types::ID_LENGTH;
pub const KEY_PATH_PREFIX: &str = "keys";
pub const DEFAULT_PARAM: DKGParams = BC_PARAMS_SNS;
pub const TEST_PARAM: DKGParams = PARAMS_TEST_BK_SNS;

pub const SIG_SIZE: usize = 64; // a 32 byte r value and a 32 byte s value
pub const RND_SIZE: usize = 128 / 8; // the amount of bytes used for sampling random values to stop brute-forcing or statistical attacks

// TODO do we want to load this from a configuration?
pub const SEC_PAR: u64 = 128;
// TODO do we want to load this from a configuration?
// The maximum amount of public/user decryptions to be stored in RAM
pub const DEC_CAPACITY: usize = 10000;
// The minimum amount of completed public/user decryptions to cache before old ones are evicted and new ones are allowed, if the store has reached its max capacity
pub const MIN_DEC_CACHE: usize = 6000;
pub const COMPRESSED: bool = true;

pub const MINIMUM_SESSIONS_PREPROC: u16 = 2;

pub const PRSS_INIT_REQ_ID: &str =
    "0000000000000000000000000000000000000000000000000000000000000001";

pub const DEFAULT_AMOUNT_PARTIES: usize = 13;
pub const DEFAULT_THRESHOLD: usize = 4;

pub const SAFE_SER_SIZE_LIMIT: u64 = threshold_fhe::hashing::SAFE_SER_SIZE_LIMIT;

//TODO: Do we want to load this from configuration ?
pub const DURATION_WAITING_ON_RESULT_SECONDS: u64 = 60;

// Maximum number of attempts to try to wait for a result to be done on the server
pub const MAX_TRIES: usize = 50;

pub const DEFAULT_URL: &str = "127.0.0.1";
pub const DEFAULT_PROTOCOL: &str = "http";

#[cfg(feature = "non-wasm")]
cfg_if::cfg_if! {
    if #[cfg(any(test, feature = "testing"))] {
        pub const TMP_PATH_PREFIX: &str = "temp";
        pub const DEFAULT_CENTRAL_KEYS_PATH: &str = "temp/default-central-keys.bin";

        lazy_static::lazy_static! {
            pub static ref TEST_CENTRAL_KEY_ID: RequestId =
                derive_request_id("TEST_CENTRAL_KEY_ID").unwrap();
            pub static ref TEST_THRESHOLD_KEY_ID_4P: RequestId =
                derive_request_id("TEST_THRESHOLD_KEY_ID_4P").unwrap();
            pub static ref TEST_THRESHOLD_KEY_ID_10P: RequestId =
                derive_request_id("TEST_THRESHOLD_KEY_ID_10P").unwrap();
            pub static ref TEST_THRESHOLD_KEY_ID_13P: RequestId =
                derive_request_id("TEST_THRESHOLD_KEY_ID_13P").unwrap();
            pub static ref TEST_CENTRAL_CRS_ID: RequestId = derive_request_id("TEST_CENTRAL_CRS_ID").unwrap();
            pub static ref TEST_THRESHOLD_CRS_ID_4P: RequestId = derive_request_id("TEST_THRESHOLD_CRS_ID_4P").unwrap();
            pub static ref TEST_THRESHOLD_CRS_ID_10P: RequestId = derive_request_id("TEST_THRESHOLD_CRS_ID_10P").unwrap();
            pub static ref TEST_THRESHOLD_CRS_ID_13P: RequestId = derive_request_id("TEST_THRESHOLD_CRS_ID_13P").unwrap();
            pub static ref OTHER_CENTRAL_TEST_ID: RequestId = derive_request_id("OTHER_TEST_ID").unwrap();
            pub static ref DEFAULT_CENTRAL_KEY_ID: RequestId =
                derive_request_id("DEFAULT_CENTRAL_KEY_ID").unwrap();
            pub static ref DEFAULT_THRESHOLD_KEY_ID_4P: RequestId =
                derive_request_id("DEFAULT_THRESHOLD_KEY_ID_4P").unwrap();
            pub static ref DEFAULT_THRESHOLD_KEY_ID_10P: RequestId =
                derive_request_id("DEFAULT_THRESHOLD_KEY_ID_10P").unwrap();
            pub static ref DEFAULT_THRESHOLD_KEY_ID_13P: RequestId =
                derive_request_id("DEFAULT_THRESHOLD_KEY_ID_13P").unwrap();
            pub static ref DEFAULT_CENTRAL_CRS_ID: RequestId = derive_request_id("DEFAULT_CENTRAL_CRS_ID").unwrap();
            pub static ref DEFAULT_THRESHOLD_CRS_ID_4P: RequestId = derive_request_id("DEFAULT_THRESHOLD_CRS_ID_4P").unwrap();
            pub static ref DEFAULT_THRESHOLD_CRS_ID_10P: RequestId = derive_request_id("DEFAULT_THRESHOLD_CRS_ID_10P").unwrap();
            pub static ref DEFAULT_THRESHOLD_CRS_ID_13P: RequestId = derive_request_id("DEFAULT_THRESHOLD_CRS_ID_13P").unwrap();
            pub static ref DEFAULT_DEC_ID: RequestId = derive_request_id("DEFAULT_DEC_ID").unwrap();
            pub static ref OTHER_CENTRAL_DEFAULT_ID: RequestId =
                derive_request_id("OTHER_DEFAULT_ID").unwrap();

            // What we will use in a default deployment
            pub static ref TEST_THRESHOLD_KEY_ID: RequestId = *TEST_THRESHOLD_KEY_ID_13P;
            pub static ref TEST_THRESHOLD_CRS_ID: RequestId = *TEST_THRESHOLD_CRS_ID_13P;
            pub static ref DEFAULT_THRESHOLD_KEY_ID: RequestId = *DEFAULT_THRESHOLD_KEY_ID_13P;
            pub static ref DEFAULT_THRESHOLD_CRS_ID: RequestId = *DEFAULT_THRESHOLD_CRS_ID_13P;
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(test)] {
        // These ones should be removed or more to relevant positions in client or central kms
        pub const TEST_CENTRAL_KEYS_PATH: &str = "temp/test-central-keys.bin";
        pub const TEST_CENTRAL_WASM_TRANSCRIPT_PATH: &str = "temp/test-central-wasm-transcript.bin";
        pub const TEST_THRESHOLD_WASM_TRANSCRIPT_PATH: &str = "temp/test-threshold-wasm-transcript.bin";
        pub const DEFAULT_CENTRAL_WASM_TRANSCRIPT_PATH: &str = "temp/default-central-wasm-transcript.bin";
        pub const DEFAULT_THRESHOLD_WASM_TRANSCRIPT_PATH: &str = "temp/default-threshold-wasm-transcript.bin";

        pub const TEST_CENTRAL_WASM_TRANSCRIPT_LEGACY_PATH: &str = "temp/test-central-wasm-transcript-legacy.bin";
        pub const TEST_THRESHOLD_WASM_TRANSCRIPT_LEGACY_PATH: &str = "temp/test-threshold-wasm-transcript-legacy.bin";
        pub const DEFAULT_CENTRAL_WASM_TRANSCRIPT_LEGACY_PATH: &str = "temp/default-central-wasm-transcript-legacy.bin";
        pub const DEFAULT_THRESHOLD_WASM_TRANSCRIPT_LEGACY_PATH: &str = "temp/default-threshold-wasm-transcript-legacy.bin";

        pub const TEST_SEC_PAR: u64 = 40;
    }
}

#[cfg(feature = "non-wasm")]
lazy_static::lazy_static! {
    // The static ID we will use for the signing key for each of the MPC parties.
    // We do so, since there is ever only one conceptual signing key per party (at least for now).
    // This is a bit hackish, but it works for now.
    pub static ref SIGNING_KEY_ID: RequestId = derive_request_id("SIGNING_KEY_ID").unwrap();

    pub static ref DEFAULT_MPC_CONTEXT: RequestId = derive_request_id("DEFAULT_MPC_CONTEXT").unwrap();
}

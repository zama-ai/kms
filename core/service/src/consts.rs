// The amount of bytes in an ID (key handle, request ID etc.)
pub const ID_LENGTH: usize = 20;
pub const KEY_PATH_PREFIX: &str = "keys";
pub const DEFAULT_PARAM_PATH: &str = "parameters/default_params.json";
pub const TEST_PARAM_PATH: &str = "parameters/small_test_params.json";

#[cfg(test)]
pub const TMP_PATH_PREFIX: &str = "temp";
#[cfg(test)]
pub const DEFAULT_CENTRAL_KEYS_PATH: &str = "temp/default-central-keys.bin";

pub const SIG_SIZE: usize = 64; // a 32 byte r value and a 32 byte s value
pub const RND_SIZE: usize = 128 / 8; // the amount of bytes used for sampling random values to stop brute-forcing or statistical attacks

// TODO do we want to load this from a configuration?
pub const SEC_PAR: u64 = 128;
// TODO do we want to load this from a configuration?
// The maximum amount of decryptions/reencryptions to be stored in RAM
pub const DEC_CAPACITY: usize = 10000;
// The minimum amount of completed decryptions/reencryptions to cache before old ones are evicted and new ones are allowed, if the store has reached its max capacity
pub const MIN_DEC_CACHE: usize = 6000;
pub const COMPRESSED: bool = true;

pub const MINIMUM_SESSIONS_PREPROC: u16 = 2;

pub const PRSS_EPOCH_ID: u128 = 1;

cfg_if::cfg_if! {
    if #[cfg(any(test, feature = "testing"))] {
        use crate::kms::RequestId;
        use lazy_static::lazy_static;
        pub const AMOUNT_PARTIES: usize = 4;
        pub const THRESHOLD: usize = 1;
        pub const BASE_PORT: u16 = 50050;
        pub const DEFAULT_URL: &str = "127.0.0.1";
        pub const DEFAULT_PROT: &str = "http";

        lazy_static! {
            pub static ref TEST_CENTRAL_KEY_ID: RequestId =
                RequestId::derive("TEST_CENTRAL_KEY_ID").unwrap();
            pub static ref TEST_THRESHOLD_KEY_ID: RequestId =
                RequestId::derive("TEST_THRESHOLD_KEY_ID").unwrap();
            pub static ref TEST_CRS_ID: RequestId = RequestId::derive("TEST_CRS_ID").unwrap();
            pub static ref OTHER_CENTRAL_TEST_ID: RequestId = RequestId::derive("OTHER_TEST_ID").unwrap();
            pub static ref DEFAULT_CENTRAL_KEY_ID: RequestId =
                RequestId::derive("DEFAULT_CENTRAL_KEY_ID").unwrap();
            pub static ref DEFAULT_THRESHOLD_KEY_ID: RequestId =
                RequestId::derive("DEFAULT_THRESHOLD_KEY_ID").unwrap();
            pub static ref DEFAULT_CRS_ID: RequestId = RequestId::derive("DEFAULT_CRS_ID").unwrap();
            pub static ref DEFAULT_DEC_ID: RequestId = RequestId::derive("DEFAULT_DEC_ID").unwrap();
            pub static ref OTHER_CENTRAL_DEFAULT_ID: RequestId =
                RequestId::derive("OTHER_DEFAULT_ID").unwrap();
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

        pub const TEST_SEC_PAR: u64 = 40;
    }
}

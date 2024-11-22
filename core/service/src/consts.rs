use crate::kms::ParamChoice;
use crate::kms::RequestId;
use distributed_decryption::execution::tfhe_internals::parameters::{
    DKGParams, BC_PARAMS_SAM_SNS, PARAMS_TEST_BK_SNS,
};
use lazy_static::lazy_static;

// The amount of bytes in an ID (key handle, request ID etc.)
pub const ID_LENGTH: usize = 20;
pub const KEY_PATH_PREFIX: &str = "keys";
pub const DEFAULT_PARAM: DKGParams = BC_PARAMS_SAM_SNS;
pub const TEST_PARAM: DKGParams = PARAMS_TEST_BK_SNS;

impl From<ParamChoice> for DKGParams {
    fn from(value: ParamChoice) -> Self {
        match value {
            ParamChoice::Test => TEST_PARAM,
            ParamChoice::Default => DEFAULT_PARAM,
        }
    }
}

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

pub const DEFAULT_AMOUNT_PARTIES: usize = 4;
pub const DEFAULT_THRESHOLD: usize = 1;

pub const SAFE_SER_SIZE_LIMIT: u64 = 1024 * 1024 * 1024 * 2;

lazy_static! {
    // The static ID we will use for the signing key for each of the MPC parties.
    // We do so, since there is ever only one conceptual signing key per party (at least for now).
    // This is a bit hackish, but it works for now.
    pub static ref SIGNING_KEY_ID: RequestId = RequestId::derive("SIGNING_KEY_ID").unwrap();
}

cfg_if::cfg_if! {
    if #[cfg(any(test, feature = "testing"))] {
        pub const BASE_PORT: u16 = 50050;
        pub const DEFAULT_URL: &str = "127.0.0.1";
        pub const DEFAULT_PROT: &str = "http";
        pub const TMP_PATH_PREFIX: &str = "temp";
        pub const DEFAULT_CENTRAL_KEYS_PATH: &str = "temp/default-central-keys.bin";

        lazy_static! {
            pub static ref TEST_CENTRAL_KEY_ID: RequestId =
                RequestId::derive("TEST_CENTRAL_KEY_ID").unwrap();
            pub static ref TEST_THRESHOLD_KEY_ID_4P: RequestId =
                RequestId::derive("TEST_THRESHOLD_KEY_ID_4P").unwrap();
            // This key is currently used for testing with 10 threshold parties
            pub static ref TEST_THRESHOLD_KEY_ID_10P: RequestId =
                RequestId::derive("TEST_THRESHOLD_KEY_ID_10P").unwrap();
            pub static ref TEST_CENTRAL_CRS_ID: RequestId = RequestId::derive("TEST_CENTRAL_CRS_ID").unwrap();
            pub static ref TEST_THRESHOLD_CRS_ID_4P: RequestId = RequestId::derive("TEST_THRESHOLD_CRS_ID_4P").unwrap();
            // This crs is currently used for testing with 10 threshold parties
            pub static ref TEST_THRESHOLD_CRS_ID_10P: RequestId = RequestId::derive("TEST_THRESHOLD_CRS_ID_10P").unwrap();
            pub static ref OTHER_CENTRAL_TEST_ID: RequestId = RequestId::derive("OTHER_TEST_ID").unwrap();
            pub static ref DEFAULT_CENTRAL_KEY_ID: RequestId =
                RequestId::derive("DEFAULT_CENTRAL_KEY_ID").unwrap();
            pub static ref DEFAULT_THRESHOLD_KEY_ID_4P: RequestId =
                RequestId::derive("DEFAULT_THRESHOLD_KEY_ID_4P").unwrap();
            // This key is currently used for testing with 10 threshold parties
            pub static ref DEFAULT_THRESHOLD_KEY_ID_10P: RequestId =
                RequestId::derive("DEFAULT_THRESHOLD_KEY_ID_10P").unwrap();
            pub static ref DEFAULT_CENTRAL_CRS_ID: RequestId = RequestId::derive("DEFAULT_CENTRAL_CRS_ID").unwrap();
            pub static ref DEFAULT_THRESHOLD_CRS_ID_4P: RequestId = RequestId::derive("DEFAULT_THRESHOLD_CRS_ID_4P").unwrap();
            // This crs is currently used for testing with 10 threshold parties
            pub static ref DEFAULT_THRESHOLD_CRS_ID_10P: RequestId = RequestId::derive("DEFAULT_THRESHOLD_CRS_ID_10P").unwrap();
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

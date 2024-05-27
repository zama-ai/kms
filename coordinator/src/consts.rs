use crate::kms::{FheType, RequestId};
use lazy_static::lazy_static;

// The amount of bytes in an ID (key handle, request ID etc.)
pub const ID_LENGTH: usize = 20;

pub const KEY_PATH_PREFIX: &str = "keys";
pub const TMP_PATH_PREFIX: &str = "temp";

pub const DEFAULT_PARAM_PATH: &str = "parameters/default_params.json";

#[cfg(test)]
pub const DEFAULT_CENTRAL_KEYS_PATH: &str = "temp/default-central-keys.bin";

// TODO Test should be in a test module, however I have spend an hour trying to refactor this
// without success. Someone with good rust skills are very welcome to try this
pub const BASE_PORT: u16 = 50050;
pub const DEFAULT_URL: &str = "127.0.0.1";
pub const DEFAULT_PROT: &str = "http";
pub const DEFAULT_TIMEOUT: u64 = 60;
pub const TEST_MSG: u8 = 42;
pub const TEST_FHE_TYPE: FheType = FheType::Euint8;
pub const AMOUNT_PARTIES: usize = 4;
pub const THRESHOLD: usize = 1;
// TODO do we want to load this from a configuration?
pub const SEC_PAR: u64 = 128;
// TODO do we want to load this from a configuration?
// The maximum amount of decryptions/reencryptions to be stored in RAM
pub const DEC_CAPACITY: usize = 10000;
// The minimum amount of completed decryptions/reencryptions to cache before old ones are evicted and new ones are allowed, if the store has reached its max capacity
pub const MIN_DEC_CACHE: usize = 6000;
pub const COMPRESSED: bool = true;

pub const MINIMUM_SESSIONS_PREPROC: u16 = 2;

lazy_static! {
    pub static ref TEST_CENTRAL_KEY_ID: RequestId =
        RequestId::derive("TEST_CENTRAL_KEY_ID").unwrap();
    pub static ref TEST_THRESHOLD_KEY_ID: RequestId =
        RequestId::derive("TEST_THRESHOLD_KEY_ID").unwrap();
    pub static ref TEST_CRS_ID: RequestId = RequestId::derive("TEST_CRS_ID").unwrap();
    pub static ref TEST_DEC_ID: RequestId = RequestId::derive("TEST_DEC_ID").unwrap();
    pub static ref TEST_REENC_ID: RequestId = RequestId::derive("TEST_REENC_ID").unwrap();
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

pub const TEST_PARAM_PATH: &str = "parameters/small_test_params.json";
// These ones should be removed or more to relevant positions in client or central kms
pub const TEST_CENTRAL_KEYS_PATH: &str = "temp/test-central-keys.bin";
pub const TEST_CENTRAL_WASM_TRANSCRIPT_PATH: &str = "temp/test-central-wasm-transcript.bin";
pub const TEST_THRESHOLD_WASM_TRANSCRIPT_PATH: &str = "temp/test-threshold-wasm-transcript.bin";

pub const TEST_SEC_PAR: u64 = 40;

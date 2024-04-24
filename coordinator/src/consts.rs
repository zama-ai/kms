use crate::kms::FheType;

// The amount of bytes in an ID (key handle, request ID etc.)
pub const ID_LENGTH: usize = 20;

pub const KEY_PATH_PREFIX: &str = "keys";
pub const CRS_PATH_PREFIX: &str = "crs";
pub const TMP_PATH_PREFIX: &str = "temp";

pub const DEFAULT_PARAM_PATH: &str = "parameters/default_params.json";
pub const DEFAULT_THRESHOLD_KEYS_PATH: &str = "temp/default-threshold-keys";
pub const DEFAULT_THRESHOLD_CT_PATH: &str = "temp/default-threshold-ciphertext.bin";
pub const DEFAULT_CENTRAL_KEYS_PATH: &str = "temp/default-central-keys.bin";
pub const DEFAULT_CENTRAL_CRS_PATH: &str = "crs/default-crs-store.bin";
pub const DEFAULT_CENTRAL_MULTI_KEYS_PATH: &str = "temp/default-central-multi-keys.bin";
pub const DEFAULT_CENTRAL_CT_PATH: &str = "temp/default-central-ciphertext.bin";
pub const DEFAULT_CENTRAL_MULTI_CT_PATH: &str = "temp/default-central-multi-keys-ciphertext.bin";

// TODO Test should be in a test module, however I have spend an hour trying to refactor this
// without success. Someone with good rust skills are very welcome to try this
pub const BASE_PORT: u16 = 50050;
pub const DEFAULT_URL: &str = "127.0.0.1";
pub const DEFAULT_PROT: &str = "http";
pub const TEST_MSG: u8 = 42;
pub const TEST_FHE_TYPE: FheType = FheType::Euint8;
pub const AMOUNT_PARTIES: usize = 4;
pub const THRESHOLD: usize = 1;
// TODO do we want to load this from a configuration?
pub const SEC_PAR: u64 = 128;
pub const COMPRESSED: bool = true;

pub const MINIMUM_SESSIONS_PREPROC: u128 = 2;

pub const TEST_KEY_ID: &str = "keytest"; // TODO should be a valid request id
pub const TEST_CRS_ID: &str = "crstest";
pub const TEST_DEC_ID: &str = "dectest";
pub const TEST_PARAM_PATH: &str = "parameters/small_test_params.json";
pub const TEST_THRESHOLD_KEYS_PATH: &str = "temp/test-threshold-keys";
pub const TEST_THRESHOLD_CT_PATH: &str = "temp/test-threshold-ciphertext.bin";
pub const TEST_CENTRAL_KEYS_PATH: &str = "temp/test-central-keys.bin";
pub const TEST_CENTRAL_CRS_PATH: &str = "crs/test-crs-store.bin";
pub const TEST_CENTRAL_MULTI_KEYS_PATH: &str = "temp/test-central-multi-keys.bin";
pub const TEST_CENTRAL_CT_PATH: &str = "temp/test-central-ciphertext.bin";
pub const TEST_CENTRAL_MULTI_CT_PATH: &str = "temp/test-central-multi-keys-ciphertext.bin";
pub const TEST_CENTRAL_WASM_TRANSCRIPT_PATH: &str = "temp/test-central-wasm-transcript.bin";
pub const TEST_THRESHOLD_WASM_TRANSCRIPT_PATH: &str = "temp/test-threshold-wasm-transcript.bin";
pub const OTHER_KEY_HANDLE: &str = "otherKeyHandle";

pub const TEST_SEC_PAR: u64 = 40;

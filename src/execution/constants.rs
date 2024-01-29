use const_format::concatcp;

/// log_2 of parameter Bd, computed from values in the paper
pub(crate) const LOG_BD: u32 = 74;

/// the party ID of the party doing the reconstruction
pub(crate) const INPUT_PARTY_ID: usize = 1;

/// maximum number of PRSS party sets (n choose t) before the precomputation aborts
pub(crate) const PRSS_SIZE_MAX: usize = 8192;

/// statistical security parameter in bits
pub(crate) const STATSEC: u32 = 40;

/// Maximum absolute size of the Mask in PRSS-Mask BD1 = 2^stat * Bd
pub(crate) const BD1: u128 = 1 << (STATSEC + LOG_BD);

/// constants for key separation in PRSS/PRZS
pub(crate) const PHI_XOR_CONSTANT: u8 = 2;
pub(crate) const CHI_XOR_CONSTANT: u8 = 1;

/// param and keygen directories
pub const PARAMS_DIR: &str = "parameters";
pub const TEMP_DIR: &str = "temp";

pub const SMALL_TEST_PARAM_PATH: &str = concatcp!(PARAMS_DIR, "/small_test_params.json");
pub const SMALL_TEST_KEY_PATH: &str = concatcp!(TEMP_DIR, "/small_test_keys.bin");
pub const REAL_PARAM_PATH: &str = concatcp!(PARAMS_DIR, "/default_params.json");
pub const REAL_KEY_PATH: &str = concatcp!(TEMP_DIR, "/default_keys.bin");

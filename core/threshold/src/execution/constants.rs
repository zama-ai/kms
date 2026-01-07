use const_format::concatcp;

cfg_if::cfg_if! {
    if #[cfg(feature = "non-wasm")] {
        /// log_2 of parameter B_{SwitchSquash}, always using the upper bound
        pub(crate) const LOG_B_SWITCH_SQUASH: u32 = 70;
        pub(crate) const B_SWITCH_SQUASH: u128 = 1 << LOG_B_SWITCH_SQUASH;

        /// maximum number of PRSS party sets (n choose t) before the precomputation aborts
        pub(crate) const PRSS_SIZE_MAX: usize = 8192;

        /// statistical security parameter in bits
        pub(crate) const STATSEC: u32 = 40;

        /// constants for key separation in PRSS/PRZS
        pub(crate) const PHI_XOR_CONSTANT: u8 = 2;
        pub(crate) const CHI_XOR_CONSTANT: u8 = 1;
    }
}

/// param and keygen directories
pub const PARAMS_DIR: &str = "parameters";
pub const TEMP_DIR: &str = "temp";
pub const TEMP_DKG_DIR: &str = "temp/dkg";

pub const SMALL_TEST_KEY_PATH: &str = concatcp!(TEMP_DIR, "/small_test_keys.bin");
pub const REAL_KEY_PATH: &str = concatcp!(TEMP_DIR, "/default_keys.bin");

mod common;
mod crs_gen_tests;
mod custodian_backup_tests;
mod custodian_context_tests;
mod key_gen_tests;
mod misc_tests;
mod mpc_context_tests;
#[cfg(feature = "slow_tests")]
mod mpc_epoch_tests;
#[cfg(feature = "slow_tests")]
mod nightly_tests;
mod public_decryption_tests;
#[cfg(feature = "slow_tests")]
mod restore_from_backup_tests;
mod user_decryption_tests;

// =============================================================================
// ISOLATED TESTS (Docker-free, use pre-generated material)
// =============================================================================
// These tests use the consolidated testing module (kms_lib::testing) and run
// in isolated temporary directories with pre-generated cryptographic material.
// They are intended to eventually replace the Docker-based tests above.
//
// Run isolated tests with: cargo test --lib --features insecure,testing <test_name>
//
// Note: Pre-generated material (`make generate-test-material-testing`) is optional
// and speeds up test startup. PRSS is generated at runtime when `.with_prss()` is used.

#[cfg(any(feature = "testing", feature = "insecure"))]
mod key_gen_tests_isolated;

#[cfg(any(feature = "testing", feature = "insecure"))]
mod misc_tests_isolated;

#[cfg(any(feature = "testing", feature = "insecure"))]
mod restore_from_backup_tests_isolated;

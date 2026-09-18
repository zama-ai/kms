mod common;
mod crs_gen_tests;
mod custodian_backup_tests;
mod custodian_context_tests;
// CI runs tests prefixed with `nightly_` only on scheduled runs.
// The remaining tests also run in regular CI.
#[cfg(feature = "slow_tests")]
mod extended_tests;
mod key_gen_tests;
mod misc_tests;
mod mpc_context_tests;
#[cfg(feature = "slow_tests")]
mod mpc_epoch_tests;
mod public_decryption_tests;
mod restore_from_backup_tests;
mod user_decryption_tests;

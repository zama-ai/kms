#[cfg(feature = "non-wasm")]
pub mod client_non_wasm;
pub mod client_wasm;
#[cfg(feature = "non-wasm")]
pub mod crs_gen;
#[cfg(feature = "non-wasm")]
pub mod custodian_context;
#[cfg(not(feature = "non-wasm"))]
pub mod js_api;
#[cfg(feature = "non-wasm")]
pub mod key_gen;
#[cfg(feature = "non-wasm")]
pub mod mpc_context;
#[cfg(feature = "non-wasm")]
pub mod public_decryption;
#[cfg(any(test, feature = "testing"))]
#[cfg(feature = "non-wasm")]
pub mod test_tools;
#[cfg(feature = "non-wasm")]
pub mod user_decryption_non_wasm;
pub mod user_decryption_wasm;

#[allow(deprecated)]
#[cfg(test)]
pub(crate) mod tests {
    mod centralized;
    mod common;
    mod isolated_test_example;
    mod threshold;
}

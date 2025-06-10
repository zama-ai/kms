#[cfg(feature = "non-wasm")]
mod server;
#[cfg(feature = "non-wasm")]
pub use server::*;

#[cfg(feature = "non-wasm")]
pub mod base;
#[cfg(feature = "non-wasm")]
pub mod centralized;
#[cfg(feature = "non-wasm")]
pub mod context;
#[cfg(feature = "non-wasm")]
pub mod threshold;
#[cfg(feature = "non-wasm")]
pub mod traits;

#[cfg(feature = "non-wasm")]
mod validation_non_wasm;
mod validation_wasm;

// This is the only one that is allowed to be compiled with wasm
pub(crate) mod validation {
    #[cfg(feature = "non-wasm")]
    pub(crate) use super::validation_non_wasm::*;
    pub(crate) use super::validation_wasm::*;
}

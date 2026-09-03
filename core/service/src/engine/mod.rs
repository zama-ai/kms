#[cfg(feature = "non-wasm")]
pub use server::*;
#[cfg(feature = "non-wasm")]
mod server;

#[cfg(feature = "non-wasm")]
pub mod backup_operator;
#[cfg(feature = "non-wasm")]
pub mod base;
#[cfg(feature = "non-wasm")]
pub mod centralized;
#[cfg(feature = "non-wasm")]
pub mod context;
#[cfg(feature = "non-wasm")]
pub mod context_manager;
#[cfg(feature = "non-wasm")]
pub mod keyset_configuration;
#[cfg(feature = "non-wasm")]
pub mod material_integrity;
#[cfg(feature = "non-wasm")]
pub mod migration;
#[cfg(feature = "non-wasm")]
pub(crate) mod storage_material_verification;
#[cfg(feature = "non-wasm")]
pub mod rng_registry;
#[cfg(feature = "non-wasm")]
pub mod threshold;
#[cfg(feature = "non-wasm")]
pub mod traits;
#[cfg(feature = "non-wasm")]
pub mod utils;

#[cfg(feature = "non-wasm")]
mod validation_non_wasm;
mod validation_wasm;

/// Client-side validation of aggregated decryption responses.
///
/// Public decryption (`validation_non_wasm`) and user decryption (`validation_wasm`) follow the
/// **same robust-partition design**, so the two read as mirror images:
///
/// 1. **Select the pivot.** `select_most_common` groups responses by a `Hash + Eq` *invariants* key
///    and returns the value shared by the ≥ `t + 1` majority. A response whose key cannot even be
///    built (e.g. an unparseable request id) is skipped from the vote, never aborting it.
/// 2. **Establish the invariants.** The consensus invariants are taken from the pivot (and checked
///    against the client's own request). Everything downstream reads "what the servers agreed on"
///    from this single value — never from an individual, untrusted response.
/// 3. **Classify each response against the invariants.** `classify_{public,user}_decrypt_response`
///    is **infallible w.r.t. response content**: every failure mode is a typed `*RejectReason`, so a
///    single Byzantine response can never abort the batch. The output is a partition into `accepted`
///    (or, for user decryption, *authenticated*) and typed `rejected`.
///
/// The one structural difference is recovery: a public-decryption response already carries the
/// cleartext plaintext, so classification fully accepts it; a user-decryption response carries a
/// *signcrypted* share, so full acceptance additionally requires un-signcryption with the client's
/// key — a step that lives in `client::user_decryption_wasm`, not here. The secret-free validation
/// here (`validate_user_decrypt_responses`) can therefore be run by a party that does
/// not hold the decryption key.
///
// This is the only one that is allowed to be compiled with wasm
pub(crate) mod validation {
    #[cfg(feature = "non-wasm")]
    pub(crate) use super::validation_non_wasm::*;
    pub(crate) use super::validation_wasm::*;
}

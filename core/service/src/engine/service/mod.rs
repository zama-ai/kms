//
// Module Structure for Threshold Service Implementation
//
// - crs_generator.rs: CrsGenerator implementation for CRS generation
// - initiator.rs: RealInitiator implementation for PRSS setup
// - key_generator.rs: KeyGenerator implementation for key generation
// - kms_impl.rs: Server initialization functions
// - preprocessor.rs: Preprocessor implementation for preprocessing
// - public_decryptor.rs: PublicDecryptor implementation for public decryption
// - session.rs: SessionPreparer implementation for session management
// - user_decryptor.rs: UserDecryptor implementation for user decryption

// Re-export initialization functions
mod kms_impl;
pub use kms_impl::*;

// Module components
pub(crate) mod crs_generator;
pub(crate) mod epoch_manager;
// Re-exported so the epoch data type is reachable outside the crate (e.g. the
// backward-compatibility generators and tests) without exposing the rest of the
// epoch manager internals.
pub use epoch_manager::EpochData;
//mod initiator;
pub(crate) mod key_generator;
pub(crate) mod preprocessor;
pub(crate) mod public_decryptor;
pub(crate) mod reshare_utils;
pub mod session;
pub(crate) mod user_decryptor;

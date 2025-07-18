//
// Module Structure for Service Components
//
// - crs_gen.rs: Common Reference String generation implementation
// - decryption.rs: Decryption service implementation
// - endpoint.rs: Service endpoint and API handlers
// - key_gen.rs: Key generation implementation

// Module components
mod context;
mod crs_gen;
mod decryption;
mod key_gen;

// Re-export all the service components
pub use context::*;
pub use crs_gen::*;
pub use decryption::*;
pub use key_gen::*;

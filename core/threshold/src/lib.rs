#[cfg(feature = "non-wasm")]
#[cfg(feature = "choreographer")]
pub mod choreography;
pub mod commitment;
pub mod execution;
pub mod file_handling;
pub mod hashing;
#[cfg(feature = "non-wasm")]
pub mod networking;
pub mod session_id;
#[cfg(any(test, feature = "testing"))]
pub mod tests;
#[cfg(feature = "non-wasm")]
pub use tokio;
pub mod algebra;
#[cfg(all(feature = "non-wasm", feature = "measure_memory"))]
pub mod allocator;
#[cfg(feature = "non-wasm")]
pub mod conf;
pub mod error;
#[cfg(feature = "experimental")]
pub mod experimental;
#[cfg(feature = "non-wasm")]
pub mod grpc;
#[cfg(any(test, feature = "malicious_strategies"))]
pub mod malicious_execution;
#[cfg(feature = "non-wasm")]
pub mod thread_handles;
#[cfg(feature = "non-wasm")]
pub mod tls_certs;

pub trait ProtocolDescription {
    fn protocol_desc(depth: usize) -> String;
}

//! gRPC-based networking.
//!
//! - [`config`]: [`CoreToCoreNetworkConfig`] tuning knobs and their defaults.
//! - [`message_queue`]: per-sender channel/buffer types
//!   ([`MessageQueueStore`], [`ReceiverState`], [`NetworkRoundValue`], …).
//! - [`session_store`]: the session registry ([`SessionStore`], [`SessionStatus`]).
//! - [`server`]: the [`Gnetworking`](crate::ggen::gnetworking_server::Gnetworking)
//!   server impl ([`NetworkingImpl`]) and the [`Tag`]/[`HealthTag`] wire types.
//! - [`manager`]: [`GrpcNetworkingManager`], which wires everything together and
//!   creates sessions.

mod config;
mod manager;
mod message_queue;
mod server;
mod session_store;

// Public API — external crates use these via `threshold_networking::grpc::…`.
pub use config::CoreToCoreNetworkConfig;
pub use manager::{GrpcNetworkingManager, GrpcServer};
pub use message_queue::NetworkRoundValue;
pub use server::{HealthTag, NetworkingImpl, Tag, TlsExtensionGetter};

// Crate-internal types shared across submodules and with `sending_service`.
pub(crate) use message_queue::{ChannelPair, MessageQueueStore, ReceiverState};
pub(crate) use session_store::{SessionStatus, SessionStore};

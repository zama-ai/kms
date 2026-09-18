//! Outbound sending transport and the per-session networking abstraction.
//!
//! - [`service`]: [`GrpcSendingService`] + the [`SendingService`] trait — connect
//!   to peers and run the per-peer retry/backoff send task.
//! - [`session`]: [`NetworkSession`], the [`Networking`](threshold_types::network::Networking)
//!   implementation with the round-aware `send`/`receive`.
//!
//! Lock-free time helpers live in the crate-level [`clock`](crate::clock) module.

mod service;
mod session;

// Public API — reachable as `threshold_networking::sending_service::…`.
pub use service::{ArcSendValueRequest, GrpcSendingService, SendingService};
pub use session::NetworkSession;

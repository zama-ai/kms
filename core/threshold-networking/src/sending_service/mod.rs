//! Outbound sending transport and the per-session networking abstraction.
//!
//! - [`service`]: [`GrpcSendingService`] + the [`SendingService`] trait — connect
//!   to peers and run the per-peer retry/backoff send task.
//! - [`session`]: [`NetworkSession`], the [`Networking`](threshold_types::network::Networking)
//!   implementation with the round-aware `send`/`receive`.
//! - [`clock`]: lock-free time helpers (`now_activity_millis`, `AtomicDuration`).

mod clock;
mod service;
mod session;

// Public API — reachable as `threshold_networking::sending_service::…`.
pub use service::{ArcSendValueRequest, GrpcSendingService, SendingService};
pub use session::NetworkSession;

// Crate-internal helpers shared with the `grpc` module and across submodules.
pub(crate) use clock::{AtomicDuration, now_activity_millis};

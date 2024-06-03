use crate::execution::runtime::party::RoleAssignment;
use crate::execution::runtime::session::NetworkingImpl;
use crate::session_id::SessionId;

pub mod choreographer;
pub mod grpc;
pub mod requests;

pub type NetworkingStrategy =
    Box<dyn Fn(SessionId, RoleAssignment) -> NetworkingImpl + Send + Sync>;

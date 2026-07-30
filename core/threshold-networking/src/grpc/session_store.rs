//! The per-[`SessionId`] session registry and its status enum.

use crate::ggen::{SendValueResponse, Status};
use crate::grpc::MessageQueueStore;
use crate::sending_service::NetworkSession;
use dashmap::DashMap;
use std::sync::Weak;
use threshold_types::session_id::SessionId;
use tokio::time::Instant;

pub(crate) type SessionStore = DashMap<SessionId, SessionStatus>;

#[derive(Debug)]
/// Represents the status of a session in the session store.
/// It can be:
/// - Completed: The session has been completed and the timestamp of completion is stored.
/// - Inactive: The session is inactive (I haven't yet heard about the request) and has a message queue store for senders.
/// - Active: The session is active (I know about the request) and holds a weak reference to the `NetworkSession`.
pub(crate) enum SessionStatus {
    Completed(Instant),
    Inactive((MessageQueueStore, Instant)),
    Active(Weak<NetworkSession>),
}

impl From<SessionStatus> for SendValueResponse {
    fn from(value: SessionStatus) -> Self {
        // Same mapping as the borrowing impl; delegate so the two cannot drift.
        (&value).into()
    }
}

impl From<&SessionStatus> for SendValueResponse {
    fn from(value: &SessionStatus) -> Self {
        let status = match value {
            SessionStatus::Completed(_) => Status::Completed,
            SessionStatus::Inactive(_) => Status::Inactive,
            SessionStatus::Active(_) => Status::Active,
        };
        SendValueResponse {
            status: status.into(),
        }
    }
}

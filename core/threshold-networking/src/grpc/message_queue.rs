//! Per-sender message queues and the future-round reordering buffer.

use dashmap::DashMap;
use std::sync::Arc;
use threshold_types::party::{MpcIdentity, RoleAssignment};
use threshold_types::role::{RoleKind, RoleTrait};
use tokio::sync::{
    Mutex,
    mpsc::{Receiver, Sender, channel},
};

// we need a counter for each value sent over the local queues
// so that messages that haven't been pickup up using receive() calls will get dropped
#[derive(Debug)]
pub struct NetworkRoundValue {
    pub value: Vec<u8>,
    pub round_counter: usize,
}

/// Per-sender receiver plus a bounded buffer of future-round messages that
/// arrived before the local session advanced to their round.
///
/// The receiver is a bounded mpsc whose ordering is fully controlled by the
/// (possibly malicious) peer, so `receive` must not treat "next packet" as
/// "current-round packet". Messages tagged with a strictly future round are
/// parked here — keyed by their round counter — until the session reaches that
/// round, at which point they are delivered from the fast path. The buffer is
/// bounded by [`max_future_rounds`](crate::grpc::CoreToCoreNetworkConfig::get_max_future_rounds)
/// and [`max_buffered_future_msgs`](crate::grpc::CoreToCoreNetworkConfig::get_max_buffered_future_msgs)
/// to prevent a peer from exhausting memory with distinct future round numbers.
#[derive(Debug)]
pub(crate) struct ReceiverState {
    /// The bounded mpsc receiver for this sender.
    pub(crate) rx: Receiver<NetworkRoundValue>,
    /// Future-round messages, keyed by round counter (all strictly greater than
    /// the current round when inserted). Holds at most one value per round.
    pub(crate) future: std::collections::BTreeMap<usize, Vec<u8>>,
}

impl ReceiverState {
    /// Wrap a freshly created receiver with an empty future-round buffer.
    pub(crate) fn new(rx: Receiver<NetworkRoundValue>) -> Self {
        Self {
            rx,
            future: std::collections::BTreeMap::new(),
        }
    }

    /// Drop every buffered message strictly older than `current`, then take the
    /// buffered message for exactly `current` if one is present.
    pub(crate) fn take_current(&mut self, current: usize) -> Option<Vec<u8>> {
        // Keep only rounds >= current; everything below is stale and dropped.
        self.future = self.future.split_off(&current);
        self.future.remove(&current)
    }

    /// Buffer a strictly-future-round message, enforcing the reordering-buffer
    /// bounds. Returns `true` if the message was buffered, `false` if it was
    /// dropped for being outside the `max_future_rounds` look-ahead window or
    /// over the per-sender `max_buffered` cap.
    ///
    /// At most one value is kept per round: a duplicate for an already-buffered
    /// round is discarded (first one wins) so a malicious peer cannot clobber a
    /// genuine future-round message.
    pub(crate) fn buffer_future(
        &mut self,
        round: usize,
        value: Vec<u8>,
        current: usize,
        max_buffered: usize,
    ) -> bool {
        if round > current
            && round <= current.saturating_add(max_buffered)
            && self.future.len() < max_buffered
        {
            self.future.entry(round).or_insert(value);
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct InitializedMessageQueueStore {
    // role assignment is needed because the message store
    // needs to translate between identity and role
    tx: DashMap<MpcIdentity, Arc<Sender<NetworkRoundValue>>>,
    receiver_state: DashMap<RoleKind, Arc<Mutex<ReceiverState>>>,
}

/// The pair of channel halves kept per sender in an uninitialized message
/// queue: the sending half other parties push into (`tx`) and the shared
/// receiving state the owning session drains (`rx`).
#[derive(Debug, Clone)]
pub(crate) struct ChannelPair {
    pub(crate) tx: Arc<Sender<NetworkRoundValue>>,
    pub(crate) rx: Arc<Mutex<ReceiverState>>,
}

#[derive(Debug, Clone)]
pub(crate) enum MessageQueueStore {
    Uninitialized(DashMap<MpcIdentity, ChannelPair>),
    Initialized(InitializedMessageQueueStore),
}

impl MessageQueueStore {
    pub(crate) fn new_uninitialized(channel_maps: DashMap<MpcIdentity, ChannelPair>) -> Self {
        MessageQueueStore::Uninitialized(channel_maps)
    }

    pub(crate) fn new_initialized<R: RoleTrait>(
        channel_size_limit: usize,
        others: &RoleAssignment<R>,
    ) -> Self {
        let mut out = Self::new_uninitialized(DashMap::new());
        out.init(channel_size_limit, others);
        out
    }

    pub(crate) fn init<R: RoleTrait>(
        &mut self,
        channel_size_limit: usize,
        others: &RoleAssignment<R>,
    ) {
        if let MessageQueueStore::Uninitialized(channel_maps) = &self {
            let tx_map = DashMap::with_capacity(channel_maps.len());
            let rx_map = DashMap::with_capacity(channel_maps.len());

            // If an identity is in channel_maps and also in role_assignment,
            // then we insert it to the initialized message queue.
            // If an identity is not in channel_maps but in role_assignment,
            // then we create a new channel for it.
            for (role, identity) in others.iter() {
                let mpc_id = identity.mpc_identity();
                if let Some(entry) = channel_maps.get(&mpc_id) {
                    let pair = entry.value();
                    tx_map.insert(entry.key().clone(), pair.tx.clone());
                    rx_map.insert(role.get_role_kind(), pair.rx.clone());
                } else {
                    let (tx, rx) = channel::<NetworkRoundValue>(channel_size_limit);
                    tx_map.insert(identity.mpc_identity(), Arc::new(tx));
                    rx_map.insert(
                        role.get_role_kind(),
                        Arc::new(Mutex::new(ReceiverState::new(rx))),
                    );
                }
            }

            *self = MessageQueueStore::Initialized(InitializedMessageQueueStore {
                tx: tx_map,
                receiver_state: rx_map,
            });
        } else {
            tracing::warn!("MessageQueueStore is already initialized");
        }
    }

    pub(crate) fn get_tx(
        &self,
        mpc_identity: &MpcIdentity,
    ) -> Result<Option<Arc<Sender<NetworkRoundValue>>>, Box<tonic::Status>> {
        match &self {
            MessageQueueStore::Initialized(store) => Ok(store
                .tx
                .get(mpc_identity)
                .map(|entry| entry.value().clone())),
            MessageQueueStore::Uninitialized(_) => Err(Box::new(tonic::Status::internal(
                "trying to get tx message queue on id {mpc_identity} when it is not initialized",
            ))),
        }
    }

    pub(crate) fn get_receiver_state<R: RoleTrait>(
        &self,
        role: &R,
    ) -> anyhow::Result<Option<Arc<Mutex<ReceiverState>>>> {
        match &self {
            MessageQueueStore::Initialized(store) => Ok(store
                .receiver_state
                .get(&role.get_role_kind())
                .map(|entry| entry.value().clone())),
            MessageQueueStore::Uninitialized(_) => Err(anyhow::anyhow!(
                "trying to get rx message queue on role {role} when it is not initialized",
            )),
        }
    }

    // this must be performed on the uninitialized message queue
    pub(crate) fn entry(
        &self,
        mpc_identity: MpcIdentity,
    ) -> anyhow::Result<dashmap::mapref::entry::Entry<'_, MpcIdentity, ChannelPair>> {
        match &self {
            MessageQueueStore::Uninitialized(inner) => Ok(inner.entry(mpc_identity)),
            MessageQueueStore::Initialized(_) => Err(anyhow::anyhow!(
                "entry can only be performed on uninitialized message queue"
            )),
        }
    }

    pub(crate) fn iter_keys(
        &self,
    ) -> Result<impl Iterator<Item = RoleKind> + '_, Box<tonic::Status>> {
        match &self {
            MessageQueueStore::Uninitialized(_) => Err(Box::new(tonic::Status::internal(
                "trying to iterate keys when message queue is not initialized",
            ))),
            MessageQueueStore::Initialized(inner) => {
                Ok(inner.receiver_state.iter().map(|entry| *entry.key()))
            }
        }
    }
}

// Unit tests for the struct defined in this file
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_take_current() {
        let (_, rx) = channel::<NetworkRoundValue>(10);
        let mut receiver_state = ReceiverState::new(rx);
        let mut current_round = 2;
        let window_size = 5;
        for i in 0..10 {
            let res = receiver_state.buffer_future(i, vec![i as u8], current_round, window_size);

            // Check that messages for rounds outside the window are dropped, and those within the window are buffered.
            if i <= current_round || i > current_round + 5 {
                assert!(!res, "Message for round {i} should be dropped");
            } else {
                assert!(res, "Message for round {i} should be buffered");
            }
        }

        // Move to next round and verify we do have window size messages in the buffer
        current_round += 1;
        for _ in 0..window_size {
            let current = receiver_state.take_current(current_round);
            let expected_msg = current_round as u8;
            assert_eq!(
                current,
                Some(vec![expected_msg]),
                "Expected message for round {current_round}: {expected_msg}"
            );
            current_round += 1;
        }
    }
}

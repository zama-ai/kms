use std::cmp::min;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use error_utils::anyhow_error_and_log;

use super::*;
use crate::clock::AtomicInstant;
use constants::{
    NETWORK_TIMEOUT, NETWORK_TIMEOUT_ASYNC, NETWORK_TIMEOUT_BK, NETWORK_TIMEOUT_BK_SNS,
};
use threshold_types::network::{NetworkMode, Networking, RoundClock};
use threshold_types::role::RoleTrait;

use async_trait::async_trait;
use dashmap::DashMap;
use futures_util::future::{join, join3, join4};
use tokio::sync::{
    Mutex,
    mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
};

/// A simple implementation of networking for local execution.
///
/// This implementation is intended for local development/testing purposes
/// only. It simply stores all values in a hashmap without any actual networking.
//This is using mutexes for everything round related to be able to
//mutate state without needing self to be mutable in functions' signature
pub struct LocalNetworking<R: RoleTrait> {
    current_network_timeout: Mutex<Duration>,
    next_network_timeout: Mutex<Duration>,
    max_elapsed_time: Mutex<Duration>,
    pairwise_channels: SimulatedPairwiseChannels<R>,
    pub owner: R,
    pub send_counter: DashMap<R, usize>,
    pub network_round: Arc<Mutex<usize>>,
    already_sent: Arc<Mutex<HashSet<(R, usize)>>>,
    /// Anchor of the round clock, stamped at session creation. Stored lock-free
    /// (an [`AtomicInstant`]) so `synchronize_from` can overwrite it from `&self`.
    pub(crate) init_time: AtomicInstant,
    network_mode: NetworkMode,
    //If set, the party will sleep for the given duration at the start of each round
    delayed_party: Option<Duration>,
}

impl<R: RoleTrait> Default for LocalNetworking<R> {
    fn default() -> Self {
        Self {
            current_network_timeout: Mutex::new(NETWORK_TIMEOUT),
            next_network_timeout: Mutex::new(NETWORK_TIMEOUT),
            max_elapsed_time: Mutex::new(Duration::ZERO),
            pairwise_channels: Default::default(),
            owner: Default::default(),
            send_counter: Default::default(),
            network_round: Default::default(),
            already_sent: Default::default(),
            init_time: AtomicInstant::now(),
            network_mode: NetworkMode::Sync,
            delayed_party: None,
        }
    }
}

#[derive(Default)]
pub struct LocalNetworkingProducer<R: RoleTrait> {
    pairwise_channels: SimulatedPairwiseChannels<R>,
}

impl<R: RoleTrait> LocalNetworkingProducer<R> {
    pub fn from_roles(roles: &HashSet<R>) -> Self {
        let pairwise_channels = DashMap::new();
        for v1 in roles {
            for v2 in roles {
                if *v1 != *v2 {
                    let (tx, rx) = unbounded_channel::<LocalTaggedValue>();
                    pairwise_channels.insert(
                        (*v1, *v2),
                        (Arc::new(tx), Arc::new(tokio::sync::Mutex::new(rx))),
                    );
                }
            }
        }
        LocalNetworkingProducer {
            pairwise_channels: Arc::new(pairwise_channels),
        }
    }
    pub fn user_net(
        &self,
        owner: R,
        network_mode: NetworkMode,
        delayed_party: Option<Duration>,
    ) -> LocalNetworking<R> {
        // Async network means a timeout of 1 year
        let timeout = match network_mode {
            NetworkMode::Sync => NETWORK_TIMEOUT,
            NetworkMode::Async => NETWORK_TIMEOUT_ASYNC,
        };

        LocalNetworking {
            pairwise_channels: Arc::clone(&self.pairwise_channels),
            owner,
            network_mode,
            current_network_timeout: Mutex::new(timeout),
            next_network_timeout: Mutex::new(timeout),
            delayed_party,
            ..Default::default()
        }
    }
}

type SimulatedPairwiseChannels<R> = Arc<
    DashMap<
        (R, R),
        (
            Arc<UnboundedSender<LocalTaggedValue>>,
            Arc<tokio::sync::Mutex<UnboundedReceiver<LocalTaggedValue>>>,
        ),
    >,
>;

#[async_trait]
impl<R: RoleTrait> Networking<R> for LocalNetworking<R> {
    async fn send(&self, val: Arc<Vec<u8>>, receiver: &R) -> anyhow::Result<(), anyhow::Error> {
        let (tx, _) = self
            .pairwise_channels
            .get(&(self.owner, *receiver))
            .ok_or_else(|| {
                anyhow_error_and_log(format!(
                "Could not retrieve pairwise channels in send call, owner: {:?}, receiver: {:?}.",
                self.owner, receiver
            ))
            })?
            .value()
            .clone();

        let net_round = self.network_round.lock().await;

        let tagged_value = LocalTaggedValue {
            send_counter: *net_round,
            value: val.as_ref().clone(),
        };

        let mut already_sent = self.already_sent.lock().await;

        if already_sent.contains(&(*receiver, *net_round)) {
            return Err(anyhow::anyhow!(
                "Trying to send to {receiver} in round {net_round} more than once !"
            ));
        } else {
            already_sent.insert((*receiver, *net_round));
        }

        tx.send(tagged_value).map_err(|e| e.into())
    }

    async fn receive(&self, sender: &R) -> anyhow::Result<Vec<u8>> {
        let (_, rx) = self
            .pairwise_channels
            .get(&(*sender, self.owner))
            .ok_or_else(|| {
                anyhow_error_and_log(format!(
                "Could not retrieve pairwise channels in receive call, owner: {:?}, sender: {:?}",
                self.owner, sender
            ))
            })?
            .value()
            .clone();
        let mut rx = rx.lock().await;

        let mut tagged_value = rx
            .recv()
            .await
            .ok_or_else(|| anyhow_error_and_log("Trying to receive from a closed channel"))?;

        let network_round: usize = *self.network_round.lock().await;

        while tagged_value.send_counter < network_round {
            tracing::debug!(
                "@ round {} - dropped value {:?} from round {}",
                network_round,
                tagged_value.value[..min(tagged_value.value.len(), 16)].to_vec(),
                tagged_value.send_counter
            );
            tagged_value = rx
                .recv()
                .await
                .ok_or_else(|| anyhow_error_and_log("Trying to receive from a closed channel"))?;
        }

        Ok(tagged_value.value)
    }

    async fn increase_round_counter(&self) {
        if let Some(duration) = self.delayed_party {
            // Async sleep: a blocking `std::thread::sleep` here would stall the
            // tokio worker thread (and any other tasks scheduled on it).
            tokio::time::sleep(duration).await;
        }
        //Locking all mutexes in same place
        //Update max_elapsed_time
        let (mut max_elapsed_time, mut current_round_timeout, next_round_timeout, mut net_round) =
            join4(
                self.max_elapsed_time.lock(),
                self.current_network_timeout.lock(),
                self.next_network_timeout.lock(),
                self.network_round.lock(),
            )
            .await;
        *max_elapsed_time += *current_round_timeout;

        //Update next round timeout
        *current_round_timeout = *next_round_timeout;

        //Update round counter
        *net_round += 1;
        tracing::debug!(
            "changed network round to: {:?} on party: {:?}, with timeout: {:?}",
            *net_round,
            self.owner,
            *current_round_timeout
        )
    }

    async fn get_timeout_current_round(&self) -> Instant {
        let (max_elapsed_time, network_timeout) = join(
            self.max_elapsed_time.lock(),
            self.current_network_timeout.lock(),
        )
        .await;
        self.init_time.load() + *network_timeout + *max_elapsed_time
    }

    async fn get_current_round(&self) -> usize {
        *self.network_round.lock().await
    }

    async fn round_clock_snapshot(&self) -> RoundClock {
        let (round, max_elapsed_time, current_network_timeout) = join3(
            self.network_round.lock(),
            self.max_elapsed_time.lock(),
            self.current_network_timeout.lock(),
        )
        .await;
        RoundClock {
            init_time: self.init_time.load(),
            round: *round,
            max_elapsed_time: *max_elapsed_time,
            current_network_timeout: *current_network_timeout,
        }
    }

    async fn restore_round_clock(&self, clock: RoundClock) {
        let (mut round, mut max_elapsed_time, mut current_network_timeout) = join3(
            self.network_round.lock(),
            self.max_elapsed_time.lock(),
            self.current_network_timeout.lock(),
        )
        .await;
        // A round clock only ever moves forward.
        assert!(
            clock.round >= *round,
            "restore_round_clock: refusing to move round backwards from {} to {}",
            *round,
            clock.round
        );
        self.init_time.store(clock.init_time);
        *round = clock.round;
        *max_elapsed_time = clock.max_elapsed_time;
        *current_network_timeout = clock.current_network_timeout;
    }

    async fn set_timeout_for_next_round(&self, timeout: Duration) {
        match self.get_network_mode() {
            NetworkMode::Sync => {
                let mut next_network_timeout = self.next_network_timeout.lock().await;
                *next_network_timeout = timeout;
            }
            NetworkMode::Async => {
                tracing::warn!(
                    "Trying to change network timeout with async network, doesn't do anything"
                );
            }
        }
    }

    async fn set_timeout_for_bk(&self) {
        self.set_timeout_for_next_round(NETWORK_TIMEOUT_BK).await
    }

    async fn set_timeout_for_bk_sns(&self) {
        self.set_timeout_for_next_round(NETWORK_TIMEOUT_BK_SNS)
            .await
    }

    fn get_network_mode(&self) -> NetworkMode {
        self.network_mode
    }

    async fn get_num_byte_sent(&self) -> usize {
        0
    }

    async fn get_num_byte_received(&self) -> anyhow::Result<usize> {
        Ok(0)
    }
}

#[derive(Debug, Clone)]
struct LocalTaggedValue {
    value: Vec<u8>,
    send_counter: usize,
}

#[cfg(test)]
mod tests {
    use threshold_execution::{
        network_value::NetworkValue, runtime::sessions::session_parameters::DeSerializationRunTime,
    };
    use threshold_types::network::Networking;
    use threshold_types::role::{Role, TwoSetsRole};

    use super::*;
    use std::num::Wrapping;

    #[tokio::test]
    async fn test_sync_networking() {
        let alice = Role::indexed_from_one(1);
        let bob = Role::indexed_from_one(2);
        let roles = HashSet::from([alice, bob]);
        let net_producer = LocalNetworkingProducer::from_roles(&roles);

        let net_alice = net_producer.user_net(alice, NetworkMode::Sync, None);
        let net_bob = net_producer.user_net(bob, NetworkMode::Sync, None);

        let task1 = tokio::spawn(async move {
            let recv = net_bob.receive(&alice).await;
            assert_eq!(
                bc2wrap::serialize(
                    &NetworkValue::<Wrapping::<u64>>::from_network(
                        recv,
                        DeSerializationRunTime::Tokio
                    )
                    .await
                    .unwrap()
                )
                .unwrap(),
                bc2wrap::serialize(&NetworkValue::RingValue(Wrapping::<u64>(1234))).unwrap()
            );
        });

        let task2 = tokio::spawn(async move {
            let value = NetworkValue::RingValue(Wrapping::<u64>(1234));
            net_alice.send(Arc::new(value.to_network()), &bob).await
        });

        let _ = tokio::try_join!(task1, task2).unwrap();
    }

    #[tokio::test]
    async fn test_networking_two_sets() {
        let role_1_set_1 = TwoSetsRole::OnlySet1(Role::indexed_from_one(1));
        let role_1_set_2 = TwoSetsRole::OnlySet2(Role::indexed_from_one(1));

        let roles = HashSet::from([role_1_set_1, role_1_set_2]);
        let net_producer = LocalNetworkingProducer::from_roles(&roles);

        let net_party_1_set_1 = net_producer.user_net(role_1_set_1, NetworkMode::Sync, None);
        let net_party_1_set_2 = net_producer.user_net(role_1_set_2, NetworkMode::Sync, None);

        let task1 = tokio::spawn(async move {
            let recv = net_party_1_set_1.receive(&role_1_set_2).await;
            assert_eq!(
                bc2wrap::serialize(
                    &NetworkValue::<Wrapping::<u64>>::from_network(
                        recv,
                        DeSerializationRunTime::Tokio
                    )
                    .await
                    .unwrap()
                )
                .unwrap(),
                bc2wrap::serialize(&NetworkValue::RingValue(Wrapping::<u64>(1234))).unwrap()
            );
        });

        let task2 = tokio::spawn(async move {
            let value = NetworkValue::RingValue(Wrapping::<u64>(1234));
            net_party_1_set_2
                .send(Arc::new(value.to_network()), &role_1_set_1)
                .await
        });

        let _ = tokio::try_join!(task1, task2).unwrap();
    }

    #[tokio::test]
    async fn test_sync_networking_duplicate_send_error() {
        let alice = Role::indexed_from_one(1);
        let bob = Role::indexed_from_one(2);
        let roles = HashSet::from([alice, bob]);
        let net_producer = LocalNetworkingProducer::from_roles(&roles);

        let net_alice = net_producer.user_net(alice, NetworkMode::Sync, None);

        let value = Arc::new(NetworkValue::RingValue(Wrapping::<u64>(1234)).to_network());
        // First send should succeed
        let result1 = net_alice.send(value.clone(), &bob).await;
        assert!(result1.is_ok());

        // Second send to same receiver in same round should fail
        let result2 = net_alice.send(value.clone(), &bob).await;
        assert!(result2.is_err());
        let error_msg = result2.unwrap_err().to_string();
        assert!(
            error_msg.contains(
                &format!("Trying to send to {bob} in round 0 more than once !").to_string()
            )
        );
    }

    /// Advancing a session by `n` rounds moves the round counter to `n` and the
    /// deadline of the current round to `init_time + (n + 1) * timeout`: every
    /// skipped round contributes its full timeout to the accumulated budget.
    #[tokio::test]
    async fn test_round_clock_deadline_grows_by_one_timeout_per_round() {
        let alice = Role::indexed_from_one(1);
        let net_producer = LocalNetworkingProducer::from_roles(&HashSet::from([alice]));
        let net = net_producer.user_net(alice, NetworkMode::Sync, None);
        let init_time = net.init_time.load();

        assert_eq!(net.get_current_round().await, 0);
        assert_eq!(
            net.get_timeout_current_round().await,
            init_time + NETWORK_TIMEOUT
        );

        for round in 1..=7 {
            net.increase_round_counter().await;
            assert_eq!(net.get_current_round().await, round);
            assert_eq!(
                net.get_timeout_current_round().await,
                init_time + NETWORK_TIMEOUT * (round as u32 + 1),
                "deadline after {round} rounds must be init_time + (round + 1) * timeout"
            );
        }
    }

    /// The round-clock anchor is stamped at construction, not at first use. Two
    /// sessions created together share the same round-0 deadline even if one of
    /// them is only used much later, so a party that idles before its first message
    /// does not silently get a later deadline than its peers.
    #[tokio::test]
    async fn test_init_time_is_stamped_at_construction() {
        let alice = Role::indexed_from_one(1);
        let bob = Role::indexed_from_one(2);
        let net_producer = LocalNetworkingProducer::from_roles(&HashSet::from([alice, bob]));
        let used_immediately = net_producer.user_net(alice, NetworkMode::Sync, None);
        let used_later = net_producer.user_net(bob, NetworkMode::Sync, None);

        let deadline_immediate = used_immediately.get_timeout_current_round().await;

        let idle = Duration::from_millis(300);
        tokio::time::sleep(idle).await;
        let deadline_later = used_later.get_timeout_current_round().await;

        // Construction of the two sessions is a few microseconds apart; the idle
        // time must not show up in the deadline.
        let skew = deadline_later.saturating_duration_since(deadline_immediate);
        assert!(
            skew < idle / 2,
            "first use {idle:?} after construction moved the deadline by {skew:?}"
        );
    }

    /// A deterministic advance shifts every party's deadline by the same amount, so
    /// it does not absorb a difference in session *creation* time: two parties whose
    /// sessions were created `stagger` apart keep deadlines `stagger` apart at every
    /// round. Parties must therefore create a shared session within one round
    /// timeout of each other for the earliest party not to time out on round 0.
    #[tokio::test]
    async fn test_creation_stagger_is_not_absorbed_by_advance() {
        let alice = Role::indexed_from_one(1);
        let bob = Role::indexed_from_one(2);
        let net_producer = LocalNetworkingProducer::from_roles(&HashSet::from([alice, bob]));
        let early = net_producer.user_net(alice, NetworkMode::Sync, None);
        let stagger = Duration::from_millis(300);
        tokio::time::sleep(stagger).await;
        let late = net_producer.user_net(bob, NetworkMode::Sync, None);

        for _ in 0..4 {
            early.increase_round_counter().await;
            late.increase_round_counter().await;
        }

        let deadline_gap = late
            .get_timeout_current_round()
            .await
            .saturating_duration_since(early.get_timeout_current_round().await);
        let tolerance = Duration::from_millis(100);
        assert!(
            deadline_gap > stagger - tolerance && deadline_gap < stagger + tolerance,
            "creation stagger of {stagger:?} must carry over 1:1 to the deadlines, got {deadline_gap:?}"
        );
    }

    /// `synchronize_from` copies the whole round clock: anchor, round counter,
    /// accumulated budget and current-round timeout. Afterwards both sessions
    /// report the same round and the same deadline.
    #[tokio::test]
    async fn test_synchronize_from_copies_round_clock() {
        let alice = Role::indexed_from_one(1);
        let bob = Role::indexed_from_one(2);
        let net_producer = LocalNetworkingProducer::from_roles(&HashSet::from([alice, bob]));
        let source = net_producer.user_net(alice, NetworkMode::Sync, None);

        // Give the source a non-trivial clock: three rounds, the last one with a
        // custom timeout.
        source.increase_round_counter().await;
        source.increase_round_counter().await;
        source
            .set_timeout_for_next_round(Duration::from_secs(42))
            .await;
        source.increase_round_counter().await;

        // Create the target later so that its anchor differs from the source's.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let target = net_producer.user_net(bob, NetworkMode::Sync, None);
        assert_ne!(target.init_time.load(), source.init_time.load());

        target.synchronize_from(&source).await;

        let source_clock = source.round_clock_snapshot().await;
        let target_clock = target.round_clock_snapshot().await;
        assert_eq!(target_clock.init_time, source_clock.init_time);
        assert_eq!(target_clock.round, source_clock.round);
        assert_eq!(target_clock.round, 3);
        assert_eq!(target_clock.max_elapsed_time, source_clock.max_elapsed_time);
        assert_eq!(target_clock.max_elapsed_time, NETWORK_TIMEOUT * 3);
        assert_eq!(
            target_clock.current_network_timeout,
            source_clock.current_network_timeout
        );
        assert_eq!(
            target_clock.current_network_timeout,
            Duration::from_secs(42)
        );
        assert_eq!(
            target.get_timeout_current_round().await,
            source.get_timeout_current_round().await
        );

        // Synchronizing to the same round is allowed (idempotent).
        target.synchronize_from(&source).await;
        assert_eq!(target.get_current_round().await, 3);
    }

    /// A round clock never moves backwards: synchronizing to a session that is
    /// behind would reuse round tags that were already sent.
    #[tokio::test]
    #[should_panic(expected = "refusing to move round backwards")]
    async fn test_synchronize_from_refuses_to_rewind() {
        let alice = Role::indexed_from_one(1);
        let bob = Role::indexed_from_one(2);
        let net_producer = LocalNetworkingProducer::from_roles(&HashSet::from([alice, bob]));
        let ahead = net_producer.user_net(alice, NetworkMode::Sync, None);
        let behind = net_producer.user_net(bob, NetworkMode::Sync, None);
        ahead.increase_round_counter().await;
        ahead.increase_round_counter().await;

        ahead.synchronize_from(&behind).await;
    }

    /// Two parties that advance their session by the same number of rounds keep
    /// their round tags aligned, so a value sent after the advance is delivered.
    /// A receiver that is one round ahead treats the value as stale and drops it.
    /// This is what makes a deterministic, identical advance on every party a
    /// requirement for the session-skew compensation.
    #[tokio::test]
    async fn test_round_tags_after_identical_advance() {
        let alice = Role::indexed_from_one(1);
        let bob = Role::indexed_from_one(2);
        let net_producer = LocalNetworkingProducer::from_roles(&HashSet::from([alice, bob]));
        let net_alice = net_producer.user_net(alice, NetworkMode::Sync, None);
        let net_bob = net_producer.user_net(bob, NetworkMode::Sync, None);
        let payload = Arc::new(vec![7u8; 4]);

        let advance = 5;
        for _ in 0..advance {
            net_alice.increase_round_counter().await;
        }

        // Same advance on the receiver: delivered.
        for _ in 0..advance {
            net_bob.increase_round_counter().await;
        }
        net_alice.send(payload.clone(), &bob).await.unwrap();
        assert_eq!(net_bob.receive(&alice).await.unwrap(), *payload);

        // Receiver one round ahead: the value is stale and is dropped, so the
        // receive does not complete.
        net_alice.increase_round_counter().await;
        net_bob.increase_round_counter().await;
        net_bob.increase_round_counter().await;
        net_alice.send(payload.clone(), &bob).await.unwrap();
        let dropped =
            tokio::time::timeout(Duration::from_millis(200), net_bob.receive(&alice)).await;
        assert!(
            dropped.is_err(),
            "a value tagged with an older round must not be delivered"
        );
    }
}

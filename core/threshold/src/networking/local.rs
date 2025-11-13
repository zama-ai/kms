use crate::error::error_handler::anyhow_error_and_log;

use super::*;
use constants::{
    NETWORK_TIMEOUT, NETWORK_TIMEOUT_ASYNC, NETWORK_TIMEOUT_BK, NETWORK_TIMEOUT_BK_SNS,
};

use dashmap::DashMap;
use futures_util::future::{join, join4};
use std::cmp::min;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::sync::{
    mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
    Mutex,
};
use tokio::time::Duration;

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
    pub init_time: OnceLock<Instant>,
    network_mode: NetworkMode,
    //If set, the party will sleep for the given duration at the start of each round
    delayed_party: Option<Duration>,
}

impl<R: RoleTrait> Default for LocalNetworking<R> {
    fn default() -> Self {
        Self {
            current_network_timeout: Mutex::new(*NETWORK_TIMEOUT),
            next_network_timeout: Mutex::new(*NETWORK_TIMEOUT),
            max_elapsed_time: Mutex::new(Duration::ZERO),
            pairwise_channels: Default::default(),
            owner: Default::default(),
            send_counter: Default::default(),
            network_round: Default::default(),
            already_sent: Default::default(),
            init_time: OnceLock::new(), // init_time will be initialized on first access
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
            NetworkMode::Sync => *NETWORK_TIMEOUT,
            NetworkMode::Async => *NETWORK_TIMEOUT_ASYNC,
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
                "Could not retrieve pairwise channels in receive call, owner: {:?}, receiver: {:?}.",
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
            std::thread::sleep(duration);
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
        // initialize init_time on first access
        // this avoids running into timeouts when large computations happen after the test runtime is set up and before the first message is received.
        let init_time = self.init_time.get_or_init(Instant::now);

        let (max_elapsed_time, network_timeout) = join(
            self.max_elapsed_time.lock(),
            self.current_network_timeout.lock(),
        )
        .await;
        *init_time + *network_timeout + *max_elapsed_time
    }

    async fn get_current_round(&self) -> usize {
        *self.network_round.lock().await
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
        self.set_timeout_for_next_round(*NETWORK_TIMEOUT_BK).await
    }

    async fn set_timeout_for_bk_sns(&self) {
        self.set_timeout_for_next_round(*NETWORK_TIMEOUT_BK_SNS)
            .await
    }

    fn get_network_mode(&self) -> NetworkMode {
        self.network_mode
    }

    #[cfg(feature = "choreographer")]
    async fn get_num_byte_sent(&self) -> usize {
        0
    }

    #[cfg(feature = "choreographer")]
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

    use crate::{
        execution::runtime::{
            party::{Role, TwoSetsRole},
            sessions::session_parameters::DeSerializationRunTime,
        },
        networking::value::NetworkValue,
    };

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
        let role_1_set_1 = TwoSetsRole::Set1(Role::indexed_from_one(1));
        let role_1_set_2 = TwoSetsRole::Set2(Role::indexed_from_one(1));

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
        assert!(error_msg
            .contains(&format!("Trying to send to {bob} in round 0 more than once !").to_string()));
    }
}

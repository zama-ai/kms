use super::*;
use anyhow::anyhow;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::Mutex;

/// A simple implementation of networking for local execution.
///
/// This implementation is intended for local development/testing purposes
/// only. It simply stores all values in a hashmap without any actual networking.
#[derive(Default)]
pub struct LocalNetworking {
    pairwise_channels: SimulatedPairwiseChannels,
    pub owner: Identity,
    pub send_counter: DashMap<Identity, usize>,
    pub network_round: Arc<Mutex<usize>>,
}

#[derive(Default)]
pub struct LocalNetworkingProducer {
    pairwise_channels: SimulatedPairwiseChannels,
}

impl LocalNetworkingProducer {
    pub fn from_ids(identities: &[Identity]) -> Self {
        let pairwise_channels = DashMap::new();
        for v1 in identities.to_owned().iter() {
            for v2 in identities.to_owned().iter() {
                if v1 != v2 {
                    let (tx, rx) = async_channel::unbounded::<LocalTaggedValue>();
                    pairwise_channels
                        .insert((v1.clone(), v2.clone()), (Arc::new(tx), Arc::new(rx)));
                }
            }
        }
        LocalNetworkingProducer {
            pairwise_channels: Arc::new(pairwise_channels),
        }
    }
    pub fn user_net(&self, owner: Identity) -> LocalNetworking {
        LocalNetworking {
            pairwise_channels: Arc::clone(&self.pairwise_channels),
            owner,
            ..Default::default()
        }
    }
}

impl LocalNetworking {
    pub fn from_identity(owner: Identity) -> Self {
        LocalNetworking {
            owner,
            ..Default::default()
        }
    }
    pub fn from_ids(owner: Identity, identities: &[Identity]) -> Self {
        let pairwise_channels = DashMap::new();
        for v1 in identities.to_owned().iter() {
            for v2 in identities.to_owned().iter() {
                if v1 != v2 {
                    let (tx, rx) = async_channel::unbounded::<LocalTaggedValue>();
                    pairwise_channels
                        .insert((v1.clone(), v2.clone()), (Arc::new(tx), Arc::new(rx)));
                }
            }
        }
        LocalNetworking {
            pairwise_channels: Arc::new(pairwise_channels),
            owner,
            ..Default::default()
        }
    }
}

type SimulatedPairwiseChannels = Arc<
    DashMap<
        (Identity, Identity),
        (
            Arc<async_channel::Sender<LocalTaggedValue>>,
            Arc<async_channel::Receiver<LocalTaggedValue>>,
        ),
    >,
>;

#[async_trait]
impl Networking for LocalNetworking {
    async fn send(
        &self,
        val: NetworkValue,
        receiver: &Identity,
        _session_id: &SessionId,
    ) -> anyhow::Result<(), anyhow::Error> {
        tracing::debug!("Async sending;");
        let (tx, _) = self
            .pairwise_channels
            .get(&(self.owner.clone(), receiver.clone()))
            .ok_or(anyhow!("Could not retrieve pairwise channels in send call"))?
            .value()
            .clone();

        let net_round = {
            match self.network_round.lock() {
                Ok(net_round) => *net_round,
                _ => panic!(),
            }
        };

        let tagged_value = LocalTaggedValue {
            send_counter: net_round,
            value: val,
        };
        tracing::debug!(
            "async sender: owner: {:?} receiver: {:?}, value: {:?}",
            self.owner,
            receiver,
            tagged_value
        );

        tx.send(tagged_value).await.map_err(|e| e.into())
    }

    async fn receive(
        &self,
        sender: &Identity,
        _session_id: &SessionId,
    ) -> anyhow::Result<NetworkValue> {
        let (_, rx) = self
            .pairwise_channels
            .get(&(sender.clone(), self.owner.clone()))
            .ok_or(anyhow!(format!(
                "Could not retrieve pairwise channels in receive call, owner: {:?}, sender: {:?}",
                self.owner, sender
            )))?
            .value()
            .clone();

        let mut tagged_value = rx.recv().await?;
        let network_round: usize = *self
            .network_round
            .lock()
            .map_err(|e| anyhow!(format!("Locking error: {:?}", e.to_string())))?;

        tracing::debug!(
            "async receiving: owner: {:?} sender: {:?}, network_round = {:?}, tagged value ctr = {:?}",
            self.owner,
            sender,
            network_round,
            tagged_value
        );

        while tagged_value.send_counter < network_round {
            tracing::debug!("Dropped value: {:?}", tagged_value);
            tagged_value = rx.recv().await?;
        }

        Ok(tagged_value.value)
    }

    async fn increase_round_counter(&self) -> anyhow::Result<()> {
        if let Ok(mut net_round) = self.network_round.lock() {
            *net_round += 1;
            tracing::debug!(
                "changed network round to: {:?} on party :{:?}",
                *net_round,
                self.owner
            );
        } else {
            return Err(anyhow!("Couldn't lock mutex"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct LocalTaggedValue {
    value: NetworkValue,
    send_counter: usize,
}

#[cfg(test)]
mod tests {
    use crate::value::Value;

    use super::*;
    use std::num::Wrapping;
    use tracing_test::traced_test;

    #[tokio::test]
    #[traced_test]
    async fn test_async_networking() {
        let identities: Vec<Identity> = vec!["alice".into(), "bob".into()];
        let net_producer = LocalNetworkingProducer::from_ids(&identities);

        let net_alice = net_producer.user_net("alice".into());
        let net_bob = net_producer.user_net("bob".into());

        let task1 = tokio::spawn(async move {
            let recv = net_bob.receive(&"alice".into(), &123_u128.into()).await;
            assert_eq!(
                recv.unwrap(),
                NetworkValue::RingValue(Value::Ring64(Wrapping::<u64>(1234)))
            );
        });

        let task2 = tokio::spawn(async move {
            let value = NetworkValue::RingValue(Value::Ring64(Wrapping::<u64>(1234)));
            net_alice.send(value, &"bob".into(), &123_u128.into()).await
        });

        let _ = tokio::try_join!(task1, task2).unwrap();
    }
}

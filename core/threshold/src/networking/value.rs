use crate::algebra::structure_traits::{Ring, Zero};
use crate::error::error_handler::anyhow_error_and_log;
#[cfg(any(test, feature = "testing"))]
use crate::execution::endpoints::keygen::FhePubKeySet;
use crate::execution::large_execution::local_double_share::MapsDoubleSharesChallenges;
use crate::execution::large_execution::local_single_share::MapsSharesChallenges;
use crate::execution::large_execution::vss::{
    ExchangedDataRound1, ValueOrPoly, VerificationValues,
};
use crate::execution::zk::ceremony;
use crate::execution::{runtime::party::Role, small_execution::prss::PartySet};
use crate::{
    commitment::{Commitment, Opening},
    execution::small_execution::prf::PrfKey,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

/// Captures network values which can (and sometimes should) be broadcast
#[derive(Serialize, Deserialize, PartialEq, Clone, Hash, Eq, Debug)]
pub enum BroadcastValue<Z: Eq + Zero> {
    Bot,
    RingVector(Vec<Z>),
    RingValue(Z),
    PRSSVotes(Vec<(PartySet, Vec<Z>)>),
    Round2VSS(Vec<VerificationValues<Z>>),
    Round3VSS(BTreeMap<(usize, Role, Role), Vec<Z>>),
    Round4VSS(BTreeMap<(usize, Role), ValueOrPoly<Z>>),
    LocalSingleShare(MapsSharesChallenges<Z>),
    LocalDoubleShare(MapsDoubleSharesChallenges<Z>),
    PartialProof(ceremony::PartialProof),
}

impl<Z: Ring> From<Z> for BroadcastValue<Z> {
    fn from(value: Z) -> Self {
        BroadcastValue::RingValue(value)
    }
}

impl<Z: Ring> From<Vec<Z>> for BroadcastValue<Z> {
    fn from(value: Vec<Z>) -> Self {
        BroadcastValue::RingVector(value)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Hash, Eq, Debug)]
pub enum AgreeRandomValue {
    CommitmentValue(Vec<Commitment>),
    KeyOpenValue(Vec<(PrfKey, Opening)>),
    KeyValue(Vec<PrfKey>),
}

/// a value that is sent via network
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub enum NetworkValue<Z: Eq + Zero> {
    #[cfg(any(test, feature = "testing"))]
    PubKeySet(Box<FhePubKeySet>),
    RingValue(Z),
    VecRingValue(Vec<Z>),
    VecPairRingValue(Vec<(Z, Z)>),
    Send(BroadcastValue<Z>),
    EchoBatch(HashMap<Role, BroadcastValue<Z>>),
    VoteBatch(HashMap<Role, BroadcastValue<Z>>),
    AgreeRandom(AgreeRandomValue),
    Bot,
    Empty,
    Round1VSS(ExchangedDataRound1<Z>),
}

impl<Z: Ring> NetworkValue<Z> {
    pub fn to_network(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap()
    }

    pub fn from_network(serialized: anyhow::Result<Vec<u8>>) -> anyhow::Result<Self> {
        bincode::deserialize::<Self>(&serialized?)
            .map_err(|_e| anyhow_error_and_log("failed to parse value"))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        algebra::base_ring::Z128,
        execution::{
            constants::SMALL_TEST_KEY_PATH, runtime::party::Identity,
            tfhe_internals::test_feature::KeySet,
        },
        file_handling::read_element,
        networking::{local::LocalNetworkingProducer, Networking},
    };

    use super::*;

    #[tokio::test]
    async fn test_box_sending() {
        let keys: KeySet = read_element(SMALL_TEST_KEY_PATH.to_string()).unwrap();

        let identities: Vec<Identity> = vec!["alice".into(), "bob".into()];
        let net_producer = LocalNetworkingProducer::from_ids(&identities);
        let pk = keys.public_keys.clone();
        let value = NetworkValue::<Z128>::PubKeySet(Box::new(keys.public_keys));

        let net_alice = net_producer.user_net("alice".into());
        let net_bob = net_producer.user_net("bob".into());

        let task1 = tokio::spawn(async move {
            let recv = net_bob.receive(&"alice".into(), &123_u128.into()).await;
            let received_key = match NetworkValue::<Z128>::from_network(recv) {
                Ok(NetworkValue::PubKeySet(key)) => key,
                _ => panic!(),
            };
            assert_eq!(*received_key, pk);
        });

        let task2 = tokio::spawn(async move {
            net_alice
                .send(value.to_network(), &"bob".into(), &123_u128.into())
                .await
        });

        let _ = tokio::try_join!(task1, task2).unwrap();
    }
}

use crate::algebra::structure_traits::{Ring, Zero};
use crate::error::error_handler::anyhow_error_and_log;
use crate::execution::large_execution::local_double_share::MapsDoubleSharesChallenges;
use crate::execution::large_execution::local_single_share::MapsSharesChallenges;
use crate::execution::large_execution::vss::{
    ExchangedDataRound1, ValueOrPoly, VerificationValues,
};
use crate::execution::runtime::session::DeSerializationRunTime;
#[cfg(any(test, feature = "testing"))]
use crate::execution::tfhe_internals::public_keysets::FhePubKeySet;
use crate::execution::zk::ceremony;
use crate::execution::{runtime::party::Role, small_execution::prss::PartySet};
#[cfg(feature = "experimental")]
use crate::experimental::bgv::basics::PublicBgvKeySet;
use crate::hashing::{serialize_hash_element, DomainSep};
use crate::thread_handles::spawn_compute_bound;
use crate::{
    commitment::{Commitment, Opening},
    execution::small_execution::prf::PrfKey,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::time::SystemTime;
#[cfg(any(test, feature = "testing"))]
use tfhe::zk::CompactPkeCrs;

pub(crate) const BCAST_HASH_BYTE_LEN: usize = 32;
pub(crate) type BcastHash = [u8; BCAST_HASH_BYTE_LEN];

const DSEP_BRACH: DomainSep = *b"BRACHABC";

/// Captures network values which can (and sometimes should) be broadcast.
///
/// Developers:
/// ensure the (de)serialization for the types here are not expensive
/// since the same message might be deserialized multiple times
/// from different parties.
/// It is also important to ensure that types are of constant size across systems,
/// since the raw data will be hashed. In particular this means that `usize` CANNOT be used any types.
#[derive(Serialize, Deserialize, PartialEq, Clone, Hash, Eq, Debug)]
pub struct BroadcastValue<Z: Eq + Zero + Sized> {
    pub(crate) inner: BroadcastValueInner<Z>,

    /// This timestamp should not be set manually, it is set automatically
    /// by the broadcast protocol when the message is ready to be sent.
    pub(crate) timestamp: Option<SystemTime>,
}

impl<Z: Eq + Zero + Sized> BroadcastValue<Z> {
    pub(crate) fn new(inner: BroadcastValueInner<Z>) -> Self {
        Self {
            inner,
            timestamp: None,
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Hash, Eq, Debug)]
pub(crate) enum BroadcastValueInner<Z: Eq + Zero + Sized> {
    Bot,
    RingVector(Vec<Z>),
    RingValue(Z),
    PRSSVotes(Vec<(PartySet, Vec<Z>)>),
    Round2VSS(Vec<VerificationValues<Z>>),
    Round3VSS(BTreeMap<(Role, Role, Role), Vec<Z>>),
    Round4VSS(BTreeMap<(Role, Role), ValueOrPoly<Z>>),
    LocalSingleShare(MapsSharesChallenges<Z>),
    LocalDoubleShare(MapsDoubleSharesChallenges<Z>),
    PartialProof(ceremony::PartialProof),
}

impl<Z: Eq + Zero + Sized> BroadcastValue<Z> {
    pub fn type_name(&self) -> String {
        match self.inner {
            BroadcastValueInner::Bot => "Bot".to_string(),
            BroadcastValueInner::RingVector(_) => "RingVector".to_string(),
            BroadcastValueInner::RingValue(_) => "RingValue".to_string(),
            BroadcastValueInner::PRSSVotes(_) => "PRSSVotes".to_string(),
            BroadcastValueInner::Round2VSS(_) => "Round2VSS".to_string(),
            BroadcastValueInner::Round3VSS(_) => "Round3VSS".to_string(),
            BroadcastValueInner::Round4VSS(_) => "Round4VSS".to_string(),
            BroadcastValueInner::LocalSingleShare(_) => "LocalSingleShare".to_string(),
            BroadcastValueInner::LocalDoubleShare(_) => "LocalDoubleShare".to_string(),
            BroadcastValueInner::PartialProof(_) => "PartialProof".to_string(),
        }
    }
}

impl<Z: Eq + Zero + Serialize> BroadcastValue<Z> {
    pub fn to_bcast_hash(&self) -> Result<BcastHash, anyhow::Error> {
        // Note that we are implicitly assuming that the serialization of a broadcast value ensure uniqueness
        // IMPORTANT: use self.inner and not self because self contains a timestamp which may be different between messagees
        let digest = serialize_hash_element(&DSEP_BRACH, &self.inner)
            .map_err(|e| anyhow::anyhow!("Could not serialize and hash message: {}", e))?;
        digest
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid hash length for broadcast hash"))
    }
}

impl<Z: Ring> From<Z> for BroadcastValue<Z> {
    fn from(value: Z) -> Self {
        Self {
            inner: BroadcastValueInner::RingValue(value),
            timestamp: None,
        }
    }
}

impl<Z: Ring> From<Vec<Z>> for BroadcastValue<Z> {
    fn from(value: Vec<Z>) -> Self {
        Self {
            inner: BroadcastValueInner::RingVector(value),
            timestamp: None,
        }
    }
}

impl<Z: Ring> From<(Vec<Z>, SystemTime)> for BroadcastValue<Z> {
    fn from(value: (Vec<Z>, SystemTime)) -> Self {
        Self {
            inner: BroadcastValueInner::RingVector(value.0),
            timestamp: Some(value.1),
        }
    }
}

impl<Z: Ring> From<Vec<(PartySet, Vec<Z>)>> for BroadcastValue<Z> {
    fn from(value: Vec<(PartySet, Vec<Z>)>) -> Self {
        Self {
            inner: BroadcastValueInner::PRSSVotes(value),
            timestamp: None,
        }
    }
}

impl<Z: Ring> From<Vec<VerificationValues<Z>>> for BroadcastValue<Z> {
    fn from(value: Vec<VerificationValues<Z>>) -> Self {
        Self {
            inner: BroadcastValueInner::Round2VSS(value),
            timestamp: None,
        }
    }
}

impl<Z: Ring> From<BTreeMap<(Role, Role, Role), Vec<Z>>> for BroadcastValue<Z> {
    fn from(value: BTreeMap<(Role, Role, Role), Vec<Z>>) -> Self {
        Self {
            inner: BroadcastValueInner::Round3VSS(value),
            timestamp: None,
        }
    }
}

impl<Z: Ring> From<BTreeMap<(Role, Role), ValueOrPoly<Z>>> for BroadcastValue<Z> {
    fn from(value: BTreeMap<(Role, Role), ValueOrPoly<Z>>) -> Self {
        Self {
            inner: BroadcastValueInner::Round4VSS(value),
            timestamp: None,
        }
    }
}

impl<Z: Ring> From<MapsSharesChallenges<Z>> for BroadcastValue<Z> {
    fn from(value: MapsSharesChallenges<Z>) -> Self {
        Self {
            inner: BroadcastValueInner::LocalSingleShare(value),
            timestamp: None,
        }
    }
}

impl<Z: Ring> From<MapsDoubleSharesChallenges<Z>> for BroadcastValue<Z> {
    fn from(value: MapsDoubleSharesChallenges<Z>) -> Self {
        Self {
            inner: BroadcastValueInner::LocalDoubleShare(value),
            timestamp: None,
        }
    }
}

impl<Z: Ring> From<ceremony::PartialProof> for BroadcastValue<Z> {
    fn from(value: ceremony::PartialProof) -> Self {
        Self {
            inner: BroadcastValueInner::PartialProof(value),
            timestamp: None,
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Hash, Eq, Debug)]
pub enum AgreeRandomValue {
    CommitmentValue(Vec<Commitment>),
    KeyOpenValue(Vec<(PrfKey, Opening)>),
    KeyValue(Vec<PrfKey>),
}

/// a value that is sent via network
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum NetworkValue<Z: Eq + Zero> {
    #[cfg(any(test, feature = "testing"))]
    PubKeySet(Box<FhePubKeySet>),
    #[cfg(feature = "experimental")]
    PubBgvKeySet(Box<PublicBgvKeySet>),
    #[cfg(any(test, feature = "testing"))]
    Crs(Box<CompactPkeCrs>),
    #[cfg(any(test, feature = "testing"))]
    DecompressionKey(Box<tfhe::integer::compression_keys::DecompressionKey>),
    #[cfg(any(test, feature = "testing"))]
    SnsCompressionKey(Box<tfhe::shortint::list_compression::NoiseSquashingCompressionKey>),
    RingValue(Z),
    VecRingValue(Vec<Z>),
    VecPairRingValue(Vec<(Z, Z)>),
    Send(BroadcastValue<Z>),
    EchoBatch(HashMap<Role, BroadcastValue<Z>>),
    VoteBatch(HashMap<Role, BcastHash>),
    AgreeRandom(AgreeRandomValue),
    Bot,
    Empty,
    Round1VSS(ExchangedDataRound1<Z>),
}

impl<Z: Eq + Zero> AsRef<NetworkValue<Z>> for NetworkValue<Z> {
    fn as_ref(&self) -> &NetworkValue<Z> {
        self
    }
}

impl<Z: Ring> NetworkValue<Z> {
    // Note we do not offload the serialization to rayon as
    // benchmark show serialization is fast
    // and sending to rayon implies a clone which makes it significantly slower
    pub fn to_network(&self) -> Vec<u8> {
        bc2wrap::serialize(self).unwrap()
    }

    pub async fn from_network(
        serialized: anyhow::Result<Vec<u8>>,
        serialization_runtime: DeSerializationRunTime,
    ) -> anyhow::Result<Self> {
        match serialization_runtime {
            DeSerializationRunTime::Tokio => bc2wrap::deserialize_safe::<Self>(&serialized?)
                .map_err(|_e| anyhow_error_and_log("failed to parse value")),
            DeSerializationRunTime::Rayon => {
                // offload to rayon threadpool
                spawn_compute_bound(move || {
                    bc2wrap::deserialize_safe::<Self>(&serialized?)
                        .map_err(|_e| anyhow_error_and_log("failed to parse value"))
                })
                .await?
            }
        }
    }
}

impl<Z: Eq + Zero> NetworkValue<Z> {
    pub fn network_type_name(&self) -> String {
        match self {
            #[cfg(any(test, feature = "testing"))]
            NetworkValue::PubKeySet(_) => "PubKeySet".to_string(),
            #[cfg(feature = "experimental")]
            NetworkValue::PubBgvKeySet(_) => "PubBgvKeySet".to_string(),
            #[cfg(any(test, feature = "testing"))]
            NetworkValue::Crs(_) => "Crs".to_string(),
            #[cfg(any(test, feature = "testing"))]
            NetworkValue::DecompressionKey(_) => "DecompressionKey".to_string(),
            #[cfg(any(test, feature = "testing"))]
            NetworkValue::SnsCompressionKey(_) => "SnsCompressionKey".to_string(),
            NetworkValue::RingValue(_) => "RingValue".to_string(),
            NetworkValue::VecRingValue(_) => "VecRingValue".to_string(),
            NetworkValue::VecPairRingValue(_) => "VecPairRingValue".to_string(),
            NetworkValue::Send(_) => "Send".to_string(),
            NetworkValue::EchoBatch(_) => "EchoBatch".to_string(),
            NetworkValue::VoteBatch(_) => "VoteBatch".to_string(),
            NetworkValue::AgreeRandom(_) => "AgreeRandom".to_string(),
            NetworkValue::Bot => "Bot".to_string(),
            NetworkValue::Empty => "Empty".to_string(),
            NetworkValue::Round1VSS(_) => "Round1VSS".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        algebra::base_ring::Z128,
        execution::{constants::SMALL_TEST_KEY_PATH, tfhe_internals::test_feature::KeySet},
        file_handling::tests::read_element,
        networking::{local::LocalNetworkingProducer, NetworkMode, Networking},
    };
    use std::collections::HashSet;

    #[tokio::test]
    async fn test_box_sending() {
        let keys: KeySet = read_element(SMALL_TEST_KEY_PATH).unwrap();
        let alice = Role::indexed_from_one(1);
        let bob = Role::indexed_from_one(2);
        let roles = HashSet::from([alice, bob]);
        let net_producer = LocalNetworkingProducer::from_roles(&roles);
        let pk = keys.public_keys.clone();
        let value = NetworkValue::<Z128>::PubKeySet(Box::new(keys.public_keys));

        let net_alice = net_producer.user_net(alice, NetworkMode::Sync, None);
        let net_bob = net_producer.user_net(bob, NetworkMode::Sync, None);

        let task1 = tokio::spawn(async move {
            let recv = net_bob.receive(&alice).await;
            let received_key =
                match NetworkValue::<Z128>::from_network(recv, DeSerializationRunTime::Tokio).await
                {
                    Ok(NetworkValue::PubKeySet(key)) => key,
                    _ => panic!(),
                };
            assert_eq!(*received_key, pk);
        });

        let task2 = tokio::spawn(async move {
            net_alice
                .send(Arc::new(value.to_network()), &bob.clone())
                .await
        });

        let _ = tokio::try_join!(task1, task2).unwrap();
    }
}

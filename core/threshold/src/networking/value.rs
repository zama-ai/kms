use crate::algebra::structure_traits::{Ring, Zero};
use crate::error::error_handler::anyhow_error_and_log;
use crate::execution::large_execution::local_double_share::MapsDoubleSharesChallenges;
use crate::execution::large_execution::local_single_share::MapsSharesChallenges;
use crate::execution::large_execution::vss::{
    ExchangedDataRound1, ValueOrPoly, VerificationValues,
};
#[cfg(any(test, feature = "testing"))]
use crate::execution::tfhe_internals::public_keysets::FhePubKeySet;
use crate::execution::zk::ceremony;
use crate::execution::{runtime::party::Role, small_execution::prss::PartySet};
#[cfg(feature = "experimental")]
use crate::experimental::bgv::basics::PublicBgvKeySet;
use crate::hashing::{serialize_hash_element, DomainSep};
use crate::{
    commitment::{Commitment, Opening},
    execution::small_execution::prf::PrfKey,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
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
pub enum BroadcastValue<Z: Eq + Zero + Sized> {
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
        match self {
            BroadcastValue::Bot => "Bot".to_string(),
            BroadcastValue::RingVector(_) => "RingVector".to_string(),
            BroadcastValue::RingValue(_) => "RingValue".to_string(),
            BroadcastValue::PRSSVotes(_) => "PRSSVotes".to_string(),
            BroadcastValue::Round2VSS(_) => "Round2VSS".to_string(),
            BroadcastValue::Round3VSS(_) => "Round3VSS".to_string(),
            BroadcastValue::Round4VSS(_) => "Round4VSS".to_string(),
            BroadcastValue::LocalSingleShare(_) => "LocalSingleShare".to_string(),
            BroadcastValue::LocalDoubleShare(_) => "LocalDoubleShare".to_string(),
            BroadcastValue::PartialProof(_) => "PartialProof".to_string(),
        }
    }
}

impl<Z: Eq + Zero + Serialize> BroadcastValue<Z> {
    pub fn to_bcast_hash(&self) -> Result<BcastHash, anyhow::Error> {
        // Note that we are implicitly assuming that the serialization of a broadcast value ensure uniqueness
        let digest = serialize_hash_element(&DSEP_BRACH, &self)
            .map_err(|e| anyhow::anyhow!("Could not serialize and hash message: {}", e))?;
        digest
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid hash length for broadcast hash"))
    }
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
    pub fn to_network(&self) -> Vec<u8> {
        bc2wrap::serialize(self).unwrap()
    }

    pub fn from_network(serialized: anyhow::Result<Vec<u8>>) -> anyhow::Result<Self> {
        bc2wrap::deserialize::<Self>(&serialized?)
            .map_err(|_e| anyhow_error_and_log("failed to parse value"))
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
            let received_key = match NetworkValue::<Z128>::from_network(recv) {
                Ok(NetworkValue::PubKeySet(key)) => key,
                _ => panic!(),
            };
            assert_eq!(*received_key, pk);
        });

        let task2 = tokio::spawn(async move { net_alice.send(value.to_network(), &bob).await });

        let _ = tokio::try_join!(task1, task2).unwrap();
    }
}

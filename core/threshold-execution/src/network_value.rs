use crate::tfhe_internals::public_keysets::FhePubKeySet;
use crate::{
    large_execution::{
        local_double_share::MapsDoubleSharesChallenges,
        local_single_share::MapsSharesChallenges,
        vss::{ExchangedDataRound1, ValueOrPoly, VerificationValues},
    },
    runtime::sessions::session_parameters::DeSerializationRunTime,
    small_execution::{prf::PrfKey, prss::PartySet},
    zk::ceremony,
};
use algebra::structure_traits::{Ring, Zero};
use bytes::Bytes;
use error_utils::anyhow_error_and_log;
use hashing::{DomainSep, serialize_hash_element};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use tfhe::zk::CompactPkeCrs;
use thread_handles::spawn_compute_bound;
use threshold_types::commitment::{Commitment, Opening};
use threshold_types::role::Role;

pub(crate) const BCAST_HASH_BYTE_LEN: usize = 32;
pub(crate) type BcastHash = [u8; BCAST_HASH_BYTE_LEN];

const DSEP_BRACH: DomainSep = *b"BRACHABC";

/// Whether this build may send and receive the testing-only [`NetworkValue`] variants.
const TESTING_BUILD: bool = cfg!(any(test, feature = "testing"));

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
    /// Batched check-value maps for a `LocalSingleShare` verification: one
    /// [`MapsSharesChallenges`] per challenge index `g in 0..m`, broadcast in a
    /// single parallel round (see `local_single_share::verify_sharing`).
    LocalSingleShare(Vec<MapsSharesChallenges<Z>>),
    /// Batched check-value maps for a `LocalDoubleShare` verification: one
    /// [`MapsDoubleSharesChallenges`] per challenge index `g in 0..m`, broadcast
    /// in a single parallel round (see `local_double_share::verify_sharing`).
    LocalDoubleShare(Vec<MapsDoubleSharesChallenges<Z>>),
    PartialProof(ceremony::PartialProof),
    MapRingVector(BTreeMap<Role, Vec<Z>>),
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
            BroadcastValue::MapRingVector(_) => "MapRingVector".to_string(),
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

/// A value that is sent via network.
///
/// IMPORTANT: when adding new _test_ variants, they must be added to the *end*
/// of the enum for bincode to behave in a backward compatible way.
/// When adding production variants, they must also be added to the *end* of
/// the production variants, but _before_ the test variants, i.e. between
/// `Round1VSS` and `CompressedXofKeySet`.
/// Otherwise we will have issues when performing a rolling upgrade.
///
/// The test variants are `PubKeySet`, `Crs`, `DecompressionKey`,
/// `SnsCompressionKey` and `CompressedXofKeySet` exist in every build, so that
/// testing and production builds use the same variant indices. Only a testing
/// build may send or receive them.
#[derive(Serialize, Deserialize, Clone)]
pub enum NetworkValue<Z: Eq + Zero> {
    PubKeySet(Box<FhePubKeySet>),
    Crs(Box<CompactPkeCrs>),
    DecompressionKey(Box<tfhe::integer::compression_keys::DecompressionKey>),
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
    CompressedXofKeySet(Box<tfhe::xof_key_set::CompressedXofKeySet>),
}

impl<Z: Eq + Zero + std::fmt::Debug> std::fmt::Debug for NetworkValue<Z> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkValue::PubKeySet(_pk) => f
                .debug_tuple(self.network_type_name())
                .field(&"...")
                .finish(),
            NetworkValue::Crs(_crs) => f
                .debug_tuple(self.network_type_name())
                .field(&"...")
                .finish(),
            NetworkValue::DecompressionKey(_) => f
                .debug_tuple(self.network_type_name())
                .field(&"...")
                .finish(),
            NetworkValue::SnsCompressionKey(_) => f
                .debug_tuple(self.network_type_name())
                .field(&"...")
                .finish(),
            NetworkValue::RingValue(v) => f.debug_tuple(self.network_type_name()).field(v).finish(),
            NetworkValue::VecRingValue(v) => {
                f.debug_tuple(self.network_type_name()).field(v).finish()
            }
            NetworkValue::VecPairRingValue(v) => {
                f.debug_tuple(self.network_type_name()).field(v).finish()
            }
            NetworkValue::Send(v) => f.debug_tuple(self.network_type_name()).field(v).finish(),
            NetworkValue::EchoBatch(v) => f.debug_tuple(self.network_type_name()).field(v).finish(),
            NetworkValue::VoteBatch(v) => f.debug_tuple(self.network_type_name()).field(v).finish(),
            NetworkValue::AgreeRandom(v) => {
                f.debug_tuple(self.network_type_name()).field(v).finish()
            }
            NetworkValue::Bot => f.write_str(self.network_type_name()),
            NetworkValue::Empty => f.write_str(self.network_type_name()),
            NetworkValue::Round1VSS(v) => f.debug_tuple(self.network_type_name()).field(v).finish(),
            NetworkValue::CompressedXofKeySet(_) => f
                .debug_tuple(self.network_type_name())
                .field(&"...")
                .finish(),
        }
    }
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
    //
    // Returned as `Bytes` (wrapping the serialized `Vec` without copying) so the
    // result can be sent to several parties, and retried, with refcount clones only.
    //
    // Returns an error if a production build tries to send a testing-only variant,
    // or if serialization fails.
    pub fn to_network(&self) -> anyhow::Result<Bytes> {
        self.ensure_allowed(TESTING_BUILD)?;
        let serialized = bc2wrap::serialize(self)
            .map_err(|e| anyhow_error_and_log(format!("failed to serialize value: {e}")))?;
        Ok(Bytes::from(serialized))
    }

    pub async fn from_network(
        serialized: anyhow::Result<Bytes>,
        serialization_runtime: DeSerializationRunTime,
    ) -> anyhow::Result<Self> {
        let value = match serialization_runtime {
            DeSerializationRunTime::Tokio => bc2wrap::deserialize_slice::<Self>(&serialized?)
                .map_err(|_e| anyhow_error_and_log("failed to parse value")),
            DeSerializationRunTime::Rayon => {
                // offload to rayon threadpool
                spawn_compute_bound(move || {
                    bc2wrap::deserialize_slice::<Self>(&serialized?)
                        .map_err(|_e| anyhow_error_and_log("failed to parse value"))
                })
                .await?
            }
        }?;
        value.ensure_allowed(TESTING_BUILD)?;
        Ok(value)
    }
}

impl<Z: Eq + Zero> NetworkValue<Z> {
    /// Returns an error if `self` is a testing-only variant and `testing_build` is false.
    fn ensure_allowed(&self, testing_build: bool) -> anyhow::Result<()> {
        if !testing_build {
            match self {
                NetworkValue::RingValue(_)
                | NetworkValue::VecRingValue(_)
                | NetworkValue::VecPairRingValue(_)
                | NetworkValue::Send(_)
                | NetworkValue::EchoBatch(_)
                | NetworkValue::VoteBatch(_)
                | NetworkValue::AgreeRandom(_)
                | NetworkValue::Bot
                | NetworkValue::Empty
                | NetworkValue::Round1VSS(_) => {} // production values
                _ => {
                    return Err(anyhow_error_and_log(format!(
                        "network value {} is only allowed in testing builds",
                        self.network_type_name()
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn network_type_name(&self) -> &str {
        match self {
            NetworkValue::PubKeySet(_) => "PubKeySet",
            NetworkValue::Crs(_) => "Crs",
            NetworkValue::DecompressionKey(_) => "DecompressionKey",
            NetworkValue::SnsCompressionKey(_) => "SnsCompressionKey",
            NetworkValue::RingValue(_) => "RingValue",
            NetworkValue::VecRingValue(_) => "VecRingValue",
            NetworkValue::VecPairRingValue(_) => "VecPairRingValue",
            NetworkValue::Send(_) => "Send",
            NetworkValue::EchoBatch(_) => "EchoBatch",
            NetworkValue::VoteBatch(_) => "VoteBatch",
            NetworkValue::AgreeRandom(_) => "AgreeRandom",
            NetworkValue::Bot => "Bot",
            NetworkValue::Empty => "Empty",
            NetworkValue::Round1VSS(_) => "Round1VSS",
            NetworkValue::CompressedXofKeySet(_) => "CompressedXofKeySet",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        constants::SMALL_TEST_KEY_PATH, tests::ensure_test_data_setup,
        tfhe_internals::test_feature::KeySet,
    };
    use algebra::base_ring::Z128;
    use std::{collections::HashSet, num::Wrapping};
    use test_utils::read_element;
    use threshold_networking::local::LocalNetworkingProducer;
    use threshold_types::network::{NetworkMode, Networking};

    /// The variant indices must stay the same as in v0.14.2, which was built with the testing
    /// feature.
    #[test]
    fn test_serialization_matches_released_layout() {
        let ring: Z128 = Wrapping(42);
        let role = Role::indexed_from_one(1);
        let cases: Vec<(u32, NetworkValue<Z128>)> = vec![
            (4, NetworkValue::RingValue(ring)),
            (5, NetworkValue::VecRingValue(vec![ring])),
            (6, NetworkValue::VecPairRingValue(vec![(ring, ring)])),
            (7, NetworkValue::Send(BroadcastValue::Bot)),
            (
                8,
                NetworkValue::EchoBatch(HashMap::from([(role, BroadcastValue::RingValue(ring))])),
            ),
            (
                9,
                NetworkValue::VoteBatch(HashMap::from([(role, [7u8; BCAST_HASH_BYTE_LEN])])),
            ),
            (
                10,
                NetworkValue::AgreeRandom(AgreeRandomValue::KeyValue(vec![])),
            ),
            (11, NetworkValue::Bot),
            (12, NetworkValue::Empty),
            (
                13,
                NetworkValue::Round1VSS(ExchangedDataRound1::default(1, 1)),
            ),
        ];
        for (index, value) in cases {
            assert_eq!(
                value.to_network().unwrap()[..4],
                bc2wrap::serialize(&index).unwrap()[..],
                "{}",
                value.network_type_name()
            );
        }

        // The payload follows the variant index directly.
        assert_eq!(
            NetworkValue::RingValue(ring).to_network().unwrap()[..],
            [
                bc2wrap::serialize(&4).unwrap(),
                bc2wrap::serialize(&ring).unwrap()
            ]
            .concat()[..]
        );
    }

    /// A production build must reject the testing-only variants and accept the other variants.
    #[test]
    fn test_production_rejects_testing_only_values() {
        ensure_test_data_setup();
        let keys: KeySet = read_element(SMALL_TEST_KEY_PATH).unwrap();
        let pub_key_set = NetworkValue::<Z128>::PubKeySet(Box::new(keys.public_keys));
        assert!(pub_key_set.ensure_allowed(false).is_err());
        assert!(pub_key_set.ensure_allowed(true).is_ok());
        // This test runs in a testing build, so sending must succeed.
        assert!(pub_key_set.to_network().is_ok());

        let ring: Z128 = Wrapping(42);
        for value in [
            NetworkValue::RingValue(ring),
            NetworkValue::Send(BroadcastValue::Bot),
            NetworkValue::Bot,
            NetworkValue::Empty,
        ] {
            assert!(
                value.ensure_allowed(false).is_ok(),
                "{}",
                value.network_type_name()
            );
        }
    }

    #[tokio::test]
    async fn test_box_sending() {
        ensure_test_data_setup();
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
                .send(value.to_network().unwrap(), &bob.clone())
                .await
        });

        let _ = tokio::try_join!(task1, task2).unwrap();
    }
}

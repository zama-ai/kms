use crate::error::error_handler::anyhow_error_and_log;
use crate::execution::{party::Role, small_execution::prss::PsiSet};
use crate::lwe::PubConKeyPair;
use crate::residue_poly::ResiduePoly;
use crate::shamir::ShamirGSharings;
use crate::sharing::vss::ValueOrPoly;
use crate::{
    commitment::{Commitment, Opening},
    execution::{session::DisputePayload, small_execution::prss::PrfKey},
};
use crate::{Z128, Z64};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    num::Wrapping,
};

/// a collection of shares
#[derive(Serialize, Deserialize, PartialEq, Clone, Hash, Eq, Debug)]
pub enum Value {
    Poly64(ResiduePoly<Z64>),
    Poly128(ResiduePoly<Z128>),
    Ring64(Z64),
    Ring128(Z128),
    U64(u64),
}

impl From<u128> for Value {
    fn from(value: u128) -> Self {
        Value::Ring128(Wrapping(value))
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Hash, Eq, Debug)]
pub struct IndexedValue {
    pub party_id: usize,
    pub value: Value,
}

/// Captures network values which can (and sometimes should) be broadcast
#[derive(Serialize, Deserialize, PartialEq, Clone, Hash, Eq, Debug)]
pub enum BroadcastValue {
    RingVector(Vec<Value>),
    RingValue(Value),
    PRSSVotes(Vec<(PsiSet, Value)>),
    AddDispute(DisputePayload),
    Round2VSS(Vec<crate::sharing::vss::VerificationValues>),
    Round3VSS(BTreeMap<(usize, Role, Role), ResiduePoly<Z128>>),
    Round4VSS(BTreeMap<(usize, Role), ValueOrPoly>),
    LocalSingleShare(crate::sharing::local_single_share::MapsSharesChallenges),
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Hash, Eq, Debug)]

pub enum AgreeRandomValue {
    CommitmentValue(Vec<Commitment>),
    KeyOpenValue(Vec<(PrfKey, Opening)>),
}

impl From<Value> for BroadcastValue {
    fn from(value: Value) -> Self {
        BroadcastValue::RingValue(value)
    }
}
impl From<Vec<Value>> for BroadcastValue {
    fn from(value: Vec<Value>) -> Self {
        BroadcastValue::RingVector(value)
    }
}

/// a value that is sent via network
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub enum NetworkValue {
    PubKey(Box<PubConKeyPair>),
    RingValue(Value),
    VecRingValue(Vec<Value>),
    VecPairRingValue(Vec<(Value, Value)>),
    Send(BroadcastValue),
    EchoBatch(HashMap<Role, BroadcastValue>),
    VoteBatch(HashMap<Role, BroadcastValue>),
    AgreeRandom(AgreeRandomValue),
    Bot,
    Empty,
    Round1VSS(crate::sharing::vss::ExchangedDataRound1),
}

pub fn err_reconstruct(
    shares: &Vec<IndexedValue>,
    threshold: usize,
    max_error_count: usize,
) -> anyhow::Result<Value> {
    if shares.is_empty() {
        return Err(anyhow_error_and_log(
            "Input to reconstruction is empty".to_string(),
        ));
    }
    match shares[0].value {
        Value::Poly64(_) => {
            let stripped_shares: Vec<_> = shares
                .iter()
                .filter_map(|v| match v.value {
                    Value::Poly64(vv) => Some((v.party_id, vv)),
                    _ => None,
                })
                .collect();
            if stripped_shares.len() != shares.len() {
                Err(anyhow_error_and_log(
                    "Mixed types when reconstructing, expected to be Ring64".to_string(),
                ))
            } else {
                Ok(Value::Poly64(ShamirGSharings::<Z64>::err_reconstruct(
                    &ShamirGSharings {
                        shares: stripped_shares,
                    },
                    threshold,
                    max_error_count,
                )?))
            }
        }
        Value::Poly128(_) => {
            let stripped_shares: Vec<_> = shares
                .iter()
                .filter_map(|v| match v.value {
                    Value::Poly128(vv) => Some((v.party_id, vv)),
                    _ => None,
                })
                .collect();
            if stripped_shares.len() != shares.len() {
                Err(anyhow_error_and_log(
                    "Mixed types when reconstructing, expected to be Ring128".to_string(),
                ))
            } else {
                Ok(Value::Poly128(ShamirGSharings::<Z128>::err_reconstruct(
                    &ShamirGSharings {
                        shares: stripped_shares,
                    },
                    threshold,
                    max_error_count,
                )?))
            }
        }
        _ => Err(anyhow_error_and_log(
            "Cannot reconstruct when types are not indexed shares".to_string(),
        )),
    }
}
#[cfg(test)]
mod tests {
    use crate::{
        execution::party::Identity,
        file_handling::read_element,
        lwe::{KeySet, PubConKeyPair},
        networking::{local::LocalNetworkingProducer, Networking},
        tests::test_data_setup::tests::TEST_KEY_PATH,
    };

    use super::*;

    #[tokio::test]
    async fn test_box_sending() {
        let keys: KeySet = read_element(TEST_KEY_PATH.to_string()).unwrap();
        let pck = PubConKeyPair::new(keys);
        let value = NetworkValue::PubKey(Box::new(pck.clone()));

        let identities: Vec<Identity> = vec!["alice".into(), "bob".into()];
        let net_producer = LocalNetworkingProducer::from_ids(&identities);

        let net_alice = net_producer.user_net("alice".into());
        let net_bob = net_producer.user_net("bob".into());

        let task1 = tokio::spawn(async move {
            let recv = net_bob.receive(&"alice".into(), &123_u128.into()).await;
            let received_key = match recv {
                Ok(NetworkValue::PubKey(key)) => key,
                _ => panic!(),
            };
            assert_eq!(received_key.pk, pck.pk);
            assert_eq!(received_key.ck, pck.ck);
        });

        let task2 =
            tokio::spawn(
                async move { net_alice.send(value, &"bob".into(), &123_u128.into()).await },
            );

        let _ = tokio::try_join!(task1, task2).unwrap();
    }
}

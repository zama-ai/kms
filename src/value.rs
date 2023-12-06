use crate::execution::{party::Role, small_execution::prss::PartySet};
use crate::lwe::PubConKeyPair;
use crate::residue_poly::ResiduePoly;
use crate::shamir::ShamirGSharings;
use crate::sharing::vss::ValueOrPoly;
use crate::{
    commitment::{Commitment, Opening},
    execution::{session::DisputePayload, small_execution::prss::PrfKey},
};
use crate::{error::error_handler::anyhow_error_and_log, residue_poly::F_DEG};
use crate::{Zero, Z128, Z64};
use itertools::Itertools;
use num_traits::ToBytes;
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
    Empty,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RingType {
    GalExtRing64,
    GalExtRing128,
    Ring64,
    Ring128,
}

impl Value {
    pub fn ty(&self) -> anyhow::Result<RingType> {
        match self {
            Value::Poly64(_) => Ok(RingType::GalExtRing64),
            Value::Poly128(_) => Ok(RingType::GalExtRing128),
            Value::Ring64(_) => Ok(RingType::Ring64),
            Value::Ring128(_) => Ok(RingType::Ring128),
            _ => Err(anyhow_error_and_log("Not a ring".to_string())),
        }
    }
}

impl From<u64> for Value {
    fn from(value: u64) -> Self {
        Value::Ring64(Wrapping(value))
    }
}
impl From<u128> for Value {
    fn from(value: u128) -> Self {
        Value::Ring128(Wrapping(value))
    }
}
impl From<ResiduePoly<Z64>> for Value {
    fn from(value: ResiduePoly<Z64>) -> Self {
        Value::Poly64(value)
    }
}
impl From<ResiduePoly<Z128>> for Value {
    fn from(value: ResiduePoly<Z128>) -> Self {
        Value::Poly128(value)
    }
}

impl Value {
    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            Value::Poly64(val) => {
                let size = F_DEG * u64::BITS as usize / 8;
                let mut res = Vec::with_capacity(size);
                for i in 0..F_DEG {
                    res.append(&mut val.coefs[i].0.to_be_bytes().to_vec());
                }
                res
            }
            Value::Poly128(val) => {
                let size = F_DEG * u128::BITS as usize / 8;
                let mut res = Vec::with_capacity(size);
                for i in 0..F_DEG {
                    res.append(&mut val.coefs[i].0.to_be_bytes().to_vec());
                }
                res
            }
            Value::Ring64(val) => val.0.to_be_bytes().to_vec(),
            Value::Ring128(val) => val.0.to_be_bytes().to_vec(),
            Value::U64(val) => val.to_be_bytes().to_vec(),
            Value::Empty => [0_u8; 0].to_vec(),
        }
    }
}

// TODO this struct is now fully captured by [Share] and hence this type should be removed at next refactoring.
#[derive(Serialize, Deserialize, PartialEq, Clone, Hash, Eq, Debug)]
pub struct IndexedValue {
    pub party_id: usize,
    pub value: Value,
}

/// Captures network values which can (and sometimes should) be broadcast
#[derive(Serialize, Deserialize, PartialEq, Clone, Hash, Eq, Debug)]
pub enum BroadcastValue {
    Bot,
    RingVector(Vec<Value>),
    RingValue(Value),
    PRSSVotes(Vec<(PartySet, Vec<Value>)>),
    AddDispute(DisputePayload),
    Round2VSS(Vec<crate::sharing::vss::VerificationValues>),
    Round3VSS(BTreeMap<(usize, Role, Role), ResiduePoly<Z128>>),
    Round4VSS(BTreeMap<(usize, Role), ValueOrPoly>),
    LocalSingleShare(crate::sharing::local_single_share::MapsSharesChallenges),
    LocalDoubleShare(crate::sharing::local_double_share::MapsDoubleSharesChallenges),
}

impl From<u64> for BroadcastValue {
    fn from(value: u64) -> Self {
        BroadcastValue::RingValue(Value::Ring64(Wrapping(value)))
    }
}
impl From<u128> for BroadcastValue {
    fn from(value: u128) -> Self {
        BroadcastValue::RingValue(Value::Ring128(Wrapping(value)))
    }
}
impl From<ResiduePoly<Z64>> for BroadcastValue {
    fn from(value: ResiduePoly<Z64>) -> Self {
        BroadcastValue::RingValue(Value::Poly64(value))
    }
}
impl From<ResiduePoly<Z128>> for BroadcastValue {
    fn from(value: ResiduePoly<Z128>) -> Self {
        BroadcastValue::RingValue(Value::Poly128(value))
    }
}

impl From<Vec<u64>> for BroadcastValue {
    fn from(value: Vec<u64>) -> Self {
        BroadcastValue::RingVector(
            value
                .iter()
                .map(|cur| Value::Ring64(Wrapping(*cur)))
                .collect_vec(),
        )
    }
}
impl From<Vec<u128>> for BroadcastValue {
    fn from(value: Vec<u128>) -> Self {
        BroadcastValue::RingVector(
            value
                .iter()
                .map(|cur| Value::Ring128(Wrapping(*cur)))
                .collect_vec(),
        )
    }
}
impl From<Vec<ResiduePoly<Z64>>> for BroadcastValue {
    fn from(value: Vec<ResiduePoly<Z64>>) -> Self {
        BroadcastValue::RingVector(
            value
                .iter()
                .map(|cur: &ResiduePoly<Wrapping<u64>>| Value::Poly64(*cur))
                .collect_vec(),
        )
    }
}
impl From<Vec<ResiduePoly<Z128>>> for BroadcastValue {
    fn from(value: Vec<ResiduePoly<Z128>>) -> Self {
        BroadcastValue::RingVector(value.iter().map(|cur| Value::Poly128(*cur)).collect_vec())
    }
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Hash, Eq, Debug)]
pub enum AgreeRandomValue {
    CommitmentValue(Vec<Commitment>),
    KeyOpenValue(Vec<(PrfKey, Opening)>),
    KeyValue(Vec<PrfKey>),
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
    expected_type: &RingType,
) -> anyhow::Result<Value> {
    if shares.is_empty() {
        return Err(anyhow_error_and_log(
            "Input to reconstruction is empty".to_string(),
        ));
    }
    match expected_type {
        RingType::GalExtRing64 => {
            let stripped_shares: Vec<_> = shares
                .iter()
                .map(|v| match v.value {
                    Value::Poly64(vv) => (v.party_id, vv),
                    _ => (v.party_id, ResiduePoly::ZERO), //default to 0
                })
                .collect();
            Ok(Value::Poly64(ShamirGSharings::<Z64>::err_reconstruct(
                &ShamirGSharings {
                    shares: stripped_shares,
                },
                threshold,
                max_error_count,
            )?))
        }
        RingType::GalExtRing128 => {
            let stripped_shares: Vec<_> = shares
                .iter()
                .map(|v| match v.value {
                    Value::Poly128(vv) => (v.party_id, vv),
                    _ => (v.party_id, ResiduePoly::ZERO), //default to 0
                })
                .collect();
            Ok(Value::Poly128(ShamirGSharings::<Z128>::err_reconstruct(
                &ShamirGSharings {
                    shares: stripped_shares,
                },
                threshold,
                max_error_count,
            )?))
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

use crate::execution::dispute::DisputePayload;
use crate::execution::party::Role;
use crate::lwe::PubConKeyPair;
use crate::residue_poly::ResiduePoly;
use crate::shamir::ShamirGSharings;
use crate::sharing::vss::ValueOrPoly;
use crate::{Z128, Z64};
use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

/// a collection of shares
#[derive(Serialize, Deserialize, PartialEq, Clone, Hash, Eq, Debug)]
pub enum Value {
    IndexedShare64((usize, ResiduePoly<Z64>)),
    IndexedShare128((usize, ResiduePoly<Z128>)),
    Poly64(ResiduePoly<Z64>),
    Poly128(ResiduePoly<Z128>),
    Ring64(Z64),
    Ring128(Z128),
    U64(u64),
}

/// Captures network values which can (and sometimes should) be broadcast
#[derive(Serialize, Deserialize, PartialEq, Clone, Hash, Eq, Debug)]
pub enum BroadcastValue {
    RingValue(Value),
    AddDispute(DisputePayload),
    Round2VSS(Vec<crate::sharing::vss::VerificationValues>),
    Round3VSS(BTreeMap<(usize, Role, Role), ResiduePoly<Z128>>),
    Round4VSS(BTreeMap<(usize, Role), ValueOrPoly>),
}

impl From<Value> for BroadcastValue {
    fn from(value: Value) -> Self {
        BroadcastValue::RingValue(value)
    }
}

/// a value that is sent via network
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub enum NetworkValue {
    PubKey(Box<PubConKeyPair>),
    RingValue(Value),
    Send(BroadcastValue),
    EchoBatch(HashMap<Role, BroadcastValue>),
    VoteBatch(HashMap<Role, BroadcastValue>),
    Bot,
    Round1VSS(crate::sharing::vss::ExchangedDataRound1),
}

pub fn err_reconstruct(
    shares: &Vec<Value>,
    threshold: usize,
    max_error_count: usize,
) -> anyhow::Result<Value> {
    if shares.is_empty() {
        return Err(anyhow!("Input to reconstruction is empty"));
    }
    match shares[0] {
        Value::IndexedShare64(_) => {
            let stripped_shares: Vec<_> = shares
                .iter()
                .filter_map(|v| match v {
                    Value::IndexedShare64((i, s)) => Some((*i, *s)),
                    _ => None,
                })
                .collect();
            if stripped_shares.len() != shares.len() {
                Err(anyhow!(
                    "Mixed types when reconstructing, expected to be Ring64"
                ))
            } else {
                Ok(Value::Ring64(ShamirGSharings::<Z64>::err_reconstruct(
                    &ShamirGSharings {
                        shares: stripped_shares,
                    },
                    threshold,
                    max_error_count,
                )?))
            }
        }
        Value::IndexedShare128(_) => {
            let stripped_shares: Vec<_> = shares
                .iter()
                .filter_map(|v| match v {
                    Value::IndexedShare128((i, s)) => Some((*i, *s)),
                    _ => None,
                })
                .collect();
            if stripped_shares.len() != shares.len() {
                Err(anyhow!(
                    "Mixed types when reconstructing, expected to be Ring128"
                ))
            } else {
                Ok(Value::Ring128(ShamirGSharings::<Z128>::err_reconstruct(
                    &ShamirGSharings {
                        shares: stripped_shares,
                    },
                    threshold,
                    max_error_count,
                )?))
            }
        }
        _ => Err(anyhow!(
            "Cannot reconstruct when types are not indexed shares"
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
    use tracing_test::traced_test;

    #[tokio::test]
    #[traced_test]
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

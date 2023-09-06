use crate::execution::party::Role;
use crate::lwe::PublicKey;
use crate::residue_poly::ResiduePoly;
use crate::shamir::ShamirGSharings;
use crate::{Z128, Z64};
use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// a collection of shares
#[derive(Serialize, Deserialize, PartialEq, Clone, Hash, Eq, Debug)]
pub enum Value {
    IndexedShare64((usize, ResiduePoly<Z64>)),
    IndexedShare128((usize, ResiduePoly<Z128>)),
    Ring64(Z64),
    Ring128(Z128),
    U64(u64),
}

/// a value that is sent via network
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub enum NetworkValue {
    PubKey(PublicKey),
    RingValue(Value),
    Send(Value),
    EchoBatch(HashMap<Role, Value>),
    VoteBatch(HashMap<Role, Value>),
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

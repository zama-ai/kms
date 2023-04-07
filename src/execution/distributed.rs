use crate::computation::SessionId;
use crate::execution::player::{Identity, Role};
use crate::networking::Networking;
use crate::parser::Circuit;
use crate::poly_shamir::Value;
use crate::poly_shamir::*;
use anyhow::anyhow;
use rand::RngCore;
use std::collections::HashMap;
use std::num::Wrapping;
use std::str::FromStr;
use std::sync::Arc;
use tokio::task::JoinSet;

pub type NetworkingImpl = Arc<dyn Networking + Send + Sync>;

#[derive(Clone)]
pub struct DistributedSession {
    pub session_id: SessionId,
    pub role_assignments: HashMap<Role, Identity>,
    pub networking: NetworkingImpl,
    pub threshold: u8,
}

impl DistributedSession {
    pub fn new(
        session_id: SessionId,
        role_assignments: HashMap<Role, Identity>,
        networking: NetworkingImpl,
        threshold: u8,
    ) -> Self {
        DistributedSession {
            session_id,
            role_assignments,
            networking,
            threshold,
        }
    }
}

pub async fn robust_open_to(
    session: &DistributedSession,
    share: &Value,
    role: &Role,
    player_open: usize,
) -> anyhow::Result<Option<Value>> {
    if role.player_no() == player_open {
        let mut collected_sharings = Vec::new();
        collected_sharings.push(share.clone());

        let mut set = JoinSet::new();
        for (other_role, identity) in session.role_assignments.clone() {
            if role != &other_role {
                let networking = Arc::clone(&session.networking);
                let session_id = session.session_id.clone();
                set.spawn(async move { networking.receive(&identity, &session_id).await });
            }
        }

        while let Some(v) = set.join_next().await {
            let share = v??;
            collected_sharings.push(share);

            let num_parties = session.role_assignments.len();
            let t = session.threshold as usize;

            if 4 * t < num_parties {
                if collected_sharings.len() > 3 * t {
                    if let Ok(opened) = err_reconstruct(&collected_sharings, t, 0) {
                        tracing::debug!(
                            "managed to reconstruct with given {:?} shares",
                            collected_sharings.len()
                        );
                        set.abort_all();
                        return Ok(Some(opened));
                    }
                }
            } else if 3 * t < num_parties {
                for max_error in 0..t {
                    if collected_sharings.len() > 2 * t + max_error {
                        if let Ok(opened) = err_reconstruct(&collected_sharings, t, max_error) {
                            tracing::debug!(
                                "managed to reconstruct with error count: {:?} given {:?} shares",
                                max_error,
                                collected_sharings.len()
                            );
                            set.abort_all();
                            return Ok(Some(opened));
                        }
                    }
                }
            }
        }
        Err(anyhow!("Could not reconstruct the sharing"))
    } else {
        let receiver = session
            .role_assignments
            .get(&Role(player_open as u64))
            .ok_or(anyhow!(
                "Couldn't get identity for role {player_open} in opening"
            ))?
            .clone();
        let networking = Arc::clone(&session.networking);
        let share = share.clone();
        let session_id = session.session_id.clone();

        tokio::spawn(async move {
            let _ = networking.send(&share, &receiver, &session_id).await;
        })
        .await?;
        Ok(None)
    }
}

pub async fn robust_input<R: RngCore>(
    rng: &mut R,
    session: &DistributedSession,
    value: &Option<Value>,
    role: &Role,
    player_input: usize,
) -> anyhow::Result<Value> {
    if role.player_no() == player_input {
        let threshold = session.threshold;
        let si = value.clone().unwrap();
        let num_parties = session.role_assignments.len();

        let (shamir_sharings, identities): (Vec<Value>, Vec<&Identity>) = match si {
            Value::Ring64(s64) => {
                let sharings = ZPoly::<Z64>::share(rng, s64, num_parties, threshold as usize)?;
                let values: Vec<_> = sharings
                    .shares
                    .iter()
                    .map(|x| Value::IndexedShare64(*x))
                    .collect();
                let identities: Vec<_> = sharings
                    .shares
                    .iter()
                    .map(|(party_id, _)| {
                        session
                            .role_assignments
                            .get(&Role(*party_id as u64))
                            .ok_or(anyhow!("couldn't get identity for role {party_id}"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                (values, identities)
            }
            Value::Ring128(s128) => {
                let sharings = ZPoly::<Z128>::share(rng, s128, num_parties, threshold as usize)?;
                let values: Vec<_> = sharings
                    .shares
                    .iter()
                    .map(|x| Value::IndexedShare128(*x))
                    .collect();
                let identities: Vec<_> = sharings
                    .shares
                    .iter()
                    .map(|(party_id, _)| {
                        session
                            .role_assignments
                            .get(&Role(*party_id as u64))
                            .ok_or(anyhow!("couldn't get identity for role {party_id}"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                (values, identities)
            }
            _ => {
                return Err(anyhow!(
                    "Cannot share a value which has type different than Ring64/Ring128"
                ));
            }
        };

        let mut set = JoinSet::new();
        for (indexed_share, identity) in shamir_sharings.iter().zip(identities).skip(1) {
            let networking = Arc::clone(&session.networking);
            let session_id = session.session_id.clone();
            let share = indexed_share.clone();
            let identity = identity.clone();

            set.spawn(async move {
                let _ = networking.send(&share, &identity, &session_id).await;
            });
        }
        while (set.join_next().await).is_some() {}
        Ok(shamir_sharings[0].clone())
    } else {
        let receiver = session
            .role_assignments
            .get(&Role(player_input as u64))
            .ok_or(anyhow!("couldn't get identity for role {player_input}"))?
            .clone();
        let networking = Arc::clone(&session.networking);
        let session_id = session.session_id.clone();
        let data: Value =
            tokio::spawn(async move { networking.receive(&receiver, &session_id).await }).await??;
        Ok(data)
    }
}

pub async fn execute_small_circuit<R: RngCore>(
    session: &DistributedSession,
    circuit: &Circuit,
    own_identity: &Identity,
    rng: &mut R,
) -> anyhow::Result<Vec<Value>> {
    let mut env: HashMap<&String, Value> = HashMap::new();
    let mut outputs = Vec::new();

    let own_role: Vec<&Role> = session
        .role_assignments
        .iter()
        .filter_map(|(role, identity)| {
            if identity == own_identity {
                Some(role)
            } else {
                None
            }
        })
        .collect();

    let own_role = {
        match own_role.len() {
            1 => Ok(own_role[0].clone()),
            _ => Err(anyhow!("Cannot continue circuit execution if current party has a number of roles equal to {:?}", own_role.len()))
        }?
    };
    #[allow(clippy::get_first)]
    for op in circuit.operations.iter() {
        use crate::parser::Operator::*;
        match op.operator {
            LdSI => {
                let r0 = op
                    .operands
                    .get(0)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let si = Wrapping(u128::from_str(
                    op.operands
                        .get(1)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?,
                )?);

                let secret = match own_role.player_no() {
                    1 => Some(Value::Ring128(si)),
                    _ => None,
                };
                let sharing: Value = robust_input(rng, session, &secret, &own_role, 1).await?;
                env.insert(r0, sharing);
            }
            Open => {
                tracing::info!("started to execute open instruction");
                let c0 = op
                    .operands
                    .get(2)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let s0 = op
                    .operands
                    .get(3)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;

                let own_share = env.get(s0).ok_or(anyhow!(
                    "Couldn't retrieve secret register index for opening"
                ))?;

                let opened = robust_open_to(session, own_share, &own_role, 1).await?;
                if let Some(val) = opened {
                    env.insert(c0, val);
                }
            }
            LdCI => {
                let r0 = op
                    .operands
                    .get(0)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let ci = Value::U64(u64::from_str(
                    op.operands
                        .get(1)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?,
                )?);
                env.insert(r0, ci);
            }
            PrintRegPlain => {
                if own_role.player_no() == 1 {
                    let r0 = op
                        .operands
                        .get(0)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                    let c = env
                        .get(&r0.to_string())
                        .ok_or_else(|| anyhow!("Couldn't find register {r0}"))?
                        .clone();
                    outputs.push(c);
                }
            }
            _ => todo!(),
        }
    }
    Ok(outputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::networking::local::LocalNetworking;
    use crate::parser::Operation;
    use crate::parser::*;
    use aes_prng::AesRng;
    use rand::SeedableRng;
    use tracing_test::traced_test;

    #[tokio::test]
    #[traced_test]
    async fn test_load_ci_circuit() {
        let role_assignments = HashMap::from([
            (Role(1), Identity("localhost:5000".to_string())),
            (Role(2), Identity("localhost:5001".to_string())),
            (Role(3), Identity("localhost:5002".to_string())),
            (Role(4), Identity("localhost:5003".to_string())),
        ]);
        let session_id = SessionId::from(1);
        let networking = Arc::new(LocalNetworking {
            session_id: session_id.clone(),
            recv_channels: Default::default(),
            send_channels: Default::default(),
        });
        let threshold = 1;

        let session = DistributedSession::new(session_id, role_assignments, networking, threshold);

        let circuit = Circuit {
            operations: vec![
                Operation {
                    operator: Operator::LdCI,
                    operands: vec![String::from("c0"), String::from("100")],
                },
                Operation {
                    operator: Operator::PrintRegPlain,
                    operands: vec![String::from("c0")],
                },
            ],
            input_wires: vec![String::from("c0")],
        };

        let mut rng = AesRng::seed_from_u64(0);
        let out = execute_small_circuit(
            &session,
            &circuit,
            &Identity("localhost:5000".to_string()),
            &mut rng,
        )
        .await
        .unwrap();
        assert_eq!(out[0], Value::U64(100));
    }

    #[tokio::test]
    async fn test_open_secret_large_t() {
        let role_assignments = HashMap::from([
            (Role(1), Identity("localhost:5000".to_string())),
            (Role(2), Identity("localhost:5001".to_string())),
            (Role(3), Identity("localhost:5002".to_string())),
            (Role(4), Identity("localhost:5003".to_string())),
        ]);
        let session_id = SessionId::from(1);
        let networking = Arc::new(LocalNetworking {
            session_id: session_id.clone(),
            recv_channels: Default::default(),
            send_channels: Default::default(),
        });
        let threshold = 1;

        let session = DistributedSession::new(session_id, role_assignments, networking, threshold);

        let circuit = Circuit {
            operations: vec![
                Operation {
                    operator: Operator::LdSI,
                    operands: vec![String::from("s0"), String::from("100")],
                },
                Operation {
                    operator: Operator::Open,
                    operands: vec![
                        String::from("1"),
                        String::from("false"),
                        String::from("c0"),
                        String::from("s0"),
                    ],
                },
                Operation {
                    operator: Operator::PrintRegPlain,
                    operands: vec![String::from("c0")],
                },
            ],
            input_wires: vec![String::from("c0")],
        };

        let mut rng = AesRng::seed_from_u64(0);
        let out = execute_small_circuit(
            &session,
            &circuit,
            &Identity("localhost:5000".to_string()),
            &mut rng,
        )
        .await
        .unwrap();
        assert_eq!(out[0], Value::Ring128(std::num::Wrapping(100)));
    }

    #[tokio::test]
    async fn test_open_secret_small_t() {
        let role_assignments = HashMap::from([
            (Role(1), Identity("localhost:5000".to_string())),
            (Role(2), Identity("localhost:5001".to_string())),
            (Role(3), Identity("localhost:5002".to_string())),
            (Role(4), Identity("localhost:5003".to_string())),
            (Role(5), Identity("localhost:5004".to_string())),
        ]);
        let session_id = SessionId::from(1);
        let networking = Arc::new(LocalNetworking {
            session_id: session_id.clone(),
            recv_channels: Default::default(),
            send_channels: Default::default(),
        });
        let threshold = 1;

        let session = DistributedSession::new(session_id, role_assignments, networking, threshold);

        let circuit = Circuit {
            operations: vec![
                Operation {
                    operator: Operator::LdSI,
                    operands: vec![String::from("s0"), String::from("100")],
                },
                Operation {
                    operator: Operator::Open,
                    operands: vec![
                        String::from("1"),
                        String::from("false"),
                        String::from("c0"),
                        String::from("s0"),
                    ],
                },
                Operation {
                    operator: Operator::PrintRegPlain,
                    operands: vec![String::from("c0")],
                },
            ],
            input_wires: vec![String::from("c0")],
        };

        let mut rng = AesRng::seed_from_u64(0);
        let out = execute_small_circuit(
            &session,
            &circuit,
            &Identity("localhost:5000".to_string()),
            &mut rng,
        )
        .await
        .unwrap();
        assert_eq!(out[0], Value::Ring128(std::num::Wrapping(100)));
    }
}

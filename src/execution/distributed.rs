use crate::circuit::{Circuit, Operator};
use crate::computation::SessionId;
use crate::execution::player::{Identity, Role, RoleAssignment};
use crate::execution::prss::PRSSState;
use crate::networking::local::{LocalNetworking, LocalNetworkingProducer};
use crate::networking::Networking;
use crate::residue_poly::ResiduePoly;
use crate::shamir::ShamirGSharings;
use crate::value::{err_reconstruct, Value};
use crate::{One, Z128, Z64};
use aes_prng::AesRng;
use anyhow::anyhow;
use rand::RngCore;
use rand::SeedableRng;
use std::collections::HashMap;
use std::num::Wrapping;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;

use super::prss::PRSSSetup;

pub type NetworkingImpl = Arc<dyn Networking + Send + Sync>;

#[derive(Clone)]
pub struct DistributedSession {
    pub session_id: SessionId,
    pub role_assignments: HashMap<Role, Identity>,
    pub networking: NetworkingImpl,
    pub threshold: u8,
    prss_state: Option<PRSSState>,
}

impl DistributedSession {
    pub fn new(
        session_id: SessionId,
        role_assignments: HashMap<Role, Identity>,
        networking: NetworkingImpl,
        threshold: u8,
        prss_setup: Option<PRSSSetup>,
    ) -> Self {
        DistributedSession {
            session_id,
            role_assignments,
            networking,
            threshold,
            prss_state: prss_setup.map(|x| x.new_session(session_id)),
        }
    }
}

pub struct DistributedTestRuntime {
    identities: Vec<Identity>,
    threshold: u8,
    prss_setup: Option<PRSSSetup>,
}

impl DistributedTestRuntime {
    pub fn new(identities: Vec<Identity>, threshold: u8, prss_setup: Option<PRSSSetup>) -> Self {
        DistributedTestRuntime {
            identities,
            threshold,
            prss_setup,
        }
    }

    pub fn evaluate_circuit(
        &self,
        circuit: &Circuit,
    ) -> anyhow::Result<HashMap<Identity, Vec<Value>>> {
        // TODO(Dragos) replaced this with a random sid
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new()?;
        let _guard = rt.enter();

        let role_assignments: RoleAssignment = self
            .identities
            .clone()
            .into_iter()
            .enumerate()
            .map(|(role_id, identity)| (Role(role_id as u64 + 1), identity))
            .collect();

        let net_producer = LocalNetworkingProducer::from_ids(&self.identities);
        let user_nets: Vec<Arc<LocalNetworking>> = self
            .identities
            .iter()
            .map(|user_identity| {
                let net = net_producer.user_net(user_identity.clone());
                Arc::new(net)
            })
            .collect();

        let mut set = JoinSet::new();
        for (index_id, identity) in self.identities.clone().into_iter().enumerate() {
            let role_assignments = role_assignments.clone();
            let net = Arc::clone(&user_nets[index_id]);
            let circuit = circuit.clone();
            let threshold = self.threshold;
            let prss_setup = self.prss_setup.clone();
            set.spawn(async move {
                let mut rng = AesRng::seed_from_u64(0);
                let mut session = DistributedSession::new(
                    session_id,
                    role_assignments,
                    net,
                    threshold,
                    prss_setup,
                );
                let (out, _init_time) =
                    execute_small_circuit(&mut session, &circuit, &identity, &mut rng)
                        .await
                        .unwrap();
                (identity, out)
            });
        }

        let results = rt.block_on(async {
            let mut results = HashMap::new();
            while let Some(v) = set.join_next().await {
                let (identity, val) = v.unwrap();
                results.insert(identity, val);
            }
            results
        });
        Ok(results)
    }
}

pub async fn robust_open_to(
    session: &DistributedSession,
    share: &Value,
    role: &Role,
    player_open: usize,
) -> anyhow::Result<Option<Value>> {
    if role.player_no() == player_open {
        session.networking.increase_round_counter().await?;
        let mut collected_sharings = Vec::new();
        collected_sharings.push(share.clone());

        let mut set = JoinSet::new();
        for (other_role, _identity) in session.role_assignments.clone() {
            if role != &other_role {
                let networking = Arc::clone(&session.networking);
                let session_id = session.session_id;

                let sender = session
                    .role_assignments
                    .get(&other_role)
                    .ok_or(anyhow!("couldn't get identity for role {role}"))?
                    .clone();

                set.spawn(async move { networking.receive(&sender, &session_id).await });
            }
        }

        while let Some(v) = set.join_next().await {
            let share = v??;
            collected_sharings.push(share);

            let num_parties = session.role_assignments.len();
            let t = session.threshold as usize;

            if 4 * t < num_parties {
                if collected_sharings.len() > 3 * t {
                    let opened = err_reconstruct(&collected_sharings, t, 0)?;
                    tracing::debug!(
                        "managed to reconstruct with given {:?} shares",
                        collected_sharings.len()
                    );
                    set.shutdown().await;
                    return Ok(Some(opened));
                }
            } else if 3 * t < num_parties {
                for max_error in 0..t + 1 {
                    if collected_sharings.len() > 2 * t + max_error {
                        if let Ok(opened) = err_reconstruct(&collected_sharings, t, max_error) {
                            tracing::debug!(
                                "managed to reconstruct with error count: {:?} given {:?} shares",
                                max_error,
                                collected_sharings.len()
                            );
                            set.shutdown().await;
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
        let session_id = session.session_id;

        tokio::spawn(async move {
            let _ = networking.send(share, &receiver, &session_id).await;
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
        let si = {
            match value {
                Some(v) => v.clone(),
                None => {
                    return Err(anyhow!(
                        "Expected Some(v) as an input argument for the input player, got None"
                    ))
                }
            }
        };
        let num_parties = session.role_assignments.len();

        let (shamir_sharings, roles): (Vec<Value>, Vec<Role>) = match si {
            Value::Ring64(s64) => {
                let sharings =
                    ShamirGSharings::<Z64>::share(rng, s64, num_parties, threshold as usize)?;
                let values: Vec<_> = sharings
                    .shares
                    .iter()
                    .map(|x| Value::IndexedShare64(*x))
                    .collect();
                let roles: Vec<_> = sharings
                    .shares
                    .iter()
                    .map(|(party_id, _)| Role(*party_id as u64))
                    .collect();
                (values, roles)
            }
            Value::Ring128(s128) => {
                let sharings =
                    ShamirGSharings::<Z128>::share(rng, s128, num_parties, threshold as usize)?;
                let values: Vec<_> = sharings
                    .shares
                    .iter()
                    .map(|x| Value::IndexedShare128(*x))
                    .collect();
                let roles: Vec<_> = sharings
                    .shares
                    .iter()
                    .map(|(party_id, _)| Role(*party_id as u64))
                    .collect();
                (values, roles)
            }
            _ => {
                return Err(anyhow!(
                    "Cannot share a value which has type different than Ring64/Ring128"
                ));
            }
        };
        let mut set = JoinSet::new();
        for (indexed_share, to_send_role) in shamir_sharings.iter().zip(roles).skip(1) {
            let receiver = session
                .role_assignments
                .get(&to_send_role)
                .ok_or(anyhow!("couldn't get identity for role {to_send_role}"))?
                .clone();

            let networking = Arc::clone(&session.networking);
            let session_id = session.session_id;
            let share = indexed_share.clone();

            set.spawn(async move {
                let _ = networking.send(share, &receiver, &session_id).await;
            });
        }
        while (set.join_next().await).is_some() {}
        Ok(shamir_sharings[0].clone())
    } else {
        session.networking.increase_round_counter().await?;
        let sender = session
            .role_assignments
            .get(&Role(player_input as u64))
            .ok_or(anyhow!("couldn't get identity for role {player_input}"))?
            .clone();

        let networking = Arc::clone(&session.networking);
        let session_id = session.session_id;
        let data: Value =
            tokio::spawn(async move { networking.receive(&sender, &session_id).await }).await??;
        Ok(data)
    }
}

pub async fn execute_small_circuit<R: RngCore>(
    session: &mut DistributedSession,
    circuit: &Circuit,
    own_identity: &Identity,
    rng: &mut R,
) -> anyhow::Result<(Vec<Value>, Duration)> {
    let mut env: HashMap<&String, Value> = HashMap::new();
    let mut outputs = Vec::new();
    let mut init_time = Duration::ZERO;

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
        use Operator::*;
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

                let own_share = env.get(s0).ok_or_else(|| {
                    anyhow!("Couldn't retrieve secret register index for opening")
                })?;
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
            ShrCI => {
                if own_role.player_no() == 1 {
                    let dest = op
                        .operands
                        .get(0)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?;

                    let source = op
                        .operands
                        .get(1)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?;

                    let source = env
                        .get(&source.to_string())
                        .ok_or_else(|| anyhow!("Couldn't find register {source}"))?
                        .clone();

                    let offset = usize::from_str(
                        op.operands
                            .get(2)
                            .ok_or_else(|| anyhow!("Wrong index buddy"))?,
                    )?;

                    match source {
                        Value::Ring128(v) => {
                            env.insert(dest, Value::Ring128(v >> offset));
                        }
                        Value::Ring64(v) => {
                            env.insert(dest, Value::Ring64(v >> offset));
                        }
                        _ => return Err(anyhow!("Cannot do shift right on a cleartext register with a different type than Ring64/Ring128"))
                    }
                }
            }
            DistPrep => {
                // this instruction does steps 1-3 from dist dec paper
                // computes a sharing of b - a * s + E
                // where dim(a) = L, E = sum(shared_bits)
                let dest = op
                    .operands
                    .get(0)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;

                let message = u8::from_str(
                    op.operands
                        .get(1)
                        .ok_or_else(|| anyhow!("Couldn't retrieve message"))?,
                )?;

                let prep_seed = u64::from_str(
                    op.operands
                        .get(2)
                        .ok_or_else(|| anyhow!("Couldn't retrieve seed"))?,
                )?;

                let big_ell = usize::from_str(
                    op.operands
                        .get(3)
                        .ok_or_else(|| anyhow!("Couldn't retrieve L (lwe dimension"))?,
                )?;

                let (s, init_t) = crate::execution::prep::ddec_prep(
                    prep_seed,
                    big_ell,
                    message,
                    own_role.player_no(),
                    session.threshold as usize,
                )?;
                init_time = init_t;
                tracing::debug!("finished generating proto 2 prep: {:?}", s);
                env.insert(dest, s);
            }
            PrssPrep => {
                // this instruction does PRSS.Init() and steps 1-2 from dist dec paper
                // computes a sharing of b - a * s + E
                // where dim(a) = L, E = sum(shared_bits)
                let dest = op
                    .operands
                    .get(0)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;

                let message = u8::from_str(
                    op.operands
                        .get(1)
                        .ok_or_else(|| anyhow!("Couldn't retrieve message"))?,
                )?;

                let prep_seed = u64::from_str(
                    op.operands
                        .get(2)
                        .ok_or_else(|| anyhow!("Couldn't retrieve seed"))?,
                )?;

                let big_ell = usize::from_str(
                    op.operands
                        .get(3)
                        .ok_or_else(|| anyhow!("Couldn't retrieve L (lwe dimension"))?,
                )?;

                let prss_state = session
                    .prss_state
                    .as_mut()
                    .ok_or_else(|| anyhow!("PRSS_State not initialized"))?;

                let (s, init_t) = crate::execution::prep::prss_prep(
                    prep_seed,
                    big_ell,
                    message,
                    own_role.player_no(),
                    session.threshold as usize,
                    prss_state,
                )?;
                init_time = init_t;
                tracing::debug!("finished generating PRSS prep: {:?}", s);
                env.insert(dest, s);
            }
            FaultyThreshold => {
                // all parties up to (including) t manipulate their share
                // (to simulate a faulty/malicious party in benchmarking)
                let party_id = own_role.player_no();
                if party_id <= session.threshold as usize {
                    let dest = op
                        .operands
                        .get(0)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?;

                    let correct_share_value = env
                        .get(dest)
                        .ok_or_else(|| anyhow!("Couldn't retrieve party share to modify"))?;

                    // increase value of existing share by 1
                    if let Value::IndexedShare128(share) = correct_share_value {
                        tracing::debug!("I'm party {} and I will send bollocks!", party_id);
                        env.insert(
                            dest,
                            Value::IndexedShare128((share.0, share.1 + ResiduePoly::ONE)),
                        );
                    } else {
                        return Err(anyhow!(
                            "Other type than IndexShare128 found in threshold_fault"
                        ));
                    }
                }
            }
            _ => todo!(),
        }
    }
    Ok((outputs, init_time))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::Operation;
    use tracing_test::traced_test;

    #[traced_test]
    #[test]
    fn test_load_ci_circuit() {
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
            input_wires: vec![],
        };
        let identities = vec![
            Identity("localhost:5000".to_string()),
            Identity("localhost:5001".to_string()),
            Identity("localhost:5002".to_string()),
            Identity("localhost:5003".to_string()),
        ];
        let threshold = 1;

        let runtime = DistributedTestRuntime::new(identities, threshold, None);
        let results = runtime.evaluate_circuit(&circuit).unwrap();
        let out = &results[&Identity("localhost:5000".to_string())];
        assert_eq!(out[0], Value::U64(100));
    }

    #[traced_test]
    #[test]
    fn test_open_secret_large_t() {
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
            input_wires: vec![],
        };
        let identities = vec![
            Identity("localhost:5000".to_string()),
            Identity("localhost:5001".to_string()),
            Identity("localhost:5002".to_string()),
            Identity("localhost:5003".to_string()),
            Identity("localhost:5004".to_string()),
        ];
        let threshold = 1;

        let runtime = DistributedTestRuntime::new(identities, threshold, None);
        let results = runtime.evaluate_circuit(&circuit).unwrap();
        let out = &results[&Identity("localhost:5000".to_string())];
        assert_eq!(out[0], Value::Ring128(std::num::Wrapping(100)));
    }

    #[test]
    fn test_open_secret_small_t() {
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
            input_wires: vec![],
        };
        let identities = vec![
            Identity("localhost:5000".to_string()),
            Identity("localhost:5001".to_string()),
            Identity("localhost:5002".to_string()),
            Identity("localhost:5003".to_string()),
            Identity("localhost:5004".to_string()),
            Identity("localhost:5005".to_string()),
        ];
        let threshold = 1;
        let runtime = DistributedTestRuntime::new(identities, threshold, None);
        let results = runtime.evaluate_circuit(&circuit).unwrap();
        let out = &results[&Identity("localhost:5000".to_string())];
        assert_eq!(out[0], Value::Ring128(std::num::Wrapping(100)));
    }

    #[test]
    fn test_multiple_opens() {
        let circuit: Circuit = Circuit {
            operations: vec![
                Operation {
                    operator: Operator::LdSI,
                    operands: vec![String::from("s0"), String::from("100")],
                },
                Operation {
                    operator: Operator::LdSI,
                    operands: vec![String::from("s1"), String::from("101")],
                },
                Operation {
                    operator: Operator::LdSI,
                    operands: vec![String::from("s2"), String::from("102")],
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
                    operator: Operator::Open,
                    operands: vec![
                        String::from("1"),
                        String::from("false"),
                        String::from("c1"),
                        String::from("s1"),
                    ],
                },
                Operation {
                    operator: Operator::Open,
                    operands: vec![
                        String::from("1"),
                        String::from("false"),
                        String::from("c2"),
                        String::from("s2"),
                    ],
                },
                Operation {
                    operator: Operator::PrintRegPlain,
                    operands: vec![String::from("c0")],
                },
                Operation {
                    operator: Operator::PrintRegPlain,
                    operands: vec![String::from("c1")],
                },
                Operation {
                    operator: Operator::PrintRegPlain,
                    operands: vec![String::from("c2")],
                },
            ],
            input_wires: vec![],
        };
        let identities = vec![
            Identity("localhost:5000".to_string()),
            Identity("localhost:5001".to_string()),
            Identity("localhost:5002".to_string()),
            Identity("localhost:5003".to_string()),
            Identity("localhost:5004".to_string()),
            Identity("localhost:5005".to_string()),
            Identity("localhost:5006".to_string()),
            Identity("localhost:5007".to_string()),
            Identity("localhost:5008".to_string()),
            Identity("localhost:5009".to_string()),
        ];
        let threshold = 1;
        let runtime = DistributedTestRuntime::new(identities, threshold, None);
        let results = runtime.evaluate_circuit(&circuit).unwrap();
        let out = &results[&Identity("localhost:5000".to_string())];
        assert_eq!(out[0], Value::Ring128(std::num::Wrapping(100)));
        assert_eq!(out[1], Value::Ring128(std::num::Wrapping(101)));
        assert_eq!(out[2], Value::Ring128(std::num::Wrapping(102)));
    }
}

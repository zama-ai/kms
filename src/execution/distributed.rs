use super::prss::PRSSSetup;
use crate::circuit::{Circuit, Operator};
use crate::computation::SessionId;
use crate::execution::constants::INPUT_PARTY_ID;
use crate::execution::party::{Identity, Role, RoleAssignment};
use crate::execution::prss::PRSSState;
use crate::lwe::{keygen, Ciphertext, PublicKey, SecretKey, SecretKeyShare};
use crate::networking::local::{LocalNetworking, LocalNetworkingProducer};
use crate::networking::Networking;
use crate::residue_poly::ResiduePoly;
use crate::shamir::ShamirGSharings;
use crate::value::{err_reconstruct, NetworkValue, Value};
use crate::{One, Z128, Z64};
use aes_prng::AesRng;
use anyhow::anyhow;
use derive_more::Display;
use ndarray::Array1;
use rand::RngCore;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::num::Wrapping;
use std::str::FromStr;
use std::sync::Arc;
use tokio::task::JoinSet;

pub type NetworkingImpl = Arc<dyn Networking + Send + Sync>;

#[derive(Clone, Serialize, Deserialize, Display)]
pub enum DecryptionMode {
    PRSSDecrypt,
    Proto2Decrypt,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Display)]
pub enum SetupMode {
    AllProtos,
    NoPrss,
}

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

    /// return Role for given Identity in this session
    pub fn get_role_from(&self, own_identity: &Identity) -> anyhow::Result<Role> {
        let own_role: Vec<&Role> = self
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
                _ => Err(anyhow!(
                    "Unknown or ambiguous role for identity {:?}",
                    own_identity
                )),
            }?
        };

        Ok(own_role)
    }
}

pub struct DistributedTestRuntime {
    identities: Vec<Identity>,
    threshold: u8,
    prss_setup: Option<PRSSSetup>,
    keyshares: Option<Vec<SecretKeyShare>>,
}

impl DistributedTestRuntime {
    pub fn new(
        identities: Vec<Identity>,
        threshold: u8,
        prss_setup: Option<PRSSSetup>,
        keyshares: Option<Vec<SecretKeyShare>>,
    ) -> Self {
        DistributedTestRuntime {
            identities,
            threshold,
            prss_setup,
            keyshares,
        }
    }

    /// test the circuit evaluation
    pub fn evaluate_circuit(
        &self,
        circuit: &Circuit,
        ct: Option<Ciphertext>,
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

            let party_keyshare = self.keyshares.clone().map(|ks| ks[index_id].clone());

            let ct = ct.clone();

            set.spawn(async move {
                let mut rng = AesRng::seed_from_u64(0);
                let mut session = DistributedSession::new(
                    session_id,
                    role_assignments,
                    net,
                    threshold,
                    prss_setup,
                );
                let out = run_circuit_operations_debug(
                    &mut session,
                    &identity,
                    &circuit,
                    party_keyshare,
                    ct,
                    &mut rng,
                )
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

    /// test the threshold decryption
    pub fn threshold_decrypt(
        &self,
        ct: Ciphertext,
        mode: DecryptionMode,
    ) -> anyhow::Result<HashMap<Identity, Vec<Value>>> {
        // TODO(Dragos) replaced this with a random sid
        let session_id = SessionId(2);

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
            let threshold = self.threshold;
            let prss_setup = self.prss_setup.clone();

            let party_keyshare = self
                .keyshares
                .clone()
                .map(|ks| ks[index_id].clone())
                .ok_or_else(|| anyhow!("key share not set"))?;

            let ct = ct.clone();
            let mode = mode.clone();

            set.spawn(async move {
                let mut rng = AesRng::seed_from_u64(0);
                let mut session = DistributedSession::new(
                    session_id,
                    role_assignments,
                    net,
                    threshold,
                    prss_setup,
                );
                let out = run_decryption(
                    &mut session,
                    &identity,
                    party_keyshare,
                    ct,
                    mode,
                    rng.next_u64(),
                )
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
    output_party_id: usize,
) -> anyhow::Result<Option<Value>> {
    if role.party_id() == output_party_id {
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
            let rcv_val = v??;

            let share = match rcv_val {
                NetworkValue::RingValue(rv) => rv,
                _ => Err(anyhow!("I have received sth different from a ring value!"))?,
            };

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
                for max_error in 0..=t {
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
            .get(&Role(output_party_id as u64))
            .ok_or(anyhow!(
                "Couldn't get identity for role {output_party_id} in opening"
            ))?
            .clone();

        let networking = Arc::clone(&session.networking);
        let share = share.clone();
        let session_id = session.session_id;

        tokio::spawn(async move {
            let _ = networking
                .send(NetworkValue::RingValue(share), &receiver, &session_id)
                .await;
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
    input_party_id: usize,
) -> anyhow::Result<Value> {
    if role.party_id() == input_party_id {
        let threshold = session.threshold;
        let si = {
            match value {
                Some(v) => v.clone(),
                None => {
                    return Err(anyhow!(
                        "Expected Some(v) as an input argument for the input party, got None"
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
                let _ = networking
                    .send(NetworkValue::RingValue(share), &receiver, &session_id)
                    .await;
            });
        }
        while (set.join_next().await).is_some() {}
        Ok(shamir_sharings[0].clone())
    } else {
        session.networking.increase_round_counter().await?;
        let sender = session
            .role_assignments
            .get(&Role(input_party_id as u64))
            .ok_or(anyhow!("couldn't get identity for role {input_party_id}"))?
            .clone();

        let networking = Arc::clone(&session.networking);
        let session_id = session.session_id;
        let data =
            tokio::spawn(async move { networking.receive(&sender, &session_id).await }).await??;

        let data = match data {
            NetworkValue::RingValue(rv) => rv,
            _ => Err(anyhow!("I have received sth different from a ring value!"))?,
        };

        Ok(data)
    }
}

pub async fn transfer_pk(
    session: &DistributedSession,
    pubkey: &PublicKey,
    role: &Role,
    input_party_id: usize,
) -> anyhow::Result<PublicKey> {
    if role.party_id() == input_party_id {
        let num_parties = session.role_assignments.len();
        let pkval = NetworkValue::PubKey(pubkey.clone());

        let mut set = JoinSet::new();
        for to_send_role in 1..=num_parties {
            if to_send_role != input_party_id {
                let identity = session
                    .role_assignments
                    .get(&Role(to_send_role as u64))
                    .ok_or(anyhow!("couldn't get identity for role {to_send_role}"))?
                    .clone();

                let networking = Arc::clone(&session.networking);
                let session_id = session.session_id;
                let send_pk = pkval.clone();

                set.spawn(async move {
                    let _ = networking.send(send_pk, &identity, &session_id).await;
                });
            }
        }
        while (set.join_next().await).is_some() {}
        Ok(pubkey.clone())
    } else {
        let receiver = session
            .role_assignments
            .get(&Role(input_party_id as u64))
            .ok_or(anyhow!("couldn't get identity for role {input_party_id}"))?
            .clone();
        let networking = Arc::clone(&session.networking);
        let session_id = session.session_id;
        let data: NetworkValue =
            tokio::spawn(async move { networking.receive(&receiver, &session_id).await }).await??;

        let pk = match data {
            NetworkValue::PubKey(pk) => pk,
            _ => Err(anyhow!("I have received sth different from a public key!"))?,
        };
        Ok(pk)
    }
}

/// run selected circuit operations
/// this will be replaced by separate endpoints for individual functions in the future
/// TODO(Daniel) remove this from production builds
pub async fn run_circuit_operations_debug<R: RngCore>(
    session: &mut DistributedSession,
    own_identity: &Identity,
    circuit: &Circuit,
    keyshares: Option<SecretKeyShare>,
    ct: Option<Ciphertext>,
    rng: &mut R,
) -> anyhow::Result<Vec<Value>> {
    let mut env: HashMap<&String, Value> = HashMap::new();
    let mut outputs = Vec::new();

    let own_role = session.get_role_from(own_identity)?;

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

                let secret = match own_role.party_id() {
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
                if own_role.party_id() == INPUT_PARTY_ID {
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
                if own_role.party_id() == INPUT_PARTY_ID {
                    let dest = op
                        .operands
                        .get(0)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?;

                    let source = op
                        .operands
                        .get(1)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?;

                    let source_val = env
                        .get(&source.to_string())
                        .ok_or_else(|| anyhow!("Couldn't find register {source}"))?
                        .clone();

                    let offset = usize::from_str(
                        op.operands
                            .get(2)
                            .ok_or_else(|| anyhow!("Wrong index buddy"))?,
                    )?;

                    match source_val {
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
                // this instruction does steps 1-3 from dist dec paper, proto 2
                // computes a sharing of b - a * s + E
                // where dim(a) = L, E = sum(shared_bits)
                let dest = op
                    .operands
                    .get(0)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;

                let prep_seed = u64::from_str(
                    op.operands
                        .get(1)
                        .ok_or_else(|| anyhow!("Couldn't retrieve seed"))?,
                )?;

                let ciphertext = ct
                    .clone()
                    .ok_or_else(|| anyhow!("no ciphertext found to decrypt"))?;

                let s = crate::execution::prep::ddec_prep(
                    prep_seed,
                    own_role.party_id(),
                    session.threshold as usize,
                    keyshares
                        .clone()
                        .ok_or_else(|| anyhow!("Key share not set"))?,
                    &ciphertext,
                )?;
                tracing::debug!("finished generating proto 2 prep: {:?}", s);
                env.insert(dest, s);
            }
            PrssPrep => {
                // this instruction calls PRSS.next() in steps 1-2 from dist dec paper, proto 1
                // computes a sharing of b - a * s + E
                // where dim(a) = L, E = sum(shared_bits)
                let dest = op
                    .operands
                    .get(0)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;

                let prss_state = session
                    .prss_state
                    .as_mut()
                    .ok_or_else(|| anyhow!("PRSS_State not initialized"))?;

                let ciphertext = ct
                    .clone()
                    .ok_or_else(|| anyhow!("no ciphertext found to decrypt"))?;

                let s = crate::execution::prep::prss_prep(
                    own_role.party_id(),
                    prss_state,
                    keyshares
                        .clone()
                        .ok_or_else(|| anyhow!("Key share not set"))?,
                    &ciphertext,
                )?;
                tracing::debug!("finished generating PRSS prep: {:?}", s);
                env.insert(dest, s);
            }
            FaultyThreshold => {
                // all parties up to (including) t manipulate their share
                // (to simulate a faulty/malicious party in benchmarking)
                if own_role.party_id() <= session.threshold as usize {
                    let dest = op
                        .operands
                        .get(0)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?;

                    let correct_share_value = env
                        .get(dest)
                        .ok_or_else(|| anyhow!("Couldn't retrieve party share to modify"))?;

                    // increase value of existing share by 1
                    if let Value::IndexedShare128(share) = correct_share_value {
                        tracing::debug!(
                            "I'm party {} and I will send bollocks!",
                            own_role.party_id()
                        );
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
    Ok(outputs)
}

/// run decryption
pub async fn run_decryption(
    session: &mut DistributedSession,
    own_identity: &Identity,
    keyshares: SecretKeyShare,
    ciphertext: Ciphertext,
    mode: DecryptionMode,
    seed: u64,
) -> anyhow::Result<Vec<Value>> {
    let mut outputs = Vec::new();

    let own_role = session.get_role_from(own_identity)?;

    let plaintext_bits = keyshares.plaintext_bits;

    let res = match mode {
        DecryptionMode::PRSSDecrypt => {
            let prss_state = session
                .prss_state
                .as_mut()
                .ok_or_else(|| anyhow!("PRSS_State not initialized"))?;

            crate::execution::prep::prss_prep(
                own_role.party_id(),
                prss_state,
                keyshares,
                &ciphertext,
            )?
        }
        DecryptionMode::Proto2Decrypt => crate::execution::prep::ddec_prep(
            seed,
            own_role.party_id(),
            session.threshold as usize,
            keyshares,
            &ciphertext,
        )?,
    };

    let opened = robust_open_to(session, &res, &own_role, 1).await?;

    if own_role.party_id() == INPUT_PARTY_ID {
        // shift
        let c = match opened {
            Some(Value::Ring128(v)) => Value::Ring128(v >> (127 - plaintext_bits) as usize),
            Some(Value::Ring64(v)) => Value::Ring64(v >> (63 - plaintext_bits) as usize),
            _ => {
                return Err(anyhow!(
                    "Right shift not possible - wrong opened value type"
                ))
            }
        };

        outputs.push(c);
    }

    Ok(outputs)
}

pub async fn initialize_key_material<R: RngCore>(
    session: &DistributedSession,
    own_identity: &Identity,
    rng: &mut R,
    setup_mode: SetupMode,
    big_ell: u32,
    plaintext_bits: u8,
    seed: u64,
) -> anyhow::Result<(SecretKeyShare, PublicKey, Option<PRSSSetup>)> {
    let own_role = session.get_role_from(own_identity)?;

    // initialize PRSS
    let num_parties = session.role_assignments.len();
    let mut prss_rng = AesRng::seed_from_u64(seed); // use a fixed seed until we have implemented AgreeRandom

    // TODO remove party/threshold from if condition when PRSS is generic and independent of (n,t)
    let prss_setup =
        if setup_mode == SetupMode::AllProtos && num_parties == 4 && session.threshold == 1 {
            Some(PRSSSetup::epoch_init(
                num_parties,
                session.threshold as usize,
                &mut prss_rng,
            ))
        } else {
            None
        };

    let mut sk: SecretKey = SecretKey::default(); // keys must be initialized for all parties
    let mut pk: PublicKey = PublicKey::default();

    if own_role.party_id() == INPUT_PARTY_ID {
        (sk, pk) = keygen(rng, big_ell, plaintext_bits);
    }

    let mut key_shares = Vec::new();
    // iterate through sk and share each element
    for i in 0..big_ell as usize {
        let secret = match own_role.party_id() {
            1 => Some(Value::Ring128(sk.s[i])),
            _ => None,
        };
        let share: Value = robust_input(rng, session, &secret, &own_role, 1).await?; //TODO(Daniel) batch this for all big_ell

        if let Value::IndexedShare128((_id, s)) = share {
            key_shares.push(s);
        }
    }

    let transferred_pk = transfer_pk(session, &pk, &own_role, 1).await?;

    let shared_sk = SecretKeyShare {
        s: Array1::from_vec(key_shares),
        plaintext_bits,
    };

    Ok((shared_sk, transferred_pk, prss_setup))
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

        let runtime = DistributedTestRuntime::new(identities, threshold, None, None);
        let results = runtime.evaluate_circuit(&circuit, None).unwrap();
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

        let runtime = DistributedTestRuntime::new(identities, threshold, None, None);
        let results = runtime.evaluate_circuit(&circuit, None).unwrap();
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
        let runtime = DistributedTestRuntime::new(identities, threshold, None, None);
        let results = runtime.evaluate_circuit(&circuit, None).unwrap();
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
        let runtime = DistributedTestRuntime::new(identities, threshold, None, None);
        let results = runtime.evaluate_circuit(&circuit, None).unwrap();
        let out = &results[&Identity("localhost:5000".to_string())];
        assert_eq!(out[0], Value::Ring128(std::num::Wrapping(100)));
        assert_eq!(out[1], Value::Ring128(std::num::Wrapping(101)));
        assert_eq!(out[2], Value::Ring128(std::num::Wrapping(102)));
    }
}

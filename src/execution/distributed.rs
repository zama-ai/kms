use super::prss::PRSSSetup;
use crate::circuit::{Circuit, Operator};
use crate::computation::SessionId;
use crate::execution::constants::INPUT_PARTY_ID;
use crate::execution::party::{Identity, Role, RoleAssignment};
use crate::execution::prss::PRSSState;
use crate::lwe::{
    from_expanded_msg, gen_key_set, Ciphertext128, PubConKeyPair, SecretKeyShare,
    ThresholdLWEParameters,
};
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
use num_integer::div_ceil;
use rand::RngCore;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::num::Wrapping;
use std::str::FromStr;
use std::sync::Arc;
use tfhe::integer::block_decomposition::{BlockDecomposer, BlockRecomposer};
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
    pub own_identity: Identity,
}

impl DistributedSession {
    pub fn new(
        session_id: SessionId,
        role_assignments: HashMap<Role, Identity>,
        networking: NetworkingImpl,
        threshold: u8,
        prss_setup: Option<PRSSSetup>,
        own_identity: Identity,
    ) -> Self {
        DistributedSession {
            session_id,
            role_assignments,
            networking,
            threshold,
            own_identity,
            prss_state: prss_setup.map(|x| x.new_session(session_id)),
        }
    }

    pub fn get_identity_from(&self, role: &Role) -> anyhow::Result<Identity> {
        match self.role_assignments.get(role) {
            Some(identity) => Ok(identity.clone()),
            None => Err(anyhow!("Role {} does not exist", role.0)),
        }
    }

    pub fn get_amount_of_parties(&self) -> usize {
        self.role_assignments.len()
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
    pub identities: Vec<Identity>,
    threshold: u8,
    prss_setups: Vec<Option<PRSSSetup>>,
    keyshares: Option<Vec<SecretKeyShare>>,
    pub user_nets: Vec<Arc<LocalNetworking>>,
    pub role_assignments: RoleAssignment,
}

impl DistributedTestRuntime {
    pub fn new(
        identities: Vec<Identity>,
        threshold: u8,
        keyshares: Option<Vec<SecretKeyShare>>,
        setup_mode: SetupMode,
    ) -> Self {
        let role_assignments: RoleAssignment = identities
            .clone()
            .into_iter()
            .enumerate()
            .map(|(role_id, identity)| (Role(role_id as u64 + 1), identity))
            .collect();

        let prss_setups: Vec<Option<PRSSSetup>> = match setup_mode {
            SetupMode::AllProtos => {
                let mut prss_rng = AesRng::seed_from_u64(2023);

                identities
                    .clone()
                    .into_iter()
                    .enumerate()
                    .map(|(role_id, _identity)| {
                        PRSSSetup::party_epoch_init(
                            role_assignments.len(),
                            threshold as usize,
                            &mut prss_rng,
                            role_id + 1,
                        )
                        .ok()
                    })
                    .collect()
            }
            _ => vec![None; identities.len()],
        };

        let net_producer = LocalNetworkingProducer::from_ids(&identities);
        let user_nets: Vec<Arc<LocalNetworking>> = identities
            .iter()
            .map(|user_identity| {
                let net = net_producer.user_net(user_identity.clone());
                Arc::new(net)
            })
            .collect();

        DistributedTestRuntime {
            identities,
            threshold,
            prss_setups,
            keyshares,
            user_nets,
            role_assignments,
        }
    }

    pub fn session_for_player(
        &self,
        session_id: SessionId,
        player_id: usize,
    ) -> DistributedSession {
        let role_assignments = self.role_assignments.clone();
        let net = Arc::clone(&self.user_nets[player_id]);
        let prss_setup = None;
        let own_role = Role(player_id as u64 + 1);
        let identity = self.role_assignments[&own_role].clone();

        DistributedSession::new(
            session_id,
            role_assignments,
            net,
            self.threshold,
            prss_setup,
            identity,
        )
    }

    /// test the circuit evaluation
    pub fn evaluate_circuit(
        &self,
        circuit: &Circuit,
        ct: Option<Ciphertext128>,
    ) -> anyhow::Result<HashMap<Identity, Vec<Value>>> {
        // TODO(Dragos) replaced this with a random sid
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new()?;
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        for (index_id, identity) in self.identities.clone().into_iter().enumerate() {
            let role_assignments = self.role_assignments.clone();
            let net = Arc::clone(&self.user_nets[index_id]);
            let circuit = circuit.clone();
            let threshold = self.threshold;
            let prss_setup = self.prss_setups[index_id].clone();

            let party_keyshare = self.keyshares.clone().map(|ks| ks[index_id].clone());

            let ct: Option<Ciphertext128> = ct.clone();

            set.spawn(async move {
                let mut rng = AesRng::seed_from_u64(0);
                let mut session = DistributedSession::new(
                    session_id,
                    role_assignments,
                    net,
                    threshold,
                    prss_setup,
                    identity.clone(),
                );
                let out = run_circuit_operations_debug(
                    &mut session,
                    &identity,
                    &circuit,
                    party_keyshare.as_ref(),
                    ct.as_ref(),
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
                if let Err(e) = v {
                    tracing::debug!("Got error: {:?}", e);
                } else if let Ok((identity, val)) = v {
                    results.insert(identity, val);
                }
            }
            results
        });
        Ok(results)
    }

    /// test the threshold decryption
    pub fn threshold_decrypt(
        &self,
        ct: Ciphertext128,
        mode: DecryptionMode,
    ) -> anyhow::Result<HashMap<Identity, Vec<Value>>> {
        // TODO(Dragos) replaced this with a random sid
        let session_id = SessionId(2);

        let rt = tokio::runtime::Runtime::new()?;
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        for (index_id, identity) in self.identities.clone().into_iter().enumerate() {
            let role_assignments = self.role_assignments.clone();
            let net = Arc::clone(&self.user_nets[index_id]);
            let threshold = self.threshold;
            let prss_setup = self.prss_setups[index_id].clone();

            let party_keyshare = self
                .keyshares
                .clone()
                .map(|ks| ks[index_id].clone())
                .ok_or_else(|| anyhow!("key share not set during decryption"))?;

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
                    identity.clone(),
                );
                let out = run_decryption(
                    &mut session,
                    &identity,
                    &party_keyshare,
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
    session.networking.increase_round_counter().await?;
    if role.party_id() == output_party_id {
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

            let num_parties = session.get_amount_of_parties();
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
    session.networking.increase_round_counter().await?;
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
        let num_parties = session.get_amount_of_parties();

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
            Value::U64(s64) => {
                let sharings = ShamirGSharings::<Z64>::share(
                    rng,
                    Wrapping(s64),
                    num_parties,
                    threshold as usize,
                )?;
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
            _ => {
                return Err(anyhow!(
                    "Cannot share a value which has type different than U64, Ring64/Ring128"
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
    pubkey: &PubConKeyPair,
    role: &Role,
    input_party_id: usize,
) -> anyhow::Result<PubConKeyPair> {
    if role.party_id() == input_party_id {
        let num_parties = session.get_amount_of_parties();
        let pkval = NetworkValue::PubKey(Box::new(pubkey.clone()));

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
        Ok(*pk)
    }
}

/// Helper function that takes a vector of decrypted plaintexts (each of [bits_in_block] plaintext bits)
/// and combine them into the integer message (u128) of many bits.
fn combine(bits_in_block: u32, decryptions: Vec<Value>) -> anyhow::Result<u128> {
    let mut recomposer = BlockRecomposer::<u128>::new(bits_in_block);

    for block in decryptions {
        let value = match block {
            Value::IndexedShare128(value) => value.1.coefs[0].0,
            Value::IndexedShare64(value) => value.1.coefs[0].0 as u128,
            Value::Ring128(value) => value.0,
            Value::Ring64(value) => value.0 as u128,
            Value::U64(value) => value as u128,
            Value::Poly64(value) => value.coefs[0].0 as u128,
            Value::Poly128(value) => value.coefs[0].0,
        };
        if !recomposer.add_unmasked(value) {
            // End of T::BITS reached no need to try more
            // recomposition
            break;
        };
    }
    Ok(recomposer.value())
}

/// run selected circuit operations
/// this will be replaced by separate endpoints for individual functions in the future
/// TODO(Daniel) remove this from production builds
pub async fn run_circuit_operations_debug<R: RngCore>(
    session: &mut DistributedSession,
    own_identity: &Identity,
    circuit: &Circuit,
    keyshares: Option<&SecretKeyShare>,
    ct: Option<&Ciphertext128>,
    rng: &mut R,
) -> anyhow::Result<Vec<Value>> {
    // env holds a map from a variable to a list of ciphertext, or partial decrypted ciphertexts or decrypted value (depending on the circuit evaluation calls executed)
    let mut env: HashMap<&String, Vec<Value>> = HashMap::new();
    let mut outputs = Vec::new();

    let own_role = session.get_role_from(own_identity)?;

    #[allow(clippy::get_first)]
    for op in circuit.operations.iter() {
        use Operator::*;
        match op.operator {
            // Privately input a value.
            // Operand 0 => register to store the private value
            // Operand 1 => the value given as input
            // Operand 2 => the amount of bits that can be used in each ciphertext block
            // Operand 3 => how many bits should the plaintext domain be
            LdSI => {
                let r0 = op
                    .operands
                    .get(0)
                    .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                let si = u32::from_str(
                    op.operands
                        .get(1)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?,
                )?;
                let bits_in_block = u32::from_str(
                    op.operands
                        .get(2)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?,
                )?;
                let bits_to_encrypt = u32::from_str(
                    op.operands
                        .get(3)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?,
                )?;
                let amount_of_blocks = div_ceil(bits_to_encrypt, bits_in_block);

                let mut sharings = Vec::new();
                if own_role.party_id() == 1 {
                    let decomposer = BlockDecomposer::new(si, bits_in_block);
                    for block in decomposer.iter_as::<u64>().take(amount_of_blocks as usize) {
                        let sharing: Value =
                            robust_input(rng, session, &Some(Value::U64(block)), &own_role, 1)
                                .await?;
                        sharings.push(sharing);
                    }
                } else {
                    for _ in 1..=amount_of_blocks {
                        let sharing = robust_input(rng, session, &None, &own_role, 1).await?;
                        sharings.push(sharing);
                    }
                }
                env.insert(r0, sharings);
            }
            // Opens an encrypted value.
            // Operand 0 => not in use
            // Operand 1 => not in use
            // Operand 2 => register to store the opened value
            // Operand 2 => register of the value to open
            Open => {
                tracing::info!("started to execute open instruction");
                let c0: &String = op
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
                let mut opened = Vec::new();
                for current_share in own_share {
                    // TODO is this the behaviour we want here?
                    if let Some(val) = robust_open_to(session, current_share, &own_role, 1).await? {
                        opened.push(val);
                    }
                }
                env.insert(c0, opened);
            }
            // Inputs a public constant.
            // Operand 0 => register to store the constant
            // Operand 1 => the constant to store, as an unsigned 64 bit integer
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
                env.insert(r0, vec![ci]);
            }
            // Returns an opened value stored in a register as output.
            // Operand 0 => register of the opened value
            // Operand 1 => the amount of bits in the plaintext space of each ciphertext block
            PrintRegPlain => {
                if own_role.party_id() == INPUT_PARTY_ID {
                    let r0 = op
                        .operands
                        .get(0)
                        .ok_or_else(|| anyhow!("Wrong index buddy"))?;
                    let bits_in_block = u32::from_str(
                        op.operands
                            .get(1)
                            .ok_or_else(|| anyhow!("Wrong index buddy"))?,
                    )?;
                    let val = env
                        .get(&r0.to_string())
                        .ok_or_else(|| anyhow!("Couldn't find register {r0}"))?
                        .clone();
                    let res = match combine(bits_in_block, val) {
                        Ok(res) => res,
                        Err(error) => {
                            eprint!("Panicked in combining {error}");
                            return Err(error);
                        }
                    };
                    outputs.append(&mut vec![Value::Ring128(Wrapping(res))]);
                }
            }
            // Computes a specified right shift of an open value, stored in a register with rounding.
            // This is particularely useful when decoding a full-domain decrypted value to its actual plaintext value.
            // Operand 0 => register to store the result
            // Operand 1 => register of the open value to shift
            // Operand 2 => value as unsigned integer indicating how many bits the shift should be
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

                    let mut res = Vec::new();
                    for current_source in source_val {
                        match current_source {
                            Value::Ring128(v) => {
                                res.push(Value::Ring128(v >> offset));
                            }
                            Value::Ring64(v) => {
                                res.push(Value::Ring64(v >> offset));
                            }
                            _ => return Err(anyhow!("Cannot do shift right on a cleartext register with a different type than Ring64/Ring128"))
                        };
                    }
                    env.insert(dest, res);
                }
            }
            // Computes a specified right shift of an open value, stored in a register.
            // Operand 0 => register to store the result
            // Operand 1 => register of the open value to shift
            // Operand 2 => value as unsigned integer indicating how many bits the shift should be
            ShrCIRound => {
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

                    let mut res = Vec::new();
                    for current_source in source_val {
                        match current_source {
                            Value::Ring128(v) => {
                                let rounding_bit = 1 << (offset - 1);
                                let rounding = (v.0 & rounding_bit) << 1;
                                res.push(Value::Ring128(Wrapping(v.0 + rounding) >> offset));
                            },
                            Value::Ring64(v) => {
                                let rounding_bit = 1 << (offset - 1);
                                let rounding = (v.0 & rounding_bit) << 1;
                                res.push(Value::Ring64(Wrapping(v.0 + rounding) >> offset));
                            },
                            _ => return Err(anyhow!("Cannot do shift right on a cleartext register with a different type than Ring64/Ring128"))
                        };
                    }
                    env.insert(dest, res);
                }
            }
            // Computes random shared bits to be used to add noise for distributed decryption.
            // Operand 0 => register to store the result
            // Operand 1 => seed to use for the randomness generation
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
                let ciphertext = ct.ok_or_else(|| anyhow!("no ciphertext found to decrypt"))?;
                let existing_keyshare =
                    keyshares.ok_or_else(|| anyhow!("Key share not set during dist prep"))?;
                let mut block_shares = Vec::with_capacity(ciphertext.len());
                for i in 0..ciphertext.len() {
                    // current_block in ciphertext {
                    let block_share = crate::execution::prep::ddec_prep(
                        prep_seed,
                        own_role.party_id(),
                        session.threshold as usize,
                        existing_keyshare,
                        ciphertext
                            .get(i)
                            .ok_or_else(|| anyhow!("Wrong index in ciphertext"))?,
                    )?;
                    tracing::debug!("finished generating proto 2 prep: {:?}", block_share);
                    block_shares.push(block_share);
                }
                env.insert(dest, block_shares);
            }
            // Computes random noise using a pseudorandom generator for use in distributed decryption.
            // Operand 0 => register to store the result
            // Operand 1 => the pseudorandom generator state
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

                let ciphertext = ct.ok_or_else(|| anyhow!("no ciphertext found to decrypt"))?;

                let existing_keyshare =
                    keyshares.ok_or_else(|| anyhow!("Key share not set during prssprep"))?;
                let mut partial_decrypted_blocks = Vec::with_capacity(ciphertext.len());
                for i in 0..ciphertext.len() {
                    // current_block in ciphertext {
                    let partial_decryption = crate::execution::prep::prss_prep(
                        own_role.party_id(),
                        prss_state,
                        existing_keyshare,
                        ciphertext
                            .get(i)
                            .ok_or_else(|| anyhow!("Wrong index in ciphertext"))?,
                    )?;
                    tracing::debug!(
                        "finished generating PRSS proto prep: {:?}",
                        partial_decryption
                    );
                    partial_decrypted_blocks.push(partial_decryption);
                }
                env.insert(dest, partial_decrypted_blocks);
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
                    let mut parsed_shares = Vec::with_capacity(correct_share_value.len());
                    for current_share in correct_share_value {
                        // increase value of existing share by 1
                        if let Value::IndexedShare128(parsed_share) = current_share {
                            tracing::debug!(
                                "I'm party {} and I will send bollocks!",
                                own_role.party_id()
                            );
                            parsed_shares.push(Value::IndexedShare128((
                                parsed_share.0,
                                parsed_share.1 + ResiduePoly::ONE,
                            )));
                        } else {
                            return Err(anyhow!(
                                "Other type than IndexShare128 found in threshold_fault"
                            ));
                        }
                    }
                    env.insert(dest, parsed_shares);
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
    keyshares: &SecretKeyShare,
    ciphertext: Ciphertext128,
    mode: DecryptionMode,
    seed: u64,
) -> anyhow::Result<Vec<Value>> {
    let mut outputs = Vec::new();

    let own_role = session.get_role_from(own_identity)?;

    let mut partial_decrypted = Vec::with_capacity(ciphertext.len());
    for current_ct_block in ciphertext {
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
                    &current_ct_block,
                )?
            }
            DecryptionMode::Proto2Decrypt => crate::execution::prep::ddec_prep(
                seed,
                own_role.party_id(),
                session.threshold as usize,
                keyshares,
                &current_ct_block,
            )?,
        };

        let opened = robust_open_to(session, &res, &own_role, 1).await?;

        if own_role.party_id() == INPUT_PARTY_ID {
            let message_mod_bits = keyshares
                .threshold_lwe_parameters
                .output_cipher_parameters
                .message_modulus_log
                .0;
            // shift
            let c = match opened {
                Some(Value::Ring128(v)) => Value::Ring128(from_expanded_msg(v.0, message_mod_bits)),
                _ => {
                    return Err(anyhow!(
                        "Right shift not possible - wrong opened value type"
                    ))
                }
            };
            partial_decrypted.push(c);
        }
    }
    if own_role.party_id() == INPUT_PARTY_ID {
        let bits_in_block = keyshares
            .threshold_lwe_parameters
            .output_cipher_parameters
            .usable_message_modulus_log
            .0;
        let res = match combine(bits_in_block as u32, partial_decrypted) {
            Ok(res) => res,
            Err(error) => {
                eprint!("Panicked in combining {error}");
                return Err(error);
            }
        };
        outputs.push(Value::Ring128(Wrapping(res)));
    }

    Ok(outputs)
}

pub async fn initialize_key_material<R: RngCore>(
    session: &DistributedSession,
    own_identity: &Identity,
    rng: &mut R,
    setup_mode: SetupMode,
    params: ThresholdLWEParameters,
    seed: u64,
) -> anyhow::Result<(SecretKeyShare, PubConKeyPair, Option<PRSSSetup>)> {
    let own_role = session.get_role_from(own_identity)?;

    // initialize PRSS
    let num_parties = session.get_amount_of_parties();
    let mut prss_rng = AesRng::seed_from_u64(seed); // use a fixed seed until we have implemented AgreeRandom

    let prss_setup = if setup_mode == SetupMode::AllProtos {
        Some(PRSSSetup::party_epoch_init(
            num_parties,
            session.threshold as usize,
            &mut prss_rng,
            own_role.party_id(),
        )?)
    } else {
        None
    };

    let keyset = gen_key_set(params, rng);

    let sk_container = keyset.sk.lwe_secret_key_128.into_container();
    let mut key_shares = Vec::new();
    // iterate through sk and share each element
    for cur in sk_container {
        let secret = match own_role.party_id() {
            1 => Some(Value::Ring128(Wrapping(cur))),
            _ => None,
        };
        let share: Value = robust_input(rng, session, &secret, &own_role, 1).await?; //TODO(Daniel) batch this for all big_ell

        if let Value::IndexedShare128((_id, s)) = share {
            key_shares.push(s);
        }
    }
    let pubcon = PubConKeyPair {
        pk: keyset.pk,
        ck: keyset.ck,
    };
    let transferred_pk = transfer_pk(session, &pubcon, &own_role, 1).await?;

    let shared_sk = SecretKeyShare {
        input_key_share: Array1::from_vec(key_shares),
        threshold_lwe_parameters: params,
    };

    Ok((shared_sk, transferred_pk, prss_setup))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuit::Operation, file_handling::read_as_json,
        tests::test_data_setup::tests::DEFAULT_PARAM_PATH,
    };
    use tracing_test::traced_test;

    #[traced_test]
    #[test]
    fn test_load_ci_circuit() {
        let circuit = Circuit {
            operations: vec![
                Operation {
                    operator: Operator::LdCI, // Input
                    operands: vec![
                        String::from("c0"),  // Variable name
                        String::from("100"), // Value of variable
                    ],
                },
                Operation {
                    operator: Operator::PrintRegPlain, // Recompose (opened ciphertexts) and print the result
                    operands: vec![
                        String::from("c0"), // Variable name
                        String::from("8"),  // bits per block
                    ],
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

        let runtime = DistributedTestRuntime::new(identities, threshold, None, SetupMode::NoPrss);
        let results = runtime.evaluate_circuit(&circuit, None).unwrap();
        let out = &results[&Identity("localhost:5000".to_string())];
        assert_eq!(out[0], Value::Ring128(Wrapping(100)));
    }

    #[traced_test]
    #[test]
    fn test_open_secret_large_t() {
        let circuit = Circuit {
            operations: vec![
                Operation {
                    operator: Operator::LdSI, // Input
                    operands: vec![
                        String::from("s0"),  // Variable name
                        String::from("100"), // Value to input
                        String::from("4"),   // bits per block
                        String::from("8"),   // bits to encode input
                    ],
                },
                Operation {
                    operator: Operator::Open, // Open
                    operands: vec![
                        String::from("1"),     // Unused
                        String::from("false"), // Unused
                        String::from("c0"),    // Variable name to store the opened value in
                        String::from("s0"),    // Variable name to open
                    ],
                },
                Operation {
                    operator: Operator::PrintRegPlain, // Recompose (opened ciphertexts) and print the result
                    operands: vec![
                        String::from("c0"), // Variable name to print
                        String::from("4"),  // bits per block
                    ],
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

        let runtime = DistributedTestRuntime::new(identities, threshold, None, SetupMode::NoPrss);
        let results = runtime.evaluate_circuit(&circuit, None).unwrap();
        let out = &results[&Identity("localhost:5000".to_string())];
        assert_eq!(out[0], Value::Ring128(std::num::Wrapping(100)));
    }

    #[test]
    fn test_open_secret_small_t() {
        let msg: u8 = 15;
        let params: ThresholdLWEParameters = read_as_json(DEFAULT_PARAM_PATH.to_string()).unwrap();
        let usable_mod_bits = params.input_cipher_parameters.usable_message_modulus_log.0;
        let circuit = Circuit {
            operations: vec![
                Operation {
                    operator: Operator::LdSI, // Input
                    operands: vec![
                        String::from("s0"),          // Variable name
                        msg.to_string(),             // Value of variable
                        usable_mod_bits.to_string(), // bits per block
                        String::from("8"),           // bits to encode input
                    ],
                },
                Operation {
                    operator: Operator::Open, // Open encrypted values
                    operands: vec![
                        String::from("1"),     // Unused
                        String::from("false"), // Unused
                        String::from("c0"),    // Variable name to store the opened value in
                        String::from("s0"),    // Variable name to open
                    ],
                },
                Operation {
                    operator: Operator::PrintRegPlain,
                    operands: vec![String::from("c0"), usable_mod_bits.to_string()],
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
        let runtime = DistributedTestRuntime::new(identities, threshold, None, SetupMode::NoPrss);
        let results = runtime.evaluate_circuit(&circuit, None).unwrap();
        let out = &results[&Identity("localhost:5000".to_string())];
        assert_eq!(out[0], Value::Ring128(std::num::Wrapping(msg as u128)));
    }

    #[test]
    fn test_multiple_opens() {
        let params: ThresholdLWEParameters =
            read_as_json("parameters/default_params.json".to_string()).unwrap();
        let usable_mod_bits = params.input_cipher_parameters.usable_message_modulus_log.0;
        let circuit: Circuit = Circuit {
            operations: vec![
                Operation {
                    operator: Operator::LdSI, // Input
                    operands: vec![
                        String::from("s0"),          // Variable name
                        String::from("100"),         // Value of variable
                        usable_mod_bits.to_string(), // bits per block
                        String::from("8"),           // bits to encode input
                    ],
                },
                Operation {
                    operator: Operator::LdSI,
                    operands: vec![
                        String::from("s1"),
                        String::from("101"),
                        usable_mod_bits.to_string(),
                        String::from("8"), // bits to encode input
                    ],
                },
                Operation {
                    operator: Operator::LdSI,
                    operands: vec![
                        String::from("s2"),
                        String::from("102"),
                        usable_mod_bits.to_string(),
                        String::from("8"), // bits to encode input
                    ],
                },
                Operation {
                    operator: Operator::Open, // Open the ciphertext blocks
                    operands: vec![
                        String::from("1"),     // Unused
                        String::from("false"), // Unused
                        String::from("c0"),    // Variable to store opened value in
                        String::from("s0"),    // Varible to open from
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
                    operator: Operator::PrintRegPlain, // Recombine and print opened value
                    operands: vec![
                        String::from("c0"),          // Variable to open
                        usable_mod_bits.to_string(), // Bits per ciphertext block
                    ],
                },
                Operation {
                    operator: Operator::PrintRegPlain,
                    operands: vec![String::from("c1"), usable_mod_bits.to_string()],
                },
                Operation {
                    operator: Operator::PrintRegPlain,
                    operands: vec![String::from("c2"), usable_mod_bits.to_string()],
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
        let runtime = DistributedTestRuntime::new(identities, threshold, None, SetupMode::NoPrss);
        let results = runtime.evaluate_circuit(&circuit, None).unwrap();
        let out = &results[&Identity("localhost:5000".to_string())];
        assert_eq!(out[0], Value::Ring128(std::num::Wrapping(100)));
        assert_eq!(out[1], Value::Ring128(std::num::Wrapping(101)));
        assert_eq!(out[2], Value::Ring128(std::num::Wrapping(102)));
    }
}

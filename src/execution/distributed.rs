use super::broadcast::send_to_all;
use super::{
    agree_random::{AgreeRandom, DummyAgreeRandom},
    session::{
        BaseSession, BaseSessionHandles, DecryptionMode, LargeSession, ParameterHandles,
        SessionParameters, SetupMode, SmallSession,
    },
    small_execution::prss::PRSSSetup,
};
use crate::execution::broadcast::generic_receive_from_all;
use crate::execution::party::{Identity, Role, RoleAssignment};
use crate::execution::{constants::INPUT_PARTY_ID, session::ToBaseSession};
use crate::lwe::{
    from_expanded_msg, gen_key_set, Ciphertext128, PubConKeyPair, SecretKeyShare,
    ThresholdLWEParameters,
};
use crate::networking::local::{LocalNetworking, LocalNetworkingProducer};
use crate::residue_poly::ResiduePoly;
use crate::shamir::ShamirGSharings;
use crate::value::{err_reconstruct, IndexedValue, NetworkValue, Value};
use crate::{
    circuit::{Circuit, Operator},
    execution::small_execution::prep::ddec_prep,
};
use crate::{computation::SessionId, execution::small_execution::prep::prss_prep};
use crate::{One, Z128, Z64};
use aes_prng::AesRng;
use anyhow::anyhow;
use ndarray::Array1;
use num_integer::div_ceil;
use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::collections::{HashMap, HashSet};
use std::num::Wrapping;
use std::str::FromStr;
use std::sync::Arc;
use tfhe::integer::block_decomposition::{BlockDecomposer, BlockRecomposer};
use tokio::task::JoinSet;
use tokio::time::error::Elapsed;

// TODO The name and use of unwrap hints that this is a struct only to be used for testing, but it is laos used in production, e.g. in grpc.rs
// Unsafe and test code should not be mixed with production code. See issue 173
pub struct DistributedTestRuntime {
    pub identities: Vec<Identity>,
    threshold: u8,
    prss_setups: Option<HashMap<usize, PRSSSetup>>,
    keyshares: Option<Vec<SecretKeyShare>>,
    pub user_nets: Vec<Arc<LocalNetworking>>,
    pub role_assignments: RoleAssignment,
}

impl DistributedTestRuntime {
    pub fn new(identities: Vec<Identity>, threshold: u8) -> Self {
        let role_assignments: RoleAssignment = identities
            .clone()
            .into_iter()
            .enumerate()
            .map(|(role_id, identity)| (Role(role_id as u64 + 1), identity))
            .collect();

        let net_producer = LocalNetworkingProducer::from_ids(&identities);
        let user_nets: Vec<Arc<LocalNetworking>> = identities
            .iter()
            .map(|user_identity| {
                let net = net_producer.user_net(user_identity.clone());
                Arc::new(net)
            })
            .collect();

        let prss_setups = None;

        DistributedTestRuntime {
            identities,
            threshold,
            prss_setups,
            keyshares: None,
            user_nets,
            role_assignments,
        }
    }

    // store keyshares if you want to test sth related to them
    pub fn setup_keys(&mut self, keyshares: Vec<SecretKeyShare>) {
        self.keyshares = Some(keyshares);
    }

    // store prss setups if you want to test sth related to them
    pub fn setup_prss(&mut self, setups: Option<HashMap<usize, PRSSSetup>>) {
        self.prss_setups = setups;
    }

    // Setups and adds the PRSS state to the current session
    pub fn add_prss<A: AgreeRandom + Send>(session: &mut SmallSession) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let prss_setup = rt
            .block_on(async {
                PRSSSetup::party_epoch_init_sess::<A>(
                    session,
                    session.my_role().unwrap().party_id(),
                )
                .await
            })
            .unwrap();
        session.prss_state = Some(prss_setup.new_prss_session_state(session.session_id()));
    }

    pub fn small_session_for_player(
        &self,
        session_id: SessionId,
        player_id: usize,
        rng: Option<ChaCha20Rng>,
    ) -> anyhow::Result<SmallSession> {
        let role_assignments = self.role_assignments.clone();
        let net = Arc::clone(&self.user_nets[player_id]);

        let prss_setup = self
            .prss_setups
            .as_ref()
            .map(|per_party| per_party[&player_id].clone());

        let own_role = Role(player_id as u64 + 1);
        let identity = self.role_assignments[&own_role].clone();

        SmallSession::new(
            session_id,
            role_assignments,
            net,
            self.threshold,
            prss_setup,
            identity,
            rng,
        )
    }

    pub fn large_session_for_player(
        &self,
        session_id: SessionId,
        player_id: usize,
    ) -> anyhow::Result<LargeSession> {
        let role_assignments = self.role_assignments.clone();
        let net = Arc::clone(&self.user_nets[player_id]);
        let own_role = Role(player_id as u64 + 1);
        let identity = self.role_assignments[&own_role].clone();
        let parameters =
            SessionParameters::new(self.threshold, session_id, identity, role_assignments)?;
        LargeSession::new(parameters, net)
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

            let prss_setup = self
                .prss_setups
                .as_ref()
                .map(|per_party| per_party[&index_id].clone());

            let party_keyshare = self.keyshares.clone().map(|ks| ks[index_id].clone());

            let ct: Option<Ciphertext128> = ct.clone();

            set.spawn(async move {
                let mut session = SmallSession {
                    parameters: SessionParameters {
                        threshold,
                        session_id,
                        own_identity: identity.clone(),
                        role_assignments,
                    },
                    network: net,
                    rng: ChaCha20Rng::from_seed([0_u8; 32]),
                    corrupt_roles: HashSet::new(),
                    prss_state: prss_setup.map(|x| x.new_prss_session_state(session_id)),
                };
                let out = run_circuit_operations_debug::<ChaCha20Rng>(
                    &mut session,
                    &circuit,
                    party_keyshare.as_ref(),
                    ct.as_ref(),
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

            let prss_setup = self
                .prss_setups
                .as_ref()
                .map(|per_party| per_party[&index_id].clone());

            let party_keyshare = self
                .keyshares
                .clone()
                .map(|ks| ks[index_id].clone())
                .ok_or_else(|| anyhow!("key share not set during decryption"))?;

            let ct = ct.clone();
            let mode = mode.clone();

            // TODO currently things only work with the static seed rng
            set.spawn(async move {
                let mut session = SmallSession::new(
                    session_id,
                    role_assignments,
                    net,
                    threshold,
                    prss_setup,
                    identity.clone(),
                    Some(ChaCha20Rng::seed_from_u64(0)),
                )
                .unwrap();
                let out = run_decryption(&mut session, &party_keyshare, ct, mode)
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

// async helper function that creates the prss setups
pub async fn setup_prss_sess<A: AgreeRandom + Send>(
    sessions: Vec<SmallSession>,
) -> Option<HashMap<usize, PRSSSetup>> {
    let mut jobs = JoinSet::new();

    for (role_idx, sess) in sessions.iter().enumerate() {
        let ss = sess.clone();

        jobs.spawn(async move {
            let epoc = PRSSSetup::party_epoch_init_sess::<A>(&ss.clone(), role_idx + 1).await;
            (role_idx, epoc)
        });
    }

    let mut hm: HashMap<usize, PRSSSetup> = HashMap::new();

    for _ in &sessions {
        while let Some(v) = jobs.join_next().await {
            let vv = v.unwrap();
            let data = vv.1.ok().unwrap();
            let role = vv.0;
            hm.insert(role, data);
        }
    }

    Some(hm)
}

/// Helper function of robust reconstructions which collect the shares and tries to reconstruct
/// Takes as input:
/// - num_parties as number of parties
/// - indexed_share as the indexed share of the local party
/// - a set of jobs to receive the shares from the other parties
/// - t as the threshold
async fn try_reconstruct_from_shares<P: ParameterHandles>(
    session_parameters: &P,
    indexed_share: &IndexedValue,
    jobs: &mut JoinSet<Result<(Role, anyhow::Result<Value>), Elapsed>>,
) -> anyhow::Result<Option<Value>> {
    let num_parties = session_parameters.amount_of_parties();
    let t = session_parameters.threshold() as usize;
    let own_role = session_parameters.my_role()?;

    let mut answering_parties = HashSet::<Role>::new();
    let mut collected_shares = Vec::with_capacity(num_parties);
    collected_shares.push(indexed_share.clone());

    while let Some(v) = jobs.join_next().await {
        let joined_result = v?;
        if let Ok((party_id, data)) = joined_result {
            answering_parties.insert(party_id);
            if let Ok(value) = data {
                collected_shares.push(IndexedValue {
                    party_id: party_id.party_id(),
                    value,
                });
            } else if let Err(e) = data {
                tracing::warn!(
                    "(Share reconstruction) Received malformed data from {party_id}:  {:?}",
                    e
                );
            }
        }

        for role in session_parameters.role_assignments().keys() {
            if !answering_parties.contains(role) && role != &own_role {
                tracing::warn!("(Share reconstruction) Party {role} timed out.");
            }
        }

        if 4 * t < num_parties {
            if collected_shares.len() > 3 * t {
                let opened = err_reconstruct(&collected_shares, t, 0)?;
                tracing::debug!(
                    "managed to reconstruct with given {:?} shares",
                    collected_shares.len()
                );
                jobs.shutdown().await;
                return Ok(Some(opened));
            }
        } else if 3 * t < num_parties {
            for max_error in 0..=t {
                if collected_shares.len() > 2 * t + max_error {
                    if let Ok(opened) = err_reconstruct(&collected_shares, t, max_error) {
                        tracing::debug!(
                            "managed to reconstruct with error count: {:?} given {:?} shares",
                            max_error,
                            collected_shares.len()
                        );
                        jobs.shutdown().await;
                        return Ok(Some(opened));
                    }
                }
            }
        }
    }
    Err(anyhow!("Could not reconstruct the sharing"))
}

/// Try to reconstruct to all the secret which corresponds to the provided share.
/// Inputs:
/// - session
/// - share of the secret to open
///
/// Output:
/// - The reconstructed secret if reconstruction was possible
///
/// NOTE: Will likely need a batched version in the future
pub async fn robust_open_to_all<R: RngCore + Send, B: BaseSessionHandles<R>>(
    session: &B,
    share: &Value,
) -> anyhow::Result<Option<Value>> {
    let own_role = session.my_role()?;

    session.network().increase_round_counter().await?;
    send_to_all(session, &own_role, NetworkValue::RingValue(share.clone())).await;

    let mut jobs = JoinSet::<Result<(Role, anyhow::Result<Value>), Elapsed>>::new();
    generic_receive_from_all(&mut jobs, session, &own_role, None, |msg, _id| match msg {
        NetworkValue::RingValue(v) => Ok(v),
        _ => Err(anyhow!(
            "Received something else than a Ring value in robust open to all"
        )),
    })?;

    let indexed_share = IndexedValue {
        party_id: own_role.party_id(),
        value: share.clone(),
    };
    try_reconstruct_from_shares(session, &indexed_share, &mut jobs).await
}

pub async fn robust_open_to<R: RngCore + Send, B: BaseSessionHandles<R>>(
    session: &B,
    share: &Value,
    role: &Role,
    output_party_id: usize,
) -> anyhow::Result<Option<Value>> {
    session.network().increase_round_counter().await?;
    if role.party_id() == output_party_id {
        let mut set = JoinSet::new();

        generic_receive_from_all(&mut set, session, role, None, |msg, _id| match msg {
            NetworkValue::RingValue(v) => Ok(v),
            _ => Err(anyhow!(
                "Received something else than a Ring value in robust open to all"
            )),
        })?;
        let indexed_share = IndexedValue {
            party_id: role.party_id(),
            value: share.clone(),
        };
        try_reconstruct_from_shares(session, &indexed_share, &mut set).await
    } else {
        let receiver = session.identity_from(&Role(output_party_id as u64))?;

        let networking = Arc::clone(session.network());
        let share = share.clone();
        let session_id = session.session_id();

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
    session: &mut BaseSession,
    value: &Option<Value>,
    role: &Role,
    input_party_id: usize,
) -> anyhow::Result<Value> {
    session.network().increase_round_counter().await?;
    if role.party_id() == input_party_id {
        let threshold = session.threshold();
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
        let num_parties = session.amount_of_parties();

        let (shamir_sharings, roles): (Vec<Value>, Vec<Role>) = match si {
            Value::Ring64(s64) => {
                let sharings = ShamirGSharings::<Z64>::share(
                    session.rng(),
                    s64,
                    num_parties,
                    threshold as usize,
                )?;
                let values: Vec<_> = sharings.shares.iter().map(|x| Value::Poly64(x.1)).collect();
                let roles: Vec<_> = sharings
                    .shares
                    .iter()
                    .map(|(party_id, _)| Role(*party_id as u64))
                    .collect();
                (values, roles)
            }
            Value::Ring128(s128) => {
                let sharings = ShamirGSharings::<Z128>::share(
                    session.rng(),
                    s128,
                    num_parties,
                    threshold as usize,
                )?;
                let values: Vec<_> = sharings
                    .shares
                    .iter()
                    .map(|x| Value::Poly128(x.1))
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
                    session.rng(),
                    Wrapping(s64),
                    num_parties,
                    threshold as usize,
                )?;
                let values: Vec<_> = sharings.shares.iter().map(|x| Value::Poly64(x.1)).collect();
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
            let receiver = session.identity_from(&to_send_role)?;

            let networking = Arc::clone(session.network());
            let session_id = session.session_id();
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
        let sender = session.identity_from(&Role(input_party_id as u64))?;

        let networking = Arc::clone(session.network());
        let session_id = session.session_id();
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
    session: &BaseSession,
    pubkey: &PubConKeyPair,
    role: &Role,
    input_party_id: usize,
) -> anyhow::Result<PubConKeyPair> {
    if role.party_id() == input_party_id {
        let num_parties = session.amount_of_parties();
        let pkval = NetworkValue::PubKey(Box::new(pubkey.clone()));

        let mut set = JoinSet::new();
        for to_send_role in 1..=num_parties {
            if to_send_role != input_party_id {
                let identity = session.identity_from(&Role(to_send_role as u64))?;

                let networking = Arc::clone(session.network());
                let session_id = session.session_id();
                let send_pk = pkval.clone();

                set.spawn(async move {
                    let _ = networking.send(send_pk, &identity, &session_id).await;
                });
            }
        }
        while (set.join_next().await).is_some() {}
        Ok(pubkey.clone())
    } else {
        let receiver = session.identity_from(&Role(input_party_id as u64))?;
        let networking = Arc::clone(session.network());
        let session_id = session.session_id();
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
    session: &mut SmallSession,
    circuit: &Circuit,
    keyshares: Option<&SecretKeyShare>,
    ct: Option<&Ciphertext128>,
) -> anyhow::Result<Vec<Value>> {
    // env holds a map from a variable to a list of ciphertext, or partial decrypted ciphertexts or decrypted value (depending on the circuit evaluation calls executed)
    let mut env: HashMap<&String, Vec<Value>> = HashMap::new();
    let mut outputs = Vec::new();

    let own_role = session.my_role()?;

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
                        let sharing: Value = robust_input::<R>(
                            &mut session.to_base_session(),
                            &Some(Value::U64(block)),
                            &own_role,
                            1,
                        )
                        .await?;
                        sharings.push(sharing);
                    }
                } else {
                    for _ in 1..=amount_of_blocks {
                        let sharing =
                            robust_input::<R>(&mut session.to_base_session(), &None, &own_role, 1)
                                .await?;
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
                    if let Some(val) =
                        robust_open_to(&session.to_base_session(), current_share, &own_role, 1)
                            .await?
                    {
                        match val {
                            Value::Poly64(v) => {
                                let val_scalar = Z64::try_from(v)?;
                                opened.push(Value::Ring64(val_scalar));
                            }
                            Value::Poly128(v) => {
                                let val_scalar = Z128::try_from(v)?;
                                opened.push(Value::Ring128(val_scalar));
                            }
                            _ => unimplemented!("Can't open type other than Pol128 or Pol64"),
                        }
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
                // TODO @Daniel should we replace this with a prfkey from SetupInfo or direct call to agree_random?
                let prep_seed = u64::from_str(
                    op.operands
                        .get(1)
                        .ok_or_else(|| anyhow!("Couldn't retrieve seed"))?,
                )?;
                let mut rng = AesRng::seed_from_u64(prep_seed);
                let ciphertext = ct.ok_or_else(|| anyhow!("no ciphertext found to decrypt"))?;
                let existing_keyshare =
                    keyshares.ok_or_else(|| anyhow!("Key share not set during dist prep"))?;
                let mut block_shares = Vec::with_capacity(ciphertext.len());
                for i in 0..ciphertext.len() {
                    // current_block in ciphertext {
                    let block_share = ddec_prep(
                        &mut rng,
                        own_role.party_id(),
                        session.threshold() as usize,
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
                    let partial_decryption = prss_prep(
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
                if own_role.party_id() <= session.threshold() as usize {
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
                        if let Value::Poly128(parsed_share) = current_share {
                            tracing::debug!(
                                "I'm party {} and I will send bollocks!",
                                own_role.party_id()
                            );
                            parsed_shares
                                .push(Value::Poly128(ResiduePoly::<Z128>::ONE + parsed_share));
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
    session: &mut SmallSession,
    keyshares: &SecretKeyShare,
    ciphertext: Ciphertext128,
    mode: DecryptionMode,
) -> anyhow::Result<Vec<Value>> {
    let mut outputs = Vec::new();
    let threshold = session.threshold() as usize;
    let own_role = session.my_role()?;

    let mut partial_decrypted = Vec::with_capacity(ciphertext.len());
    for current_ct_block in ciphertext {
        let res = match mode {
            DecryptionMode::PRSSDecrypt => {
                let prss_state = session
                    .prss_state
                    .as_mut()
                    .ok_or_else(|| anyhow!("PRSS_State not initialized"))?;

                prss_prep(
                    own_role.party_id(),
                    prss_state,
                    keyshares,
                    &current_ct_block,
                )?
            }
            DecryptionMode::Proto2Decrypt => ddec_prep(
                session.rng(),
                own_role.party_id(),
                threshold,
                keyshares,
                &current_ct_block,
            )?,
        };

        let opened = robust_open_to(&session.to_base_session(), &res, &own_role, 1).await?;

        if own_role.party_id() == INPUT_PARTY_ID {
            let message_mod_bits = keyshares
                .threshold_lwe_parameters
                .output_cipher_parameters
                .message_modulus_log
                .0;
            // shift
            let c = match opened {
                Some(Value::Poly128(v)) => {
                    let v_scalar = Z128::try_from(v)?;
                    Value::Ring128(from_expanded_msg(v_scalar.0, message_mod_bits))
                }
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

pub async fn initialize_key_material(
    session: &mut SmallSession,
    setup_mode: SetupMode,
    params: ThresholdLWEParameters,
) -> anyhow::Result<(SecretKeyShare, PubConKeyPair, Option<PRSSSetup>)> {
    let own_role = session.my_role()?;

    let prss_setup = if setup_mode == SetupMode::AllProtos {
        Some(
            PRSSSetup::party_epoch_init_sess::<DummyAgreeRandom>(session, own_role.party_id())
                .await?,
        )
    } else {
        None
    };

    let keyset = gen_key_set(params, &mut session.rng());

    let sk_container = keyset.sk.lwe_secret_key_128.into_container();
    let mut key_shares = Vec::new();
    // iterate through sk and share each element
    for cur in sk_container {
        let secret = match own_role.party_id() {
            1 => Some(Value::Ring128(Wrapping(cur))),
            _ => None,
        };
        let share: Value =
            robust_input::<ChaCha20Rng>(&mut session.to_base_session(), &secret, &own_role, 1)
                .await?; //TODO(Daniel) batch this for all big_ell

        if let Value::Poly128(s) = share {
            key_shares.push(s);
        }
    }
    let pubcon = PubConKeyPair {
        pk: keyset.pk,
        ck: keyset.ck,
    };
    let transferred_pk = transfer_pk(&session.to_base_session(), &pubcon, &own_role, 1).await?;

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
        circuit::Operation,
        file_handling::read_as_json,
        tests::{helper::tests::generate_identities, test_data_setup::tests::DEFAULT_PARAM_PATH},
    };

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
        let identities = generate_identities(4);
        let threshold = 1;

        let runtime = DistributedTestRuntime::new(identities, threshold);
        let results = runtime.evaluate_circuit(&circuit, None).unwrap();
        let out = &results[&Identity("localhost:5000".to_string())];
        assert_eq!(out[0], Value::Ring128(Wrapping(100)));
    }

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
        let identities = generate_identities(4);
        let threshold = 1;

        let runtime = DistributedTestRuntime::new(identities, threshold);
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
        let identities = generate_identities(6);
        let threshold = 1;
        let runtime = DistributedTestRuntime::new(identities, threshold);
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
        let identities = generate_identities(10);
        let threshold = 1;
        let runtime = DistributedTestRuntime::new(identities, threshold);
        let results = runtime.evaluate_circuit(&circuit, None).unwrap();
        let out = &results[&Identity("localhost:5000".to_string())];
        assert_eq!(out[0], Value::Ring128(std::num::Wrapping(100)));
        assert_eq!(out[1], Value::Ring128(std::num::Wrapping(101)));
        assert_eq!(out[2], Value::Ring128(std::num::Wrapping(102)));
    }
}

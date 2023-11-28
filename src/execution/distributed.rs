use super::broadcast::send_to_all;
use super::{
    agree_random::{AgreeRandom, DummyAgreeRandom},
    session::{
        BaseSession, BaseSessionHandles, DecryptionMode, LargeSession, ParameterHandles,
        SessionParameters, SetupMode, SmallSession,
    },
    small_execution::prss::PRSSSetup,
};
use crate::error::error_handler::anyhow_error_and_log;
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
use crate::value::{err_reconstruct, IndexedValue, NetworkValue, RingType, Value};
use crate::{
    circuit::{Circuit, Operator},
    execution::small_execution::prep::ddec_prep,
};
use crate::{computation::SessionId, execution::small_execution::prep::prss_prep};
use crate::{One, Z128, Z64};
use aes_prng::AesRng;
use itertools::Itertools;
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
use tokio::time::timeout_at;

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
            .map(|(role_id, identity)| (Role::indexed_by_zero(role_id), identity))
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

    // Setups and adds a PRSS state with DummyAgreeRandom to the current session
    pub fn add_dummy_prss(session: &mut SmallSession) {
        // this only works for DummyAgreeRandom
        // for RealAgreeRandom this needs to happen async/in parallel, so the parties can actually talk to each other at the same time
        // ==> use a JoinSet where this is called and collect the results later.
        // see also setup_prss_sess() below
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let prss_setup = rt
            .block_on(async { PRSSSetup::init_with_abort::<DummyAgreeRandom>(session).await })
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

        let own_role = Role::indexed_by_zero(player_id);
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
        let own_role = Role::indexed_by_zero(player_id);
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
                .ok_or_else(|| {
                    anyhow_error_and_log("key share not set during decryption".to_string())
                })?;

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

    for sess in sessions.clone() {
        jobs.spawn(async move {
            let epoc = PRSSSetup::init_with_abort::<A>(&sess).await;
            (sess.my_role().unwrap().zero_based(), epoc)
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

fn fill_indexed_shares(
    vec_collected_shares: &mut [Vec<IndexedValue>],
    values: Vec<Value>,
    num_values: usize,
    party_id: usize,
) {
    let values_len = values.len();
    values
        .into_iter()
        .zip(vec_collected_shares.iter_mut())
        .for_each(|(v, collected_shares)| {
            collected_shares.push(IndexedValue { party_id, value: v });
        });

    if values_len < num_values {
        for collected_shares in vec_collected_shares.iter_mut().skip(values_len) {
            collected_shares.push(IndexedValue {
                party_id,
                value: Value::Empty,
            });
        }
    }
}

type JobResultType = (Role, anyhow::Result<Vec<Value>>);
/// Helper function of robust reconstructions which collect the shares and tries to reconstruct
/// Takes as input:
/// - the session_parameters
/// - indexed_share as the indexed share of the local party
/// - degree as the degree of the secret sharing
/// - t as the max. number of errors we allow (if no party has been flagged as corrupt, this is session.threshold)
/// - a set of jobs to receive the shares from the other parties
async fn try_reconstruct_from_shares<P: ParameterHandles>(
    session_parameters: &P,
    indexed_shares: &[IndexedValue],
    expected_type: RingType,
    degree: usize,
    threshold: usize,
    jobs: &mut JoinSet<Result<JobResultType, Elapsed>>,
) -> anyhow::Result<Option<Vec<Value>>> {
    let num_parties = session_parameters.amount_of_parties();
    let own_role = session_parameters.my_role()?;
    let num_secrets = indexed_shares.len();
    let mut answering_parties = HashSet::<Role>::new();
    let mut vec_collected_shares = indexed_shares
        .iter()
        .map(|indexed_share| {
            let mut res = Vec::with_capacity(num_parties);
            res.push(indexed_share.clone());
            res
        })
        .collect_vec();

    while let Some(v) = jobs.join_next().await {
        let joined_result = v?;
        if let Ok((party_id, data)) = joined_result {
            answering_parties.insert(party_id);
            if let Ok(values) = data {
                fill_indexed_shares(
                    &mut vec_collected_shares,
                    values,
                    num_secrets,
                    party_id.one_based(),
                );
            } else if let Err(e) = data {
                tracing::warn!(
                    "(Share reconstruction) Received malformed data from {party_id}:  {:?}",
                    e
                );
                fill_indexed_shares(
                    &mut vec_collected_shares,
                    [].to_vec(),
                    num_secrets,
                    party_id.one_based(),
                );
            }
        }

        //Note: here we keep waiting on new shares until we have all of the values opened.
        //Also, not sure we want to try reconstruct stuff before having heard from all parties
        //at least in the sync case, waiting for d+2t+1, basically means waiting for everyone.
        //reconstruct_w_errors_sync will just instantly return None for all
        let res: Option<Vec<_>> = vec_collected_shares
            .iter()
            .map(|collected_shares| {
                if let Ok(Some(r)) = reconstruct_w_errors_sync(
                    num_parties,
                    degree,
                    threshold,
                    collected_shares,
                    &expected_type,
                ) {
                    Some(r)
                } else {
                    None
                }
            })
            .collect();
        if let Some(r) = res {
            jobs.shutdown().await;
            return Ok(Some(r));
        }
    }

    //If we havent yet been able to reconstruct it may be because we havent heard from all parties
    //In which case we have to know if we knew those were already malicious.
    //If not, we have to try reconstruct with those parties considered as malicious (i.e. w/ updated threshold)
    let num_known_corrupt = session_parameters.threshold() as usize - threshold;
    let mut num_non_answering = 0;
    for role in session_parameters.role_assignments().keys() {
        if !answering_parties.contains(role) && role != &own_role {
            tracing::warn!("(Share reconstruction) Party {role} timed out.");
            num_non_answering += 1;
        }
    }
    //If we have more non-answering parties than expected by previous malicious set
    //try to reconstruct with updated threshold
    //If there is even one that can not be opened at this point,
    //then we will error out
    if num_non_answering > num_known_corrupt {
        let updated_threshold = session_parameters.threshold() as usize - num_non_answering;
        let res: Option<Vec<_>> = vec_collected_shares
            .iter()
            .map(|collected_shares| {
                if let Ok(Some(r)) = reconstruct_w_errors_sync(
                    num_parties,
                    degree,
                    updated_threshold,
                    collected_shares,
                    &expected_type,
                ) {
                    Some(r)
                } else {
                    None
                }
            })
            .collect();
        if let Some(r) = res {
            return Ok(Some(r));
        }
    }
    Err(anyhow_error_and_log(
        "Could not reconstruct the sharing".to_string(),
    ))
}

/// Core algorithm for robust reconstructions which tries to reconstruct from a collection of shares
/// Takes as input:
/// - num_parties as number of parties
/// - degree as the degree of the sharing (usually either t or 2t)
/// - threshold as the threshold of maximum corruptions
/// - indexed_shares as the indexed shares of the parties
/// NOTE: When needed, inplement the async version
pub fn reconstruct_w_errors_sync(
    num_parties: usize,
    degree: usize,
    threshold: usize,
    indexed_shares: &Vec<IndexedValue>,
    expected_type: &RingType,
) -> anyhow::Result<Option<Value>> {
    if degree + 2 * threshold < num_parties && indexed_shares.len() > degree + 2 * threshold {
        let opened = err_reconstruct(indexed_shares, degree, threshold, expected_type)?;
        tracing::debug!(
            "managed to reconstruct with given {:?} shares",
            indexed_shares.len()
        );
        return Ok(Some(opened));
    } else if degree + 2 * threshold >= num_parties {
        return Err(anyhow_error_and_log(format!("Can NOT reconstruct with degree {degree}, threshold {threshold} and num_parties {num_parties}")));
    }

    Ok(None)
}

pub async fn robust_open_to_all<R: RngCore, B: BaseSessionHandles<R>>(
    session: &B,
    share: Value,
    degree: usize,
) -> anyhow::Result<Option<Value>> {
    let res = robust_opens_to_all(session, &[share], degree).await?;
    match res {
        Some(mut r) => Ok(r.pop()),
        _ => Ok(None),
    }
}
/// Try to reconstruct to all the secret which corresponds to the provided share.
///
/// Inputs:
/// - session
/// - shares of the secrets to open
/// - degree of the sharing
///
/// Output:
/// - The reconstructed secrets if reconstruction for all was possible
pub async fn robust_opens_to_all<R: RngCore, B: BaseSessionHandles<R>>(
    session: &B,
    shares: &[Value],
    degree: usize,
) -> anyhow::Result<Option<Vec<Value>>> {
    let expected_type = *shares
        .iter()
        .map(|v| v.ty())
        .try_collect::<_, Vec<_>, _>()?
        .iter()
        .all_equal_value()
        .map_err(|err| anyhow_error_and_log(format!("Error in opening types {:?}", err)))?;

    let own_role = session.my_role()?;

    session.network().increase_round_counter().await?;
    send_to_all(
        session,
        &own_role,
        NetworkValue::VecRingValue(shares.to_vec()),
    )
    .await;

    let mut jobs = JoinSet::<Result<(Role, anyhow::Result<Vec<Value>>), Elapsed>>::new();
    //Note: we give the set of corrupt parties as the non_answering_parties argument
    //Thus generic_receive_from_all will not receive from corrupt parties.
    generic_receive_from_all(
        &mut jobs,
        session,
        &own_role,
        Some(session.corrupt_roles()),
        |msg, _id| match msg {
            NetworkValue::VecRingValue(v) => Ok(v),
            _ => Err(anyhow_error_and_log(
                "Received something else than a Ring value in robust open to all".to_string(),
            )),
        },
    )?;

    let indexed_shares = shares
        .iter()
        .map(|share| IndexedValue {
            party_id: own_role.one_based(),
            value: share.clone(),
        })
        .collect_vec();
    //Note: We are not even considering shares for the already known corrupt parties,
    //thus the effective threshold at this point is the "real" threshold - the number of known corrupt parties
    let threshold = session.threshold() as usize - session.corrupt_roles().len();
    try_reconstruct_from_shares(
        session,
        &indexed_shares,
        expected_type,
        degree,
        threshold,
        &mut jobs,
    )
    .await
}

pub async fn robust_open_to<R: RngCore + Send, B: BaseSessionHandles<R>>(
    session: &B,
    share: Value,
    degree: usize,
    role: &Role,
    output_party_id: usize,
) -> anyhow::Result<Option<Value>> {
    let res = robust_opens_to(session, &[share], degree, role, output_party_id).await?;
    match res {
        Some(mut r) => Ok(r.pop()),
        _ => Ok(None),
    }
}

pub async fn robust_opens_to<R: RngCore + Send, B: BaseSessionHandles<R>>(
    session: &B,
    shares: &[Value],
    degree: usize,
    role: &Role,
    output_party_id: usize,
) -> anyhow::Result<Option<Vec<Value>>> {
    session.network().increase_round_counter().await?;
    if role.one_based() == output_party_id {
        let expected_type = *shares
            .iter()
            .map(|v| v.ty())
            .try_collect::<_, Vec<_>, _>()?
            .iter()
            .all_equal_value()
            .map_err(|err| anyhow_error_and_log(format!("Error in opening types {:?}", err)))?;
        let mut set = JoinSet::new();

        //Note: we give the set of corrupt parties as the non_answering_parties argument
        //Thus generic_receive_from_all will not receive from corrupt parties.
        generic_receive_from_all(
            &mut set,
            session,
            role,
            Some(session.corrupt_roles()),
            |msg, _id| match msg {
                NetworkValue::VecRingValue(v) => Ok(v),
                _ => Err(anyhow_error_and_log(
                    "Received something else than a Ring value in robust open to all".to_string(),
                )),
            },
        )?;
        let indexed_shares = shares
            .iter()
            .map(|share| IndexedValue {
                party_id: role.one_based(),
                value: share.clone(),
            })
            .collect_vec();

        //Note: We are not even considering shares for the already known corrupt parties,
        //thus the effective threshold at this point is the "real" threshold - the number of known corrupt parties
        let threshold = session.threshold() as usize - session.corrupt_roles().len();
        try_reconstruct_from_shares(
            session,
            &indexed_shares,
            expected_type,
            degree,
            threshold,
            &mut set,
        )
        .await
    } else {
        let receiver = session.identity_from(&Role::indexed_by_one(output_party_id))?;

        let networking = Arc::clone(session.network());
        let shares = shares.to_vec();
        let session_id = session.session_id();

        tokio::spawn(async move {
            let _ = networking
                .send(NetworkValue::VecRingValue(shares), &receiver, &session_id)
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
    if role.one_based() == input_party_id {
        let threshold = session.threshold();
        let si = {
            match value {
                Some(v) => v.clone(),
                None => {
                    return Err(anyhow_error_and_log(
                        "Expected Some(v) as an input argument for the input party, got None"
                            .to_string(),
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
                    .map(|(party_id, _)| Role::indexed_by_one(*party_id))
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
                    .map(|(party_id, _)| Role::indexed_by_one(*party_id))
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
                    .map(|(party_id, _)| Role::indexed_by_one(*party_id))
                    .collect();
                (values, roles)
            }
            _ => {
                return Err(anyhow_error_and_log(
                    "Cannot share a value which has type different than U64, Ring64/Ring128"
                        .to_string(),
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
        let sender = session.identity_from(&Role::indexed_by_one(input_party_id))?;

        let networking = Arc::clone(session.network());
        let session_id = session.session_id();
        let data = tokio::spawn(timeout_at(
            session.network().get_timeout_current_round()?,
            async move { networking.receive(&sender, &session_id).await },
        ))
        .await???;

        let data = match data {
            NetworkValue::RingValue(rv) => rv,
            _ => Err(anyhow_error_and_log(
                "I have received sth different from a ring value!".to_string(),
            ))?,
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
    session.network().increase_round_counter().await?;
    if role.one_based() == input_party_id {
        let num_parties = session.amount_of_parties();
        let pkval = NetworkValue::PubKey(Box::new(pubkey.clone()));

        let mut set = JoinSet::new();
        for to_send_role in 1..=num_parties {
            if to_send_role != input_party_id {
                let identity = session.identity_from(&Role::indexed_by_one(to_send_role))?;

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
        let receiver = session.identity_from(&Role::indexed_by_one(input_party_id))?;
        let networking = Arc::clone(session.network());
        let session_id = session.session_id();
        let data: NetworkValue = tokio::spawn(timeout_at(
            session.network().get_timeout_current_round()?,
            async move { networking.receive(&receiver, &session_id).await },
        ))
        .await???;

        let pk = match data {
            NetworkValue::PubKey(pk) => pk,
            _ => Err(anyhow_error_and_log(
                "I have received sth different from a public key!".to_string(),
            ))?,
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
            Value::Empty => 0_u128, //Default 0
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
                    .ok_or_else(|| anyhow_error_and_log("Wrong index buddy".to_string()))?;
                let si = u32::from_str(
                    op.operands
                        .get(1)
                        .ok_or_else(|| anyhow_error_and_log("Wrong index buddy".to_string()))?,
                )?;
                let bits_in_block = u32::from_str(
                    op.operands
                        .get(2)
                        .ok_or_else(|| anyhow_error_and_log("Wrong index buddy".to_string()))?,
                )?;
                let bits_to_encrypt = u32::from_str(
                    op.operands
                        .get(3)
                        .ok_or_else(|| anyhow_error_and_log("Wrong index buddy".to_string()))?,
                )?;
                let amount_of_blocks = div_ceil(bits_to_encrypt, bits_in_block);

                let mut sharings = Vec::new();
                if own_role.one_based() == 1 {
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
                    .ok_or_else(|| anyhow_error_and_log("Wrong index buddy".to_string()))?;
                let s0 = op
                    .operands
                    .get(3)
                    .ok_or_else(|| anyhow_error_and_log("Wrong index buddy".to_string()))?;
                let own_share = env.get(s0).ok_or_else(|| {
                    anyhow_error_and_log(
                        "Couldn't retrieve secret register index for opening".to_string(),
                    )
                })?;
                let mut opened = Vec::new();
                for current_share in own_share {
                    // TODO is this the behaviour we want here?
                    if let Some(val) = robust_open_to(
                        &session.to_base_session(),
                        current_share.clone(),
                        session.threshold() as usize,
                        &own_role,
                        1,
                    )
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
                    .ok_or_else(|| anyhow_error_and_log("Wrong index buddy".to_string()))?;
                let ci =
                    Value::U64(u64::from_str(op.operands.get(1).ok_or_else(|| {
                        anyhow_error_and_log("Wrong index buddy".to_string())
                    })?)?);
                env.insert(r0, vec![ci]);
            }
            // Returns an opened value stored in a register as output.
            // Operand 0 => register of the opened value
            // Operand 1 => the amount of bits in the plaintext space of each ciphertext block
            PrintRegPlain => {
                if own_role.one_based() == INPUT_PARTY_ID {
                    let r0 = op
                        .operands
                        .get(0)
                        .ok_or_else(|| anyhow_error_and_log("Wrong index buddy".to_string()))?;
                    let bits_in_block =
                        u32::from_str(op.operands.get(1).ok_or_else(|| {
                            anyhow_error_and_log("Wrong index buddy".to_string())
                        })?)?;
                    let val = env
                        .get(&r0.to_string())
                        .ok_or_else(|| {
                            anyhow_error_and_log(format!("Couldn't find register {r0}"))
                        })?
                        .clone();
                    let res = match combine(bits_in_block, val) {
                        Ok(res) => res,
                        Err(error) => {
                            eprint!("Panicked in combining {error}");
                            return Err(anyhow_error_and_log(format!(
                                "Panicked in combining {error}"
                            )));
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
                if own_role.one_based() == INPUT_PARTY_ID {
                    let dest = op
                        .operands
                        .get(0)
                        .ok_or_else(|| anyhow_error_and_log("Wrong index buddy".to_string()))?;

                    let source = op
                        .operands
                        .get(1)
                        .ok_or_else(|| anyhow_error_and_log("Wrong index buddy".to_string()))?;

                    let source_val = env
                        .get(&source.to_string())
                        .ok_or_else(|| {
                            anyhow_error_and_log(format!("Couldn't find register {source}"))
                        })?
                        .clone();

                    let offset =
                        usize::from_str(op.operands.get(2).ok_or_else(|| {
                            anyhow_error_and_log("Wrong index buddy".to_string())
                        })?)?;

                    let mut res = Vec::new();
                    for current_source in source_val {
                        match current_source {
                            Value::Ring128(v) => {
                                res.push(Value::Ring128(v >> offset));
                            }
                            Value::Ring64(v) => {
                                res.push(Value::Ring64(v >> offset));
                            }
                            _ => return Err(anyhow_error_and_log("Cannot do shift right on a cleartext register with a different type than Ring64/Ring128".to_string()))
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
                if own_role.one_based() == INPUT_PARTY_ID {
                    let dest = op
                        .operands
                        .get(0)
                        .ok_or_else(|| anyhow_error_and_log("Wrong index buddy".to_string()))?;

                    let source = op
                        .operands
                        .get(1)
                        .ok_or_else(|| anyhow_error_and_log("Wrong index buddy".to_string()))?;

                    let source_val = env
                        .get(&source.to_string())
                        .ok_or_else(|| {
                            anyhow_error_and_log(format!("Couldn't find register {source}"))
                        })?
                        .clone();

                    let offset =
                        usize::from_str(op.operands.get(2).ok_or_else(|| {
                            anyhow_error_and_log("Wrong index buddy".to_string())
                        })?)?;

                    let mut res = Vec::new();
                    for current_source in source_val {
                        match current_source {
                            Value::Ring128(v) => {
                                let rounding_bit = 1 << (offset - 1);
                                let rounding = (v.0 & rounding_bit) << 1;
                                res.push(Value::Ring128(Wrapping(v.0.wrapping_add(rounding)) >> offset));
                            },
                            Value::Ring64(v) => {
                                let rounding_bit = 1 << (offset - 1);
                                let rounding = (v.0 & rounding_bit) << 1;
                                res.push(Value::Ring64(Wrapping(v.0.wrapping_add(rounding)) >> offset));
                            },
                            _ => return Err(anyhow_error_and_log("Cannot do shift right on a cleartext register with a different type than Ring64/Ring128".to_string()))
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
                    .ok_or_else(|| anyhow_error_and_log("Wrong index buddy".to_string()))?;
                // TODO @Daniel should we replace this with a prfkey from SetupInfo or direct call to agree_random?
                let prep_seed =
                    u64::from_str(op.operands.get(1).ok_or_else(|| {
                        anyhow_error_and_log("Couldn't retrieve seed".to_string())
                    })?)?;
                let mut rng = AesRng::seed_from_u64(prep_seed);
                let ciphertext = ct.ok_or_else(|| {
                    anyhow_error_and_log("no ciphertext found to decrypt".to_string())
                })?;
                let existing_keyshare = keyshares.ok_or_else(|| {
                    anyhow_error_and_log("Key share not set during dist prep".to_string())
                })?;
                let mut block_shares = Vec::with_capacity(ciphertext.len());
                for i in 0..ciphertext.len() {
                    // current_block in ciphertext {
                    let block_share = ddec_prep(
                        &mut rng,
                        own_role.one_based(),
                        session.threshold() as usize,
                        existing_keyshare,
                        ciphertext.get(i).ok_or_else(|| {
                            anyhow_error_and_log("Wrong index in ciphertext".to_string())
                        })?,
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
                    .ok_or_else(|| anyhow_error_and_log("Wrong index buddy".to_string()))?;

                let prss_state = session.prss_state.as_mut().ok_or_else(|| {
                    anyhow_error_and_log("PRSS_State not initialized".to_string())
                })?;

                let ciphertext = ct.ok_or_else(|| {
                    anyhow_error_and_log("no ciphertext found to decrypt".to_string())
                })?;

                let existing_keyshare = keyshares.ok_or_else(|| {
                    anyhow_error_and_log("Key share not set during prssprep".to_string())
                })?;
                let mut partial_decrypted_blocks = Vec::with_capacity(ciphertext.len());
                for i in 0..ciphertext.len() {
                    // current_block in ciphertext {
                    let partial_decryption = prss_prep(
                        own_role.one_based(),
                        prss_state,
                        existing_keyshare,
                        ciphertext.get(i).ok_or_else(|| {
                            anyhow_error_and_log("Wrong index in ciphertext".to_string())
                        })?,
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
                if own_role.one_based() <= session.threshold() as usize {
                    let dest = op
                        .operands
                        .get(0)
                        .ok_or_else(|| anyhow_error_and_log("Wrong index buddy".to_string()))?;

                    let correct_share_value = env.get(dest).ok_or_else(|| {
                        anyhow_error_and_log("Couldn't retrieve party share to modify".to_string())
                    })?;
                    let mut parsed_shares = Vec::with_capacity(correct_share_value.len());
                    for current_share in correct_share_value {
                        // increase value of existing share by 1
                        if let Value::Poly128(parsed_share) = current_share {
                            tracing::debug!(
                                "I'm party {} and I will send bollocks!",
                                own_role.one_based()
                            );
                            parsed_shares
                                .push(Value::Poly128(ResiduePoly::<Z128>::ONE + parsed_share));
                        } else {
                            return Err(anyhow_error_and_log(
                                "Other type than IndexShare128 found in threshold_fault"
                                    .to_string(),
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
                let prss_state = session.prss_state.as_mut().ok_or_else(|| {
                    anyhow_error_and_log("PRSS_State not initialized".to_string())
                })?;

                prss_prep(
                    own_role.one_based(),
                    prss_state,
                    keyshares,
                    &current_ct_block,
                )?
            }
            DecryptionMode::Proto2Decrypt => ddec_prep(
                session.rng(),
                own_role.one_based(),
                threshold,
                keyshares,
                &current_ct_block,
            )?,
        };

        let opened = robust_open_to(
            &session.to_base_session(),
            res,
            session.threshold() as usize,
            &own_role,
            INPUT_PARTY_ID,
        )
        .await?;

        if own_role.one_based() == INPUT_PARTY_ID {
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
                    return Err(anyhow_error_and_log(
                        "Right shift not possible - no opened value".to_string(),
                    ))
                }
            };
            partial_decrypted.push(c);
        }
    }
    if own_role.one_based() == INPUT_PARTY_ID {
        let bits_in_block = keyshares
            .threshold_lwe_parameters
            .output_cipher_parameters
            .usable_message_modulus_log
            .0;
        let res = match combine(bits_in_block as u32, partial_decrypted) {
            Ok(res) => res,
            Err(error) => {
                eprint!("Panicked in combining {error}");
                return Err(anyhow_error_and_log(format!(
                    "Panicked in combining {error}"
                )));
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
    let prss_setup = if setup_mode == SetupMode::AllProtos {
        Some(PRSSSetup::init_with_abort::<DummyAgreeRandom>(session).await?)
    } else {
        None
    };

    let keyset = gen_key_set(params, &mut session.rng());

    let sk_container = keyset.sk.lwe_secret_key_128.into_container();
    let mut key_shares = Vec::new();
    let own_role = session.my_role()?;
    // iterate through sk and share each element
    for cur in sk_container {
        let secret = match own_role.one_based() {
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
        tests::{
            helper::tests::{execute_protocol, generate_identities},
            test_data_setup::tests::DEFAULT_PARAM_PATH,
        },
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

    #[test]
    fn test_robust_open_all() {
        let parties = 4;
        let threshold = 1;

        async fn task(session: LargeSession) -> Vec<Value> {
            let parties = 4;
            let threshold = 1;
            let num_secrets = 10;
            let mut rng = ChaCha20Rng::seed_from_u64(0);
            let shares = (0..num_secrets)
                .map(|idx| {
                    Value::Poly128(
                        ShamirGSharings::<Z128>::share(&mut rng, Wrapping(idx), parties, threshold)
                            .unwrap()
                            .shares
                            .get(session.my_role().unwrap().zero_based())
                            .unwrap()
                            .1,
                    )
                })
                .collect_vec();
            let res = robust_opens_to_all(&session, &shares, threshold)
                .await
                .unwrap()
                .unwrap();
            for (idx, r) in res.clone().into_iter().enumerate() {
                if let Value::Poly128(r) = r {
                    assert_eq!(Z128::try_from(r).unwrap(), Wrapping::<u128>(idx as u128));
                } else {
                    panic!();
                }
            }
            res
        }

        let _ = execute_protocol(parties, threshold, &mut task);
    }
}

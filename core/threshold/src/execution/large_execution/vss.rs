use async_trait::async_trait;
use itertools::{EitherOrBoth, Itertools};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use tokio::task::JoinError;
use tokio::{task::JoinSet, time::error::Elapsed};
use tracing::instrument;

use crate::execution::communication::broadcast::{Broadcast, SyncReliableBroadcast};
use crate::{
    algebra::{
        bivariate::{BivariateEval, BivariatePoly},
        poly::Poly,
        structure_traits::{Ring, RingWithExceptionalSequence},
    },
    error::error_handler::anyhow_error_and_log,
    execution::{
        communication::p2p::{generic_receive_from_all, send_to_parties},
        runtime::{party::Role, session::BaseSessionHandles},
    },
    networking::value::{BroadcastValue, NetworkValue},
    ProtocolDescription,
};

/// Secure implementation of VSS as defined in NIST document
///
/// In particular, relies on the secure version of
/// the broadcast protocol defined in [`SyncReliableBroadcast`]
pub type SecureVss = RealVss<SyncReliableBroadcast>;

#[async_trait]
pub trait Vss: Send + Sync + Clone + ProtocolDescription {
    /// Executes a Verifiable Secret Sharing
    /// where every party inputs one secret.
    /// The trait provides a default implementation for [execute]
    /// that reports *errors* if the [execute_many] implementation
    /// gives unexpected results. This behaviour may need to be
    /// overridden when implementating malicious VSS for testing.
    /// - session as the MPC session
    /// - secret as secret to be shared
    ///
    /// Returns
    /// - a vector of shares (share at index i is a sharing of the secret of party i)
    async fn execute<Z: RingWithExceptionalSequence, S: BaseSessionHandles>(
        &self,
        session: &mut S,
        secret: &Z,
    ) -> anyhow::Result<Vec<Z>> {
        let out_vec = self.execute_many(session, &[*secret]).await?;
        let n = session.num_parties();
        if out_vec.len() != n {
            return Err(anyhow_error_and_log(format!(
                "incorrect output length, expect {n} but got {}",
                out_vec.len()
            )));
        }
        if out_vec[0].len() != 1 {
            return Err(anyhow_error_and_log(format!(
                "incorrect number of secrets, expect 1 but got {}",
                out_vec[0].len()
            )));
        }
        Ok(out_vec.into_iter().map(|vs| vs[0]).collect_vec())
    }

    /// Executes a batched Verifiable Secret Sharing
    /// where every party inputs a batch of secrets
    /// - session as the MPC session
    /// - secrets as secrets to be shared
    ///
    /// Returns
    /// - a vector of shares (shares at index i is a sharing of the secrets of party i)
    /// so in a successful execution shares.len() should be the number of parties
    /// and shares[0].len() should be the number of secrets
    async fn execute_many<Z: RingWithExceptionalSequence, S: BaseSessionHandles>(
        &self,
        session: &mut S,
        secrets: &[Z],
    ) -> anyhow::Result<Vec<Vec<Z>>>;
}

/// Alias that represents the list of challenges sent by a party during VSS
/// such that list[j][k] correspond to the challenges for the kth secret in the batch
/// where P_j is the VSS sender
type ChallengesList<Z> = Vec<Vec<Z>>;
pub(crate) type VerificationValues<Z> = Vec<Vec<(Z, Z)>>;
type ResultRound1<Z> = Result<(Role, Result<ExchangedDataRound1<Z>, anyhow::Error>), Elapsed>;

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Hash, Debug)]
pub enum ValueOrPoly<Z>
where
    Z: Eq,
    Poly<Z>: Eq,
{
    Value(Vec<Z>),
    Poly(Vec<Poly<Z>>),
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Hash, Debug, Default)]
pub(crate) struct DoublePoly<Z>
where
    Poly<Z>: Eq,
{
    pub(crate) share_in_x: Poly<Z>,
    pub(crate) share_in_y: Poly<Z>,
}

/// Struct to hold data sent during round 1 of VSS, composed of
/// - double_poly is my share in a single VSS instance
/// - we need n challenges sent and n challenges received (one from every party)
#[derive(Serialize, Deserialize, PartialEq, Clone, Hash, Debug)]
pub struct ExchangedDataRound1<Z>
where
    Poly<Z>: Eq,
{
    double_poly_list: Vec<DoublePoly<Z>>,
    challenges_list: ChallengesList<Z>,
}

impl<Z: Ring> ExchangedDataRound1<Z> {
    pub fn default(num_parties: usize, num_secrets: usize) -> Self {
        Self {
            double_poly_list: vec![
                DoublePoly::<Z> {
                    share_in_x: Poly::default(),
                    share_in_y: Poly::default(),
                };
                num_secrets
            ],
            challenges_list: (0..num_parties)
                .map(|_| vec![Z::default(); num_secrets])
                .collect_vec(),
        }
    }
}

///This data structure is indexed by [party_idx, idx_vss]
#[derive(Clone, Debug)]
pub struct Round1VSSOutput<Z: Ring> {
    sent_challenges: Vec<ChallengesList<Z>>,
    received_vss: Vec<ExchangedDataRound1<Z>>,
    my_poly: Vec<BivariatePoly<Z>>,
}

///Simply send the trivial sharing P: X -> secret (P constant polynomial)
///i.e. the secret is the share for everyone
#[derive(Default, Clone)]
pub struct DummyVss {}

impl ProtocolDescription for DummyVss {
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!("{indent}-DummyVss")
    }
}

#[async_trait]
impl Vss for DummyVss {
    async fn execute_many<Z: RingWithExceptionalSequence, S: BaseSessionHandles>(
        &self,
        session: &mut S,
        secrets: &[Z],
    ) -> anyhow::Result<Vec<Vec<Z>>> {
        let own_role = session.my_role();
        let num_parties = session.num_parties();

        // send all secrets to all parties
        let values_to_send: HashMap<Role, NetworkValue<Z>> = session
            .roles()
            .iter()
            .map(|role| (*role, NetworkValue::VecRingValue(secrets.to_vec())))
            .collect();
        send_to_parties(&values_to_send, session).await?;
        let mut jobs: JoinSet<Result<(Role, Result<Vec<Z>, anyhow::Error>), Elapsed>> =
            JoinSet::new();
        generic_receive_from_all(&mut jobs, session, &own_role, None, |msg, _id| match msg {
            NetworkValue::VecRingValue(v) => Ok(v),
            _ => Err(anyhow_error_and_log(
                "Received something else, not a galois ring element".to_string(),
            )),
        })
        .await;

        // index 0: num_parties, index 1: number of shares
        let mut res = vec![vec![Z::ZERO; secrets.len()]; num_parties];
        res[&own_role] = secrets.to_vec();
        while let Some(v) = jobs.join_next().await {
            let joined_result = v?;
            match joined_result {
                Ok((party_id, Ok(data))) => {
                    res[&party_id] = data;
                }
                //NOTE: received_data was init with default 0 values,
                //so no need to do anything when p2p fails
                Err(e) => {
                    tracing::error!("Error in Dummy VSS round 1 {:?}", e);
                }
                Ok((party_id, Err(e))) => {
                    tracing::error!(
                        "Error in Dummy VSS round 1, when receiving from party {}: {:?}",
                        party_id,
                        e
                    );
                }
            }
        }

        Ok(res)
    }
}

#[derive(Default, Clone)]
pub struct RealVss<BCast: Broadcast> {
    broadcast: BCast,
}

impl<BCast: Broadcast> ProtocolDescription for RealVss<BCast> {
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!("{}-RealVss:\n{}", indent, BCast::protocol_desc(depth + 1))
    }
}

impl<BCast: Broadcast> RealVss<BCast> {
    pub fn new(broadcast_strategy: &BCast) -> Self {
        Self {
            broadcast: broadcast_strategy.clone(),
        }
    }
}

#[async_trait]
impl<BCast: Broadcast> Vss for RealVss<BCast> {
    #[instrument(name="VSS", skip(self,session, secrets),fields(sid = ?session.session_id(),my_role = ?session.my_role()), batch_size= ?secrets.len())]
    async fn execute_many<Z: RingWithExceptionalSequence, S: BaseSessionHandles>(
        &self,
        session: &mut S,
        secrets: &[Z],
    ) -> anyhow::Result<Vec<Vec<Z>>> {
        let num_secrets = secrets.len();
        let (bivariate_poly, map_double_shares) = sample_secret_polys(session, secrets)?;
        let vss = round_1(session, num_secrets, bivariate_poly, map_double_shares).await?;
        let verification_map = round_2(session, num_secrets, &vss, &self.broadcast).await?;
        let unhappy_vec = round_3(
            session,
            num_secrets,
            &vss,
            &verification_map,
            &self.broadcast,
        )
        .await?;
        Ok(round_4(session, num_secrets, &vss, unhappy_vec, &self.broadcast).await?)
    }
}

pub(crate) type MapRoleDoublePoly<Z> = HashMap<Role, Vec<DoublePoly<Z>>>;

pub(crate) fn sample_secret_polys<Z: RingWithExceptionalSequence, S: BaseSessionHandles>(
    session: &mut S,
    secrets: &[Z],
) -> anyhow::Result<(Vec<BivariatePoly<Z>>, MapRoleDoublePoly<Z>)> {
    let degree = session.threshold() as usize;
    //Sample the bivariate polynomials Vec<F(X,Y)>
    let bivariate_poly = secrets
        .iter()
        .map(|s| BivariatePoly::from_secret(session.rng(), *s, degree))
        .collect::<Result<Vec<_>, _>>()?;
    //Evaluate the bivariate poly in its first and second variables
    //to create a mapping role -> Vec<(F(X,alpha_role), F(alpha_role,Y))>
    let map_double_shares: MapRoleDoublePoly<Z> = session
        .roles()
        .iter()
        .map(|r| {
            let embedded_role = Z::embed_role_to_exceptional_sequence(r)?;
            let mut vec_map = Vec::with_capacity(bivariate_poly.len());
            for p in &bivariate_poly {
                let share_in_x = p.partial_y_evaluation(embedded_role)?;
                let share_in_y = p.partial_x_evaluation(embedded_role)?;
                vec_map.push(DoublePoly {
                    share_in_x,
                    share_in_y,
                });
            }
            Ok::<(Role, Vec<DoublePoly<Z>>), anyhow::Error>((*r, vec_map))
        })
        .try_collect()?;
    Ok((bivariate_poly, map_double_shares))
}

pub(crate) async fn round_1<Z: Ring, S: BaseSessionHandles>(
    session: &mut S,
    num_secrets: usize,
    bivariate_poly: Vec<BivariatePoly<Z>>,
    map_double_shares: MapRoleDoublePoly<Z>,
) -> anyhow::Result<Round1VSSOutput<Z>> {
    let my_role = session.my_role();
    let num_parties = session.num_parties();

    // Init the received data with all 0s for all roles, will be filled
    // later with what we receive from other parties.
    let mut received_data: Vec<ExchangedDataRound1<Z>> =
        vec![ExchangedDataRound1::default(num_parties, num_secrets); num_parties];

    // Start filling the received data with the info for the VSS where
    // I am the sender.
    // Use direct indexing instead of get as this is all data created locally
    received_data[&my_role]
        .double_poly_list
        .clone_from(&map_double_shares[&my_role]);

    // For every party, create challenges for every VSS
    // We end up with challenges = Vec<Vec<Vec<Z>>>
    // such that challenges[i][j][k]
    // corresponds to the challenge to send to P_i for the kth secret in the batch
    // where P_j is the sender
    let challenges: Vec<ChallengesList<Z>> = (0..num_parties)
        .map(|_| {
            (0..num_parties)
                .map(|_| (0..num_secrets).map(|_| Z::sample(session.rng())).collect())
                .collect::<ChallengesList<Z>>()
        })
        .collect();

    // Prepare ExchangedDataRound1 to send to P_i for all P_i
    // where ExhangedDataRound1 contains:
    // - double_poly_list: a vec of num_secrets pair of polynomials (F_i(X), G_i(Y))
    //   for the VSS where I act as sender
    // - challenge: challenges[i] from above for all VSS
    let msgs_to_send = map_double_shares
        .iter()
        .map(|(role, poly)| {
            (
                *role,
                NetworkValue::Round1VSS(ExchangedDataRound1 {
                    double_poly_list: poly.clone(),
                    challenges_list: challenges[role].clone(),
                }),
            )
        })
        .collect();

    send_to_parties(&msgs_to_send, session).await?;

    let mut jobs = JoinSet::<ResultRound1<Z>>::new();
    // Receive data
    vss_receive_round_1(session, &mut jobs, my_role).await;

    // Parse the result, making sure we receive the expected amount of data
    // if there is any inconsistency we default to 0
    while let Some(v) = jobs.join_next().await {
        parse_round_1_received_data(
            v,
            &mut received_data,
            num_parties,
            session.threshold() as usize,
            num_secrets,
        );
    }

    Ok(Round1VSSOutput {
        sent_challenges: challenges,
        received_vss: received_data,
        my_poly: bivariate_poly,
    })
}

type RawReceivedDataRound1<Z> =
    Result<Result<(Role, anyhow::Result<ExchangedDataRound1<Z>>), Elapsed>, JoinError>;

/// Parses the data received during the round 1 of VSS
/// and enforces consistency.
/// If the data is consistent, fills the parsed_received_data
/// else logs and does nothing.
/// Thus expects the parsed_received_data
/// is properly init to the default 0 value.
fn parse_round_1_received_data<Z: Ring>(
    raw_received_data: RawReceivedDataRound1<Z>,
    parsed_received_data: &mut [ExchangedDataRound1<Z>],
    num_parties: usize,
    expected_max_degree: usize,
    batch_size: usize,
) {
    if let Ok(raw_received_data) = raw_received_data {
        if let Ok((sender_role, received_data)) = raw_received_data {
            if let Ok(received_data) = received_data {
                // Make sure the received data is consistent with what we expect:
                // - (condition_vss_sender) For sender_role as sender in VSS, expect batch_size poly of degree at most expected_max_degree
                // - (condiiton_vss_receiver) For sender_role as receiver in VSS, expect a Vec<Vec<Z>> of size num_parties x batch_size
                let condition_vss_sender = received_data.double_poly_list.len() == batch_size
                    && received_data.double_poly_list.iter().all(|double_poly| {
                        double_poly.share_in_x.deg() <= expected_max_degree
                            && double_poly.share_in_y.deg() <= expected_max_degree
                    });

                let condition_vss_receiver = received_data.challenges_list.len() == num_parties
                    && received_data
                        .challenges_list
                        .iter()
                        .all(|challenges| challenges.len() == batch_size);

                if condition_vss_sender && condition_vss_receiver {
                    // Use direct indexing as parsed_received_data is created locally
                    // and of correct size
                    parsed_received_data[&sender_role] = received_data;
                } else {
                    tracing::warn!(
                        "Party {:?} sent inconsistent data in VSS round 1. Either as the VSS sender ({:?}) or the VSS receiver ({:?})",
                        sender_role,
                        condition_vss_sender,
                        condition_vss_receiver
                    );
                }
            } else {
                tracing::warn!(
                    "Error on receiving data from {:?} in VSS round 1: {:?}. Default to 0.",
                    sender_role,
                    received_data
                );
            }
        } else {
            tracing::warn!(
                "Elapsed error on receiving data in VSS round 1: {:?}. Default to 0.",
                raw_received_data
            );
        }
    } else {
        tracing::warn!(
            "JoinError on receiving data in VSS round 1: {:?}. Default to 0.",
            raw_received_data
        )
    }
}

pub(crate) async fn round_2<
    Z: RingWithExceptionalSequence,
    S: BaseSessionHandles,
    BCast: Broadcast,
>(
    session: &mut S,
    num_secrets: usize,
    vss: &Round1VSSOutput<Z>,
    broadcast: &BCast,
) -> anyhow::Result<HashMap<Role, Option<Vec<VerificationValues<Z>>>>> {
    let my_role = session.my_role();
    let num_parties = session.num_parties();

    //For every VSS, compute
    // aij = F_i(\alpha_j) + r_ij
    // bij = G_i(\alpha_j) + r_ji
    //NOTE: aii and bii are not computed, input default there
    let all_roles = session.get_all_sorted_roles();
    let verification_vector: Vec<VerificationValues<Z>> = all_roles
        .iter()
        .map(|dealer_role| {
            all_roles
                .iter()
                .map(|party_idx| {
                    let verification_values = generate_verification_value(
                        num_secrets,
                        &my_role,
                        party_idx,
                        dealer_role,
                        vss,
                    )?;
                    Ok::<_, anyhow::Error>(verification_values)
                })
                .try_collect()
        })
        .try_collect()?;

    tracing::debug!(
        "Corrupt set before round2 broadcast is {:?}",
        session.corrupt_roles()
    );

    let bcast_data = broadcast
        .broadcast_from_all_w_corrupt_set_update(
            session,
            BroadcastValue::Round2VSS(verification_vector),
        )
        .await?;

    let mut casted_bcast_data: HashMap<Role, Option<Vec<VerificationValues<Z>>>> = bcast_data
        .into_iter()
        .map(|(role, broadcast_value)| {
            (
                role,
                verify_round_2_broadcast(role, broadcast_value, num_parties, num_secrets),
            )
        })
        .collect();

    // All parties agree on the result of the bcast, so add corrupt parties as needed
    for (role, result) in casted_bcast_data.iter() {
        if result.is_none() {
            session.add_corrupt(*role);
        }
    }

    //Also make sure we don't bother with corrupted parties
    for corrupted_role in session.corrupt_roles().iter() {
        casted_bcast_data.insert(*corrupted_role, None);
    }

    Ok(casted_bcast_data)
}

/// Verifies consistency of the data broadcast in round 2 of VSS
/// by checking that the data has the expected type and lengths.
/// Returns None if the check fails.
fn verify_round_2_broadcast<Z: Ring>(
    role: Role,
    broadcast_value: BroadcastValue<Z>,
    num_parties: usize,
    batch_size: usize,
) -> Option<Vec<VerificationValues<Z>>> {
    if let BroadcastValue::Round2VSS(value) = broadcast_value {
        // We want to make sure that each party did sent verification values for
        // - condition_1 : all VSS
        // - condition_2 : for all VSS, for all parties, for the whole batch
        let condition_1 = value.len() == num_parties;
        let condition_2 = value
            .iter()
            .all(|v| v.len() == num_parties && v.iter().all(|vv| vv.len() == batch_size));
        if condition_1 && condition_2 {
            return Some(value);
        } else {
            tracing::warn!(
                "Party {:?} failed to pass verification of VSS round 2 broadcast.
                Either not sending for all VSS ({:?}), or not for all parties and not for the whole batch ({:?}).",
                role,
                condition_1,
                condition_2,
            );
        }
    } else {
        tracing::warn!("Party {:?} sent unexpected type in VSS round 2.", role);
    }
    None
}

//NOTE: Verification_map is Map<Role, Option<Vec<Vec<(ResiduePol,ResiduePol)>>>> st
// Role0 -> Some(v) with v indexed as v[dealer_idx][Pj index][secret_idx]
// Role1 -> None means somethings wrong happened, consider all values to be 0
//...
pub(crate) async fn round_3<
    Z: RingWithExceptionalSequence,
    S: BaseSessionHandles,
    BCast: Broadcast,
>(
    session: &mut S,
    num_secrets: usize,
    vss: &Round1VSSOutput<Z>,
    verification_map: &HashMap<Role, Option<Vec<VerificationValues<Z>>>>,
    broadcast: &BCast,
) -> anyhow::Result<Vec<HashSet<Role>>> {
    let num_parties = session.num_parties();
    let own_role = session.my_role();

    //First create a HashSet<usize, role, role> that references all the conflicts
    //the usize represents the dealer idx of the conflict.
    //Remember: If there's a conflict for any secret_idx, we consider there's a conflict for the whole batch
    let potentially_unhappy =
        find_potential_conflicts_for_all_roles(verification_map, session.get_all_sorted_roles());

    tracing::info!(
        "I am {own_role} and Potentially unhappy with {:?}",
        potentially_unhappy
    );

    //Using BTreeMap instead of HashMap to send to network, BroadcastValue requires the Hash trait.
    let msg = answer_to_potential_conflicts(&potentially_unhappy, &own_role, vss)?;

    tracing::info!(
        "Corrupt set before unhappy broadcast is {:?}",
        session.corrupt_roles()
    );

    //Broadcast the potential conflicts only if there is a potentially unhappy set
    //wont cause sync issue on round number since all honest parties agree on this set
    //(as it is the result of bcast in round 2)
    let bcast_settlements: HashMap<Role, BroadcastValue<Z>> = if !potentially_unhappy.is_empty() {
        broadcast
            .broadcast_from_all_w_corrupt_set_update(session, BroadcastValue::Round3VSS(msg))
            .await?
    } else {
        HashMap::<Role, BroadcastValue<Z>>::new()
    };

    //Act on the bcast settlement
    let (unhappy_vec, malicious_bcast) = find_real_conflicts(
        num_secrets,
        &potentially_unhappy,
        bcast_settlements,
        num_parties,
    );

    tracing::info!("I am {own_role} and def. unhappy with {:?}", unhappy_vec);

    // Add the parties that have broadcast something obviously wrong
    for malicious_party in malicious_bcast.into_iter() {
        session.add_corrupt(malicious_party);
    }

    //Find out if any dealer is corrupt
    for (dealer_idx, unhappy_set) in unhappy_vec.iter().enumerate() {
        if unhappy_set.len() > session.threshold() as usize {
            session.add_corrupt(Role::indexed_from_zero(dealer_idx));
        }
    }

    Ok(unhappy_vec)
}

pub(crate) async fn round_4<
    Z: RingWithExceptionalSequence,
    S: BaseSessionHandles,
    BCast: Broadcast,
>(
    session: &mut S,
    num_secrets: usize,
    vss: &Round1VSSOutput<Z>,
    unhappy_vec: Vec<HashSet<Role>>,
    broadcast: &BCast,
) -> anyhow::Result<Vec<Vec<Z>>> {
    let mut msg = BTreeMap::<(Role, Role), ValueOrPoly<Z>>::new();
    let own_role = session.my_role();

    //For all dealers
    //For all parties Pi in unhappy, if I'm Sender OR I'm not in unhappy, help solve the conflict
    //if Sender send Fi(X) = F(X,alpha_i)
    //if not sender (Im Pj) send Gj(alpha_i)
    unhappy_vec
        .iter()
        .enumerate()
        .filter(|(dealer_idx, unhappy_set)| {
            !unhappy_set.contains(&own_role)
                && !session
                    .corrupt_roles()
                    .contains(&Role::indexed_from_zero(*dealer_idx))
        })
        .try_for_each(|(dealer_idx, unhappy_set)| {
            let dealer_role = Role::indexed_from_zero(dealer_idx);
            let is_dealer = own_role == dealer_role;
            round_4_conflict_resolution(&mut msg, is_dealer, dealer_role, unhappy_set, vss)?;
            Ok::<(), anyhow::Error>(())
        })?;

    //Broadcast_with_corruption uses broadcast_all,
    //but here we dont expect parties that are in unhappy in all vss to participate
    //For now let's just have everyone broadcast
    tracing::debug!(
        "Corrupt set before round4 broadcast is {:?}",
        session.corrupt_roles()
    );
    let unhappy_vec_is_empty = unhappy_vec
        .iter()
        .map(|unhappy_set| unhappy_set.is_empty())
        .fold(true, |acc, v| acc & v);

    let bcast_data = if !unhappy_vec_is_empty {
        broadcast
            .broadcast_from_all_w_corrupt_set_update(session, BroadcastValue::Round4VSS(msg))
            .await?
    } else {
        HashMap::<Role, BroadcastValue<Z>>::new()
    };

    //NOTE THAT IF I AM IN UNHAPPY, THUS SENDER SENT MY Fi IN THIS ROUND, THIS IS THE SHARE TO BE CONSIDERED
    //Loop through the unhappy sets (one for each vss),
    //retrieve correspondig bcast data and determine whether sender is corrupt
    unhappy_vec
        .iter()
        .enumerate()
        .try_for_each(|(dealer_idx, unhappy_set)| {
            let dealer_role = Role::indexed_from_zero(dealer_idx);
            if !session.corrupt_roles().contains(&dealer_role) {
                round_4_fix_conflicts(session, num_secrets, dealer_role, unhappy_set, &bcast_data)?;
            }
            Ok::<_, anyhow::Error>(())
        })?;

    //Remains to output trivial 0 for all senders in corrupt and correct share for all others
    //we use an auxiliary result variable to insert the result in order and not rely on the arbitrary order of keys()
    let num_parties = session.num_parties();
    let mut result: Vec<Vec<Z>> = vec![vec![Z::ZERO; num_secrets]; num_parties];
    session
        .roles()
        .iter()
        .filter(|sender| !session.corrupt_roles().contains(sender))
        .for_each(|role_sender| {
            //If sender is not considered corrupt but had to send my share in round 4, use this value
            let maybe_eval = bcast_data
                .get(role_sender)
                .and_then(|bcast| match bcast {
                    BroadcastValue::Round4VSS(v) => Some(v),
                    _ => None,
                })
                .and_then(|v| v.get(&(*role_sender, own_role)))
                .and_then(|entry| {
                    if let ValueOrPoly::Poly(p) = entry {
                        Some(p)
                    } else {
                        None
                    }
                })
                .map(|p| p.iter().map(|pp| pp.eval(&Z::ZERO)).collect_vec());

            if let Some(p) = maybe_eval {
                result[role_sender] = p;
            //Else, use the value received in the first round
            } else {
                result[role_sender] = vss.received_vss[role_sender]
                    .double_poly_list
                    .iter()
                    .map(|poly| poly.share_in_x.eval(&Z::ZERO))
                    .collect_vec();
            }
        });
    Ok(result)
}

async fn vss_receive_round_1<Z: Ring, S: BaseSessionHandles>(
    session: &S,
    jobs: &mut JoinSet<ResultRound1<Z>>,
    my_role: Role,
) {
    generic_receive_from_all(
        jobs,
        session,
        &my_role,
        Some(session.corrupt_roles()),
        |msg, _id| match msg {
            NetworkValue::Round1VSS(v) => Ok(v),
            _ => Err(anyhow_error_and_log(
                "Received something else, not a VSS round1 struct".to_string(),
            )),
        },
    )
    .await
}

/// Compute a_{i,j} and b_{i,j} for the num_secrets secrets shared by
/// Pk indexed by dealer_index, for Pj indexed by party_idx
fn generate_verification_value<Z>(
    num_secrets: usize,
    my_role: &Role,
    party_role: &Role,
    dealer_role: &Role,
    r1vss: &Round1VSSOutput<Z>,
) -> anyhow::Result<Vec<(Z, Z)>>
where
    Z: RingWithExceptionalSequence,
{
    // Using direct indexing is fine because we checked all the lengths before
    let current_vss = &r1vss.received_vss[dealer_role];
    let mut out = Vec::with_capacity(num_secrets);
    let alpha_other = Z::embed_role_to_exceptional_sequence(party_role)?;
    let my_challenges_to_pj = &r1vss.sent_challenges[party_role][dealer_role];
    let pj_challenges_to_me = &r1vss.received_vss[party_role].challenges_list[dealer_role];
    for i in 0..num_secrets {
        let double_poly = &current_vss.double_poly_list[i];
        if my_role != party_role {
            let my_share_in_x_eval = double_poly.share_in_x.eval(&alpha_other);
            let my_share_in_y_eval = double_poly.share_in_y.eval(&alpha_other);
            out.push((
                my_share_in_x_eval + my_challenges_to_pj[i],
                my_share_in_y_eval + pj_challenges_to_me[i],
            ))
        } else {
            out.push((Z::default(), Z::default()))
        }
    }
    Ok(out)
}

fn find_potential_conflicts_for_all_roles<Z: Ring>(
    verification_map: &HashMap<Role, Option<Vec<VerificationValues<Z>>>>,
    all_roles: &[Role],
) -> HashSet<(Role, Role, Role)> {
    let mut potentially_unhappy = HashSet::<(Role, Role, Role)>::new();
    //iter over all claims
    verification_map
        .iter()
        .for_each(|(pi_role, pi_claims_all_vss)| match pi_claims_all_vss {
            Some(pi_claims_all_vss) => {
                //We have claims for pi, look for potential conflicts
                find_potential_conflicts_received_challenges(
                    verification_map,
                    pi_role,
                    pi_claims_all_vss,
                    &mut potentially_unhappy,
                );
            }
            //We do not have claims for pi, it's in conflict with everyone for every vss (except itself)
            None => all_roles.iter().for_each(|dealer_role| {
                verification_map.keys().for_each(|pj_role| {
                    if pj_role != pi_role {
                        potentially_unhappy.insert((*dealer_role, *pi_role, *pj_role));
                    }
                })
            }),
        });
    potentially_unhappy
}

/// Compare P_i's claims with all the other parties
/// the verification map contains the claims of everyone
fn find_potential_conflicts_received_challenges<Z: Ring>(
    verification_map: &HashMap<Role, Option<Vec<VerificationValues<Z>>>>,
    pi_role: &Role,
    pi_claims_all_vss: &[VerificationValues<Z>],
    potentially_unhappy: &mut HashSet<(Role, Role, Role)>,
) {
    pi_claims_all_vss
        .iter()
        .enumerate()
        .for_each(|(dealer_idx, pi_claims_single_vss)| {
            // For Pi at vss dealer_idx, iter over all P_i claims a_ij
            // add potential conflict for the current vss
            // that is add Pi,Pj when a_ij neq bji
            let dealer_role = Role::indexed_from_zero(dealer_idx);
            pi_claims_single_vss
                .iter()
                .enumerate()
                .for_each(|(pj_index, aij_bij_list)| {
                    let pj_role = Role::indexed_from_zero(pj_index);
                    // No need to compare with itself
                    if pi_role != &pj_role {
                        // Retrieve all the claims of Pj and look bji for VSS dealer_idx,
                        match verification_map.get(&pj_role) {
                            // If there is any value for b_ji AND a_ij != bji add the pair to potential unhappy
                            // for the whole batch dealt by dealer_idx
                            Some(Some(pj_verification_values)) => {
                                // Make sure such bij exists, if not something went wrong and we
                                // add to unhappy
                                let aji_bji_list = pj_verification_values.get(dealer_idx).and_then(
                                    |pj_values_at_dealer_idx| {
                                        pi_role.get_from(pj_values_at_dealer_idx)
                                    },
                                );
                                if let Some(aji_bji_list) = aji_bji_list {
                                    for either_or_both_a_b in
                                        aij_bij_list.iter().zip_longest(aji_bji_list)
                                    {
                                        if let EitherOrBoth::Both(aij_bij, aji_bji) =
                                            either_or_both_a_b
                                        {
                                            if aij_bij.0 != aji_bji.1 {
                                                potentially_unhappy.insert((
                                                    dealer_role,
                                                    *pi_role,
                                                    pj_role,
                                                ));
                                                break;
                                            }
                                        } else {
                                            potentially_unhappy.insert((
                                                dealer_role,
                                                *pi_role,
                                                pj_role,
                                            ));
                                            break;
                                        }
                                    }
                                } else {
                                    potentially_unhappy.insert((dealer_role, *pi_role, pj_role));
                                }
                            }
                            //If there is no value for bji, add the pair to potential unhappy
                            _ => {
                                potentially_unhappy.insert((dealer_role, *pi_role, pj_role));
                            }
                        }
                    }
                })
        })
}

fn answer_to_potential_conflicts<Z>(
    potentially_unhappy: &HashSet<(Role, Role, Role)>,
    own_role: &Role,
    vss: &Round1VSSOutput<Z>,
) -> anyhow::Result<BTreeMap<(Role, Role, Role), Vec<Z>>>
where
    Z: RingWithExceptionalSequence,
{
    let mut msg = BTreeMap::<(Role, Role, Role), Vec<Z>>::new();
    //Can now match over the tuples of keys in potentially unhappy
    for key_tuple in potentially_unhappy.iter() {
        match key_tuple {
            //If vss_idx is the one where I'm sender send F(alpha_j, alpha_i)
            (dealer_role, pi_role, pj_role) if dealer_role == own_role => {
                let point_x = Z::embed_role_to_exceptional_sequence(pj_role)?;
                let point_y = Z::embed_role_to_exceptional_sequence(pi_role)?;
                msg.insert(
                    (*own_role, *pi_role, *pj_role),
                    vss.my_poly
                        .iter()
                        .map(|poly| poly.full_evaluation(point_x, point_y))
                        .collect::<Result<Vec<_>, _>>()?,
                );
            }
            //If im a Pi send Fi(alpha_j)
            (dealer_role, pi_role, pj_role) if pi_role == own_role => {
                let point = Z::embed_role_to_exceptional_sequence(pj_role)?;
                msg.insert(
                    (*dealer_role, *pi_role, *pj_role),
                    vss.received_vss[dealer_role]
                        .double_poly_list
                        .iter()
                        .map(|poly| poly.share_in_x.eval(&point))
                        .collect(),
                );
            }
            //If im a Pj send Gj(alpha_i)
            (dealer_role, pi_role, pj_role) if pj_role == own_role => {
                let point = Z::embed_role_to_exceptional_sequence(pi_role)?;
                msg.insert(
                    (*dealer_role, *pi_role, *pj_role),
                    vss.received_vss[dealer_role]
                        .double_poly_list
                        .iter()
                        .map(|poly| poly.share_in_y.eval(&point))
                        .collect(),
                );
            }
            //Else do nothing yet
            _ => {}
        }
    }

    Ok(msg)
}

/// Loop through potential unhappy, retrieve the corresponding three dispute settlement values and decide who to add in the unhappy set
/// Returns a vector of unhappy sets (one for each VSS sender) as well as a set of malicious which have been found to be broadcasting
/// something unexpected (either wrong type, or wrong length)
fn find_real_conflicts<Z: Ring>(
    num_secrets: usize,
    potentially_unhappy: &HashSet<(Role, Role, Role)>,
    bcast_settlements: HashMap<Role, BroadcastValue<Z>>,
    num_parties: usize,
) -> (Vec<HashSet<Role>>, HashSet<Role>) {
    let mut unhappy_vec = vec![HashSet::<Role>::new(); num_parties];
    let mut malicious_bcast = HashSet::new();
    let zeros = vec![Z::ZERO; num_secrets];
    for (dealer_role, role_pi, role_pj) in potentially_unhappy {
        let common_key = (*dealer_role, *role_pi, *role_pj);
        let sender_resolve = bcast_settlements
            .get(dealer_role)
            .and_then(|bcd| match bcd {
                BroadcastValue::Round3VSS(v) => Some(v),
                _ => None,
            })
            .and_then(|v| v.get(&common_key))
            .filter(|resolve_values| resolve_values.len() == num_secrets)
            .unwrap_or_else(|| {
                malicious_bcast.insert(*dealer_role);
                &zeros
            });

        let pi_resolve = bcast_settlements
            .get(role_pi)
            .and_then(|bcd| match bcd {
                BroadcastValue::Round3VSS(v) => Some(v),
                _ => None,
            })
            .and_then(|v| v.get(&common_key))
            .filter(|resolve_values| resolve_values.len() == num_secrets)
            .unwrap_or_else(|| {
                malicious_bcast.insert(*role_pi);
                &zeros
            });

        let pj_resolve = bcast_settlements
            .get(role_pj)
            .and_then(|bcd| match bcd {
                BroadcastValue::Round3VSS(v) => Some(v),
                _ => None,
            })
            .and_then(|v| v.get(&common_key))
            .filter(|resolve_values| resolve_values.len() == num_secrets)
            .unwrap_or_else(|| {
                malicious_bcast.insert(*role_pj);
                &zeros
            });

        if pi_resolve != sender_resolve {
            unhappy_vec[dealer_role].insert(*role_pi);
        }

        if pj_resolve != sender_resolve {
            unhappy_vec[dealer_role].insert(*role_pj);
        }
    }
    (unhappy_vec, malicious_bcast)
}

fn round_4_conflict_resolution<Z: RingWithExceptionalSequence>(
    msg: &mut BTreeMap<(Role, Role), ValueOrPoly<Z>>,
    is_dealer: bool,
    dealer_role: Role,
    unhappy_set: &HashSet<Role>,
    vss: &Round1VSSOutput<Z>,
) -> anyhow::Result<()> {
    for role_pi in unhappy_set.iter() {
        let point_pi = Z::embed_role_to_exceptional_sequence(role_pi)?;
        let msg_entry = match is_dealer {
            //As a dealer, resolve conflict with P_i by sending F(X,alpha_i) (P_i 's share)
            true => ValueOrPoly::Poly(
                vss.my_poly
                    .iter()
                    .map(|poly| poly.partial_y_evaluation(point_pi))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            //As P_j external from the conflict, resolve conflict with P_i by sending F(alpha_j,alpha_i)
            false => ValueOrPoly::Value(
                vss.received_vss[&dealer_role]
                    .double_poly_list
                    .iter()
                    .map(|poly| poly.share_in_y.eval(&point_pi))
                    .collect_vec(),
            ),
        };
        msg.insert((dealer_role, *role_pi), msg_entry);
    }
    Ok(())
}

fn round_4_fix_conflicts<Z: RingWithExceptionalSequence, S: BaseSessionHandles>(
    session: &mut S,
    num_secrets: usize,
    dealer_role: Role,
    unhappy_set: &HashSet<Role>,
    bcast_data: &HashMap<Role, BroadcastValue<Z>>,
) -> anyhow::Result<()> {
    let threshold = session.threshold() as usize;
    let mut malicious_bcast = HashSet::new();

    let default_maybe_poly = vec![Poly::zero(); num_secrets];
    for role_pi in unhappy_set.iter() {
        //Retrieve what parties that are not the dealer and are happy have to say for the conflict with Pi
        let non_dealer_happy_values: HashMap<Role, Vec<Z>> = session
            .roles()
            .iter()
            .filter_map(|role_pj| {
                if unhappy_set.contains(role_pj) || role_pj == role_pi || role_pj == &dealer_role {
                    None
                } else {
                    let maybe_pair = bcast_data
                        .get(role_pj)
                        .and_then(|bcd| match bcd {
                            BroadcastValue::Round4VSS(v) => Some(v),
                            _ => None,
                        })
                        .and_then(|v| v.get(&(dealer_role, *role_pi)))
                        .and_then(|v| match v {
                            ValueOrPoly::Value(vv) => {
                                // If there are not the expected number of values
                                // we discard the whole contribution from P_j
                                if vv.len() == num_secrets {
                                    Some((*role_pj, vv.clone()))
                                } else {
                                    None
                                }
                            }
                            _ => None,
                        });
                    // Outputs the values sent or zero and add Pj to malicious if nothing or garbage was sent
                    maybe_pair.map_or_else(
                        || {
                            malicious_bcast.insert(*role_pj);
                            Some((*role_pj, vec![Z::ZERO; num_secrets]))
                        },
                        Some,
                    )
                }
            })
            .collect();

        // Starting at 1 cause the dealer always votes for itself
        // as we do not explicitly broadcast both F_i(X) (from dealer)
        // and G_j(alpha_i) for P_j == dealer (thus from dealer too)
        let mut votes_for_dealer = 1_usize;
        if non_dealer_happy_values.len() >= 2 * threshold {
            //Retrieve sender's data from bcast related to Pi for this vss
            let maybe_poly = bcast_data
                .get(&dealer_role)
                .and_then(|bcd| match bcd {
                    BroadcastValue::Round4VSS(v) => Some(v),
                    _ => None,
                })
                .and_then(|v| v.get(&(dealer_role, *role_pi)))
                .and_then(|p| match p {
                    ValueOrPoly::Poly(p) => {
                        // If there are not enough polynomials sent by the dealer
                        // or if at least one doesn't have correct degree
                        // we discard the whole dealer's contribution
                        if p.len() == num_secrets && p.iter().all(|pol| pol.deg() <= threshold) {
                            Some(p)
                        } else {
                            None
                        }
                    }
                    _ => None,
                });

            // Output the polyomials sent by the VSS sender
            // or zero and add the VSS sender to malicious if nothing or garbage was sent
            let sender_poly = maybe_poly.map_or_else(
                || {
                    malicious_bcast.insert(dealer_role);
                    &default_maybe_poly
                },
                |p| p,
            );
            for (role_pj, value_pj) in non_dealer_happy_values {
                let point_pj = Z::embed_role_to_exceptional_sequence(&role_pj)?;
                let all_equals = sender_poly
                    .iter()
                    .map(|p| p.eval(&point_pj))
                    .zip_longest(value_pj)
                    .all(|zipped_claims| match zipped_claims {
                        EitherOrBoth::Both(sender_claim, party_claim) => {
                            sender_claim == party_claim
                        }
                        _ => false,
                    });
                if all_equals {
                    votes_for_dealer += 1;
                }
            }
        }
        if votes_for_dealer <= 2 * threshold {
            session.add_corrupt(dealer_role);
        }
    }

    // Also add all those who have sent garbage during broadcast
    for role in malicious_bcast.into_iter() {
        session.add_corrupt(role);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::algebra::bivariate::BivariateEval;
    use crate::algebra::galois_rings::degree_4::{
        ResiduePolyF4, ResiduePolyF4Z128, ResiduePolyF4Z64,
    };
    use crate::algebra::structure_traits::{ErrorCorrect, Invert};
    use crate::execution::runtime::session::SmallSession;
    use crate::execution::runtime::test_runtime::{generate_fixed_roles, DistributedTestRuntime};
    use crate::execution::sharing::shamir::{RevealOp, ShamirSharings};
    use crate::execution::sharing::share::Share;
    use crate::execution::small_execution::prf::PRSSConversions;
    use crate::execution::{
        runtime::party::Role,
        runtime::session::{BaseSessionHandles, LargeSession, ParameterHandles},
    };
    use crate::malicious_execution::large_execution::malicious_vss::{
        WrongDegreeSharingVss, WrongSecretLenVss,
    };
    use crate::networking::NetworkMode;
    use crate::session_id::SessionId;
    use crate::tests::helper::tests::{
        execute_protocol_large_w_disputes_and_malicious, TestingParameters,
    };
    use crate::tests::helper::tests_and_benches::execute_protocol_small;
    use futures_util::future::join;
    use rstest::rstest;
    use std::num::Wrapping;
    use tokio::task::JoinSet;

    fn setup_parties_and_secret(
        num_parties: usize,
        num_secrets: usize,
    ) -> (HashSet<Role>, Vec<Vec<ResiduePolyF4Z128>>) {
        let secret_f = |secret: usize| {
            (0..num_secrets)
                .map(|i| {
                    ResiduePolyF4Z128::from_scalar(Wrapping(((secret + 1) * i).try_into().unwrap()))
                })
                .collect_vec()
        };
        let secrets: Vec<Vec<ResiduePolyF4Z128>> = (0..num_parties).map(secret_f).collect();

        (generate_fixed_roles(num_parties), secrets)
    }

    #[test]
    fn test_dummy() {
        let num_secrets = 2;
        let (roles, secrets) = setup_parties_and_secret(4, num_secrets);

        // code for session setup
        let threshold = 1;
        // VSS assumes sync network
        let runtime = DistributedTestRuntime::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
        >::new(roles.clone(), threshold, NetworkMode::Sync, None);
        let session_id = SessionId::from(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();

        for party in roles {
            let mut session = runtime.large_session_for_party(session_id, party);
            let s = secrets[party.one_based() - 1].clone();
            set.spawn(async move {
                let dummy_vss = DummyVss::default();
                (
                    party,
                    dummy_vss.execute_many(&mut session, &s).await.unwrap(),
                )
            });
        }

        let results = rt.block_on(async {
            let mut results = Vec::new();
            while let Some(v) = set.join_next().await {
                let data = v.unwrap();
                results.push(data);
            }
            results
        });

        //Check that for each VSS the share IS the secret,
        //and for sanity that interpolation works
        for vss_idx in 0..=3 {
            let vec_shares: Vec<Vec<Share<_>>> = results
                .iter()
                .map(|(party, vec_shares_party)| {
                    (0..num_secrets)
                        .map(|i| Share::new(*party, vec_shares_party[vss_idx][i]))
                        .collect_vec()
                })
                .collect();
            assert_eq!(vec_shares.len(), 4);
            for vs in vec_shares.iter() {
                for (i, v) in vs.iter().enumerate() {
                    assert_eq!(v.value(), secrets[vss_idx][i]);
                }
            }

            // we need to "transpose" vec_shares to create `ShamirSharings`
            let shamir_sharings = (0..num_secrets)
                .map(|i| vec_shares.iter().map(|share| share[i]).collect_vec())
                .map(ShamirSharings::create);
            for (secret_i, shamir_sharing) in shamir_sharings.enumerate() {
                assert_eq!(
                    secrets[vss_idx][secret_i],
                    shamir_sharing.reconstruct(threshold.into()).unwrap()
                );
            }
        }
    }

    #[test]
    fn test_round_1() {
        let num_secrets = 2;
        let (roles, secrets) = setup_parties_and_secret(4, num_secrets);

        // code for session setup
        let threshold = 1;
        // VSS assumes sync network
        let runtime = DistributedTestRuntime::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
        >::new(roles.clone(), threshold, NetworkMode::Sync, None);
        let session_id = SessionId::from(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();

        for party in roles {
            let mut session = runtime.large_session_for_party(session_id, party);
            let s = &secrets[party.one_based() - 1];
            let (bivariate_poly, map_double_shares) = sample_secret_polys(&mut session, s).unwrap();
            set.spawn(async move {
                (
                    party,
                    round_1(&mut session, num_secrets, bivariate_poly, map_double_shares)
                        .await
                        .unwrap(),
                )
            });
        }
        let results = rt.block_on(async {
            let mut results = Vec::new();
            while let Some(v) = set.join_next().await {
                let data = v.unwrap();
                results.push(data);
            }
            results
        });

        //Check that bivariate polynomial has correct 0 coeffs
        //Also check that both univariate polynomial interpolate to secret
        for (party, result) in results.iter().cloned() {
            let x_0 = ResiduePolyF4::from_scalar(Wrapping(0));
            let y_0 = ResiduePolyF4::from_scalar(Wrapping(0));
            let expected_secret = &secrets[party.one_based() - 1];
            assert_eq!(
                &result
                    .my_poly
                    .iter()
                    .map(|p| p.full_evaluation(x_0, y_0).unwrap())
                    .collect_vec(),
                expected_secret,
            );
            //Check that received share come from bivariate pol
            for (pn, r) in results.iter().cloned() {
                if pn != party {
                    let embedded_pn =
                        ResiduePolyF4Z128::get_from_exceptional_sequence(pn.one_based()).unwrap();
                    let expected_result_x = result
                        .my_poly
                        .iter()
                        .map(|p| p.partial_y_evaluation(embedded_pn).unwrap())
                        .collect_vec();
                    let expected_result_y = result
                        .my_poly
                        .iter()
                        .map(|p| p.partial_x_evaluation(embedded_pn).unwrap())
                        .collect_vec();

                    assert_eq!(
                        expected_result_x,
                        r.received_vss[party.one_based() - 1]
                            .double_poly_list
                            .iter()
                            .map(|p| p.share_in_x.clone())
                            .collect_vec()
                    );

                    assert_eq!(
                        expected_result_y,
                        r.received_vss[party.one_based() - 1]
                            .double_poly_list
                            .iter()
                            .map(|p| p.share_in_y.clone())
                            .collect_vec()
                    );
                }
            }

            //Check that received share interpolate to secret
            let mut vec_x = Vec::with_capacity(4);
            let mut vec_y = Vec::with_capacity(4);
            for (pn, r) in results.iter().cloned() {
                if pn != party {
                    let point_pn = ResiduePolyF4Z128::get_from_exceptional_sequence(0).unwrap();
                    vec_x.push(
                        (0..num_secrets)
                            .map(|i| {
                                Share::new(
                                    pn,
                                    r.received_vss[party.one_based() - 1].double_poly_list[i]
                                        .share_in_x
                                        .eval(&point_pn),
                                )
                            })
                            .collect_vec(),
                    );
                    vec_y.push(
                        (0..num_secrets)
                            .map(|i| {
                                Share::new(
                                    pn,
                                    r.received_vss[party.one_based() - 1].double_poly_list[i]
                                        .share_in_y
                                        .eval(&point_pn),
                                )
                            })
                            .collect_vec(),
                    );
                }
            }

            for i in 0..num_secrets {
                let expected = expected_secret[i];
                let xs_shares = vec_x.iter().map(|xs| xs[i]).collect_vec();
                let ys_shares = vec_y.iter().map(|xs| xs[i]).collect_vec();
                let ss_x = ShamirSharings::create(xs_shares);
                let ss_y = ShamirSharings::create(ys_shares);
                assert_eq!(expected, ss_x.reconstruct(threshold.into()).unwrap());
                assert_eq!(expected, ss_y.reconstruct(threshold.into()).unwrap());
            }
        }
    }

    async fn test_vss_small<
        Z: ErrorCorrect + Invert + PRSSConversions,
        const EXTENSION_DEGREE: usize,
    >(
        params: TestingParameters,
        num_secrets: usize,
    ) {
        let mut task_honest = |mut session: SmallSession<Z>, _bot: Option<String>| async move {
            let real_vss = SecureVss::default();
            let secrets = (0..num_secrets)
                .map(|_| Z::sample(session.rng()))
                .collect_vec();
            (
                session.my_role(),
                real_vss.execute_many(&mut session, &secrets).await.unwrap(),
                secrets,
                session.corrupt_roles().clone(),
            )
        };

        // VSS assumes sync network
        let res = execute_protocol_small::<_, _, Z, EXTENSION_DEGREE>(
            params.num_parties,
            params.threshold as u8,
            params.expected_rounds,
            NetworkMode::Sync,
            None,
            &mut task_honest,
            None,
        )
        .await;
        let mut expected_secrets = vec![vec![Z::ZERO; num_secrets]; params.num_parties];
        for (party_role, _, s, _) in res.iter() {
            expected_secrets[party_role].clone_from(s);
        }

        for i in 0..num_secrets {
            for vss_idx in 0..params.num_parties {
                let vec_shares = res
                    .iter()
                    .map(|(party_role, vec_shares, _, _)| {
                        Share::new(*party_role, vec_shares[vss_idx][i])
                    })
                    .collect_vec();
                let shamir_sharing = ShamirSharings::create(vec_shares);
                let reconstructed_secret = shamir_sharing.reconstruct(params.threshold);
                assert!(reconstructed_secret.is_ok());
                assert_eq!(expected_secrets[vss_idx][i], reconstructed_secret.unwrap());
            }
        }
    }

    #[rstest]
    #[case(TestingParameters::init_honest(4, 1, Some(5)), 1)]
    #[case(TestingParameters::init_honest(4, 1, Some(5)), 5)]
    #[case(TestingParameters::init_honest(7, 2, Some(6)), 5)]
    #[case(TestingParameters::init_honest(10, 3, Some(7)), 5)]
    async fn test_vss_small_honest(#[case] params: TestingParameters, #[case] num_secrets: usize) {
        test_vss_small::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }>(
            params,
            num_secrets,
        )
        .await
    }

    async fn test_vss_strategies_large<
        Z: ErrorCorrect,
        const EXTENSION_DEGREE: usize,
        V: Vss + 'static,
    >(
        params: TestingParameters,
        num_secrets: usize,
        malicious_vss: V,
    ) {
        let mut task_honest = |mut session: LargeSession| async move {
            let real_vss = SecureVss::default();
            let secrets = (0..num_secrets)
                .map(|_| Z::sample(session.rng()))
                .collect_vec();
            (
                real_vss.execute_many(&mut session, &secrets).await.unwrap(),
                secrets,
                session.corrupt_roles().clone(),
            )
        };

        let mut task_malicious = |mut session: LargeSession, malicious_vss: V| async move {
            let secrets = (0..num_secrets)
                .map(|_| Z::sample(session.rng()))
                .collect_vec();
            let _ = malicious_vss.execute_many(&mut session, &secrets).await;
            secrets
        };

        // VSS assumes sync network
        let (results_honest, results_malicious) =
            execute_protocol_large_w_disputes_and_malicious::<_, _, _, _, _, Z, EXTENSION_DEGREE>(
                &params,
                &[],
                &params.malicious_roles,
                malicious_vss,
                NetworkMode::Sync,
                None,
                &mut task_honest,
                &mut task_malicious,
            )
            .await;

        //Assert malicious parties we shouldve caught indeed are
        if params.should_be_detected {
            for (_, _, corrupt_set) in results_honest.values() {
                for role in params.malicious_roles.iter() {
                    assert!(corrupt_set.contains(role));
                }
            }
        }

        //Create a vec of expected secrets
        let mut expected_secrets = vec![vec![Z::ZERO; num_secrets]; params.num_parties];
        for (party_role, (_, s, _)) in results_honest.iter() {
            expected_secrets[party_role].clone_from(s);
        }

        if !params.should_be_detected {
            for (party_role, result_malicious) in results_malicious.iter() {
                expected_secrets[party_role].clone_from(result_malicious);
            }
        }

        //Reconstruct secret from honest parties and check it's correct
        for i in 0..num_secrets {
            for vss_idx in 0..params.num_parties {
                let vec_shares = results_honest
                    .iter()
                    .map(|(party_role, (vec_shares, _, _))| {
                        Share::new(*party_role, vec_shares[vss_idx][i])
                    })
                    .collect_vec();
                let shamir_sharing = ShamirSharings::create(vec_shares);
                let reconstructed_secret = shamir_sharing.reconstruct(params.threshold);
                assert!(
                    reconstructed_secret.is_ok(),
                    "Failed to reconstruct secret coming from P {vss_idx} with error {reconstructed_secret:?}"
                );
                assert_eq!(expected_secrets[vss_idx][i], reconstructed_secret.unwrap());
            }
        }
    }

    //This is honest execution, so no malicious strategy
    // Rounds (happy path): We expect 3+1+t rounds
    #[rstest]
    #[case(TestingParameters::init_honest(4, 1, Some(5)), 1)]
    #[case(TestingParameters::init_honest(4, 1, Some(5)), 5)]
    #[case(TestingParameters::init_honest(7, 2, Some(6)), 5)]
    #[case(TestingParameters::init_honest(10, 3, Some(7)), 5)]
    async fn test_vss_honest_z128(#[case] params: TestingParameters, #[case] num_secrets: usize) {
        let malicious_vss = SecureVss::default();
        join(test_vss_strategies_large::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            num_secrets,
            malicious_vss.clone(),
        ),
        test_vss_strategies_large::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            num_secrets,
            malicious_vss.clone(),
        )).await;
    }

    // Test the behaviour where the adversary does not send the correct number of secrets
    #[rstest]
    #[case(TestingParameters::init(4,1,&[0],&[],&[],true,None), 4)]
    #[case(TestingParameters::init(7,2,&[0,2],&[],&[],true,None), 4)]
    async fn test_vss_wrong_secret_len<BCast: Broadcast + 'static>(
        #[case] params: TestingParameters,
        #[case] num_secrets: usize,
        #[values(SyncReliableBroadcast::default())] broadcast_strategy: BCast,
    ) {
        let wrong_secret_len_vss = WrongSecretLenVss::new(&broadcast_strategy);
        join(test_vss_strategies_large::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            num_secrets,
            wrong_secret_len_vss.clone(),
        ),
        test_vss_strategies_large::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            num_secrets,
            wrong_secret_len_vss.clone(),
        )).await;
    }

    // Test that when the sender sends a polynomial that has too
    // high degree it's caught
    #[rstest]
    #[case(TestingParameters::init(4,1,&[3],&[],&[],true,None), 4)]
    #[case(TestingParameters::init(7,2,&[0,2],&[],&[],true,None), 4)]
    async fn test_wrong_degree<BCast: Broadcast + 'static>(
        #[case] params: TestingParameters,
        #[case] num_secrets: usize,
        #[values(SyncReliableBroadcast::default())] broadcast_strategy: BCast,
    ) {
        let malicious_strategy = WrongDegreeSharingVss::new(&broadcast_strategy);

        join(
            test_vss_strategies_large::<
                ResiduePolyF4Z128,
                { ResiduePolyF4Z128::EXTENSION_DEGREE },
                _,
            >(params.clone(), 1, malicious_strategy.clone()),
            test_vss_strategies_large::<
                ResiduePolyF4Z128,
                { ResiduePolyF4Z128::EXTENSION_DEGREE },
                _,
            >(params, num_secrets, malicious_strategy),
        )
        .await;
    }

    //Test behaviour if a party doesn't participate in the protocol
    //Expected behaviour is that we end up with trivial 0 sharing for this party
    //and all other vss are fine
    #[cfg(feature = "slow_tests")]
    #[rstest]
    #[case(TestingParameters::init(4,1,&[0],&[],&[],true,None), 1)]
    #[case(TestingParameters::init(4,1,&[0],&[],&[],true,None), 2)]
    #[case(TestingParameters::init(4,1,&[1],&[],&[],true,None), 2)]
    #[case(TestingParameters::init(4,1,&[2],&[],&[],true,None), 2)]
    #[case(TestingParameters::init(4,1,&[2],&[],&[],true,None), 2)]
    #[case(TestingParameters::init(7,2,&[0,2],&[],&[],true,None), 2)]
    #[case(TestingParameters::init(7,2,&[1,3],&[],&[],true,None), 2)]
    #[case(TestingParameters::init(7,2,&[5,6],&[],&[],true,None), 2)]
    async fn test_vss_dropping_from_start(
        #[case] params: TestingParameters,
        #[case] num_secrets: usize,
    ) {
        use crate::malicious_execution::large_execution::malicious_vss::DroppingVssFromStart;

        let dropping_vss_from_start = DroppingVssFromStart::default();
        join(test_vss_strategies_large::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            num_secrets,
            dropping_vss_from_start.clone(),
        ),
        test_vss_strategies_large::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            num_secrets,
            dropping_vss_from_start.clone(),
        )).await;
    }

    ///Test for an adversary that sends malformed sharing in round 1 and does everything else honestly.
    ///If it lies to strictly more than t parties, we expect this party to get caught
    //Otherwise, we expect everything to happen normally - dispute will settle
    #[cfg(feature = "slow_tests")]
    #[tracing_test::traced_test]
    #[rstest]
    #[case(TestingParameters::init(4,1,&[0],&[3],&[],false,None), 1)]
    #[case(TestingParameters::init(4,1,&[0],&[3],&[],false,None), 2)]
    #[case(TestingParameters::init(4,1,&[1],&[0],&[],false,None), 2)]
    #[case(TestingParameters::init(4,1,&[2],&[1],&[],false,None), 2)]
    #[case(TestingParameters::init(4,1,&[3],&[2],&[],false,None), 2)]
    #[case(TestingParameters::init(4,1,&[0],&[3,1],&[],true,None), 2)]
    #[case(TestingParameters::init(4,1,&[1],&[0,2],&[],true,None), 2)]
    #[case(TestingParameters::init(4,1,&[2],&[3,0],&[],true,None), 2)]
    #[case(TestingParameters::init(4,1,&[3],&[2,1],&[],true,None), 2)]
    #[case(TestingParameters::init(7,2,&[0,2],&[3,1],&[],false,None), 2)]
    #[case(TestingParameters::init(7,2,&[1,3],&[4,2,0],&[],true,None), 2)]
    #[case(TestingParameters::init(7,2,&[5,6],&[3,1,0,2],&[],true,None), 2)]
    async fn test_vss_malicious_r1<BCast: Broadcast + 'static>(
        #[case] params: TestingParameters,
        #[case] num_secrets: usize,
        #[values(SyncReliableBroadcast::default())] broadcast_strategy: BCast,
    ) {
        use crate::malicious_execution::large_execution::malicious_vss::MaliciousVssR1;

        let malicious_vss_r1 = MaliciousVssR1::new(&broadcast_strategy, &params.roles_to_lie_to);
        join(test_vss_strategies_large::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            num_secrets,
            malicious_vss_r1.clone(),
        ),
        test_vss_strategies_large::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            num_secrets,
            malicious_vss_r1.clone(),
        )).await;
    }

    //Test for an adversary that drops out after Round1
    //We expect that adversarial parties will see their vss default to 0, all others VSS will recover
    #[cfg(feature = "slow_tests")]
    #[rstest]
    #[case(TestingParameters::init(4,1,&[0],&[],&[],true,None), 1)]
    #[case(TestingParameters::init(4,1,&[0],&[],&[],true,None), 2)]
    #[case(TestingParameters::init(4,1,&[1],&[],&[],true,None), 2)]
    #[case(TestingParameters::init(4,1,&[2],&[],&[],true,None), 2)]
    #[case(TestingParameters::init(4,1,&[2],&[],&[],true,None), 2)]
    #[case(TestingParameters::init(7,2,&[0,2],&[],&[],true,None), 2)]
    #[case(TestingParameters::init(7,2,&[1,3],&[],&[],true,None), 2)]
    #[case(TestingParameters::init(7,2,&[5,6],&[],&[],true,None), 2)]
    async fn test_vss_dropout_after_r1(
        #[case] params: TestingParameters,
        #[case] num_secrets: usize,
    ) {
        use crate::malicious_execution::large_execution::malicious_vss::DroppingVssAfterR1;

        let dropping_vss_after_r1 = DroppingVssAfterR1::default();
        join(test_vss_strategies_large::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            num_secrets,
            dropping_vss_after_r1.clone(),
        ),
        test_vss_strategies_large::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            num_secrets,
            dropping_vss_after_r1.clone(),
        )).await;
    }

    //Test for an adversary that drops out after Round2
    //We expect all goes fine as if honest round2, there's no further communication
    #[cfg(feature = "slow_tests")]
    #[rstest]
    #[case(TestingParameters::init(4,1,&[0],&[],&[],false,None), 1)]
    #[case(TestingParameters::init(4,1,&[0],&[],&[],false,None), 2)]
    #[case(TestingParameters::init(4,1,&[1],&[],&[],false,None), 2)]
    #[case(TestingParameters::init(4,1,&[2],&[],&[],false,None), 2)]
    #[case(TestingParameters::init(4,1,&[2],&[],&[],false,None), 2)]
    #[case(TestingParameters::init(7,2,&[0,2],&[],&[],false,None), 2)]
    #[case(TestingParameters::init(7,2,&[1,3],&[],&[],false,None), 2)]
    #[case(TestingParameters::init(7,2,&[5,6],&[],&[],false,None), 2)]
    async fn test_dropout_r3<BCast: Broadcast + 'static>(
        #[case] params: TestingParameters,
        #[case] num_secrets: usize,
        #[values(SyncReliableBroadcast::default())] broadcast_strategy: BCast,
    ) {
        use crate::malicious_execution::large_execution::malicious_vss::DroppingVssAfterR2;

        let dropping_vss_after_r2 = DroppingVssAfterR2::new(&broadcast_strategy);
        join(test_vss_strategies_large::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            num_secrets,
            dropping_vss_after_r2.clone(),
        ),
        test_vss_strategies_large::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            num_secrets,
            dropping_vss_after_r2.clone(),
        )).await;
    }
}

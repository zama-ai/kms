use std::collections::{BTreeMap, HashMap, HashSet};

use async_trait::async_trait;
use itertools::Itertools;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::{task::JoinSet, time::error::Elapsed};

use crate::error::error_handler::anyhow_error_and_log;
use crate::execution::{
    broadcast::generic_receive_from_all, p2p::send_to_parties, session::LargeSessionHandles,
};
use crate::value::NetworkValue;
use crate::{algebra::bivariate::BivariateEval, value::Value};

use crate::{
    algebra::bivariate::BivariateResiduePoly,
    execution::{broadcast::broadcast_with_corruption, party::Role},
    poly::Poly,
    residue_poly::ResiduePoly,
    value::BroadcastValue,
    Sample, Zero, Z128,
};

#[async_trait]
pub trait Vss: Send + Sync + Default + Clone {
    /// Executes a batched Verifiable Secret Sharing with
    /// - session as the MPC session
    /// - secret as secret to be shared
    /// - corrupt_set as the set of corrupted parties used for broadcast
    ///
    /// Returns
    /// - a vector of shares (share at idx i is a sharing of the secret of party i)
    async fn execute<R: RngCore, L: LargeSessionHandles<R>>(
        &self,
        session: &mut L,
        secret: &ResiduePoly<Z128>,
    ) -> anyhow::Result<Vec<ResiduePoly<Z128>>>;
}
type Challenge = Vec<ResiduePoly<Z128>>;
pub(crate) type VerificationValues = Vec<(ResiduePoly<Z128>, ResiduePoly<Z128>)>;
type ResultRound1 = Result<(Role, Result<ExchangedDataRound1, anyhow::Error>), Elapsed>;

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Hash, Debug)]
pub enum ValueOrPoly {
    Value(ResiduePoly<Z128>),
    Poly(Poly<ResiduePoly<Z128>>),
}

#[derive(Serialize, Deserialize, PartialEq, Clone, Hash, Debug, Default)]
struct DoublePoly {
    share_in_x: Poly<ResiduePoly<Z128>>,
    share_in_y: Poly<ResiduePoly<Z128>>,
}

/// Struct to hold data sent during round 1 of VSS, composed of
/// - double_poly is my share in a single VSS instance
/// - we need n challenges sent and n challenges received (one from every party)
#[derive(Serialize, Deserialize, PartialEq, Clone, Hash, Debug)]
pub struct ExchangedDataRound1 {
    double_poly: DoublePoly,
    challenge: Challenge,
}

impl ExchangedDataRound1 {
    pub fn default(num_parties: usize) -> Self {
        Self {
            double_poly: DoublePoly {
                share_in_x: Poly::default(),
                share_in_y: Poly::default(),
            },
            challenge: (0..num_parties).map(|_| ResiduePoly::default()).collect(),
        }
    }
}

///This data structure is indexed by [party_idx, idx_vss]
#[derive(Clone, Debug)]
pub struct Round1VSSOutput {
    sent_challenges: Vec<Challenge>,
    received_vss: Vec<ExchangedDataRound1>,
    my_poly: BivariateResiduePoly<Z128>,
}

///Simply send the trivial sharing P: X -> secret (P constant polynomial)
///i.e. the secret is the share for everyone
#[derive(Default, Clone)]
pub struct DummyVss {}

#[async_trait]
impl Vss for DummyVss {
    async fn execute<R: RngCore, L: LargeSessionHandles<R>>(
        &self,
        session: &mut L,
        secret: &ResiduePoly<Z128>,
    ) -> anyhow::Result<Vec<ResiduePoly<Z128>>> {
        let own_role = session.my_role()?;
        let num_parties = session.amount_of_parties();
        let values_to_send: HashMap<Role, NetworkValue> = session
            .role_assignments()
            .keys()
            .map(|role| (*role, NetworkValue::RingValue(Value::Poly128(*secret))))
            .collect();
        session.network().increase_round_counter().await?;
        send_to_parties(&values_to_send, session).await?;
        let mut jobs: JoinSet<Result<(Role, Result<ResiduePoly<Z128>, anyhow::Error>), Elapsed>> =
            JoinSet::new();
        generic_receive_from_all(&mut jobs, session, &own_role, None, |msg, _id| match msg {
            NetworkValue::RingValue(Value::Poly128(v)) => Ok(v),
            _ => Err(anyhow_error_and_log(
                "Received something else, not a galois ring element".to_string(),
            )),
        })?;

        let mut res = vec![ResiduePoly::<Z128>::ZERO; num_parties];
        res[own_role.zero_based()] = *secret;
        while let Some(v) = jobs.join_next().await {
            let joined_result = v?;
            match joined_result {
                Ok((party_id, Ok(data))) => {
                    res[party_id.zero_based()] = data;
                }
                //NOTE: received_data was init with default 0 values,
                //so no need to do anything when p2p fails
                Err(e) => {
                    tracing::error!("Error {:?}", e);
                }
                Ok((_party_id, Err(e))) => {
                    tracing::error!("Error {:?}", e);
                }
            }
        }

        Ok(res)
    }
}

//TODO: Once ready, add SyncBroadcast via generic and trait bounds
#[derive(Default, Clone)]
pub struct RealVss {}

#[async_trait]
impl Vss for RealVss {
    async fn execute<R: RngCore, L: LargeSessionHandles<R>>(
        &self,
        session: &mut L,
        secret: &ResiduePoly<Z128>,
    ) -> anyhow::Result<Vec<ResiduePoly<Z128>>> {
        let (bivariate_poly, map_double_shares) = sample_secret(session, secret)?;
        let vss = round_1(session, bivariate_poly, map_double_shares).await?;
        let verification_map = round_2(session, &vss).await?;
        let unhappy_vec = round_3(session, &vss, &verification_map).await?;
        Ok(round_4(session, &vss, unhappy_vec).await?)
    }
}
fn sample_secret<R: RngCore, L: LargeSessionHandles<R>>(
    session: &mut L,
    secret: &ResiduePoly<Z128>,
) -> anyhow::Result<(BivariateResiduePoly<Z128>, HashMap<Role, DoublePoly>)> {
    let threshold = session.threshold() as usize;
    let bivariate_poly = BivariateResiduePoly::from_secret(session.rng(), *secret, threshold)?;
    let map_double_shares: HashMap<Role, DoublePoly> = session
        .role_assignments()
        .keys()
        .map(|r| {
            let embedded_role = ResiduePoly::embed(r.one_based())?;
            let share_in_x = bivariate_poly.partial_y_evaluation(embedded_role)?;
            let share_in_y = bivariate_poly.partial_x_evaluation(embedded_role)?;
            Ok::<(Role, DoublePoly), anyhow::Error>((
                *r,
                DoublePoly {
                    share_in_x,
                    share_in_y,
                },
            ))
        })
        .try_collect()?;
    Ok((bivariate_poly, map_double_shares))
}

async fn round_1<R: RngCore, L: LargeSessionHandles<R>>(
    session: &mut L,
    bivariate_poly: BivariateResiduePoly<Z128>,
    map_double_shares: HashMap<Role, DoublePoly>,
) -> anyhow::Result<Round1VSSOutput> {
    let my_role = session.my_role()?;
    let num_parties = session.amount_of_parties();

    let mut received_data: Vec<ExchangedDataRound1> =
        vec![ExchangedDataRound1::default(num_parties); num_parties];
    received_data[my_role.zero_based()].double_poly = map_double_shares[&my_role].clone();

    //For every party, create challenges for every VSS
    let challenges: Vec<Challenge> = (0..num_parties)
        .map(|_| {
            {
                (0..num_parties)
                    .map(|_| ResiduePoly::<Z128>::sample(session.rng()))
                    .collect::<Challenge>()
            }
        })
        .collect();

    //Sending data
    let msgs_to_send = map_double_shares
        .iter()
        .map(|(role, poly)| {
            (
                *role,
                crate::value::NetworkValue::Round1VSS(ExchangedDataRound1 {
                    double_poly: poly.clone(),
                    challenge: challenges[role.zero_based()].clone(),
                }),
            )
        })
        .collect();

    session.network().increase_round_counter().await?;
    send_to_parties(&msgs_to_send, session).await?;

    let mut jobs = JoinSet::<ResultRound1>::new();
    // Receive data
    vss_receive_round_1(session, &mut jobs, my_role)?;

    while let Some(v) = jobs.join_next().await {
        let joined_result = v?;
        match joined_result {
            Ok((party_id, Ok(data))) => {
                received_data[party_id.zero_based()] = data;
            }
            //NOTE: received_data was init with default 0 values,
            //so no need to do anything when p2p fails
            Err(e) => {
                tracing::error!("Error {:?}", e);
            }
            Ok((_party_id, Err(e))) => {
                tracing::error!("Error {:?}", e);
            }
        }
    }
    Ok(Round1VSSOutput {
        sent_challenges: challenges,
        received_vss: received_data,
        my_poly: bivariate_poly,
    })
}

async fn round_2<R: RngCore, L: LargeSessionHandles<R>>(
    session: &mut L,
    vss: &Round1VSSOutput,
) -> anyhow::Result<HashMap<Role, Option<Vec<VerificationValues>>>> {
    let my_role = session.my_role()?;
    let num_parties = session.amount_of_parties();

    //For every VSS, compute
    // aij = F_i(\alpha_j) + r_ij
    // bij = G_i(\alpha_j) + r_ji
    //NOTE: aii and bii are not computed, input default there
    let verification_vector: Vec<VerificationValues> = (0..num_parties)
        .map(|vss_idx| {
            (0..num_parties)
                .map(|party_idx| {
                    let verification_values =
                        generate_verification_value(my_role.zero_based(), party_idx, vss_idx, vss)?;
                    Ok::<_, anyhow::Error>(verification_values)
                })
                .try_collect()
        })
        .try_collect()?;

    tracing::debug!(
        "Corrupt set before round2 broadcast is {:?}",
        session.corrupt_roles()
    );
    let bcast_data = broadcast_with_corruption::<R, L>(
        session,
        crate::value::BroadcastValue::Round2VSS(verification_vector),
    )
    .await?;

    //Do we want to use a filter map instead of a map to Option?
    let mut casted_bcast_data: HashMap<Role, Option<Vec<VerificationValues>>> = bcast_data
        .into_iter()
        .map(|(role, vv)| match vv {
            BroadcastValue::Round2VSS(v) => (role, Some(v)),
            _ => {
                tracing::warn!("Broadcast from {role} is of unexpected type");
                (role, None)
            }
        })
        .collect();

    //Also make sure we don't bother with corrupted players
    for corrupted_role in session.corrupt_roles().iter() {
        casted_bcast_data.insert(*corrupted_role, None);
    }

    Ok(casted_bcast_data)
}

//NOTE: Verification_map is Map<Role, Option<Vec<Vec<(ResiduePol,ResiduePol)>>>> st
// Role0 -> Some(v) with v = <VSS1:{<(a_00,b_00), (a_01,b_01), ...>}, VSS2:{}, ..., VSSn:{}>
// Role1 -> None means somethings wrong happened, consider all values to be 0
// Role2 -> Some(v) with v = <VSS1:{<(a_20,b_20), (a_21,b_21), ...>}, VSS2:{}, ..., VSSn:{}>
async fn round_3<R: RngCore, L: LargeSessionHandles<R>>(
    session: &mut L,
    vss: &Round1VSSOutput,
    verification_map: &HashMap<Role, Option<Vec<VerificationValues>>>,
) -> anyhow::Result<Vec<HashSet<Role>>> {
    let num_parties = session.amount_of_parties();
    let own_role = session.my_role()?;

    //First create a HashSet<usize, role, role> that references all the conflicts
    let potentially_unhappy = find_potential_conflicts_for_all_roles(verification_map, num_parties);

    tracing::info!(
        "I am {own_role} and Potentially unhappy with {:?}",
        potentially_unhappy
    );

    //Using BTreeMap instead of HashMap to send to network, BroadcastValue requires the Hash trait.
    let msg = answer_to_potential_conflicts(&potentially_unhappy, &own_role, vss)?;

    //Broadcast the potential conflicts
    tracing::info!(
        "Corrupt set before unhappy broadcast is {:?}",
        session.corrupt_roles()
    );

    //Only broadcast if msg is not empty
    let bcast_data: HashMap<Role, BroadcastValue> = if !potentially_unhappy.is_empty() {
        broadcast_with_corruption::<R, L>(session, BroadcastValue::Round3VSS(msg)).await?
    } else {
        HashMap::<Role, BroadcastValue>::new()
    };

    let unhappy_vec = find_real_conflicts(&potentially_unhappy, bcast_data, num_parties);

    tracing::info!("I am {own_role} and def. unhappy with {:?}", unhappy_vec);

    for (vss_idx, unhappy_set) in unhappy_vec.iter().enumerate() {
        if unhappy_set.len() > session.threshold() as usize {
            session.add_corrupt(Role::indexed_by_zero(vss_idx))?;
        }
    }

    Ok(unhappy_vec)
}

async fn round_4<R: RngCore, L: LargeSessionHandles<R>>(
    session: &mut L,
    vss: &Round1VSSOutput,
    unhappy_vec: Vec<HashSet<Role>>,
) -> anyhow::Result<Vec<ResiduePoly<Z128>>> {
    let mut msg = BTreeMap::<(usize, Role), ValueOrPoly>::new();
    let own_role = session.my_role()?;
    //For all parties Pi in unhappy, if I'm Sender OR I'm not in unhappy, help solve the conflict
    //if Sender send Fi(X) = F(X,alpha_i)
    //if not sender (Im Pj) send Gj(alpha_i)

    unhappy_vec
        .iter()
        .enumerate()
        .filter(|(idx, us)| {
            !us.contains(&own_role)
                && !session
                    .corrupt_roles()
                    .contains(&Role::indexed_by_zero(*idx))
        })
        .try_for_each(|unhappy_tuple| {
            let is_sender = own_role.zero_based() == unhappy_tuple.0;
            round_4_conflict_resolution(&mut msg, is_sender, unhappy_tuple, vss)?;
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
        broadcast_with_corruption::<R, L>(session, BroadcastValue::Round4VSS(msg)).await?
    } else {
        HashMap::<Role, BroadcastValue>::new()
    };

    //NOTE THAT IF I AM IN UNHAPPY, THUS SENDER SENT MY Fi IN THIS ROUND, THIS IS THE SHARE TO BE CONSIDERED
    //Loop through the unhappy sets (one for each vss),
    //retrieve correspondig bcast data and determine whether sender is corrupt
    unhappy_vec
        .iter()
        .enumerate()
        .try_for_each(|unhappy_tuple| {
            if !session
                .corrupt_roles()
                .contains(&Role::indexed_by_zero(unhappy_tuple.0))
            {
                round_4_fix_conflicts(session, unhappy_tuple, &bcast_data)?;
            }
            Ok::<_, anyhow::Error>(())
        })?;
    //Remains to output trivial 0 for all senders in corrupt and correct share for all others
    //aux result variable to insert the result in order and not rely on the arbitrary order of keys()
    let num_parties = session.amount_of_parties();
    let mut result: Vec<ResiduePoly<Z128>> = vec![ResiduePoly::<Z128>::ZERO; num_parties];
    session
        .role_assignments()
        .keys()
        .filter(|sender| !session.corrupt_roles().contains(sender))
        .for_each(|role_sender| {
            let vss_idx = role_sender.zero_based();
            let maybe_eval = bcast_data
                .get(role_sender)
                .and_then(|bcast| match bcast {
                    BroadcastValue::Round4VSS(v) => Some(v),
                    _ => None,
                })
                .and_then(|v| v.get(&(vss_idx, own_role)))
                .and_then(|entry| {
                    if let ValueOrPoly::Poly(p) = entry {
                        Some(p)
                    } else {
                        None
                    }
                })
                .map(|p| p.eval(&ResiduePoly::<Z128>::ZERO));

            if let Some(p) = maybe_eval {
                result[vss_idx] = p;
            } else {
                result[role_sender.zero_based()] = vss.received_vss[vss_idx]
                    .double_poly
                    .share_in_x
                    .eval(&ResiduePoly::<Z128>::ZERO);
            }
        });
    Ok(result)
}

fn vss_receive_round_1<R: RngCore, L: LargeSessionHandles<R>>(
    session: &L,
    jobs: &mut JoinSet<ResultRound1>,
    my_role: Role,
) -> anyhow::Result<()> {
    generic_receive_from_all::<ExchangedDataRound1, R, L>(
        jobs,
        session,
        &my_role,
        Some(session.corrupt_roles()),
        |msg, _id| match msg {
            crate::value::NetworkValue::Round1VSS(v) => Ok(v),
            _ => Err(anyhow_error_and_log(
                "Received something else, not a VSS round1 struct".to_string(),
            )),
        },
    )?;
    Ok(())
}

fn generate_verification_value(
    my_index: usize,
    party_idx: usize,
    vss_idx: usize,
    vss: &Round1VSSOutput,
) -> anyhow::Result<(ResiduePoly<Z128>, ResiduePoly<Z128>)> {
    if my_index != party_idx {
        let alpha_other = ResiduePoly::<Z128>::embed(party_idx + 1)?;
        let my_share_in_x_eval = vss.received_vss[vss_idx]
            .double_poly
            .share_in_x
            .eval(&alpha_other);
        let my_share_in_y_eval = vss.received_vss[vss_idx]
            .double_poly
            .share_in_y
            .eval(&alpha_other);
        Ok((
            my_share_in_x_eval + vss.sent_challenges[party_idx][vss_idx],
            my_share_in_y_eval + vss.received_vss[party_idx].challenge[vss_idx],
        ))
    } else {
        Ok((ResiduePoly::default(), ResiduePoly::default()))
    }
}

fn find_potential_conflicts_for_all_roles(
    verification_map: &HashMap<Role, Option<Vec<VerificationValues>>>,
    num_parties: usize,
) -> HashSet<(usize, Role, Role)> {
    let mut potentially_unhappy = HashSet::<(usize, Role, Role)>::new();
    //iter over all roles
    verification_map
        .iter()
        .for_each(|(pi_role, opt_challenge_vss)| match opt_challenge_vss {
            Some(challenge_vss) => {
                //We have challenges for pi, look for potential conflicts
                find_potential_conflicts_received_challenges(
                    verification_map,
                    pi_role,
                    challenge_vss,
                    &mut potentially_unhappy,
                );
            }
            //We do not have challenges for pi, it's in conflict with everyone for every vss (except itself)
            None => (0..num_parties).for_each(|idx_vss| {
                verification_map.keys().for_each(|pj_role| {
                    if pj_role != pi_role {
                        potentially_unhappy.insert((idx_vss, *pi_role, *pj_role));
                    }
                })
            }),
        });
    potentially_unhappy
}

fn find_potential_conflicts_received_challenges(
    verification_map: &HashMap<Role, Option<Vec<VerificationValues>>>,
    pi_role: &Role,
    challenge_vss: &[VerificationValues],
    potentially_unhappy: &mut HashSet<(usize, Role, Role)>,
) {
    challenge_vss
        .iter()
        .enumerate()
        .for_each(|(idx_vss, challenge_single_vss)| {
            //For Pi at vss idx_vss, iter over all the challenges a_ij
            //add potential conflict for the current vss
            //that is add Pi,Pj when a_ij neq bji
            challenge_single_vss
                .iter()
                .enumerate()
                .for_each(|(pj_index, aij)| {
                    let pj_role = Role::indexed_by_zero(pj_index);
                    //No need to compare with itself
                    if pi_role != &pj_role {
                        //Retrieve all the challenges of Pj and look bji for VSS idx_vss,
                        match verification_map.get(&pj_role) {
                            //If there is value for bji AND aij neq bji add the pair to potential unhappy
                            Some(Some(v)) => {
                                if v[idx_vss][pi_role.zero_based()].1 != aij.0 {
                                    potentially_unhappy.insert((idx_vss, *pi_role, pj_role));
                                }
                            }
                            //If there is no value for bji, add the pair to potential unhappy
                            _ => {
                                potentially_unhappy.insert((idx_vss, *pi_role, pj_role));
                            }
                        }
                    }
                })
        })
}

fn answer_to_potential_conflicts(
    potentially_unhappy: &HashSet<(usize, Role, Role)>,
    own_role: &Role,
    vss: &Round1VSSOutput,
) -> anyhow::Result<BTreeMap<(usize, Role, Role), ResiduePoly<Z128>>> {
    let mut msg = BTreeMap::<(usize, Role, Role), ResiduePoly<Z128>>::new();
    let my_vss_idx = own_role.zero_based();
    //Can now match over the tuples of keys in potentially unhappy
    //If vss_idx is the one where I'm sender send F(alpha_j, alpha_i)
    //If im a Pi send Fi(alpha_j)
    //If im a Pj send Gj(alpha_i)
    //Else do nothing yet
    for key_tuple in potentially_unhappy.iter() {
        match key_tuple {
            (vss_idx, pi_role, pj_role) if vss_idx == &my_vss_idx => {
                let point_x = ResiduePoly::<Z128>::embed(pj_role.one_based())?;
                let point_y = ResiduePoly::<Z128>::embed(pi_role.one_based())?;
                msg.insert(
                    (*vss_idx, *pi_role, *pj_role),
                    vss.my_poly.full_evaluation(point_x, point_y)?,
                );
            }
            (vss_idx, pi_role, pj_role) if pi_role == own_role => {
                let point = ResiduePoly::<Z128>::embed(pj_role.one_based())?;
                msg.insert(
                    (*vss_idx, *pi_role, *pj_role),
                    vss.received_vss[*vss_idx]
                        .double_poly
                        .share_in_x
                        .eval(&point),
                );
            }
            (vss_idx, pi_role, pj_role) if pj_role == own_role => {
                let point = ResiduePoly::<Z128>::embed(pi_role.one_based())?;
                msg.insert(
                    (*vss_idx, *pi_role, *pj_role),
                    vss.received_vss[*vss_idx]
                        .double_poly
                        .share_in_y
                        .eval(&point),
                );
            }
            _ => {}
        }
    }

    Ok(msg)
}

fn find_real_conflicts(
    potentially_unhappy: &HashSet<(usize, Role, Role)>,
    bcast_settlements: HashMap<Role, BroadcastValue>,
    num_parties: usize,
) -> Vec<HashSet<Role>> {
    //Loop through potential unhappy, retrieve the corresponding three dispute settlment values and decide who to add in the unhappy set
    let mut unhappy_vec = vec![HashSet::<Role>::new(); num_parties];
    for (vss_idx, role_pi, role_pj) in potentially_unhappy {
        let common_key = (*vss_idx, *role_pi, *role_pj);

        let sender_resolve = bcast_settlements
            .get(&Role::indexed_by_zero(*vss_idx))
            .and_then(|bcd| match bcd {
                BroadcastValue::Round3VSS(v) => Some(v),
                _ => None,
            })
            .and_then(|v| v.get(&common_key))
            .unwrap_or(&ResiduePoly::<Z128>::ZERO);

        let pi_resolve = bcast_settlements
            .get(role_pi)
            .and_then(|bcd| match bcd {
                BroadcastValue::Round3VSS(v) => Some(v),
                _ => None,
            })
            .and_then(|v| v.get(&common_key))
            .unwrap_or(&ResiduePoly::<Z128>::ZERO);

        let pj_resolve = bcast_settlements
            .get(role_pj)
            .and_then(|bcd| match bcd {
                BroadcastValue::Round3VSS(v) => Some(v),
                _ => None,
            })
            .and_then(|v| v.get(&common_key))
            .unwrap_or(&ResiduePoly::<Z128>::ZERO);

        if pi_resolve != sender_resolve {
            unhappy_vec[*vss_idx].insert(*role_pi);
        }

        if pj_resolve != sender_resolve {
            unhappy_vec[*vss_idx].insert(*role_pj);
        }
    }
    unhappy_vec
}

fn round_4_conflict_resolution(
    msg: &mut BTreeMap<(usize, Role), ValueOrPoly>,
    is_sender: bool,
    unhappy_tuple: (usize, &HashSet<Role>),
    vss: &Round1VSSOutput,
) -> anyhow::Result<()> {
    let (vss_idx, unhappy_set) = unhappy_tuple;
    for role_pi in unhappy_set.iter() {
        let point_pi = ResiduePoly::<Z128>::embed(role_pi.one_based())?;
        let msg_entry = match is_sender {
            true => ValueOrPoly::Poly(vss.my_poly.partial_y_evaluation(point_pi)?),
            false => ValueOrPoly::Value(
                vss.received_vss[vss_idx]
                    .double_poly
                    .share_in_y
                    .eval(&point_pi),
            ),
        };
        msg.insert((vss_idx, *role_pi), msg_entry);
    }
    Ok(())
}

fn round_4_fix_conflicts<R: RngCore, L: LargeSessionHandles<R>>(
    session: &mut L,
    unhappy_tuple: (usize, &HashSet<Role>),
    bcast_data: &HashMap<Role, BroadcastValue>,
) -> anyhow::Result<()> {
    let (vss_idx, unhappy_set) = unhappy_tuple;
    let sender_role = Role::indexed_by_zero(vss_idx);
    let threshold = session.threshold() as usize;

    for role_pi in unhappy_set.iter() {
        let non_sender_happy_values: HashMap<Role, ResiduePoly<Z128>> = session
            .role_assignments()
            .keys()
            .filter_map(|role_pj| {
                if unhappy_set.contains(role_pj) || role_pj == role_pi || role_pj == &sender_role {
                    None
                } else {
                    let maybe_pair = bcast_data
                        .get(role_pj)
                        .and_then(|bcd| match bcd {
                            BroadcastValue::Round4VSS(v) => Some(v),
                            _ => None,
                        })
                        .and_then(|v| v.get(&(vss_idx, *role_pi)))
                        .and_then(|v| match v {
                            ValueOrPoly::Value(vv) => Some((*role_pj, *vv)),
                            _ => None,
                        });
                    maybe_pair.map_or_else(|| Some((*role_pj, ResiduePoly::<Z128>::ZERO)), Some)
                }
            })
            .collect();
        if non_sender_happy_values.len() >= 2 * threshold {
            //Retrieve sender's data from bcast related to Pi for this vss
            let maybe_poly = bcast_data
                .get(&sender_role)
                .and_then(|bcd| match bcd {
                    BroadcastValue::Round4VSS(v) => Some(v),
                    _ => None,
                })
                .and_then(|v| v.get(&(vss_idx, *role_pi)))
                .and_then(|p| match p {
                    ValueOrPoly::Poly(p) => Some(p),
                    _ => None,
                });

            let sender_poly = maybe_poly.map_or_else(Poly::zero, |p| p.clone());
            let mut votes_against_sender = 0_usize;
            for (role_pj, value_pj) in non_sender_happy_values {
                let point_pj = ResiduePoly::<Z128>::embed(role_pj.one_based())?;
                if value_pj != sender_poly.eval(&point_pj) {
                    votes_against_sender += 1;
                }
            }
            if votes_against_sender >= 2 * threshold {
                session.add_corrupt(sender_role)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use std::collections::HashMap;
    use std::num::Wrapping;

    use rand::SeedableRng;
    use rstest::rstest;
    use tokio::task::JoinSet;

    use super::*;
    use crate::algebra::bivariate::BivariateEval;
    use crate::algebra::bivariate::BivariateResiduePoly;
    use crate::computation::SessionId;
    use crate::execution::party::Role;
    use crate::execution::session::BaseSessionHandles;
    use crate::execution::session::LargeSession;
    use crate::execution::session::ParameterHandles;
    use crate::execution::{distributed::DistributedTestRuntime, party::Identity};
    use crate::poly::Poly;
    use crate::residue_poly::ResiduePoly;
    use crate::shamir::ShamirGSharings;
    use crate::tests::helper::tests::execute_protocol_w_disputes_and_malicious;
    use crate::tests::helper::tests::roles_from_idxs;
    use crate::{One, Zero, Z128};
    use rand_chacha::ChaCha12Rng;

    fn setup_parties_and_secret(num_parties: usize) -> (Vec<Identity>, Vec<ResiduePoly<Z128>>) {
        let identities: Vec<Identity> = (0..num_parties)
            .map(|party_nb| {
                let mut id_str = "localhost:500".to_owned();
                id_str.push_str(&party_nb.to_string());
                Identity(id_str)
            })
            .collect();

        let secrets: Vec<ResiduePoly<Z128>> = (0..num_parties)
            .map(|secret| {
                ResiduePoly::<Z128>::from_scalar(Wrapping((secret + 1).try_into().unwrap()))
            })
            .collect();

        (identities, secrets)
    }

    #[test]
    fn test_dummy() {
        let (identities, secrets) = setup_parties_and_secret(4);

        // code for session setup
        let threshold = 1;
        let runtime = DistributedTestRuntime::new(identities.clone(), threshold);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();

        for (party_nb, _) in runtime.identities.iter().enumerate() {
            let mut session = runtime
                .large_session_for_player(session_id, party_nb)
                .unwrap();
            let s = secrets[party_nb];
            set.spawn(async move {
                let dummy_vss = DummyVss::default();
                (party_nb, dummy_vss.execute(&mut session, &s).await.unwrap())
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
            let vec_shares: Vec<(usize, ResiduePoly<Z128>)> = results
                .iter()
                .map(|(party_id, vec_shares_party)| (party_id + 1, vec_shares_party[vss_idx]))
                .collect();
            assert_eq!(vec_shares.len(), 4);
            for v in vec_shares.iter() {
                assert_eq!(v.1, secrets[vss_idx]);
            }
            let shamir_sharing = ShamirGSharings { shares: vec_shares };
            assert_eq!(
                secrets[vss_idx],
                shamir_sharing.reconstruct(threshold.into()).unwrap()
            );
        }
    }
    #[test]
    fn test_round_1() {
        let (identities, secrets) = setup_parties_and_secret(4);

        // code for session setup
        let threshold = 1;
        let runtime = DistributedTestRuntime::new(identities.clone(), threshold);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();

        for (party_nb, _) in runtime.identities.iter().enumerate() {
            //let own_role = Role::from(party_nb as u64 + 1);
            let mut session = runtime
                .large_session_for_player(session_id, party_nb)
                .unwrap();
            let s = secrets[party_nb];
            let (bivariate_poly, map_double_shares) = sample_secret(&mut session, &s).unwrap();
            set.spawn(async move {
                (
                    party_nb,
                    round_1(&mut session, bivariate_poly, map_double_shares)
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
        for (party_nb, result) in results.clone().iter() {
            let x_0 = ResiduePoly::from_scalar(Wrapping(0));
            let y_0 = ResiduePoly::from_scalar(Wrapping(0));
            let expected_secret = secrets[*party_nb];
            assert_eq!(
                result.my_poly.full_evaluation(x_0, y_0).unwrap(),
                expected_secret.clone()
            );
            //Check that received share come from bivariate pol
            for (pn, r) in results.clone().iter() {
                if pn != party_nb {
                    let embedded_pn = ResiduePoly::<Z128>::embed(pn + 1).unwrap();
                    let expected_result_x =
                        result.my_poly.partial_y_evaluation(embedded_pn).unwrap();
                    let expected_result_y =
                        result.my_poly.partial_x_evaluation(embedded_pn).unwrap();

                    assert_eq!(
                        expected_result_x,
                        r.received_vss[*party_nb].double_poly.share_in_x
                    );

                    assert_eq!(
                        expected_result_y,
                        r.received_vss[*party_nb].double_poly.share_in_y
                    );
                }
            }

            //Check that received share interpolate to secret
            let mut vec_x = Vec::<(usize, ResiduePoly<Z128>)>::with_capacity(4);
            let mut vec_y = Vec::<(usize, ResiduePoly<Z128>)>::with_capacity(4);
            for (pn, r) in results.clone().iter() {
                if pn != party_nb {
                    let point_pn = ResiduePoly::<Z128>::embed(0).unwrap();
                    vec_x.push((
                        *pn + 1,
                        r.received_vss[*party_nb]
                            .double_poly
                            .share_in_x
                            .eval(&point_pn),
                    ));
                    vec_y.push((
                        *pn + 1,
                        r.received_vss[*party_nb]
                            .double_poly
                            .share_in_y
                            .eval(&point_pn),
                    ));
                }
            }

            let ss_x = ShamirGSharings {
                shares: vec_x.clone(),
            };
            let ss_y = ShamirGSharings {
                shares: vec_y.clone(),
            };

            assert_eq!(expected_secret, ss_x.reconstruct(threshold.into()).unwrap());

            assert_eq!(expected_secret, ss_y.reconstruct(threshold.into()).unwrap());
        }
    }

    //We now define cheatin strategies, each implement the VSS trait
    ///Does nothing, and output an empty Vec
    #[derive(Default, Clone)]
    pub struct DroppingVssFromStart {}
    ///Does round 1 and then drops
    #[derive(Default, Clone)]
    pub struct DroppingVssAfterR1 {}
    ///Does round 1 and 2 and then drops
    #[derive(Default, Clone)]
    pub struct DroppingVssAfterR2 {}
    ///Participate in the protocol, but lies to some parties in the first round
    #[derive(Default, Clone)]
    pub struct MaliciousVssR1 {
        roles_to_lie_to: Vec<Role>,
    }

    #[async_trait]
    impl Vss for DroppingVssFromStart {
        //Do nothing, and output an empty Vec
        async fn execute<R: RngCore, L: LargeSessionHandles<R>>(
            &self,
            _session: &mut L,
            _secret: &ResiduePoly<Z128>,
        ) -> anyhow::Result<Vec<ResiduePoly<Z128>>> {
            Ok(Vec::new())
        }
    }

    #[async_trait]
    impl Vss for DroppingVssAfterR1 {
        //Do round1, and output an empty Vec
        async fn execute<R: RngCore, L: LargeSessionHandles<R>>(
            &self,
            session: &mut L,
            secret: &ResiduePoly<Z128>,
        ) -> anyhow::Result<Vec<ResiduePoly<Z128>>> {
            let (bivariate_poly, map_double_shares) = sample_secret(session, secret)?;
            let _ = round_1(session, bivariate_poly, map_double_shares).await?;
            Ok(Vec::new())
        }
    }

    #[async_trait]
    impl Vss for DroppingVssAfterR2 {
        //Do round1 and round2, and output an empty Vec
        async fn execute<R: RngCore, L: LargeSessionHandles<R>>(
            &self,
            session: &mut L,
            secret: &ResiduePoly<Z128>,
        ) -> anyhow::Result<Vec<ResiduePoly<Z128>>> {
            let (bivariate_poly, map_double_shares) = sample_secret(session, secret)?;
            let vss = round_1(session, bivariate_poly, map_double_shares).await?;
            let _ = round_2(session, &vss).await?;
            Ok(Vec::new())
        }
    }

    impl MaliciousVssR1 {
        pub fn init(roles_from_zero: &[usize]) -> Self {
            Self {
                roles_to_lie_to: roles_from_zero
                    .iter()
                    .map(|id_role| Role::indexed_by_zero(*id_role))
                    .collect_vec(),
            }
        }
    }
    #[async_trait]
    impl Vss for MaliciousVssR1 {
        async fn execute<R: RngCore, L: LargeSessionHandles<R>>(
            &self,
            session: &mut L,
            secret: &ResiduePoly<Z128>,
        ) -> anyhow::Result<Vec<ResiduePoly<Z128>>> {
            //Execute a malicious round 1
            let vss = malicious_round_1(session, secret, &self.roles_to_lie_to).await?;
            let verification_map = round_2(session, &vss).await?;
            let unhappy_vec = round_3(session, &vss, &verification_map).await?;
            Ok(round_4(session, &vss, unhappy_vec).await?)
        }
    }

    //This code executes a round1 where the party sends malformed double shares for its VSS to parties in roles_to_lie_to
    async fn malicious_round_1<R: RngCore, L: LargeSessionHandles<R>>(
        session: &mut L,
        secret: &ResiduePoly<Z128>,
        roles_to_lie_to: &[Role],
    ) -> anyhow::Result<Round1VSSOutput> {
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let bivariate_poly =
            BivariateResiduePoly::from_secret(&mut rng, *secret, session.threshold() as usize)
                .unwrap();
        let map_double_shares: HashMap<Role, DoublePoly> = session
            .role_assignments()
            .keys()
            .map(|r| {
                let embedded_role = ResiduePoly::embed(r.one_based()).unwrap();
                if roles_to_lie_to.contains(r) {
                    (
                        *r,
                        DoublePoly {
                            share_in_x: Poly::<ResiduePoly<Z128>>::sample_random(
                                &mut rng,
                                ResiduePoly::<Z128>::ONE,
                                session.threshold().into(),
                            ),
                            share_in_y: Poly::<ResiduePoly<Z128>>::sample_random(
                                &mut rng,
                                ResiduePoly::<Z128>::ZERO,
                                session.threshold().into(),
                            ),
                        },
                    )
                } else {
                    (
                        *r,
                        DoublePoly {
                            share_in_x: bivariate_poly.partial_y_evaluation(embedded_role).unwrap(),
                            share_in_y: bivariate_poly.partial_x_evaluation(embedded_role).unwrap(),
                        },
                    )
                }
            })
            .collect();
        round_1(session, bivariate_poly, map_double_shares).await
    }

    fn test_vss_strategies<V: Vss + 'static>(
        num_parties: usize,
        threshold: usize,
        malicious_vss: V,
        malicious_roles: &[Role],
        should_be_detected: bool,
    ) {
        async fn task_honest(
            mut session: LargeSession,
        ) -> (
            usize,
            ResiduePoly<Z128>,
            Vec<ResiduePoly<Z128>>,
            HashSet<Role>,
        ) {
            let real_vss = RealVss::default();
            let secret = ResiduePoly::<Z128>::sample(session.rng());
            (
                session.my_role().unwrap().zero_based(),
                secret,
                real_vss.execute(&mut session, &secret).await.unwrap(),
                session.corrupt_roles().clone(),
            )
        }

        async fn task_malicious<V: Vss>(
            mut session: LargeSession,
            malicious_vss: V,
        ) -> (usize, ResiduePoly<Z128>) {
            let secret = ResiduePoly::<Z128>::sample(session.rng());
            let _ = malicious_vss.execute(&mut session, &secret).await;
            (session.my_role().unwrap().zero_based(), secret)
        }

        let (results_honest, results_malicious) = execute_protocol_w_disputes_and_malicious(
            num_parties,
            threshold as u8,
            &[],
            malicious_roles,
            malicious_vss,
            &mut task_honest,
            &mut task_malicious,
        );

        //Assert malicious parties we shouldve been caught indeed are
        if should_be_detected {
            for (_, _, _, corrupt_set) in results_honest.iter() {
                for role in malicious_roles {
                    assert!(corrupt_set.contains(role));
                }
            }
        }

        //Create a vec of expected secrets
        let mut expected_secrets = vec![ResiduePoly::<Z128>::ZERO; num_parties];
        for (party_idx, s, _, _) in results_honest.iter() {
            expected_secrets[*party_idx] = *s;
        }

        if !should_be_detected {
            for result_malicious in results_malicious.iter() {
                assert!(result_malicious.is_ok());
                let (party_idx, s) = result_malicious.as_ref().unwrap();
                expected_secrets[*party_idx] = *s;
            }
        }

        //Reconstruct secret from honest parties and check it's correct
        for vss_idx in 0..num_parties {
            let vec_shares = results_honest
                .iter()
                .map(|(party_id, _, vec_shares, _)| (party_id + 1, vec_shares[vss_idx]))
                .collect_vec();
            let shamir_sharing = ShamirGSharings { shares: vec_shares };
            let reconstructed_secret = shamir_sharing.reconstruct(threshold);
            assert!(reconstructed_secret.is_ok());
            assert_eq!(expected_secrets[vss_idx], reconstructed_secret.unwrap());
        }
    }

    #[rstest]
    #[case(4, 1)]
    #[case(7, 2)]
    #[case(10, 3)]
    fn test_vss_honest(#[case] num_parties: usize, #[case] threshold: usize) {
        //This is honest execution, so no malicious strategy
        let malicious_vss = RealVss::default();
        let malicious_roles = &[];
        let should_be_detected = false;

        test_vss_strategies(
            num_parties,
            threshold,
            malicious_vss,
            malicious_roles,
            should_be_detected,
        );
    }

    //Test behaviour if a party doesn't participate in the protocol
    //Expected behaviour is that we end up with trivial 0 sharing for this party
    //and all other vss are fine
    #[rstest]
    #[case(4,1,&roles_from_idxs(&[0]),true)]
    #[case(4,1,&roles_from_idxs(&[1]),true)]
    #[case(4,1,&roles_from_idxs(&[2]),true)]
    #[case(4,1,&roles_from_idxs(&[2]),true)]
    #[case(7,2,&roles_from_idxs(&[0,2]),true)]
    #[case(7,2,&roles_from_idxs(&[1,3]),true)]
    #[case(7,2,&roles_from_idxs(&[5,6]),true)]
    fn test_vss_dropping_from_start(
        #[case] num_parties: usize,
        #[case] threshold: usize,
        #[case] malicious_roles: &[Role],
        #[case] should_be_detected: bool,
    ) {
        let dropping_vss_from_start = DroppingVssFromStart::default();
        test_vss_strategies(
            num_parties,
            threshold,
            dropping_vss_from_start,
            malicious_roles,
            should_be_detected,
        );
    }

    ///Test for an adversary that sends malformed sharing in round 1 and does everything else honestly.
    ///If it lies to strictly more than t parties, we expect this party to get caught
    //Otherwise, we expect everything to happen normally - dispute will settle
    #[rstest]
    #[case(4,1,&roles_from_idxs(&[0]),&roles_from_idxs(&[3]),false)]
    #[case(4,1,&roles_from_idxs(&[1]),&roles_from_idxs(&[0]),false)]
    #[case(4,1,&roles_from_idxs(&[2]),&roles_from_idxs(&[1]),false)]
    #[case(4,1,&roles_from_idxs(&[3]),&roles_from_idxs(&[2]),false)]
    #[case(4,1,&roles_from_idxs(&[0]),&roles_from_idxs(&[3,1]),true)]
    #[case(4,1,&roles_from_idxs(&[1]),&roles_from_idxs(&[0,2]),true)]
    #[case(4,1,&roles_from_idxs(&[2]),&roles_from_idxs(&[3,0]),true)]
    #[case(4,1,&roles_from_idxs(&[3]),&roles_from_idxs(&[2,1]),true)]
    #[case(7,2,&roles_from_idxs(&[0,2]),&roles_from_idxs(&[3,1]),false)]
    #[case(7,2,&roles_from_idxs(&[1,3]),&roles_from_idxs(&[4,2,0]),true)]
    #[case(7,2,&roles_from_idxs(&[5,6]),&roles_from_idxs(&[3,1,0,2]),true)]
    fn test_vss_malicious_r1(
        #[case] num_parties: usize,
        #[case] threshold: usize,
        #[case] malicious_roles: &[Role],
        #[case] roles_to_lie_to: &[Role],
        #[case] should_be_detected: bool,
    ) {
        let malicious_vss_r1 = MaliciousVssR1 {
            roles_to_lie_to: roles_to_lie_to.to_vec(),
        };

        test_vss_strategies(
            num_parties,
            threshold,
            malicious_vss_r1,
            malicious_roles,
            should_be_detected,
        );
    }

    //Test for an adversary that drops out after Round1
    //We expect that adversarial parties will see their vss default to 0, all others VSS will recover
    #[rstest]
    #[case(4,1,&roles_from_idxs(&[0]),true)]
    #[case(4,1,&roles_from_idxs(&[1]),true)]
    #[case(4,1,&roles_from_idxs(&[2]),true)]
    #[case(4,1,&roles_from_idxs(&[2]),true)]
    #[case(7,2,&roles_from_idxs(&[0,2]),true)]
    #[case(7,2,&roles_from_idxs(&[1,3]),true)]
    #[case(7,2,&roles_from_idxs(&[5,6]),true)]
    fn test_vss_dropout_after_r1(
        #[case] num_parties: usize,
        #[case] threshold: usize,
        #[case] malicious_roles: &[Role],
        #[case] should_be_detected: bool,
    ) {
        let dropping_vss_after_r1 = DroppingVssAfterR1::default();
        test_vss_strategies(
            num_parties,
            threshold,
            dropping_vss_after_r1,
            malicious_roles,
            should_be_detected,
        );
    }

    //Test for an adversary that drops out after Round2
    //We expect all goes fine as if honest round2, there's no further communication
    #[rstest]
    #[case(4,1,&roles_from_idxs(&[0]),false)]
    #[case(4,1,&roles_from_idxs(&[1]),false)]
    #[case(4,1,&roles_from_idxs(&[2]),false)]
    #[case(4,1,&roles_from_idxs(&[2]),false)]
    #[case(7,2,&roles_from_idxs(&[0,2]),false)]
    #[case(7,2,&roles_from_idxs(&[1,3]),false)]
    #[case(7,2,&roles_from_idxs(&[5,6]),false)]
    fn test_dropout_r3(
        #[case] num_parties: usize,
        #[case] threshold: usize,
        #[case] malicious_roles: &[Role],
        #[case] should_be_detected: bool,
    ) {
        let dropping_vss_after_r2 = DroppingVssAfterR2::default();
        test_vss_strategies(
            num_parties,
            threshold,
            dropping_vss_after_r2,
            malicious_roles,
            should_be_detected,
        );
    }
}

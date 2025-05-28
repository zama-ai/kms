use async_trait::async_trait;
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use tokio::{task::JoinSet, time::error::Elapsed};
use tracing::instrument;

use crate::execution::communication::broadcast::{Broadcast, SyncReliableBroadcast};
use crate::{
    algebra::{
        bivariate::{BivariateEval, BivariatePoly},
        poly::Poly,
        structure_traits::{Ring, RingEmbed},
    },
    error::error_handler::anyhow_error_and_log,
    execution::{
        communication::p2p::{generic_receive_from_all, send_to_parties},
        runtime::{party::Role, session::BaseSessionHandles},
    },
    networking::value::{BroadcastValue, NetworkValue},
};

/// Secure implementation of VSS as defined in NIST document
///
/// In particular, relies on the secure version of
/// the broadcast protocol defined in [`SyncReliableBroadcast`]
pub type SecureVss = RealVss<SyncReliableBroadcast>;

#[async_trait]
pub trait Vss: Send + Sync + Clone {
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
    async fn execute<Z: Ring + RingEmbed, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
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
    async fn execute_many<Z: Ring + RingEmbed, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        session: &mut S,
        secrets: &[Z],
    ) -> anyhow::Result<Vec<Vec<Z>>>;
}

type Challenge<Z> = Vec<Vec<Z>>; // There will be num_secrets challenge for every party
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
struct DoublePoly<Z>
where
    Poly<Z>: Eq,
{
    share_in_x: Poly<Z>,
    share_in_y: Poly<Z>,
}

/// Struct to hold data sent during round 1 of VSS, composed of
/// - double_poly is my share in a single VSS instance
/// - we need n challenges sent and n challenges received (one from every party)
#[derive(Serialize, Deserialize, PartialEq, Clone, Hash, Debug)]
pub struct ExchangedDataRound1<Z>
where
    Poly<Z>: Eq,
{
    double_poly: Vec<DoublePoly<Z>>,
    challenge: Challenge<Z>,
}

impl<Z: Ring> ExchangedDataRound1<Z> {
    pub fn default(num_parties: usize, num_secrets: usize) -> Self {
        Self {
            double_poly: vec![
                DoublePoly::<Z> {
                    share_in_x: Poly::default(),
                    share_in_y: Poly::default(),
                };
                num_secrets
            ],
            challenge: (0..num_parties)
                .map(|_| vec![Z::default(); num_secrets])
                .collect_vec(),
        }
    }
}

///This data structure is indexed by [party_idx, idx_vss]
#[derive(Clone, Debug)]
pub struct Round1VSSOutput<Z: Ring> {
    sent_challenges: Vec<Challenge<Z>>,
    received_vss: Vec<ExchangedDataRound1<Z>>,
    my_poly: Vec<BivariatePoly<Z>>,
}

///Simply send the trivial sharing P: X -> secret (P constant polynomial)
///i.e. the secret is the share for everyone
#[derive(Default, Clone)]
pub struct DummyVss {}

#[async_trait]
impl Vss for DummyVss {
    async fn execute_many<Z: Ring + RingEmbed, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        session: &mut S,
        secrets: &[Z],
    ) -> anyhow::Result<Vec<Vec<Z>>> {
        let own_role = session.my_role()?;
        let num_parties = session.num_parties();

        // send all secrets to all parties
        let values_to_send: HashMap<Role, NetworkValue<Z>> = session
            .role_assignments()
            .keys()
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
        })?;

        // index 0: num_parties, index 1: number of shares
        let mut res = vec![vec![Z::ZERO; secrets.len()]; num_parties];
        res[own_role.zero_based()] = secrets.to_vec();
        while let Some(v) = jobs.join_next().await {
            let joined_result = v?;
            match joined_result {
                Ok((party_id, Ok(data))) => {
                    res[party_id.zero_based()] = data;
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

//TODO: Once ready, add SyncBroadcast via generic and trait bounds
#[derive(Default, Clone)]
pub struct RealVss<BCast: Broadcast> {
    broadcast: BCast,
}

#[async_trait]
impl<BCast: Broadcast> Vss for RealVss<BCast> {
    #[instrument(name="VSS", skip(self,session, secrets),fields(sid = ?session.session_id(),own_identity = ?session.own_identity()), batch_size= ?secrets.len())]
    async fn execute_many<Z: Ring + RingEmbed, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
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

type MapRoleDoublePoly<Z> = HashMap<Role, Vec<DoublePoly<Z>>>;

fn sample_secret_polys<Z: Ring + RingEmbed, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
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
        .role_assignments()
        .keys()
        .map(|r| {
            let embedded_role = Z::embed_exceptional_set(r.one_based())?;
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

async fn round_1<Z: Ring, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
    session: &mut S,
    num_secrets: usize,
    bivariate_poly: Vec<BivariatePoly<Z>>,
    map_double_shares: MapRoleDoublePoly<Z>,
) -> anyhow::Result<Round1VSSOutput<Z>> {
    let my_role = session.my_role()?;
    let num_parties = session.num_parties();

    let mut received_data: Vec<ExchangedDataRound1<Z>> =
        vec![ExchangedDataRound1::default(num_parties, num_secrets); num_parties];
    received_data[my_role.zero_based()]
        .double_poly
        .clone_from(&map_double_shares[&my_role]);

    //For every party, create challenges for every VSS
    let challenges: Vec<Challenge<Z>> = (0..num_parties)
        .map(|_| {
            (0..num_parties)
                .map(|_| (0..num_secrets).map(|_| Z::sample(session.rng())).collect())
                .collect::<Challenge<Z>>()
        })
        .collect();

    //Sending data
    let msgs_to_send = map_double_shares
        .iter()
        .map(|(role, poly)| {
            //We send to Pj its share of our secrets
            //and our challenges for each senders for each secrets
            (
                *role,
                NetworkValue::Round1VSS(ExchangedDataRound1 {
                    double_poly: poly.clone(),
                    challenge: challenges[role.zero_based()].clone(),
                }),
            )
        })
        .collect();

    send_to_parties(&msgs_to_send, session).await?;

    let mut jobs = JoinSet::<ResultRound1<Z>>::new();
    // Receive data
    vss_receive_round_1(session, &mut jobs, my_role)?;

    while let Some(v) = jobs.join_next().await {
        let joined_result = v?;
        match joined_result {
            Ok((party_id, Ok(data))) => {
                // Do nothing if something goes wrong
                // since received_data is initialized with default,
                // which has the correct lengths.
                // Consequently, the input to round 2 should never have incorrect lengths.
                if data.challenge.len() != num_parties {
                    tracing::error!(
                        "challenge length error, expected {} but got {}",
                        num_parties,
                        data.challenge.len()
                    );
                } else if data.challenge[0].len() != data.double_poly.len() {
                    tracing::error!(
                        "challenge length does not match double_poly, expected {} but got {}",
                        data.double_poly.len(),
                        data.challenge[0].len()
                    );
                } else if data.double_poly.len() != num_secrets {
                    tracing::error!(
                        "wrong number of secrets, expected {} but got {}",
                        num_secrets,
                        data.double_poly.len()
                    );
                } else {
                    received_data[party_id.zero_based()] = data;
                }
            }
            //NOTE: received_data was init with default 0 values,
            //so no need to do anything when p2p fails
            Err(e) => {
                tracing::error!("Error in VSS round 1 {:?}", e);
            }
            Ok((party_id, Err(e))) => {
                tracing::error!(
                    "Error in VSS round 1, when receiving from party {}: {:?}",
                    party_id,
                    e
                );
            }
        }
    }

    Ok(Round1VSSOutput {
        sent_challenges: challenges,
        received_vss: received_data,
        my_poly: bivariate_poly,
    })
}

async fn round_2<
    Z: Ring + RingEmbed,
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    BCast: Broadcast,
>(
    session: &mut S,
    num_secrets: usize,
    vss: &Round1VSSOutput<Z>,
    broadcast: &BCast,
) -> anyhow::Result<HashMap<Role, Option<Vec<VerificationValues<Z>>>>> {
    let my_role = session.my_role()?;
    let num_parties = session.num_parties();

    //For every VSS, compute
    // aij = F_i(\alpha_j) + r_ij
    // bij = G_i(\alpha_j) + r_ji
    //NOTE: aii and bii are not computed, input default there
    let verification_vector: Vec<VerificationValues<Z>> = (0..num_parties)
        .map(|dealer_idx| {
            (0..num_parties)
                .map(|party_idx| {
                    let verification_values = generate_verification_value(
                        num_secrets,
                        my_role.zero_based(),
                        party_idx,
                        dealer_idx,
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

    //Do we want to use a filter map instead of a map to Option?
    let mut casted_bcast_data: HashMap<Role, Option<Vec<VerificationValues<Z>>>> = bcast_data
        .into_iter()
        .map(|(role, vv)| match vv {
            BroadcastValue::Round2VSS(v) => (role, Some(v)),
            _ => {
                tracing::warn!("Broadcast from {role} is of unexpected type");
                (role, None)
            }
        })
        .collect();

    //Also make sure we don't bother with corrupted parties
    for corrupted_role in session.corrupt_roles().iter() {
        casted_bcast_data.insert(*corrupted_role, None);
    }

    Ok(casted_bcast_data)
}

//NOTE: Verification_map is Map<Role, Option<Vec<Vec<(ResiduePol,ResiduePol)>>>> st
// Role0 -> Some(v) with v indexed as v[dealer_idx][Pj index][secret_idx]
// Role1 -> None means somethings wrong happened, consider all values to be 0
//...
async fn round_3<
    Z: Ring + RingEmbed,
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    BCast: Broadcast,
>(
    session: &mut S,
    num_secrets: usize,
    vss: &Round1VSSOutput<Z>,
    verification_map: &HashMap<Role, Option<Vec<VerificationValues<Z>>>>,
    broadcast: &BCast,
) -> anyhow::Result<Vec<HashSet<Role>>> {
    let num_parties = session.num_parties();
    let own_role = session.my_role()?;

    //First create a HashSet<usize, role, role> that references all the conflicts
    //the usize represents the dealer idx of the conflict.
    //Remember: If there's a conflict for any secret_idx, we consider there's a conflict for the whole batch
    let potentially_unhappy = find_potential_conflicts_for_all_roles(verification_map, num_parties);

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
    let unhappy_vec = find_real_conflicts(
        num_secrets,
        &potentially_unhappy,
        bcast_settlements,
        num_parties,
    );

    tracing::info!("I am {own_role} and def. unhappy with {:?}", unhappy_vec);

    //Find out if any dealer is corrupt
    for (dealer_idx, unhappy_set) in unhappy_vec.iter().enumerate() {
        if unhappy_set.len() > session.threshold() as usize {
            session.add_corrupt(Role::indexed_by_zero(dealer_idx))?;
        }
    }

    Ok(unhappy_vec)
}

async fn round_4<
    Z: Ring + RingEmbed,
    R: Rng + CryptoRng,
    S: BaseSessionHandles<R>,
    BCast: Broadcast,
>(
    session: &mut S,
    num_secrets: usize,
    vss: &Round1VSSOutput<Z>,
    unhappy_vec: Vec<HashSet<Role>>,
    broadcast: &BCast,
) -> anyhow::Result<Vec<Vec<Z>>> {
    let mut msg = BTreeMap::<(u64, Role), ValueOrPoly<Z>>::new();
    let own_role = session.my_role()?;

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
                    .contains(&Role::indexed_by_zero(*dealer_idx))
        })
        .try_for_each(|(dealer_idx, unhappy_set)| {
            let is_dealer = own_role.zero_based() == dealer_idx;
            round_4_conflict_resolution(&mut msg, is_dealer, dealer_idx, unhappy_set, vss)?;
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
            if !session
                .corrupt_roles()
                .contains(&Role::indexed_by_zero(dealer_idx))
            {
                round_4_fix_conflicts(session, num_secrets, dealer_idx, unhappy_set, &bcast_data)?;
            }
            Ok::<_, anyhow::Error>(())
        })?;

    //Remains to output trivial 0 for all senders in corrupt and correct share for all others
    //we use an auxiliary result variable to insert the result in order and not rely on the arbitrary order of keys()
    let num_parties = session.num_parties();
    let mut result: Vec<Vec<Z>> = vec![vec![Z::ZERO; num_secrets]; num_parties];
    session
        .role_assignments()
        .keys()
        .filter(|sender| !session.corrupt_roles().contains(sender))
        .for_each(|role_sender| {
            let dealer_idx = role_sender.zero_based();
            //If sender is not considered corrupt but had to send my share in round 4, use this value
            let maybe_eval = bcast_data
                .get(role_sender)
                .and_then(|bcast| match bcast {
                    BroadcastValue::Round4VSS(v) => Some(v),
                    _ => None,
                })
                .and_then(|v| v.get(&(dealer_idx as u64, own_role)))
                .and_then(|entry| {
                    if let ValueOrPoly::Poly(p) = entry {
                        Some(p)
                    } else {
                        None
                    }
                })
                .map(|p| p.iter().map(|pp| pp.eval(&Z::ZERO)).collect_vec());

            if let Some(p) = maybe_eval {
                result[dealer_idx] = p;
            //Else, use the value received in the first round
            } else {
                result[dealer_idx] = vss.received_vss[dealer_idx]
                    .double_poly
                    .iter()
                    .map(|poly| poly.share_in_x.eval(&Z::ZERO))
                    .collect_vec();
            }
        });
    Ok(result)
}

fn vss_receive_round_1<Z: Ring, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
    session: &S,
    jobs: &mut JoinSet<ResultRound1<Z>>,
    my_role: Role,
) -> anyhow::Result<()> {
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
    )?;
    Ok(())
}

/// Compute a_{i,j} and b_{i,j} for the num_secrets secrets shared by
/// Pk indexed by dealer_index, for Pj indexed by party_idx
fn generate_verification_value<Z>(
    num_secrets: usize,
    my_index: usize,
    party_idx: usize,
    dealer_idx: usize,
    r1vss: &Round1VSSOutput<Z>,
) -> anyhow::Result<Vec<(Z, Z)>>
where
    Z: Ring,
    Z: RingEmbed,
{
    //Sanity check all vectors are of correct length
    let current_vss = &r1vss.received_vss[dealer_idx];
    let dbl_poly_len = current_vss.double_poly.len();
    let len_ok = dbl_poly_len == r1vss.received_vss[party_idx].challenge[dealer_idx].len()
        && dbl_poly_len == num_secrets;
    if !len_ok {
        return Err(anyhow_error_and_log(
            "incorrect input length that should have been caught in roud 1".to_string(),
        ));
    }

    let mut out = Vec::with_capacity(num_secrets);
    let alpha_other = Z::embed_exceptional_set(party_idx + 1)?;
    let my_challenges_to_pj = &r1vss.sent_challenges[party_idx][dealer_idx];
    let pj_challenges_to_me = &r1vss.received_vss[party_idx].challenge[dealer_idx];
    for i in 0..num_secrets {
        let double_poly = &current_vss.double_poly[i];
        if my_index != party_idx {
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
            None => (0..num_parties).for_each(|dealer_idx| {
                verification_map.keys().for_each(|pj_role| {
                    if pj_role != pi_role {
                        potentially_unhappy.insert((dealer_idx, *pi_role, *pj_role));
                    }
                })
            }),
        });
    potentially_unhappy
}

fn find_potential_conflicts_received_challenges<Z: Ring>(
    verification_map: &HashMap<Role, Option<Vec<VerificationValues<Z>>>>,
    pi_role: &Role,
    challenge_vss: &[VerificationValues<Z>],
    potentially_unhappy: &mut HashSet<(usize, Role, Role)>,
) {
    challenge_vss
        .iter()
        .enumerate()
        .for_each(|(dealer_idx, challenge_single_vss)| {
            //For Pi at vss dealer_idx, iter over all the challenges a_ij
            //add potential conflict for the current vss
            //that is add Pi,Pj when a_ij neq bji
            challenge_single_vss
                .iter()
                .enumerate()
                .for_each(|(pj_index, aij)| {
                    let pj_role = Role::indexed_by_zero(pj_index);
                    //No need to compare with itself
                    if pi_role != &pj_role {
                        //Retrieve all the challenges of Pj and look bji for VSS dealer_idx,
                        match verification_map.get(&pj_role) {
                            //If there is any value for bji AND aij neq bji add the pair to potential unhappy
                            //for the whole batch dealt by dealer_idx
                            Some(Some(v)) => {
                                for (a, b) in v[dealer_idx][pi_role.zero_based()].iter().zip(aij) {
                                    if a.1 != b.0 {
                                        potentially_unhappy.insert((dealer_idx, *pi_role, pj_role));
                                        break;
                                    }
                                }
                            }
                            //If there is no value for bji, add the pair to potential unhappy
                            _ => {
                                potentially_unhappy.insert((dealer_idx, *pi_role, pj_role));
                            }
                        }
                    }
                })
        })
}

fn answer_to_potential_conflicts<Z>(
    potentially_unhappy: &HashSet<(usize, Role, Role)>,
    own_role: &Role,
    vss: &Round1VSSOutput<Z>,
) -> anyhow::Result<BTreeMap<(u64, Role, Role), Vec<Z>>>
where
    Z: Ring,
    Z: RingEmbed,
{
    let mut msg = BTreeMap::<(u64, Role, Role), Vec<Z>>::new();
    let my_dealer_idx = own_role.zero_based();
    //Can now match over the tuples of keys in potentially unhappy
    for key_tuple in potentially_unhappy.iter() {
        match key_tuple {
            //If vss_idx is the one where I'm sender send F(alpha_j, alpha_i)
            (dealer_idx, pi_role, pj_role) if dealer_idx == &my_dealer_idx => {
                let point_x = Z::embed_exceptional_set(pj_role.one_based())?;
                let point_y = Z::embed_exceptional_set(pi_role.one_based())?;
                msg.insert(
                    (*dealer_idx as u64, *pi_role, *pj_role),
                    vss.my_poly
                        .iter()
                        .map(|poly| poly.full_evaluation(point_x, point_y))
                        .collect::<Result<Vec<_>, _>>()?,
                );
            }
            //If im a Pi send Fi(alpha_j)
            (dealer_idx, pi_role, pj_role) if pi_role == own_role => {
                let point = Z::embed_exceptional_set(pj_role.one_based())?;
                msg.insert(
                    (*dealer_idx as u64, *pi_role, *pj_role),
                    vss.received_vss[*dealer_idx]
                        .double_poly
                        .iter()
                        .map(|poly| poly.share_in_x.eval(&point))
                        .collect(),
                );
            }
            //If im a Pj send Gj(alpha_i)
            (dealer_idx, pi_role, pj_role) if pj_role == own_role => {
                let point = Z::embed_exceptional_set(pi_role.one_based())?;
                msg.insert(
                    (*dealer_idx as u64, *pi_role, *pj_role),
                    vss.received_vss[*dealer_idx]
                        .double_poly
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

fn find_real_conflicts<Z: Ring>(
    num_secrets: usize,
    potentially_unhappy: &HashSet<(usize, Role, Role)>,
    bcast_settlements: HashMap<Role, BroadcastValue<Z>>,
    num_parties: usize,
) -> Vec<HashSet<Role>> {
    //Loop through potential unhappy, retrieve the corresponding three dispute settlement values and decide who to add in the unhappy set
    let mut unhappy_vec = vec![HashSet::<Role>::new(); num_parties];
    let zeros = vec![Z::ZERO; num_secrets];
    for (dealer_idx, role_pi, role_pj) in potentially_unhappy {
        let common_key = (*dealer_idx as u64, *role_pi, *role_pj);
        let sender_resolve = bcast_settlements
            .get(&Role::indexed_by_zero(*dealer_idx))
            .and_then(|bcd| match bcd {
                BroadcastValue::Round3VSS(v) => Some(v),
                _ => None,
            })
            .and_then(|v| v.get(&common_key))
            .unwrap_or(&zeros);

        let pi_resolve = bcast_settlements
            .get(role_pi)
            .and_then(|bcd| match bcd {
                BroadcastValue::Round3VSS(v) => Some(v),
                _ => None,
            })
            .and_then(|v| v.get(&common_key))
            .unwrap_or(&zeros);

        let pj_resolve = bcast_settlements
            .get(role_pj)
            .and_then(|bcd| match bcd {
                BroadcastValue::Round3VSS(v) => Some(v),
                _ => None,
            })
            .and_then(|v| v.get(&common_key))
            .unwrap_or(&zeros);

        if pi_resolve != sender_resolve {
            unhappy_vec[*dealer_idx].insert(*role_pi);
        }

        if pj_resolve != sender_resolve {
            unhappy_vec[*dealer_idx].insert(*role_pj);
        }
    }
    unhappy_vec
}

fn round_4_conflict_resolution<Z: Ring + RingEmbed>(
    msg: &mut BTreeMap<(u64, Role), ValueOrPoly<Z>>,
    is_dealer: bool,
    dealer_idx: usize,
    unhappy_set: &HashSet<Role>,
    vss: &Round1VSSOutput<Z>,
) -> anyhow::Result<()> {
    for role_pi in unhappy_set.iter() {
        let point_pi = Z::embed_exceptional_set(role_pi.one_based())?;
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
                vss.received_vss[dealer_idx]
                    .double_poly
                    .iter()
                    .map(|poly| poly.share_in_y.eval(&point_pi))
                    .collect_vec(),
            ),
        };
        msg.insert((dealer_idx as u64, *role_pi), msg_entry);
    }
    Ok(())
}

fn round_4_fix_conflicts<Z: Ring + RingEmbed, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
    session: &mut S,
    num_secrets: usize,
    dealer_idx: usize,
    unhappy_set: &HashSet<Role>,
    bcast_data: &HashMap<Role, BroadcastValue<Z>>,
) -> anyhow::Result<()> {
    let dealer_role = Role::indexed_by_zero(dealer_idx);
    let threshold = session.threshold() as usize;

    for role_pi in unhappy_set.iter() {
        //Retrieve what parties that are not the dealer and are happy have to say for the conflict with Pi
        let non_dealer_happy_values: HashMap<Role, Vec<Z>> = session
            .role_assignments()
            .keys()
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
                        .and_then(|v| v.get(&(dealer_idx as u64, *role_pi)))
                        .and_then(|v| match v {
                            ValueOrPoly::Value(vv) => Some((*role_pj, vv.clone())),
                            _ => None,
                        });
                    //Outputs the value sent or zero if nothing was sent
                    maybe_pair.map_or_else(|| Some((*role_pj, vec![Z::ZERO; num_secrets])), Some)
                }
            })
            .collect();

        if non_dealer_happy_values.len() >= 2 * threshold {
            //Retrieve sender's data from bcast related to Pi for this vss
            let maybe_poly = bcast_data
                .get(&dealer_role)
                .and_then(|bcd| match bcd {
                    BroadcastValue::Round4VSS(v) => Some(v),
                    _ => None,
                })
                .and_then(|v| v.get(&(dealer_idx as u64, *role_pi)))
                .and_then(|p| match p {
                    ValueOrPoly::Poly(p) => Some(p),
                    _ => None,
                });

            let sender_poly =
                maybe_poly.map_or_else(|| vec![Poly::zero(); num_secrets], |p| p.clone());
            let mut votes_against_dealer = 0_usize;
            for (role_pj, value_pj) in non_dealer_happy_values {
                //If length of either is not as expected, vote against the dealer
                if sender_poly.len() != num_secrets || value_pj.len() != num_secrets {
                    votes_against_dealer += 1;
                    continue;
                }
                let point_pj = Z::embed_exceptional_set(role_pj.one_based())?;
                // if there is at least one failure, vote against the sender
                for (a, b) in sender_poly.iter().map(|p| p.eval(&point_pj)).zip(value_pj) {
                    if a != b {
                        votes_against_dealer += 1;
                        break;
                    }
                }
            }

            //If at least 2*threshold parties have voted against dealer, it is corrupt
            if votes_against_dealer >= 2 * threshold {
                session.add_corrupt(dealer_role)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::algebra::bivariate::{BivariateEval, BivariatePoly};
    use crate::algebra::galois_rings::degree_4::{
        ResiduePolyF4, ResiduePolyF4Z128, ResiduePolyF4Z64,
    };
    use crate::algebra::structure_traits::{ErrorCorrect, Invert};
    use crate::execution::runtime::session::SmallSession;
    use crate::execution::sharing::shamir::{RevealOp, ShamirSharings};
    use crate::execution::sharing::share::Share;
    use crate::execution::small_execution::prf::PRSSConversions;
    use crate::execution::{
        runtime::party::Identity, runtime::test_runtime::DistributedTestRuntime,
    };
    use crate::execution::{
        runtime::party::Role,
        runtime::session::{BaseSessionHandles, LargeSession, ParameterHandles},
    };
    use crate::networking::NetworkMode;
    use crate::session_id::SessionId;
    #[cfg(feature = "slow_tests")]
    use crate::tests::helper::tests::roles_from_idxs;
    use crate::tests::helper::tests::{
        execute_protocol_large_w_disputes_and_malicious, TestingParameters,
    };
    use crate::tests::helper::tests_and_benches::execute_protocol_small;
    use aes_prng::AesRng;
    use rand::SeedableRng;
    use rstest::rstest;
    use std::num::Wrapping;
    use tokio::task::JoinSet;

    fn setup_parties_and_secret(
        num_parties: usize,
        num_secrets: usize,
    ) -> (Vec<Identity>, Vec<Vec<ResiduePolyF4Z128>>) {
        let identities: Vec<Identity> = (0..num_parties)
            .map(|party_nb| {
                let mut id_str = "localhost:500".to_owned();
                id_str.push_str(&party_nb.to_string());
                Identity(id_str)
            })
            .collect();

        let secret_f = |secret: usize| {
            (0..num_secrets)
                .map(|i| {
                    ResiduePolyF4Z128::from_scalar(Wrapping(((secret + 1) * i).try_into().unwrap()))
                })
                .collect_vec()
        };
        let secrets: Vec<Vec<ResiduePolyF4Z128>> = (0..num_parties).map(secret_f).collect();

        (identities, secrets)
    }

    //TODO: When we actually have malicious strategies implemented for broadcast,
    //test them in VSS
    impl<BCast: Broadcast> RealVss<BCast> {
        pub fn init(broadcast_strategy: &BCast) -> Self {
            Self {
                broadcast: broadcast_strategy.clone(),
            }
        }
    }

    #[test]
    fn test_dummy() {
        let num_secrets = 2;
        let (identities, secrets) = setup_parties_and_secret(4, num_secrets);

        // code for session setup
        let threshold = 1;
        // VSS assumes sync network
        let runtime = DistributedTestRuntime::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
        >::new(identities.clone(), threshold, NetworkMode::Sync, None);
        let session_id = SessionId::from(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();

        for (party_nb, _) in runtime.identities.iter().enumerate() {
            let mut session = runtime.large_session_for_party(session_id, party_nb);
            let s = secrets[party_nb].clone();
            set.spawn(async move {
                let dummy_vss = DummyVss::default();
                (
                    party_nb,
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
                .map(|(party_id, vec_shares_party)| {
                    (0..num_secrets)
                        .map(|i| {
                            Share::new(
                                Role::indexed_by_zero(*party_id),
                                vec_shares_party[vss_idx][i],
                            )
                        })
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
        let (identities, secrets) = setup_parties_and_secret(4, num_secrets);

        // code for session setup
        let threshold = 1;
        // VSS assumes sync network
        let runtime = DistributedTestRuntime::<
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
        >::new(identities.clone(), threshold, NetworkMode::Sync, None);
        let session_id = SessionId::from(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();

        for (party_nb, _) in runtime.identities.iter().enumerate() {
            let mut session = runtime.large_session_for_party(session_id, party_nb);
            let s = &secrets[party_nb];
            let (bivariate_poly, map_double_shares) = sample_secret_polys(&mut session, s).unwrap();
            set.spawn(async move {
                (
                    party_nb,
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
        for (party_nb, result) in results.clone().iter() {
            let x_0 = ResiduePolyF4::from_scalar(Wrapping(0));
            let y_0 = ResiduePolyF4::from_scalar(Wrapping(0));
            let expected_secret = &secrets[*party_nb];
            assert_eq!(
                &result
                    .my_poly
                    .iter()
                    .map(|p| p.full_evaluation(x_0, y_0).unwrap())
                    .collect_vec(),
                expected_secret,
            );
            //Check that received share come from bivariate pol
            for (pn, r) in results.clone().iter() {
                if pn != party_nb {
                    let embedded_pn = ResiduePolyF4Z128::embed_exceptional_set(pn + 1).unwrap();
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
                        r.received_vss[*party_nb]
                            .double_poly
                            .iter()
                            .map(|p| p.share_in_x.clone())
                            .collect_vec()
                    );

                    assert_eq!(
                        expected_result_y,
                        r.received_vss[*party_nb]
                            .double_poly
                            .iter()
                            .map(|p| p.share_in_y.clone())
                            .collect_vec()
                    );
                }
            }

            //Check that received share interpolate to secret
            let mut vec_x = Vec::with_capacity(4);
            let mut vec_y = Vec::with_capacity(4);
            for (pn, r) in results.clone().iter() {
                if pn != party_nb {
                    let point_pn = ResiduePolyF4Z128::embed_exceptional_set(0).unwrap();
                    vec_x.push(
                        (0..num_secrets)
                            .map(|i| {
                                Share::new(
                                    Role::indexed_by_zero(*pn),
                                    r.received_vss[*party_nb].double_poly[i]
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
                                    Role::indexed_by_zero(*pn),
                                    r.received_vss[*party_nb].double_poly[i]
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

    //We now define cheating strategies, each implement the VSS trait
    ///Does nothing, and output an empty Vec
    #[derive(Default, Clone)]
    pub(crate) struct DroppingVssFromStart {}

    ///Does round 1 and then drops
    #[derive(Default, Clone)]
    pub(crate) struct DroppingVssAfterR1 {}

    ///Does round 1 and 2 and then drops
    #[derive(Default, Clone)]
    pub(crate) struct DroppingVssAfterR2<BCast: Broadcast> {
        broadcast: BCast,
    }

    ///Participate in the protocol, but lies to some parties in the first round
    #[derive(Default, Clone)]
    pub(crate) struct MaliciousVssR1<BCast: Broadcast> {
        broadcast: BCast,
        roles_to_lie_to: Vec<Role>,
    }

    #[derive(Default, Clone)]
    pub(crate) struct WrongSecretLenVss<BCast: Broadcast> {
        broadcast: BCast,
    }

    #[async_trait]
    impl Vss for DroppingVssFromStart {
        //Do nothing, and output an empty Vec
        async fn execute_many<Z: Ring, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
            &self,
            _session: &mut S,
            _secrets: &[Z],
        ) -> anyhow::Result<Vec<Vec<Z>>> {
            Ok(Vec::new())
        }

        async fn execute<Z: Ring, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
            &self,
            _session: &mut S,
            _secret: &Z,
        ) -> anyhow::Result<Vec<Z>> {
            Ok(Vec::new())
        }
    }

    #[async_trait]
    impl Vss for DroppingVssAfterR1 {
        //Do round1, and output an empty Vec
        async fn execute_many<Z: Ring + RingEmbed, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
            &self,
            session: &mut S,
            secrets: &[Z],
        ) -> anyhow::Result<Vec<Vec<Z>>> {
            let (bivariate_poly, map_double_shares) = sample_secret_polys(session, secrets)?;
            let _ = round_1(session, secrets.len(), bivariate_poly, map_double_shares).await?;
            Ok(Vec::new())
        }

        async fn execute<Z: Ring + RingEmbed, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
            &self,
            session: &mut S,
            secret: &Z,
        ) -> anyhow::Result<Vec<Z>> {
            let _ = self.execute_many(session, &[*secret]).await?;
            Ok(Vec::new())
        }
    }

    impl<BCast: Broadcast> DroppingVssAfterR2<BCast> {
        pub fn init(broadcast_strategy: &BCast) -> Self {
            Self {
                broadcast: broadcast_strategy.clone(),
            }
        }
    }

    #[async_trait]
    impl<BCast: Broadcast> Vss for DroppingVssAfterR2<BCast> {
        //Do round1 and round2, and output an empty Vec
        async fn execute_many<Z: Ring + RingEmbed, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
            &self,
            session: &mut S,
            secrets: &[Z],
        ) -> anyhow::Result<Vec<Vec<Z>>> {
            let (bivariate_poly, map_double_shares) = sample_secret_polys(session, secrets)?;
            let num_secrets = secrets.len();
            let vss = round_1(session, num_secrets, bivariate_poly, map_double_shares).await?;
            let _ = round_2(session, num_secrets, &vss, &self.broadcast).await?;
            Ok(Vec::new())
        }

        async fn execute<Z: Ring + RingEmbed, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
            &self,
            session: &mut S,
            secret: &Z,
        ) -> anyhow::Result<Vec<Z>> {
            let _ = self.execute_many(session, &[*secret]).await?;
            Ok(Vec::new())
        }
    }

    impl<BCast: Broadcast> MaliciousVssR1<BCast> {
        pub fn init(broadcast_strategy: &BCast, roles_from_zero: &[usize]) -> Self {
            Self {
                broadcast: broadcast_strategy.clone(),
                roles_to_lie_to: roles_from_zero
                    .iter()
                    .map(|id_role| Role::indexed_by_zero(*id_role))
                    .collect_vec(),
            }
        }
    }

    #[async_trait]
    impl<BCast: Broadcast> Vss for MaliciousVssR1<BCast> {
        async fn execute_many<Z: Ring + RingEmbed, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
            &self,
            session: &mut S,
            secrets: &[Z],
        ) -> anyhow::Result<Vec<Vec<Z>>> {
            //Execute a malicious round 1
            let num_secrets = secrets.len();
            let vss = malicious_round_1(session, secrets, &self.roles_to_lie_to).await?;
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

    //This code executes a round1 where the party sends malformed double shares for its VSS to parties in roles_to_lie_to
    async fn malicious_round_1<
        Z: Ring + RingEmbed,
        R: Rng + CryptoRng,
        S: BaseSessionHandles<R>,
    >(
        session: &mut S,
        secrets: &[Z],
        roles_to_lie_to: &[Role],
    ) -> anyhow::Result<Round1VSSOutput<Z>> {
        let num_secrets = secrets.len();
        let mut rng = AesRng::seed_from_u64(0);
        let bivariate_poly = secrets
            .iter()
            .map(|secret| {
                BivariatePoly::from_secret(&mut rng, *secret, session.threshold() as usize).unwrap()
            })
            .collect_vec();
        let map_double_shares: MapRoleDoublePoly<Z> = session
            .role_assignments()
            .keys()
            .map(|r| {
                let embedded_role = Z::embed_exceptional_set(r.one_based()).unwrap();
                let correct_bpolys = (0..num_secrets)
                    .map(|i| DoublePoly {
                        share_in_x: bivariate_poly[i]
                            .partial_y_evaluation(embedded_role)
                            .unwrap(),
                        share_in_y: bivariate_poly[i]
                            .partial_x_evaluation(embedded_role)
                            .unwrap(),
                    })
                    .collect_vec();
                if roles_to_lie_to.contains(r) {
                    // we only lie for one of the polynomials, the first one
                    let mut wrong_bpolys = correct_bpolys.clone();
                    wrong_bpolys[0] = DoublePoly {
                        share_in_x: Poly::<Z>::sample_random_with_fixed_constant(
                            &mut rng,
                            Z::ONE,
                            session.threshold().into(),
                        ),
                        share_in_y: Poly::<Z>::sample_random_with_fixed_constant(
                            &mut rng,
                            Z::ZERO,
                            session.threshold().into(),
                        ),
                    };
                    (*r, wrong_bpolys)
                } else {
                    (*r, correct_bpolys)
                }
            })
            .collect();
        round_1(session, num_secrets, bivariate_poly, map_double_shares).await
    }

    fn test_vss_small<Z: ErrorCorrect + Invert + PRSSConversions, const EXTENSION_DEGREE: usize>(
        params: TestingParameters,
        num_secrets: usize,
    ) {
        let mut task_honest = |mut session: SmallSession<Z>, _bot: Option<String>| async move {
            let real_vss = SecureVss::default();
            let secrets = (0..num_secrets)
                .map(|_| Z::sample(session.rng()))
                .collect_vec();
            (
                session.my_role().unwrap().zero_based(),
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
        );
        let mut expected_secrets = vec![vec![Z::ZERO; num_secrets]; params.num_parties];
        for (party_idx, _, s, _) in res.iter() {
            expected_secrets[*party_idx].clone_from(s);
        }

        for i in 0..num_secrets {
            for vss_idx in 0..params.num_parties {
                let vec_shares = res
                    .iter()
                    .map(|(party_id, vec_shares, _, _)| {
                        Share::new(Role::indexed_by_zero(*party_id), vec_shares[vss_idx][i])
                    })
                    .collect_vec();
                let shamir_sharing = ShamirSharings::create(vec_shares);
                let reconstructed_secret = shamir_sharing.reconstruct(params.threshold);
                assert!(reconstructed_secret.is_ok());
                assert_eq!(expected_secrets[vss_idx][i], reconstructed_secret.unwrap());
            }
        }
    }

    #[async_trait]
    impl<BCast: Broadcast> Vss for WrongSecretLenVss<BCast> {
        // The adversary will halve the number of secrets
        async fn execute_many<Z: Ring + RingEmbed, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
            &self,
            session: &mut S,
            secrets: &[Z],
        ) -> anyhow::Result<Vec<Vec<Z>>> {
            assert!(secrets.len() > 1);
            let num_secrets = secrets.len() / 2;
            let (bivariate_poly, map_double_shares) =
                sample_secret_polys(session, &secrets[..num_secrets])?;
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

    #[rstest]
    #[case(TestingParameters::init_honest(4, 1, Some(5)), 1)]
    #[case(TestingParameters::init_honest(4, 1, Some(5)), 5)]
    #[case(TestingParameters::init_honest(7, 2, Some(6)), 5)]
    #[case(TestingParameters::init_honest(10, 3, Some(7)), 5)]
    fn test_vss_small_honest(#[case] params: TestingParameters, #[case] num_secrets: usize) {
        test_vss_small::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }>(
            params,
            num_secrets,
        )
    }

    fn test_vss_strategies_large<
        Z: Ring + RingEmbed + ErrorCorrect,
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
                session.my_role().unwrap().zero_based(),
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
            (session.my_role().unwrap().zero_based(), secrets)
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
            );

        //Assert malicious parties we shouldve been caught indeed are
        if params.should_be_detected {
            for (_, _, _, corrupt_set) in results_honest.iter() {
                for role in params.malicious_roles.iter() {
                    assert!(corrupt_set.contains(role));
                }
            }
        }

        //Create a vec of expected secrets
        let mut expected_secrets = vec![vec![Z::ZERO; num_secrets]; params.num_parties];
        for (party_idx, _, s, _) in results_honest.iter() {
            expected_secrets[*party_idx].clone_from(s);
        }

        if !params.should_be_detected {
            for result_malicious in results_malicious.iter() {
                assert!(result_malicious.is_ok());
                let (party_idx, s) = result_malicious.as_ref().unwrap();
                expected_secrets[*party_idx].clone_from(s);
            }
        }

        //Reconstruct secret from honest parties and check it's correct
        for i in 0..num_secrets {
            for vss_idx in 0..params.num_parties {
                let vec_shares = results_honest
                    .iter()
                    .map(|(party_id, vec_shares, _, _)| {
                        Share::new(Role::indexed_by_zero(*party_id), vec_shares[vss_idx][i])
                    })
                    .collect_vec();
                let shamir_sharing = ShamirSharings::create(vec_shares);
                let reconstructed_secret = shamir_sharing.reconstruct(params.threshold);
                assert!(reconstructed_secret.is_ok());
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
    fn test_vss_honest_z128(#[case] params: TestingParameters, #[case] num_secrets: usize) {
        let malicious_vss = SecureVss::default();
        test_vss_strategies_large::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            num_secrets,
            malicious_vss.clone(),
        );
        test_vss_strategies_large::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            num_secrets,
            malicious_vss.clone(),
        );
    }

    // Test the behaviour where the adversary does not send the correct number of secrets
    #[rstest]
    #[case(TestingParameters::init(4,1,&[0],&[],&[],true,None), 4)]
    #[case(TestingParameters::init(7,2,&[0,2],&[],&[],true,None), 4)]
    fn test_vss_wrong_secret_len<BCast: Broadcast + 'static>(
        #[case] params: TestingParameters,
        #[case] num_secrets: usize,
        #[values(SyncReliableBroadcast::default())] broadcast_strategy: BCast,
    ) {
        let wrong_secret_len_vss = WrongSecretLenVss {
            broadcast: broadcast_strategy,
        };
        test_vss_strategies_large::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            num_secrets,
            wrong_secret_len_vss.clone(),
        );
        test_vss_strategies_large::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            num_secrets,
            wrong_secret_len_vss.clone(),
        );
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
    fn test_vss_dropping_from_start(#[case] params: TestingParameters, #[case] num_secrets: usize) {
        let dropping_vss_from_start = DroppingVssFromStart::default();
        test_vss_strategies_large::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            num_secrets,
            dropping_vss_from_start.clone(),
        );
        test_vss_strategies_large::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            num_secrets,
            dropping_vss_from_start.clone(),
        );
    }

    ///Test for an adversary that sends malformed sharing in round 1 and does everything else honestly.
    ///If it lies to strictly more than t parties, we expect this party to get caught
    //Otherwise, we expect everything to happen normally - dispute will settle
    #[cfg(feature = "slow_tests")]
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
    fn test_vss_malicious_r1<BCast: Broadcast + 'static>(
        #[case] params: TestingParameters,
        #[case] num_secrets: usize,
        #[values(SyncReliableBroadcast::default())] broadcast_strategy: BCast,
    ) {
        let malicious_vss_r1 = MaliciousVssR1 {
            roles_to_lie_to: roles_from_idxs(&params.roles_to_lie_to),
            broadcast: broadcast_strategy,
        };
        test_vss_strategies_large::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            num_secrets,
            malicious_vss_r1.clone(),
        );
        test_vss_strategies_large::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            num_secrets,
            malicious_vss_r1.clone(),
        );
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
    fn test_vss_dropout_after_r1(#[case] params: TestingParameters, #[case] num_secrets: usize) {
        let dropping_vss_after_r1 = DroppingVssAfterR1::default();
        test_vss_strategies_large::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            num_secrets,
            dropping_vss_after_r1.clone(),
        );
        test_vss_strategies_large::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            num_secrets,
            dropping_vss_after_r1.clone(),
        );
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
    fn test_dropout_r3<BCast: Broadcast + 'static>(
        #[case] params: TestingParameters,
        #[case] num_secrets: usize,
        #[values(SyncReliableBroadcast::default())] broadcast_strategy: BCast,
    ) {
        let dropping_vss_after_r2 = DroppingVssAfterR2 {
            broadcast: broadcast_strategy,
        };
        test_vss_strategies_large::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _>(
            params.clone(),
            num_secrets,
            dropping_vss_after_r2.clone(),
        );
        test_vss_strategies_large::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }, _>(
            params.clone(),
            num_secrets,
            dropping_vss_after_r2.clone(),
        );
    }
}

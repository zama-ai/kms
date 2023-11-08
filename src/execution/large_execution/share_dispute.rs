use std::collections::HashMap;

use crate::{
    error::error_handler::anyhow_error_and_log,
    execution::{
        p2p::{exchange_values, receive_from_parties_w_dispute, send_to_parties_w_dispute},
        party::Role,
        session::{BaseSessionHandles, LargeSession, LargeSessionHandles},
    },
    poly::Poly,
    residue_poly::ResiduePoly,
    value::{NetworkValue, Value},
    One, Zero, Z128,
};
use async_trait::async_trait;
use itertools::Itertools;
use rand::RngCore;

#[allow(dead_code)]
pub enum ShareableInput {
    Ring(Z128),
    PolyRing(ResiduePoly<Z128>),
}
#[derive(Clone, Default)]
pub struct ShareDisputeOutput {
    pub all_shares: HashMap<Role, Vec<ResiduePoly<Z128>>>,
    pub shares_own_secret: HashMap<Role, Vec<ResiduePoly<Z128>>>,
}

#[derive(Clone, Default)]
pub struct ShareDisputeOutputDouble {
    pub output_t: ShareDisputeOutput,
    pub output_2t: ShareDisputeOutput,
}
//Not sure it makes sense to do a dummy implementation?
//what would it look like?
#[async_trait]
pub trait ShareDispute: Send + Default {
    /// Executes the ShareDispute protocol on a vector of secrets,
    /// expecting all parties to also share a vector of secrets of the same length.
    /// Returns:
    /// - a hashmap which maps roles to shares I received
    /// - another hashmap which maps roles to shares I sent
    async fn execute<R: RngCore, L: LargeSessionHandles<R>>(
        session: &mut L,
        secrets: &[ResiduePoly<Z128>],
    ) -> anyhow::Result<ShareDisputeOutput>;

    /// Executes the ShareDispute protocol on a vector of secrets,
    /// actually sharing the secret using a sharing of degree t and one of degree 2t
    /// Needed for doubleSharings
    async fn execute_double<R: RngCore, L: LargeSessionHandles<R>>(
        session: &mut L,
        secrets: &[ResiduePoly<Z128>],
    ) -> anyhow::Result<ShareDisputeOutputDouble>;
}

#[derive(Default)]
pub struct RealShareDispute {}

//Want to puncture only at Dispute\Corrupt ids
fn compute_puncture_idx<R: RngCore, L: LargeSessionHandles<R>>(
    session: &L,
) -> anyhow::Result<Vec<usize>> {
    Ok(session
        .disputed_roles()
        .get(&session.my_role()?)?
        .iter()
        .filter_map(|id| {
            if session.corrupt_roles().contains(id) {
                None
            } else {
                Some(id.one_based())
            }
        })
        .collect())
}

fn share_secrets<R: RngCore>(
    rng: &mut R,
    secrets: &[ResiduePoly<Z128>],
    punctured_idx: &[usize],
    num_parties: usize,
    degree: usize,
) -> anyhow::Result<Vec<Vec<ResiduePoly<Z128>>>> {
    secrets
        .iter()
        .map(|secret| {
            interpolate_poly_w_punctures(rng, num_parties, degree, punctured_idx.to_vec(), *secret)
        })
        .collect::<anyhow::Result<_>>()
}

//Fill in missing values with 0s
fn fill_incomplete_output<R: RngCore, L: LargeSessionHandles<R>>(
    session: &L,
    result: &mut HashMap<Role, Vec<ResiduePoly<Z128>>>,
    len: usize,
) {
    for role in session.role_assignments().keys() {
        if !result.contains_key(role) {
            result.insert(*role, vec![ResiduePoly::<Z128>::ZERO; len]);
        //Using unwrap here because the first clause makes sure the key is present!
        } else if result.get(role).unwrap().len() < len {
            let incomplete_vec = result.get_mut(role).unwrap();
            incomplete_vec.append(&mut vec![
                ResiduePoly::<Z128>::ZERO;
                len - incomplete_vec.len()
            ]);
        }
    }
}

#[async_trait]
impl ShareDispute for RealShareDispute {
    async fn execute_double<R: RngCore, L: LargeSessionHandles<R>>(
        session: &mut L,
        secrets: &[ResiduePoly<Z128>],
    ) -> anyhow::Result<ShareDisputeOutputDouble> {
        let num_parties = session.amount_of_parties();
        let degree_t = session.threshold() as usize;
        let degree_2t = 2 * degree_t;

        let dispute_ids = compute_puncture_idx(session)?;

        //Sample one random polynomial of correct degree per secret
        //and evaluate it at the parties' points
        let vec_polypoints_t: Vec<Vec<ResiduePoly<Z128>>> =
            share_secrets(session.rng(), secrets, &dispute_ids, num_parties, degree_t)?;
        let vec_polypoints_2t: Vec<Vec<ResiduePoly<Z128>>> =
            share_secrets(session.rng(), secrets, &dispute_ids, num_parties, degree_2t)?;

        //Map each parties' role with their pairs of shares (one share of deg t and one of deg 2t per secret)
        let mut polypoints_map: HashMap<Role, NetworkValue> = HashMap::new();
        for (polypoints_t, polypoints_2t) in vec_polypoints_t
            .into_iter()
            .zip(vec_polypoints_2t.into_iter())
        {
            for (role_id, (polypoint_t, polypoint_2t)) in polypoints_t
                .into_iter()
                .zip(polypoints_2t.into_iter())
                .enumerate()
            {
                let curr_role = Role::indexed_by_zero(role_id);
                match polypoints_map.get_mut(&curr_role) {
                    Some(NetworkValue::VecPairRingValue(v)) => {
                        v.push((Value::Poly128(polypoint_t), Value::Poly128(polypoint_2t)))
                    }
                    None => {
                        let mut new_party_vec = Vec::with_capacity(secrets.len());
                        new_party_vec
                            .push((Value::Poly128(polypoint_t), Value::Poly128(polypoint_2t)));
                        polypoints_map
                            .insert(curr_role, NetworkValue::VecPairRingValue(new_party_vec));
                    }
                    _ => {
                        return Err(anyhow_error_and_log(
                            "Unexpected type appeared in my own map".to_string(),
                        ));
                    }
                }
            }
        }

        session.network().increase_round_counter().await?;
        send_to_parties_w_dispute(&polypoints_map, session).await?;

        let sender_list = session.role_assignments().keys().cloned().collect_vec();
        let mut received_values = receive_from_parties_w_dispute(&sender_list, session).await?;
        //Insert shares for my own sharing
        received_values.insert(
            session.my_role()?,
            polypoints_map
                .get(&session.my_role()?)
                .ok_or_else(|| anyhow_error_and_log("Can not find my own share".to_string()))?
                .clone(),
        );

        //Recast polypoints_map to two hashmaps, one for t one for 2t
        let mut polypoints_map_t: HashMap<Role, Vec<ResiduePoly<Z128>>> =
            HashMap::<Role, Vec<ResiduePoly<Z128>>>::new();
        let mut polypoints_map_2t: HashMap<Role, Vec<ResiduePoly<Z128>>> =
            HashMap::<Role, Vec<ResiduePoly<Z128>>>::new();
        for (role, net_value) in polypoints_map.into_iter() {
            if let NetworkValue::VecPairRingValue(value) = net_value {
                let mut vec_residue_t: Vec<ResiduePoly<Z128>> =
                    Vec::<ResiduePoly<Z128>>::with_capacity(secrets.len());
                let mut vec_residue_2t: Vec<ResiduePoly<Z128>> =
                    Vec::<ResiduePoly<Z128>>::with_capacity(secrets.len());
                for v in value.into_iter() {
                    match v {
                        (Value::Poly128(v_t), Value::Poly128(v_2t)) => {
                            vec_residue_t.push(v_t);
                            vec_residue_2t.push(v_2t);
                        }
                        _ => {
                            return Err(anyhow_error_and_log(
                                "I had an incorrect type inside my own share sampling".to_string(),
                            ))
                        }
                    }
                }
                polypoints_map_t.insert(role, vec_residue_t);
                polypoints_map_2t.insert(role, vec_residue_2t);
            } else {
                return Err(anyhow_error_and_log(
                    "I had an incorrect type inside my own share sampling.".to_string(),
                ));
            }
        }

        //Returns my polypoints_map AND the points received from others
        let mut result_t: HashMap<Role, Vec<ResiduePoly<Z128>>> =
            HashMap::<Role, Vec<ResiduePoly<Z128>>>::new();
        let mut result_2t: HashMap<Role, Vec<ResiduePoly<Z128>>> =
            HashMap::<Role, Vec<ResiduePoly<Z128>>>::new();

        for (role, net_value) in received_values.into_iter() {
            if let NetworkValue::VecPairRingValue(value) = net_value {
                let mut vec_residue_t: Vec<ResiduePoly<Z128>> =
                    Vec::<ResiduePoly<Z128>>::with_capacity(secrets.len());
                let mut vec_residue_2t: Vec<ResiduePoly<Z128>> =
                    Vec::<ResiduePoly<Z128>>::with_capacity(secrets.len());
                for v in value.into_iter() {
                    match v {
                        (Value::Poly128(v_t), Value::Poly128(v_2t)) => {
                            vec_residue_t.push(v_t);
                            vec_residue_2t.push(v_2t);
                        }
                        _ => {
                            vec_residue_t.push(ResiduePoly::<Z128>::ZERO);
                            vec_residue_2t.push(ResiduePoly::<Z128>::ZERO);
                        }
                    }
                }
                result_t.insert(role, vec_residue_t);
                result_2t.insert(role, vec_residue_2t);
            } else {
                result_t.insert(role, vec![ResiduePoly::<Z128>::ZERO; secrets.len()]);
                result_2t.insert(role, vec![ResiduePoly::<Z128>::ZERO; secrets.len()]);
            }
        }

        //Fill in missing values with 0s
        fill_incomplete_output(session, &mut result_t, secrets.len());
        fill_incomplete_output(session, &mut result_2t, secrets.len());

        Ok(ShareDisputeOutputDouble {
            output_t: ShareDisputeOutput {
                all_shares: result_t,
                shares_own_secret: polypoints_map_t,
            },
            output_2t: ShareDisputeOutput {
                all_shares: result_2t,
                shares_own_secret: polypoints_map_2t,
            },
        })
    }

    async fn execute<R: RngCore, L: LargeSessionHandles<R>>(
        session: &mut L,
        secrets: &[ResiduePoly<Z128>],
    ) -> anyhow::Result<ShareDisputeOutput> {
        let num_parties = session.amount_of_parties();
        let degree = session.threshold() as usize;
        //If some party is corrupt I shouldn't sample a specific point for it
        //Even if it is in dispute with me
        let dispute_ids: Vec<usize> = compute_puncture_idx(session)?;

        //Sample one random polynomial of correct degree per secret
        //and evaluate it at the parties' points
        let vec_polypoints: Vec<Vec<ResiduePoly<Z128>>> =
            share_secrets(session.rng(), secrets, &dispute_ids, num_parties, degree)?;

        //Map each parties' role with their shares (one share per secret)
        let mut polypoints_map: HashMap<Role, NetworkValue> = HashMap::new();
        for polypoints in vec_polypoints.into_iter() {
            for (role_id, polypoint) in polypoints.into_iter().enumerate() {
                let curr_role = Role::indexed_by_zero(role_id);
                match polypoints_map.get_mut(&curr_role) {
                    Some(NetworkValue::VecRingValue(v)) => v.push(Value::Poly128(polypoint)),
                    None => {
                        let mut new_party_vec = Vec::with_capacity(secrets.len());
                        new_party_vec.push(Value::Poly128(polypoint));
                        polypoints_map.insert(curr_role, NetworkValue::VecRingValue(new_party_vec));
                    }
                    _ => {
                        return Err(anyhow_error_and_log(
                            "Unexpected type appeared in my own map".to_string(),
                        ));
                    }
                }
            }
        }
        session.network().increase_round_counter().await?;
        send_to_parties_w_dispute(&polypoints_map, session).await?;

        let sender_list = session.role_assignments().keys().cloned().collect_vec();
        let mut received_values = receive_from_parties_w_dispute(&sender_list, session).await?;

        //Insert shares for my own sharing
        received_values.insert(
            session.my_role()?,
            polypoints_map
                .get(&session.my_role()?)
                .ok_or_else(|| {
                    anyhow_error_and_log(format!(
                        "I am {} and can not find my own share",
                        session.my_role().unwrap()
                    ))
                })?
                .clone(),
        );

        //Recast polypoints_map to residuepoly instead of network value
        let polypoints_map: HashMap<Role, Vec<ResiduePoly<Z128>>> = polypoints_map
            .into_iter()
            .map(|(role, net_value)| {
                if let NetworkValue::VecRingValue(value) = net_value {
                    let vec_residue: Vec<ResiduePoly<Z128>> = value
                        .into_iter()
                        .map(|v| match v {
                            Value::Poly128(vv) => Ok(vv),
                            _ => Err(anyhow_error_and_log(
                                "I had an incorrect type inside my own share sampling".to_string(),
                            )),
                        })
                        .try_collect()?;
                    Ok((role, vec_residue))
                } else {
                    Err(anyhow_error_and_log(
                        "I had an incorrect type inside my own share sampling.".to_string(),
                    ))
                }
            })
            .try_collect()?;

        //Returns my polypoints_map AND the points received from others
        let mut result: HashMap<Role, Vec<ResiduePoly<Z128>>> = received_values
            .into_iter()
            .map(|(role, net_value)| {
                if let NetworkValue::VecRingValue(value) = net_value {
                    let vec_residue: Vec<ResiduePoly<Z128>> = value
                        .into_iter()
                        .map(|v| match v {
                            Value::Poly128(vv) => vv,
                            _ => ResiduePoly::<Z128>::ZERO,
                        })
                        .collect();
                    (role, vec_residue)
                } else {
                    (role, vec![ResiduePoly::<Z128>::ZERO; secrets.len()])
                }
            })
            .collect();

        //Fill in missing values with 0s
        fill_incomplete_output(session, &mut result, secrets.len());

        Ok(ShareDisputeOutput {
            all_shares: result,
            shares_own_secret: polypoints_map,
        })
    }
}

/// Secret shares a value `input` with the other parties while handling disputes.
/// That is, in case of malicious behaviour detected by a party they will be added to dispute
// TODO remove this dead code annotation once the code using shareDispute gets implemented
// NOTE: Not sure we will ever use it? (idem for p2p::exchange_values)
#[allow(dead_code)]
pub async fn share_w_dispute(
    num_parties: usize,
    degree: usize,
    input: ShareableInput,
    session: &mut LargeSession,
) -> anyhow::Result<HashMap<Role, ResiduePoly<Z128>>> {
    let secret_input = match input {
        ShareableInput::PolyRing(val) => val,
        ShareableInput::Ring(val) => ResiduePoly::from_scalar(val),
    };
    let polypoints = if session.my_disputes()?.is_empty() {
        // Happy case when there are no disputes
        // construct a random polynomial
        let poly = Poly::sample_random(session.rng(), secret_input, degree);
        // embed party IDs as invertable x-points on the polynomial
        let x_coords: Vec<_> = (0..=num_parties)
            .map(ResiduePoly::<Z128>::embed)
            .collect::<Result<Vec<_>, _>>()?;
        // evaluate the polynomial on the invertable party IDs
        (1..=num_parties).map(|p| poly.eval(&x_coords[p])).collect()
    } else {
        // Pessimistic case
        tracing::info!(
            "Doing secret sharing with {:?} parties being in dispute",
            session.my_disputes()?.len()
        );
        let dispute_ids = session
            .my_disputes()?
            .iter()
            .map(|id| id.one_based())
            .collect();

        interpolate_poly_w_punctures(
            session.rng(),
            num_parties,
            degree,
            dispute_ids,
            secret_input,
        )?
    };
    let polypoint_map: HashMap<Role, NetworkValue> = polypoints
        .iter()
        .enumerate()
        .map(|(i, p)| {
            (
                Role::indexed_by_zero(i),
                NetworkValue::RingValue(Value::Poly128(*p)),
            )
        })
        .collect();
    let exchanged_vals = exchange_values(
        &polypoint_map,
        NetworkValue::RingValue(Value::Poly128(ResiduePoly::ZERO)),
        session,
    )
    .await?;
    let mut res = HashMap::new();
    let mut disputed_parties = Vec::new();
    // Finally check that all network values
    for (cur_role, cur_value) in exchanged_vals {
        if let NetworkValue::RingValue(Value::Poly128(val)) = cur_value {
            res.insert(cur_role, val);
        } else {
            // We can assume no value from `cur_role` is already in `exchanged_vals` since we only launched one task for each party so we can insert without checking the result
            disputed_parties.push(cur_role);
            // And remove it from the result
            res.remove(&cur_role);
            // And insert the default value instead
            res.insert(cur_role, ResiduePoly::ZERO);
        }
    }
    session.add_dispute_and_bcast(&disputed_parties).await?;
    Ok(res)
}

/// Constructs a random polynomial given a set of `threshold` party IDs which should evaluate to 0 on the interpolated polynomial.
/// Returns all the `num_parties` y-values interpolated from the `dispute_party_ids` point embedded onto the x-axis.
pub fn interpolate_poly_w_punctures<R: RngCore>(
    rng: &mut R,
    num_parties: usize,
    threshold: usize,
    dispute_party_ids: Vec<usize>,
    secret: ResiduePoly<Z128>,
) -> anyhow::Result<Vec<ResiduePoly<Z128>>> {
    if threshold < dispute_party_ids.len() {
        return Err(anyhow_error_and_log(format!(
            "Too many disputes, {}, for threshold {}",
            dispute_party_ids.len(),
            threshold,
        )));
    }
    let degree = threshold - dispute_party_ids.len();
    // make a random polynomial of degree threshold `dispute_party_ids`
    let base_poly = Poly::sample_random(rng, secret, degree);
    // Modify the polynomial by increasing its degree with |dispute_party_ids| and ensuring the points
    // in `dispute_party_ids` gets y-value=0 and evaluate it for 1..num_parties
    let points = evaluate_w_zero_roots(num_parties, dispute_party_ids, &base_poly)?;
    // check that the zero point is `secret`
    debug_assert_eq!(secret, points[0]);
    // evaluate the poly at the party indices gamma
    // exclude the point at x=0
    Ok(points[1..points.len()].to_vec())
}

/// Helper method for punctured polynomial interpolation.
/// Takes a base polynomial and increases its degree by |points_of_zero_roots] by ensuring that each of the [points_of_zero_roots] gets embedded to x-points whose y-value is 0.
/// And then returns all the 0..[num_parties] points on the polynomial.
/// More specifically the values in [points_of_zero_roots] gets embedded on the polynomial to ensure they are invertable, then
/// the polynomial gets modified to ensure that each of the points in [points_of_zero_roots] will have y-value 0
/// by increasing its degres with |points_of_zero_roots|. Then the polynomial is evaluated in embedded points 0..[num_partes] and this is returned.
pub fn evaluate_w_zero_roots(
    num_parties: usize,
    points_of_zero_roots: Vec<usize>,
    base_poly: &Poly<ResiduePoly<Z128>>,
) -> anyhow::Result<Vec<ResiduePoly<Z128>>> {
    // compute lifted and inverted gamma values once, i.e. Lagrange coefficients
    let mut inv_coefs = (1..=num_parties)
        .map(ResiduePoly::<Z128>::lift_and_invert)
        .collect::<Result<Vec<_>, _>>()?;
    inv_coefs.insert(0, ResiduePoly::<Z128>::ZERO);

    // embed party IDs as invertable x-points on the polynomial
    let x_coords: Vec<_> = (0..=num_parties)
        .map(ResiduePoly::<Z128>::embed)
        .collect::<Result<Vec<_>, _>>()?;

    // compute additive inverse of embedded party IDs
    let neg_parties: Vec<_> = (0..=num_parties)
        .map(|p| Poly::from_coefs(vec![ResiduePoly::<Z128>::ZERO - x_coords[p]]))
        .collect::<Vec<_>>();

    // make a polynomial F(X)=X
    let x: Poly<ResiduePoly<std::num::Wrapping<u128>>> =
        Poly::from_coefs(vec![ResiduePoly::<Z128>::ZERO, ResiduePoly::<Z128>::ONE]);

    let mut poly = base_poly.clone();
    // poly will be of degree [threshold], zero at the points [x_coords], which reflect the party IDs embedded, and [secret] at 0
    for p in points_of_zero_roots {
        poly = poly * (x.clone() + neg_parties[p].clone()) * Poly::from_coefs(vec![inv_coefs[p]]);
    }
    // evaluate the poly at the embedded party indices
    let points: Vec<_> = (0..=num_parties).map(|p| poly.eval(&x_coords[p])).collect();
    Ok(points)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        num::Wrapping,
    };

    use itertools::Itertools;
    use rand::SeedableRng;
    use rand_chacha::{ChaCha12Rng, ChaCha20Rng};
    use tokio::task::JoinSet;
    use tracing_test::traced_test;

    use crate::{
        computation::SessionId,
        execution::{
            distributed::DistributedTestRuntime,
            large_execution::share_dispute::{
                interpolate_poly_w_punctures, RealShareDispute, ShareDispute, ShareDisputeOutput,
                ShareDisputeOutputDouble,
            },
            p2p::send_to_parties_w_dispute,
            party::{Identity, Role},
            session::{BaseSessionHandles, DisputeSet, LargeSession, ParameterHandles},
        },
        poly::Poly,
        residue_poly::ResiduePoly,
        shamir::ShamirGSharings,
        tests::helper::tests::{execute_protocol, generate_identities, get_large_session},
        value::{NetworkValue, Value},
        Zero, Z128,
    };

    use super::{evaluate_w_zero_roots, share_w_dispute, ShareableInput};

    #[test]
    fn optimistic_share() {
        let msg = Wrapping(42);
        let mut session = get_large_session();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        rt.block_on(async {
            let share = share_w_dispute(1, 0, ShareableInput::Ring(msg), &mut session).await;

            assert!(share.is_ok());
            // Since we only have one party we assume the result is just a constant which is exactly the message given as input
            let shared_val = *share.unwrap().get(&Role::indexed_by_one(1)).unwrap();
            assert_eq!(msg, shared_val.coefs[0]);
            shared_val.coefs[1..]
                .iter()
                .for_each(|c| assert_eq!(Z128::ZERO, *c))
        });
    }

    #[test]
    fn optimistic_share_multiple_parties() {
        let msg = Wrapping(42);
        let identities = generate_identities(4);
        let threshold = 1;

        let test_runtime = DistributedTestRuntime::new(identities.clone(), threshold);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();

        let mut set = JoinSet::new();
        for (party_no, _id) in identities.iter().cloned().enumerate() {
            let num_parties = identities.len();
            let own_role = Role::indexed_by_zero(party_no);
            let mut session = test_runtime
                .large_session_for_player(session_id, party_no)
                .unwrap();
            set.spawn(async move {
                session.rng = ChaCha20Rng::seed_from_u64(party_no as u64);
                (
                    own_role,
                    share_w_dispute(
                        num_parties,
                        threshold.into(),
                        ShareableInput::Ring(msg),
                        &mut session,
                    )
                    .await,
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

        assert_eq!(results.len(), identities.len());
        // Recover the shares shared by for each of the parties and validate that they reconstruct to the shared msg
        for received_from_role in 1..identities.len() {
            let mut poly_points = Vec::new();
            for (cur_role, cur_data) in &results {
                let shared_val = cur_data
                    .as_ref()
                    .unwrap()
                    .get(&Role::indexed_by_zero(received_from_role))
                    .unwrap();
                poly_points.push((cur_role.one_based(), *shared_val));
            }
            // Each party shares the same msg
            let sham = ShamirGSharings::<Z128> {
                shares: poly_points,
            };
            // Reconstruct the message and check it is as expected
            let res = Z128::try_from(sham.err_reconstruct(threshold as usize, 0).unwrap()).unwrap();
            assert_eq!(msg, res);
        }
    }

    #[test]
    fn test_sharing_with_dispute() {
        let msg = Wrapping(42);
        let identities = generate_identities(5);
        let threshold = 3;
        let mut dispute_roles = DisputeSet::new(identities.len());
        let dispute_party = Role::indexed_by_one(1);
        // Party 1 is in dispute
        for i in 1..=identities.len() {
            dispute_roles
                .add(&Role::indexed_by_one(i), &dispute_party)
                .unwrap();
        }

        let test_runtime = DistributedTestRuntime::new(identities.clone(), threshold);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let mut set = JoinSet::new();
        for (party_no, _id) in identities.iter().cloned().enumerate() {
            let num_parties = identities.len();
            let own_role = Role::indexed_by_zero(party_no);
            let mut session = test_runtime
                .large_session_for_player(session_id, party_no)
                .unwrap();
            let internal_dispute_roles = dispute_roles.clone();
            set.spawn(async move {
                session.rng = ChaCha20Rng::seed_from_u64(party_no as u64);
                let mut session = LargeSession {
                    parameters: session.parameters,
                    network: session.network,
                    rng: ChaCha20Rng::seed_from_u64(42),
                    corrupt_roles: HashSet::new(),
                    disputed_roles: internal_dispute_roles,
                };
                (
                    own_role,
                    share_w_dispute(
                        num_parties,
                        threshold.into(),
                        ShareableInput::Ring(msg),
                        &mut session,
                    )
                    .await,
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

        assert_eq!(results.len(), identities.len());
        // Recover the shares shared by for each of the parties and validate that they reconstruct to the shared msg
        for received_from_role in 1..identities.len() {
            let mut poly_points = Vec::new();
            for (executing_role, cur_data) in &results {
                if executing_role == &dispute_party {
                    // If `executing_role` is the dispute party then we should get an error because we don't want to talk to anyone
                    assert!(cur_data.is_err());
                } else {
                    // If we an honest party then check what we received
                    assert!(cur_data.is_ok());
                    // Unwrap the shares received
                    let shared_val = cur_data
                        .as_ref()
                        .unwrap()
                        .get(&Role::indexed_by_one(received_from_role))
                        .unwrap();
                    // Check the shares for all the honest parties with the disputed party (i.e. party 1) is 0
                    if received_from_role == dispute_party.one_based() {
                        assert_eq!(ResiduePoly::ZERO, *shared_val);
                    } else {
                        assert_ne!(ResiduePoly::ZERO, *shared_val);
                    }
                    poly_points.push((executing_role.one_based(), *shared_val));
                }
            }
            if received_from_role != dispute_party.one_based() {
                // Each honest party shared the same msg
                let sham = ShamirGSharings::<Z128> {
                    shares: poly_points,
                };
                // Reconstruct the message the honest party shared with the other honest parties
                let res =
                    Z128::try_from(sham.err_reconstruct(threshold as usize, 0).unwrap()).unwrap();
                assert_eq!(msg, res);
            }
        }
    }

    fn generate_ids_and_secrets(
        nb_party: usize,
    ) -> (Vec<Identity>, HashMap<Identity, Vec<ResiduePoly<Z128>>>) {
        let identities = generate_identities(nb_party);
        let secrets: HashMap<Identity, Vec<ResiduePoly<Z128>>> = identities
            .iter()
            .enumerate()
            .map(|(party_idx, party_id)| {
                (
                    party_id.clone(),
                    (0..=4)
                        .map(|v| {
                            ResiduePoly::<Z128>::from_scalar(Wrapping::<u128>(
                                (v + party_idx * 10).try_into().unwrap(),
                            ))
                        })
                        .collect(),
                )
            })
            .collect();
        (identities, secrets)
    }
    #[test]
    fn test_real_share_dispute() {
        let parties = 5;
        let threshold = 1;
        let (identities, secrets) = generate_ids_and_secrets(parties);

        async fn task(mut session: LargeSession) -> (Role, anyhow::Result<ShareDisputeOutput>) {
            let own_role = session.my_role().unwrap();
            let secret: Vec<ResiduePoly<Z128>> = (0..=4)
                .map(|v| {
                    ResiduePoly::<Z128>::from_scalar(Wrapping::<u128>(
                        (v + own_role.zero_based() * 10).try_into().unwrap(),
                    ))
                })
                .collect();
            (
                own_role,
                RealShareDispute::execute(&mut session, &secret).await,
            )
        }

        let results = execute_protocol(parties, threshold, &mut task);

        assert_eq!(results.len(), identities.len());
        //Can check that for each party the received value corresponds to the sent one
        let mut vec_of_vec_of_shares =
            vec![vec![vec![(usize::default(), ResiduePoly::<Z128>::ZERO); 5]; 5]; 5];
        for (role_pi, res_pi) in results.iter() {
            let res_pi = res_pi.as_ref().unwrap();
            let (rcv_res_pi, _sent_res_pi) = (&res_pi.all_shares, &res_pi.shares_own_secret);
            for (role_pj, data_vec) in rcv_res_pi.iter() {
                for (idx_data, data) in data_vec.iter().enumerate() {
                    vec_of_vec_of_shares[role_pj.zero_based()][idx_data][role_pi.zero_based()] =
                        (role_pi.one_based(), *data);
                }
            }
            for (role_pj, res_pj) in results.iter() {
                let res_pj = res_pj.as_ref().unwrap();
                let (_rcv_res_pj, sent_res_pj) = (&res_pj.all_shares, &res_pj.shares_own_secret);
                assert_eq!(
                    rcv_res_pi.get(role_pj).unwrap(),
                    sent_res_pj.get(role_pi).unwrap()
                );
            }
        }
        //Can also check that the secrets correctly reconstruct to the expected values
        for (idx_party, vec_of_shares) in vec_of_vec_of_shares.iter().enumerate() {
            for (idx_sharing, shares) in vec_of_shares.iter().enumerate() {
                let expected_secret = secrets.get(&identities[idx_party]).unwrap()[idx_sharing];
                let shamir_sharing = ShamirGSharings {
                    shares: shares.clone(),
                };
                assert_eq!(
                    shamir_sharing.reconstruct(threshold.into()).unwrap(),
                    expected_secret
                );
            }
        }
    }

    #[test]
    fn test_real_share_dispute_2t() {
        let parties = 5;
        let threshold = 1;
        let (identities, secrets) = generate_ids_and_secrets(parties);

        async fn task(
            mut session: LargeSession,
        ) -> (Role, anyhow::Result<ShareDisputeOutputDouble>) {
            let own_role = session.my_role().unwrap();
            let secret: Vec<ResiduePoly<Z128>> = (0..=4)
                .map(|v| {
                    ResiduePoly::<Z128>::from_scalar(Wrapping::<u128>(
                        (v + own_role.zero_based() * 10).try_into().unwrap(),
                    ))
                })
                .collect();
            (
                own_role,
                RealShareDispute::execute_double(&mut session, &secret).await,
            )
        }

        let results = execute_protocol(parties, threshold, &mut task);

        assert_eq!(results.len(), identities.len());
        //Can check that for each party the received value corresponds to the sent one in both sharings
        let mut vec_of_vec_of_shares_t =
            vec![vec![vec![(usize::default(), ResiduePoly::<Z128>::ZERO); 5]; 5]; 5];
        let mut vec_of_vec_of_shares_2t =
            vec![vec![vec![(usize::default(), ResiduePoly::<Z128>::ZERO); 5]; 5]; 5];
        for (role_pi, res_pi) in results.iter() {
            let res_pi = res_pi.as_ref().unwrap();
            let (res_pi_t, res_pi_2t) = (res_pi.output_t.clone(), res_pi.output_2t.clone());
            let (rcv_res_pi_t, _sent_res_pi_t) =
                (&res_pi_t.all_shares, &res_pi_t.shares_own_secret);
            let (rcv_res_pi_2t, _sent_res_pi_2t) =
                (&res_pi_2t.all_shares, &res_pi_2t.shares_own_secret);
            for (role_pj, data_vec) in rcv_res_pi_t.iter() {
                for (idx_data, data) in data_vec.iter().enumerate() {
                    vec_of_vec_of_shares_t[role_pj.zero_based()][idx_data][role_pi.zero_based()] =
                        (role_pi.one_based(), *data);
                }
            }
            for (role_pj, data_vec) in rcv_res_pi_2t.iter() {
                for (idx_data, data) in data_vec.iter().enumerate() {
                    vec_of_vec_of_shares_2t[role_pj.zero_based()][idx_data][role_pi.zero_based()] =
                        (role_pi.one_based(), *data);
                }
            }
            for (role_pj, res_pj) in results.iter() {
                let res_pj = res_pj.as_ref().unwrap();
                let (res_pj_t, res_pj_2t) = (res_pj.output_t.clone(), res_pj.output_2t.clone());
                let (_rcv_res_pj_t, sent_res_pj_t) =
                    (&res_pj_t.all_shares, &res_pj_t.shares_own_secret);
                let (_rcv_res_pj_2t, sent_res_pj_2t) =
                    (&res_pj_2t.all_shares, &res_pj_2t.shares_own_secret);
                assert_eq!(
                    rcv_res_pi_t.get(role_pj).unwrap(),
                    sent_res_pj_t.get(role_pi).unwrap()
                );

                assert_eq!(
                    rcv_res_pi_2t.get(role_pj).unwrap(),
                    sent_res_pj_2t.get(role_pi).unwrap()
                );
            }
        }
        //Can also check that the secrets correctly reconstruct to the expected values
        for (idx_party, vec_of_shares) in vec_of_vec_of_shares_t.iter().enumerate() {
            for (idx_sharing, shares) in vec_of_shares.iter().enumerate() {
                let expected_secret = secrets.get(&identities[idx_party]).unwrap()[idx_sharing];
                let shamir_sharing = ShamirGSharings {
                    shares: shares.clone(),
                };
                assert_eq!(
                    shamir_sharing.reconstruct(threshold.into()).unwrap(),
                    expected_secret
                );
            }
        }
        for (idx_party, vec_of_shares) in vec_of_vec_of_shares_2t.iter().enumerate() {
            for (idx_sharing, shares) in vec_of_shares.iter().enumerate() {
                let expected_secret = secrets.get(&identities[idx_party]).unwrap()[idx_sharing];
                let shamir_sharing = ShamirGSharings {
                    shares: shares.clone(),
                };
                assert_eq!(
                    shamir_sharing.reconstruct(2 * threshold as usize).unwrap(),
                    expected_secret
                );
            }
        }
    }

    //Test with one party no participating.
    #[test]
    fn test_real_share_dispute_dropout() {
        let parties = 5;
        let threshold = 1;
        let (identities, secrets) = generate_ids_and_secrets(parties);

        async fn task(mut session: LargeSession) -> (Role, anyhow::Result<ShareDisputeOutput>) {
            let own_role = session.my_role().unwrap();
            let secret: Vec<ResiduePoly<Z128>> = (0..=4)
                .map(|v| {
                    ResiduePoly::<Z128>::from_scalar(Wrapping::<u128>(
                        (v + own_role.zero_based() * 10).try_into().unwrap(),
                    ))
                })
                .collect();
            if own_role.zero_based() != 0 {
                (
                    own_role,
                    RealShareDispute::execute(&mut session, &secret).await,
                )
            } else {
                (own_role, Ok(ShareDisputeOutput::default()))
            }
        }

        let mut results = execute_protocol(parties, threshold, &mut task);
        //drop first party as its malicious
        let _ = results.remove(0);
        assert_eq!(results.len(), identities.len() - 1);
        //Can check that for each party the received value corresponds to the sent one
        //Except for party 0, check defaulted to 0
        let mut vec_of_vec_of_shares =
            vec![vec![vec![(1_usize, ResiduePoly::<Z128>::ZERO); 5]; 5]; 5];
        //vec_of_vec_of_shares is indexed by [idx_of_sender][idx_of_secret][idx_of_share]
        for (role_pi, res_pi) in results.iter() {
            let res_pi = res_pi.as_ref().unwrap();
            let (rcv_res_pi, _sent_res_pi) = (&res_pi.all_shares, &res_pi.shares_own_secret);
            for (role_pj, data_vec) in rcv_res_pi.iter() {
                for (idx_data, data) in data_vec.iter().enumerate() {
                    vec_of_vec_of_shares[role_pj.zero_based()][idx_data][role_pi.zero_based()] =
                        (role_pi.one_based(), *data);
                }
            }
            for (role_pj, res_pj) in results.iter() {
                if role_pj.zero_based() == 0 {
                    assert_eq!(
                        rcv_res_pi.get(role_pj).unwrap(),
                        &vec![ResiduePoly::<Z128>::ZERO; 5]
                    );
                } else {
                    let res_pj = res_pj.as_ref().unwrap();
                    let (_rcv_res_pj, sent_res_pj) =
                        (&res_pj.all_shares, &res_pj.shares_own_secret);
                    assert_eq!(
                        rcv_res_pi.get(role_pj).unwrap(),
                        sent_res_pj.get(role_pi).unwrap()
                    );
                }
            }
        }
        //Can also check that the secrets correctly reconstruct to the expected values
        for (idx_party, vec_of_shares) in vec_of_vec_of_shares.iter().enumerate() {
            for (idx_sharing, shares) in vec_of_shares.iter().enumerate() {
                let expected_secret = if idx_party == 0 {
                    ResiduePoly::<Z128>::ZERO
                } else {
                    secrets.get(&identities[idx_party]).unwrap()[idx_sharing]
                };
                let shamir_sharing = ShamirGSharings {
                    shares: shares.clone(),
                };
                assert_eq!(
                    shamir_sharing.err_reconstruct(threshold.into(), 1).unwrap(),
                    expected_secret
                );
            }
        }
    }

    //We have party 0 share not enough secrets of incorrect type. We expect fall back to the default 0 value
    #[test]
    fn test_real_share_dispute_incorrect_type() {
        let parties = 5;
        let threshold = 1;
        let (identities, secrets) = generate_ids_and_secrets(parties);

        async fn task(mut session: LargeSession) -> (Role, anyhow::Result<ShareDisputeOutput>) {
            let own_role = session.my_role().unwrap();
            let secret: Vec<ResiduePoly<Z128>> = (0..=4)
                .map(|v| {
                    ResiduePoly::<Z128>::from_scalar(Wrapping::<u128>(
                        (v + own_role.zero_based() * 10).try_into().unwrap(),
                    ))
                })
                .collect();
            if own_role.zero_based() != 0 {
                (
                    own_role,
                    RealShareDispute::execute(&mut session, &secret).await,
                )
            } else {
                let vec_polypoints: Vec<Vec<Z128>> = (0..=2_usize)
                    .map(|secret_idx| {
                        (0_usize..session.amount_of_parties())
                            .map(|party_idx| {
                                Wrapping(
                                    (secret_idx * session.amount_of_parties() + party_idx) as u128,
                                )
                            })
                            .collect::<Vec<Z128>>()
                    })
                    .collect_vec();
                //Map each parties' role with their shares (one share per secret)
                let mut polypoints_map: HashMap<Role, NetworkValue> = HashMap::new();
                for polypoints in vec_polypoints.into_iter() {
                    for (role_id, polypoint) in polypoints.into_iter().enumerate() {
                        let curr_role = Role::indexed_by_zero(role_id);
                        match polypoints_map.get_mut(&curr_role) {
                            Some(NetworkValue::VecRingValue(v)) => {
                                v.push(Value::Ring128(polypoint))
                            }
                            None => {
                                let mut new_party_vec = Vec::with_capacity(5);
                                new_party_vec.push(Value::Ring128(polypoint));
                                polypoints_map
                                    .insert(curr_role, NetworkValue::VecRingValue(new_party_vec));
                            }
                            _ => {}
                        }
                    }
                }
                session.network().increase_round_counter().await.unwrap();
                send_to_parties_w_dispute(&polypoints_map, &session)
                    .await
                    .unwrap();
                (own_role, Ok(ShareDisputeOutput::default()))
            }
        }

        let mut results = execute_protocol(parties, threshold, &mut task);
        //drop first party as its malicious
        let _ = results.remove(0);
        assert_eq!(results.len(), identities.len() - 1);
        //Can check that for each party the received value corresponds to the sent one
        //Except for party 0, check defaulted to 0
        let mut vec_of_vec_of_shares =
            vec![vec![vec![(1_usize, ResiduePoly::<Z128>::ZERO); 5]; 5]; 5];
        //vec_of_vec_of_shares is indexed by [idx_of_sender][idx_of_secret][idx_of_share]
        for (role_pi, res_pi) in results.iter() {
            let res_pi = res_pi.as_ref().unwrap();
            let (rcv_res_pi, _sent_res_pi) = (&res_pi.all_shares, &res_pi.shares_own_secret);
            for (role_pj, data_vec) in rcv_res_pi.iter() {
                for (idx_data, data) in data_vec.iter().enumerate() {
                    vec_of_vec_of_shares[role_pj.zero_based()][idx_data][role_pi.zero_based()] =
                        (role_pi.one_based(), *data);
                }
            }
            for (role_pj, res_pj) in results.iter() {
                if role_pj.zero_based() == 0 {
                    assert_eq!(
                        rcv_res_pi.get(role_pj).unwrap(),
                        &vec![ResiduePoly::<Z128>::ZERO; 5]
                    );
                } else {
                    let res_pj = res_pj.as_ref().unwrap();
                    let (_rcv_res_pj, sent_res_pj) =
                        (&res_pj.all_shares, &res_pj.shares_own_secret);
                    assert_eq!(
                        rcv_res_pi.get(role_pj).unwrap(),
                        sent_res_pj.get(role_pi).unwrap()
                    );
                }
            }
        }
        //Can also check that the secrets correctly reconstruct to the expected values
        for (idx_party, vec_of_shares) in vec_of_vec_of_shares.iter().enumerate() {
            for (idx_sharing, shares) in vec_of_shares.iter().enumerate() {
                let expected_secret = if idx_party == 0 {
                    ResiduePoly::<Z128>::ZERO
                } else {
                    secrets.get(&identities[idx_party]).unwrap()[idx_sharing]
                };
                let shamir_sharing = ShamirGSharings {
                    shares: shares.clone(),
                };
                assert_eq!(
                    shamir_sharing.err_reconstruct(threshold.into(), 1).unwrap(),
                    expected_secret
                );
            }
        }
    }

    #[traced_test]
    #[test]
    fn test_evaluate_w_zero_roots() {
        let parties = 4;
        let msg = 42;
        let zero_points = vec![1];
        // Constant base-poly
        let base = Poly::from_coefs(vec![ResiduePoly::from_scalar(Wrapping(msg))]);
        let res = evaluate_w_zero_roots(parties, zero_points.clone(), &base).unwrap();
        // Check msg is in the constant
        assert_eq!(ResiduePoly::from_scalar(Wrapping(msg)), res[0]);
        // Check that the zero_points are 0
        zero_points
            .iter()
            .for_each(|x| assert_eq!(ResiduePoly::ZERO, res[*x]));
    }

    #[test]
    fn test_interpolate_w_puncture() {
        let parties = 7;
        let threshold = 2;
        let msg = 42;
        let dispute_ids = vec![7];
        execute_interpolate_poly_w_punctures(msg, parties, threshold, dispute_ids);
    }

    #[test]
    fn test_no_disputes() {
        let parties = 7;
        let threshold = 2;
        let msg = 42;
        let dispute_ids = vec![];
        execute_interpolate_poly_w_punctures(msg, parties, threshold, dispute_ids);
    }

    #[test]
    fn test_too_many_disputes() {
        let parties = 7;
        let threshold = 2;
        let msg = 42;
        let dispute_ids = vec![5, 6, 7];
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        assert!(interpolate_poly_w_punctures(
            &mut rng,
            parties,
            threshold,
            dispute_ids.clone(),
            ResiduePoly::from_scalar(Wrapping(msg)),
        )
        .is_err());
    }

    fn execute_interpolate_poly_w_punctures(
        msg: u128,
        parties: usize,
        threshold: usize,
        dispute_ids: Vec<usize>,
    ) {
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        let interpolation = interpolate_poly_w_punctures(
            &mut rng,
            parties,
            threshold,
            dispute_ids.clone(),
            ResiduePoly::from_scalar(Wrapping(msg)),
        )
        .unwrap();
        // Check that the points of dispuite_ids are 0
        dispute_ids
            .iter()
            .for_each(|x| assert_eq!(ResiduePoly::ZERO, interpolation[*x - 1]));
        // Map the y-points to their corresponding (not embedded) x-points
        let points = (1..parties).map(|x| (x, interpolation[x - 1])).collect();
        let sham = ShamirGSharings::<Z128> { shares: points };
        // Reconstruct the message and check it is as expected
        let ref_msg =
            Z128::try_from(sham.err_reconstruct(threshold, dispute_ids.len()).unwrap()).unwrap();
        assert_eq!(msg, ref_msg.0);
    }

    #[test]
    fn zero_degree_interpolate_w_puncture() {
        let parties = 4;
        let threshold = 1;
        let msg = 42;
        let dispute_ids = vec![1, 2]; // too many disputes since the threshold is 1
        let mut rng = ChaCha12Rng::seed_from_u64(0);
        assert!(interpolate_poly_w_punctures(
            &mut rng,
            parties,
            threshold,
            dispute_ids.clone(),
            ResiduePoly::from_scalar(Wrapping(msg)),
        )
        .is_err());
    }
}

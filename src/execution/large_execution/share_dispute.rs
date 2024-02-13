use crate::{
    algebra::poly::Poly,
    algebra::structure_traits::Ring,
    error::error_handler::anyhow_error_and_log,
    execution::{
        communication::p2p::{receive_from_parties_w_dispute, send_to_parties_w_dispute},
        runtime::party::Role,
        runtime::session::LargeSessionHandles,
        sharing::shamir::ShamirRing,
    },
    networking::value::NetworkValue,
};
use async_trait::async_trait;
use itertools::Itertools;
use rand_core::CryptoRngCore;
use std::collections::HashMap;

#[derive(Clone, Default)]
pub struct ShareDisputeOutput<Z> {
    pub all_shares: HashMap<Role, Vec<Z>>,
    pub shares_own_secret: HashMap<Role, Vec<Z>>,
}

#[derive(Clone, Default)]
pub struct ShareDisputeOutputDouble<Z> {
    pub output_t: ShareDisputeOutput<Z>,
    pub output_2t: ShareDisputeOutput<Z>,
}
//Not sure it makes sense to do a dummy implementation?
//what would it look like?
#[async_trait]
pub trait ShareDispute: Send + Sync + Clone + Default {
    /// Executes the ShareDispute protocol on a vector of secrets,
    /// expecting all parties to also share a vector of secrets of the same length.
    /// Returns:
    /// - a hashmap which maps roles to shares I received
    /// - another hashmap which maps roles to shares I sent
    async fn execute<Z: ShamirRing, R: CryptoRngCore, L: LargeSessionHandles<R>>(
        &self,
        session: &mut L,
        secrets: &[Z],
    ) -> anyhow::Result<ShareDisputeOutput<Z>>;

    /// Executes the ShareDispute protocol on a vector of secrets,
    /// actually sharing the secret using a sharing of degree t and one of degree 2t
    /// Needed for doubleSharings
    async fn execute_double<Z: ShamirRing, R: CryptoRngCore, L: LargeSessionHandles<R>>(
        &self,
        session: &mut L,
        secrets: &[Z],
    ) -> anyhow::Result<ShareDisputeOutputDouble<Z>>;
}

#[derive(Default, Clone)]
pub struct RealShareDispute {}

//Want to puncture only at Dispute\Corrupt ids
fn compute_puncture_idx<R: CryptoRngCore, L: LargeSessionHandles<R>>(
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

fn share_secrets<Z: ShamirRing, R: CryptoRngCore>(
    rng: &mut R,
    secrets: &[Z],
    punctured_idx: &[usize],
    num_parties: usize,
    degree: usize,
) -> anyhow::Result<Vec<Vec<Z>>> {
    secrets
        .iter()
        .map(|secret| {
            interpolate_poly_w_punctures(rng, num_parties, degree, punctured_idx.to_vec(), *secret)
        })
        .collect::<anyhow::Result<_>>()
}

//Fill in missing values with 0s
fn fill_incomplete_output<Z: Ring, R: CryptoRngCore, L: LargeSessionHandles<R>>(
    session: &L,
    result: &mut HashMap<Role, Vec<Z>>,
    len: usize,
) {
    for role in session.role_assignments().keys() {
        if !result.contains_key(role) {
            result.insert(*role, vec![Z::ZERO; len]);
        //Using unwrap here because the first clause makes sure the key is present!
        } else if result.get(role).unwrap().len() < len {
            let incomplete_vec = result.get_mut(role).unwrap();
            incomplete_vec.append(&mut vec![Z::ZERO; len - incomplete_vec.len()]);
        }
    }
}

#[async_trait]
impl ShareDispute for RealShareDispute {
    async fn execute_double<Z: ShamirRing, R: CryptoRngCore, L: LargeSessionHandles<R>>(
        &self,
        session: &mut L,
        secrets: &[Z],
    ) -> anyhow::Result<ShareDisputeOutputDouble<Z>> {
        let num_parties = session.amount_of_parties();
        let degree_t = session.threshold() as usize;
        let degree_2t = 2 * degree_t;

        let dispute_ids = compute_puncture_idx(session)?;

        //Sample one random polynomial of correct degree per secret
        //and evaluate it at the parties' points
        let vec_polypoints_t =
            share_secrets(session.rng(), secrets, &dispute_ids, num_parties, degree_t)?;
        let vec_polypoints_2t =
            share_secrets(session.rng(), secrets, &dispute_ids, num_parties, degree_2t)?;

        //Map each parties' role with their pairs of shares (one share of deg t and one of deg 2t per secret)
        let mut polypoints_map = HashMap::new();
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
                    Some(NetworkValue::VecPairRingValue(v)) => v.push((polypoint_t, polypoint_2t)),
                    None => {
                        let mut new_party_vec = Vec::with_capacity(secrets.len());
                        new_party_vec.push((polypoint_t, polypoint_2t));
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

        send_and_receive_share_dispute_double(session, polypoints_map, secrets.len()).await
    }

    async fn execute<Z: ShamirRing, R: CryptoRngCore, L: LargeSessionHandles<R>>(
        &self,
        session: &mut L,
        secrets: &[Z],
    ) -> anyhow::Result<ShareDisputeOutput<Z>> {
        let num_parties = session.amount_of_parties();
        let degree = session.threshold() as usize;
        //If some party is corrupt I shouldn't sample a specific point for it
        //Even if it is in dispute with me
        let dispute_ids = compute_puncture_idx(session)?;

        //Sample one random polynomial of correct degree per secret
        //and evaluate it at the parties' points
        let vec_polypoints =
            share_secrets(session.rng(), secrets, &dispute_ids, num_parties, degree)?;

        //Map each parties' role with their shares (one share per secret)
        let mut polypoints_map = HashMap::new();
        for polypoints in vec_polypoints.into_iter() {
            for (role_id, polypoint) in polypoints.into_iter().enumerate() {
                let curr_role = Role::indexed_by_zero(role_id);
                match polypoints_map.get_mut(&curr_role) {
                    Some(NetworkValue::VecRingValue(v)) => v.push(polypoint),
                    None => {
                        let mut new_party_vec = Vec::with_capacity(secrets.len());
                        new_party_vec.push(polypoint);
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
        send_and_receive_share_dispute_single(session, polypoints_map, secrets.len()).await
    }
}

async fn send_and_receive_share_dispute_double<
    Z: Ring,
    R: CryptoRngCore,
    L: LargeSessionHandles<R>,
>(
    session: &mut L,
    polypoints_map: HashMap<Role, NetworkValue<Z>>,
    num_secrets: usize,
) -> anyhow::Result<ShareDisputeOutputDouble<Z>> {
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
    let mut polypoints_map_t = HashMap::new();
    let mut polypoints_map_2t = HashMap::new();
    for (role, net_value) in polypoints_map.into_iter() {
        if let NetworkValue::VecPairRingValue(value) = net_value {
            let mut vec_residue_t = Vec::with_capacity(num_secrets);
            let mut vec_residue_2t = Vec::with_capacity(num_secrets);
            for v in value.into_iter() {
                let (v_t, v_2t) = v;
                {
                    vec_residue_t.push(v_t);
                    vec_residue_2t.push(v_2t);
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
    let mut result_t = HashMap::new();
    let mut result_2t = HashMap::new();

    for (role, net_value) in received_values.into_iter() {
        if let NetworkValue::<Z>::VecPairRingValue(value) = net_value {
            let mut vec_residue_t = Vec::with_capacity(num_secrets);
            let mut vec_residue_2t = Vec::with_capacity(num_secrets);
            for v in value.into_iter() {
                let (v_t, v_2t) = v;
                {
                    vec_residue_t.push(v_t);
                    vec_residue_2t.push(v_2t);
                }
            }
            result_t.insert(role, vec_residue_t);
            result_2t.insert(role, vec_residue_2t);
        } else {
            result_t.insert(role, vec![Z::ZERO; num_secrets]);
            result_2t.insert(role, vec![Z::ZERO; num_secrets]);
        }
    }

    //Fill in missing values with 0s
    fill_incomplete_output(session, &mut result_t, num_secrets);
    fill_incomplete_output(session, &mut result_2t, num_secrets);

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

async fn send_and_receive_share_dispute_single<
    Z: Ring,
    R: CryptoRngCore,
    L: LargeSessionHandles<R>,
>(
    session: &mut L,
    polypoints_map: HashMap<Role, NetworkValue<Z>>,
    num_secrets: usize,
) -> anyhow::Result<ShareDisputeOutput<Z>> {
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
    let polypoints_map = polypoints_map
        .into_iter()
        .map(|(role, net_value)| {
            if let NetworkValue::VecRingValue(value) = net_value {
                Ok((role, value))
            } else {
                Err(anyhow_error_and_log(
                    "I had an incorrect type inside my own share sampling.".to_string(),
                ))
            }
        })
        .try_collect()?;

    //Returns my polypoints_map AND the points received from others
    let mut result = received_values
        .into_iter()
        .map(|(role, net_value)| {
            if let NetworkValue::VecRingValue(value) = net_value {
                (role, value)
            } else {
                (role, vec![Z::ZERO; num_secrets])
            }
        })
        .collect();

    //Fill in missing values with 0s
    fill_incomplete_output(session, &mut result, num_secrets);

    Ok(ShareDisputeOutput {
        all_shares: result,
        shares_own_secret: polypoints_map,
    })
}

/// Constructs a random polynomial given a set of `threshold` party IDs which should evaluate to 0 on the interpolated polynomial.
/// Returns all the `num_parties` y-values interpolated from the `dispute_party_ids` point embedded onto the x-axis.
pub fn interpolate_poly_w_punctures<Z: ShamirRing, R: CryptoRngCore>(
    rng: &mut R,
    num_parties: usize,
    threshold: usize,
    dispute_party_ids: Vec<usize>,
    secret: Z,
) -> anyhow::Result<Vec<Z>> {
    if threshold < dispute_party_ids.len() {
        return Err(anyhow_error_and_log(format!(
            "Too many disputes, {:?}, for threshold {}",
            dispute_party_ids, threshold,
        )));
    }
    let degree = threshold - dispute_party_ids.len();
    // make a random polynomial of degree threshold `dispute_party_ids`
    let base_poly = Poly::sample_random_with_fixed_constant(rng, secret, degree);
    // Modify the polynomial by increasing its degree with |dispute_party_ids| and ensuring the points
    // in `dispute_party_ids` gets y-value=0 and evaluate it for 1..num_parties
    let points = evaluate_w_zero_roots(num_parties, dispute_party_ids, &base_poly)?;
    // check that the zero point is `secret`
    debug_assert_eq!(secret, points[0]);
    // evaluate the poly at the party indices gamma
    // exclude the point at x=0
    Ok(points[1..points.len()].to_vec())
}

//TODO: This function should be optimized with memoized calls to normalized_parties_root
/// Helper method for punctured polynomial interpolation.
/// Takes a base polynomial and increases its degree by |points_of_zero_roots] by ensuring that each of the [points_of_zero_roots] gets embedded to x-points whose y-value is 0.
/// And then returns all the 0..[num_parties] points on the polynomial.
/// More specifically the values in [points_of_zero_roots] gets embedded on the polynomial to ensure they are invertable, then
/// the polynomial gets modified to ensure that each of the points in [points_of_zero_roots] will have y-value 0
/// by increasing its degres with |points_of_zero_roots|. Then the polynomial is evaluated in embedded points 0..[num_partes] and this is returned.
pub fn evaluate_w_zero_roots<Z: ShamirRing>(
    num_parties: usize,
    points_of_zero_roots: Vec<usize>,
    base_poly: &Poly<Z>,
) -> anyhow::Result<Vec<Z>> {
    let (normalized_parties_root, x_coords) = Poly::<Z>::normalized_parties_root(num_parties)?;
    let mut poly = base_poly.clone();

    // poly will be of degree [threshold], zero at the points [x_coords], which reflect the party IDs embedded, and [secret] at 0
    for p in points_of_zero_roots {
        poly = poly * normalized_parties_root[p - 1].clone(); //(x.clone() + neg_parties[p].clone()) * Poly::from_coefs(vec![inv_coefs[p]]);
    }
    // evaluate the poly at the embedded party indices
    let points: Vec<_> = (0..=num_parties).map(|p| poly.eval(&x_coords[p])).collect();
    Ok(points)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{
        compute_puncture_idx, evaluate_w_zero_roots, send_and_receive_share_dispute_double,
        send_and_receive_share_dispute_single, share_secrets,
    };
    use crate::algebra::residue_poly::ResiduePoly128;
    use crate::algebra::residue_poly::ResiduePoly64;
    use crate::{
        algebra::{
            poly::Poly,
            residue_poly::ResiduePoly,
            structure_traits::{Ring, Zero},
        },
        execution::{
            communication::p2p::send_to_parties_w_dispute,
            large_execution::share_dispute::{
                interpolate_poly_w_punctures, RealShareDispute, ShareDispute, ShareDisputeOutput,
                ShareDisputeOutputDouble,
            },
            runtime::party::Role,
            runtime::session::{
                BaseSessionHandles, LargeSession, LargeSessionHandles, ParameterHandles,
            },
            sharing::{
                shamir::{ShamirRing, ShamirSharing},
                share::Share,
            },
        },
        networking::value::NetworkValue,
        tests::helper::tests::{
            execute_protocol_large_w_disputes_and_malicious, TestingParameters,
        },
    };
    use aes_prng::AesRng;
    use async_trait::async_trait;
    use itertools::Itertools;
    use rand::SeedableRng;
    use rand_core::CryptoRngCore;
    use rstest::rstest;
    use std::{collections::HashMap, num::Wrapping};
    use tracing_test::traced_test;

    ///Dropout strategy
    #[derive(Default, Clone)]
    pub(crate) struct DroppingShareDispute {}

    ///Send an incorrect amount
    #[derive(Default, Clone)]
    pub(crate) struct WrongShareDisputeRecons {}

    ///Strategy of a malicious player that just sends BS (but correct amount of correct type)
    /// Not really used to test ShareDispute itself, but rather higher level protocols
    #[derive(Default, Clone)]
    pub(crate) struct MaliciousShareDisputeRecons {
        roles_to_lie_to: Vec<Role>,
    }

    impl MaliciousShareDisputeRecons {
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
    impl ShareDispute for DroppingShareDispute {
        async fn execute<Z: Ring, R: CryptoRngCore, L: LargeSessionHandles<R>>(
            &self,
            _session: &mut L,
            _secrets: &[Z],
        ) -> anyhow::Result<ShareDisputeOutput<Z>> {
            Ok(ShareDisputeOutput::default())
        }

        async fn execute_double<Z: Ring, R: CryptoRngCore, L: LargeSessionHandles<R>>(
            &self,
            _session: &mut L,
            _secrets: &[Z],
        ) -> anyhow::Result<ShareDisputeOutputDouble<Z>> {
            Ok(ShareDisputeOutputDouble::default())
        }
    }

    #[async_trait]
    impl ShareDispute for WrongShareDisputeRecons {
        async fn execute<Z: Ring, R: CryptoRngCore, L: LargeSessionHandles<R>>(
            &self,
            session: &mut L,
            secrets: &[Z],
        ) -> anyhow::Result<ShareDisputeOutput<Z>> {
            //Sample random not enough shares
            let vec_polypoints: Vec<Vec<Z>> = (0..secrets.len() - 1)
                .map(|_secret_idx| {
                    (0_usize..session.amount_of_parties())
                        .map(|_party_idx| {
                            //Wrapping((secret_idx * session.amount_of_parties() + party_idx) as u128)
                            Z::sample(session.rng())
                        })
                        .collect::<Vec<Z>>()
                })
                .collect_vec();

            //Map each parties' role with their shares (one share per secret)
            //Except its not of correct type, and we are sending one too few shares per party
            let mut polypoints_map: HashMap<Role, NetworkValue<Z>> = HashMap::new();
            for polypoints in vec_polypoints.into_iter() {
                for (role_id, polypoint) in polypoints.into_iter().enumerate() {
                    let curr_role = Role::indexed_by_zero(role_id);
                    match polypoints_map.get_mut(&curr_role) {
                        Some(NetworkValue::VecRingValue(v)) => v.push(polypoint),
                        None => {
                            let mut new_party_vec = Vec::with_capacity(secrets.len());
                            new_party_vec.push(polypoint);
                            polypoints_map
                                .insert(curr_role, NetworkValue::VecRingValue(new_party_vec));
                        }
                        _ => {}
                    }
                }
            }
            send_to_parties_w_dispute(&polypoints_map, session)
                .await
                .unwrap();
            Ok(ShareDisputeOutput::default())
        }

        async fn execute_double<Z: Ring, R: CryptoRngCore, L: LargeSessionHandles<R>>(
            &self,
            session: &mut L,
            secrets: &[Z],
        ) -> anyhow::Result<ShareDisputeOutputDouble<Z>> {
            //Sample random and not enough shares
            let vec_polypoints: Vec<Vec<Z>> = (0..secrets.len() - 1)
                .map(|_secret_idx| {
                    (0_usize..session.amount_of_parties())
                        .map(|_party_idx| {
                            //Wrapping((secret_idx * session.amount_of_parties() + party_idx) as u128)
                            Z::sample(session.rng())
                        })
                        .collect::<Vec<Z>>()
                })
                .collect_vec();

            //Map each parties' role with their shares (one share per secret)
            //Except its not of correct type, and we are sending one too few shares per party
            let mut polypoints_map: HashMap<Role, NetworkValue<Z>> = HashMap::new();
            for polypoints in vec_polypoints.into_iter() {
                for (role_id, polypoint) in polypoints.into_iter().enumerate() {
                    let curr_role = Role::indexed_by_zero(role_id);
                    match polypoints_map.get_mut(&curr_role) {
                        Some(NetworkValue::VecPairRingValue(v)) => v.push((polypoint, polypoint)),
                        None => {
                            let mut new_party_vec = Vec::with_capacity(secrets.len());
                            new_party_vec.push((polypoint, polypoint));
                            polypoints_map
                                .insert(curr_role, NetworkValue::VecPairRingValue(new_party_vec));
                        }
                        _ => {}
                    }
                }
            }
            send_to_parties_w_dispute(&polypoints_map, session)
                .await
                .unwrap();
            Ok(ShareDisputeOutputDouble::default())
        }
    }

    #[async_trait]
    impl ShareDispute for MaliciousShareDisputeRecons {
        async fn execute_double<Z: ShamirRing, R: CryptoRngCore, L: LargeSessionHandles<R>>(
            &self,
            session: &mut L,
            secrets: &[Z],
        ) -> anyhow::Result<ShareDisputeOutputDouble<Z>> {
            let num_parties = session.amount_of_parties();
            let degree_t = session.threshold() as usize;
            let degree_2t = 2 * degree_t;

            let dispute_ids = compute_puncture_idx(session)?;

            //Sample one random polynomial of correct degree per secret
            //and evaluate it at the parties' points
            let vec_polypoints_t: Vec<Vec<Z>> =
                share_secrets(session.rng(), secrets, &dispute_ids, num_parties, degree_t)?;
            let vec_polypoints_2t: Vec<Vec<Z>> =
                share_secrets(session.rng(), secrets, &dispute_ids, num_parties, degree_2t)?;

            //Map each parties' role with their pairs of shares (one share of deg t and one of deg 2t per secret)
            let mut polypoints_map: HashMap<Role, NetworkValue<Z>> = HashMap::new();
            for (mut polypoints_t, mut polypoints_2t) in vec_polypoints_t
                .into_iter()
                .zip(vec_polypoints_2t.into_iter())
            {
                for (role_id, (polypoint_t, polypoint_2t)) in polypoints_t
                    .iter_mut()
                    .zip(polypoints_2t.iter_mut())
                    .enumerate()
                {
                    let curr_role = Role::indexed_by_zero(role_id);
                    //Cheat if we should
                    if self.roles_to_lie_to.contains(&curr_role) {
                        let cheating_poly = Z::sample(session.rng());
                        *polypoint_t += cheating_poly;
                        *polypoint_2t += cheating_poly;
                    }
                    match polypoints_map.get_mut(&curr_role) {
                        Some(NetworkValue::VecPairRingValue(v)) => {
                            v.push((*polypoint_t, *polypoint_2t))
                        }
                        None => {
                            let mut new_party_vec = Vec::with_capacity(secrets.len());
                            new_party_vec.push((*polypoint_t, *polypoint_2t));
                            polypoints_map
                                .insert(curr_role, NetworkValue::VecPairRingValue(new_party_vec));
                        }
                        _ => {}
                    }
                }
            }

            send_and_receive_share_dispute_double(session, polypoints_map, secrets.len()).await
        }

        async fn execute<Z: ShamirRing, R: CryptoRngCore, L: LargeSessionHandles<R>>(
            &self,
            session: &mut L,
            secrets: &[Z],
        ) -> anyhow::Result<ShareDisputeOutput<Z>> {
            let num_parties = session.amount_of_parties();
            let degree = session.threshold() as usize;
            //If some party is corrupt I shouldn't sample a specific point for it
            //Even if it is in dispute with me
            let dispute_ids: Vec<usize> = compute_puncture_idx(session)?;

            //Sample one random polynomial of correct degree per secret
            //and evaluate it at the parties' points
            let mut vec_polypoints: Vec<Vec<Z>> =
                share_secrets(session.rng(), secrets, &dispute_ids, num_parties, degree)?;

            //Map each parties' role with their shares (one share per secret)
            let mut polypoints_map: HashMap<Role, NetworkValue<Z>> = HashMap::new();
            for polypoints in vec_polypoints.iter_mut() {
                for (role_id, polypoint) in polypoints.iter_mut().enumerate() {
                    let curr_role = Role::indexed_by_zero(role_id);
                    if self.roles_to_lie_to.contains(&curr_role) {
                        let cheating_poly = Z::sample(session.rng());
                        *polypoint += cheating_poly;
                    }
                    match polypoints_map.get_mut(&curr_role) {
                        Some(NetworkValue::VecRingValue(v)) => v.push(*polypoint),
                        None => {
                            let mut new_party_vec = Vec::with_capacity(secrets.len());
                            new_party_vec.push(*polypoint);
                            polypoints_map
                                .insert(curr_role, NetworkValue::VecRingValue(new_party_vec));
                        }
                        _ => {}
                    }
                }
            }
            send_and_receive_share_dispute_single(session, polypoints_map, secrets.len()).await
        }
    }

    /// Test share_dispute for different malicious strategies, doing both execute and execute_double
    /// Accepts a set of dispute pairs that will be inserted to the honest parties' sessions
    /// before executing the protocol
    fn test_share_dispute_strategies<Z: ShamirRing, S: ShareDispute + 'static>(
        params: TestingParameters,
        malicious_share_dispute: S,
    ) {
        let num_secrets = 2;

        let (dispute_map, malicious_due_to_dispute) = params.get_dispute_map();

        //Define an honest execution of share_dispute (do both execute and execute_double)
        let mut task_honest = |mut session: LargeSession| async move {
            let real_share_dispute = RealShareDispute::default();
            let secrets = (0..num_secrets)
                .map(|_| Z::sample(session.rng()))
                .collect_vec();

            (
                session.my_role().unwrap(),
                secrets.clone(),
                real_share_dispute
                    .execute(&mut session, &secrets)
                    .await
                    .unwrap(),
                real_share_dispute
                    .execute_double(&mut session, &secrets)
                    .await
                    .unwrap(),
            )
        };

        //Define a malicious execution of share_dispute (again both execute and execute_double)
        let mut task_malicious = |mut session: LargeSession, malicious_share_dispute: S| async move {
            let secrets = (0..num_secrets)
                .map(|_| Z::sample(session.rng()))
                .collect_vec();
            (
                session.my_role().unwrap(),
                malicious_share_dispute
                    .execute(&mut session, &secrets)
                    .await,
                malicious_share_dispute
                    .execute_double(&mut session, &secrets)
                    .await,
            )
        };

        //Execute the protocol with malicious parties and added disputes
        let (result_honest, _) = execute_protocol_large_w_disputes_and_malicious::<Z, _, _, _, _, _>(
            &params,
            &params.dispute_pairs,
            &[
                malicious_due_to_dispute.clone(),
                params.malicious_roles.to_vec(),
            ]
            .concat(),
            malicious_share_dispute,
            &mut task_honest,
            &mut task_malicious,
        );

        //Check that dispute (pi,pj) maps to 0 for pi and pj, malicious map to 0 for all
        //and otherwise share sent are share received between honest parties.
        //Also prepare the reconstruction vectors
        let mut reconstruction_vectors_single =
            vec![vec![Vec::<Share::<Z>>::default(); num_secrets]; params.num_parties];

        let mut reconstruction_vectors_double_t =
            vec![vec![Vec::<Share::<Z>>::default(); num_secrets]; params.num_parties];

        let mut reconstruction_vectors_double_2t =
            vec![vec![Vec::<Share::<Z>>::default(); num_secrets]; params.num_parties];

        for (role_pi, _, output_single_pi, output_double_pi) in result_honest.iter() {
            let rcv_res_pi_single = &output_single_pi.all_shares;
            let rcv_res_pi_double_t = &output_double_pi.output_t.all_shares;
            let rcv_res_pi_double_2t = &output_double_pi.output_2t.all_shares;

            let pi_disputes = dispute_map.get(role_pi);
            //Push shares into the appropriate reconstruction vectors
            //AND check that received shares is 0 if (pi,pj) in dispute or pj is corrupt
            //First for the result of execute
            for (role_pj, vec_shares_from_pj) in rcv_res_pi_single {
                for (idx_share, share_from_pj) in vec_shares_from_pj.iter().enumerate() {
                    //Check 0 if malicious
                    if malicious_due_to_dispute.contains(role_pj) {
                        assert_eq!(share_from_pj, &Z::ZERO);
                    }
                    //Check 0 if in dispute
                    if let Some(dispute) = pi_disputes {
                        if dispute.contains(role_pj) {
                            assert_eq!(share_from_pj, &Z::ZERO);
                        }
                    }
                    reconstruction_vectors_single[role_pj.zero_based()][idx_share]
                        .push(Share::new(*role_pi, *share_from_pj));
                }
            }

            //Then for the result of execute_double of degree t
            for (role_pj, vec_shares_from_pj) in rcv_res_pi_double_t {
                for (idx_share, share_from_pj) in vec_shares_from_pj.iter().enumerate() {
                    //Check 0 if malicious
                    if malicious_due_to_dispute.contains(role_pj) {
                        assert_eq!(share_from_pj, &Z::ZERO);
                    }
                    //Check 0 if in dispute
                    if let Some(dispute) = pi_disputes {
                        if dispute.contains(role_pj) {
                            assert_eq!(share_from_pj, &Z::ZERO);
                        }
                    }
                    reconstruction_vectors_double_t[role_pj.zero_based()][idx_share]
                        .push(Share::new(*role_pi, *share_from_pj));
                }
            }

            //Finally for the result of execute_double of degree 2t
            for (role_pj, vec_shares_from_pj) in rcv_res_pi_double_2t {
                for (idx_share, share_from_pj) in vec_shares_from_pj.iter().enumerate() {
                    //Check 0 if malicious
                    if malicious_due_to_dispute.contains(role_pj) {
                        assert_eq!(share_from_pj, &Z::ZERO);
                    }
                    //Check 0 if in dispute
                    if let Some(dispute) = pi_disputes {
                        if dispute.contains(role_pj) {
                            assert_eq!(share_from_pj, &Z::ZERO);
                        }
                    }
                    reconstruction_vectors_double_2t[role_pj.zero_based()][idx_share]
                        .push(Share::new(*role_pi, *share_from_pj));
                }
            }
        }

        //Check correct reconstruction of all honest parties
        for (role_pi, secrets_pi, _, _) in result_honest {
            if !malicious_due_to_dispute.contains(&role_pi) {
                for (idx_secret, expected_secret) in secrets_pi.iter().enumerate() {
                    //Reconstruct the secret shared by execute
                    let reconst_single_t = ShamirSharing::create(
                        reconstruction_vectors_single[role_pi.zero_based()][idx_secret].clone(),
                    )
                    .reconstruct(params.threshold);

                    //Reconstruct the secret of degree t shared by execute_double
                    let reconst_double_t = ShamirSharing::create(
                        reconstruction_vectors_double_t[role_pi.zero_based()][idx_secret].clone(),
                    )
                    .reconstruct(params.threshold);

                    //Reconstruct the secret of degree 2t shared by execute_double
                    let reconst_double_2t = ShamirSharing::create(
                        reconstruction_vectors_double_2t[role_pi.zero_based()][idx_secret].clone(),
                    )
                    .reconstruct(2 * params.threshold);

                    //Assert all went fine
                    assert!(reconst_single_t.is_ok());
                    assert!(reconst_double_t.is_ok());
                    assert!(reconst_double_2t.is_ok());
                    assert_eq!(expected_secret, &reconst_single_t.unwrap());
                    assert_eq!(expected_secret, &reconst_double_t.unwrap());
                    assert_eq!(expected_secret, &reconst_double_2t.unwrap());
                }
            }
        }
    }

    // Rounds: 1 per share dispute (2 here, since we run single and double)
    #[rstest]
    #[case(TestingParameters::init_honest(4, 1, Some(2)))]
    #[case(TestingParameters::init_dispute(4, 1, &[(1,2),(0,3)]))]
    #[case(TestingParameters::init_dispute(4, 1, &[(1,2),(1,3)]))]
    #[case(TestingParameters::init_dispute(7, 2, &[(1,2),(1,3),(4,6),(0,5)]))]
    fn test_share_dispute_honest_z128(#[case] params: TestingParameters) {
        let malicious_share_dispute = RealShareDispute::default();
        test_share_dispute_strategies::<ResiduePoly64, _>(
            params.clone(),
            malicious_share_dispute.clone(),
        );
        test_share_dispute_strategies::<ResiduePoly128, _>(
            params.clone(),
            malicious_share_dispute.clone(),
        );
    }

    #[cfg(feature = "extensive_testing")]
    #[rstest]
    #[case(TestingParameters::init(4, 1, &[0], &[], &[], false, None))]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[], false, None))]
    #[case(TestingParameters::init(4, 1, &[2], &[], &[], false, None))]
    #[case(TestingParameters::init(4, 1, &[3], &[], &[], false, None))]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[(1,3)], false, None))]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[(1,2),(0,3)], false, None))]
    #[case(TestingParameters::init(4, 1, &[2], &[], &[(0,2),(1,3)], false, None))]
    #[case(TestingParameters::init(7, 2, &[2,6], &[], &[(0,2),(1,3),(0,4),(1,5)], false, None))]
    fn test_share_dispute_dropout(#[case] params: TestingParameters) {
        let dropping_share_dispute = DroppingShareDispute::default();
        test_share_dispute_strategies::<ResiduePoly64, _>(
            params.clone(),
            dropping_share_dispute.clone(),
        );
        test_share_dispute_strategies::<ResiduePoly128, _>(
            params.clone(),
            dropping_share_dispute.clone(),
        );
    }

    #[cfg(feature = "extensive_testing")]
    #[rstest]
    #[case(TestingParameters::init(4, 1, &[0], &[], &[], false, None))]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[], false, None))]
    #[case(TestingParameters::init(4, 1, &[2], &[], &[], false, None))]
    #[case(TestingParameters::init(4, 1, &[3], &[], &[], false, None))]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[(1,2),(0,3)], false, None))]
    #[case(TestingParameters::init(4, 1, &[2], &[], &[(0,2),(1,3)], false, None))]
    #[case(TestingParameters::init(7, 2, &[2,6], &[], &[(0,2),(1,3),(0,4),(1,5)], false, None))]
    fn test_malicious_share_dispute(#[case] params: TestingParameters) {
        let malicious_share_dispute_recons = WrongShareDisputeRecons::default();

        test_share_dispute_strategies::<ResiduePoly64, _>(
            params.clone(),
            malicious_share_dispute_recons.clone(),
        );
        test_share_dispute_strategies::<ResiduePoly128, _>(
            params.clone(),
            malicious_share_dispute_recons.clone(),
        );
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
        assert_eq!(ResiduePoly::from_scalar(Wrapping::<u128>(msg)), res[0]);
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
        let mut rng = AesRng::seed_from_u64(0);
        assert!(interpolate_poly_w_punctures(
            &mut rng,
            parties,
            threshold,
            dispute_ids.clone(),
            ResiduePoly::from_scalar(Wrapping::<u128>(msg)),
        )
        .is_err());
    }

    fn execute_interpolate_poly_w_punctures(
        msg: u128,
        parties: usize,
        threshold: usize,
        dispute_ids: Vec<usize>,
    ) {
        let mut rng = AesRng::seed_from_u64(0);
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
        let points = (1..parties)
            .map(|x| Share::new(Role::indexed_by_one(x), interpolation[x - 1]))
            .collect();
        let sham = ShamirSharing::create(points);
        // Reconstruct the message and check it is as expected
        let ref_msg = sham
            .err_reconstruct(threshold, dispute_ids.len())
            .unwrap()
            .coefs[0];
        assert_eq!(msg, ref_msg.0);
    }

    #[test]
    fn zero_degree_interpolate_w_puncture() {
        let parties = 4;
        let threshold = 1;
        let msg = 42;
        let dispute_ids = vec![1, 2]; // too many disputes since the threshold is 1
        let mut rng = AesRng::seed_from_u64(0);
        assert!(interpolate_poly_w_punctures(
            &mut rng,
            parties,
            threshold,
            dispute_ids.clone(),
            ResiduePoly::from_scalar(Wrapping::<u128>(msg)),
        )
        .is_err());
    }
}

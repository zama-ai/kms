use crate::{
    algebra::{
        poly::Poly,
        structure_traits::{Invert, Ring, RingWithExceptionalSequence},
    },
    error::error_handler::anyhow_error_and_log,
    execution::{
        communication::p2p::{receive_from_parties_w_dispute, send_to_honest_parties},
        runtime::{party::Role, sessions::large_session::LargeSessionHandles},
    },
    networking::value::NetworkValue,
    ProtocolDescription,
};
use async_trait::async_trait;
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use std::collections::HashMap;
use tracing::instrument;

/// Alias for RealShareDispute to follow the convetion
/// of the other protocols, except ShareDispute doesn't
/// rely on any subprotocol, so its Real and Secure version
/// are the same
pub type SecureShareDispute = RealShareDispute;

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
pub trait ShareDispute: ProtocolDescription + Send + Sync + Clone {
    /// Executes the ShareDispute protocol on a vector of secrets,
    /// expecting all parties to also share a vector of secrets of the same length.
    /// Returns:
    /// - a hashmap which maps roles to shares I received
    /// - another hashmap which maps roles to shares I sent
    async fn execute<Z: RingWithExceptionalSequence + Invert, L: LargeSessionHandles>(
        &self,
        session: &mut L,
        secrets: &[Z],
    ) -> anyhow::Result<ShareDisputeOutput<Z>>;

    /// Executes the ShareDispute protocol on a vector of secrets,
    /// actually sharing the secret using a sharing of degree t and one of degree 2t
    /// Needed for doubleSharings
    async fn execute_double<Z: RingWithExceptionalSequence + Invert, L: LargeSessionHandles>(
        &self,
        session: &mut L,
        secrets: &[Z],
    ) -> anyhow::Result<ShareDisputeOutputDouble<Z>>;
}

#[derive(Default, Clone)]
pub struct RealShareDispute {}

impl ProtocolDescription for RealShareDispute {
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!("{indent}-RealShareDispute")
    }
}

/// Returns the ids (one based) of the roles I am in dispute with
pub(crate) fn compute_idx_dispute<L: LargeSessionHandles>(
    session: &L,
) -> anyhow::Result<Vec<usize>> {
    Ok(session
        .disputed_roles()
        .get(&session.my_role())
        .iter()
        .map(|id| id.one_based())
        .collect())
}

pub(crate) fn share_secrets<Z, R: Rng + CryptoRng>(
    rng: &mut R,
    secrets: &[Z],
    punctured_idx: &[usize],
    num_parties: usize,
    degree: usize,
) -> anyhow::Result<Vec<Vec<Z>>>
where
    Z: RingWithExceptionalSequence + Invert,
{
    secrets
        .iter()
        .map(|secret| {
            interpolate_poly_w_punctures(rng, num_parties, degree, punctured_idx.to_vec(), *secret)
        })
        .collect::<anyhow::Result<_>>()
}

//Fill in missing values with 0s
pub(crate) fn fill_incomplete_output<Z: Ring, L: LargeSessionHandles>(
    session: &L,
    result: &mut HashMap<Role, Vec<Z>>,
    len: usize,
) {
    for role in session.roles() {
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
    #[instrument(name="ShareDispute (t,2t)",skip(self,session,secrets),fields(sid = ?session.session_id(),my_role=?session.my_role(),batch_size= ?secrets.len()))]
    async fn execute_double<Z: RingWithExceptionalSequence + Invert, L: LargeSessionHandles>(
        &self,
        session: &mut L,
        secrets: &[Z],
    ) -> anyhow::Result<ShareDisputeOutputDouble<Z>> {
        let num_parties = session.num_parties();
        let degree_t = session.threshold() as usize;
        let degree_2t = 2 * degree_t;

        //Get the IDs of all parties I'm in dispute with (ignoring the fact that some might or might not be in the Corrupt set)
        let dispute_ids = compute_idx_dispute(session)?;

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
            // May panic, but would imply a bug in `share_secrets`
            .zip_eq(vec_polypoints_2t.into_iter())
        {
            for (role_id, (polypoint_t, polypoint_2t)) in polypoints_t
                .into_iter()
                // May panic, but would imply a bug in `share_secrets`
                .zip_eq(polypoints_2t.into_iter())
                .enumerate()
            {
                let curr_role = Role::indexed_from_zero(role_id);
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
                            "Unexpected type appeared in my own map",
                        ));
                    }
                }
            }
        }

        send_and_receive_share_dispute_double(session, polypoints_map, secrets.len()).await
    }

    #[instrument(name="ShareDispute (t)",skip(self,session,secrets),fields(sid = ?session.session_id(),my_role=?session.my_role(),batch_size=?secrets.len()))]
    async fn execute<Z: RingWithExceptionalSequence + Invert, L: LargeSessionHandles>(
        &self,
        session: &mut L,
        secrets: &[Z],
    ) -> anyhow::Result<ShareDisputeOutput<Z>> {
        let num_parties = session.num_parties();
        let degree = session.threshold() as usize;
        //Get the IDs of all parties I'm in dispute with (ignoring the fact that some might or might not be in the Corrupt set)
        let dispute_ids = compute_idx_dispute(session)?;

        //Sample one random polynomial of correct degree per secret
        //and evaluate it at the parties' points
        let vec_polypoints =
            share_secrets(session.rng(), secrets, &dispute_ids, num_parties, degree)?;

        //Map each parties' role with their shares (one share per secret)
        let mut polypoints_map = HashMap::new();
        for polypoints in vec_polypoints.into_iter() {
            for (role_id, polypoint) in polypoints.into_iter().enumerate() {
                let curr_role = Role::indexed_from_zero(role_id);
                match polypoints_map.get_mut(&curr_role) {
                    Some(NetworkValue::VecRingValue(v)) => v.push(polypoint),
                    None => {
                        let mut new_party_vec = Vec::with_capacity(secrets.len());
                        new_party_vec.push(polypoint);
                        polypoints_map.insert(curr_role, NetworkValue::VecRingValue(new_party_vec));
                    }
                    _ => {
                        return Err(anyhow_error_and_log(
                            "Unexpected type appeared in my own map",
                        ));
                    }
                }
            }
        }
        send_and_receive_share_dispute_single(session, polypoints_map, secrets.len()).await
    }
}

pub(crate) async fn send_and_receive_share_dispute_double<Z: Ring, L: LargeSessionHandles>(
    session: &mut L,
    polypoints_map: HashMap<Role, NetworkValue<Z>>,
    num_secrets: usize,
) -> anyhow::Result<ShareDisputeOutputDouble<Z>> {
    send_to_honest_parties(&polypoints_map, session).await?;

    let senders = session.roles();
    let mut received_values = receive_from_parties_w_dispute(senders, session).await?;
    //Insert shares for my own sharing
    received_values.insert(
        session.my_role(),
        polypoints_map
            .get(&session.my_role())
            .ok_or_else(|| anyhow_error_and_log("Can not find my own share"))?
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
                "I had an incorrect type inside my own share sampling.",
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

pub(crate) async fn send_and_receive_share_dispute_single<Z: Ring, L: LargeSessionHandles>(
    session: &mut L,
    polypoints_map: HashMap<Role, NetworkValue<Z>>,
    num_secrets: usize,
) -> anyhow::Result<ShareDisputeOutput<Z>> {
    send_to_honest_parties(&polypoints_map, session).await?;

    let mut received_values = receive_from_parties_w_dispute(session.roles(), session).await?;

    //Insert shares for my own sharing
    received_values.insert(
        session.my_role(),
        polypoints_map
            .get(&session.my_role())
            .ok_or_else(|| {
                anyhow_error_and_log(format!(
                    "I am {} and can not find my own share",
                    session.my_role()
                ))
            })?
            .clone(),
    );

    //Recast polypoints_map to ring value instead of network value
    let polypoints_map = polypoints_map
        .into_iter()
        .map(|(role, net_value)| {
            if let NetworkValue::VecRingValue(value) = net_value {
                Ok((role, value))
            } else {
                Err(anyhow_error_and_log(
                    "I had an incorrect type inside my own share sampling.",
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
                //If other party sent me wrong type, replace with 0s
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
pub(crate) fn interpolate_poly_w_punctures<Z, R: Rng + CryptoRng>(
    rng: &mut R,
    num_parties: usize,
    threshold: usize,
    dispute_party_ids: Vec<usize>,
    secret: Z,
) -> anyhow::Result<Vec<Z>>
where
    Z: RingWithExceptionalSequence,
    Z: Invert,
{
    if threshold < dispute_party_ids.len() {
        return Err(anyhow_error_and_log(format!(
            "Too many disputes, {dispute_party_ids:?}, for threshold {threshold}",
        )));
    }
    let degree = threshold - dispute_party_ids.len();
    // make a random polynomial of degree threshold `dispute_party_ids`
    let base_poly = Poly::sample_random_with_fixed_constant(rng, secret, degree);
    // Modify the polynomial by increasing its degree with |dispute_party_ids| and ensuring the points
    // in `dispute_party_ids` gets y-value=0 and evaluate it for 1..num_parties
    let points = evaluate_w_new_roots(num_parties, dispute_party_ids, &base_poly)?;
    // check that the zero point is `secret`
    debug_assert_eq!(secret, points[0]);
    // exclude the point at x=0 (i.e. the secret)
    Ok(points[1..points.len()].to_vec())
}

//TODO: This function should be optimized with memoized calls to normalized_parties_root
/// Helper method for `punctured` polynomial interpolation.
/// Takes a base polynomial and increases its degree by multiplying roots of the form (1 - X/embed(i)) for each i in [points_of_new_roots].
/// Such that the new polynomial has same constant term, and evaluates to 0 at each embed(i) for i in [points_of_new_roots]
/// Then returns all the 0..[num_parties] points on the polynomial.
pub(crate) fn evaluate_w_new_roots<Z>(
    num_parties: usize,
    points_of_new_roots: Vec<usize>,
    base_poly: &Poly<Z>,
) -> anyhow::Result<Vec<Z>>
where
    Z: RingWithExceptionalSequence,
    Z: Invert,
{
    let (normalized_parties_root, x_coords) = Poly::<Z>::normalized_parties_root(num_parties)?;
    let mut poly = base_poly.clone();

    // poly will be of degree [threshold], zero at the points [x_coords], which reflect the party IDs embedded, and [secret] at 0
    for p in points_of_new_roots {
        poly = poly * normalized_parties_root[p - 1].clone();
    }
    // evaluate the poly at the embedded party indices
    let points: Vec<_> = (0..=num_parties).map(|p| poly.eval(&x_coords[p])).collect();
    Ok(points)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::evaluate_w_new_roots;
    use crate::execution::runtime::sessions::base_session::GenericBaseSessionHandles;
    use crate::execution::sharing::shamir::RevealOp;
    use crate::networking::NetworkMode;
    use crate::{
        algebra::{
            galois_rings::degree_4::{ResiduePolyF4, ResiduePolyF4Z128, ResiduePolyF4Z64},
            poly::Poly,
            structure_traits::{ErrorCorrect, Invert, Ring, Zero},
        },
        execution::{
            large_execution::share_dispute::{
                interpolate_poly_w_punctures, RealShareDispute, ShareDispute,
            },
            runtime::{party::Role, sessions::large_session::LargeSession},
            sharing::{shamir::ShamirSharings, share::Share},
        },
        tests::helper::tests::{
            execute_protocol_large_w_disputes_and_malicious, TestingParameters,
        },
    };
    use aes_prng::AesRng;
    use futures_util::future::join;
    use itertools::Itertools;
    use rand::SeedableRng;
    use rstest::rstest;
    use std::{collections::HashSet, num::Wrapping};
    use tracing_test::traced_test;

    /// Test share_dispute for different malicious strategies, doing both execute and execute_double
    /// Accepts a set of dispute pairs that will be inserted to the honest parties' sessions
    /// before executing the protocol
    async fn test_share_dispute_strategies<
        Z: ErrorCorrect + Invert,
        const EXTENSION_DEGREE: usize,
        S: ShareDispute + 'static,
    >(
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
            let _ = malicious_share_dispute
                .execute(&mut session, &secrets)
                .await;
            let _ = malicious_share_dispute
                .execute_double(&mut session, &secrets)
                .await;
        };

        let mut malicious_roles_with_dispute = HashSet::from_iter(malicious_due_to_dispute.clone());
        malicious_roles_with_dispute.extend(params.malicious_roles.clone());

        //Execute the protocol with malicious parties and added disputes
        //ShareDispute assumes Sync network
        let (result_honest, _) =
            execute_protocol_large_w_disputes_and_malicious::<_, _, _, _, _, Z, EXTENSION_DEGREE>(
                &params,
                &params.dispute_pairs,
                &malicious_roles_with_dispute,
                malicious_share_dispute,
                NetworkMode::Sync,
                None,
                &mut task_honest,
                &mut task_malicious,
            )
            .await;

        //Check that dispute (pi,pj) maps to 0 for pi and pj, malicious map to 0 for all
        //and otherwise share sent are share received between honest parties.
        //Also prepare the reconstruction vectors
        let mut reconstruction_vectors_single =
            vec![vec![Vec::<Share::<Z>>::default(); num_secrets]; params.num_parties];

        let mut reconstruction_vectors_double_t =
            vec![vec![Vec::<Share::<Z>>::default(); num_secrets]; params.num_parties];

        let mut reconstruction_vectors_double_2t =
            vec![vec![Vec::<Share::<Z>>::default(); num_secrets]; params.num_parties];

        for (role_pi, (_, output_single_pi, output_double_pi)) in result_honest.iter() {
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
                    reconstruction_vectors_single[role_pj][idx_share]
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
                    reconstruction_vectors_double_t[role_pj][idx_share]
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
                    reconstruction_vectors_double_2t[role_pj][idx_share]
                        .push(Share::new(*role_pi, *share_from_pj));
                }
            }
        }

        //Check correct reconstruction of all honest parties
        for (role_pi, (secrets_pi, _, _)) in result_honest {
            if !malicious_due_to_dispute.contains(&role_pi) {
                for (idx_secret, expected_secret) in secrets_pi.iter().enumerate() {
                    //Reconstruct the secret shared by execute
                    let reconst_single_t = ShamirSharings::create(
                        reconstruction_vectors_single[&role_pi][idx_secret].clone(),
                    )
                    .reconstruct(params.threshold);

                    //Reconstruct the secret of degree t shared by execute_double
                    let reconst_double_t = ShamirSharings::create(
                        reconstruction_vectors_double_t[&role_pi][idx_secret].clone(),
                    )
                    .reconstruct(params.threshold);

                    //Reconstruct the secret of degree 2t shared by execute_double
                    let reconst_double_2t = ShamirSharings::create(
                        reconstruction_vectors_double_2t[&role_pi][idx_secret].clone(),
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
    async fn test_share_dispute_honest_z128(#[case] params: TestingParameters) {
        let malicious_share_dispute = RealShareDispute::default();
        join(
            test_share_dispute_strategies::<
                ResiduePolyF4Z64,
                { ResiduePolyF4Z64::EXTENSION_DEGREE },
                _,
            >(params.clone(), malicious_share_dispute.clone()),
            test_share_dispute_strategies::<
                ResiduePolyF4Z128,
                { ResiduePolyF4Z128::EXTENSION_DEGREE },
                _,
            >(params.clone(), malicious_share_dispute.clone()),
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[rstest]
    #[case(TestingParameters::init(4, 1, &[0], &[], &[], false, None))]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[], false, None))]
    #[case(TestingParameters::init(4, 1, &[2], &[], &[], false, None))]
    #[case(TestingParameters::init(4, 1, &[3], &[], &[], false, None))]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[(1,3)], false, None))]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[(1,2),(0,3)], false, None))]
    #[case(TestingParameters::init(4, 1, &[2], &[], &[(0,2),(1,3)], false, None))]
    #[case(TestingParameters::init(7, 2, &[2,6], &[], &[(0,2),(1,3),(0,4),(1,5)], false, None))]
    async fn test_share_dispute_dropout(#[case] params: TestingParameters) {
        use crate::malicious_execution::large_execution::malicious_share_dispute::DroppingShareDispute;

        let dropping_share_dispute = DroppingShareDispute::default();
        join(
            test_share_dispute_strategies::<
                ResiduePolyF4Z64,
                { ResiduePolyF4Z64::EXTENSION_DEGREE },
                _,
            >(params.clone(), dropping_share_dispute.clone()),
            test_share_dispute_strategies::<
                ResiduePolyF4Z128,
                { ResiduePolyF4Z128::EXTENSION_DEGREE },
                _,
            >(params.clone(), dropping_share_dispute.clone()),
        )
        .await;
    }

    #[cfg(feature = "slow_tests")]
    #[rstest]
    #[case(TestingParameters::init(4, 1, &[0], &[], &[], false, None))]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[], false, None))]
    #[case(TestingParameters::init(4, 1, &[2], &[], &[], false, None))]
    #[case(TestingParameters::init(4, 1, &[3], &[], &[], false, None))]
    #[case(TestingParameters::init(4, 1, &[1], &[], &[(1,2),(0,3)], false, None))]
    #[case(TestingParameters::init(4, 1, &[2], &[], &[(0,2),(1,3)], false, None))]
    #[case(TestingParameters::init(7, 2, &[2,6], &[], &[(0,2),(1,3),(0,4),(1,5)], false, None))]
    async fn test_malicious_share_dispute(#[case] params: TestingParameters) {
        use crate::malicious_execution::large_execution::malicious_share_dispute::WrongShareDisputeRecons;

        let malicious_share_dispute_recons = WrongShareDisputeRecons::default();

        join(
            test_share_dispute_strategies::<
                ResiduePolyF4Z64,
                { ResiduePolyF4Z64::EXTENSION_DEGREE },
                _,
            >(params.clone(), malicious_share_dispute_recons.clone()),
            test_share_dispute_strategies::<
                ResiduePolyF4Z128,
                { ResiduePolyF4Z128::EXTENSION_DEGREE },
                _,
            >(params.clone(), malicious_share_dispute_recons.clone()),
        )
        .await;
    }

    #[traced_test]
    #[test]
    fn test_evaluate_w_zero_roots() {
        let parties = 4;
        let msg = 42;
        let zero_points = vec![1];
        // Constant base-poly
        let base = Poly::from_coefs(vec![ResiduePolyF4::from_scalar(Wrapping(msg))]);
        let res = evaluate_w_new_roots(parties, zero_points.clone(), &base).unwrap();
        // Check msg is in the constant
        assert_eq!(ResiduePolyF4::from_scalar(Wrapping::<u128>(msg)), res[0]);
        // Check that the zero_points are 0
        zero_points
            .iter()
            .for_each(|x| assert_eq!(ResiduePolyF4::ZERO, res[*x]));
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
            ResiduePolyF4::from_scalar(Wrapping::<u128>(msg)),
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
            ResiduePolyF4::from_scalar(Wrapping(msg)),
        )
        .unwrap();
        // Check that the points of dispuite_ids are 0
        dispute_ids
            .iter()
            .for_each(|x| assert_eq!(ResiduePolyF4::ZERO, interpolation[*x - 1]));
        // Map the y-points to their corresponding (not embedded) x-points
        let points = (1..parties)
            .map(|x| Share::new(Role::indexed_from_one(x), interpolation[x - 1]))
            .collect();
        let sham = ShamirSharings::create(points);
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
            ResiduePolyF4::from_scalar(Wrapping::<u128>(msg)),
        )
        .is_err());
    }
}

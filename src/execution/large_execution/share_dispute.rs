use std::collections::HashMap;

use crate::{
    execution::{
        p2p::exchange_values,
        party::Role,
        session::{BaseSessionHandles, LargeSession, LargeSessionHandles},
    },
    poly::Poly,
    residue_poly::ResiduePoly,
    value::{NetworkValue, Value},
    One, Zero, Z128,
};
use anyhow::anyhow;
use rand::RngCore;

#[allow(dead_code)]
pub enum ShareableInput {
    Ring(Z128),
    PolyRing(ResiduePoly<Z128>),
}

/// Secret shares a value `input` with the other parties while handling disputes.
/// That is, in case of malicious behaviour detected by a party they will be added to dispute
// TODO remove this dead code annotation once the code using shareDispute gets implemented
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
            .map(|id| id.0 as usize)
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
                Role((i + 1) as u64),
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
    session.add_dispute(&disputed_parties).await?;
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
    if threshold <= dispute_party_ids.len() {
        return Err(anyhow!(
            "Too many disputess, {}, for threshold {}",
            threshold,
            dispute_party_ids.len()
        ));
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
    use std::{collections::HashSet, num::Wrapping};

    use rand::SeedableRng;
    use rand_chacha::{ChaCha12Rng, ChaCha20Rng};
    use tokio::task::JoinSet;
    use tracing_test::traced_test;

    use crate::{
        computation::SessionId,
        execution::{
            distributed::DistributedTestRuntime,
            large_execution::share_dispute::interpolate_poly_w_punctures,
            party::Role,
            session::{DisputeSet, LargeSession},
        },
        poly::Poly,
        residue_poly::ResiduePoly,
        shamir::ShamirGSharings,
        tests::helper::tests::{generate_identities, get_large_session},
        Zero, Z128,
    };

    use super::{evaluate_w_zero_roots, share_w_dispute, ShareableInput};

    #[traced_test]
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
            let shared_val = *share.unwrap().get(&Role(1)).unwrap();
            assert_eq!(msg, shared_val.coefs[0]);
            shared_val.coefs[1..]
                .iter()
                .for_each(|c| assert_eq!(Z128::ZERO, *c))
        });
    }

    #[traced_test]
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
            let own_role = Role::from(party_no as u64 + 1);
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
                    .get(&Role((received_from_role + 1) as u64))
                    .unwrap();
                poly_points.push((cur_role.0 as usize, *shared_val));
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

    #[traced_test]
    #[test]
    fn test_sharing_with_dispute() {
        let msg = Wrapping(42);
        let identities = generate_identities(5);
        let threshold = 3;
        let mut dispute_roles = DisputeSet::new(identities.len());
        let dispute_party = Role(1);
        // Party 1 is in dispute
        for i in 1..=identities.len() as u64 {
            dispute_roles.add(&Role(i), &dispute_party).unwrap();
        }

        let test_runtime = DistributedTestRuntime::new(identities.clone(), threshold);
        let session_id = SessionId(1);

        let rt = tokio::runtime::Runtime::new().unwrap();
        let _guard = rt.enter();
        let mut set = JoinSet::new();
        for (party_no, _id) in identities.iter().cloned().enumerate() {
            let num_parties = identities.len();
            let own_role = Role::from(party_no as u64 + 1);
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
        for received_from_role in 1..identities.len() as u64 {
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
                        .get(&Role(received_from_role))
                        .unwrap();
                    // Check the shares for all the honest parties with the disputed party (i.e. party 1) is 0
                    if received_from_role == dispute_party.0 {
                        assert_eq!(ResiduePoly::ZERO, *shared_val);
                    } else {
                        assert_ne!(ResiduePoly::ZERO, *shared_val);
                    }
                    poly_points.push((executing_role.0 as usize, *shared_val));
                }
            }
            if received_from_role != dispute_party.0 {
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

    #[traced_test]
    #[test]
    fn test_interpolate_w_puncture() {
        let parties = 7;
        let threshold = 2;
        let msg = 42;
        let dispute_ids = vec![7];
        execute_interpolate_poly_w_punctures(msg, parties, threshold, dispute_ids);
    }

    #[traced_test]
    #[test]
    fn test_no_disputes() {
        let parties = 7;
        let threshold = 2;
        let msg = 42;
        let dispute_ids = vec![];
        execute_interpolate_poly_w_punctures(msg, parties, threshold, dispute_ids);
    }

    #[traced_test]
    #[test]
    fn test_too_many_disputes() {
        let parties = 7;
        let threshold = 2;
        let msg = 42;
        let dispute_ids = vec![6, 7];
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

    #[traced_test]
    #[test]
    fn zero_degree_interpolate_w_puncture() {
        let parties = 4;
        let threshold = 1;
        let msg = 42;
        let dispute_ids = vec![1]; // too many disputes since the threshold is 1
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

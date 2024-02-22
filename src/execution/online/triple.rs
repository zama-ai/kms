use crate::{
    algebra::structure_traits::Ring,
    error::error_handler::anyhow_error_and_log,
    execution::{
        runtime::session::BaseSessionHandles,
        sharing::{open::robust_opens_to_all, shamir::ErrorCorrect, share::Share},
    },
};
use anyhow::Context;
use itertools::Itertools;
use rand::{CryptoRng, Rng};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Triple<R>
where
    R: Ring + Sync,
{
    pub a: Share<R>,
    pub b: Share<R>,
    pub c: Share<R>,
}
impl<R: Ring + Sync> Triple<R> {
    pub fn new(a: Share<R>, b: Share<R>, c: Share<R>) -> Self {
        Self { a, b, c }
    }

    pub fn take(&self) -> (Share<R>, Share<R>, Share<R>) {
        (self.a, self.b, self.c)
    }
}

/// Multiplication of two shares using a triple.
/// Concretely computing the following:
///     [epsilon]   =[x]+[triple.a]
///     [rho]       =[y]+[triple.b]
///     Open        [epsilon], [rho]
///     Output [z]  =[y]*epsilon-[triple.a]*rho+[triple.c]
pub async fn mult<
    Z: Ring + ErrorCorrect,
    Rnd: Rng + CryptoRng + Send + Sync,
    Ses: BaseSessionHandles<Rnd>,
>(
    x: Share<Z>,
    y: Share<Z>,
    triple: Triple<Z>,
    session: &Ses,
) -> anyhow::Result<Share<Z>> {
    let res = mult_list(&[x], &[y], vec![triple], session).await?;
    match res.first() {
        Some(res) => Ok(*res),
        None => Err(anyhow_error_and_log(
            "Mult_list did not return a result".to_string(),
        )),
    }
}

/// Pairwise multiplication of two vectors of shares using a vector of triples
/// Concretely computing the following entry-wise on the input vectors:
///     [epsilon]   =[x]+[triple.a]
///     [rho]       =[y]+[triple.b]
///     Open        [epsilon], [rho]
///     Output [z]  =[y]*epsilon-[triple.a]*rho+[triple.c]
pub async fn mult_list<
    Z: Ring + ErrorCorrect,
    Rnd: Rng + CryptoRng + Sync,
    Ses: BaseSessionHandles<Rnd>,
>(
    x_vec: &[Share<Z>],
    y_vec: &[Share<Z>],
    triples: Vec<Triple<Z>>,
    session: &Ses,
) -> anyhow::Result<Vec<Share<Z>>> {
    let amount = x_vec.len();
    if amount != y_vec.len() || amount != triples.len() {
        return Err(anyhow_error_and_log(format!(
            "Trying to multiply two lists of values using a list of triple, but they are not of equal length: a_vec: {:?}, b_vec: {:?}, triples: {:?}",
            amount,
            y_vec.len(),
            triples.len()
        )));
    }
    let mut to_open = Vec::with_capacity(2 * amount);
    // Compute the shares of epsilon and rho and merge them together into a single list
    for ((cur_x, cur_y), cur_trip) in x_vec.iter().zip(y_vec).zip(&triples) {
        if cur_x.owner() != cur_y.owner()
            || cur_trip.a.owner() != cur_x.owner()
            || cur_trip.b.owner() != cur_x.owner()
            || cur_trip.c.owner() != cur_x.owner()
        {
            tracing::warn!("Trying to multiply with shares of different owners. This will always result in an incorrect share");
        }
        let share_epsilon = cur_trip.a + *cur_x;
        let share_rho = cur_trip.b + *cur_y;
        to_open.push(share_epsilon);
        to_open.push(share_rho);
    }
    // Open and seperate the list of both epsilon and rho values into two lists of values
    let mut epsilonrho = open_list(&to_open, session).await?;
    let mut epsilon_vec = Vec::with_capacity(amount);
    let mut rho_vec = Vec::with_capacity(amount);
    // Indicator variable if the current element is an eprilson value (or rho value)
    let mut epsilon_val = false;
    // Go through the list from the back
    while let Some(cur_val) = epsilonrho.pop() {
        match epsilon_val {
            true => epsilon_vec.push(cur_val),
            false => rho_vec.push(cur_val),
        }
        // Flip the indicator
        epsilon_val = !epsilon_val;
    }
    // Compute the linear equation of shares to get the result
    let mut res = Vec::with_capacity(amount);
    for i in 0..amount {
        let y = *y_vec.get(i).with_context(|| "Missing y value")?;
        // Observe that the list of epsilons and rhos have already been reversed above, because of the use of pop,
        // so we get the elements in the original order by popping again here
        let epsilon = epsilon_vec.pop().with_context(|| "Missing epsilon value")?;
        let rho = rho_vec.pop().with_context(|| "Missing rho value")?;
        let trip = triples.get(i).with_context(|| "Missing triple")?;
        res.push(y * epsilon - trip.a * rho + trip.c);
    }
    Ok(res)
}

// Open a single share
pub async fn open<
    Z: Ring + ErrorCorrect,
    Rnd: Rng + CryptoRng + Send + Sync,
    Ses: BaseSessionHandles<Rnd>,
>(
    to_open: Share<Z>,
    session: &Ses,
) -> anyhow::Result<Z> {
    let res = open_list(&[to_open], session).await?;
    match res.first() {
        Some(res) => Ok(*res),
        None => Err(anyhow_error_and_log(
            "Open_list did not return a result".to_string(),
        )),
    }
}

/// Opens a list of shares to all parties
pub async fn open_list<
    Z: Ring + ErrorCorrect,
    Rnd: Rng + CryptoRng + Sync,
    Ses: BaseSessionHandles<Rnd>,
>(
    to_open: &[Share<Z>],
    session: &Ses,
) -> anyhow::Result<Vec<Z>> {
    let parsed_to_open = to_open
        .iter()
        .map(|cur_open| cur_open.value())
        .collect_vec();
    // TODO should be updated to the async one when #217 is complete
    let opened_vals: Vec<Z> =
        match robust_opens_to_all(session, &parsed_to_open, session.threshold() as usize).await? {
            Some(opened_vals) => opened_vals,
            None => return Err(anyhow_error_and_log("Could not open shares".to_string())),
        };
    Ok(opened_vals)
}

#[cfg(test)]
mod tests {
    use super::Share;
    use crate::{
        algebra::{
            base_ring::{Z128, Z64},
            residue_poly::ResiduePoly,
        },
        execution::{
            online::{
                preprocessing::{
                    dummy::DummyPreprocessing, RandomPreprocessing, TriplePreprocessing,
                },
                triple::{mult, mult_list, open_list},
            },
            runtime::party::Role,
            runtime::session::{ParameterHandles, SmallSession},
        },
        tests::helper::tests_and_benches::execute_protocol_small,
    };
    use aes_prng::AesRng;
    use paste::paste;
    use std::num::Wrapping;

    macro_rules! test_triples {
        ($z:ty, $u:ty) => {
            paste! {
                // Multiply random values and open the random values and the result
                #[test]
                fn [<mult_sunshine_ $z:lower>]() {
                    let parties = 4;
                    let threshold = 1;
                    async fn task(session: SmallSession<ResiduePoly<$z>>) -> Vec<ResiduePoly<$z>> {
                        let mut preprocessing = DummyPreprocessing::<ResiduePoly<$z>, AesRng, SmallSession<ResiduePoly<$z>>>::new(42, session.clone());
                        let cur_a = preprocessing.next_random().unwrap();
                        let cur_b = preprocessing.next_random().unwrap();
                        let trip = preprocessing.next_triple().unwrap();
                        let cur_c = mult(cur_a, cur_b, trip, &session).await.unwrap();
                        open_list(&[cur_a, cur_b, cur_c], &session).await.unwrap()
                    }

                    // expect 2 rounds: 1 for multiplication and 1 for opening
                    let results = execute_protocol_small(parties, threshold, Some(2), &mut task);
                    assert_eq!(results.len(), parties);

                    for cur_res in results {
                        let recon_a = cur_res[0];
                        let recon_b = cur_res[1];
                        let recon_c = cur_res[2];
                        assert_eq!(recon_c, recon_a * recon_b);
                    }
                }

                // Multiply lists of random values and use repeated openings to open the random values and the result
                #[test]
                fn [<mult_list_sunshine_ $z:lower>]() {
                    let parties = 4;
                    let threshold = 1;
                    const AMOUNT: usize = 3;
                    async fn task(
                        session: SmallSession<ResiduePoly<$z>>,
                    ) -> (
                        Vec<ResiduePoly<$z>>,
                        Vec<ResiduePoly<$z>>,
                        Vec<ResiduePoly<$z>>,
                    ) {
                        let mut preprocessing = DummyPreprocessing::<ResiduePoly<$z>, AesRng, SmallSession<ResiduePoly<$z>>>::new(42, session.clone());
                        let mut a_vec = Vec::with_capacity(AMOUNT);
                        let mut b_vec = Vec::with_capacity(AMOUNT);
                        let mut trip_vec = Vec::with_capacity(AMOUNT);
                        for _i in 0..AMOUNT {
                            a_vec.push(preprocessing.next_random().unwrap());
                            b_vec.push(preprocessing.next_random().unwrap());
                            trip_vec.push(preprocessing.next_triple().unwrap());
                        }
                        let c_vec = mult_list(&a_vec, &b_vec, trip_vec, &session).await.unwrap();
                        let a_plain = open_list(&a_vec, &session).await.unwrap();
                        let b_plain = open_list(&b_vec, &session).await.unwrap();
                        let c_plain = open_list(&c_vec, &session).await.unwrap();
                        (a_plain, b_plain, c_plain)
                    }

                    // expect 4 rounds: 1 for bit multiplication and 3 for the separate openings
                    let results = execute_protocol_small(parties, threshold, Some(4), &mut task);
                    assert_eq!(results.len(), parties);
                    for (a_vec, b_vec, c_vec) in &results {
                        for i in 0..AMOUNT {
                            assert_eq!(
                                *c_vec.get(i).unwrap(),
                                *a_vec.get(i).unwrap() * *b_vec.get(i).unwrap()
                            );
                        }
                    }
                }

                // Multiply random values and open the random values and the result when a party drops out
                #[test]
                fn [<mult_party_drop_ $z:lower>]() {
                    let parties = 4;
                    let threshold = 1;
                    let bad_role: Role = Role::indexed_by_one(4);
                    let mut task = |session: SmallSession<ResiduePoly<$z>>| async move {
                        if session.my_role().unwrap() != bad_role {
                            let mut preprocessing = DummyPreprocessing::<ResiduePoly<$z>, AesRng, SmallSession<ResiduePoly<$z>>>::new(42, session.clone());
                            let cur_a = preprocessing.next_random().unwrap();
                            let cur_b = preprocessing.next_random().unwrap();
                            let trip = preprocessing.next_triple().unwrap();
                            let cur_c = mult(cur_a, cur_b, trip, &session).await.unwrap();
                            (
                                session.my_role().unwrap(),
                                open_list(&[cur_a, cur_b, cur_c], &session).await.unwrap(),
                            )
                        } else {
                            (session.my_role().unwrap(), Vec::new())
                        }
                    };

                    let results = execute_protocol_small(parties, threshold, None, &mut task);
                    assert_eq!(results.len(), parties);

                    for (cur_role, cur_res) in results {
                        if cur_role != bad_role {
                            let recon_a = cur_res[0];
                            let recon_b = cur_res[1];
                            let recon_c = cur_res[2];
                            assert_eq!(recon_c, recon_a * recon_b);
                        } else {
                            assert_eq!(Vec::<ResiduePoly<$z>>::new(), *cur_res);
                        }
                    }
                }

                // Multiply random values and open the random values and the result when a party uses a wrong value
                #[test]
                fn [<mult_wrong_value_ $z:lower>]() {
                    let parties = 4;
                    let threshold = 1;
                    let bad_role: Role = Role::indexed_by_one(4);
                    let mut task = |session: SmallSession<ResiduePoly<$z>>| async move {
                        let mut preprocessing = DummyPreprocessing::<ResiduePoly<$z>, AesRng, SmallSession<ResiduePoly<$z>>>::new(42, session.clone());
                        let cur_a = preprocessing.next_random().unwrap();
                        let cur_b = match session.my_role().unwrap() {
                            role if role == bad_role  => Share::new(bad_role, ResiduePoly::<$z>::from_scalar(Wrapping(42))),
                            _ => preprocessing.next_random().unwrap(),
                        };
                        let trip = preprocessing.next_triple().unwrap();
                        let cur_c = mult(cur_a, cur_b, trip, &session).await.unwrap();
                        open_list(&[cur_a, cur_b, cur_c], &session).await.unwrap()
                    };

                    let results = execute_protocol_small(parties, threshold, None, &mut task);
                    assert_eq!(results.len(), parties);

                    for cur_res in results {
                        let recon_a = cur_res[0];
                        let recon_b = cur_res[1];
                        let recon_c = cur_res[2];
                        assert_eq!(recon_c, recon_a * recon_b);
                    }
                }
            }
        };
    }
    test_triples![Z64, u64];
    test_triples![Z128, u128];
}

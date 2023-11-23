use crate::{
    error::error_handler::anyhow_error_and_log,
    execution::{distributed::robust_opens_to_all, session::BaseSessionHandles},
    poly::Ring,
    value::{self, Value},
};
use anyhow::Context;
use itertools::Itertools;
use rand::RngCore;

use super::share::Share;

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct Triple<R>
where
    R: Ring + std::convert::From<value::Value> + Send + Sync,
    value::Value: std::convert::From<R>,
{
    pub a: Share<R>,
    pub b: Share<R>,
    pub c: Share<R>,
}
impl<R: Ring + std::convert::From<value::Value> + Send + Sync> Triple<R>
where
    value::Value: std::convert::From<R>,
{
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
    R: Ring + std::convert::From<value::Value> + Send + Sync,
    Rnd: RngCore + Send + Sync,
    Ses: BaseSessionHandles<Rnd>,
>(
    x: Share<R>,
    y: Share<R>,
    triple: Triple<R>,
    session: &Ses,
) -> anyhow::Result<Share<R>>
where
    value::Value: std::convert::From<R>,
{
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
    R: Ring + std::convert::From<value::Value> + Send + Sync,
    Rnd: RngCore + Send + Sync,
    Ses: BaseSessionHandles<Rnd>,
>(
    x_vec: &[Share<R>],
    y_vec: &[Share<R>],
    triples: Vec<Triple<R>>,
    session: &Ses,
) -> anyhow::Result<Vec<Share<R>>>
where
    value::Value: std::convert::From<R>,
{
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
        let y = *y_vec.get(i).context("Missing y value")?;
        // Observe that the list of epsilons and rhos have already been reversed above, because of the use of pop,
        // so we get the elements in the original order by popping again here
        let epsilon = epsilon_vec.pop().context("Missing epsilon value")?;
        let rho = rho_vec.pop().context("Missing rho value")?;
        let trip = triples.get(i).context("Missing triple")?;
        res.push(y * epsilon - trip.a * rho + trip.c);
    }
    Ok(res)
}

// Open a single share
pub async fn open<
    R: Ring + std::convert::From<value::Value> + Send + Sync,
    Rnd: RngCore + Send + Sync,
    Ses: BaseSessionHandles<Rnd>,
>(
    to_open: Share<R>,
    session: &Ses,
) -> anyhow::Result<R>
where
    value::Value: std::convert::From<R>,
{
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
    R: Ring + std::convert::From<value::Value> + Send + Sync,
    Rnd: RngCore + Send + Sync,
    Ses: BaseSessionHandles<Rnd>,
>(
    to_open: &[Share<R>],
    session: &Ses,
) -> anyhow::Result<Vec<R>>
where
    value::Value: std::convert::From<R>,
{
    let parsed_to_open = to_open
        .iter()
        .map(|cur_open| Value::from(cur_open.value()))
        .collect_vec();
    let opened_vals: Vec<R> =
        match robust_opens_to_all(session, &parsed_to_open, session.threshold() as usize).await? {
            Some(opened_vals) => opened_vals
                .iter()
                .map(|cur_opened| R::from(cur_opened.clone()))
                .collect_vec(),
            None => return Err(anyhow_error_and_log("Could not open shares".to_string())),
        };
    Ok(opened_vals)
}

#[cfg(test)]
mod tests {
    use std::num::Wrapping;

    use super::Share;
    use crate::{
        execution::{
            online::{
                preprocessing::{DummyPreprocessing, Preprocessing},
                triple::{mult, mult_list, open_list},
            },
            party::Role,
            session::{ParameterHandles, SmallSession},
        },
        residue_poly::ResiduePoly,
        tests::helper::tests::execute_protocol_small,
        Z128, Z64,
    };
    use paste::paste;

    macro_rules! tests {
        ($z:ty, $u:ty) => {
            paste! {
                // Multiply random values and open the random values and the result
                #[test]
                fn [<mult_sunshine_ $z:lower>]() {
                    let parties = 4;
                    let threshold = 1;
                    async fn task(mut session: SmallSession) -> Vec<ResiduePoly<Wrapping<$u>>> {
                        let mut preprocessing = DummyPreprocessing::<$z>::new(42);
                        let cur_a = preprocessing.next_random(&mut session).unwrap();
                        let cur_b = preprocessing.next_random(&mut session).unwrap();
                        let trip = preprocessing.next_triple(&mut session).unwrap();
                        let cur_c = mult(cur_a, cur_b, trip, &session).await.unwrap();
                        open_list(&[cur_a, cur_b, cur_c], &session).await.unwrap()
                    }

                    let results = execute_protocol_small(parties, threshold, &mut task);
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
                        mut session: SmallSession,
                    ) -> (
                        Vec<ResiduePoly<Wrapping<$u>>>,
                        Vec<ResiduePoly<Wrapping<$u>>>,
                        Vec<ResiduePoly<Wrapping<$u>>>,
                    ) {
                        let mut preprocessing = DummyPreprocessing::<$z>::new(42);
                        let mut a_vec = Vec::with_capacity(AMOUNT);
                        let mut b_vec = Vec::with_capacity(AMOUNT);
                        let mut trip_vec = Vec::with_capacity(AMOUNT);
                        for _i in 0..AMOUNT {
                            a_vec.push(preprocessing.next_random(&mut session).unwrap());
                            b_vec.push(preprocessing.next_random(&mut session).unwrap());
                            trip_vec.push(preprocessing.next_triple(&mut session).unwrap());
                        }
                        let c_vec = mult_list(&a_vec, &b_vec, trip_vec, &session).await.unwrap();
                        let a_plain = open_list(&a_vec, &session).await.unwrap();
                        let b_plain = open_list(&b_vec, &session).await.unwrap();
                        let c_plain = open_list(&c_vec, &session).await.unwrap();
                        (a_plain, b_plain, c_plain)
                    }

                    let results = execute_protocol_small(parties, threshold, &mut task);
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
                    let mut task = |mut session: SmallSession| async move {
                        if session.my_role().unwrap() != bad_role {
                            let mut preprocessing = DummyPreprocessing::<$z>::new(42);
                            let cur_a = preprocessing.next_random(&mut session).unwrap();
                            let cur_b = preprocessing.next_random(&mut session).unwrap();
                            let trip = preprocessing.next_triple(&mut session).unwrap();
                            let cur_c = mult(cur_a, cur_b, trip, &session).await.unwrap();
                            (
                                session.my_role().unwrap(),
                                open_list(&[cur_a, cur_b, cur_c], &session).await.unwrap(),
                            )
                        } else {
                            (session.my_role().unwrap(), Vec::new())
                        }
                    };

                    let results = execute_protocol_small(parties, threshold, &mut task);
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
                    let mut task = |mut session: SmallSession| async move {
                        let mut preprocessing = DummyPreprocessing::<$z>::new(42);
                        let cur_a = preprocessing.next_random(&mut session).unwrap();
                        let cur_b = match session.my_role().unwrap() {
                            role if role == bad_role  => Share::new(bad_role, ResiduePoly::<$z>::from_scalar(Wrapping(42))),
                            _ => preprocessing.next_random(&mut session).unwrap(),
                        };
                        let trip = preprocessing.next_triple(&mut session).unwrap();
                        let cur_c = mult(cur_a, cur_b, trip, &session).await.unwrap();
                        open_list(&[cur_a, cur_b, cur_c], &session).await.unwrap()
                    };

                    let results = execute_protocol_small(parties, threshold, &mut task);
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
    tests![Z64, u64];
    tests![Z128, u128];
}

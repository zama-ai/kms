use crate::{
    algebra::structure_traits::{ErrorCorrect, Ring},
    error::error_handler::{anyhow_error_and_log, log_error_wrapper},
    execution::{
        runtime::session::BaseSessionHandles,
        sharing::{
            open::{RobustOpen, SecureRobustOpen},
            share::Share,
        },
    },
};
use anyhow::Context;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tracing::instrument;

#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Triple<R: Clone> {
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
pub async fn mult<Z: Ring + ErrorCorrect, Ses: BaseSessionHandles>(
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
#[instrument(name="MPC.Mult", skip(session,x_vec,y_vec,triples), fields(sid = ?session.session_id(),own_identity=?session.own_identity(),batch_size=?x_vec.len()))]
pub async fn mult_list<Z: Ring + ErrorCorrect, Ses: BaseSessionHandles>(
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
    //NOTE: That's a lot of memory manipulation, could execute the "linear equation loop" with epsilonrho directly
    // Open and seperate the list of both epsilon and rho values into two lists of values
    let mut epsilonrho = open_list(&to_open, session).await?;
    let mut epsilon_vec = Vec::with_capacity(amount);
    let mut rho_vec = Vec::with_capacity(amount);
    // Indicator variable if the current element is an epsilson value (or rho value)
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
        let y = *y_vec
            .get(i)
            .with_context(|| log_error_wrapper("Missing y value"))?;
        // Observe that the list of epsilons and rhos have already been reversed above, because of the use of pop,
        // so we get the elements in the original order by popping again here
        let epsilon = epsilon_vec
            .pop()
            .with_context(|| log_error_wrapper("Missing epsilon value"))?;
        let rho = rho_vec
            .pop()
            .with_context(|| log_error_wrapper("Missing rho value"))?;
        let trip = triples
            .get(i)
            .with_context(|| log_error_wrapper("Missing triple"))?;
        res.push(y * epsilon - trip.a * rho + trip.c);
    }
    Ok(res)
}

/// Opens a single secret
pub async fn open<Z: Ring + ErrorCorrect, Ses: BaseSessionHandles>(
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

/// Opens a list of secrets to all parties
#[instrument(name="MPC.Open",skip(to_open, session),fields(sid=?session.session_id(),own_identity=?session.own_identity(),batch_size=?to_open.len()))]
pub async fn open_list<Z: Ring + ErrorCorrect, Ses: BaseSessionHandles>(
    to_open: &[Share<Z>],
    session: &Ses,
) -> anyhow::Result<Vec<Z>> {
    let parsed_to_open = to_open
        .iter()
        .map(|cur_open| cur_open.value())
        .collect_vec();
    let opened_vals: Vec<Z> = match SecureRobustOpen::default()
        .robust_open_list_to_all(session, parsed_to_open, session.threshold() as usize)
        .await?
    {
        Some(opened_vals) => opened_vals,
        None => return Err(anyhow_error_and_log("Could not open shares".to_string())),
    };
    Ok(opened_vals)
}

#[cfg(test)]
mod tests {
    use super::Share;
    #[cfg(feature = "extension_degree_3")]
    use crate::algebra::galois_rings::degree_3::{ResiduePolyF3Z128, ResiduePolyF3Z64};
    #[cfg(feature = "extension_degree_5")]
    use crate::algebra::galois_rings::degree_5::{ResiduePolyF5Z128, ResiduePolyF5Z64};
    #[cfg(feature = "extension_degree_6")]
    use crate::algebra::galois_rings::degree_6::{ResiduePolyF6Z128, ResiduePolyF6Z64};
    #[cfg(feature = "extension_degree_7")]
    use crate::algebra::galois_rings::degree_7::{ResiduePolyF7Z128, ResiduePolyF7Z64};
    #[cfg(feature = "extension_degree_8")]
    use crate::algebra::galois_rings::degree_8::{ResiduePolyF8Z128, ResiduePolyF8Z64};
    use crate::{
        algebra::{
            galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64},
            structure_traits::Ring,
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
        networking::NetworkMode,
        tests::helper::tests_and_benches::execute_protocol_small,
    };
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
                    async fn task(session: SmallSession<$z>, _bot: Option<String>) -> Vec<$z> {
                        let mut preprocessing = DummyPreprocessing::<$z>::new(42, &session);
                        let cur_a = preprocessing.next_random().unwrap();
                        let cur_b = preprocessing.next_random().unwrap();
                        let trip = preprocessing.next_triple().unwrap();
                        let cur_c = mult(cur_a, cur_b, trip, &session).await.unwrap();
                        open_list(&[cur_a, cur_b, cur_c], &session).await.unwrap()
                    }

                    // expect 2 rounds: 1 for multiplication and 1 for opening
                    // Online phase so Async
                    //Delay P1 by 1s every round
                    let delay_vec = vec![tokio::time::Duration::from_secs(1)];
                    let results = execute_protocol_small::<_,_,$z,{$z::EXTENSION_DEGREE}>(parties, threshold, Some(2), NetworkMode::Async, Some(delay_vec), &mut task, None);
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
                        session: SmallSession<$z>,
                        _bot: Option<String>,
                    ) -> (
                        Vec<$z>,
                        Vec<$z>,
                        Vec<$z>,
                    ) {
                        let mut preprocessing = DummyPreprocessing::<$z>::new(42, &session);
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
                    // Online phase so Async
                    //Delay P1 by 1s every round
                    let delay_vec = vec![tokio::time::Duration::from_secs(1)];
                    let results = execute_protocol_small::<_,_,$z,{$z::EXTENSION_DEGREE}>(parties, threshold, Some(4), NetworkMode::Async,Some(delay_vec), &mut task, None);
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
                    let bad_role: Role = Role::indexed_from_one(4);
                    let mut task = |session: SmallSession<$z>, _bot: Option<String>| async move {
                        if session.my_role() != bad_role {
                            let mut preprocessing = DummyPreprocessing::<$z>::new(42, &session);
                            let cur_a = preprocessing.next_random().unwrap();
                            let cur_b = preprocessing.next_random().unwrap();
                            let trip = preprocessing.next_triple().unwrap();
                            let cur_c = mult(cur_a, cur_b, trip, &session).await.unwrap();
                            (
                                session.my_role(),
                                open_list(&[cur_a, cur_b, cur_c], &session).await.unwrap(),
                            )
                        } else {
                            (session.my_role(), Vec::new())
                        }
                    };

                    // Online phase so Async
                    //Delay P1 by 1s every round
                    let delay_vec = vec![tokio::time::Duration::from_secs(1)];
                    let results = execute_protocol_small::<_,_,$z,{$z::EXTENSION_DEGREE}>(parties, threshold, None, NetworkMode::Async, Some(delay_vec), &mut task, None);
                    assert_eq!(results.len(), parties);

                    for (cur_role, cur_res) in results {
                        if cur_role != bad_role {
                            let recon_a = cur_res[0];
                            let recon_b = cur_res[1];
                            let recon_c = cur_res[2];
                            assert_eq!(recon_c, recon_a * recon_b);
                        } else {
                            assert_eq!(Vec::<$z>::new(), *cur_res);
                        }
                    }
                }

                // Multiply random values and open the random values and the result when a party uses a wrong value
                #[test]
                fn [<mult_wrong_value_ $z:lower>]() {
                    let parties = 4;
                    let threshold = 1;
                    let bad_role: Role = Role::indexed_from_one(4);
                    let mut task = |session: SmallSession<$z>, _bot: Option<String>| async move {
                        let mut preprocessing = DummyPreprocessing::<$z>::new(42, &session);
                        let cur_a = preprocessing.next_random().unwrap();
                        let cur_b = match session.my_role() {
                            role if role == bad_role  => Share::new(bad_role, $z::from_scalar(Wrapping(42))),
                            _ => preprocessing.next_random().unwrap(),
                        };
                        let trip = preprocessing.next_triple().unwrap();
                        let cur_c = mult(cur_a, cur_b, trip, &session).await.unwrap();
                        open_list(&[cur_a, cur_b, cur_c], &session).await.unwrap()
                    };

                    // Online phase so Async
                    //Delay P1 by 1s every round
                    let delay_vec = vec![tokio::time::Duration::from_secs(1)];
                    let results = execute_protocol_small::<_,_,$z,{$z::EXTENSION_DEGREE}>(parties, threshold, None, NetworkMode::Async, Some(delay_vec), &mut task, None);
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

    test_triples![ResiduePolyF4Z64, u64];
    test_triples![ResiduePolyF4Z128, u128];

    #[cfg(feature = "extension_degree_3")]
    test_triples![ResiduePolyF3Z64, u64];

    #[cfg(feature = "extension_degree_3")]
    test_triples![ResiduePolyF3Z128, u128];

    #[cfg(feature = "extension_degree_5")]
    test_triples![ResiduePolyF5Z64, u64];

    #[cfg(feature = "extension_degree_5")]
    test_triples![ResiduePolyF5Z128, u128];

    #[cfg(feature = "extension_degree_6")]
    test_triples![ResiduePolyF6Z64, u64];

    #[cfg(feature = "extension_degree_6")]
    test_triples![ResiduePolyF6Z128, u128];

    #[cfg(feature = "extension_degree_7")]
    test_triples![ResiduePolyF7Z64, u64];

    #[cfg(feature = "extension_degree_7")]
    test_triples![ResiduePolyF7Z128, u128];

    #[cfg(feature = "extension_degree_8")]
    test_triples![ResiduePolyF8Z64, u64];

    #[cfg(feature = "extension_degree_8")]
    test_triples![ResiduePolyF8Z128, u128];
}

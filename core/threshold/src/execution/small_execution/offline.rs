use anyhow::Context;
use itertools::Itertools;
use std::collections::HashMap;
use tonic::async_trait;
use tracing::instrument;

use super::prss::PRSSPrimitives;
use crate::error::error_handler::log_error_wrapper;
use crate::execution::communication::broadcast::SyncReliableBroadcast;
use crate::execution::config::BatchParams;
use crate::execution::online::preprocessing::memory::InMemoryBasePreprocessing;
use crate::execution::online::preprocessing::{RandomPreprocessing, TriplePreprocessing};
use crate::execution::runtime::session::BaseSessionHandles;
use crate::execution::sharing::shamir::RevealOp;
use crate::thread_handles::spawn_compute_bound;
use crate::{
    algebra::structure_traits::{ErrorCorrect, Ring},
    execution::{
        communication::broadcast::Broadcast,
        online::triple::Triple,
        runtime::party::Role,
        runtime::session::SmallSessionHandles,
        sharing::{shamir::ShamirSharings, share::Share},
    },
    networking::value::BroadcastValue,
    ProtocolDescription,
};

#[async_trait]
pub trait Preprocessing<Z: Clone, S: BaseSessionHandles>:
    ProtocolDescription + Send + Sync
{
    /// Executes both GenTriples and NextRandom based on the given `batch_sizes`.
    async fn execute(
        &mut self,
        session: &mut S,
        batch_sizes: BatchParams,
    ) -> anyhow::Result<InMemoryBasePreprocessing<Z>>;
}

#[derive(Clone)]
pub struct RealSmallPreprocessing<BCast: Broadcast> {
    broadcast: BCast,
}

impl<BCast: Broadcast> ProtocolDescription for RealSmallPreprocessing<BCast> {
    fn protocol_desc(depth: usize) -> String {
        let indent = "   ".repeat(depth);
        format!(
            "{}-RealSmallPreprocessing:\n{}",
            indent,
            BCast::protocol_desc(depth + 1)
        )
    }
}

impl<BCast: Broadcast> RealSmallPreprocessing<BCast> {
    /// Creates an instance of a preprocessing protocol.
    pub fn new(broadcast: BCast) -> Self {
        Self { broadcast }
    }
}

impl<BCast: Broadcast + Default> Default for RealSmallPreprocessing<BCast> {
    fn default() -> Self {
        Self::new(BCast::default())
    }
}

/// Alias for [`RealSmallPreprocessing`] with a secure implementation of [`PRSSPrimitives`] and [`Broadcast`]
pub type SecureSmallPreprocessing = RealSmallPreprocessing<SyncReliableBroadcast>;

#[async_trait]
impl<
        Z: ErrorCorrect,
        // Note: Having the phantom data inside the struct definition
        // allows us to define this trait constraint.
        Ses: SmallSessionHandles<Z>,
        BCast: Broadcast,
    > Preprocessing<Z, Ses> for RealSmallPreprocessing<BCast>
{
    async fn execute(
        &mut self,
        small_session: &mut Ses,
        batch_sizes: BatchParams,
    ) -> anyhow::Result<InMemoryBasePreprocessing<Z>> {
        //We always want the session to use in-memory storage, it's up to higher level process (e.g. orchestrator)
        //to maybe decide to store data somewhere else
        let mut base_preprocessing = InMemoryBasePreprocessing::<Z>::default();

        // In case of malicious behavior not all triples might have been constructed, so we have to continue making triples until the batch is done
        while base_preprocessing.triples_len() < batch_sizes.triples {
            base_preprocessing.append_triples(
                next_triple_batch(
                    small_session,
                    batch_sizes.triples - base_preprocessing.triples_len(),
                    &self.broadcast,
                )
                .await?,
            );
        }
        if batch_sizes.randoms > 0 {
            base_preprocessing
                .append_randoms(next_random_batch(batch_sizes.randoms, small_session).await?);
        }
        Ok(base_preprocessing)
    }
}

/// Computes a new batch of random values and appends the new batch to the the existing stash of preprocessing random values.
#[instrument(name="MPC_Small.GenRandom",skip(amount,session), fields(sid= ?session.session_id(), my_role = ?session.my_role(), batch_size = ?amount))]
async fn next_random_batch<Z: Ring, Ses: SmallSessionHandles<Z>>(
    amount: usize,
    session: &mut Ses,
) -> anyhow::Result<Vec<Share<Z>>> {
    let my_role = session.my_role();
    //Create telemetry span to record all calls to PRSS.Next
    let res = session
        .prss_as_mut()
        .prss_next_vec(my_role, amount)
        .await?
        .into_iter()
        .map(|x| Share::new(my_role, x))
        .collect();
    Ok(res)
}

/// Constructs a new batch of triples and appends this to the internal triple storage.
/// If the method terminates correctly then an _entire_ new batch has been constructed and added to the internal stash.
/// If corruption occurs during the process then the corrupt parties are added to the corrupt set in `session` and the method
/// Caller then needs to retry to construct any missing triples, to ensure a full batch has been constructed before returning.
#[instrument(name="MPC_Small.GenTriples",skip(session,broadcast), fields(sid= ?session.session_id(), my_role = ?session.my_role(),batch_size = amount))]
async fn next_triple_batch<Z: ErrorCorrect, Ses: SmallSessionHandles<Z>, BCast: Broadcast>(
    session: &mut Ses,
    amount: usize,
    broadcast: &BCast,
) -> anyhow::Result<Vec<Triple<Z>>> {
    let counters = session.prss().get_counters();
    let my_role = session.my_role();
    let threshold = session.threshold();
    let prss_base_ctr = counters.prss_ctr;
    let przs_base_ctr = counters.przs_ctr;

    let all_prss = session
        .prss_as_mut()
        .prss_next_vec(my_role, 3 * amount)
        .await?;
    let vec_z_double: Vec<_> = session
        .prss_as_mut()
        .przs_next_vec(my_role, threshold, amount)
        .await?;

    let (vec_x_single, vec_y_single, vec_v_single, vec_d_double) = spawn_compute_bound( move ||{
    let mut all_prss = all_prss.into_iter();
    let vec_x_single: Vec<_> = all_prss.by_ref().take(amount).collect();
    let vec_y_single: Vec<_> = all_prss.by_ref().take(amount).collect();
    let vec_v_single: Vec<_> = all_prss.by_ref().take(amount).collect();

    if vec_x_single.len() != amount
        || vec_y_single.len() != amount
        || vec_v_single.len() != amount
        || vec_z_double.len() != amount
    {
        return Err(anyhow::anyhow!(
            "BUG: Not all expected values were generated, x={}, y={}, v={}, z={}. Expected {amount}.",
            vec_x_single.len(),
            vec_y_single.len(),
            vec_v_single.len(),
            vec_z_double.len(),
        ));
    }

    let res = vec_x_single
        .iter()
        .zip_eq(vec_y_single.iter())
        .zip_eq(vec_v_single.iter())
        .zip_eq(vec_z_double.into_iter())
        .map(|(((x, y), v), z)| *x * *y + (z + *v))
        .collect_vec();

    Ok((vec_x_single, vec_y_single, vec_v_single, res))
    }).await??;

    let broadcast_res = broadcast
        .broadcast_from_all_w_corrupt_set_update(session, vec_d_double.into())
        .await?;

    //Try reconstructing 2t sharings of d, a None means reconstruction failed.
    let recons_vec_d = reconstruct_d_values(session, amount, broadcast_res.clone()).await?;

    let mut triples = Vec::with_capacity(amount);
    let mut bad_triples_idx = Vec::new();
    for (i, (x, (y, z))) in vec_x_single
        .into_iter()
        .zip_eq(vec_y_single.into_iter().zip_eq(vec_v_single.into_iter()))
        .enumerate()
    {
        //If we managed to reconstruct, we store the triple
        if let Some(d) = recons_vec_d
            .get(i)
            .with_context(|| log_error_wrapper("Not all expected d values exist"))?
        {
            triples.push(Triple {
                a: Share::new(session.my_role(), x),
                b: Share::new(session.my_role(), y),
                c: Share::new(session.my_role(), d.to_owned() - z),
            });
        //If reconstruction failed, it's a bad triple and we will run cheater identification
        } else {
            bad_triples_idx.push(i);
        }
    }
    // If non-correctable malicious behaviour has been detected
    if !bad_triples_idx.is_empty() {
        // Recover the individual d shares from broadcast
        let d_shares = parse_d_shares(session, amount, broadcast_res)?;
        for i in bad_triples_idx {
            check_d(
                session,
                // Observe that each triple requires 3 calls to `prss_next`
                prss_base_ctr + (i as u128),
                przs_base_ctr + (i as u128),
                amount as u128,
                d_shares
                    .get(i)
                    .with_context(|| log_error_wrapper("Expected d share does not exist"))?
                    .to_owned(),
            )
            .await?;
        }
    }
    Ok(triples)
}

/// Helper method to parse the result of the broadcast by taking the ith share from each party and combine them in a vector for which reconstruction is then computed.
/// Returns a list of length `amount` which contains the reconstructed values.
/// In case a wrong amount of elements or a wrong type is returned then the culprit is added to the list of corrupt parties.
async fn reconstruct_d_values<Z, Ses: BaseSessionHandles>(
    session: &mut Ses,
    amount: usize,
    d_recons: HashMap<Role, BroadcastValue<Z>>,
) -> anyhow::Result<Vec<Option<Z>>>
where
    Z: ErrorCorrect,
{
    let mut collected_shares = vec![Vec::with_capacity(session.num_parties()); amount];
    // Go through the Role/value map of a broadcast of vectors of values and turn them into a vector of vectors of indexed values.
    // I.e. transpose the result and convert the role and value into indexed values
    for (cur_role, cur_values) in d_recons {
        match cur_values {
            BroadcastValue::RingVector(cur_values) => {
                if cur_values.len() != amount {
                    tracing::warn!(
                            "I am party {:?} and party {:?} did not broadcast the correct amount of shares and is thus malicious",
                            session.my_role().one_based(),
                            cur_role.one_based()
                        );
                    session.add_corrupt(cur_role);
                    continue;
                }
                // No need for zip_eq as we just checked the length
                for (cur_collect_share, cur_value) in
                    collected_shares.iter_mut().zip(cur_values.into_iter())
                {
                    cur_collect_share.push(Share::new(cur_role, cur_value));
                }
            }
            _ => {
                tracing::warn!(
                    "Party {:?} did not broadcast the correct type and is thus malicious",
                    cur_role.one_based()
                );
                session.add_corrupt(cur_role);
                continue;
            }
        };
    }

    // Check if there are enough honest parties to correct the errors
    if session.num_parties() - session.corrupt_roles().len() < 2 * session.threshold() as usize + 1
    {
        return Err(anyhow::anyhow!(
            "BUG: Not enough honest parties to correct the errors: {} honest parties, threshold={}",
            session.num_parties() - session.corrupt_roles().len(),
            session.threshold()
        ));
    }

    //We know we may not be able to correct all errors, thus we set max_errors to maximum number of errors the code can correct,
    //and deal with failure with the cheater identification strategy
    let degree = 2 * session.threshold() as usize;
    let max_errors = (session.num_parties() - session.corrupt_roles().len() - (degree + 1)) / 2;

    spawn_compute_bound(move || {
        collected_shares
            .into_iter()
            .map(|cur_collection| {
                let sharing = ShamirSharings::create(cur_collection);
                sharing.err_reconstruct(degree, max_errors).ok()
            })
            .collect_vec()
    })
    .await
}

/// Helper method which takes the list of d shares of each party (the result of the broadcast)
/// and parses it into a vector that stores at index i a map from the sending [Role] to their ith d share.
///
/// Note: In case we can not find a correct share for a Party, we set [None] as its share.
fn parse_d_shares<Z: Ring, Ses: BaseSessionHandles>(
    session: &mut Ses,
    amount: usize,
    d_recons: HashMap<Role, BroadcastValue<Z>>,
) -> anyhow::Result<Vec<HashMap<Role, Option<Z>>>> {
    let mut res = Vec::with_capacity(amount);
    for i in 0..amount {
        let mut cur_map = HashMap::new();
        for (cur_role, cur_values) in &d_recons {
            match cur_values {
                BroadcastValue::RingVector(cur_values) => {
                    if cur_values.len() > i {
                        cur_map.insert(*cur_role, Some(cur_values[i]));
                    } else {
                        tracing::warn!(
                            "I am party {:?} and party {:?} did not broadcast the correct amount of shares and is thus malicious",
                            session.my_role().one_based(),
                            cur_role.one_based());

                        cur_map.insert(*cur_role, None);
                    }
                }
                _ => {
                    tracing::warn!(
                        "Party {:?} did not broadcast the correct type and is thus malicious",
                        cur_role.one_based()
                    );
                    cur_map.insert(*cur_role, None);
                }
            };
        }
        res.push(cur_map);
    }
    Ok(res)
}

/// Output amount of PRSS.Next() calls
#[instrument(name="PRSS.Next",skip(session,amount),fields(sid=?session.session_id(),my_role=?session.my_role(),batch_size=?amount))]
fn prss_list<Z: Ring, Ses: SmallSessionHandles<Z>>(
    session: &mut Ses,
    amount: usize,
) -> anyhow::Result<Vec<Z>> {
    let my_id = session.my_role();
    let mut vec_prss = Vec::with_capacity(amount);
    for _i in 0..amount {
        vec_prss.push(session.prss_as_mut().prss_next(my_id)?);
    }
    Ok(vec_prss)
}

/// Output amount of PRZS.Next() calls
#[instrument(name="PRZS.Next",skip(session,amount),fields(sid=?session.session_id(),my_role=?session.my_role(),batch_size=?amount))]
fn przs_list<Z: Ring, Ses: SmallSessionHandles<Z>>(
    session: &mut Ses,
    amount: usize,
) -> anyhow::Result<Vec<Z>> {
    let my_id = session.my_role();
    let threshold = session.threshold();
    let mut vec_przs = Vec::with_capacity(amount);
    for _i in 0..amount {
        vec_przs.push(session.prss_as_mut().przs_next(my_id, threshold)?);
    }
    Ok(vec_przs)
}

/// Helper method for validating results when corruption has happened (by the reconstruction not being successful).
/// The method finds the corrupt parties (based on what they broadcast) and adds them to the list of corrupt parties in the session.
///
/// __NOTE__: This method could be batched.
async fn check_d<Z: Ring, Ses: SmallSessionHandles<Z>>(
    session: &mut Ses,
    prss_ctr: u128,
    przs_ctr: u128,
    amount: u128,
    shared_d_double: HashMap<Role, Option<Z>>,
) -> anyhow::Result<()> {
    //x is sampled first sot at given prss_ctr
    let vec_x = session.prss().prss_check(session, prss_ctr).await?;
    //y is sampled after all the xs so at prss_ctr + amount
    let vec_y = session
        .prss()
        .prss_check(session, prss_ctr + amount)
        .await?;
    //v is sampled after all the ys so at prss_ctr + 2*amount
    let vec_v = session
        .prss()
        .prss_check(session, prss_ctr + 2 * amount)
        .await?;
    let vec_z_double = session.prss().przs_check(session, przs_ctr).await?;

    for (cur_role, cur_d_share) in shared_d_double {
        let v_single = vec_v
            .get(&cur_role)
            .with_context(|| log_error_wrapper("Not all expected v check values exist"))?
            .to_owned();
        let z_double = vec_z_double
            .get(&cur_role)
            .with_context(|| log_error_wrapper("Not all expected z check values exist"))?
            .to_owned();
        let v_double = v_single + z_double;
        let x = vec_x
            .get(&cur_role)
            .with_context(|| log_error_wrapper("Not all expected x check values exist"))?
            .to_owned();
        let y = vec_y
            .get(&cur_role)
            .with_context(|| log_error_wrapper("Not all expected y check values exist"))?
            .to_owned();
        let d_prime_double = x * y + v_double;
        if cur_d_share.is_none() || cur_d_share.is_some_and(|d_share| d_prime_double != d_share) {
            tracing::warn!(
                "Party {cur_role} did not send correct values during PRSS-init and
                has been added to the list of corrupt parties"
            );
            session.add_corrupt(cur_role);
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use futures_util::future::join;
    use rstest::rstest;
    use std::{collections::HashMap, num::Wrapping};

    use crate::algebra::structure_traits::{ErrorCorrect, Invert, Ring};
    use crate::execution::communication::broadcast::SyncReliableBroadcast;
    use crate::execution::large_execution::vss::SecureVss;
    use crate::execution::runtime::session::ToBaseSession;
    use crate::execution::sharing::shamir::{RevealOp, ShamirSharings};
    use crate::execution::small_execution::agree_random::RobustSecureAgreeRandom;
    use crate::execution::small_execution::offline::reconstruct_d_values;
    use crate::execution::small_execution::prss::{
        DerivePRSSState, PRSSInit, RobustSecurePrssInit,
    };
    use crate::malicious_execution::runtime::malicious_session::GenericSmallSessionStruct;
    use crate::malicious_execution::small_execution::malicious_offline::{
        MaliciousOfflineDrop, MaliciousOfflineWrongAmount,
    };
    use crate::malicious_execution::small_execution::malicious_prss::{
        MaliciousPrssDrop, MaliciousPrssHonestInitLieAll, MaliciousPrssHonestInitRobustThenRandom,
    };
    use crate::networking::NetworkMode;
    use crate::tests::helper::tests::{execute_protocol_small_w_malicious, TestingParameters};
    use crate::tests::randomness_check::execute_all_randomness_tests_loose;
    use crate::{
        algebra::galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64},
        execution::{
            online::{
                preprocessing::{RandomPreprocessing, TriplePreprocessing},
                triple::Triple,
            },
            runtime::{
                party::Role,
                session::{BaseSessionHandles, ParameterHandles, SmallSession},
            },
            sharing::share::Share,
            small_execution::{
                offline::{BatchParams, Preprocessing, SecureSmallPreprocessing},
                prf::PRSSConversions,
            },
        },
        networking::value::BroadcastValue,
        tests::helper::testing::get_networkless_base_session_for_parties,
    };

    use super::RealSmallPreprocessing;

    // Needs to be big enough to cope with statistical tests
    // which require sequences of at least SAMPLE_COUNT (=100)
    const RANDOM_BATCH_SIZE: usize = 100;
    const TRIPLE_BATCH_SIZE: usize = 50;
    const BATCH_PARAMS: BatchParams = BatchParams {
        triples: TRIPLE_BATCH_SIZE,
        randoms: RANDOM_BATCH_SIZE,
    };

    /// Executes [`Preprocessing::execute`] for _small sessions_
    /// (i.e. generates [`RANDOM_BATCH_SIZE`] random and [`TRIPLE_BATCH_SIZE`] triples)
    /// with honest and malicious strategies where the identity of the malicious parties
    /// is dictated by the params.
    ///
    /// If [`TestingParameters::should_be_detected`] is set, we assert that the honest parties
    /// have inserted the malicious parties' identity in their corrupt set.
    /// We validate the results by making sure the honest parties can always reconstruct
    /// the output correlated randomness (and check that the triple relation holds).
    /// We include malicious parties' output in the reconstruction check if the malicious
    /// party did not panic.
    async fn test_offline_small_strategies<
        Z: ErrorCorrect + Invert + PRSSConversions,
        const EXTENSION_DEGREE: usize,
        PrssInitMalicious: PRSSInit<Z> + Default,
        PreprocMalicious: Preprocessing<
                Z,
                GenericSmallSessionStruct<
                    Z,
                    <PrssInitMalicious::OutputType as DerivePRSSState<Z>>::OutputType,
                >,
            > + Clone
            + 'static,
    >(
        params: TestingParameters,
        malicious_offline: PreprocMalicious,
    ) where
        <PrssInitMalicious::OutputType as DerivePRSSState<Z>>::OutputType: Clone,
    {
        let mut task_honest = |session: SmallSession<Z>| async move {
            // explicitly init the session
            // to be able to run different PRSS init strategies
            let base_session = session.to_base_session();
            let mut new_session = SmallSession::new_and_init_prss_state(base_session)
                .await
                .unwrap();
            let my_role = new_session.my_role();
            let mut honest_offline = SecureSmallPreprocessing::default();
            let preprocessing = honest_offline
                .execute(&mut new_session, BATCH_PARAMS)
                .await
                .unwrap();
            (new_session, my_role, preprocessing)
        };

        let mut task_malicious =
            |session: SmallSession<Z>, mut malicious_offline: PreprocMalicious| async move {
                // explicitly init the session
                // to be able to run different PRSS init strategies
                let base_session = session.to_base_session();
                let mut malicious_session = GenericSmallSessionStruct::new_and_init_prss_state(
                    base_session,
                    PrssInitMalicious::default(),
                )
                .await
                .unwrap();

                let my_role = malicious_session.my_role();
                let preprocessing = malicious_offline
                    .execute(&mut malicious_session, BATCH_PARAMS)
                    .await;
                (malicious_session, my_role, preprocessing)
            };

        let (results_honest, results_malicious) =
            execute_protocol_small_w_malicious::<_, _, _, _, _, Z, EXTENSION_DEGREE>(
                &params,
                &params.malicious_roles,
                malicious_offline,
                NetworkMode::Sync,
                None,
                &mut task_honest,
                &mut task_malicious,
            )
            .await;

        // If malicious behaviour should be detected, make sure it actually is
        if params.should_be_detected {
            for (session, _, _) in results_honest.values() {
                for role in params.malicious_roles.iter() {
                    assert!(
                        session.corrupt_roles().contains(role),
                        "Honest party's corrupt set does not contain the expected malicious party with role {role:?}"
                    );
                }
            }
        }

        // Make sure the honest parties can reconstruct fine
        let mut honest_preprocessings = results_honest
            .values()
            .map(|(_, _, hp)| hp)
            .cloned()
            .collect::<Vec<_>>();

        let mut malicious_preprocessings = results_malicious
            .into_iter()
            .filter_map(|(role, mp)| match mp {
                Ok((_, _, Ok(mp))) => Some((role, mp)),
                _ => None,
            })
            .collect::<HashMap<Role, _>>();

        // Works because all malicious strategies are identical and so they either all
        // output something or none do
        let num_malicious = if malicious_preprocessings.is_empty() {
            0
        } else {
            params.malicious_roles.len()
        };

        // Try and reconstruct the randoms and perform stat test
        let mut reconstructed_randoms = Vec::new();
        for _ in 0..RANDOM_BATCH_SIZE {
            let mut shares = ShamirSharings::default();
            for honest_preprocessing in honest_preprocessings.iter_mut() {
                shares.add_share(honest_preprocessing.next_random().unwrap());
            }
            for (role, malicious_preprocessing) in malicious_preprocessings.iter_mut() {
                shares.add_share(
                    malicious_preprocessing
                        .next_random()
                        .unwrap_or_else(|_| Share::new(*role, Z::ZERO)),
                );
            }
            let random = shares.err_reconstruct(params.threshold, num_malicious);
            assert!(random.is_ok(), "Failed to reconstruct random: {random:?}");
            reconstructed_randoms.push(random.unwrap());
        }

        let randomness_test = execute_all_randomness_tests_loose(&reconstructed_randoms);
        assert!(
            randomness_test.is_ok(),
            "Failed randomness test of random generation: {randomness_test:?}"
        );

        // Try and reconstruct the triples and perform stat test
        let mut reconstructed_x_y = Vec::new();
        for _ in 0..TRIPLE_BATCH_SIZE {
            let mut shares_x = ShamirSharings::default();
            let mut shares_y = ShamirSharings::default();
            let mut shares_z = ShamirSharings::default();
            for honest_preprocessing in honest_preprocessings.iter_mut() {
                let Triple { a: x, b: y, c: z } = honest_preprocessing.next_triple().unwrap();
                shares_x.add_share(x);
                shares_y.add_share(y);
                shares_z.add_share(z);
            }
            for (role, malicious_preprocessing) in malicious_preprocessings.iter_mut() {
                let Triple { a: x, b: y, c: z } = malicious_preprocessing
                    .next_triple()
                    .unwrap_or_else(|_| Triple {
                        a: Share::new(*role, Z::ZERO),
                        b: Share::new(*role, Z::ZERO),
                        c: Share::new(*role, Z::ZERO),
                    });
                shares_x.add_share(x);
                shares_y.add_share(y);
                shares_z.add_share(z);
            }
            let (x, y, z) = (
                shares_x.err_reconstruct(params.threshold, num_malicious),
                shares_y.err_reconstruct(params.threshold, num_malicious),
                shares_z.err_reconstruct(params.threshold, num_malicious),
            );
            assert!(
                x.is_ok(),
                "Failed to reconstruct x component of triple: {x:?}"
            );
            assert!(
                y.is_ok(),
                "Failed to reconstruct y component of triple: {y:?}"
            );
            assert!(
                z.is_ok(),
                "Failed to reconstruct z component of triple: {z:?}"
            );
            let (x, y, z) = (x.unwrap(), y.unwrap(), z.unwrap());
            assert!(z == (x * y), "Triple does not verifiy z = x*y");
            reconstructed_x_y.push(x);
            reconstructed_x_y.push(y);
        }

        println!("{:?}", reconstructed_x_y);
        let randomness_test = execute_all_randomness_tests_loose(&reconstructed_x_y);
        assert!(
            randomness_test.is_ok(),
            "Failed randomness test of triple generation (x and y components): {randomness_test:?}"
        );
    }

    // Test small offline generation with no malicious parties
    // Expected number of rounds is:
    // - 5 + t for robust PRSS init
    // - 3 + t for broadcast
    // total = 8 + 2t
    #[rstest]
    #[case(TestingParameters::init(4, 1, &[], &[], &[], false, Some(10)))]
    #[case(TestingParameters::init(5, 1, &[], &[], &[], false, Some(10)))]
    #[case(TestingParameters::init(7, 2, &[], &[], &[], false, Some(12)))]
    #[case(TestingParameters::init(10, 3, &[], &[], &[], false, Some(14)))]
    async fn test_offline_small(#[case] params: TestingParameters) {
        join(
            test_offline_small_strategies::<
                ResiduePolyF4Z128,
                { ResiduePolyF4Z128::EXTENSION_DEGREE },
                RobustSecurePrssInit,
                _,
            >(params.clone(), SecureSmallPreprocessing::default()),
            test_offline_small_strategies::<
                ResiduePolyF4Z64,
                { ResiduePolyF4Z64::EXTENSION_DEGREE },
                RobustSecurePrssInit,
                _,
            >(params, SecureSmallPreprocessing::default()),
        )
        .await;
    }

    #[rstest]
    #[case(TestingParameters::init(4, 1, &[2], &[], &[], true, None))]
    #[case(TestingParameters::init(5, 1, &[1], &[], &[], true, None))]
    #[case(TestingParameters::init(7, 2, &[4,5], &[], &[], true, None))]
    #[case(TestingParameters::init(10, 3, &[1,3,7], &[], &[], true, None))]
    async fn test_dropout_offline_small_from_start(#[case] params: TestingParameters) {
        join(
            test_offline_small_strategies::<
                ResiduePolyF4Z128,
                { ResiduePolyF4Z128::EXTENSION_DEGREE },
                MaliciousPrssDrop,
                _,
            >(params.clone(), MaliciousOfflineDrop::default()),
            test_offline_small_strategies::<
                ResiduePolyF4Z64,
                { ResiduePolyF4Z64::EXTENSION_DEGREE },
                MaliciousPrssDrop,
                _,
            >(params, MaliciousOfflineDrop::default()),
        )
        .await;
    }

    #[rstest]
    #[case(TestingParameters::init(4, 1, &[2], &[], &[], true, None))]
    #[case(TestingParameters::init(5, 1, &[1], &[], &[], true, None))]
    #[case(TestingParameters::init(7, 2, &[4,5], &[], &[], true, None))]
    #[case(TestingParameters::init(10, 3, &[1,3,7], &[], &[], true, None))]
    async fn test_dropout_offline_small_after_init(#[case] params: TestingParameters) {
        join(
            test_offline_small_strategies::<
                ResiduePolyF4Z128,
                { ResiduePolyF4Z128::EXTENSION_DEGREE },
                RobustSecurePrssInit,
                _,
            >(params.clone(), MaliciousOfflineDrop::default()),
            test_offline_small_strategies::<
                ResiduePolyF4Z64,
                { ResiduePolyF4Z64::EXTENSION_DEGREE },
                RobustSecurePrssInit,
                _,
            >(params, MaliciousOfflineDrop::default()),
        )
        .await;
    }

    #[rstest]
    #[case(TestingParameters::init(4, 1, &[2], &[], &[], true, None))]
    #[case(TestingParameters::init(5, 1, &[1], &[], &[], true, None))]
    #[case(TestingParameters::init(7, 2, &[4,5], &[], &[], true, None))]
    #[case(TestingParameters::init(10, 3, &[1,3,7], &[], &[], true, None))]
    async fn test_malicious_wrongamount_offline_small(#[case] params: TestingParameters) {
        join(
            test_offline_small_strategies::<
                ResiduePolyF4Z128,
                { ResiduePolyF4Z128::EXTENSION_DEGREE },
                RobustSecurePrssInit,
                _,
            >(
                params.clone(),
                MaliciousOfflineWrongAmount::new(SyncReliableBroadcast::default()),
            ),
            test_offline_small_strategies::<
                ResiduePolyF4Z64,
                { ResiduePolyF4Z64::EXTENSION_DEGREE },
                RobustSecurePrssInit,
                _,
            >(
                params,
                MaliciousOfflineWrongAmount::new(SyncReliableBroadcast::default()),
            ),
        )
        .await;
    }

    #[rstest]
    #[case(TestingParameters::init(4, 1, &[2], &[], &[], true, None))]
    //with (5,1) we are able to reconstruct so we don't run the unhappy path and don't catch malicious party
    #[case(TestingParameters::init(5, 1, &[1], &[], &[], false, None))]
    #[case(TestingParameters::init(7, 2, &[4,5], &[], &[], true, None))]
    #[case(TestingParameters::init(10, 3, &[1,3,7], &[], &[], true, None))]
    async fn test_malicious_wrongprss_offline_small(#[case] params: TestingParameters) {
        type MaliciousPrss<Z> = MaliciousPrssHonestInitRobustThenRandom<
            RobustSecureAgreeRandom,
            SecureVss,
            SyncReliableBroadcast,
            Z,
        >;

        join(
            test_offline_small_strategies::<
                ResiduePolyF4Z128,
                { ResiduePolyF4Z128::EXTENSION_DEGREE },
                MaliciousPrss<ResiduePolyF4Z128>,
                _,
            >(
                params.clone(),
                RealSmallPreprocessing::<SyncReliableBroadcast>::default(),
            ),
            test_offline_small_strategies::<
                ResiduePolyF4Z64,
                { ResiduePolyF4Z64::EXTENSION_DEGREE },
                MaliciousPrss<ResiduePolyF4Z64>,
                _,
            >(
                params,
                RealSmallPreprocessing::<SyncReliableBroadcast>::default(),
            ),
        )
        .await;
    }

    #[rstest]
    #[case(TestingParameters::init(4, 1, &[2], &[], &[], true, None))]
    //with (5,1) we are able to reconstruct so we don't run the unhappy path and don't catch malicious party
    #[case(TestingParameters::init(5, 1, &[1], &[], &[], false, None))]
    #[case(TestingParameters::init(7, 2, &[4,5], &[], &[], true, None))]
    #[case(TestingParameters::init(10, 3, &[1,3,7], &[], &[], true, None))]
    async fn test_malicious_wrongprss_wrongcheck_offline_small(#[case] params: TestingParameters) {
        type MaliciousPrss<Z> = MaliciousPrssHonestInitLieAll<
            RobustSecureAgreeRandom,
            SecureVss,
            SyncReliableBroadcast,
            Z,
        >;

        join(
            test_offline_small_strategies::<
                ResiduePolyF4Z128,
                { ResiduePolyF4Z128::EXTENSION_DEGREE },
                MaliciousPrss<ResiduePolyF4Z128>,
                _,
            >(
                params.clone(),
                RealSmallPreprocessing::<SyncReliableBroadcast>::default(),
            ),
            test_offline_small_strategies::<
                ResiduePolyF4Z64,
                { ResiduePolyF4Z64::EXTENSION_DEGREE },
                MaliciousPrss<ResiduePolyF4Z64>,
                _,
            >(
                params,
                RealSmallPreprocessing::<SyncReliableBroadcast>::default(),
            ),
        )
        .await;
    }

    /// Unit testing of [`reconstruct_d_values`]
    /// Test what happens when a party send a wrong type of value
    #[tracing_test::traced_test]
    #[tokio::test]
    async fn test_wrong_type() {
        let mut session = get_networkless_base_session_for_parties(4, 1, Role::indexed_from_one(1));
        // Observe party 1 inputs a vector of size 1 and party 2 inputs a single element
        let d_recons = HashMap::from([
            (
                Role::indexed_from_one(1),
                BroadcastValue::RingVector(Vec::from([ResiduePolyF4Z128::from_scalar(Wrapping(
                    42,
                ))])),
            ),
            (
                Role::indexed_from_one(2),
                BroadcastValue::RingValue(ResiduePolyF4Z128::from_scalar(Wrapping(13))),
            ),
        ]);
        assert!(session.corrupt_roles().is_empty());
        let res = reconstruct_d_values(&mut session, 1, d_recons)
            .await
            .unwrap();
        assert_eq!(1, session.corrupt_roles().len());
        assert!(session.corrupt_roles().contains(&Role::indexed_from_one(2)));
        assert!(logs_contain(
            "did not broadcast the correct type and is thus malicious"
        ));
        assert_eq!(1, res.len());
        let first = res.first();
        assert!(first.is_some());
    }
}

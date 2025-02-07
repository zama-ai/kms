use anyhow::Context;
use itertools::Itertools;
use rand::{CryptoRng, Rng};
use std::collections::HashMap;
use tracing::{info_span, instrument};

use super::{agree_random::AgreeRandom, prf::PRSSConversions};
use crate::error::error_handler::log_error_wrapper;
use crate::execution::config::BatchParams;
use crate::execution::online::preprocessing::memory::InMemoryBasePreprocessing;
use crate::execution::online::preprocessing::{
    BasePreprocessing, RandomPreprocessing, TriplePreprocessing,
};
use crate::execution::runtime::session::BaseSessionHandles;
use crate::execution::sharing::shamir::RevealOp;
use crate::{
    algebra::structure_traits::{ErrorCorrect, Invert, Ring, RingEmbed},
    execution::{
        communication::broadcast::broadcast_from_all_w_corruption,
        online::triple::Triple,
        runtime::party::Role,
        runtime::session::SmallSessionHandles,
        sharing::{shamir::ShamirSharings, share::Share},
    },
    networking::value::BroadcastValue,
};

/// Preprocessing for a single small session using a specific functionality for [A] for the [AgreeRandom] trait.
pub struct SmallPreprocessing<Z: Ring, A> {
    batch_sizes: BatchParams,
    elements: Box<dyn BasePreprocessing<Z>>,
    _marker: std::marker::PhantomData<A>,
}

impl<Z, A: AgreeRandom + Send + Sync> SmallPreprocessing<Z, A>
where
    Z: PRSSConversions,
    Z: RingEmbed,
    Z: ErrorCorrect,
    Z: Invert,
{
    /// Initializes the preprocessing for a new epoch, by preprocessing a batch
    /// We require a [`SmallSessionHandles`] which implicitly require an initialized PRSS
    /// Init also executes automatically GenTriples and NextRandom based on the provided [`BatchParams`]
    pub async fn init<Rnd: Rng + CryptoRng, Ses: SmallSessionHandles<Z, Rnd>>(
        session: &mut Ses,
        batch_sizes: BatchParams,
    ) -> anyhow::Result<Self> {
        let batch = batch_sizes;
        //We always want the session to use in-memory storage, it's up to higher level process (e.g. orchestrator)
        //to maybe decide to store data somewhere else
        let base_preprocessing = Box::<InMemoryBasePreprocessing<Z>>::default();

        let mut res = SmallPreprocessing::<Z, A> {
            batch_sizes: batch,
            elements: base_preprocessing,
            _marker: std::marker::PhantomData,
        };
        // In case of malicious behavior not all triples might have been constructed, so we have to continue making triples until the batch is done
        while res.triples_len() < res.batch_sizes.triples {
            res.next_triple_batch(
                session,
                res.batch_sizes.triples - res.elements.triples_len(),
            )
            .await?;
        }
        if batch.randoms > 0 {
            res.next_random_batch(session).await?;
        }
        Ok(res)
    }

    /// Computes a new batch of random values and appends the new batch to the the existing stash of preprocessing random values.
    #[instrument(name="MPC_Small.GenRandom",skip(self,session), fields(sid= ?session.session_id(), own_identity = ?session.own_identity(),batch_size = ?self.batch_sizes.randoms))]
    async fn next_random_batch<Rnd: Rng + CryptoRng, Ses: SmallSessionHandles<Z, Rnd>>(
        &mut self,
        session: &mut Ses,
    ) -> anyhow::Result<()> {
        let my_role = session.my_role()?;
        //Create telemetry span to record all calls to PRSS.Next
        let prss_span = info_span!("PRSS.Next", batch_size = self.batch_sizes.randoms);
        let res = prss_span.in_scope(|| {
            let mut res = Vec::with_capacity(self.batch_sizes.randoms);
            for _ in 0..self.batch_sizes.randoms {
                res.push(Share::new(
                    my_role,
                    session.prss_as_mut().prss_next(my_role)?,
                ));
            }
            Ok::<_, anyhow::Error>(res)
        })?;
        self.elements.append_randoms(res);
        Ok(())
    }

    /// Constructs a new batch of triples and appends this to the internal triple storage.
    /// If the method terminates correctly then an _entire_ new batch has been constructed and added to the internal stash.
    /// If corruption occurs during the process then the corrupt parties are added to the corrupt set in `session` and the method
    /// Caller then needs to retry to construct any missing triples, to ensure a full batch has been constructed before returning.
    #[instrument(name="MPC_Small.GenTriples",skip(self,session), fields(sid= ?session.session_id(), own_identity = ?session.own_identity(),batch_size = amount))]
    async fn next_triple_batch<Rnd: Rng + CryptoRng, Ses: SmallSessionHandles<Z, Rnd>>(
        &mut self,
        session: &mut Ses,
        amount: usize,
    ) -> anyhow::Result<()> {
        let prss_base_ctr = session.prss().prss_ctr;
        let przs_base_ctr = session.prss().przs_ctr;

        let vec_x_single = Self::prss_list(session, amount)?;
        let vec_y_single = Self::prss_list(session, amount)?;
        let vec_v_single = Self::prss_list(session, amount)?;
        let vec_z_double = Self::przs_list(session, amount)?;

        let mut vec_d_double = Vec::with_capacity(amount);
        for i in 0..amount {
            let x_single = vec_x_single
                .get(i)
                .with_context(|| log_error_wrapper("Expected x does not exist"))?
                .to_owned();
            let y_single = vec_y_single
                .get(i)
                .with_context(|| log_error_wrapper("Expected y does not exist"))?
                .to_owned();
            let v_single = vec_v_single
                .get(i)
                .with_context(|| log_error_wrapper("Expected v does not exist"))?
                .to_owned();
            let z_double = vec_z_double
                .get(i)
                .with_context(|| log_error_wrapper("Expected z does not exist"))?
                .to_owned();
            let v_double = z_double + v_single;
            let d_double = x_single * y_single + v_double;
            vec_d_double.push(d_double)
        }
        let broadcast_res =
            broadcast_from_all_w_corruption(session, vec_d_double.clone().into()).await?;

        //Try reconstructing 2t sharings of d, a None means reconstruction failed.
        let recons_vec_d = Self::reconstruct_d_values(session, amount, broadcast_res.clone())?;

        let mut triples = Vec::with_capacity(amount);
        let mut bad_triples_idx = Vec::new();
        for i in 0..amount {
            //If we managed to reconstruct, we store the triple
            if let Some(d) = recons_vec_d
                .get(i)
                .with_context(|| log_error_wrapper("Not all expected d values exist"))?
            {
                triples.push(Triple {
                    a: Share::new(
                        session.my_role()?,
                        vec_x_single
                            .get(i)
                            .with_context(|| log_error_wrapper("Not all expected x values exist"))?
                            .to_owned(),
                    ),
                    b: Share::new(
                        session.my_role()?,
                        vec_y_single
                            .get(i)
                            .with_context(|| log_error_wrapper("Not all expected y values exist"))?
                            .to_owned(),
                    ),
                    c: Share::new(
                        session.my_role()?,
                        d.to_owned()
                            - vec_v_single
                                .get(i)
                                .with_context(|| {
                                    log_error_wrapper("Not all expected v values exist")
                                })?
                                .to_owned(),
                    ),
                });
            //If reconstruction failed, it's a bad triple and we will run cheater identification
            } else {
                bad_triples_idx.push(i);
            }
        }
        // If non-correctable malicious behaviour has been detected
        if !bad_triples_idx.is_empty() {
            // Recover the individual d shares from broadcast
            let d_shares = Self::parse_d_shares(session, amount, broadcast_res)?;
            for i in bad_triples_idx {
                Self::check_d(
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
        self.elements.append_triples(triples);
        Ok(())
    }

    /// Helper method to parse the result of the broadcast by taking the ith share from each party and combine them in a vector for which reconstruction is then computed.
    /// Returns a list of length `amount` which contains the reconstructed values.
    /// In case a wrong amount of elements or a wrong type is returned then the culprit is added to the list of corrupt parties.
    fn reconstruct_d_values<Rnd: Rng + CryptoRng, Ses: BaseSessionHandles<Rnd>>(
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
                            session.my_role()?.one_based(),
                            cur_role.one_based()
                        );
                        session.add_corrupt(cur_role)?;
                        continue;
                    }
                    for (i, cur_collect_share) in collected_shares.iter_mut().enumerate() {
                        cur_collect_share.push(Share::new(cur_role, cur_values[i]));
                    }
                }
                _ => {
                    tracing::warn!(
                        "Party {:?} did not broadcast the correct type and is thus malicious",
                        cur_role.one_based()
                    );
                    session.add_corrupt(cur_role)?;
                    continue;
                }
            };
        }

        // Check if there are enough honest parties to correct the errors
        if session.num_parties() - session.corrupt_roles().len()
            < 2 * session.threshold() as usize + 1
        {
            return Err(anyhow::anyhow!(
                "BUG: Not enough honest parties to correct the errors: {} honest parties, threshold={}",
                session.num_parties() - session.corrupt_roles().len(),
                session.threshold()
            ));
        }

        //We know we may not be able to correct all errors, thus we set max_errors to maximum number of errors the code can correct,
        //and deal with failure with the cheater identification strategy
        let max_errors = (session.num_parties()
            - session.corrupt_roles().len()
            - (2 * session.threshold() as usize + 1))
            / 2;

        Ok(collected_shares
            .into_iter()
            .map(|cur_collection| {
                let sharing = ShamirSharings::create(cur_collection);
                if let Ok(r) = sharing.err_reconstruct(2 * session.threshold() as usize, max_errors)
                {
                    Some(r)
                } else {
                    None
                }
            })
            .collect_vec())
    }

    /// Helper method which takes the list of d shares of each party (the result of the broadcast)
    /// and parses it into a vector that stores at index i a map from the sending [Role] to their ith d share.
    ///
    /// Note: In case we can not find a correct share for a Party, we set [None] as its share.
    fn parse_d_shares<Rnd: Rng + CryptoRng, Ses: SmallSessionHandles<Z, Rnd>>(
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
                            session.my_role()?.one_based(),
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
    #[instrument(name="PRSS.Next",skip(session,amount),fields(sid=?session.session_id(),own_identity=?session.own_identity(),batch_size=?amount))]
    fn prss_list<Rnd: Rng + CryptoRng, Ses: SmallSessionHandles<Z, Rnd>>(
        session: &mut Ses,
        amount: usize,
    ) -> anyhow::Result<Vec<Z>> {
        let my_id = session.my_role()?;
        let mut vec_prss = Vec::with_capacity(amount);
        for _i in 0..amount {
            vec_prss.push(session.prss_as_mut().prss_next(my_id)?);
        }
        Ok(vec_prss)
    }

    /// Output amount of PRZS.Next() calls
    #[instrument(name="PRZS.Next",skip(session,amount),fields(sid=?session.session_id(),own_identity=?session.own_identity(),batch_size=?amount))]
    fn przs_list<Rnd: Rng + CryptoRng, Ses: SmallSessionHandles<Z, Rnd>>(
        session: &mut Ses,
        amount: usize,
    ) -> anyhow::Result<Vec<Z>> {
        let my_id = session.my_role()?;
        let threshold = session.threshold();
        let mut vec_przs = Vec::with_capacity(amount);
        for _i in 0..amount {
            vec_przs.push(session.prss_as_mut().przs_next(my_id, threshold)?);
        }
        Ok(vec_przs)
    }

    /// Helper method for validating results when corruption has happened (by the reconstruction not being successful).
    /// The method finds the corrupt parties (based on what they broadcast) and adds them to the list of corrupt parties in the session.
    async fn check_d<Rnd: Rng + CryptoRng, Ses: SmallSessionHandles<Z, Rnd>>(
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
            if cur_d_share.is_none() || cur_d_share.is_some_and(|d_share| d_prime_double != d_share)
            {
                tracing::warn!(
                    "Party {cur_role} did not send correct values during PRSS-init and
                has been added to the list of corrupt parties"
                );
                session.add_corrupt(cur_role)?;
            }
        }
        Ok(())
    }
}

impl<Z: Ring, A: AgreeRandom> TriplePreprocessing<Z> for SmallPreprocessing<Z, A> {
    fn next_triple(&mut self) -> anyhow::Result<Triple<Z>> {
        self.elements.next_triple()
    }

    fn next_triple_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Triple<Z>>> {
        self.elements.next_triple_vec(amount)
    }

    fn append_triples(&mut self, triples: Vec<Triple<Z>>) {
        self.elements.append_triples(triples);
    }

    fn triples_len(&self) -> usize {
        self.elements.triples_len()
    }
}

impl<Z: Ring, A: AgreeRandom> RandomPreprocessing<Z> for SmallPreprocessing<Z, A> {
    fn next_random_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<Z>>> {
        self.elements.next_random_vec(amount)
    }

    fn append_randoms(&mut self, randoms: Vec<Share<Z>>) {
        self.elements.append_randoms(randoms);
    }

    fn randoms_len(&self) -> usize {
        self.elements.randoms_len()
    }
}

impl<Z: Ring, A: AgreeRandom + Send + Sync> BasePreprocessing<Z> for SmallPreprocessing<Z, A> {}

#[cfg(test)]
mod test {
    use std::{collections::HashMap, num::Wrapping};

    use crate::algebra::structure_traits::{ErrorCorrect, Invert, Ring, RingEmbed};
    use crate::execution::online::preprocessing::dummy::reconstruct;
    use crate::networking::NetworkMode;
    use crate::{
        algebra::{
            galois_rings::degree_4::{ResiduePolyF4, ResiduePolyF4Z128, ResiduePolyF4Z64},
            structure_traits::{One, Zero},
        },
        execution::{
            online::{
                preprocessing::{create_memory_factory, RandomPreprocessing, TriplePreprocessing},
                triple::Triple,
            },
            runtime::{
                party::Role,
                session::{
                    BaseSessionHandles, ParameterHandles, SmallSession, SmallSessionHandles,
                },
            },
            sharing::share::Share,
            small_execution::{
                agree_random::DummyAgreeRandom,
                offline::{BatchParams, SmallPreprocessing},
                prf::PRSSConversions,
            },
        },
        networking::value::BroadcastValue,
        tests::helper::{
            testing::get_networkless_base_session_for_parties,
            tests_and_benches::execute_protocol_small,
        },
    };

    const RANDOM_BATCH_SIZE: usize = 10;
    const TRIPLE_BATCH_SIZE: usize = 10;

    fn test_rand_generation<
        Z: RingEmbed + PRSSConversions + ErrorCorrect + Invert,
        const EXTENSION_DEGREE: usize,
    >() {
        let parties = 4;
        let threshold = 1;

        let mut task = |mut session: SmallSession<Z>, _bot: Option<String>| async move {
            let default_batch_size = BatchParams {
                triples: 0,
                randoms: RANDOM_BATCH_SIZE,
            };

            let mut preproc =
                SmallPreprocessing::<_, DummyAgreeRandom>::init(&mut session, default_batch_size)
                    .await
                    .unwrap();
            let mut res = Vec::new();
            for _ in 0..RANDOM_BATCH_SIZE {
                res.push(preproc.next_random().unwrap());
            }
            (session, res)
        };

        // Rounds:
        // PRSS-Setup with Dummy AR does not send anything = 0 rounds
        // pre-processing randomness is communication free
        let rounds = 0_usize;

        // Does not really matter Sync or Async as there's no communication here, default to Sync
        let result = execute_protocol_small::<_, _, Z, EXTENSION_DEGREE>(
            parties,
            threshold,
            Some(rounds),
            NetworkMode::Sync,
            None,
            &mut task,
            None,
        );

        let mut first_to_recon = Vec::new();
        for (_, res) in result.iter() {
            first_to_recon.push(res[0]);
        }
        let mut previous = reconstruct(&result[0].0, first_to_recon).unwrap();
        //Check we can reconstruct and that values are not iteratively repeated
        for idx in 1..RANDOM_BATCH_SIZE {
            let mut to_recon = Vec::new();
            for (_, res) in result.iter() {
                to_recon.push(res[idx]);
            }
            let current = reconstruct(&result[0].0, to_recon).unwrap();
            assert_ne!(current, previous);
            previous = current;
        }
    }

    #[test]
    fn test_rand_generation_z128() {
        test_rand_generation::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }>();
    }

    #[test]
    fn test_rand_generation_z64() {
        test_rand_generation::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }>();
    }

    fn test_triple_generation<
        Z: Ring + RingEmbed + PRSSConversions + ErrorCorrect + Invert,
        const EXTENSION_DEGREE: usize,
    >() {
        let parties = 4;
        let threshold = 1;

        let mut task = |mut session: SmallSession<Z>, _bot: Option<String>| async move {
            let default_batch_size = BatchParams {
                triples: TRIPLE_BATCH_SIZE,
                randoms: 0,
            };

            let mut preproc =
                SmallPreprocessing::<_, DummyAgreeRandom>::init(&mut session, default_batch_size)
                    .await
                    .unwrap();
            let mut res = Vec::new();
            for _ in 0..TRIPLE_BATCH_SIZE {
                res.push(preproc.next_triple().unwrap());
            }
            (session, res)
        };

        // Rounds:
        // PRSS-Setup with Dummy AR does not send anything = 0 rounds
        // pre-processing without corruptions with Dummy AR does only do 1 reliable broadcast = 3 + t rounds
        let rounds = 3 + threshold as usize;

        // Sync because it is triple generation
        let result = execute_protocol_small::<_, _, Z, EXTENSION_DEGREE>(
            parties,
            threshold,
            Some(rounds),
            NetworkMode::Sync,
            None,
            &mut task,
            None,
        );

        //Check we can reconstruct everything and we do have multiplication triples
        for idx in 0..TRIPLE_BATCH_SIZE {
            let mut to_recon_a = Vec::new();
            let mut to_recon_b = Vec::new();
            let mut to_recon_c = Vec::new();
            for (_, res) in result.iter() {
                to_recon_a.push(res[idx].a);
                to_recon_b.push(res[idx].b);
                to_recon_c.push(res[idx].c);
            }
            let recon_a = reconstruct(&result[0].0, to_recon_a).unwrap();
            let recon_b = reconstruct(&result[0].0, to_recon_b).unwrap();
            let recon_c = reconstruct(&result[0].0, to_recon_c).unwrap();
            assert_eq!(recon_a * recon_b, recon_c);
        }
    }

    #[test]
    fn test_triple_generation_z128() {
        test_triple_generation::<ResiduePolyF4Z128, { ResiduePolyF4Z128::EXTENSION_DEGREE }>();
    }

    #[test]
    fn test_triple_generation_z64() {
        test_triple_generation::<ResiduePolyF4Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }>();
    }

    #[test]
    fn test_triple_generation_custom_batch() {
        let parties = 5;
        let threshold = 1;

        async fn task(mut session: SmallSession<ResiduePolyF4Z128>, _bot: Option<String>) {
            let batch_size = BatchParams {
                triples: 3,
                randoms: 2,
            };

            let mut preproc =
                SmallPreprocessing::<_, DummyAgreeRandom>::init(&mut session, batch_size)
                    .await
                    .unwrap();
            assert_eq!(batch_size.triples, preproc.elements.triples_len());
            assert_eq!(batch_size.randoms, preproc.elements.randoms_len());
            let _ = preproc.next_random_vec(batch_size.randoms);
            let _ = preproc.next_triple_vec(batch_size.triples);
        }

        // Rounds:
        // PRSS-Setup with Dummy AR does not send anything = 0 rounds
        // pre-processing without corruptions with Dummy AR does only do 1 reliable broadcast = 3 + t rounds
        let rounds = 3 + threshold as usize;

        // Sync because it is triple generation
        let _result = execute_protocol_small::<
            _,
            _,
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
        >(
            parties,
            threshold,
            Some(rounds),
            NetworkMode::Sync,
            None,
            &mut task,
            None,
        );
    }

    // Test what happens when a party send a wrong type of value
    #[tracing_test::traced_test]
    #[test]
    fn test_wrong_type() {
        let mut session = get_networkless_base_session_for_parties(4, 1, Role::indexed_by_one(1));
        // Observe party 1 inputs a vector of size 1 and party 2 inputs a single element
        let d_recons = HashMap::from([
            (
                Role::indexed_by_one(1),
                BroadcastValue::RingVector(Vec::from([ResiduePolyF4Z128::from_scalar(Wrapping(
                    42,
                ))])),
            ),
            (
                Role::indexed_by_one(2),
                BroadcastValue::RingValue(ResiduePolyF4Z128::from_scalar(Wrapping(13))),
            ),
        ]);
        assert!(session.corrupt_roles().is_empty());
        let res = SmallPreprocessing::<ResiduePolyF4Z128, DummyAgreeRandom>::reconstruct_d_values(
            &mut session,
            1,
            d_recons,
        )
        .unwrap();
        assert_eq!(1, session.corrupt_roles().len());
        assert!(session.corrupt_roles().contains(&Role::indexed_by_one(2)));
        assert!(logs_contain(
            "did not broadcast the correct type and is thus malicious"
        ));
        assert_eq!(1, res.len());
        let first = res.first();
        assert!(first.is_some());
    }

    #[test]
    fn test_party_drop() {
        let parties = 5;
        let threshold = 1;
        const BAD_ID: usize = 3;
        async fn task(
            mut session: SmallSession<ResiduePolyF4Z128>,
            _bot: Option<String>,
        ) -> (
            SmallSession<ResiduePolyF4Z128>,
            Vec<Triple<ResiduePolyF4Z128>>,
            Vec<Share<ResiduePolyF4Z128>>,
        ) {
            let mut triple_res = Vec::new();
            let mut rand_res = Vec::new();
            if session.my_role().unwrap() != Role::indexed_by_one(BAD_ID) {
                let default_batch_size = BatchParams {
                    triples: TRIPLE_BATCH_SIZE,
                    randoms: RANDOM_BATCH_SIZE,
                };

                let mut preproc = SmallPreprocessing::<_, DummyAgreeRandom>::init(
                    &mut session,
                    default_batch_size,
                )
                .await
                .unwrap();
                for _ in 0..TRIPLE_BATCH_SIZE {
                    triple_res.push(preproc.next_triple().unwrap());
                }
                for _ in 0..RANDOM_BATCH_SIZE {
                    rand_res.push(preproc.next_random().unwrap());
                }
            }
            (session, triple_res, rand_res)
        }

        // Sync because it is triple generation
        let result = execute_protocol_small::<
            _,
            _,
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
        >(
            parties,
            threshold,
            None,
            NetworkMode::Sync,
            None,
            &mut task,
            None,
        );

        //Check we can reconstruct everything and we do have multiplication triples
        for idx in 0..TRIPLE_BATCH_SIZE {
            let mut to_recon_a = Vec::new();
            let mut to_recon_b = Vec::new();
            let mut to_recon_c = Vec::new();
            let mut to_recon_rand = Vec::new();
            let mut test_session = &result[0].0;
            for (session, res_trip, res_rand) in result.iter() {
                // Skip bad party since the result will be empty
                if session.my_role().unwrap() != Role::indexed_by_one(BAD_ID) {
                    to_recon_a.push(res_trip[idx].a);
                    to_recon_b.push(res_trip[idx].b);
                    to_recon_c.push(res_trip[idx].c);
                    to_recon_rand.push(res_rand[idx]);
                    // Ensure we use the session of an honest party to check things
                    test_session = session;
                } else {
                    assert_eq!(0, res_trip.len());
                    assert_eq!(0, res_rand.len());
                }
            }
            let recon_a = reconstruct(test_session, to_recon_a).unwrap();
            let recon_b = reconstruct(test_session, to_recon_b).unwrap();
            let recon_c = reconstruct(test_session, to_recon_c).unwrap();
            assert_eq!(recon_a * recon_b, recon_c);
            let recon_rand = reconstruct(test_session, to_recon_rand).unwrap();
            // Sanity check the random reconstruction
            assert_ne!(recon_rand, ResiduePolyF4::ZERO);
            assert_ne!(recon_rand, ResiduePolyF4::ONE);
        }
    }

    // Test what happens when a malicious party does not send the correct amount of elements in the broadcast
    #[test]
    fn test_malicious_party_wrong_amount() {
        let parties = 5;
        let threshold = 1;
        const BAD_ID: usize = 3;

        async fn task(
            mut session: SmallSession<ResiduePolyF4Z128>,
            _bot: Option<String>,
        ) -> (
            SmallSession<ResiduePolyF4Z128>,
            Vec<Triple<ResiduePolyF4Z128>>,
            Vec<Share<ResiduePolyF4Z128>>,
        ) {
            let mut triple_res = Vec::new();
            let mut rand_res = Vec::new();
            // Observe that 1 triple too little is made
            let bad_batch_sizes = BatchParams {
                triples: TRIPLE_BATCH_SIZE - 1,
                randoms: RANDOM_BATCH_SIZE,
            };
            let default_batch_size = BatchParams {
                triples: 10,
                randoms: 10,
            };

            if session.my_role().unwrap() != Role::indexed_by_one(BAD_ID) {
                let mut preproc = SmallPreprocessing::<_, DummyAgreeRandom>::init(
                    &mut session,
                    default_batch_size,
                )
                .await
                .unwrap();
                for _ in 0..TRIPLE_BATCH_SIZE {
                    triple_res.push(preproc.next_triple().unwrap());
                }
                for _ in 0..RANDOM_BATCH_SIZE {
                    rand_res.push(preproc.next_random().unwrap());
                }
            } else {
                let _ =
                    SmallPreprocessing::<_, DummyAgreeRandom>::init(&mut session, bad_batch_sizes)
                        .await;
            }
            (session, triple_res, rand_res)
        }

        // Sync because it is triple generation
        let result = execute_protocol_small::<
            _,
            _,
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
        >(
            parties,
            threshold,
            None,
            NetworkMode::Sync,
            None,
            &mut task,
            None,
        );

        // Check that the malicious party has been added to the list
        for (cur_ses, _, _) in result.clone() {
            if cur_ses.my_role().unwrap().one_based() != BAD_ID {
                assert!(cur_ses
                    .corrupt_roles()
                    .contains(&Role::indexed_by_one(BAD_ID)));
            }
        }

        //Check we can reconstruct everything and we do have multiplication triples
        for idx in 0..TRIPLE_BATCH_SIZE {
            let mut to_recon_a = Vec::new();
            let mut to_recon_b = Vec::new();
            let mut to_recon_c = Vec::new();
            let mut to_recon_rand = Vec::new();
            let mut test_session = &result[0].0;
            for (session, res_trip, res_rand) in result.iter() {
                // Skip bad party since the result will be empty
                if session.my_role().unwrap() != Role::indexed_by_one(BAD_ID) {
                    to_recon_a.push(res_trip[idx].a);
                    to_recon_b.push(res_trip[idx].b);
                    to_recon_c.push(res_trip[idx].c);
                    to_recon_rand.push(res_rand[idx]);
                    // Ensure we use the session of an honest party to check things
                    test_session = session;
                } else {
                    assert_eq!(0, res_trip.len());
                    assert_eq!(0, res_rand.len());
                }
            }
            let recon_a = reconstruct(test_session, to_recon_a).unwrap();
            let recon_b = reconstruct(test_session, to_recon_b).unwrap();
            let recon_c = reconstruct(test_session, to_recon_c).unwrap();
            assert_eq!(recon_a * recon_b, recon_c);
            let recon_rand = reconstruct(test_session, to_recon_rand).unwrap();
            // Sanity check the random reconstruction
            assert_ne!(recon_rand, ResiduePolyF4::ZERO);
            assert_ne!(recon_rand, ResiduePolyF4::ONE);
        }
    }

    // Test what happens when a malicious party is using wrong values and check_d gets executed
    #[test]
    fn test_malicious_party_bad_values() {
        // Observe that with more parties the error correction part of the flow will work and check_d will not be executed
        let parties = 4;
        let threshold = 1;
        const BAD_ID: usize = 2;

        async fn task(
            mut session: SmallSession<ResiduePolyF4Z128>,
            _bot: Option<String>,
        ) -> SmallSession<ResiduePolyF4Z128> {
            if session.my_role().unwrap() == Role::indexed_by_one(BAD_ID) {
                // Change the counter offset to make the party use wrong values
                let prss_state = session.prss_as_mut();
                prss_state.prss_ctr = 12;
                prss_state.przs_ctr = 234;
            };

            let base_preprocessing =
                create_memory_factory().create_base_preprocessing_residue_128();

            let default_batch = BatchParams {
                triples: 10,
                randoms: 10,
            };
            let mut res = SmallPreprocessing::<_, DummyAgreeRandom> {
                batch_sizes: default_batch,
                elements: base_preprocessing,
                _marker: std::marker::PhantomData,
            };
            let _ = res.next_triple_batch(&mut session, 1).await;
            // Check that no triples get constructed due to the corrupt party
            assert_eq!(res.elements.triples_len(), 0);
            session
        }

        // Sync because it is triple generation
        let result = execute_protocol_small::<
            _,
            _,
            ResiduePolyF4Z128,
            { ResiduePolyF4Z128::EXTENSION_DEGREE },
        >(
            parties,
            threshold,
            None,
            NetworkMode::Sync,
            None,
            &mut task,
            None,
        );

        // Check that the malicious party has been added to the list
        for cur_ses in result.clone() {
            if cur_ses.my_role().unwrap().one_based() != BAD_ID {
                assert!(cur_ses
                    .corrupt_roles()
                    .contains(&Role::indexed_by_one(BAD_ID)));
                // Check that the list only contains one corrupt party
                assert_eq!(1, cur_ses.corrupt_roles().len());
            }
        }
    }
}

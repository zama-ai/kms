use num_integer::div_ceil;
use tokio::{sync::mpsc::Sender, task::JoinSet};
use tracing::instrument;

use crate::{
    algebra::structure_traits::Ring,
    error::error_handler::anyhow_error_and_log,
    execution::{
        config::BatchParams,
        large_execution::offline::SecureLargePreprocessing,
        online::preprocessing::{
            orchestration::{
                producer_traits::RandomProducerTrait, progress_tracker::ProgressTracker,
            },
            RandomPreprocessing,
        },
        runtime::session::{BaseSessionHandles, LargeSession, SmallSession},
        sharing::share::Share,
        small_execution::offline::{Preprocessing, SecureSmallPreprocessing},
    },
};

use super::common::{execute_preprocessing, ProducerSession};

pub struct GenericRandomProducer<Z, S, PreprocStrat>
where
    Z: Ring,
    S: BaseSessionHandles + 'static,
{
    batch_size: usize,
    total_size: usize,
    producers: Vec<ProducerSession<S, Vec<Share<Z>>>>,
    progress_tracker: Option<ProgressTracker>,
    _marker_strat: std::marker::PhantomData<PreprocStrat>,
}

impl<Z, S, PreprocStrat> RandomProducerTrait<Z, S> for GenericRandomProducer<Z, S, PreprocStrat>
where
    Z: Ring,
    S: BaseSessionHandles + 'static,
    PreprocStrat: Preprocessing<Z, S> + Default,
{
    fn new(
        batch_size: usize,
        total_size: usize,
        mut sessions: Vec<S>,
        channels: Vec<Sender<Vec<Share<Z>>>>,
        progress_tracker: Option<ProgressTracker>,
    ) -> anyhow::Result<Self> {
        if sessions.len() != channels.len() {
            return Err(anyhow_error_and_log(format!("Trying to instantiate a producer with {} sessions and {} channels, but we need as many sessions as channels",sessions.len(), channels.len())));
        }

        //Always sort the sessions by sid so we are sure it's order the same way for all parties
        sessions.sort_by_key(|s| s.session_id());

        let producers = sessions
            .into_iter()
            .zip(channels)
            .map(|(session, channel)| ProducerSession::new(session, channel))
            .collect();

        Ok(Self {
            batch_size,
            total_size,
            producers,
            progress_tracker,
            _marker_strat: std::marker::PhantomData,
        })
    }

    #[instrument(name="Random Factory",skip(self),fields(num_sessions= ?self.producers.len()))]
    fn start_random_production(self) -> JoinSet<Result<S, anyhow::Error>> {
        let num_producers = self.producers.len();
        let num_loops = div_ceil(self.total_size, self.batch_size * num_producers);

        let batch_size = self.batch_size;
        let task_gen = |mut session: S,
                        sender_channel: Sender<Vec<Share<Z>>>,
                        progress_tracker: Option<ProgressTracker>| async move {
            let base_batch_size = BatchParams {
                triples: 0,
                randoms: batch_size,
            };

            let mut preprocessing = PreprocStrat::default();
            for _ in 0..num_loops {
                let randoms = preprocessing
                    .execute(&mut session, base_batch_size)
                    .await?
                    .next_random_vec(batch_size)?;

                //Drop the error on purpose as the receiver end might be closed already if we produced too much
                let _ = sender_channel.send(randoms).await;
                progress_tracker.as_ref().map(|p| p.increment(batch_size));
            }
            Ok::<_, anyhow::Error>(session)
        };
        execute_preprocessing(self.producers, task_gen, self.progress_tracker)
    }
}

pub type SecureSmallSessionRandomProducer<Z> =
    GenericRandomProducer<Z, SmallSession<Z>, SecureSmallPreprocessing>;

pub type SecureLargeSessionRandomProducer<Z> =
    GenericRandomProducer<Z, LargeSession, SecureLargePreprocessing<Z>>;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use itertools::Itertools;

    use crate::{
        algebra::{
            base_ring::{Z128, Z64},
            galois_rings::common::ResiduePoly,
            structure_traits::{Derive, ErrorCorrect, Invert, Solve},
        },
        execution::{
            online::preprocessing::{
                memory::InMemoryBasePreprocessing,
                orchestration::producers::common::tests::{
                    test_production_large, test_production_small,
                    ReceiverChannelCollectionWithTracker, Typeproduction, TEST_NUM_LOOP,
                },
                RandomPreprocessing,
            },
            runtime::party::Identity,
            sharing::shamir::{RevealOp, ShamirSharings},
        },
    };

    fn check_randomness_reconstruction<const EXTENSION_DEGREE: usize>(
        all_parties_channels: Vec<
            ReceiverChannelCollectionWithTracker<ResiduePoly<Z64, EXTENSION_DEGREE>>,
        >,
        identities: &[Identity],
        num_randomness: usize,
        threshold: usize,
    ) where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
    {
        let mut random_preprocs = all_parties_channels
            .into_iter()
            .map(|channels| {
                assert!(channels.3.get_progress().unwrap().is_finished());
                let mut random_vec = Vec::new();
                let mut random_channels = channels.1;
                for _ in 0..TEST_NUM_LOOP {
                    for random_channel in random_channels.iter_mut() {
                        let next_batch = random_channel.try_recv().unwrap();
                        random_vec.extend(next_batch)
                    }
                }
                InMemoryBasePreprocessing {
                    available_triples: Vec::new(),
                    available_randoms: random_vec,
                }
            })
            .collect_vec();

        //Retrieve bits and try reconstruct them
        let mut randomness_map = HashMap::new();
        for ((party_idx, _party_id), random_preproc) in identities
            .iter()
            .enumerate()
            .zip(random_preprocs.iter_mut())
        {
            let randomness_len = random_preproc.randoms_len();
            assert_eq!(randomness_len, num_randomness);

            let randomness_shares = random_preproc.next_random_vec(num_randomness).unwrap();

            randomness_map.insert(party_idx + 1, randomness_shares);
        }

        let mut vec_sharings = vec![ShamirSharings::default(); num_randomness];
        for (_, randomness) in randomness_map {
            for (idx, bit) in randomness.iter().enumerate() {
                let _ = vec_sharings[idx].add_share(*bit);
            }
        }

        for b in vec_sharings {
            let _b = b.reconstruct(threshold).unwrap();
        }
    }

    #[test]
    fn test_random_production_large_f4() {
        test_random_production_large::<4>()
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    fn test_random_production_large_f3() {
        test_random_production_large::<3>()
    }

    #[cfg(feature = "extension_degree_5")]
    #[test]
    fn test_random_production_large_f5() {
        test_random_production_large::<5>()
    }

    #[cfg(feature = "extension_degree_6")]
    #[test]
    fn test_random_production_large_f6() {
        test_random_production_large::<6>()
    }

    #[cfg(feature = "extension_degree_7")]
    #[test]
    fn test_random_production_large_f7() {
        test_random_production_large::<7>()
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    fn test_random_production_large_f8() {
        test_random_production_large::<8>()
    }

    fn test_random_production_large<const EXTENSION_DEGREE: usize>()
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
    {
        let num_parties = 5;
        let threshold = 1;
        let num_sessions = 5;

        //Each batch is 100 long
        let batch_size = 100;

        //Want 1k, so each session needs running twice (5 sessions, each batch is 100)
        let num_randomness = num_sessions * batch_size * TEST_NUM_LOOP;

        let (identities, all_parties_channels) = test_production_large::<EXTENSION_DEGREE>(
            num_sessions as u128,
            num_randomness,
            batch_size,
            num_parties,
            threshold,
            Typeproduction::Randoms,
        );

        check_randomness_reconstruction(
            all_parties_channels,
            &identities,
            num_randomness,
            threshold as usize,
        );
    }

    #[test]
    fn test_randomness_production_small_f4() {
        test_randomness_production_small::<4>()
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    fn test_randomness_production_small_f3() {
        test_randomness_production_small::<3>()
    }

    #[cfg(feature = "extension_degree_5")]
    #[test]
    fn test_randomness_production_small_f5() {
        test_randomness_production_small::<5>()
    }

    #[cfg(feature = "extension_degree_6")]
    #[test]
    fn test_randomness_production_small_f6() {
        test_randomness_production_small::<6>()
    }

    #[cfg(feature = "extension_degree_7")]
    #[test]
    fn test_randomness_production_small_f7() {
        test_randomness_production_small::<7>()
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    fn test_randomness_production_small_f8() {
        test_randomness_production_small::<8>()
    }

    fn test_randomness_production_small<const EXTENSION_DEGREE: usize>()
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
    {
        let num_parties = 5;
        let threshold = 1;
        let num_sessions = 5;

        //Each batch is 100 long
        let batch_size = 100;

        //Want 1k, so each session needs running twice (5 sessions, each batch is 100)
        let num_randomness = num_sessions * batch_size * TEST_NUM_LOOP;

        let (identities, all_parties_channels) = test_production_small::<EXTENSION_DEGREE>(
            num_sessions as u128,
            num_randomness,
            batch_size,
            num_parties,
            threshold,
            Typeproduction::Randoms,
        );

        check_randomness_reconstruction(
            all_parties_channels,
            &identities,
            num_randomness,
            threshold as usize,
        );
    }
}

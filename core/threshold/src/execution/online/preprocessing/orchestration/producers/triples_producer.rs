use num_integer::div_ceil;
use tokio::{sync::mpsc::Sender, task::JoinSet};
use tracing::instrument;

use crate::{
    algebra::structure_traits::{Derive, ErrorCorrect, Invert},
    error::error_handler::anyhow_error_and_log,
    execution::{
        config::BatchParams,
        large_execution::offline::SecureLargePreprocessing,
        online::{
            preprocessing::{
                orchestration::progress_tracker::ProgressTracker, TriplePreprocessing,
            },
            triple::Triple,
        },
        runtime::session::{LargeSession, ParameterHandles, SmallSession},
        small_execution::{
            agree_random::RealAgreeRandom, offline::SmallPreprocessing, prf::PRSSConversions,
        },
    },
};

use super::common::{execute_preprocessing, ProducerLargeSession, ProducerSmallSession};

/// Produces triple in all session concurrently
pub struct SmallSessionTripleProducer<Z: PRSSConversions + ErrorCorrect + Invert> {
    batch_size: usize,
    total_size: usize,
    producers: Vec<ProducerSmallSession<Z, Vec<Triple<Z>>>>,
    progress_tracker: Option<ProgressTracker>,
}

impl<Z: PRSSConversions + ErrorCorrect + Invert> SmallSessionTripleProducer<Z> {
    pub fn new(
        batch_size: usize,
        total_size: usize,
        mut sessions: Vec<SmallSession<Z>>,
        channels: Vec<Sender<Vec<Triple<Z>>>>,
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
            .map(|(session, channel)| ProducerSmallSession::new(session, channel))
            .collect();

        Ok(Self {
            batch_size,
            total_size,
            producers,
            progress_tracker,
        })
    }

    #[instrument(name="Triple Factory",skip(self),fields(num_sessions= ?self.producers.len()))]
    pub fn start_triple_production(self) -> JoinSet<Result<SmallSession<Z>, anyhow::Error>> {
        let num_producers = self.producers.len();
        let num_loops = div_ceil(self.total_size, self.batch_size * num_producers);

        let batch_size = self.batch_size;
        let task_gen = |mut session: SmallSession<Z>,
                        sender_channel: Sender<Vec<Triple<Z>>>,
                        progress_tracker: Option<ProgressTracker>| async move {
            let base_batch_size = BatchParams {
                triples: batch_size,
                randoms: 0,
            };

            for _ in 0..num_loops {
                let triples =
                    SmallPreprocessing::<Z, RealAgreeRandom>::init(&mut session, base_batch_size)
                        .await?
                        .next_triple_vec(batch_size)?;

                //Drop the error on purpose as the receiver end might be closed already if we produced too much
                let _ = sender_channel.send(triples).await;
                progress_tracker.as_ref().map(|p| p.increment(batch_size));
            }
            Ok::<_, anyhow::Error>(session)
        };
        execute_preprocessing(self.producers, task_gen, self.progress_tracker)
    }
}

/// Produces triple in all session concurrently
pub struct LargeSessionTripleProducer<Z: ErrorCorrect + Invert + Derive> {
    batch_size: usize,
    total_size: usize,
    producers: Vec<ProducerLargeSession<Vec<Triple<Z>>>>,
    progress_tracker: Option<ProgressTracker>,
}

impl<Z: ErrorCorrect + Invert + Derive> LargeSessionTripleProducer<Z> {
    pub fn new(
        batch_size: usize,
        total_size: usize,
        mut sessions: Vec<LargeSession>,
        channels: Vec<Sender<Vec<Triple<Z>>>>,
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
            .map(|(session, channel)| ProducerLargeSession::new(session, channel))
            .collect();

        Ok(Self {
            batch_size,
            total_size,
            producers,
            progress_tracker,
        })
    }

    #[instrument(name="Triple Factory",skip(self),fields(num_sessions= ?self.producers.len()))]
    pub fn start_triple_production(self) -> JoinSet<Result<LargeSession, anyhow::Error>> {
        let num_producers = self.producers.len();
        let num_loops = div_ceil(self.total_size, self.batch_size * num_producers);

        let batch_size = self.batch_size;
        let task_gen = |mut session: LargeSession,
                        sender_channel: Sender<Vec<Triple<Z>>>,
                        progress_tracker: Option<ProgressTracker>| async move {
            let base_batch_size = BatchParams {
                triples: batch_size,
                randoms: 0,
            };

            for _ in 0..num_loops {
                let triples = SecureLargePreprocessing::<Z>::new(&mut session, base_batch_size)
                    .await?
                    .next_triple_vec(batch_size)?;

                //Drop the error on purpose as the receiver end might be closed already if we produced too much
                let _ = sender_channel.send(triples).await;
                progress_tracker.as_ref().map(|p| p.increment(batch_size));
            }
            Ok::<_, anyhow::Error>(session)
        };
        execute_preprocessing(self.producers, task_gen, self.progress_tracker)
    }
}

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
                TriplePreprocessing,
            },
            runtime::party::Identity,
            sharing::shamir::{RevealOp, ShamirSharings},
        },
    };

    fn check_triples_reconstruction<const EXTENSION_DEGREE: usize>(
        all_parties_channels: Vec<
            ReceiverChannelCollectionWithTracker<ResiduePoly<Z64, EXTENSION_DEGREE>>,
        >,
        identities: &[Identity],
        num_triples: usize,
        threshold: usize,
    ) where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
    {
        let mut triple_preprocs = all_parties_channels
            .into_iter()
            .map(|channels| {
                assert!(channels.3.get_progress().unwrap().is_finished());
                let mut triples_vec = Vec::new();
                let mut triple_channels = channels.0;
                for _ in 0..TEST_NUM_LOOP {
                    for triple_channel in triple_channels.iter_mut() {
                        let next_batch = triple_channel.try_recv().unwrap();
                        triples_vec.extend(next_batch)
                    }
                }
                InMemoryBasePreprocessing {
                    available_triples: triples_vec,
                    available_randoms: Vec::new(),
                }
            })
            .collect_vec();

        //Retrieve triples and try reconstruct them
        let mut triples_map = HashMap::new();
        for ((party_idx, _party_id), triple_preproc) in identities
            .iter()
            .enumerate()
            .zip(triple_preprocs.iter_mut())
        {
            let triple_len = triple_preproc.triples_len();

            assert_eq!(triple_len, num_triples);

            let triples_shares = triple_preproc.next_triple_vec(num_triples).unwrap();
            triples_map.insert(party_idx + 1, triples_shares);
        }

        let mut vec_sharings_a = vec![ShamirSharings::default(); num_triples];
        let mut vec_sharings_b = vec![ShamirSharings::default(); num_triples];
        let mut vec_sharings_c = vec![ShamirSharings::default(); num_triples];
        for (_, triples) in triples_map {
            for (idx, triple) in triples.iter().enumerate() {
                let _ = vec_sharings_a[idx].add_share(triple.a);
                let _ = vec_sharings_b[idx].add_share(triple.b);
                let _ = vec_sharings_c[idx].add_share(triple.c);
            }
        }

        for (a, (b, c)) in vec_sharings_a
            .iter()
            .zip(vec_sharings_b.iter().zip(vec_sharings_c.iter()))
        {
            let aa = a.reconstruct(threshold).unwrap();
            let bb = b.reconstruct(threshold).unwrap();
            let cc = c.reconstruct(threshold).unwrap();
            assert_eq!(aa * bb, cc);
        }
    }

    #[test]
    fn test_triple_production_large_f4() {
        test_triple_production_large::<4>()
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    fn test_triple_production_large_f3() {
        test_triple_production_large::<3>()
    }

    #[cfg(feature = "extension_degree_5")]
    #[test]
    fn test_triple_production_large_f5() {
        test_triple_production_large::<5>()
    }

    #[cfg(feature = "extension_degree_6")]
    #[test]
    fn test_triple_production_large_f6() {
        test_triple_production_large::<6>()
    }

    #[cfg(feature = "extension_degree_7")]
    #[test]
    fn test_triple_production_large_f7() {
        test_triple_production_large::<7>()
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    fn test_triple_production_large_f8() {
        test_triple_production_large::<8>()
    }

    fn test_triple_production_large<const EXTENSION_DEGREE: usize>()
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
        let num_triples = num_sessions * batch_size * TEST_NUM_LOOP;

        let (identities, all_parties_channels) = test_production_large::<EXTENSION_DEGREE>(
            num_sessions as u128,
            num_triples,
            batch_size,
            num_parties,
            threshold,
            Typeproduction::Triples,
        );

        check_triples_reconstruction(
            all_parties_channels,
            &identities,
            num_triples,
            threshold as usize,
        );
    }

    #[test]
    fn test_triple_production_small_f4() {
        test_triple_production_small::<4>()
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    fn test_triple_production_small_f3() {
        test_triple_production_small::<3>()
    }

    #[cfg(feature = "extension_degree_5")]
    #[test]
    fn test_triple_production_small_f5() {
        test_triple_production_small::<5>()
    }

    #[cfg(feature = "extension_degree_6")]
    #[test]
    fn test_triple_production_small_f6() {
        test_triple_production_small::<6>()
    }

    #[cfg(feature = "extension_degree_7")]
    #[test]
    fn test_triple_production_small_f7() {
        test_triple_production_small::<7>()
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    fn test_triple_production_small_f8() {
        test_triple_production_small::<8>()
    }

    fn test_triple_production_small<const EXTENSION_DEGREE: usize>()
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
        let num_triples = num_sessions * batch_size * TEST_NUM_LOOP;

        let (identities, all_parties_channels) = test_production_small::<EXTENSION_DEGREE>(
            num_sessions as u128,
            num_triples,
            batch_size,
            num_parties,
            threshold,
            Typeproduction::Triples,
        );

        check_triples_reconstruction(
            all_parties_channels,
            &identities,
            num_triples,
            threshold as usize,
        );
    }
}

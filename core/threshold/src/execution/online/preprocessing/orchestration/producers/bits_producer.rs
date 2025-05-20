use num_integer::div_ceil;
use tokio::{sync::mpsc::Sender, task::JoinSet};
use tracing::instrument;

use crate::{
    algebra::structure_traits::{Derive, ErrorCorrect, Invert, Solve},
    error::error_handler::anyhow_error_and_log,
    execution::{
        config::BatchParams,
        large_execution::offline::SecureLargePreprocessing,
        online::{
            gen_bits::{BitGenEven, RealBitGenEven},
            preprocessing::orchestration::progress_tracker::ProgressTracker,
        },
        runtime::session::{LargeSession, ParameterHandles, SmallSession},
        sharing::share::Share,
        small_execution::{
            offline::{Preprocessing, SecureSmallPreprocessing},
            prf::PRSSConversions,
        },
    },
};

use super::common::{execute_preprocessing, ProducerLargeSession, ProducerSmallSession};

/// Produces bits in all session concurrently
/// NOTE: Includes the triple and randomness production
/// required to produce a bit
pub struct SmallSessionBitProducer<Z: PRSSConversions + ErrorCorrect + Invert> {
    pub(crate) batch_size: usize,
    pub(crate) total_size: usize,
    pub(crate) producers: Vec<ProducerSmallSession<Z, Vec<Share<Z>>>>,
    pub(crate) progress_tracker: Option<ProgressTracker>,
}

impl<Z: PRSSConversions + ErrorCorrect + Invert> SmallSessionBitProducer<Z> {
    pub fn new(
        batch_size: usize,
        total_size: usize,
        mut sessions: Vec<SmallSession<Z>>,
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
            .map(|(session, channel)| ProducerSmallSession::new(session, channel))
            .collect();

        Ok(Self {
            batch_size,
            total_size,
            producers,
            progress_tracker,
        })
    }

    #[instrument(name="Bit Factory",skip(self),fields(num_sessions= ?self.producers.len()))]
    pub fn start_bit_gen_even_production(self) -> JoinSet<Result<SmallSession<Z>, anyhow::Error>>
    where
        Z: Solve,
    {
        let num_producers = self.producers.len();
        let num_loops = div_ceil(self.total_size, self.batch_size * num_producers);

        let batch_size = self.batch_size;
        let task_gen = |mut session: SmallSession<Z>,
                        sender_channel: Sender<Vec<Share<Z>>>,
                        progress_tracker: Option<ProgressTracker>| async move {
            let base_batch_size = BatchParams {
                triples: batch_size,
                randoms: batch_size,
            };

            let mut preprocessing = SecureSmallPreprocessing::default();
            for _ in 0..num_loops {
                let mut correlated_randomness =
                    preprocessing.execute(&mut session, base_batch_size).await?;
                let bits = RealBitGenEven::gen_bits_even(
                    batch_size,
                    &mut correlated_randomness,
                    &mut session,
                )
                .await?;

                //Drop the error on purpose as the receiver end might be closed already if we produced too much
                let _ = sender_channel.send(bits).await;
                progress_tracker.as_ref().map(|p| p.increment(batch_size));
            }
            Ok::<_, anyhow::Error>(session)
        };
        execute_preprocessing(self.producers, task_gen, self.progress_tracker)
    }
}

/// Produces bits in all session concurrently
/// NOTE: Includes the triple and randomness production
/// required to produce a bit
pub struct LargeSessionBitProducer<Z: ErrorCorrect + Invert + Derive> {
    batch_size: usize,
    total_size: usize,
    producers: Vec<ProducerLargeSession<Vec<Share<Z>>>>,
    progress_tracker: Option<ProgressTracker>,
}

impl<Z: ErrorCorrect + Invert + Derive> LargeSessionBitProducer<Z> {
    pub fn new(
        batch_size: usize,
        total_size: usize,
        mut sessions: Vec<LargeSession>,
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
            .map(|(session, channel)| ProducerLargeSession::new(session, channel))
            .collect();

        Ok(Self {
            batch_size,
            total_size,
            producers,
            progress_tracker,
        })
    }

    #[instrument(name="Bit Factory",skip(self),fields(num_sessions= ?self.producers.len()))]
    pub fn start_bit_gen_even_production(self) -> JoinSet<Result<LargeSession, anyhow::Error>>
    where
        Z: Solve,
    {
        let num_producers = self.producers.len();
        let num_loops = div_ceil(self.total_size, self.batch_size * num_producers);

        let batch_size = self.batch_size;
        let task_gen = |mut session: LargeSession,
                        sender_channel: Sender<Vec<Share<Z>>>,
                        progress_tracker: Option<ProgressTracker>| async move {
            let base_batch_size = BatchParams {
                triples: batch_size,
                randoms: batch_size,
            };

            let mut preprocessing = SecureLargePreprocessing::default();
            for _ in 0..num_loops {
                let mut correlated_randomness =
                    preprocessing.execute(&mut session, base_batch_size).await?;
                let bits = RealBitGenEven::gen_bits_even(
                    batch_size,
                    &mut correlated_randomness,
                    &mut session,
                )
                .await?;

                //Drop the error on purpose as the receiver end might be closed already if we produced too much
                let _ = sender_channel.send(bits).await;
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
            structure_traits::{Derive, ErrorCorrect, Invert, One, Solve, Zero},
        },
        execution::{
            online::preprocessing::{
                memory::InMemoryBitPreprocessing,
                orchestration::producers::common::tests::{
                    test_production_large, test_production_small,
                    ReceiverChannelCollectionWithTracker, Typeproduction, TEST_NUM_LOOP,
                },
                BitPreprocessing,
            },
            runtime::party::Identity,
            sharing::shamir::{RevealOp, ShamirSharings},
        },
    };

    fn check_bits_reconstruction<const EXTENSION_DEGREE: usize>(
        all_parties_channels: Vec<
            ReceiverChannelCollectionWithTracker<ResiduePoly<Z64, EXTENSION_DEGREE>>,
        >,
        identities: &[Identity],
        num_bits: usize,
        threshold: usize,
    ) where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect,
    {
        let mut bit_preprocs = all_parties_channels
            .into_iter()
            .map(|channels| {
                assert!(channels.3.get_progress().unwrap().is_finished());
                let mut bit_vec = Vec::new();
                let mut bit_channels = channels.2;
                for _ in 0..TEST_NUM_LOOP {
                    for bit_channel in bit_channels.iter_mut() {
                        let next_batch = bit_channel.try_recv().unwrap();
                        bit_vec.extend(next_batch)
                    }
                }
                InMemoryBitPreprocessing {
                    available_bits: bit_vec,
                }
            })
            .collect_vec();

        //Retrieve bits and try reconstruct them
        let mut bits_map = HashMap::new();
        for ((party_idx, _party_id), bit_preproc) in
            identities.iter().enumerate().zip(bit_preprocs.iter_mut())
        {
            let bit_len = bit_preproc.bits_len();
            assert_eq!(bit_len, num_bits);

            let bits_shares = bit_preproc.next_bit_vec(num_bits).unwrap();
            bits_map.insert(party_idx + 1, bits_shares);
        }

        let mut vec_sharings = vec![ShamirSharings::default(); num_bits];
        for (_, bits) in bits_map {
            for (idx, bit) in bits.iter().enumerate() {
                let _ = vec_sharings[idx].add_share(*bit);
            }
        }

        for b in vec_sharings {
            let b = b.reconstruct(threshold).unwrap().to_scalar().unwrap();

            assert_eq!(b * (Z64::ONE - b), Z64::ZERO);
        }
    }

    #[test]
    fn test_bit_production_large_f4() {
        test_bit_production_large::<4>()
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    fn test_bit_production_large_f3() {
        test_bit_production_large::<3>()
    }

    #[cfg(feature = "extension_degree_5")]
    #[test]
    fn test_bit_production_large_f5() {
        test_bit_production_large::<5>()
    }

    #[cfg(feature = "extension_degree_6")]
    #[test]
    fn test_bit_production_large_f6() {
        test_bit_production_large::<6>()
    }

    #[cfg(feature = "extension_degree_7")]
    #[test]
    fn test_bit_production_large_f7() {
        test_bit_production_large::<7>()
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    fn test_bit_production_large_f8() {
        test_bit_production_large::<8>()
    }

    fn test_bit_production_large<const EXTENSION_DEGREE: usize>()
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
        let num_bits = num_sessions * batch_size * TEST_NUM_LOOP;

        let (identities, all_parties_channels) = test_production_large::<EXTENSION_DEGREE>(
            num_sessions as u128,
            num_bits,
            batch_size,
            num_parties,
            threshold,
            Typeproduction::Bits,
        );

        check_bits_reconstruction(
            all_parties_channels,
            &identities,
            num_bits,
            threshold as usize,
        );
    }

    #[test]
    fn test_bit_production_small_f4() {
        test_bit_production_small::<4>()
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    fn test_bit_production_small_f3() {
        test_bit_production_small::<3>()
    }

    #[cfg(feature = "extension_degree_5")]
    #[test]
    fn test_bit_production_small_f5() {
        test_bit_production_small::<5>()
    }

    #[cfg(feature = "extension_degree_6")]
    #[test]
    fn test_bit_production_small_f6() {
        test_bit_production_small::<6>()
    }

    #[cfg(feature = "extension_degree_7")]
    #[test]
    fn test_bit_production_small_f7() {
        test_bit_production_small::<7>()
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    fn test_bit_production_small_f8() {
        test_bit_production_small::<8>()
    }

    fn test_bit_production_small<const EXTENSION_DEGREE: usize>()
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
        let num_bits = num_sessions * batch_size * TEST_NUM_LOOP;

        let (identities, all_parties_channels) = test_production_small::<EXTENSION_DEGREE>(
            num_sessions as u128,
            num_bits,
            batch_size,
            num_parties,
            threshold,
            Typeproduction::Bits,
        );

        check_bits_reconstruction(
            all_parties_channels,
            &identities,
            num_bits,
            threshold as usize,
        );
    }
}

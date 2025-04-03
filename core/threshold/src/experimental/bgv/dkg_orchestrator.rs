use std::sync::{Arc, RwLock};

use itertools::Itertools;
use num_integer::div_ceil;
use tokio::{
    sync::{
        mpsc::{Receiver, Sender},
        Mutex,
    },
    task::JoinSet,
};
use tracing::{instrument, Instrument};

use crate::{
    error::error_handler::anyhow_error_and_log,
    execution::{
        config::BatchParams,
        online::{
            preprocessing::{
                constants::TRACKER_LOG_PERCENTAGE,
                memory::InMemoryBitPreprocessing,
                orchestration::{
                    consumers::{
                        randoms_aggregator::RandomsAggregator,
                        triples_aggregator::TriplesAggregator,
                    },
                    dkg_orchestrator::create_channels,
                    producers::{
                        bits_producer::SmallSessionBitProducer, common::execute_preprocessing,
                        randoms_producer::SmallSessionRandomProducer,
                        triples_producer::SmallSessionTripleProducer,
                    },
                    progress_tracker::ProgressTracker,
                },
            },
            secret_distributions::{RealSecretDistributions, SecretDistributions},
        },
        runtime::session::{ParameterHandles, SmallSession},
        sharing::share::Share,
        small_execution::{agree_random::RealAgreeRandom, offline::SmallPreprocessing},
    },
    experimental::{
        algebra::levels::LevelKsw,
        bgv::dkg_preproc::BGVDkgPreprocessing,
        constants::NEW_HOPE_BOUND,
        gen_bits_odd::{BitGenOdd, RealBitGenOdd},
    },
};

///Amount of triples generated in one batch by the orchestrator
pub(crate) const BGV_BATCH_SIZE_TRIPLES: usize = 1000;
///Amount of randomness generated in one batch by the orchestrator
pub(crate) const BGV_BATCH_SIZE_RANDOMS: usize = 1000;
///Amount of bits generated in one batch by the orchestrator
pub(crate) const BGV_BATCH_SIZE_BITS: usize = 1000;

use super::dkg_preproc::InMemoryBGVDkgPreprocessing;

type SmallSessionBGVDkgResult =
    anyhow::Result<(Vec<SmallSession<LevelKsw>>, InMemoryBGVDkgPreprocessing)>;

pub struct BGVPreprocessingOrchestrator {
    poly_size: usize,
    dkg_preproc: Arc<RwLock<InMemoryBGVDkgPreprocessing>>,
    triple_progress_tracker: ProgressTracker,
    random_progress_tracker: ProgressTracker,
    bit_progress_tracker: ProgressTracker,
}

fn get_num_correlated_randomness_required(poly_size: usize) -> (usize, usize, usize) {
    let num_bits = 2 * poly_size + 2 * 2 * poly_size * NEW_HOPE_BOUND;
    let num_triples = poly_size;
    let num_randoms = 2 * poly_size;
    (num_bits, num_triples, num_randoms)
}

impl BGVPreprocessingOrchestrator {
    pub fn new(poly_size: usize) -> Self {
        let (num_bits, num_triples, num_randomness) =
            get_num_correlated_randomness_required(poly_size);
        let triple_progress_tracker =
            ProgressTracker::new("TripleGen", num_triples, TRACKER_LOG_PERCENTAGE);
        let random_progress_tracker =
            ProgressTracker::new("RandomGen", num_randomness, TRACKER_LOG_PERCENTAGE);
        let bit_progress_tracker = ProgressTracker::new("BitGen", num_bits, TRACKER_LOG_PERCENTAGE);

        Self {
            poly_size,
            dkg_preproc: Arc::new(RwLock::new(InMemoryBGVDkgPreprocessing::default())),
            triple_progress_tracker,
            random_progress_tracker,
            bit_progress_tracker,
        }
    }

    #[instrument(name="Preprocessing BGV",skip(self,sessions),fields(num_sessions=?sessions.len(), percentage_offline))]
    pub async fn orchestrate_small_session_bgv_dkg_preprocessing(
        self,
        mut sessions: Vec<SmallSession<LevelKsw>>,
    ) -> SmallSessionBGVDkgResult {
        let (num_bits, num_triples, num_randomness) =
            get_num_correlated_randomness_required(self.poly_size);

        //Ensures sessions are sorted by session id
        sessions.sort_by_key(|session| session.session_id());

        //Dedicate 1 in 20 sessions to raw triples, 1 session for randomness
        //and the rest for bits
        let num_triples_sessions = div_ceil(sessions.len(), 20);
        let triple_sessions: Vec<_> = (0..num_triples_sessions)
            .map(|_| {
                sessions.pop().ok_or_else(|| {
                    anyhow_error_and_log("Fail to retrieve sessions for basic preprocessing")
                })
            })
            .try_collect()?;

        let randomness_sessions: Vec<_> = (0..1)
            .map(|_| {
                sessions.pop().ok_or_else(|| {
                    anyhow_error_and_log("Fail to retrieve sessions for basic preprocessing")
                })
            })
            .try_collect()?;

        //Create all the channels we need for the producer to communicate their batches
        let (
            (triple_sender_channels, triple_receiver_channels),
            (random_sender_channels, random_receiver_channels),
            (bit_sender_channels, bit_receiver_channels),
        ) = create_channels::<LevelKsw>(num_triples_sessions, 1, sessions.len());

        let current_span = tracing::Span::current();
        let mut joinset_processors = JoinSet::new();

        //Start the processors
        let triple_writer = self.dkg_preproc.clone();
        let triple_aggregator =
            TriplesAggregator::new(triple_writer, triple_receiver_channels, num_triples);
        joinset_processors.spawn(triple_aggregator.run().instrument(current_span.clone()));

        let random_writer = self.dkg_preproc.clone();
        let random_aggregator =
            RandomsAggregator::new(random_writer, random_receiver_channels, num_randomness);
        joinset_processors.spawn(random_aggregator.run().instrument(current_span.clone()));

        let bit_writer = self.dkg_preproc.clone();
        let bit_processor =
            BGVDkgBitProcessor::new(bit_writer, self.poly_size, bit_receiver_channels);
        joinset_processors.spawn(bit_processor.run().instrument(current_span.clone()));

        //Start the producers
        let triple_producer = SmallSessionTripleProducer::new(
            BGV_BATCH_SIZE_TRIPLES,
            num_triples,
            triple_sessions,
            triple_sender_channels,
            Some(self.triple_progress_tracker),
        )?;
        let mut triple_producer_handles = triple_producer.start_triple_production();

        let randomness_producer = SmallSessionRandomProducer::new(
            BGV_BATCH_SIZE_RANDOMS,
            num_randomness,
            randomness_sessions,
            random_sender_channels,
            Some(self.random_progress_tracker),
        )?;
        let mut randomness_producer_handles = randomness_producer.start_random_production();

        let bit_producer = SmallSessionBitProducer::new(
            BGV_BATCH_SIZE_BITS,
            num_bits,
            sessions,
            bit_sender_channels,
            Some(self.bit_progress_tracker),
        )?;
        let mut bit_producer_handles = bit_producer.start_bit_gen_odd_production();

        //Join on producers
        let mut res_sessions = Vec::new();
        while let Some(Ok(Ok(session))) = triple_producer_handles.join_next().await {
            res_sessions.push(session);
        }
        while let Some(Ok(Ok(session))) = randomness_producer_handles.join_next().await {
            res_sessions.push(session);
        }
        while let Some(Ok(Ok(session))) = bit_producer_handles.join_next().await {
            res_sessions.push(session);
        }

        res_sessions.sort_by_key(|session| session.session_id());

        //Join on the processors
        while joinset_processors.join_next().await.is_some() {}

        //Return handle to preprocessing bucket
        let dkg_preproc_return = Arc::into_inner(self.dkg_preproc).ok_or_else(|| {
            anyhow_error_and_log("Error getting hold of dkg preprocessing store inside the Arc")
        })?;
        let dkg_preproc_return = dkg_preproc_return.into_inner().map_err(|_| {
            anyhow_error_and_log("Error consuming dkg preprocessing inside the Lock")
        })?;
        Ok((res_sessions, dkg_preproc_return))
    }
}

pub struct BGVDkgBitProcessor {
    output_writer: Arc<RwLock<InMemoryBGVDkgPreprocessing>>,
    num_ternary: usize,
    num_noise: usize,
    bit_receiver_channels: Vec<Mutex<Receiver<Vec<Share<LevelKsw>>>>>,
}

impl BGVDkgBitProcessor {
    pub fn new(
        output_writer: Arc<RwLock<InMemoryBGVDkgPreprocessing>>,
        poly_size: usize,
        bit_receiver_channels: Vec<Mutex<Receiver<Vec<Share<LevelKsw>>>>>,
    ) -> Self {
        Self {
            output_writer,
            num_ternary: poly_size,
            num_noise: 2 * poly_size,
            bit_receiver_channels,
        }
    }

    #[instrument(name = "BGV Bit Processing", skip(self), fields(num_ternary=?self.num_ternary,num_noise=?self.num_noise))]
    async fn run(mut self) -> anyhow::Result<()> {
        let inner_bit_receiver_channels = self.bit_receiver_channels;
        let mut receiver_iterator = inner_bit_receiver_channels.iter().cycle();
        let mut bit_batch: Vec<Share<LevelKsw>> = Vec::new();

        // Fill ternary
        let ternary_required_bits = 2;

        while self.num_ternary != 0 {
            if bit_batch.len() < ternary_required_bits {
                bit_batch.extend(
                    receiver_iterator
                        .next()
                        .ok_or_else(|| anyhow_error_and_log("Error in channel iterator"))?
                        .lock()
                        .await
                        .recv()
                        .await
                        .ok_or_else(|| {
                            anyhow_error_and_log(format!(
                                "Error receiving bits, remaining {}",
                                self.num_ternary
                            ))
                        })?,
                );
            }
            let num_bits_available = bit_batch.len();
            let num_ternary = std::cmp::min(
                self.num_ternary,
                num_integer::Integer::div_floor(&num_bits_available, &ternary_required_bits),
            );
            let mut bit_preproc = InMemoryBitPreprocessing {
                available_bits: bit_batch
                    .drain(..num_ternary * ternary_required_bits)
                    .collect(),
            };

            (*self
                .output_writer
                .write()
                .map_err(|e| anyhow_error_and_log(format!("Locking Error: {e}")))?)
            .append_ternary(RealSecretDistributions::newhope(
                num_ternary,
                1,
                &mut bit_preproc,
            )?);
            self.num_ternary -= num_ternary;
        }

        //Fill noise
        let noise_required_bits = NEW_HOPE_BOUND * 2;

        while self.num_noise != 0 {
            if bit_batch.len() < noise_required_bits {
                bit_batch.extend(
                    receiver_iterator
                        .next()
                        .ok_or_else(|| anyhow_error_and_log("Error in channel iterator"))?
                        .lock()
                        .await
                        .recv()
                        .await
                        .ok_or_else(|| {
                            anyhow_error_and_log(format!(
                                "Error receiving bits, remaining {}",
                                self.num_ternary
                            ))
                        })?,
                );
            }
            let num_bits_available = bit_batch.len();
            let num_noise = std::cmp::min(
                self.num_noise,
                num_integer::Integer::div_floor(&num_bits_available, &noise_required_bits),
            );
            let mut bit_preproc = InMemoryBitPreprocessing {
                available_bits: bit_batch.drain(..num_noise * noise_required_bits).collect(),
            };

            (*self
                .output_writer
                .write()
                .map_err(|e| anyhow_error_and_log(format!("Locking Error: {e}")))?)
            .append_noise(RealSecretDistributions::newhope(
                num_noise,
                NEW_HOPE_BOUND,
                &mut bit_preproc,
            )?);
            self.num_noise -= num_noise;
        }
        Ok(())
    }
}

impl SmallSessionBitProducer<LevelKsw> {
    #[instrument(name="Bit Odd Factory",skip(self),fields(num_sessions= ?self.producers.len()))]
    pub fn start_bit_gen_odd_production(
        self,
    ) -> JoinSet<Result<SmallSession<LevelKsw>, anyhow::Error>> {
        let num_producers = self.producers.len();
        let num_loops = div_ceil(self.total_size, self.batch_size * num_producers);

        let batch_size = self.batch_size;
        let task_gen = |mut session: SmallSession<LevelKsw>,
                        sender_channel: Sender<Vec<Share<LevelKsw>>>,
                        progress_tracker: Option<ProgressTracker>| async move {
            let base_batch_size = BatchParams {
                triples: batch_size,
                randoms: batch_size,
            };

            for _ in 0..num_loops {
                let mut preproc = SmallPreprocessing::<LevelKsw, RealAgreeRandom>::init(
                    &mut session,
                    base_batch_size,
                )
                .await?;
                let bits =
                    RealBitGenOdd::gen_bits_odd(batch_size, &mut preproc, &mut session).await?;

                //Drop the error on purpose as the receiver end might be closed already if we produced too much
                let _ = sender_channel.send(bits).await;
                progress_tracker.as_ref().map(|p| p.increment(batch_size));
            }
            Ok::<_, anyhow::Error>(session)
        };
        execute_preprocessing(self.producers, task_gen, self.progress_tracker)
    }
}

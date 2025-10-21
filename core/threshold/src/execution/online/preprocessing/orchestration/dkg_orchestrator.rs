use super::{
    consumers::{
        dkg_bits_processor::DkgBitProcessor, randoms_aggregator::RandomsAggregator,
        triples_aggregator::TriplesAggregator,
    },
    producer_traits::{BitProducerTrait, RandomProducerTrait, TripleProducerTrait},
    progress_tracker::ProgressTracker,
};
use crate::{
    algebra::{
        base_ring::{Z128, Z64},
        galois_rings::common::ResiduePoly,
        structure_traits::{Derive, ErrorCorrect, Invert, Solve},
    },
    error::error_handler::anyhow_error_and_log,
    execution::{
        keyset_config::KeySetConfig,
        online::{
            preprocessing::{
                constants::{
                    BATCH_SIZE_BITS, BATCH_SIZE_TRIPLES, CHANNEL_BUFFER_SIZE,
                    TRACKER_LOG_PERCENTAGE,
                },
                orchestration::producer_traits::ProducerFactory,
                DKGPreprocessing, PreprocessorFactory,
            },
            triple::Triple,
        },
        runtime::session::{DeSerializationRunTime, LargeSession, ParameterHandles, SmallSession},
        sharing::share::Share,
        small_execution::prf::PRSSConversions,
        tfhe_internals::parameters::{DKGParams, NoiseInfo},
    },
};
use itertools::Itertools;
use num_integer::div_ceil;
use std::sync::Arc;
use tokio::{
    sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex, RwLock,
    },
    task::JoinSet,
};
use tracing::{instrument, Instrument};

#[derive(Clone)]
pub struct PreprocessingOrchestrator<Z> {
    params: DKGParams,
    keyset_config: KeySetConfig,
    dkg_preproc: Arc<RwLock<Box<dyn DKGPreprocessing<Z>>>>,
    triple_progress_tracker: ProgressTracker,
    random_progress_tracker: ProgressTracker,
    bit_progress_tracker: ProgressTracker,
    // For testing purposes, can set the percentage of offline phase
    // we actually want to run
    #[cfg(feature = "choreographer")]
    percentage_offline: usize,
}

impl<Z> PreprocessingOrchestrator<Z> {
    /// Returns the [`ProgressTracker`] that tracks
    /// the triple generation process
    ///
    /// NB: Triple preprocessing is much faster
    /// than Bit preprocessing for DKG.
    /// Use [`Self::get_bit_progress_tracker`] to get a good
    /// estimate of the overall progress.
    pub fn get_triple_progress_tracker(&self) -> ProgressTracker {
        self.triple_progress_tracker.clone()
    }

    /// Returns the [`ProgressTracker`] that tracks
    /// the random generation process
    ///
    /// NB: Random processing is almost instantaneous in DKG.
    /// Use [`Self::get_bit_progress_tracker`] to get a good
    /// estimate of the overall progress.
    pub fn get_random_progress_tracker(&self) -> ProgressTracker {
        self.random_progress_tracker.clone()
    }

    /// Returns the [`ProgressTracker`] that tracks
    /// the bit generation process
    ///
    /// NB: Bit processing is a very accurate proxy to measure the
    /// progress of the whole offline phase of DKG.
    pub fn get_bit_progress_tracker(&self) -> ProgressTracker {
        self.bit_progress_tracker.clone()
    }

    fn num_tuniform_raw_bits_required(&self) -> (Vec<NoiseInfo>, usize) {
        get_num_tuniform_raw_bits_required(
            &self.params,
            self.keyset_config,
            #[cfg(feature = "choreographer")]
            self.percentage_offline,
        )
    }

    fn num_correlated_randomness_required(&self) -> (usize, usize, usize) {
        get_num_correlated_randomness_required(
            &self.params,
            self.keyset_config,
            #[cfg(feature = "choreographer")]
            self.percentage_offline,
        )
    }
}

impl<const EXTENSION_DEGREE: usize> PreprocessingOrchestrator<ResiduePoly<Z64, EXTENSION_DEGREE>> {
    ///Create a new [`PreprocessingOrchestrator`] to generate
    ///offline data required by [`crate::execution::endpoints::keygen::distributed_keygen`]
    ///for [`DKGParams::WithoutSnS`]
    ///
    ///Relies on the provided [`PreprocessorFactory`] to create:
    ///- [`DKGPreprocessing`]
    pub fn new<F: PreprocessorFactory<EXTENSION_DEGREE> + ?Sized>(
        factory: &mut F,
        params: DKGParams,
        keyset_config: KeySetConfig,
    ) -> anyhow::Result<Self> {
        if let DKGParams::WithSnS(_) = params {
            return Err(anyhow_error_and_log("Cant have SnS with ResiduePolyF8Z64"));
        }

        let (num_bits, num_triples, num_randomness) = get_num_correlated_randomness_required(
            &params,
            keyset_config,
            #[cfg(feature = "choreographer")]
            100,
        );

        let triple_progress_tracker =
            ProgressTracker::new("TripleGen", num_triples, TRACKER_LOG_PERCENTAGE);
        let random_progress_tracker =
            ProgressTracker::new("RandomGen", num_randomness, TRACKER_LOG_PERCENTAGE);
        let bit_progress_tracker = ProgressTracker::new("BitGen", num_bits, TRACKER_LOG_PERCENTAGE);

        Ok(Self {
            params,
            keyset_config,
            dkg_preproc: Arc::new(RwLock::new(factory.create_dkg_preprocessing_no_sns())),
            triple_progress_tracker,
            random_progress_tracker,
            bit_progress_tracker,
            #[cfg(feature = "choreographer")]
            percentage_offline: 100,
        })
    }

    #[cfg(feature = "choreographer")]
    pub fn new_partial<F: PreprocessorFactory<EXTENSION_DEGREE> + ?Sized>(
        factory: &mut F,
        params: DKGParams,
        keyset_config: KeySetConfig,
        percentage_offline: usize,
    ) -> anyhow::Result<Self> {
        if let DKGParams::WithSnS(_) = params {
            return Err(anyhow_error_and_log("Cant have SnS with ResiduePolyF8Z64"));
        }

        assert!(percentage_offline <= 100 && percentage_offline > 0);

        let (num_bits, num_triples, num_randomness) =
            get_num_correlated_randomness_required(&params, keyset_config, percentage_offline);

        let triple_progress_tracker =
            ProgressTracker::new("TripleGen", num_triples, TRACKER_LOG_PERCENTAGE);
        let random_progress_tracker =
            ProgressTracker::new("RandomGen", num_randomness, TRACKER_LOG_PERCENTAGE);
        let bit_progress_tracker = ProgressTracker::new("BitGen", num_bits, TRACKER_LOG_PERCENTAGE);

        Ok(Self {
            params,
            keyset_config,
            triple_progress_tracker,
            random_progress_tracker,
            bit_progress_tracker,
            dkg_preproc: Arc::new(RwLock::new(factory.create_dkg_preprocessing_no_sns())),
            percentage_offline,
        })
    }
}

impl<const EXTENSION_DEGREE: usize> PreprocessingOrchestrator<ResiduePoly<Z128, EXTENSION_DEGREE>> {
    ///Create a new [`PreprocessingOrchestrator`] to generate
    ///offline data required by [`crate::execution::endpoints::keygen::distributed_keygen`]
    ///for [`DKGParams::WithSnS`]
    ///
    ///Relies on the provided [`PreprocessorFactory`] to create:
    ///- [`DKGPreprocessing`]
    pub fn new<F: PreprocessorFactory<EXTENSION_DEGREE> + ?Sized>(
        factory: &mut F,
        params: DKGParams,
        keyset_config: KeySetConfig,
    ) -> anyhow::Result<Self> {
        if let DKGParams::WithoutSnS(_) = params {
            return Err(anyhow_error_and_log(
                "Should not have no SNS with ResiduePolyF8Z128",
            ));
        }

        let (num_bits, num_triples, num_randomness) = get_num_correlated_randomness_required(
            &params,
            keyset_config,
            #[cfg(feature = "choreographer")]
            100,
        );

        let triple_progress_tracker =
            ProgressTracker::new("TripleGen", num_triples, TRACKER_LOG_PERCENTAGE);
        let random_progress_tracker =
            ProgressTracker::new("RandomGen", num_randomness, TRACKER_LOG_PERCENTAGE);
        let bit_progress_tracker = ProgressTracker::new("BitGen", num_bits, TRACKER_LOG_PERCENTAGE);

        Ok(Self {
            params,
            keyset_config,
            dkg_preproc: Arc::new(RwLock::new(factory.create_dkg_preprocessing_with_sns())),
            triple_progress_tracker,
            random_progress_tracker,
            bit_progress_tracker,
            #[cfg(feature = "choreographer")]
            percentage_offline: 100,
        })
    }

    #[cfg(feature = "choreographer")]
    pub fn new_partial<F: PreprocessorFactory<EXTENSION_DEGREE> + ?Sized>(
        factory: &mut F,
        params: DKGParams,
        keyset_config: KeySetConfig,
        percentage_offline: usize,
    ) -> anyhow::Result<Self> {
        if let DKGParams::WithoutSnS(_) = params {
            return Err(anyhow_error_and_log(
                "Should not have no SNS with ResiduePolyF8Z128",
            ));
        }

        assert!(percentage_offline <= 100 && percentage_offline > 0);

        let (num_bits, num_triples, num_randomness) =
            get_num_correlated_randomness_required(&params, keyset_config, percentage_offline);

        let triple_progress_tracker =
            ProgressTracker::new("TripleGen", num_triples, TRACKER_LOG_PERCENTAGE);
        let random_progress_tracker =
            ProgressTracker::new("RandomGen", num_randomness, TRACKER_LOG_PERCENTAGE);
        let bit_progress_tracker = ProgressTracker::new("BitGen", num_bits, TRACKER_LOG_PERCENTAGE);

        Ok(Self {
            params,
            keyset_config,
            triple_progress_tracker,
            random_progress_tracker,
            bit_progress_tracker,
            dkg_preproc: Arc::new(RwLock::new(factory.create_dkg_preprocessing_with_sns())),
            percentage_offline,
        })
    }
}

type TripleChannels<R> = (
    Vec<Sender<Vec<Triple<R>>>>,
    Vec<Mutex<Receiver<Vec<Triple<R>>>>>,
);
type ShareChannels<R> = (
    Vec<Sender<Vec<Share<R>>>>,
    Vec<Mutex<Receiver<Vec<Share<R>>>>>,
);

///Creates three sets of channels:
///- One set for Triples
///- One set for Randomness
///- One set for Bits
pub(crate) fn create_channels<R: Clone>(
    num_triple_sessions: usize,
    num_random_sessions: usize,
    num_bits_sessions: usize,
) -> (TripleChannels<R>, ShareChannels<R>, ShareChannels<R>) {
    let mut triple_sender_channels = Vec::new();
    let mut triple_receiver_channels = Vec::new();
    for _ in 0..num_triple_sessions {
        let (tx, rx) = channel::<Vec<Triple<R>>>(CHANNEL_BUFFER_SIZE);
        triple_sender_channels.push(tx);
        triple_receiver_channels.push(Mutex::new(rx));
    }

    //Always have only one random producing thread as it's super fast to produce
    let mut random_sender_channels = Vec::new();
    let mut random_receiver_channels = Vec::new();
    for _ in 0..num_random_sessions {
        let (tx, rx) = channel::<Vec<Share<R>>>(CHANNEL_BUFFER_SIZE);
        random_sender_channels.push(tx);
        random_receiver_channels.push(Mutex::new(rx));
    }

    let mut bit_sender_channels = Vec::new();
    let mut bit_receiver_channels = Vec::new();
    for _ in 0..num_bits_sessions {
        let (tx, rx) = channel::<Vec<Share<R>>>(CHANNEL_BUFFER_SIZE);
        bit_sender_channels.push(tx);
        bit_receiver_channels.push(Mutex::new(rx));
    }
    (
        (triple_sender_channels, triple_receiver_channels),
        (random_sender_channels, random_receiver_channels),
        (bit_sender_channels, bit_receiver_channels),
    )
}

impl<Z> PreprocessingOrchestrator<Z>
where
    Z: PRSSConversions + ErrorCorrect + Invert + Derive + Solve,
{
    ///Start the orchestration of the preprocessing, returning a filled [`DKGPreprocessing`].
    ///
    ///Expects a vector of sessions implementing the Session trait __(at least 2!)__, using each of them in parallel for the preprocessing.
    ///
    ///__NOTE__ For now we dedicate 1 in 20 sessions
    /// to raw triple and randomness generation and the rest to bit generation
    #[instrument(name="Preprocessing",skip(self,sessions),fields(num_sessions=?sessions.len(), percentage_offline))]
    pub(crate) async fn orchestrate_dkg_processing<S, P>(
        self,
        mut sessions: Vec<S>,
    ) -> anyhow::Result<(Vec<S>, Box<dyn DKGPreprocessing<Z>>)>
    where
        S: ParameterHandles + 'static,
        P: ProducerFactory<Z, S>,
    {
        #[cfg(feature = "choreographer")]
        tracing::Span::current().record("percentage_offline", self.percentage_offline);

        let party_id = sessions[0].my_role();
        for session in sessions.iter() {
            assert_eq!(party_id, session.my_role());
        }

        let (num_bits, num_triples, num_randomness) = self.num_correlated_randomness_required();

        //Ensures sessions are sorted by session id
        sessions.sort_by_key(|session| session.session_id());

        // Set the deserialization runtime for each session
        for session in sessions.iter_mut() {
            session.set_deserialization_runtime(DeSerializationRunTime::Rayon);
        }

        //Dedicate 1 in 20 sessions to raw triples, the rest to bits
        let num_basic_sessions = div_ceil(sessions.len(), 20);
        let basic_sessions: Vec<_> = (0..num_basic_sessions)
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
        ) = create_channels(num_basic_sessions, 1, sessions.len());

        let current_span = tracing::Span::current();
        //Start the processors
        let mut joinset_processors = JoinSet::new();

        let triple_writer = self.dkg_preproc.clone();
        let triple_aggregator =
            TriplesAggregator::new(triple_writer, triple_receiver_channels, num_triples);
        joinset_processors.spawn(triple_aggregator.run().instrument(current_span.clone()));

        let random_writer = self.dkg_preproc.clone();
        let random_aggregator =
            RandomsAggregator::new(random_writer, random_receiver_channels, num_randomness);
        joinset_processors.spawn(random_aggregator.run().instrument(current_span.clone()));

        let bit_writer = self.dkg_preproc.clone();
        let (tuniform_productions, num_bits_required) = self.num_tuniform_raw_bits_required();
        let bit_processor = DkgBitProcessor::new(
            bit_writer,
            tuniform_productions,
            num_bits_required,
            bit_receiver_channels,
        );
        joinset_processors.spawn(bit_processor.run().instrument(current_span.clone()));

        //Start the producers
        let triple_producer = P::TripleProducer::new(
            BATCH_SIZE_TRIPLES,
            num_triples,
            basic_sessions,
            triple_sender_channels,
            Some(self.triple_progress_tracker),
        )?;
        let mut triple_producer_handles = triple_producer.start_triple_production();

        let bit_producer = P::BitProducer::new(
            BATCH_SIZE_BITS,
            num_bits,
            sessions,
            bit_sender_channels,
            Some(self.bit_progress_tracker),
        )?;
        let mut bit_producer_handles = bit_producer.start_bit_gen_even_production();

        //Join on the triple producers as they finish before bit producers, raising errors if any
        let mut res_sessions = Vec::new();
        while let Some(session) = triple_producer_handles.join_next().await {
            res_sessions.push(session??);
        }

        res_sessions.sort_by_key(|session| session.session_id());
        //Start producers for randomness
        let randomness_session = res_sessions
            .pop()
            .ok_or_else(|| anyhow_error_and_log("Failed to pop a session for randomness"))?;
        let randomness_producer = P::RandomProducer::new(
            num_randomness,
            num_randomness,
            vec![randomness_session],
            random_sender_channels,
            Some(self.random_progress_tracker),
        )?;
        let mut randomness_producer_handle = randomness_producer.start_random_production();

        //Join on bits and randomness producers, raising errors if any
        while let Some(session) = randomness_producer_handle.join_next().await {
            res_sessions.push(session??);
        }
        while let Some(session) = bit_producer_handles.join_next().await {
            res_sessions.push(session??);
        }

        res_sessions.sort_by_key(|session| session.session_id());
        //Join on the processors
        while joinset_processors.join_next().await.is_some() {}

        //Return handle to preprocessing bucket
        let dkg_preproc_return = Arc::into_inner(self.dkg_preproc).ok_or_else(|| {
            anyhow_error_and_log("Error getting hold of dkg preprocessing store inside the Arc")
        })?;
        let dkg_preproc_return = dkg_preproc_return.into_inner();
        Ok((res_sessions, dkg_preproc_return))
    }

    pub async fn orchestrate_dkg_processing_small_session<
        P: ProducerFactory<Z, SmallSession<Z>>,
    >(
        self,
        sessions: Vec<SmallSession<Z>>,
    ) -> anyhow::Result<(Vec<SmallSession<Z>>, Box<dyn DKGPreprocessing<Z>>)> {
        self.orchestrate_dkg_processing::<_, P>(sessions).await
    }

    pub async fn orchestrate_dkg_processing_large_session<P: ProducerFactory<Z, LargeSession>>(
        self,
        sessions: Vec<LargeSession>,
    ) -> anyhow::Result<(Vec<LargeSession>, Box<dyn DKGPreprocessing<Z>>)> {
        self.orchestrate_dkg_processing::<_, P>(sessions).await
    }
}

///Returns the numbers of bits, triples and randomness we need to produce
fn get_num_correlated_randomness_required(
    params: &DKGParams,
    keyset_config: KeySetConfig,
    #[cfg(feature = "choreographer")] percentage_offline: usize,
) -> (usize, usize, usize) {
    let params_basics_handle = params.get_params_basics_handle();

    let num_bits = params_basics_handle.total_bits_required(keyset_config);
    let num_triples = params_basics_handle.total_triples_required(keyset_config) - num_bits;
    let num_randomness = params_basics_handle.total_randomness_required(keyset_config) - num_bits;

    #[cfg(feature = "choreographer")]
    {
        let (num_bits, num_triples, num_randomness) = if percentage_offline < 100 {
            (
                (num_bits * percentage_offline).div_ceil(100),
                (num_triples * percentage_offline).div_ceil(100),
                (num_randomness * percentage_offline).div_ceil(100),
            )
        } else {
            (num_bits, num_triples, num_randomness)
        };
        tracing::info!(
            "About to create {} bits, {} triples and {} randomness",
            num_bits,
            num_triples,
            num_randomness
        );
        (num_bits, num_triples, num_randomness)
    }
    #[cfg(not(feature = "choreographer"))]
    {
        tracing::info!(
            "About to create {} bits, {} triples and {} randomness",
            num_bits,
            num_triples,
            num_randomness
        );
        (num_bits, num_triples, num_randomness)
    }
}

///Returns the numbers of TUniform required as well as the number of raw bits
fn get_num_tuniform_raw_bits_required(
    params: &DKGParams,
    keyset_config: KeySetConfig,
    #[cfg(feature = "choreographer")] percentage_offline: usize,
) -> (Vec<NoiseInfo>, usize) {
    let mut tuniform_productions = Vec::new();
    let params_basics_handle = params.get_params_basics_handle();

    tuniform_productions.push(params_basics_handle.all_lwe_noise(keyset_config));
    tuniform_productions.push(params_basics_handle.all_glwe_noise(keyset_config));
    tuniform_productions.push(params_basics_handle.all_compression_ksk_noise(keyset_config));

    match params {
        DKGParams::WithSnS(sns_params) => {
            tuniform_productions.push(sns_params.all_bk_sns_noise());
            if sns_params.sns_compression_params.is_some() {
                tuniform_productions.push(sns_params.num_needed_noise_sns_compression_key());
            }
        }
        DKGParams::WithoutSnS(_) => (),
    }

    tuniform_productions.push(params_basics_handle.all_lwe_hat_noise(keyset_config));

    //Required number of _raw_ bits
    let num_bits_required = params_basics_handle.num_raw_bits(keyset_config);
    #[cfg(feature = "choreographer")]
    {
        let num_bits_required = if percentage_offline < 100 {
            for tuniform_production in tuniform_productions.iter_mut() {
                if tuniform_production.amount > 0 {
                    tuniform_production.amount =
                        (tuniform_production.amount * percentage_offline).div_ceil(100) - 1;
                }
            }
            // div_floor is unstable and we don't really care being super precise
            // so just do div_ceil - 1
            if num_bits_required == 0 {
                0
            } else {
                (num_bits_required * percentage_offline).div_ceil(100) - 1
            }
        } else {
            num_bits_required
        };
        tracing::info!(
            "Bits will be split into {:?}, and {} raw bits.",
            tuniform_productions,
            num_bits_required
        );
        (tuniform_productions, num_bits_required)
    }
    #[cfg(not(feature = "choreographer"))]
    {
        tracing::info!(
            "Bits will be split into {:?}, and {} raw bits.",
            tuniform_productions,
            num_bits_required
        );
        (tuniform_productions, num_bits_required)
    }
}

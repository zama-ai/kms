use super::{
    constants::{BATCH_SIZE_BITS, BATCH_SIZE_TRIPLES, CHANNEL_BUFFER_SIZE},
    memory::InMemoryBitPreprocessing,
    NoiseBounds,
};
use crate::{
    algebra::{
        residue_poly::{ResiduePoly128, ResiduePoly64},
        structure_traits::{Derive, ErrorCorrect, Invert, RingEmbed, Solve},
    },
    error::error_handler::anyhow_error_and_log,
    execution::{
        config::BatchParams,
        large_execution::offline::{LargePreprocessing, TrueDoubleSharing, TrueSingleSharing},
        online::{
            gen_bits::{BitGenEven, RealBitGenEven},
            preprocessing::{
                DKGPreprocessing, PreprocessorFactory, RandomPreprocessing, TriplePreprocessing,
            },
            secret_distributions::{RealSecretDistributions, SecretDistributions},
            triple::Triple,
        },
        runtime::session::{BaseSessionHandles, LargeSession, ParameterHandles, SmallSession},
        sharing::share::Share,
        small_execution::{
            agree_random::RealAgreeRandom, offline::SmallPreprocessing, prf::PRSSConversions,
        },
        tfhe_internals::parameters::DKGParams,
    },
};
use futures::Future;
use itertools::Itertools;
use num_integer::div_ceil;
use rand::{CryptoRng, Rng};
use std::sync::{Arc, RwLock};
use tfhe::shortint::EncryptionKeyChoice;
use tokio::{
    sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex,
    },
    task::JoinSet,
};
use tracing::{instrument, Instrument};

#[derive(Clone)]
pub struct PreprocessingOrchestrator<Z> {
    params: DKGParams,
    dkg_preproc: Arc<RwLock<Box<dyn DKGPreprocessing<Z>>>>,
}

#[derive(Debug)]
pub struct TUniformProduction {
    pub bound: NoiseBounds,
    pub amount: usize,
}

impl PreprocessingOrchestrator<ResiduePoly64> {
    ///Create a new [`PreprocessingOrchestrator`] to generate
    ///offline data required by [`crate::execution::endpoints::keygen::distributed_keygen`]
    ///for [`DKGParams::WithoutSnS`]
    ///
    ///Relies on the provided [`PreprocessorFactory`] to create:
    ///- [`DKGPreprocessing`]
    pub fn new<F: PreprocessorFactory + ?Sized>(
        factory: &mut F,
        params: DKGParams,
    ) -> anyhow::Result<Self> {
        if let DKGParams::WithSnS(_) = params {
            return Err(anyhow_error_and_log("Cant have SnS with ResiduePoly64"));
        }

        Ok(Self {
            params,
            dkg_preproc: Arc::new(RwLock::new(factory.create_dkg_preprocessing_no_sns())),
        })
    }
}

impl PreprocessingOrchestrator<ResiduePoly128> {
    ///Create a new [`PreprocessingOrchestrator`] to generate
    ///offline data required by [`crate::execution::endpoints::keygen::distributed_keygen`]
    ///for [`DKGParams::WithSnS`]
    ///
    ///Relies on the provided [`PreprocessorFactory`] to create:
    ///- [`DKGPreprocessing`]
    pub fn new<F: PreprocessorFactory + ?Sized>(
        factory: &mut F,
        params: DKGParams,
    ) -> anyhow::Result<Self> {
        if let DKGParams::WithoutSnS(_) = params {
            return Err(anyhow_error_and_log(
                "Should not have no SNS with ResiduePoly128",
            ));
        }

        Ok(Self {
            params,
            dkg_preproc: Arc::new(RwLock::new(factory.create_dkg_preprocessing_with_sns())),
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
fn create_channels<R: Clone>(
    num_basic_sessions: usize,
    num_bits_sessions: usize,
) -> (TripleChannels<R>, ShareChannels<R>, ShareChannels<R>) {
    let mut triple_sender_channels = Vec::new();
    let mut triple_receiver_channels = Vec::new();
    for _ in 0..num_basic_sessions {
        let (tx, rx) = channel::<Vec<Triple<R>>>(CHANNEL_BUFFER_SIZE);
        triple_sender_channels.push(tx);
        triple_receiver_channels.push(Mutex::new(rx));
    }

    //Always have only one random producing thread as it's super fast to produce
    let mut random_sender_channels = Vec::new();
    let mut random_receiver_channels = Vec::new();
    for _ in 0..1 {
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

type SmallSessionDkgResult<R> =
    anyhow::Result<(Vec<SmallSession<R>>, Box<dyn DKGPreprocessing<R>>)>;

impl<R> PreprocessingOrchestrator<R>
where
    R: PRSSConversions + ErrorCorrect + Invert + Derive + RingEmbed + Solve,
{
    ///Start the orchestration of the preprocessing, returning a filled [`DKGPreprocessing`].
    ///
    ///Expects a vector of [`SmallSession`] __(at least 2!)__, using each of them in parallel for the preprocessing.
    ///
    ///__NOTE__ For now we dedicate 1 in 20 sessions
    /// to raw triple and randomness generation and the rest to bit generation
    #[instrument(name="Preprocessing",skip(self,sessions),fields(num_sessions=?sessions.len()))]
    pub async fn orchestrate_small_session_dkg_processing(
        self,
        mut sessions: Vec<SmallSession<R>>,
    ) -> SmallSessionDkgResult<R> {
        let party_id = sessions[0].own_identity();
        for session in sessions.iter() {
            assert_eq!(party_id, session.own_identity());
        }

        let (num_bits, num_triples, num_randomness) = self.get_num_correlated_randomness_required();

        //Ensures sessions are sorted by session id
        sessions.sort_by_key(|session| session.session_id());

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
        ) = create_channels(num_basic_sessions, sessions.len());

        let current_span = tracing::Span::current();
        //Start the processors
        let mut joinset_processors = JoinSet::new();
        let triple_writer = self.dkg_preproc.clone();
        let _triple_processor = joinset_processors.spawn(
            Self::triple_processing(triple_writer, num_triples, triple_receiver_channels)
                .instrument(current_span.clone()),
        );

        let random_writer = self.dkg_preproc.clone();
        let _random_processor = joinset_processors.spawn(
            Self::randomness_processing(random_writer, num_randomness, random_receiver_channels)
                .instrument(current_span.clone()),
        );

        let bit_writer = self.dkg_preproc.clone();
        let (tuniform_productions, num_bits_required) = self.get_num_tuniform_raw_bits_required();
        let _bit_processor_thread = joinset_processors.spawn(
            Self::bit_processing(
                bit_writer,
                tuniform_productions,
                num_bits_required,
                bit_receiver_channels,
            )
            .instrument(current_span.clone()),
        );

        //Start the producers
        let mut triple_producer_handles = self.orchestrate_small_session_triple_processing(
            BATCH_SIZE_TRIPLES,
            num_triples,
            basic_sessions,
            triple_sender_channels,
        );
        let mut bit_producer_handles = self.orchestrate_small_session_bit_processing(
            BATCH_SIZE_BITS,
            num_bits,
            sessions,
            bit_sender_channels,
        );

        //Join on the triple producers as they finish before bit producers
        let mut res_sessions = Vec::new();
        while let Some(session) = triple_producer_handles.join_next().await {
            match session {
                Ok(Ok(session)) => {
                    res_sessions.push(session);
                }
                other => {
                    let _ = other.unwrap();
                }
            }
        }

        res_sessions.sort_by_key(|session| session.session_id());

        //Start producers for randomness
        let randomness_session = res_sessions
            .pop()
            .ok_or_else(|| anyhow_error_and_log("Failed to pop a session for randomness"))?;
        let mut randomness_producer_handle = self.orchestrate_small_session_random_processing(
            num_randomness,
            num_randomness,
            vec![randomness_session],
            random_sender_channels,
        );

        //Join on bits and randomness producers
        while let Some(Ok(Ok(session))) = randomness_producer_handle.join_next().await {
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

    ///Start the orchestration of the preprocessing, returning a filled [`DKGPreprocessing`].
    ///
    ///Expects a vector of [`LargeSession`] __(at least 2!)__, using each of them in parallel for the preprocessing.
    ///
    ///__NOTE__ For now we dedicate 1 in 20 sessions
    /// to raw triple and randomness generation and the rest to bit generation
    pub async fn orchestrate_large_session_dkg_processing(
        self,
        mut sessions: Vec<LargeSession>,
    ) -> anyhow::Result<(Vec<LargeSession>, Box<dyn DKGPreprocessing<R>>)> {
        let party_id = sessions[0].own_identity();
        for session in sessions.iter() {
            assert_eq!(party_id, session.own_identity());
        }

        let (num_bits, num_triples, num_randomness) = self.get_num_correlated_randomness_required();

        //Ensures sessions are sorted by session id
        sessions.sort_by_key(|session| session.session_id());

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
        ) = create_channels(num_basic_sessions, sessions.len());

        let current_span = tracing::Span::current();
        //Start the processors
        let mut joinset_processors = JoinSet::new();
        let triple_writer = self.dkg_preproc.clone();
        let _triple_processor = joinset_processors.spawn(
            Self::triple_processing(triple_writer, num_triples, triple_receiver_channels)
                .instrument(current_span.clone()),
        );

        let random_writer = self.dkg_preproc.clone();
        let _random_processor = joinset_processors.spawn(
            Self::randomness_processing(random_writer, num_randomness, random_receiver_channels)
                .instrument(current_span.clone()),
        );

        let bit_writer = self.dkg_preproc.clone();
        let (tuniform_productions, num_bits_required) = self.get_num_tuniform_raw_bits_required();
        let _bit_processor_thread = joinset_processors.spawn(
            Self::bit_processing(
                bit_writer,
                tuniform_productions,
                num_bits_required,
                bit_receiver_channels,
            )
            .instrument(current_span.clone()),
        );

        //Start the producers
        let mut triple_producer_handles = self.orchestrate_large_session_triple_processing(
            BATCH_SIZE_TRIPLES,
            num_triples,
            basic_sessions,
            triple_sender_channels,
        );
        let mut bit_producer_handles = self.orchestrate_large_session_bit_processing(
            BATCH_SIZE_BITS,
            num_bits,
            sessions,
            bit_sender_channels,
        );

        //Join on the triple producers as they finish before bit producers
        let mut res_sessions = Vec::new();
        while let Some(Ok(Ok(session))) = triple_producer_handles.join_next().await {
            res_sessions.push(session);
        }

        res_sessions.sort_by_key(|session| session.session_id());
        //Start producers for randomness
        let randomness_session = res_sessions
            .pop()
            .ok_or_else(|| anyhow_error_and_log("Failed to pop a session for randomness"))?;
        let mut randomness_producer_handle = self.orchestrate_large_session_random_processing(
            num_randomness,
            num_randomness,
            vec![randomness_session],
            random_sender_channels,
        );

        //Join on bits and randomness producers
        while let Some(Ok(Ok(session))) = randomness_producer_handle.join_next().await {
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

    ///Orchestrate triple preprocessing for [`SmallSession`]
    ///
    ///Expects:
    ///- a batch size,
    ///- the total size we need to generate
    ///- the set of [`SmallSession`] dedicated to this preprocessing
    ///- the set of [`Sender`] channels to send the result back
    ///
    /// Returns:
    ///- a [`JoinSet`] to the triple processing tasks
    #[instrument(name="Triple Factory",skip(self,sessions,sender_channels),fields(num_sessions= ?sessions.len()))]
    pub fn orchestrate_small_session_triple_processing(
        &self,
        batch_size: usize,
        total_size: usize,
        sessions: Vec<SmallSession<R>>,
        sender_channels: Vec<Sender<Vec<Triple<R>>>>,
    ) -> JoinSet<Result<SmallSession<R>, anyhow::Error>> {
        let num_sessions = sessions.len();
        let num_loops = div_ceil(total_size, batch_size * num_sessions);

        let task_gen = |mut session: SmallSession<R>, sender_channel: Sender<Vec<Triple<R>>>| async move {
            let base_batch_size = BatchParams {
                triples: batch_size,
                randoms: 0,
            };

            for _ in 0..num_loops {
                let triples =
                    SmallPreprocessing::<R, RealAgreeRandom>::init(&mut session, base_batch_size)
                        .await?
                        .next_triple_vec(batch_size)?;

                //Drop the error on purpose as the receiver end might be closed already if we produced too much
                let _ = sender_channel.send(triples).await;
            }
            Ok::<_, anyhow::Error>(session)
        };

        self.new_execute_preprocessing(sessions, task_gen, sender_channels)
    }

    ///Orchestrate randomness preprocessing for [`SmallSession`]
    ///
    ///Expects:
    ///- a batch size,
    ///- the total size we need to generate
    ///- the set of [`SmallSession`] dedicated to this preprocessing
    ///- the set of [`Sender`] channels to send the result back
    ///
    /// Returns:
    ///- a [`JoinSet`] to the randomness processing tasks
    #[instrument(name="Random Factory",skip(self,sessions,sender_channels),fields(num_sessions= ?sessions.len()))]
    pub fn orchestrate_small_session_random_processing(
        &self,
        batch_size: usize,
        total_size: usize,
        sessions: Vec<SmallSession<R>>,
        sender_channels: Vec<Sender<Vec<Share<R>>>>,
    ) -> JoinSet<Result<SmallSession<R>, anyhow::Error>> {
        let num_sessions = sessions.len();
        let num_loops = div_ceil(total_size, batch_size * num_sessions);

        let task_gen = |mut session: SmallSession<R>, sender_channel: Sender<Vec<Share<R>>>| async move {
            let base_batch_size = BatchParams {
                triples: 0,
                randoms: batch_size,
            };

            for _ in 0..num_loops {
                let randoms =
                    SmallPreprocessing::<R, RealAgreeRandom>::init(&mut session, base_batch_size)
                        .await?
                        .next_random_vec(batch_size)?;

                //Drop the error on purpose as the receiver end might be closed already if we produced too much
                let _ = sender_channel.send(randoms).await;
            }
            Ok::<_, anyhow::Error>(session)
        };

        self.new_execute_preprocessing(sessions, task_gen, sender_channels)
    }

    ///Orchestrate bit preprocessing for [`SmallSession`]
    ///
    ///Expects:
    ///- a batch size,
    ///- the total size we need to generate
    ///- the set of [`SmallSession`] dedicated to this preprocessing
    ///- the set of [`Sender`] channels to send the result back
    ///
    /// Returns:
    ///- a [`JoinSet`] to the bit processing tasks
    #[instrument(name="Bit Factory",skip(self,sessions,sender_channels),fields(num_sessions= ?sessions.len()))]
    pub fn orchestrate_small_session_bit_processing(
        &self,
        batch_size: usize,
        total_size: usize,
        sessions: Vec<SmallSession<R>>,
        sender_channels: Vec<Sender<Vec<Share<R>>>>,
    ) -> JoinSet<Result<SmallSession<R>, anyhow::Error>> {
        let num_sessions = sessions.len();
        let num_loops = div_ceil(total_size, batch_size * num_sessions);

        let task_gen = |mut session: SmallSession<R>, sender_channel: Sender<Vec<Share<R>>>| async move {
            let base_batch_size = BatchParams {
                triples: batch_size,
                randoms: batch_size,
            };

            for _ in 0..num_loops {
                let mut preproc =
                    SmallPreprocessing::<R, RealAgreeRandom>::init(&mut session, base_batch_size)
                        .await?;
                let bits =
                    RealBitGenEven::gen_bits_even(batch_size, &mut preproc, &mut session).await?;

                //Drop the error on purpose as the receiver end might be closed already if we produced too much
                let _ = sender_channel.send(bits).await;
            }
            Ok::<_, anyhow::Error>(session)
        };
        self.new_execute_preprocessing(sessions, task_gen, sender_channels)
    }

    ///Orchestrate triple preprocessing for [`LargeSession`]
    ///
    ///Expects:
    ///- a batch size,
    ///- the total size we need to generate
    ///- the set of [`SmallSession`] dedicated to this preprocessing
    ///- the set of [`Sender`] channels to send the result back
    ///
    /// Returns:
    ///- a [`JoinSet`] to the triple processing tasks
    #[instrument(name="Triple Factory",skip(self,sessions,sender_channels),fields(num_sessions= ?sessions.len()))]
    pub fn orchestrate_large_session_triple_processing(
        &self,
        batch_size: usize,
        total_size: usize,
        sessions: Vec<LargeSession>,
        sender_channels: Vec<Sender<Vec<Triple<R>>>>,
    ) -> JoinSet<Result<LargeSession, anyhow::Error>> {
        let num_sessions = sessions.len();
        let num_loops = div_ceil(total_size, batch_size * num_sessions);

        let task_gen = |mut session: LargeSession, sender_channel: Sender<Vec<Triple<R>>>| async move {
            let base_batch_size = BatchParams {
                triples: batch_size,
                randoms: 0,
            };

            for _ in 0..num_loops {
                let triples = LargePreprocessing::<R, _, _>::init(
                    &mut session,
                    base_batch_size,
                    TrueSingleSharing::default(),
                    TrueDoubleSharing::default(),
                )
                .await?
                .next_triple_vec(batch_size)?;

                //Drop the error on purpose as the receiver end might be closed already if we produced too much
                let _ = sender_channel.send(triples).await;
            }
            Ok::<_, anyhow::Error>(session)
        };

        self.new_execute_preprocessing(sessions, task_gen, sender_channels)
    }

    ///Orchestrate randomness preprocessing for [`LargeSession`]
    ///
    ///Expects:
    ///- a batch size,
    ///- the total size we need to generate
    ///- the set of [`SmallSession`] dedicated to this preprocessing
    ///- the set of [`Sender`] channels to send the result back
    ///
    /// Returns:
    ///- a [`JoinSet`] to the randomness processing tasks
    #[instrument(name="Random Factory",skip(self,sessions,sender_channels),fields(num_sessions= ?sessions.len()))]
    pub fn orchestrate_large_session_random_processing(
        &self,
        batch_size: usize,
        total_size: usize,
        sessions: Vec<LargeSession>,
        sender_channels: Vec<Sender<Vec<Share<R>>>>,
    ) -> JoinSet<Result<LargeSession, anyhow::Error>> {
        let num_sessions = sessions.len();
        let num_loops = div_ceil(total_size, batch_size * num_sessions);

        let task_gen = |mut session: LargeSession, sender_channel: Sender<Vec<Share<R>>>| async move {
            let base_batch_size = BatchParams {
                triples: 0,
                randoms: batch_size,
            };

            for _ in 0..num_loops {
                let randoms = LargePreprocessing::<R, _, _>::init(
                    &mut session,
                    base_batch_size,
                    TrueSingleSharing::default(),
                    TrueDoubleSharing::default(),
                )
                .await?
                .next_random_vec(batch_size)?;

                //Drop the error on purpose as the receiver end might be closed already if we produced too much
                let _ = sender_channel.send(randoms).await;
            }
            Ok::<_, anyhow::Error>(session)
        };

        self.new_execute_preprocessing(sessions, task_gen, sender_channels)
    }

    ///Orchestrate bit preprocessing for [`LargeSession`]
    ///
    ///Expects:
    ///- a batch size,
    ///- the total size we need to generate
    ///- the set of [`SmallSession`] dedicated to this preprocessing
    ///- the set of [`Sender`] channels to send the result back
    ///
    /// Returns:
    ///- a [`JoinSet`] to the bit processing tasks
    #[instrument(name="Bit Factory",skip(self,sessions,sender_channels),fields(num_sessions= ?sessions.len()))]
    pub fn orchestrate_large_session_bit_processing(
        &self,
        batch_size: usize,
        total_size: usize,
        sessions: Vec<LargeSession>,
        sender_channels: Vec<Sender<Vec<Share<R>>>>,
    ) -> JoinSet<Result<LargeSession, anyhow::Error>> {
        let num_sessions = sessions.len();
        let num_loops = div_ceil(total_size, batch_size * num_sessions);

        let task_gen = |mut session: LargeSession, sender_channel: Sender<Vec<Share<R>>>| async move {
            let base_batch_size = BatchParams {
                triples: batch_size,
                randoms: batch_size,
            };

            for _ in 0..num_loops {
                let mut preproc = LargePreprocessing::<R, _, _>::init(
                    &mut session,
                    base_batch_size,
                    TrueSingleSharing::default(),
                    TrueDoubleSharing::default(),
                )
                .await?;
                let bits =
                    RealBitGenEven::gen_bits_even(batch_size, &mut preproc, &mut session).await?;

                //Drop the error on purpose as the receiver end might be closed already if we produced too much
                let _ = sender_channel.send(bits).await;
            }
            Ok::<_, anyhow::Error>(session)
        };

        self.new_execute_preprocessing(sessions, task_gen, sender_channels)
    }

    ///Generic functions that spawn the threads for processing
    fn new_execute_preprocessing<
        Rnd: Rng + CryptoRng + Sync + 'static,
        C,
        S: BaseSessionHandles<Rnd> + 'static,
        TaskOutput,
    >(
        &self,
        mut sessions: Vec<S>,
        task_gen: impl Fn(S, C) -> TaskOutput,
        sender_channels: Vec<C>,
    ) -> JoinSet<Result<S, anyhow::Error>>
    where
        TaskOutput: Future<Output = anyhow::Result<S>> + Send,
        TaskOutput: Send + 'static,
    {
        sessions.sort_by_key(|s| s.session_id());

        assert_eq!(sessions.len(), sender_channels.len());

        let span = tracing::Span::current();
        let mut tasks = JoinSet::new();
        for (session, channel) in sessions.into_iter().zip(sender_channels) {
            tasks.spawn(task_gen(session, channel).instrument(span.clone()));
        }

        tasks
    }

    ///Simple triple processing functions which pushes everything to the provided
    /// [`triple_writer`]
    async fn triple_processing(
        triple_writer: Arc<RwLock<Box<dyn DKGPreprocessing<R>>>>,
        num_triples: usize,
        triple_receiver_channels: Vec<Mutex<Receiver<Vec<Triple<R>>>>>,
    ) -> anyhow::Result<()> {
        let mut num_triples_needed = num_triples;
        let inner_triple_receiver_channels = triple_receiver_channels;
        let receiver_iterator = inner_triple_receiver_channels.iter().cycle();
        for receiver in receiver_iterator {
            let triple_batch = receiver
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| anyhow_error_and_log("Error receiving Triples"))?;
            let num_triples = std::cmp::min(num_triples_needed, triple_batch.len());
            (*triple_writer
                .write()
                .map_err(|e| anyhow_error_and_log(format!("Locking Error: {e}")))?)
            .append_triples(triple_batch[..num_triples].to_vec());
            num_triples_needed -= num_triples;
            if num_triples_needed == 0 {
                return Ok(());
            }
        }
        Ok::<_, anyhow::Error>(())
    }

    ///Simple triple processing functions which pushes everything to the provided
    /// [`randomness_writer`]
    async fn randomness_processing(
        randomness_writer: Arc<RwLock<Box<dyn DKGPreprocessing<R>>>>,
        num_randomness: usize,
        random_receiver_channels: Vec<Mutex<Receiver<Vec<Share<R>>>>>,
    ) -> anyhow::Result<()> {
        let mut num_randomness_needed = num_randomness;
        let inner_random_receiver_channels = random_receiver_channels;
        let receiver_iterator = inner_random_receiver_channels.iter().cycle();
        for receiver in receiver_iterator {
            let random_batch = receiver
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| anyhow_error_and_log("Error receiving Triples"))?;
            let num_randoms = std::cmp::min(num_randomness_needed, random_batch.len());
            (*randomness_writer
                .write()
                .map_err(|e| anyhow_error_and_log(format!("Locking Error: {e}")))?)
            .append_randoms(random_batch[..num_randoms].to_vec());
            num_randomness_needed -= num_randoms;
            if num_randomness_needed == 0 {
                return Ok(());
            }
        }
        Ok::<_, anyhow::Error>(())
    }

    ///Bit processing function that creates TUniform noise from bits, and pushes
    ///these and the desired amount of raw bits to the provided
    /// [`bit_writer`]
    #[instrument(skip(bit_writer, bit_receiver_channels))]
    async fn bit_processing(
        bit_writer: Arc<RwLock<Box<dyn DKGPreprocessing<R>>>>,
        mut tuniform_productions: Vec<TUniformProduction>,
        mut num_bits_required: usize,
        bit_receiver_channels: Vec<Mutex<Receiver<Vec<Share<R>>>>>,
    ) -> anyhow::Result<()> {
        let inner_bit_receiver_channels = bit_receiver_channels;
        let mut receiver_iterator = inner_bit_receiver_channels.iter().cycle();
        let mut bit_batch = Vec::new();
        for tuniform_production in tuniform_productions.iter_mut() {
            let tuniform_req_bits = tuniform_production.bound.get_bound().0 + 2;
            while tuniform_production.amount != 0 {
                if bit_batch.len() < tuniform_req_bits {
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
                                    tuniform_production.amount
                                ))
                            })?,
                    );
                }

                let num_bits_available = bit_batch.len();
                let num_tuniform = std::cmp::min(
                    tuniform_production.amount,
                    num_integer::Integer::div_floor(&num_bits_available, &tuniform_req_bits),
                );
                let mut bit_preproc = InMemoryBitPreprocessing {
                    available_bits: bit_batch
                        .drain(..num_tuniform * tuniform_req_bits)
                        .collect(),
                };
                (*bit_writer
                    .write()
                    .map_err(|e| anyhow_error_and_log(format!("Locking Error: {e}")))?)
                .append_noises(
                    RealSecretDistributions::t_uniform(
                        num_tuniform,
                        tuniform_production.bound.get_bound(),
                        &mut bit_preproc,
                    )?,
                    tuniform_production.bound,
                );
                tuniform_production.amount -= num_tuniform;
            }
        }

        while num_bits_required != 0 {
            if bit_batch.is_empty() {
                bit_batch = receiver_iterator
                    .next()
                    .ok_or_else(|| anyhow_error_and_log("Error in channel iterator"))?
                    .lock()
                    .await
                    .recv()
                    .await
                    .ok_or_else(|| {
                        anyhow_error_and_log(format!(
                            "Error receiving bits, remaining {}",
                            num_bits_required
                        ))
                    })?;
            }

            let num_bits_available = bit_batch.len();
            let num_bits = std::cmp::min(num_bits_required, num_bits_available);
            (*bit_writer
                .write()
                .map_err(|e| anyhow_error_and_log(format!("Locking Error: {e}")))?)
            .append_bits(bit_batch.drain(..num_bits).collect());
            num_bits_required -= num_bits;
        }
        Ok::<(), anyhow::Error>(())
    }

    ///Returns the numbers of bits, triples and randomness we need to produce
    fn get_num_correlated_randomness_required(&self) -> (usize, usize, usize) {
        let params_basics_handle = self.params.get_params_basics_handle();

        let num_bits = params_basics_handle.total_bits_required();
        let num_triples = params_basics_handle.total_triples_required() - num_bits;
        let num_randomness = params_basics_handle.total_randomness_required() - num_bits;

        (num_bits, num_triples, num_randomness)
    }

    ///Returns the numbers of TUniform required as well as the number of raw bits
    fn get_num_tuniform_raw_bits_required(&self) -> (Vec<TUniformProduction>, usize) {
        let mut tuniform_productions = Vec::new();
        let params_basics_handle = self.params.get_params_basics_handle();

        //Depending on encryption type of destination, pksk requires either LweNoise noise or GlweNoise
        let (amount_pksk_lwe_noise, amount_pksk_glwe_noise) = match params_basics_handle
            .get_pksk_destination()
        {
            //type = LWE case
            Some(EncryptionKeyChoice::Small) => (params_basics_handle.num_needed_noise_pksk(), 0),
            //type = F-GLWE case
            Some(EncryptionKeyChoice::Big) => (0, params_basics_handle.num_needed_noise_pksk()),
            _ => (0, 0),
        };

        tuniform_productions.push(TUniformProduction {
            bound: NoiseBounds::LweNoise(params_basics_handle.lwe_tuniform_bound()),
            amount: params_basics_handle.num_needed_noise_ksk() + amount_pksk_lwe_noise,
        });
        tuniform_productions.push(TUniformProduction {
            bound: NoiseBounds::GlweNoise(params_basics_handle.glwe_tuniform_bound()),
            amount: params_basics_handle.num_needed_noise_bk()
                + amount_pksk_glwe_noise
                + params_basics_handle.num_needed_noise_decompression_key(),
        });

        if let Some(bound) = params_basics_handle.compression_key_tuniform_bound() {
            tuniform_productions.push(TUniformProduction {
                bound: NoiseBounds::CompressionKSKNoise(bound),
                amount: params_basics_handle.num_needed_noise_compression_key(),
            });
        }

        match self.params {
            DKGParams::WithSnS(sns_params) => tuniform_productions.push(TUniformProduction {
                bound: NoiseBounds::GlweNoiseSnS(sns_params.glwe_tuniform_bound_sns()),
                amount: sns_params.num_needed_noise_bk_sns(),
            }),
            DKGParams::WithoutSnS(_) => (),
        }

        //pk requires LweHatNoise
        tuniform_productions.push(TUniformProduction {
            bound: NoiseBounds::LweHatNoise(params_basics_handle.lwe_hat_tuniform_bound()),
            amount: params_basics_handle.num_needed_noise_pk(),
        });

        //Required number of _raw_ bits
        let num_bits_required = params_basics_handle.lwe_dimension().0
            + params_basics_handle.lwe_hat_dimension().0
            + params_basics_handle.glwe_sk_num_bits()
            + params_basics_handle.compression_sk_num_bits()
            + match self.params {
                DKGParams::WithSnS(sns_params) => sns_params.glwe_sk_num_bits_sns(),
                DKGParams::WithoutSnS(_) => 0,
            };
        (tuniform_productions, num_bits_required)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc, thread};

    use itertools::Itertools;
    use tokio::sync::mpsc::{channel, Receiver, Sender};

    use crate::{
        algebra::{
            base_ring::Z64,
            residue_poly::ResiduePoly64,
            structure_traits::{One, Zero},
        },
        execution::{
            online::{
                preprocessing::{
                    create_memory_factory,
                    memory::{InMemoryBasePreprocessing, InMemoryBitPreprocessing},
                    BitPreprocessing, RandomPreprocessing, TriplePreprocessing,
                },
                triple::Triple,
            },
            runtime::{
                party::Identity,
                test_runtime::{generate_fixed_identities, DistributedTestRuntime},
            },
            sharing::{
                shamir::{RevealOp, ShamirSharings},
                share::Share,
            },
            tfhe_internals::parameters::NIST_PARAMS_P8_NO_SNS_FGLWE,
        },
        networking::NetworkMode,
        session_id::SessionId,
    };

    use super::PreprocessingOrchestrator;

    type TripleChannels<R> = (Vec<Sender<Vec<Triple<R>>>>, Vec<Receiver<Vec<Triple<R>>>>);
    type ShareChannels<R> = (Vec<Sender<Vec<Share<R>>>>, Vec<Receiver<Vec<Share<R>>>>);

    type ReceiverChannelCollection<R> = (
        Vec<Receiver<Vec<Triple<R>>>>,
        Vec<Receiver<Vec<Share<R>>>>,
        Vec<Receiver<Vec<Share<R>>>>,
    );

    const TEST_NUM_LOOP: usize = 5;

    fn create_test_channels<R: Clone>(
        num_basic_sessions: usize,
        num_bits_sessions: usize,
    ) -> (TripleChannels<R>, ShareChannels<R>, ShareChannels<R>) {
        let mut triple_sender_channels = Vec::new();
        let mut triple_receiver_channels = Vec::new();
        for _ in 0..num_basic_sessions {
            let (tx, rx) = channel::<Vec<Triple<R>>>(TEST_NUM_LOOP);
            triple_sender_channels.push(tx);
            triple_receiver_channels.push(rx);
        }

        let mut random_sender_channels = Vec::new();
        let mut random_receiver_channels = Vec::new();
        for _ in 0..num_basic_sessions {
            let (tx, rx) = channel::<Vec<Share<R>>>(TEST_NUM_LOOP);
            random_sender_channels.push(tx);
            random_receiver_channels.push(rx);
        }

        let mut bit_sender_channels = Vec::new();
        let mut bit_receiver_channels = Vec::new();
        for _ in 0..num_bits_sessions {
            let (tx, rx) = channel::<Vec<Share<R>>>(TEST_NUM_LOOP);
            bit_sender_channels.push(tx);
            bit_receiver_channels.push(rx);
        }
        (
            (triple_sender_channels, triple_receiver_channels),
            (random_sender_channels, random_receiver_channels),
            (bit_sender_channels, bit_receiver_channels),
        )
    }

    #[derive(Clone, Copy, Debug)]
    enum TypeOrchestration {
        Triples,
        Randoms,
        Bits,
    }
    fn check_triples_reconstruction(
        all_parties_channels: Vec<ReceiverChannelCollection<ResiduePoly64>>,
        identities: &[Identity],
        num_triples: usize,
        threshold: usize,
    ) {
        let mut triple_preprocs = all_parties_channels
            .into_iter()
            .map(|channels| {
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

    fn check_bits_reconstruction(
        all_parties_channels: Vec<ReceiverChannelCollection<ResiduePoly64>>,
        identities: &[Identity],
        num_bits: usize,
        threshold: usize,
    ) {
        let mut bit_preprocs = all_parties_channels
            .into_iter()
            .map(|channels| {
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

    fn check_randomness_reconstruction(
        all_parties_channels: Vec<ReceiverChannelCollection<ResiduePoly64>>,
        identities: &[Identity],
        num_randomness: usize,
        threshold: usize,
    ) {
        let mut random_preprocs = all_parties_channels
            .into_iter()
            .map(|channels| {
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

    fn test_orchestrator_large(
        num_sessions: u128,
        num_correlations: usize,
        batch_size: usize,
        num_parties: usize,
        threshold: u8,
        type_orchestration: TypeOrchestration,
    ) -> (Vec<Identity>, Vec<ReceiverChannelCollection<ResiduePoly64>>) {
        //Create identities and runtime
        let identities = generate_fixed_identities(num_parties);
        // Preprocessing assumes Sync network
        let runtimes = (0..num_sessions)
            .map(|_| {
                DistributedTestRuntime::<ResiduePoly64>::new(
                    identities.clone(),
                    threshold,
                    NetworkMode::Sync,
                    None,
                )
            })
            .collect_vec();
        let runtimes = Arc::new(runtimes);

        let mut threads = Vec::new();

        //For test runtime we need multiple runtimes for mutltiple channels
        let rt = tokio::runtime::Runtime::new().unwrap();
        for party_id in 0..num_parties {
            let runtimes = runtimes.clone();
            let rt_handle = rt.handle().clone();
            threads.push(thread::spawn(move || {
                //inside a party
                let _guard = rt_handle.enter();
                println!("Thread created for {party_id}");

                //For each party, create num_sessions sessions
                let sessions = runtimes
                    .iter()
                    .zip(0..num_sessions)
                    .map(|(runtime, session_id)| {
                        runtime.large_session_for_party(SessionId(session_id), party_id)
                    })
                    .collect_vec();

                let mut inmemory_factory = create_memory_factory();

                //DKGParams just for being able to call new (no SNS for ResiduePoly64)
                let params = NIST_PARAMS_P8_NO_SNS_FGLWE;

                let orchestrator = PreprocessingOrchestrator::<ResiduePoly64>::new(
                    inmemory_factory.as_mut(),
                    params,
                )
                .unwrap();

                let (
                    (triple_sender_channels, triple_receiver_channels),
                    (random_sender_channels, random_receiver_channels),
                    (bit_sender_channels, bit_receiver_channels),
                ) = create_test_channels(sessions.len(), sessions.len());

                let mut joinset = match type_orchestration {
                    TypeOrchestration::Triples => orchestrator
                        .orchestrate_large_session_triple_processing(
                            batch_size,
                            num_correlations,
                            sessions,
                            triple_sender_channels,
                        ),
                    TypeOrchestration::Randoms => orchestrator
                        .orchestrate_large_session_random_processing(
                            batch_size,
                            num_correlations,
                            sessions,
                            random_sender_channels,
                        ),
                    TypeOrchestration::Bits => orchestrator
                        .orchestrate_large_session_bit_processing(
                            batch_size,
                            num_correlations,
                            sessions,
                            bit_sender_channels,
                        ),
                };

                rt_handle.block_on(async { while joinset.join_next().await.is_some() {} });

                (
                    triple_receiver_channels,
                    random_receiver_channels,
                    bit_receiver_channels,
                )
            }));
        }

        let mut channels = Vec::new();
        for thread in threads {
            channels.push(thread.join().unwrap());
        }

        (identities, channels)
    }

    #[test]
    fn test_triple_orchestrator_large() {
        let num_parties = 5;
        let threshold = 1;
        let num_sessions = 5;

        //Each batch is 100 long
        let batch_size = 100;

        //Want 1k, so each session needs running twice (5 sessions, each batch is 100)
        let num_triples = num_sessions * batch_size * TEST_NUM_LOOP;

        let (identities, all_parties_channels) = test_orchestrator_large(
            num_sessions as u128,
            num_triples,
            batch_size,
            num_parties,
            threshold,
            TypeOrchestration::Triples,
        );

        check_triples_reconstruction(
            all_parties_channels,
            &identities,
            num_triples,
            threshold as usize,
        );
    }

    #[test]
    fn test_bit_orchestrator_large() {
        let num_parties = 5;
        let threshold = 1;
        let num_sessions = 5;

        //Each batch is 100 long
        let batch_size = 100;

        //Want 1k, so each session needs running twice (5 sessions, each batch is 100)
        let num_bits = num_sessions * batch_size * TEST_NUM_LOOP;

        let (identities, all_parties_channels) = test_orchestrator_large(
            num_sessions as u128,
            num_bits,
            batch_size,
            num_parties,
            threshold,
            TypeOrchestration::Bits,
        );

        check_bits_reconstruction(
            all_parties_channels,
            &identities,
            num_bits,
            threshold as usize,
        );
    }

    #[test]
    fn test_random_orchestrator_large() {
        let num_parties = 5;
        let threshold = 1;
        let num_sessions = 5;

        //Each batch is 100 long
        let batch_size = 100;

        //Want 1k, so each session needs running twice (5 sessions, each batch is 100)
        let num_randomness = num_sessions * batch_size * TEST_NUM_LOOP;

        let (identities, all_parties_channels) = test_orchestrator_large(
            num_sessions as u128,
            num_randomness,
            batch_size,
            num_parties,
            threshold,
            TypeOrchestration::Randoms,
        );

        check_randomness_reconstruction(
            all_parties_channels,
            &identities,
            num_randomness,
            threshold as usize,
        );
    }

    fn test_orchestrator_small(
        num_sessions: u128,
        num_correlations: usize,
        batch_size: usize,
        num_parties: usize,
        threshold: u8,
        type_orchestration: TypeOrchestration,
    ) -> (Vec<Identity>, Vec<ReceiverChannelCollection<ResiduePoly64>>) {
        //Create identities and runtime
        let identities = generate_fixed_identities(num_parties);
        // Preprocessing assumes Sync network
        let runtimes = (0..num_sessions)
            .map(|_| {
                DistributedTestRuntime::<ResiduePoly64>::new(
                    identities.clone(),
                    threshold,
                    NetworkMode::Sync,
                    None,
                )
            })
            .collect_vec();
        let runtimes = Arc::new(runtimes);

        let mut threads = Vec::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        for party_id in 0..num_parties {
            let runtimes = runtimes.clone();
            let rt_handle = rt.handle().clone();
            threads.push(thread::spawn(move || {
                let _guard = rt_handle.enter();
                println!("Thread created for {party_id}");

                //For each party, create num_sessions sessions
                let sessions = runtimes
                    .iter()
                    .zip(0..num_sessions)
                    .map(|(runtime, session_id)| {
                        runtime.small_session_for_party(SessionId(session_id), party_id, None)
                    })
                    .collect_vec();

                let mut inmemory_factory = create_memory_factory();

                //DKGParams just for being able to call new (no SNS for ResiduePoly64)
                let params = NIST_PARAMS_P8_NO_SNS_FGLWE;

                let orchestrator = PreprocessingOrchestrator::<ResiduePoly64>::new(
                    inmemory_factory.as_mut(),
                    params,
                )
                .unwrap();

                let (
                    (triple_sender_channels, triple_receiver_channels),
                    (random_sender_channels, random_receiver_channels),
                    (bit_sender_channels, bit_receiver_channels),
                ) = create_test_channels(sessions.len(), sessions.len());

                let mut joinset = match type_orchestration {
                    TypeOrchestration::Triples => orchestrator
                        .orchestrate_small_session_triple_processing(
                            batch_size,
                            num_correlations,
                            sessions,
                            triple_sender_channels,
                        ),
                    TypeOrchestration::Randoms => orchestrator
                        .orchestrate_small_session_random_processing(
                            batch_size,
                            num_correlations,
                            sessions,
                            random_sender_channels,
                        ),
                    TypeOrchestration::Bits => orchestrator
                        .orchestrate_small_session_bit_processing(
                            batch_size,
                            num_correlations,
                            sessions,
                            bit_sender_channels,
                        ),
                };

                rt_handle.block_on(async { while joinset.join_next().await.is_some() {} });

                (
                    triple_receiver_channels,
                    random_receiver_channels,
                    bit_receiver_channels,
                )
            }));
        }

        let mut channels = Vec::new();
        for thread in threads {
            channels.push(thread.join().unwrap());
        }

        (identities, channels)
    }

    #[test]
    fn test_triple_orchestrator_small() {
        let num_parties = 5;
        let threshold = 1;
        let num_sessions = 5;

        //Each batch is 100 long
        let batch_size = 100;

        //Want 1k, so each session needs running twice (5 sessions, each batch is 100)
        let num_triples = num_sessions * batch_size * TEST_NUM_LOOP;

        let (identities, all_parties_channels) = test_orchestrator_small(
            num_sessions as u128,
            num_triples,
            batch_size,
            num_parties,
            threshold,
            TypeOrchestration::Triples,
        );

        check_triples_reconstruction(
            all_parties_channels,
            &identities,
            num_triples,
            threshold as usize,
        );
    }

    #[test]
    fn test_bit_orchestrator_small() {
        let num_parties = 5;
        let threshold = 1;
        let num_sessions = 5;

        //Each batch is 100 long
        let batch_size = 100;

        //Want 1k, so each session needs running twice (5 sessions, each batch is 100)
        let num_bits = num_sessions * batch_size * TEST_NUM_LOOP;

        let (identities, all_parties_channels) = test_orchestrator_small(
            num_sessions as u128,
            num_bits,
            batch_size,
            num_parties,
            threshold,
            TypeOrchestration::Bits,
        );

        check_bits_reconstruction(
            all_parties_channels,
            &identities,
            num_bits,
            threshold as usize,
        );
    }

    #[test]
    fn test_randomness_orchestrator_small() {
        let num_parties = 5;
        let threshold = 1;
        let num_sessions = 5;

        //Each batch is 100 long
        let batch_size = 100;

        //Want 1k, so each session needs running twice (5 sessions, each batch is 100)
        let num_randomness = num_sessions * batch_size * TEST_NUM_LOOP;

        let (identities, all_parties_channels) = test_orchestrator_small(
            num_sessions as u128,
            num_randomness,
            batch_size,
            num_parties,
            threshold,
            TypeOrchestration::Randoms,
        );

        check_randomness_reconstruction(
            all_parties_channels,
            &identities,
            num_randomness,
            threshold as usize,
        );
    }
}

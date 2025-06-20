use std::future::Future;

use tokio::{sync::mpsc::Sender, task::JoinSet};
use tracing::Instrument;

use crate::execution::{
    online::preprocessing::orchestration::progress_tracker::ProgressTracker,
    runtime::session::BaseSessionHandles,
};

/// Struct that holds a session
/// and an outgoing channel
/// which will be filled with the result
/// of that session
pub(crate) struct ProducerSession<S: BaseSessionHandles, T> {
    session: S,
    sender_channel: Sender<T>,
}

impl<S: BaseSessionHandles, T> ProducerSession<S, T> {
    pub(crate) fn new(session: S, sender_channel: Sender<T>) -> Self {
        Self {
            session,
            sender_channel,
        }
    }
}

///Generic functions that spawn the threads for processing
pub(crate) fn execute_preprocessing<C, S: BaseSessionHandles + 'static, TaskOutput>(
    producer_sessions: Vec<ProducerSession<S, C>>,
    task_gen: impl Fn(S, Sender<C>, Option<ProgressTracker>) -> TaskOutput,
    progress_tracker: Option<ProgressTracker>,
) -> JoinSet<Result<S, anyhow::Error>>
where
    TaskOutput: Future<Output = anyhow::Result<S>> + Send,
    TaskOutput: Send + 'static,
{
    let span = tracing::Span::current();
    let mut tasks = JoinSet::new();
    for producer_session in producer_sessions.into_iter() {
        tasks.spawn(
            task_gen(
                producer_session.session,
                producer_session.sender_channel,
                progress_tracker.clone(),
            )
            .instrument(span.clone()),
        );
    }

    tasks
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{fmt::Display, sync::Arc, thread};

    use itertools::Itertools;
    use tokio::sync::mpsc::{channel, Receiver, Sender};

    use crate::{
        algebra::{
            base_ring::{Z128, Z64},
            galois_rings::common::ResiduePoly,
            structure_traits::{Derive, ErrorCorrect, Invert, Solve},
        },
        execution::{
            online::{
                preprocessing::orchestration::{
                    producer_traits::{BitProducerTrait, RandomProducerTrait, TripleProducerTrait},
                    producers::{
                        bits_producer::{
                            SecureLargeSessionBitProducer, SecureSmallSessionBitProducer,
                        },
                        randoms_producer::{
                            SecureLargeSessionRandomProducer, SecureSmallSessionRandomProducer,
                        },
                        triples_producer::{
                            SecureLargeSessionTripleProducer, SecureSmallSessionTripleProducer,
                        },
                    },
                    progress_tracker::ProgressTracker,
                },
                triple::Triple,
            },
            runtime::{
                party::Identity,
                test_runtime::{generate_fixed_identities, DistributedTestRuntime},
            },
            sharing::share::Share,
        },
        networking::NetworkMode,
        session_id::SessionId,
        thread_handles::OsThreadGroup,
    };

    pub type TripleChannels<R> = (Vec<Sender<Vec<Triple<R>>>>, Vec<Receiver<Vec<Triple<R>>>>);
    pub type ShareChannels<R> = (Vec<Sender<Vec<Share<R>>>>, Vec<Receiver<Vec<Share<R>>>>);

    pub type ReceiverChannelCollectionWithTracker<R> = (
        Vec<Receiver<Vec<Triple<R>>>>,
        Vec<Receiver<Vec<Share<R>>>>,
        Vec<Receiver<Vec<Share<R>>>>,
        ProgressTracker,
    );

    #[derive(Clone, Copy, Debug)]
    pub enum Typeproduction {
        Triples,
        Randoms,
        Bits,
    }

    impl Display for Typeproduction {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let s = match self {
                Typeproduction::Triples => "Triple",
                Typeproduction::Randoms => "Randoms",
                Typeproduction::Bits => "Bits",
            };
            write!(f, "{}", s)
        }
    }

    pub const TEST_NUM_LOOP: usize = 5;

    pub fn create_test_channels<R: Clone>(
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

    pub fn test_production_large<const EXTENSION_DEGREE: usize>(
        num_sessions: u128,
        num_correlations: usize,
        batch_size: usize,
        num_parties: usize,
        threshold: u8,
        type_production: Typeproduction,
    ) -> (
        Vec<Identity>,
        Vec<ReceiverChannelCollectionWithTracker<ResiduePoly<Z64, EXTENSION_DEGREE>>>,
    )
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
    {
        //Create identities and runtime
        let identities = generate_fixed_identities(num_parties);
        // Preprocessing assumes Sync network
        let runtimes =
            (0..num_sessions)
                .map(|_| {
                    DistributedTestRuntime::<
                    ResiduePoly<Z64, EXTENSION_DEGREE>,
                    EXTENSION_DEGREE ,
                >::new(identities.clone(), threshold, NetworkMode::Sync, None)
                })
                .collect_vec();
        let runtimes = Arc::new(runtimes);

        let mut handles = OsThreadGroup::new();

        //For test runtime we need multiple runtimes for mutltiple channels
        let rt = tokio::runtime::Runtime::new().unwrap();
        for party_id in 0..num_parties {
            let runtimes = runtimes.clone();
            let rt_handle = rt.handle().clone();
            handles.add(thread::spawn(move || {
                //inside a party
                let _guard = rt_handle.enter();
                println!("Thread created for {party_id}");

                //For each party, create num_sessions sessions
                let sessions = runtimes
                    .iter()
                    .zip(0..num_sessions)
                    .map(|(runtime, session_id)| {
                        runtime.large_session_for_party(SessionId::from(session_id), party_id)
                    })
                    .collect_vec();

                let (
                    (triple_sender_channels, triple_receiver_channels),
                    (random_sender_channels, random_receiver_channels),
                    (bit_sender_channels, bit_receiver_channels),
                ) = create_test_channels(sessions.len(), sessions.len());

                let progress_tracker =
                    ProgressTracker::new(&type_production.to_string(), num_correlations, 100);
                let mut joinset = match type_production {
                    Typeproduction::Triples => {
                        let triple_producer = SecureLargeSessionTripleProducer::new(
                            batch_size,
                            num_correlations,
                            sessions,
                            triple_sender_channels,
                            Some(progress_tracker.clone()),
                        )
                        .unwrap();
                        triple_producer.start_triple_production()
                    }
                    Typeproduction::Randoms => {
                        let random_producer = SecureLargeSessionRandomProducer::new(
                            batch_size,
                            num_correlations,
                            sessions,
                            random_sender_channels,
                            Some(progress_tracker.clone()),
                        )
                        .unwrap();
                        random_producer.start_random_production()
                    }
                    Typeproduction::Bits => {
                        let bit_producer = SecureLargeSessionBitProducer::new(
                            batch_size,
                            num_correlations,
                            sessions,
                            bit_sender_channels,
                            Some(progress_tracker.clone()),
                        )
                        .unwrap();
                        bit_producer.start_bit_gen_even_production()
                    }
                };

                rt_handle.block_on(async { while joinset.join_next().await.is_some() {} });

                (
                    triple_receiver_channels,
                    random_receiver_channels,
                    bit_receiver_channels,
                    progress_tracker,
                )
            }));
        }

        let mut channels = Vec::new();
        channels.extend(handles.join_all_with_results().unwrap());

        (identities, channels)
    }

    pub fn test_production_small<const EXTENSION_DEGREE: usize>(
        num_sessions: u128,
        num_correlations: usize,
        batch_size: usize,
        num_parties: usize,
        threshold: u8,
        type_production: Typeproduction,
    ) -> (
        Vec<Identity>,
        Vec<ReceiverChannelCollectionWithTracker<ResiduePoly<Z64, EXTENSION_DEGREE>>>,
    )
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
    {
        //Create identities and runtime
        let identities = generate_fixed_identities(num_parties);
        // Preprocessing assumes Sync network
        let runtimes = (0..num_sessions)
            .map(|_| {
                DistributedTestRuntime::<ResiduePoly<Z64, EXTENSION_DEGREE>, EXTENSION_DEGREE>::new(
                    identities.clone(),
                    threshold,
                    NetworkMode::Sync,
                    None,
                )
            })
            .collect_vec();
        let runtimes = Arc::new(runtimes);

        let mut handles = OsThreadGroup::new();

        let rt = tokio::runtime::Runtime::new().unwrap();
        for party_id in 0..num_parties {
            let runtimes = runtimes.clone();
            let rt_handle = rt.handle().clone();
            handles.add(thread::spawn(move || {
                let _guard = rt_handle.enter();
                println!("Thread created for {party_id}");

                //For each party, create num_sessions sessions
                let sessions = runtimes
                    .iter()
                    .zip(0..num_sessions)
                    .map(|(runtime, session_id)| {
                        runtime.small_session_for_party(SessionId::from(session_id), party_id, None)
                    })
                    .collect_vec();

                let (
                    (triple_sender_channels, triple_receiver_channels),
                    (random_sender_channels, random_receiver_channels),
                    (bit_sender_channels, bit_receiver_channels),
                ) = create_test_channels(sessions.len(), sessions.len());

                let progress_tracker =
                    ProgressTracker::new(&type_production.to_string(), num_correlations, 100);
                let mut joinset = match type_production {
                    Typeproduction::Triples => {
                        let triple_producer = SecureSmallSessionTripleProducer::new(
                            batch_size,
                            num_correlations,
                            sessions,
                            triple_sender_channels,
                            Some(progress_tracker.clone()),
                        )
                        .unwrap();
                        triple_producer.start_triple_production()
                    }
                    Typeproduction::Randoms => {
                        let random_producer = SecureSmallSessionRandomProducer::new(
                            batch_size,
                            num_correlations,
                            sessions,
                            random_sender_channels,
                            Some(progress_tracker.clone()),
                        )
                        .unwrap();
                        random_producer.start_random_production()
                    }
                    Typeproduction::Bits => {
                        let bit_producer = SecureSmallSessionBitProducer::new(
                            batch_size,
                            num_correlations,
                            sessions,
                            bit_sender_channels,
                            Some(progress_tracker.clone()),
                        )
                        .unwrap();
                        bit_producer.start_bit_gen_even_production()
                    }
                };

                rt_handle.block_on(async { while joinset.join_next().await.is_some() {} });

                (
                    triple_receiver_channels,
                    random_receiver_channels,
                    bit_receiver_channels,
                    progress_tracker,
                )
            }));
        }

        let mut channels = Vec::new();
        channels.extend(handles.join_all_with_results().unwrap());

        (identities, channels)
    }
}

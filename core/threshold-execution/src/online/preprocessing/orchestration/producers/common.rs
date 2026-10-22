use std::future::Future;

use tokio::{sync::mpsc::Sender, task::JoinSet};
use tracing::Instrument;

use crate::{
    online::preprocessing::orchestration::progress_tracker::ProgressTracker,
    runtime::sessions::base_session::BaseSessionHandles,
};

/// Struct that holds a session
/// and an outgoing channel
/// which will be filled with the result
/// of that session
pub struct ProducerSession<S: BaseSessionHandles, T> {
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

/// Generic functions that spawn the threads for processing
/// Bench diagnostics: once every `MPC_DKG_PHASE_LOG_EVERY` batches (process-wide, over all
/// producer sessions), log the per-phase time of the window since the previous log, from the
/// `kms_dkg_phase_*` counters. The Prometheus series carry the same data continuously; the log
/// line is for runs whose only artefact is the core log.
pub(crate) fn maybe_log_phase_snapshot() {
    use crate::constants::DKG_PHASE_LOG_EVERY;
    use observability::diag_metrics::DIAG;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{LazyLock, Mutex};
    use std::time::Instant;

    /// `(label, total microseconds, observations)` per phase, as `dkg_phase_snapshot` returns it.
    type PhaseSnapshot = Vec<(&'static str, u64, u64)>;

    static BATCHES: AtomicU64 = AtomicU64::new(0);
    static LAST: LazyLock<Mutex<Option<(Instant, PhaseSnapshot)>>> =
        LazyLock::new(|| Mutex::new(None));

    let every = *DKG_PHASE_LOG_EVERY as u64;
    if every == 0 {
        return;
    }
    let batches = BATCHES.fetch_add(1, Ordering::Relaxed) + 1;
    if !batches.is_multiple_of(every) {
        return;
    }
    let Ok(mut last) = LAST.lock() else {
        return;
    };
    // Capture under the lock so concurrent producers cannot publish older snapshots afterward.
    let now = Instant::now();
    let snapshot = DIAG.dkg_phase_snapshot();
    let mut lines = Vec::with_capacity(snapshot.len());
    if let Some((last_at, last_snapshot)) = last.as_ref() {
        let window_secs = now.duration_since(*last_at).as_secs_f64().max(1e-9);
        for ((label, micros, obs), (_, last_micros, last_obs)) in
            snapshot.iter().zip(last_snapshot.iter())
        {
            let d_micros = micros.saturating_sub(*last_micros);
            let d_obs = obs.saturating_sub(*last_obs);
            if d_obs == 0 {
                continue;
            }
            lines.push(format!(
                "{label}: {:.1} s total over {d_obs} obs ({:.0} ms avg, {:.2} session-s per wall-s)",
                d_micros as f64 / 1e6,
                d_micros as f64 / 1e3 / d_obs as f64,
                d_micros as f64 / 1e6 / window_secs,
            ));
        }
        tracing::info!(
            "DKG phase timers over the last {every} batches ({:.1} s): {}",
            window_secs,
            lines.join(" | ")
        );
    } else {
        tracing::info!("DKG phase timers: first window started after {batches} batches");
    }
    *last = Some((now, snapshot));
}

pub fn execute_preprocessing<C, S: BaseSessionHandles + 'static, TaskOutput>(
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
    use std::{collections::HashSet, fmt::Display, sync::Arc, thread};

    use futures::future::join_all;
    use itertools::Itertools;
    use tokio::sync::mpsc::{Receiver, Sender, channel};

    use crate::{
        online::{
            preprocessing::orchestration::{
                producer_traits::{BitProducerTrait, RandomProducerTrait, TripleProducerTrait},
                producers::{
                    bits_producer::{SecureLargeSessionBitProducer, SecureSmallSessionBitProducer},
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
        runtime::test_runtime::{DistributedTestRuntime, generate_fixed_roles},
    };
    use algebra::{
        base_ring::{Z64, Z128},
        galois_rings::common::ResiduePoly,
        sharing::share::Share,
        structure_traits::{Derive, ErrorCorrect, Invert, Solve},
    };
    use thread_handles::OsThreadGroup;
    use threshold_types::network::NetworkMode;
    use threshold_types::role::Role;
    use threshold_types::session_id::SessionId;

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
            write!(f, "{s}")
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
        HashSet<Role>,
        Vec<ReceiverChannelCollectionWithTracker<ResiduePoly<Z64, EXTENSION_DEGREE>>>,
    )
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
    {
        // Create roles  and runtime
        let roles = generate_fixed_roles(num_parties);
        // Preprocessing assumes Sync network
        let runtimes = (0..num_sessions)
            .map(|_| {
                DistributedTestRuntime::<
                    ResiduePoly<Z64, EXTENSION_DEGREE>,
                    Role,
                    EXTENSION_DEGREE ,
                >::new(roles.clone(), threshold, NetworkMode::Sync, None)
            })
            .collect_vec();
        let runtimes = Arc::new(runtimes);

        let mut handles = OsThreadGroup::new();

        //For test runtime we need multiple runtimes for mutltiple channels
        let rt = tokio::runtime::Runtime::new().unwrap();
        for party in roles.clone() {
            let runtimes = runtimes.clone();
            let rt_handle = rt.handle().clone();
            handles.add(thread::spawn(move || {
                //inside a party
                let _guard = rt_handle.enter();
                println!("Thread created for party {party}");

                //For each party, create num_sessions sessions
                let sessions = runtimes
                    .iter()
                    .zip_eq(0..num_sessions)
                    .map(|(runtime, session_id)| {
                        runtime.large_session_for_party(SessionId::from(session_id), party)
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

        (roles, channels)
    }

    pub fn test_production_small<const EXTENSION_DEGREE: usize>(
        num_sessions: u128,
        num_correlations: usize,
        batch_size: usize,
        num_parties: usize,
        threshold: u8,
        type_production: Typeproduction,
    ) -> (
        HashSet<Role>,
        Vec<ReceiverChannelCollectionWithTracker<ResiduePoly<Z64, EXTENSION_DEGREE>>>,
    )
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve + Derive,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
    {
        // Create identities and runtime
        let roles = generate_fixed_roles(num_parties);
        // Preprocessing assumes Sync network
        let runtimes = (0..num_sessions)
            .map(|_| {
                DistributedTestRuntime::<
                        ResiduePoly<Z64,  EXTENSION_DEGREE>,
                        Role,
                        EXTENSION_DEGREE,
                    >::new(roles.clone(), threshold, NetworkMode::Sync, None)
            })
            .collect_vec();
        let runtimes = Arc::new(runtimes);

        let mut handles = OsThreadGroup::new();

        let rt = tokio::runtime::Runtime::new().unwrap();
        for party in roles.clone() {
            let runtimes = runtimes.clone();
            let rt_handle = rt.handle().clone();
            handles.add(thread::spawn(move || {
                let _guard = rt_handle.enter();
                println!("Thread created for party {party}");

                //For each party, create num_sessions sessions
                let sessions =
                    rt_handle.block_on(join_all(runtimes.iter().zip_eq(0..num_sessions).map(
                        |(runtime, session_id)| {
                            runtime.small_session_for_party(
                                SessionId::from(session_id),
                                party,
                                None,
                            )
                        },
                    )));

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

        (roles, channels)
    }
}

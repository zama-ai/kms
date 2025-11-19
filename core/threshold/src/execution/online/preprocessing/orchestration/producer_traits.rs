use tokio::task::JoinSet;

use crate::{
    algebra::structure_traits::{Derive, ErrorCorrect, Invert, Solve},
    execution::{
        online::{
            preprocessing::orchestration::{
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
        runtime::sessions::{large_session::LargeSession, small_session::SmallSession},
        sharing::share::Share,
        small_execution::prf::PRSSConversions,
    },
};

/// Generic trait for triple producers that work with any session type
pub trait TripleProducerTrait<Z: Clone, S> {
    fn new(
        batch_size: usize,
        total_size: usize,
        sessions: Vec<S>,
        channels: Vec<tokio::sync::mpsc::Sender<Vec<Triple<Z>>>>,
        progress_tracker: Option<ProgressTracker>,
    ) -> anyhow::Result<Self>
    where
        Self: Sized;

    fn start_triple_production(self) -> JoinSet<Result<S, anyhow::Error>>;
}

/// Generic trait for random producers that work with any session type
pub trait RandomProducerTrait<Z: Clone, S> {
    fn new(
        batch_size: usize,
        total_size: usize,
        sessions: Vec<S>,
        channels: Vec<tokio::sync::mpsc::Sender<Vec<Share<Z>>>>,
        progress_tracker: Option<ProgressTracker>,
    ) -> anyhow::Result<Self>
    where
        Self: Sized;

    fn start_random_production(self) -> JoinSet<Result<S, anyhow::Error>>;
}

/// Generic trait for bit producers that work with any session type
pub trait BitProducerTrait<Z: Clone, S> {
    fn new(
        batch_size: usize,
        total_size: usize,
        sessions: Vec<S>,
        channels: Vec<tokio::sync::mpsc::Sender<Vec<Share<Z>>>>,
        progress_tracker: Option<ProgressTracker>,
    ) -> anyhow::Result<Self>
    where
        Self: Sized;

    fn start_bit_gen_even_production(self) -> JoinSet<Result<S, anyhow::Error>>
    where
        Z: Solve;
}

/// Producer factory trait that abstracts creation of different producer types
/// This trait can work with any session type (SmallSession<R> or LargeSession)
pub trait ProducerFactory<Z: Clone, S> {
    type TripleProducer: TripleProducerTrait<Z, S>;
    type RandomProducer: RandomProducerTrait<Z, S>;
    type BitProducer: BitProducerTrait<Z, S>;
}

pub struct SecureSmallProducerFactory<Z: PRSSConversions + ErrorCorrect + Invert + Derive + Solve> {
    _phantom: std::marker::PhantomData<Z>,
}

impl<Z: PRSSConversions + ErrorCorrect + Invert + Derive + Solve>
    ProducerFactory<Z, SmallSession<Z>> for SecureSmallProducerFactory<Z>
{
    type TripleProducer = SecureSmallSessionTripleProducer<Z>;
    type RandomProducer = SecureSmallSessionRandomProducer<Z>;
    type BitProducer = SecureSmallSessionBitProducer<Z>;
}

pub struct SecureLargeProducerFactory<Z: PRSSConversions + ErrorCorrect + Invert + Derive + Solve> {
    _phantom: std::marker::PhantomData<Z>,
}

impl<Z: PRSSConversions + ErrorCorrect + Invert + Derive + Solve> ProducerFactory<Z, LargeSession>
    for SecureLargeProducerFactory<Z>
{
    type TripleProducer = SecureLargeSessionTripleProducer<Z>;
    type RandomProducer = SecureLargeSessionRandomProducer<Z>;
    type BitProducer = SecureLargeSessionBitProducer<Z>;
}

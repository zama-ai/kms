use tokio::task::JoinSet;

use crate::{
    algebra::structure_traits::Solve,
    execution::{
        online::{preprocessing::orchestration::progress_tracker::ProgressTracker, triple::Triple},
        sharing::share::Share,
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

    fn create_triple_producer(
        &self,
        batch_size: usize,
        total_size: usize,
        sessions: Vec<S>,
        channels: Vec<tokio::sync::mpsc::Sender<Vec<Triple<Z>>>>,
        progress_tracker: Option<ProgressTracker>,
    ) -> anyhow::Result<Self::TripleProducer>;

    fn create_random_producer(
        &self,
        batch_size: usize,
        total_size: usize,
        sessions: Vec<S>,
        channels: Vec<tokio::sync::mpsc::Sender<Vec<Share<Z>>>>,
        progress_tracker: Option<ProgressTracker>,
    ) -> anyhow::Result<Self::RandomProducer>;

    fn create_bit_producer(
        &self,
        batch_size: usize,
        total_size: usize,
        sessions: Vec<S>,
        channels: Vec<tokio::sync::mpsc::Sender<Vec<Share<Z>>>>,
        progress_tracker: Option<ProgressTracker>,
    ) -> anyhow::Result<Self::BitProducer>;
}

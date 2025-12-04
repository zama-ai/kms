use tonic::async_trait;

use crate::{
    algebra::structure_traits::{ErrorCorrect, Ring},
    execution::{
        communication::broadcast::Broadcast,
        config::BatchParams,
        online::preprocessing::memory::InMemoryBasePreprocessing,
        runtime::sessions::{base_session::BaseSessionHandles, small_session::SmallSessionHandles},
        small_execution::offline::{Preprocessing, RealSmallPreprocessing},
    },
    ProtocolDescription,
};

/// Malicious implementation of [`Preprocessing`]
/// for any kind of session that never communicates
/// and returns an empty [`InMemoryBasePreprocessing`]
#[derive(Clone, Default)]
pub struct MaliciousOfflineDrop {}

impl ProtocolDescription for MaliciousOfflineDrop {
    fn protocol_desc(depth: usize) -> String {
        let indent = Self::INDENT_STRING.repeat(depth);
        format!("{indent}-MaliciousOfflineDrop")
    }
}

#[async_trait]
impl<Z: Clone + Default, Ses: BaseSessionHandles> Preprocessing<Z, Ses> for MaliciousOfflineDrop {
    /// Executes both GenTriples and NextRandom based on the given `batch_sizes`.
    async fn execute(
        &mut self,
        _session: &mut Ses,
        _batch_sizes: BatchParams,
    ) -> anyhow::Result<InMemoryBasePreprocessing<Z>> {
        Ok(InMemoryBasePreprocessing::default())
    }
}

/// Malicious implementation of [`Preprocessing`] for small sessions
/// that behaves honestly except uses an incorrect batch size
#[derive(Clone, Default)]
pub struct MaliciousOfflineWrongAmount<Z, Bcast: Broadcast> {
    broadcast: Bcast,
    ring_marker: std::marker::PhantomData<Z>,
}

impl<Z, Bcast: Broadcast> MaliciousOfflineWrongAmount<Z, Bcast> {
    pub fn new(broadcast: Bcast) -> Self {
        Self {
            broadcast,
            ring_marker: std::marker::PhantomData,
        }
    }
}

impl<Z, Bcast: Broadcast> ProtocolDescription for MaliciousOfflineWrongAmount<Z, Bcast> {
    fn protocol_desc(depth: usize) -> String {
        let indent = Self::INDENT_STRING.repeat(depth);
        format!(
            "{}-MaliciousOfflineWrongAmount:\n{}",
            indent,
            Bcast::protocol_desc(depth + 1)
        )
    }
}

#[async_trait]
impl<Z: ErrorCorrect, Bcast: Broadcast, Ses: SmallSessionHandles<Z>> Preprocessing<Z, Ses>
    for MaliciousOfflineWrongAmount<Z, Bcast>
{
    /// Executes both GenTriples and NextRandom based on the given `batch_sizes`.
    async fn execute(
        &mut self,
        session: &mut Ses,
        batch_sizes: BatchParams,
    ) -> anyhow::Result<InMemoryBasePreprocessing<Z>> {
        let BatchParams {
            mut triples,
            mut randoms,
        } = batch_sizes;

        triples += 42;
        randoms += 42;

        let malicious_batch_sizes = BatchParams { triples, randoms };

        RealSmallPreprocessing::<Bcast>::new(self.broadcast.clone())
            .execute(session, malicious_batch_sizes)
            .await
    }
}

pub struct FailingPreprocessing<Z>(std::marker::PhantomData<Z>);

impl<Z> Default for FailingPreprocessing<Z> {
    fn default() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<Z> ProtocolDescription for FailingPreprocessing<Z> {
    fn protocol_desc(depth: usize) -> String {
        let indent = Self::INDENT_STRING.repeat(depth);
        format!("{indent}-FailingPreprocessing")
    }
}

#[async_trait]
impl<Z, S> Preprocessing<Z, S> for FailingPreprocessing<Z>
where
    Z: Ring,
    S: BaseSessionHandles + 'static,
{
    async fn execute(
        &mut self,
        _session: &mut S,
        _batch_sizes: BatchParams,
    ) -> anyhow::Result<InMemoryBasePreprocessing<Z>> {
        Err(anyhow::anyhow!("This is a failing preprocessing"))
    }
}

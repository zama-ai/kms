use tonic::async_trait;

use crate::{
    algebra::structure_traits::ErrorCorrect,
    execution::{
        communication::broadcast::Broadcast,
        config::BatchParams,
        online::preprocessing::memory::InMemoryBasePreprocessing,
        runtime::session::{BaseSessionHandles, SmallSessionHandles},
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
        let indent = "   ".repeat(depth);
        format!("{}-MaliciousOfflineDrop", indent)
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
        let indent = "   ".repeat(depth);
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

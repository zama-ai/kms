use rand::{CryptoRng, Rng};
use tonic::async_trait;

use crate::{
    algebra::structure_traits::ErrorCorrect,
    execution::{
        communication::broadcast::Broadcast,
        config::BatchParams,
        online::preprocessing::memory::InMemoryBasePreprocessing,
        runtime::session::{BaseSessionHandles, SmallSessionHandles},
        small_execution::{
            offline::{Preprocessing, RealSmallPreprocessing},
            prss::PRSSPrimitives,
        },
    },
};

/// Malicious implementation of [`Preprocessing`]
/// for any kind of session that never communicates
/// and returns an empty [`InMemoryBasePreprocessing`]
#[derive(Clone, Default)]
pub struct MaliciousOfflineDrop {}

#[async_trait]
impl<Z: Clone + Default, Rnd: Rng + CryptoRng + Send + Sync, Ses: BaseSessionHandles<Rnd>>
    Preprocessing<Z, Rnd, Ses> for MaliciousOfflineDrop
{
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
pub struct MaliciousOfflineWrongAmount<Z, Prss: PRSSPrimitives<Z>, Bcast: Broadcast> {
    broadcast: Bcast,
    ring_marker: std::marker::PhantomData<Z>,
    prss_marker: std::marker::PhantomData<Prss>,
}

impl<Z, Prss: PRSSPrimitives<Z>, Bcast: Broadcast> MaliciousOfflineWrongAmount<Z, Prss, Bcast> {
    pub fn new(broadcast: Bcast) -> Self {
        Self {
            broadcast,
            ring_marker: std::marker::PhantomData,
            prss_marker: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<
        Z: ErrorCorrect,
        Prss: PRSSPrimitives<Z>,
        Bcast: Broadcast,
        Rnd: Rng + CryptoRng + Send + Sync,
        Ses: SmallSessionHandles<Z, Rnd, Prss>,
    > Preprocessing<Z, Rnd, Ses> for MaliciousOfflineWrongAmount<Z, Prss, Bcast>
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

        RealSmallPreprocessing::<Z, Prss, Bcast>::new(self.broadcast.clone())
            .execute(session, malicious_batch_sizes)
            .await
    }
}

use rand::{CryptoRng, Rng};
use tonic::async_trait;

use crate::{
    algebra::structure_traits::ErrorCorrect,
    execution::{
        runtime::session::BaseSessionHandles,
        small_execution::{
            agree_random::{AgreeRandom, AgreeRandomFromShare},
            prf::PrfKey,
        },
    },
};

// Malicious implementation of both [`AgreeRandom`] and [`AgreeRandomFromShare`]
// that simply does nothing
#[derive(Clone, Default)]
pub struct MaliciousAgreeRandomDrop {}

#[async_trait]
impl AgreeRandom for MaliciousAgreeRandomDrop {
    async fn execute<R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        _session: &mut S,
    ) -> anyhow::Result<Vec<PrfKey>> {
        Ok(Vec::new())
    }
}

#[async_trait]
impl AgreeRandomFromShare for MaliciousAgreeRandomDrop {
    async fn execute<Z: ErrorCorrect, R: Rng + CryptoRng, S: BaseSessionHandles<R>>(
        &self,
        _session: &mut S,
        _shares: Vec<Z>,
        _all_party_sets: &[Vec<usize>],
    ) -> anyhow::Result<Vec<PrfKey>> {
        Ok(Vec::new())
    }
}

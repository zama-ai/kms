use tonic::async_trait;

use crate::{
    algebra::structure_traits::ErrorCorrect,
    execution::{
        runtime::{party::Role, sessions::base_session::BaseSessionHandles},
        small_execution::{
            agree_random::{AgreeRandom, AgreeRandomFromShare},
            prf::PrfKey,
        },
    },
    ProtocolDescription,
};

// Malicious implementation of both [`AgreeRandom`] and [`AgreeRandomFromShare`]
// that simply does nothing
#[derive(Clone, Default)]
pub struct MaliciousAgreeRandomDrop {}

impl ProtocolDescription for MaliciousAgreeRandomDrop {
    fn protocol_desc(depth: usize) -> String {
        let indent = Self::INDENT_STRING.repeat(depth);
        format!("{indent}-MaliciousAgreeRandomDrop")
    }
}

#[async_trait]
impl AgreeRandom for MaliciousAgreeRandomDrop {
    async fn execute<S: BaseSessionHandles>(
        &self,
        _session: &mut S,
    ) -> anyhow::Result<Vec<PrfKey>> {
        Ok(Vec::new())
    }
}

#[async_trait]
impl AgreeRandomFromShare for MaliciousAgreeRandomDrop {
    async fn execute<Z: ErrorCorrect, S: BaseSessionHandles>(
        &self,
        _session: &mut S,
        _shares: Vec<Z>,
        _all_party_sets: &[Vec<Role>],
    ) -> anyhow::Result<Vec<PrfKey>> {
        Ok(Vec::new())
    }
}

use crate::{
    algebra::{
        base_ring::Z128,
        galois_rings::common::ResiduePoly,
        structure_traits::{ErrorCorrect, Invert, Solve},
    },
    error::error_handler::anyhow_error_and_log,
};

use super::{
    fetch_correlated_randomness, store_correlated_randomness, CorrelatedRandomnessType,
    RedisPreprocessing,
};
use crate::execution::online::preprocessing::NoiseFloodPreprocessing;
use async_trait::async_trait;

#[async_trait]
impl<const EXTENSION_DEGREE: usize> NoiseFloodPreprocessing<EXTENSION_DEGREE>
    for RedisPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: Invert + Solve + ErrorCorrect,
{
    fn append_masks(&mut self, masks: Vec<ResiduePoly<Z128, EXTENSION_DEGREE>>) {
        store_correlated_randomness(
            self.get_client(),
            &masks,
            CorrelatedRandomnessType::DDecMask,
            self.key_prefix(),
        )
        .unwrap()
    }
    fn next_mask(&mut self) -> anyhow::Result<ResiduePoly<Z128, EXTENSION_DEGREE>> {
        fetch_correlated_randomness(
            self.get_client(),
            1,
            CorrelatedRandomnessType::DDecMask,
            self.key_prefix(),
        )
        .map_err(|e| anyhow_error_and_log(e.to_string()))
        .and_then(|mut opt| {
            opt.pop()
                .ok_or_else(|| anyhow_error_and_log("No more masks available".to_string()))
        })
    }

    fn next_mask_vec(
        &mut self,
        amount: usize,
    ) -> anyhow::Result<Vec<ResiduePoly<Z128, EXTENSION_DEGREE>>> {
        fetch_correlated_randomness(
            self.get_client(),
            amount,
            CorrelatedRandomnessType::DDecMask,
            self.key_prefix(),
        )
        .map_err(|e| anyhow_error_and_log(e.to_string()))
    }
}

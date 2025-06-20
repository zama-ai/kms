use crate::{
    algebra::{
        base_ring::Z128,
        galois_rings::common::ResiduePoly,
        structure_traits::{ErrorCorrect, Invert, Solve},
    },
    error::error_handler::anyhow_error_and_log,
};

use crate::execution::online::preprocessing::NoiseFloodPreprocessing;
use async_trait::async_trait;

#[derive(Default)]
pub struct InMemoryNoiseFloodPreprocessing<const EXTENSION_DEGREE: usize> {
    available_masks: Vec<ResiduePoly<Z128, EXTENSION_DEGREE>>,
}

#[async_trait]
impl<const EXTENSION_DEGREE: usize> NoiseFloodPreprocessing<EXTENSION_DEGREE>
    for InMemoryNoiseFloodPreprocessing<EXTENSION_DEGREE>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: Invert + Solve + ErrorCorrect,
{
    fn append_masks(&mut self, masks: Vec<ResiduePoly<Z128, EXTENSION_DEGREE>>) {
        masks
            .into_iter()
            .for_each(|elem| self.available_masks.push(elem));
    }

    fn next_mask(&mut self) -> anyhow::Result<ResiduePoly<Z128, EXTENSION_DEGREE>> {
        self.available_masks
            .pop()
            .ok_or_else(|| anyhow_error_and_log("available masks is empty".to_string()))
    }
    fn next_mask_vec(
        &mut self,
        amount: usize,
    ) -> anyhow::Result<Vec<ResiduePoly<Z128, EXTENSION_DEGREE>>> {
        if self.available_masks.len() >= amount {
            let mut res = Vec::with_capacity(amount);
            for _ in 0..amount {
                res.push(self.next_mask()?);
            }
            Ok(res)
        } else {
            Err(anyhow_error_and_log(format!(
                "Not enough masks to pop {amount}"
            )))
        }
    }
}

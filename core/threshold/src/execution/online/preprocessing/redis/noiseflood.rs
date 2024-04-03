use itertools::Itertools;

use crate::{
    algebra::residue_poly::ResiduePoly128,
    error::error_handler::anyhow_error_and_log,
    execution::{
        constants::{BD1, LOG_BD, STATSEC},
        online::{
            gen_bits::{BitGenEven, RealBitGenEven},
            preprocessing::BasePreprocessing,
            secret_distributions::{RealSecretDistributions, SecretDistributions},
        },
        runtime::session::{ParameterHandles, SmallSession},
        tfhe_internals::parameters::TUniformBound,
    },
};

use super::{
    fetch_correlated_randomness, store_correlated_randomness, BitPreprocessing,
    CorrelatedRandomnessType, RedisPreprocessing,
};
use crate::execution::online::preprocessing::BaseSession;
use crate::execution::online::preprocessing::NoiseFloodPreprocessing;
use async_trait::async_trait;

#[async_trait]
impl NoiseFloodPreprocessing for RedisPreprocessing<ResiduePoly128> {
    fn append_masks(&mut self, masks: Vec<ResiduePoly128>) {
        store_correlated_randomness(
            self.get_client(),
            &masks,
            CorrelatedRandomnessType::DDecMask,
            self.key_prefix(),
        )
        .unwrap()
    }
    fn next_mask(&mut self) -> anyhow::Result<ResiduePoly128> {
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

    fn next_mask_vec(&mut self, amount: usize) -> anyhow::Result<Vec<ResiduePoly128>> {
        fetch_correlated_randomness(
            self.get_client(),
            amount,
            CorrelatedRandomnessType::DDecMask,
            self.key_prefix(),
        )
        .map_err(|e| anyhow_error_and_log(e.to_string()))
    }

    /// Assumes a [`SmallSession`] with **initialized**
    /// [`crate::execution::small_execution::prss::PRSSSetup`]
    fn fill_from_small_session(
        &mut self,
        session: &mut SmallSession<ResiduePoly128>,
        amount: usize,
    ) -> anyhow::Result<()> {
        let own_role = session.my_role()?;

        let masks = (0..amount)
            .map(|_| session.prss_state.mask_next(own_role.one_based(), BD1))
            .try_collect()?;

        self.append_masks(masks);

        Ok(())
    }

    ///Creates enough masks to decrypt **num_ctxt** ciphertexts from [BasePreprocessing],
    ///assuming **preprocessing** is filled with enough randomness and triples.
    /// Requires interaction to create the bits out of the [BasePreprocessing] material
    async fn fill_from_base_preproc(
        &mut self,
        preprocessing: &mut dyn BasePreprocessing<ResiduePoly128>,
        session: &mut BaseSession,
        num_ctxts: usize,
    ) -> anyhow::Result<()> {
        let bound_d = (STATSEC + LOG_BD) as usize;
        let num_bits = 2 * num_ctxts * (bound_d + 2);
        let available_bits =
            RealBitGenEven::gen_bits_even(num_bits, preprocessing, session).await?;
        let mut bit_preproc = RedisPreprocessing::new(self.key_prefix(), self.get_client());
        bit_preproc.append_bits(available_bits);

        self.fill_from_bits_preproc(&mut bit_preproc, num_ctxts)
    }

    /// Fill the masks directly from available bits provided by [`BitPreprocessing`],
    /// using [`crate::execution::online::secret_distributions::SecretDistributions`]
    fn fill_from_bits_preproc(
        &mut self,
        bit_preproc: &mut dyn BitPreprocessing<ResiduePoly128>,
        num_ctxts: usize,
    ) -> anyhow::Result<()> {
        let bound_d = (STATSEC + LOG_BD) as usize;
        let mut u_randoms =
            RealSecretDistributions::t_uniform(2 * num_ctxts, TUniformBound(bound_d), bit_preproc)?
                .into_iter()
                .map(|elem| elem.value())
                .collect_vec();

        let masks = (0..num_ctxts)
            .map(|_| {
                let (a, b) = (u_randoms.pop(), u_randoms.pop());
                match (a, b) {
                    (Some(a), Some(b)) => Ok(a + b),
                    _ => Err(anyhow_error_and_log(
                        "Not enough t_uniform generated".to_string(),
                    )),
                }
            })
            .try_collect()?;

        self.append_masks(masks);
        Ok(())
    }
}

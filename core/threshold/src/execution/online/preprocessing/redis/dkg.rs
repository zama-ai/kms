use tonic::async_trait;

use crate::{
    algebra::structure_traits::{ErrorCorrect, Invert, Solve},
    error::error_handler::anyhow_error_and_log,
    execution::{
        keyset_config::KeySetConfig,
        online::{
            gen_bits::{BitGenEven, SecureBitGenEven},
            preprocessing::{BasePreprocessing, BitPreprocessing, DKGPreprocessing, NoiseBounds},
        },
        runtime::sessions::base_session::BaseSession,
        sharing::share::Share,
        small_execution::prf::PRSSConversions,
        tfhe_internals::parameters::DKGParams,
    },
};

use super::{
    correlated_randomness_len, fetch_correlated_randomness, store_correlated_randomness,
    RedisPreprocessing,
};

#[async_trait]
impl<Z> DKGPreprocessing<Z> for RedisPreprocessing<Z>
where
    Z: Solve + Invert + ErrorCorrect + PRSSConversions,
{
    fn append_noises(&mut self, noises: Vec<Share<Z>>, bound: NoiseBounds) {
        // TODO unwrap is ok?
        store_correlated_randomness(
            self.get_client(),
            &noises,
            bound.get_type(),
            self.key_prefix(),
        )
        .unwrap();
    }

    fn next_noise_vec(
        &mut self,
        amount: usize,
        bound: NoiseBounds,
    ) -> anyhow::Result<Vec<Share<Z>>> {
        fetch_correlated_randomness(
            self.get_client(),
            amount,
            bound.get_type(),
            self.key_prefix(),
        )
        .map_err(|e| anyhow_error_and_log(e.to_string()))
    }

    async fn fill_from_base_preproc(
        &mut self,
        params: DKGParams,
        keyset_config: KeySetConfig,
        session: &mut BaseSession,
        preprocessing: &mut dyn BasePreprocessing<Z>,
    ) -> anyhow::Result<()> {
        let num_bits_required = params
            .get_params_basics_handle()
            .total_bits_required(keyset_config);

        self.append_bits(
            SecureBitGenEven::gen_bits_even(num_bits_required, preprocessing, session).await?,
        );

        let mut bit_preproc = self.clone();

        self.fill_from_triples_and_bit_preproc(
            params,
            keyset_config,
            session,
            preprocessing,
            &mut bit_preproc,
        )
    }

    //Code is completely generic for now,
    //but that may be where we want to allow for a more streaming process ?
    //
    //More streaming oriented process would require dealing with empty/incomplete answers to the next() requests.
    fn fill_from_triples_and_bit_preproc(
        &mut self,
        params: DKGParams,
        keyset_config: KeySetConfig,
        _session: &mut BaseSession,
        preprocessing_base: &mut dyn BasePreprocessing<Z>,
        preprocessing_bits: &mut dyn BitPreprocessing<Z>,
    ) -> anyhow::Result<()> {
        crate::execution::online::preprocessing::dkg_fill_from_triples_and_bit_preproc(
            self,
            params,
            keyset_config,
            preprocessing_base,
            preprocessing_bits,
        )
    }

    fn noise_len(&self, bound: NoiseBounds) -> usize {
        correlated_randomness_len(self.get_client(), bound.get_type(), self.key_prefix())
    }
}

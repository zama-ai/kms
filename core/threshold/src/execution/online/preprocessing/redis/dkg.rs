use tonic::async_trait;

use crate::{
    algebra::structure_traits::{ErrorCorrect, HenselLiftInverse, Ring, RingEmbed, Solve},
    error::error_handler::anyhow_error_and_log,
    execution::{
        online::{
            gen_bits::{BitGenEven, RealBitGenEven},
            preprocessing::{
                BasePreprocessing, BitPreprocessing, DKGPreprocessing, NoiseBounds,
                RandomPreprocessing, TriplePreprocessing,
            },
            secret_distributions::{RealSecretDistributions, SecretDistributions},
        },
        runtime::session::{BaseSession, ParameterHandles, SmallSession, SmallSessionHandles},
        sharing::share::Share,
        small_execution::{prf::PRSSConversions, prss::PRSSState},
        tfhe_internals::parameters::DKGParams,
    },
};

use super::{fetch_correlated_randomness, store_correlated_randomness, RedisPreprocessing};

#[async_trait]
impl<Z> DKGPreprocessing<Z> for RedisPreprocessing<Z>
where
    Z: Ring + RingEmbed + Solve + HenselLiftInverse + ErrorCorrect + PRSSConversions,
{
    fn append_noises(&mut self, noises: Vec<Share<Z>>, bound: NoiseBounds) {
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

    async fn fill_from_base_preproc_small_session_appendix_version(
        &mut self,
        params: DKGParams,
        session: &mut SmallSession<Z>,
        preprocessing: &mut dyn BasePreprocessing<Z>,
    ) -> anyhow::Result<()> {
        let num_bits_needed = params.get_params_basics_handle().lwe_dimension().0
            + params.get_params_basics_handle().glwe_sk_num_bits()
            + match params {
                DKGParams::WithoutSnS(_) => 0,
                DKGParams::WithSnS(sns_params) => sns_params.glwe_sk_num_bits_sns(),
            };

        self.append_bits(
            RealBitGenEven::gen_bits_even(num_bits_needed, preprocessing, session).await?,
        );

        let mut bit_preproc = self.clone();
        self.fill_from_triples_and_bit_preproc_small_session_appendix_version(
            params,
            session,
            preprocessing,
            &mut bit_preproc,
        )
    }

    //Code is completely generic for now,
    //but that may be where we want to address sync issues if we have multiple producers, etc... ?
    fn fill_from_triples_and_bit_preproc_small_session_appendix_version(
        &mut self,
        params: DKGParams,
        session: &mut SmallSession<Z>,
        preprocessing_base: &mut dyn BasePreprocessing<Z>,
        preprocessing_bits: &mut dyn BitPreprocessing<Z>,
    ) -> anyhow::Result<()> {
        let my_role = session.my_role()?;
        let my_role_one_based = my_role.one_based();
        let prss_state = session.prss_as_mut();

        let mut fill_noise = |prss_state: &mut PRSSState<Z>, num: usize, bound: NoiseBounds| {
            self.append_noises(
                (0..num)
                    .map(|_| {
                        Ok::<_, anyhow::Error>(Share::new(
                            my_role,
                            prss_state.mask_next(my_role_one_based, 1 << bound.get_bound().0)?,
                        ))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                bound,
            );
            Ok::<_, anyhow::Error>(())
        };

        let params_basics_handles = params.get_params_basics_handle();
        //Generate noise needed for the pk and the key switch key
        fill_noise(
            prss_state,
            params_basics_handles.num_needed_noise_pk()
                + params_basics_handles.num_needed_noise_ksk(),
            NoiseBounds::LweNoise(params_basics_handles.lwe_tuniform_bound()),
        )?;

        //Generate noise needed for the bootstrap key
        fill_noise(
            prss_state,
            params_basics_handles.num_needed_noise_bk(),
            NoiseBounds::GlweNoise(params_basics_handles.glwe_tuniform_bound()),
        )?;

        //Generate noise needed for Switch and Squash bootstrap key if needed
        match params {
            DKGParams::WithSnS(sns_params) => {
                fill_noise(
                    prss_state,
                    sns_params.num_needed_noise_bk_sns(),
                    NoiseBounds::GlweNoiseSnS(sns_params.glwe_tuniform_bound_sns()),
                )?;
            }
            DKGParams::WithoutSnS(_) => (),
        }

        //NOTE: BELOW WE MAY JUST BE POPING AND PUSHING THE SAME DATA
        //IF THE PREPROCESSING WE DEPEND ON IS THE SAME REDIS INSTANCE

        //Fill in the required number of _raw_ bits
        let num_bits_needed = params_basics_handles.lwe_dimension().0
            + params_basics_handles.glwe_sk_num_bits()
            + match params {
                DKGParams::WithSnS(sns_params) => sns_params.glwe_sk_num_bits_sns(),
                DKGParams::WithoutSnS(_) => 0,
            };

        self.append_bits(preprocessing_bits.next_bit_vec(num_bits_needed)?);

        //Fill in the required number of triples
        let num_triples_needed = params_basics_handles.total_triples_required()
            - params_basics_handles.total_bits_required();
        self.append_triples(preprocessing_base.next_triple_vec(num_triples_needed)?);

        //Fill in the required number of randomness
        let num_randomness_needed = params_basics_handles.total_randomness_required()
            - params_basics_handles.total_bits_required();
        self.append_randoms(preprocessing_base.next_random_vec(num_randomness_needed)?);

        Ok(())
    }

    async fn fill_from_base_preproc(
        &mut self,
        params: DKGParams,
        session: &mut BaseSession,
        preprocessing: &mut dyn BasePreprocessing<Z>,
    ) -> anyhow::Result<()> {
        let num_bits_required = params.get_params_basics_handle().total_bits_required();

        self.append_bits(
            RealBitGenEven::gen_bits_even(num_bits_required, preprocessing, session).await?,
        );

        let mut bit_preproc = self.clone();

        self.fill_from_triples_and_bit_preproc(params, session, preprocessing, &mut bit_preproc)
    }

    //Code is completely generic for now,
    //but that may be where we want to allow for a more streaming process ?
    //
    //More streaming oriented process would require dealing with empty/incomplete answers to the next() requests.
    fn fill_from_triples_and_bit_preproc(
        &mut self,
        params: DKGParams,
        _session: &mut BaseSession,
        preprocessing_base: &mut dyn BasePreprocessing<Z>,
        preprocessing_bits: &mut dyn BitPreprocessing<Z>,
    ) -> anyhow::Result<()> {
        let params_basics_handles = params.get_params_basics_handle();
        //Generate noise needed for pk and the key switch key
        self.append_noises(
            RealSecretDistributions::t_uniform(
                params_basics_handles.num_needed_noise_pk()
                    + params_basics_handles.num_needed_noise_ksk(),
                params_basics_handles.lwe_tuniform_bound(),
                preprocessing_bits,
            )?,
            NoiseBounds::LweNoise(params_basics_handles.lwe_tuniform_bound()),
        );

        //Generate noise needed for the bootstrap key
        self.append_noises(
            RealSecretDistributions::t_uniform(
                params_basics_handles.num_needed_noise_bk(),
                params_basics_handles.glwe_tuniform_bound(),
                preprocessing_bits,
            )?,
            NoiseBounds::GlweNoise(params_basics_handles.glwe_tuniform_bound()),
        );

        //Generate noise needed for Switch and Squash bootstrap key if needed
        match params {
            DKGParams::WithSnS(sns_params) => {
                self.append_noises(
                    RealSecretDistributions::t_uniform(
                        sns_params.num_needed_noise_bk_sns(),
                        sns_params.glwe_tuniform_bound_sns(),
                        preprocessing_bits,
                    )?,
                    NoiseBounds::GlweNoiseSnS(sns_params.glwe_tuniform_bound_sns()),
                );
            }
            DKGParams::WithoutSnS(_) => (),
        }

        //Fill in the required number of _raw_ bits
        let num_bits_required = params_basics_handles.lwe_dimension().0
            + params_basics_handles.glwe_sk_num_bits()
            + match params {
                DKGParams::WithSnS(sns_params) => sns_params.glwe_sk_num_bits_sns(),
                DKGParams::WithoutSnS(_) => 0,
            };

        self.append_bits(preprocessing_bits.next_bit_vec(num_bits_required)?);

        //Fill in the required number of triples
        let num_triples_required = params_basics_handles.total_triples_required()
            - params_basics_handles.total_bits_required();

        self.append_triples(preprocessing_base.next_triple_vec(num_triples_required)?);

        //Fill in the required number of randomness
        let num_randomness_required = params_basics_handles.total_randomness_required()
            - params_basics_handles.total_bits_required();
        self.append_randoms(preprocessing_base.next_random_vec(num_randomness_required)?);

        Ok(())
    }
}

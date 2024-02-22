use itertools::Itertools;
use tonic::async_trait;

use crate::{
    algebra::structure_traits::Ring,
    error::error_handler::anyhow_error_and_log,
    execution::{
        online::{
            gen_bits::{BitGenEven, RealBitGenEven, Solve},
            preprocessing::{
                BasePreprocessing, BitPreprocessing, DKGPreprocessing, NoiseBounds,
                RandomPreprocessing, TriplePreprocessing,
            },
            secret_distributions::{RealSecretDistributions, SecretDistributions},
            triple::Triple,
        },
        runtime::session::{BaseSession, ParameterHandles, SmallSession},
        sharing::{
            shamir::{ErrorCorrect, HenselLiftInverse, RingEmbed},
            share::Share,
        },
        small_execution::{prf::PRSSConversions, prss::PRSSState},
        tfhe_internals::parameters::DKGParams,
    },
};

use super::{InMemoryBasePreprocessing, InMemoryBitPreprocessing};

pub struct InMemoryDKGPreprocessing<Z: Ring> {
    params: DKGParams,
    in_memory_bits: InMemoryBitPreprocessing<Z>,
    in_memory_base: InMemoryBasePreprocessing<Z>,
    available_noise_lwe: Vec<Share<Z>>,
    available_noise_glwe: Vec<Share<Z>>,
    available_noise_oglwe: Vec<Share<Z>>,
}

impl<Z: Ring> Drop for InMemoryDKGPreprocessing<Z> {
    fn drop(&mut self) {
        debug_assert_eq!(self.available_noise_lwe.len(), 0);
        debug_assert_eq!(self.available_noise_glwe.len(), 0);
        debug_assert_eq!(self.available_noise_oglwe.len(), 0);
    }
}

impl<Z: Ring> InMemoryDKGPreprocessing<Z> {
    pub fn new(params: DKGParams) -> Self {
        Self {
            params,
            in_memory_bits: Default::default(),
            in_memory_base: Default::default(),
            available_noise_lwe: Default::default(),
            available_noise_glwe: Default::default(),
            available_noise_oglwe: Default::default(),
        }
    }
}

impl<Z: Ring> TriplePreprocessing<Z> for InMemoryDKGPreprocessing<Z> {
    fn next_triple_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Triple<Z>>> {
        self.in_memory_base.next_triple_vec(amount)
    }

    fn append_triples(&mut self, triples: Vec<Triple<Z>>) {
        self.in_memory_base.append_triples(triples)
    }

    fn triples_len(&self) -> usize {
        self.in_memory_base.triples_len()
    }
}

impl<Z: Ring> RandomPreprocessing<Z> for InMemoryDKGPreprocessing<Z> {
    fn next_random_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<Z>>> {
        self.in_memory_base.next_random_vec(amount)
    }

    fn append_randoms(&mut self, randoms: Vec<Share<Z>>) {
        self.in_memory_base.append_randoms(randoms)
    }

    fn randoms_len(&self) -> usize {
        self.in_memory_base.randoms_len()
    }
}

impl<Z: Ring> BasePreprocessing<Z> for InMemoryDKGPreprocessing<Z> {}

impl<Z: Ring> BitPreprocessing<Z> for InMemoryDKGPreprocessing<Z> {
    fn append_bits(&mut self, bits: Vec<Share<Z>>) {
        self.in_memory_bits.append_bits(bits);
    }

    fn next_bit(&mut self) -> anyhow::Result<Share<Z>> {
        self.in_memory_bits.next_bit()
    }

    fn next_bit_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<Z>>> {
        self.in_memory_bits.next_bit_vec(amount)
    }
}

#[async_trait]
impl<Z> DKGPreprocessing<Z> for InMemoryDKGPreprocessing<Z>
where
    Z: Ring + RingEmbed + HenselLiftInverse + PRSSConversions + ErrorCorrect + Solve,
{
    ///Store a vec of noise, each following the same TUniform distribution specified by bound.
    fn append_noises(&mut self, noises: Vec<Share<Z>>, bound: NoiseBounds) {
        //Note: do we want to assert that the distribution is the epxect one from self.parameters ?
        match bound {
            NoiseBounds::LweNoise(_) => self.available_noise_lwe.extend(noises),
            NoiseBounds::GlweNoise(_) => self.available_noise_glwe.extend(noises),
            NoiseBounds::GlweNoiseSnS(_) => self.available_noise_oglwe.extend(noises),
        }
    }

    //Note that storing in noise format rather than raw bits saves space (and bandwidth for read/write)
    //We may want to store the noise depending on their distribution
    //(2 or 3 diff distribution required for DKG depending on whether we need Switch and Squash keys)
    fn next_noise_vec(
        &mut self,
        amount: usize,
        bound: NoiseBounds,
    ) -> anyhow::Result<Vec<Share<Z>>> {
        let noise_distrib = match bound {
            NoiseBounds::LweNoise(_) => &mut self.available_noise_lwe,
            NoiseBounds::GlweNoise(_) => &mut self.available_noise_glwe,
            NoiseBounds::GlweNoiseSnS(_) => &mut self.available_noise_oglwe,
        };

        if noise_distrib.len() >= amount {
            Ok(noise_distrib.drain(0..amount).collect())
        } else {
            Err(anyhow_error_and_log(format!(
                "Not enough noise of distribution {:?} to pop {amount}, only have {}",
                bound,
                noise_distrib.len()
            )))
        }
    }

    /// __Fill the noise directly from the [`crate::execution::small_execution::prss::PRSSState`] available from [`SmallSession`]
    /// as described in the appendix of the NIST document.__
    /// The bits and triples are generated/pulled from the [`BasePreprocessing`],
    /// we thus need interaction to generate the bits.
    async fn fill_from_base_preproc_small_session_appendix_version(
        &mut self,
        session: &mut SmallSession<Z>,
        preprocessing: &mut dyn BasePreprocessing<Z>,
    ) -> anyhow::Result<()> {
        //Need bits for lwe sk, glwe sk and maybe glwe sk sns
        let num_bits_needed = self.params.get_params_basics_handle().lwe_dimension().0
            + self.params.get_params_basics_handle().glwe_sk_num_bits()
            + match self.params {
                DKGParams::WithoutSnS(_) => 0,
                DKGParams::WithSnS(sns_params) => sns_params.glwe_sk_num_bits_sns(),
            };

        let mut bit_preproc = InMemoryBitPreprocessing::default();

        bit_preproc.append_bits(
            RealBitGenEven::gen_bits_even(num_bits_needed, preprocessing, session).await?,
        );

        self.fill_from_triples_and_bit_preproc_small_session_appendix_version(
            session,
            preprocessing,
            &mut bit_preproc,
        )
    }

    /// __Fill the noise directly from the [`crate::execution::small_execution::prss::PRSSState`] available from [`SmallSession`]
    /// as described in the appendix of the NIST document.__
    /// Pull the triples from [`TriplePreprocessing`] and the bits from [`BitPreprocessing`]
    fn fill_from_triples_and_bit_preproc_small_session_appendix_version(
        &mut self,
        session: &mut SmallSession<Z>,
        preprocessing_base: &mut dyn BasePreprocessing<Z>,
        preprocessing_bits: &mut dyn BitPreprocessing<Z>,
    ) -> anyhow::Result<()> {
        let my_role = session.my_role()?;
        let my_role_one_based = my_role.one_based();
        let prss_state = session
            .prss_state
            .as_mut()
            .ok_or_else(|| anyhow_error_and_log("PRSS_State not initialized".to_string()))?;

        let fill_noise = |vec_to_extend: &mut Vec<Share<Z>>,
                          prss_state: &mut PRSSState<Z>,
                          num: usize,
                          bound: usize| {
            vec_to_extend.extend(
                (0..num)
                    .map(|_| {
                        Ok::<_, anyhow::Error>(Share::new(
                            my_role,
                            prss_state.mask_next(my_role_one_based, 1 << bound)?,
                        ))
                    })
                    .try_collect::<_, Vec<_>, _>()?,
            );
            Ok::<_, anyhow::Error>(())
        };

        let params_basics_handles = self.params.get_params_basics_handle();
        //Generate noise needed for the pk
        fill_noise(
            &mut self.available_noise_lwe,
            prss_state,
            params_basics_handles.num_needed_noise_pk(),
            params_basics_handles.lwe_tuniform_bound().0,
        )?;

        //Generate noise needed for the key switch key
        fill_noise(
            &mut self.available_noise_lwe,
            prss_state,
            params_basics_handles.num_needed_noise_ksk(),
            params_basics_handles.lwe_tuniform_bound().0,
        )?;

        //Generate noise needed for the bootstrap key
        fill_noise(
            &mut self.available_noise_glwe,
            prss_state,
            params_basics_handles.num_needed_noise_bk(),
            params_basics_handles.glwe_tuniform_bound().0,
        )?;

        //Generate noise needed for Switch and Squash bootstrap key if needed
        match self.params {
            DKGParams::WithSnS(sns_params) => {
                fill_noise(
                    &mut self.available_noise_oglwe,
                    prss_state,
                    sns_params.num_needed_noise_bk_sns(),
                    sns_params.glwe_tuniform_bound_sns().0,
                )?;
            }
            DKGParams::WithoutSnS(_) => (),
        }

        //Fill in the required number of _raw_ bits
        let num_bits_needed = params_basics_handles.lwe_dimension().0
            + params_basics_handles.glwe_sk_num_bits()
            + match self.params {
                DKGParams::WithSnS(sns_params) => sns_params.glwe_sk_num_bits_sns(),
                DKGParams::WithoutSnS(_) => 0,
            };

        self.in_memory_bits
            .append_bits(preprocessing_bits.next_bit_vec(num_bits_needed)?);

        //Fill in the required number of triples
        let num_triples_needed = params_basics_handles.total_triples_required()
            - params_basics_handles.total_bits_required();
        self.in_memory_base
            .append_triples(preprocessing_base.next_triple_vec(num_triples_needed)?);

        //Fill in the required number of randomness
        let num_randomness_needed = params_basics_handles.total_randomness_required()
            - params_basics_handles.total_bits_required();
        self.in_memory_base
            .append_randoms(preprocessing_base.next_random_vec(num_randomness_needed)?);

        Ok(())
    }

    /// Fill the noise from [`crate::execution::online::secret_distributions::SecretDistributions`]
    /// where the bits required to do so are generated through the [`BasePreprocessing`]
    /// Also generate the additional bits (and triples) needed from [`BasePreprocessing`]
    /// we thus need interation to generate the bits.
    async fn fill_from_base_preproc(
        &mut self,
        session: &mut BaseSession,
        preprocessing: &mut dyn BasePreprocessing<Z>,
    ) -> anyhow::Result<()> {
        let num_bits_required = self.params.get_params_basics_handle().total_bits_required();

        let mut bit_preproc = InMemoryBitPreprocessing::default();

        bit_preproc.append_bits(
            RealBitGenEven::gen_bits_even(num_bits_required, preprocessing, session).await?,
        );

        self.fill_from_triples_and_bit_preproc(session, preprocessing, &mut bit_preproc)
    }

    /// Fill the noise from [`crate::execution::online::secret_distributions::SecretDistributions`]
    /// where the bits required to do so are pulled from the [`BitPreprocessing`].
    /// The additional bits required are also pulled from [`BitPreprocessing`]
    /// and triples from [`TriplePreprocessing`].
    fn fill_from_triples_and_bit_preproc(
        &mut self,
        _session: &mut BaseSession,
        preprocessing_base: &mut dyn BasePreprocessing<Z>,
        preprocessing_bits: &mut dyn BitPreprocessing<Z>,
    ) -> anyhow::Result<()> {
        let params_basics_handles = self.params.get_params_basics_handle();
        //Generate noise needed for pk
        self.available_noise_lwe
            .extend(RealSecretDistributions::t_uniform(
                params_basics_handles.num_needed_noise_pk(),
                params_basics_handles.lwe_tuniform_bound(),
                preprocessing_bits,
            )?);

        //Generate noise needed for the key switch key
        self.available_noise_lwe
            .extend(RealSecretDistributions::t_uniform(
                params_basics_handles.num_needed_noise_ksk(),
                params_basics_handles.lwe_tuniform_bound(),
                preprocessing_bits,
            )?);

        //Generate noise needed for the bootstrap key
        self.available_noise_glwe
            .extend(RealSecretDistributions::t_uniform(
                params_basics_handles.num_needed_noise_bk(),
                params_basics_handles.glwe_tuniform_bound(),
                preprocessing_bits,
            )?);

        //Generate noise needed for Switch and Squash bootstrap key if needed
        match self.params {
            DKGParams::WithSnS(sns_params) => {
                self.available_noise_oglwe
                    .extend(RealSecretDistributions::t_uniform(
                        sns_params.num_needed_noise_bk_sns(),
                        sns_params.glwe_tuniform_bound_sns(),
                        preprocessing_bits,
                    )?);
            }
            DKGParams::WithoutSnS(_) => (),
        }

        //Fill in the required number of _raw_ bits
        let num_bits_required = params_basics_handles.lwe_dimension().0
            + params_basics_handles.glwe_sk_num_bits()
            + match self.params {
                DKGParams::WithSnS(sns_params) => sns_params.glwe_sk_num_bits_sns(),
                DKGParams::WithoutSnS(_) => 0,
            };

        self.in_memory_bits
            .append_bits(preprocessing_bits.next_bit_vec(num_bits_required)?);

        //Fill in the required number of triples
        let num_triples_required = params_basics_handles.total_triples_required()
            - params_basics_handles.total_bits_required();

        self.in_memory_base
            .append_triples(preprocessing_base.next_triple_vec(num_triples_required)?);

        //Fill in the required number of randomness
        let num_randomness_required = params_basics_handles.total_randomness_required()
            - params_basics_handles.total_bits_required();
        self.in_memory_base
            .append_randoms(preprocessing_base.next_random_vec(num_randomness_required)?);

        Ok(())
    }
}

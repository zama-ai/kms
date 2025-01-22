use tfhe::shortint::EncryptionKeyChoice;
use tonic::async_trait;

use crate::{
    algebra::structure_traits::{ErrorCorrect, Invert, Ring, Solve},
    error::error_handler::anyhow_error_and_log,
    execution::{
        online::{
            gen_bits::{BitGenEven, RealBitGenEven},
            preprocessing::{
                BasePreprocessing, BitPreprocessing, DKGPreprocessing, NoiseBounds,
                RandomPreprocessing, TriplePreprocessing,
            },
            secret_distributions::{RealSecretDistributions, SecretDistributions},
            triple::Triple,
        },
        runtime::session::{BaseSession, ParameterHandles, SmallSession, SmallSessionHandles},
        sharing::share::Share,
        small_execution::{prf::PRSSConversions, prss::PRSSState},
        tfhe_internals::parameters::DKGParams,
    },
};

use super::{InMemoryBasePreprocessing, InMemoryBitPreprocessing};

#[derive(Default)]
pub struct InMemoryDKGPreprocessing<Z: Ring> {
    in_memory_bits: InMemoryBitPreprocessing<Z>,
    in_memory_base: InMemoryBasePreprocessing<Z>,
    available_noise_lwe: Vec<Share<Z>>,
    available_noise_lwe_hat: Vec<Share<Z>>,
    available_noise_glwe: Vec<Share<Z>>,
    available_noise_oglwe: Vec<Share<Z>>,
    available_noise_compression_key: Vec<Share<Z>>,
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

    fn bits_len(&self) -> usize {
        self.in_memory_bits.bits_len()
    }
}

#[async_trait]
impl<Z> DKGPreprocessing<Z> for InMemoryDKGPreprocessing<Z>
where
    Z: Invert + PRSSConversions + ErrorCorrect + Solve,
{
    ///Store a vec of noise, each following the same TUniform distribution specified by bound.
    fn append_noises(&mut self, noises: Vec<Share<Z>>, bound: NoiseBounds) {
        //Note: do we want to assert that the distribution is the epxect one from self.parameters ?
        match bound {
            NoiseBounds::LweNoise(_) => self.available_noise_lwe.extend(noises),
            NoiseBounds::LweHatNoise(_) => self.available_noise_lwe_hat.extend(noises),
            NoiseBounds::GlweNoise(_) => self.available_noise_glwe.extend(noises),
            NoiseBounds::GlweNoiseSnS(_) => self.available_noise_oglwe.extend(noises),
            NoiseBounds::CompressionKSKNoise(_) => {
                self.available_noise_compression_key.extend(noises)
            }
        }
    }

    //Note that storing in noise format rather than raw bits saves space (and bandwidth for read/write)
    //We may want to store the noise depending on their distribution
    fn next_noise_vec(
        &mut self,
        amount: usize,
        bound: NoiseBounds,
    ) -> anyhow::Result<Vec<Share<Z>>> {
        let noise_distrib = match bound {
            NoiseBounds::LweNoise(_) => &mut self.available_noise_lwe,
            NoiseBounds::LweHatNoise(_) => &mut self.available_noise_lwe_hat,
            NoiseBounds::GlweNoise(_) => &mut self.available_noise_glwe,
            NoiseBounds::GlweNoiseSnS(_) => &mut self.available_noise_oglwe,
            NoiseBounds::CompressionKSKNoise(_) => &mut self.available_noise_compression_key,
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
        params: DKGParams,
        session: &mut SmallSession<Z>,
        preprocessing: &mut dyn BasePreprocessing<Z>,
    ) -> anyhow::Result<()> {
        //Need bits for lwe sk, pk lwe sk, glwe sk and maybe glwe sk sns
        let num_bits_needed = params.get_params_basics_handle().lwe_dimension().0
            + params.get_params_basics_handle().lwe_hat_dimension().0
            + params.get_params_basics_handle().glwe_sk_num_bits()
            + match params {
                DKGParams::WithoutSnS(_) => 0,
                DKGParams::WithSnS(sns_params) => sns_params.glwe_sk_num_bits_sns(),
            };

        let mut bit_preproc = InMemoryBitPreprocessing::default();

        bit_preproc.append_bits(
            RealBitGenEven::gen_bits_even(num_bits_needed, preprocessing, session).await?,
        );

        self.fill_from_triples_and_bit_preproc_small_session_appendix_version(
            params,
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
        params: DKGParams,
        session: &mut SmallSession<Z>,
        preprocessing_base: &mut dyn BasePreprocessing<Z>,
        preprocessing_bits: &mut dyn BitPreprocessing<Z>,
    ) -> anyhow::Result<()> {
        let my_role = session.my_role()?;
        let prss_state = session.prss_as_mut();

        let mut fill_noise = |prss_state: &mut PRSSState<Z>, num: usize, bound: NoiseBounds| {
            self.append_noises(
                (0..num)
                    .map(|_| {
                        Ok::<_, anyhow::Error>(Share::new(
                            my_role,
                            prss_state.mask_next(my_role, 1u128 << bound.get_bound().0)?,
                        ))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                bound,
            );
            Ok::<_, anyhow::Error>(())
        };

        let params_basics_handles = params.get_params_basics_handle();

        //Depending on encryption type, pksk requires either LweNoise noise or GlweNoise
        let (amount_pksk_lwe_noise, amount_pksk_glwe_noise) = match params_basics_handles
            .get_pksk_destination()
        {
            //type = LWE case
            Some(EncryptionKeyChoice::Small) => (params_basics_handles.num_needed_noise_pksk(), 0),
            //type = F-GLWE case
            Some(EncryptionKeyChoice::Big) => (0, params_basics_handles.num_needed_noise_pksk()),
            _ => (0, 0),
        };

        //Generate noise needed for the pksk (if needed) and the key switch key
        fill_noise(
            prss_state,
            amount_pksk_lwe_noise + params_basics_handles.num_needed_noise_ksk(),
            NoiseBounds::LweNoise(params_basics_handles.lwe_tuniform_bound()),
        )?;

        //Generate noise needed for pksk (if needed), the bootstrap key
        //and the decompression key
        fill_noise(
            prss_state,
            amount_pksk_glwe_noise
                + params_basics_handles.num_needed_noise_bk()
                + params_basics_handles.num_needed_noise_decompression_key(),
            NoiseBounds::GlweNoise(params_basics_handles.glwe_tuniform_bound()),
        )?;

        //Generate noise needed for compression key
        if let Some(bound) = params_basics_handles.compression_key_tuniform_bound() {
            fill_noise(
                prss_state,
                params_basics_handles.num_needed_noise_compression_key(),
                NoiseBounds::CompressionKSKNoise(bound),
            )?;
        }

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

        //Generate noise needed for pk
        fill_noise(
            prss_state,
            params_basics_handles.num_needed_noise_pk(),
            NoiseBounds::LweHatNoise(params_basics_handles.lwe_hat_tuniform_bound()),
        )?;

        //Fill in the required number of _raw_ bits
        let num_bits_needed = params_basics_handles.lwe_dimension().0
            + params_basics_handles.lwe_hat_dimension().0
            + params_basics_handles.glwe_sk_num_bits()
            + params_basics_handles.compression_sk_num_bits()
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

    /// Fill the noise from [`crate::execution::online::secret_distributions::SecretDistributions`]
    /// where the bits required to do so are generated through the [`BasePreprocessing`]
    /// Also generate the additional bits (and triples) needed from [`BasePreprocessing`]
    /// we thus need interation to generate the bits.
    async fn fill_from_base_preproc(
        &mut self,
        params: DKGParams,
        session: &mut BaseSession,
        preprocessing: &mut dyn BasePreprocessing<Z>,
    ) -> anyhow::Result<()> {
        let num_bits_required = params.get_params_basics_handle().total_bits_required();

        let mut bit_preproc = InMemoryBitPreprocessing::default();

        bit_preproc.append_bits(
            RealBitGenEven::gen_bits_even(num_bits_required, preprocessing, session).await?,
        );

        self.fill_from_triples_and_bit_preproc(params, session, preprocessing, &mut bit_preproc)
    }

    /// Fill the noise from [`crate::execution::online::secret_distributions::SecretDistributions`]
    /// where the bits required to do so are pulled from the [`BitPreprocessing`].
    /// The additional bits required are also pulled from [`BitPreprocessing`]
    /// and triples from [`TriplePreprocessing`].
    fn fill_from_triples_and_bit_preproc(
        &mut self,
        params: DKGParams,
        _session: &mut BaseSession,
        preprocessing_base: &mut dyn BasePreprocessing<Z>,
        preprocessing_bits: &mut dyn BitPreprocessing<Z>,
    ) -> anyhow::Result<()> {
        let params_basics_handles = params.get_params_basics_handle();
        let (amount_pksk_lwe_noise, amount_pksk_glwe_noise) = match params_basics_handles
            .get_pksk_destination()
        {
            //type = LWE case
            Some(EncryptionKeyChoice::Small) => (params_basics_handles.num_needed_noise_pksk(), 0),
            //type = F-GLWE case
            Some(EncryptionKeyChoice::Big) => (0, params_basics_handles.num_needed_noise_pksk()),
            _ => (0, 0),
        };

        //Generate noise needed for pksk (if needed) and the key switch key
        self.append_noises(
            RealSecretDistributions::t_uniform(
                params_basics_handles.num_needed_noise_ksk() + amount_pksk_lwe_noise,
                params_basics_handles.lwe_tuniform_bound(),
                preprocessing_bits,
            )?,
            NoiseBounds::LweNoise(params_basics_handles.lwe_tuniform_bound()),
        );

        //Generate noise needed for the pksk (if needed), the bootstrap key
        //and the decompression key
        self.append_noises(
            RealSecretDistributions::t_uniform(
                params_basics_handles.num_needed_noise_bk()
                    + amount_pksk_glwe_noise
                    + params_basics_handles.num_needed_noise_decompression_key(),
                params_basics_handles.glwe_tuniform_bound(),
                preprocessing_bits,
            )?,
            NoiseBounds::GlweNoise(params_basics_handles.glwe_tuniform_bound()),
        );

        //Generate noise needed for compression key
        if let Some(bound) = params_basics_handles.compression_key_tuniform_bound() {
            self.append_noises(
                RealSecretDistributions::t_uniform(
                    params_basics_handles.num_needed_noise_compression_key(),
                    bound,
                    preprocessing_bits,
                )?,
                NoiseBounds::CompressionKSKNoise(bound),
            );
        }

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

        //Generate noise needed for the pk
        self.append_noises(
            RealSecretDistributions::t_uniform(
                params_basics_handles.num_needed_noise_pk(),
                params_basics_handles.lwe_hat_tuniform_bound(),
                preprocessing_bits,
            )?,
            NoiseBounds::LweHatNoise(params_basics_handles.lwe_hat_tuniform_bound()),
        );

        //Fill in the required number of _raw_ bits
        let num_bits_required = params_basics_handles.lwe_dimension().0
            + params_basics_handles.glwe_sk_num_bits()
            + params_basics_handles.lwe_hat_dimension().0
            + params_basics_handles.compression_sk_num_bits()
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

    fn noise_len(&self, bound: NoiseBounds) -> usize {
        match bound {
            NoiseBounds::LweNoise(_) => self.available_noise_lwe.len(),
            NoiseBounds::LweHatNoise(_) => self.available_noise_lwe_hat.len(),
            NoiseBounds::GlweNoise(_) => self.available_noise_glwe.len(),
            NoiseBounds::GlweNoiseSnS(_) => self.available_noise_oglwe.len(),
            NoiseBounds::CompressionKSKNoise(_) => self.available_noise_compression_key.len(),
        }
    }
}

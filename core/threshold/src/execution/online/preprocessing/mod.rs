use self::redis::{redis_factory, CorrelatedRandomnessType, RedisConf};
use super::secret_distributions::{RealSecretDistributions, SecretDistributions};
use super::triple::Triple;
use crate::algebra::base_ring::{Z128, Z64};
use crate::algebra::galois_rings::common::ResiduePoly;
use crate::algebra::structure_traits::{ErrorCorrect, Invert, Solve};
use crate::execution::constants::{B_SWITCH_SQUASH, LOG_B_SWITCH_SQUASH, STATSEC};
use crate::execution::keyset_config::KeySetConfig;
use crate::execution::online::gen_bits::{BitGenEven, RealBitGenEven};
use crate::execution::online::preprocessing::memory::{memory_factory, InMemoryBitPreprocessing};
use crate::execution::runtime::session::{BaseSession, ParameterHandles, SmallSession};
use crate::execution::small_execution::prss::PRSSPrimitives;
use crate::execution::tfhe_internals::parameters::{DKGParams, NoiseBounds, TUniformBound};
use crate::{
    algebra::structure_traits::Ring, error::error_handler::anyhow_error_and_log,
    execution::sharing::share::Share,
};
use itertools::Itertools;

use async_trait::async_trait;
use mockall::{automock, mock};
#[automock]
/// Trait that a __store__ for shares of multiplication triples ([`Triple`]) needs to implement.
pub trait TriplePreprocessing<Z: Clone + Send + Sync>: Send + Sync {
    /// Outputs share of a random triple
    fn next_triple(&mut self) -> anyhow::Result<Triple<Z>> {
        if self.triples_len() == 0 {
            return Err(anyhow_error_and_log("No triples available".to_string()));
        }
        // We unwrap here because we know that the next_triple_vec will return one triple
        // as we just checked the length
        Ok(self.next_triple_vec(1).unwrap().pop().unwrap())
    }

    /// Outputs a vector of shares of random triples
    fn next_triple_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Triple<Z>>>;

    fn append_triples(&mut self, triples: Vec<Triple<Z>>);

    fn triples_len(&self) -> usize;
}

#[automock]
/// Trait that a __store__ for shares of uniform randomness needs to implement.
pub trait RandomPreprocessing<Z: Clone> {
    /// Outputs share of a uniformly random element of the [`Ring`]
    fn next_random(&mut self) -> anyhow::Result<Share<Z>> {
        if self.randoms_len() == 0 {
            return Err(anyhow_error_and_log("No randomness available".to_string()));
        }

        // We unwrap here because we know that the next_random_vec will return one triple
        // as we just checked the length
        Ok(self.next_random_vec(1).unwrap().pop().unwrap())
    }

    /// Constructs a vector of shares of uniformly random elements of the [`Ring`]
    fn next_random_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<Z>>>;

    fn append_randoms(&mut self, randoms: Vec<Share<Z>>);

    fn randoms_len(&self) -> usize;
}

/// Trait for both [`RandomPreprocessing`] and [`TriplePreprocessing`]
pub trait BasePreprocessing<Z: Clone + Send + Sync>:
    TriplePreprocessing<Z> + RandomPreprocessing<Z> + Send + Sync
{
}

//Can't automock the above
mock! {
    pub BasePreprocessing<Z: Clone> {}
    impl<Z: Ring> TriplePreprocessing<Z> for BasePreprocessing<Z> {
        fn next_triple(&mut self) -> anyhow::Result<Triple<Z>>;
        fn next_triple_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Triple<Z>>>;
        fn append_triples(&mut self, triples: Vec<Triple<Z>>);
        fn triples_len(&self) -> usize;
    }

    impl<Z: Ring> RandomPreprocessing<Z> for BasePreprocessing<Z> {
        fn next_random(&mut self) -> anyhow::Result<Share<Z>>;
        fn next_random_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<Z>>>;
        fn append_randoms(&mut self, randoms: Vec<Share<Z>>);
        fn randoms_len(&self) -> usize;
    }

    impl<Z: Ring> BasePreprocessing<Z> for BasePreprocessing<Z> {}
}

pub trait BitPreprocessing<Z: Clone>: Send + Sync {
    fn append_bits(&mut self, bits: Vec<Share<Z>>);
    fn next_bit(&mut self) -> anyhow::Result<Share<Z>>;
    fn next_bit_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<Z>>>;
    fn bits_len(&self) -> usize;
}

/// InMemory type that implement the [`BitDecPreprocessing`]
/// Trait. Put here because the trait requires being able to
/// cast to this struct
#[derive(Default, Debug)]
pub struct InMemoryBitDecPreprocessing<const EXTENSION_DEGREE: usize> {
    available_triples: Vec<Triple<ResiduePoly<Z64, EXTENSION_DEGREE>>>,
    available_bits: Vec<Share<ResiduePoly<Z64, EXTENSION_DEGREE>>>,
}

#[async_trait]
/// Trait that a __store__ for correlated randomness related to the bit
/// decomposition distributed decryption needs to implement.
///
/// Used in [`crate::execution::endpoints::decryption::run_decryption_bitdec`]
pub trait BitDecPreprocessing<const EXTENSION_DEGREE: usize>:
    BitPreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>
    + TriplePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>
{
    //For ctxt space Z_2^k need k + 3k log2(k) + 1 (raw) triples
    fn num_required_triples(&self, num_ctxts: usize) -> usize {
        1217 * num_ctxts
    }

    //For ctxt space Z_2^k need k bits
    fn num_required_bits(&self, num_ctxts: usize) -> usize {
        64 * num_ctxts
    }

    async fn fill_from_base_preproc(
        &mut self,
        preprocessing: &mut dyn BasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>,
        session: &mut BaseSession,
        num_ctxts: usize,
    ) -> anyhow::Result<()>;

    /// Load the correlated randomness from where
    /// it is stored (e.g. redis) into RAM.
    fn cast_to_in_memory_impl(
        &mut self,
        num_ctxts: usize,
    ) -> anyhow::Result<InMemoryBitDecPreprocessing<EXTENSION_DEGREE>>;
}

/// Trait that a __store__ for correlated randomness related to the
/// switch and squash distributed decryption needs to implement.
///
/// Used in [`crate::execution::endpoints::decryption::run_decryption_noiseflood`]
#[async_trait]
pub trait NoiseFloodPreprocessing<const EXTENSION_DEGREE: usize>: Send + Sync
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: Invert + Solve + ErrorCorrect,
{
    fn append_masks(&mut self, masks: Vec<ResiduePoly<Z128, EXTENSION_DEGREE>>);
    fn next_mask(&mut self) -> anyhow::Result<ResiduePoly<Z128, EXTENSION_DEGREE>>;
    fn next_mask_vec(
        &mut self,
        amount: usize,
    ) -> anyhow::Result<Vec<ResiduePoly<Z128, EXTENSION_DEGREE>>>;

    /// Fill the masks directly from the [`crate::execution::small_execution::prss::PRSSState`] available from [`SmallSession`]
    fn fill_from_small_session(
        &mut self,
        session: &mut SmallSession<ResiduePoly<Z128, EXTENSION_DEGREE>>,
        amount: usize,
    ) -> anyhow::Result<()> {
        let own_role = session.my_role();

        let prss_span = tracing::info_span!("PRSS-MASK.Next", batch_size = amount);
        let masks = prss_span.in_scope(|| {
            (0..amount)
                .map(|_| session.prss_state.mask_next(own_role, B_SWITCH_SQUASH))
                .try_collect()
        })?;

        self.append_masks(masks);

        Ok(())
    }

    /// Fill the masks by first generating bits via triples and randomness provided by [`BasePreprocessing`]
    async fn fill_from_base_preproc(
        &mut self,
        preprocessing: &mut dyn BasePreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>,
        session: &mut BaseSession,
        num_ctxts: usize,
    ) -> anyhow::Result<()> {
        let bound_d = (STATSEC + LOG_B_SWITCH_SQUASH) as usize;
        let num_bits = 2 * num_ctxts * (bound_d + 2);
        let available_bits =
            RealBitGenEven::gen_bits_even(num_bits, preprocessing, session).await?;
        let mut bit_preproc = InMemoryBitPreprocessing { available_bits };

        self.fill_from_bits_preproc(&mut bit_preproc, num_ctxts)
    }

    /// Fill the masks directly from available bits provided by [`BitPreprocessing`],
    /// using [`crate::execution::online::secret_distributions::SecretDistributions`]
    fn fill_from_bits_preproc(
        &mut self,
        bit_preproc: &mut dyn BitPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>,
        num_ctxts: usize,
    ) -> anyhow::Result<()> {
        let bound_d = (STATSEC + LOG_B_SWITCH_SQUASH) as usize;
        self.append_masks(
            RealSecretDistributions::t_uniform(2 * num_ctxts, TUniformBound(bound_d), bit_preproc)?
                .into_iter()
                .tuples()
                .map(|(a, b)| a.value() + b.value())
                .collect(),
        );
        Ok(())
    }
}

impl NoiseBounds {
    pub(crate) fn get_type(&self) -> CorrelatedRandomnessType {
        match self {
            NoiseBounds::LweNoise(_) => CorrelatedRandomnessType::NoiseLwe,
            NoiseBounds::LweHatNoise(_) => CorrelatedRandomnessType::NoiseLweHat,
            NoiseBounds::GlweNoise(_) => CorrelatedRandomnessType::NoiseGlwe,
            NoiseBounds::GlweNoiseSnS(_) => CorrelatedRandomnessType::NoiseGlweSnS,
            NoiseBounds::CompressionKSKNoise(_) => CorrelatedRandomnessType::NoiseCompressionKSK,
            NoiseBounds::SnsCompressionKSKNoise(_) => {
                CorrelatedRandomnessType::SnsNoiseCompressionKSK
            }
        }
    }
}

/// Trait that a __store__ for correlated randomness related to
/// the ditributed key generation protocol needs to implement.
///
/// Used in [`crate::execution::endpoints::keygen::distributed_keygen`]
#[async_trait]
pub trait DKGPreprocessing<Z: Ring>: BasePreprocessing<Z> + BitPreprocessing<Z> {
    ///Store a vec of noise, each following the same TUniform distribution specified by bound.
    fn append_noises(&mut self, noises: Vec<Share<Z>>, bound: NoiseBounds);

    //Note that storing in noise format rather than raw bits saves space (and bandwidth for read/write)
    //We may want to store the noise depending on their distribution
    //(2 or 3 diff distribution required for DKG depending on whether we need Switch and Squash keys)
    fn next_noise_vec(
        &mut self,
        amount: usize,
        bound: NoiseBounds,
    ) -> anyhow::Result<Vec<Share<Z>>>;

    /// Fill the noise from [`crate::execution::online::secret_distributions::SecretDistributions`]
    /// where the bits required to do so are generated through the [`BasePreprocessing`]
    /// Also generate the additional bits (and triples) needed from [`BasePreprocessing`]
    /// we thus need interation to generate the bits.
    async fn fill_from_base_preproc(
        &mut self,
        params: DKGParams,
        keyset_config: KeySetConfig,
        session: &mut BaseSession,
        preprocessing: &mut dyn BasePreprocessing<Z>,
    ) -> anyhow::Result<()>;

    /// Fill the noise from [`crate::execution::online::secret_distributions::SecretDistributions`]
    /// where the bits required to do so are pulled from the [`BitPreprocessing`].
    /// The additional bits required are also pulled from [`BitPreprocessing`]
    /// and triples from [`TriplePreprocessing`].
    fn fill_from_triples_and_bit_preproc(
        &mut self,
        params: DKGParams,
        keyset_config: KeySetConfig,
        session: &mut BaseSession,
        preprocessing_triples: &mut dyn BasePreprocessing<Z>,
        preprocessing_bits: &mut dyn BitPreprocessing<Z>,
    ) -> anyhow::Result<()>;

    fn noise_len(&self, bound: NoiseBounds) -> usize;
}

pub(crate) fn dkg_fill_from_triples_and_bit_preproc<Z: Ring>(
    prep: &mut impl DKGPreprocessing<Z>,
    params: DKGParams,
    keyset_config: KeySetConfig,
    preprocessing_base: &mut dyn BasePreprocessing<Z>,
    preprocessing_bits: &mut dyn BitPreprocessing<Z>,
) -> anyhow::Result<()> {
    let params_basics_handles = params.get_params_basics_handle();

    //Generate noise needed for pksk (if needed) and the key switch key
    prep.append_noises(
        RealSecretDistributions::from_noise_info(
            params_basics_handles.all_lwe_noise(keyset_config),
            preprocessing_bits,
        )?,
        NoiseBounds::LweNoise(params_basics_handles.lwe_tuniform_bound()),
    );

    //Generate noise needed for the pksk (if needed), the bootstrap key
    //and the decompression key
    prep.append_noises(
        RealSecretDistributions::from_noise_info(
            params_basics_handles.all_glwe_noise(keyset_config),
            preprocessing_bits,
        )?,
        NoiseBounds::GlweNoise(params_basics_handles.glwe_tuniform_bound()),
    );

    // Generate noise needed for compression key
    let ksk_noise = params_basics_handles.all_compression_ksk_noise(keyset_config);
    prep.append_noises(
        RealSecretDistributions::from_noise_info(ksk_noise.clone(), preprocessing_bits)?,
        ksk_noise.bound,
    );

    //Generate noise needed for Switch and Squash bootstrap key if needed
    if keyset_config.is_standard() {
        match params {
            DKGParams::WithSnS(sns_params) => {
                prep.append_noises(
                    RealSecretDistributions::from_noise_info(
                        sns_params.all_bk_sns_noise(),
                        preprocessing_bits,
                    )?,
                    NoiseBounds::GlweNoiseSnS(sns_params.glwe_tuniform_bound_sns()),
                );
            }
            DKGParams::WithoutSnS(_) => (),
        }
    }

    // Generate noise for sns compression key if needed
    match keyset_config {
        KeySetConfig::Standard(_) | KeySetConfig::AddSnsCompressionKey => match params {
            DKGParams::WithSnS(sns_params) => {
                let noise_info = sns_params.num_needed_noise_sns_compression_key();
                let bound = noise_info.bound;
                prep.append_noises(
                    RealSecretDistributions::from_noise_info(noise_info, preprocessing_bits)?,
                    bound,
                );
            }
            DKGParams::WithoutSnS(_) => (),
        },
        KeySetConfig::DecompressionOnly => {}
    }

    //Generate noise needed for the pk
    prep.append_noises(
        RealSecretDistributions::from_noise_info(
            params_basics_handles.all_lwe_hat_noise(keyset_config),
            preprocessing_bits,
        )?,
        NoiseBounds::LweHatNoise(params_basics_handles.lwe_hat_tuniform_bound()),
    );

    //Fill in the required number of _raw_ bits
    let num_bits_required = params_basics_handles.num_raw_bits(keyset_config);

    prep.append_bits(preprocessing_bits.next_bit_vec(num_bits_required)?);

    //Fill in the required number of triples
    let num_triples_required = params_basics_handles.total_triples_required(keyset_config)
        - params_basics_handles.total_bits_required(keyset_config);

    prep.append_triples(preprocessing_base.next_triple_vec(num_triples_required)?);

    //Fill in the required number of randomness
    let num_randomness_required = params_basics_handles.total_randomness_required(keyset_config)
        - params_basics_handles.total_bits_required(keyset_config);
    prep.append_randoms(preprocessing_base.next_random_vec(num_randomness_required)?);

    Ok(())
}

pub trait PreprocessorFactory<const EXTENSION_DEGREE: usize>: Sync + Send {
    fn create_bit_preprocessing_residue_64(
        &mut self,
    ) -> Box<dyn BitPreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>>;
    fn create_bit_preprocessing_residue_128(
        &mut self,
    ) -> Box<dyn BitPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>>;
    fn create_base_preprocessing_residue_64(
        &mut self,
    ) -> Box<dyn BasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>>;
    fn create_base_preprocessing_residue_128(
        &mut self,
    ) -> Box<dyn BasePreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>>;
    fn create_bit_decryption_preprocessing(
        &mut self,
    ) -> Box<dyn BitDecPreprocessing<EXTENSION_DEGREE>>;
    fn create_noise_flood_preprocessing(
        &mut self,
    ) -> Box<dyn NoiseFloodPreprocessing<EXTENSION_DEGREE>>;
    fn create_dkg_preprocessing_no_sns(
        &mut self,
    ) -> Box<dyn DKGPreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>>;
    fn create_dkg_preprocessing_with_sns(
        &mut self,
    ) -> Box<dyn DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>>;
}

/// Returns a default factory for the global preprocessor
pub fn create_memory_factory<const EXTENSION_DEGREE: usize>(
) -> Box<dyn PreprocessorFactory<EXTENSION_DEGREE>>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
{
    memory_factory::<EXTENSION_DEGREE>()
}

pub fn create_redis_factory<const EXTENSION_DEGREE: usize>(
    key_prefix: String,
    redis_conf: &RedisConf,
) -> Box<dyn PreprocessorFactory<EXTENSION_DEGREE>>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
{
    redis_factory::<EXTENSION_DEGREE>(key_prefix, redis_conf)
}

pub(crate) mod constants;
pub mod dummy;
pub(crate) mod memory;
pub mod orchestration;
pub mod redis;

// The non_local_effect_before_error_return lint complains
// about as_mut() calls but I believe that's a false positive.

#[allow(unknown_lints)]
#[allow(non_local_effect_before_error_return)]
impl<Z: Clone + Send + Sync> RandomPreprocessing<Z> for Box<dyn BasePreprocessing<Z>> {
    fn next_random_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<Z>>> {
        self.as_mut().next_random_vec(amount)
    }

    fn append_randoms(&mut self, randoms: Vec<Share<Z>>) {
        self.as_mut().append_randoms(randoms)
    }

    fn randoms_len(&self) -> usize {
        self.as_ref().randoms_len()
    }
}

#[allow(unknown_lints)]
#[allow(non_local_effect_before_error_return)]
impl<Z: Clone + Send + Sync> TriplePreprocessing<Z> for Box<dyn BasePreprocessing<Z>> {
    fn next_triple_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Triple<Z>>> {
        self.as_mut().next_triple_vec(amount)
    }

    fn append_triples(&mut self, triples: Vec<Triple<Z>>) {
        self.as_mut().append_triples(triples)
    }

    fn triples_len(&self) -> usize {
        self.as_ref().triples_len()
    }
}

impl<Z: Clone + Send + Sync> BasePreprocessing<Z> for Box<dyn BasePreprocessing<Z>> {}

#[allow(unknown_lints)]
#[allow(non_local_effect_before_error_return)]
impl<Z: Clone + Send + Sync> TriplePreprocessing<Z> for Box<dyn DKGPreprocessing<Z>> {
    fn next_triple_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Triple<Z>>> {
        self.as_mut().next_triple_vec(amount)
    }

    fn append_triples(&mut self, triples: Vec<Triple<Z>>) {
        self.as_mut().append_triples(triples)
    }

    fn triples_len(&self) -> usize {
        self.as_ref().triples_len()
    }
}

#[allow(unknown_lints)]
#[allow(non_local_effect_before_error_return)]
impl<Z: Clone + Send + Sync> RandomPreprocessing<Z> for Box<dyn DKGPreprocessing<Z>> {
    fn next_random_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<Z>>> {
        self.as_mut().next_random_vec(amount)
    }

    fn append_randoms(&mut self, randoms: Vec<Share<Z>>) {
        self.as_mut().append_randoms(randoms)
    }

    fn randoms_len(&self) -> usize {
        self.as_ref().randoms_len()
    }
}

impl<Z: Clone + Send + Sync> BasePreprocessing<Z> for Box<dyn DKGPreprocessing<Z>> {}

#[allow(unknown_lints)]
#[allow(non_local_effect_before_error_return)]
impl<Z: Clone + Send + Sync> BitPreprocessing<Z> for Box<dyn DKGPreprocessing<Z>> {
    fn append_bits(&mut self, bits: Vec<Share<Z>>) {
        self.as_mut().append_bits(bits)
    }
    fn next_bit(&mut self) -> anyhow::Result<Share<Z>> {
        self.as_mut().next_bit()
    }
    fn next_bit_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<Z>>> {
        self.as_mut().next_bit_vec(amount)
    }
    fn bits_len(&self) -> usize {
        self.as_ref().bits_len()
    }
}

#[allow(unknown_lints)]
#[allow(non_local_effect_before_error_return)]
#[async_trait]
impl<Z: Ring> DKGPreprocessing<Z> for Box<dyn DKGPreprocessing<Z>> {
    fn append_noises(&mut self, noises: Vec<Share<Z>>, bound: NoiseBounds) {
        self.as_mut().append_noises(noises, bound)
    }

    fn next_noise_vec(
        &mut self,
        amount: usize,
        bound: NoiseBounds,
    ) -> anyhow::Result<Vec<Share<Z>>> {
        self.as_mut().next_noise_vec(amount, bound)
    }

    async fn fill_from_base_preproc(
        &mut self,
        params: DKGParams,
        keyset_config: KeySetConfig,
        session: &mut BaseSession,
        preprocessing: &mut dyn BasePreprocessing<Z>,
    ) -> anyhow::Result<()> {
        self.as_mut()
            .fill_from_base_preproc(params, keyset_config, session, preprocessing)
            .await
    }

    fn fill_from_triples_and_bit_preproc(
        &mut self,
        params: DKGParams,
        keyset_config: KeySetConfig,
        session: &mut BaseSession,
        preprocessing_triples: &mut dyn BasePreprocessing<Z>,
        preprocessing_bits: &mut dyn BitPreprocessing<Z>,
    ) -> anyhow::Result<()> {
        self.as_mut().fill_from_triples_and_bit_preproc(
            params,
            keyset_config,
            session,
            preprocessing_triples,
            preprocessing_bits,
        )
    }

    fn noise_len(&self, bound: NoiseBounds) -> usize {
        self.as_ref().noise_len(bound)
    }
}

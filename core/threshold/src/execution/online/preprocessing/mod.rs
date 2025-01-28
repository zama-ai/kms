use self::redis::{redis_factory, CorrelatedRandomnessType, RedisConf};
use super::secret_distributions::{RealSecretDistributions, SecretDistributions};
use super::triple::Triple;
use crate::algebra::base_ring::{Z128, Z64};
use crate::algebra::galois_rings::common::ResiduePoly;
use crate::algebra::structure_traits::{ErrorCorrect, Invert, Solve};
use crate::execution::online::preprocessing::memory::memory_factory;
use crate::execution::runtime::session::{BaseSession, SmallSession};
use crate::execution::tfhe_internals::parameters::{DKGParams, NoiseBounds};
use crate::{
    algebra::structure_traits::Ring, error::error_handler::anyhow_error_and_log,
    execution::sharing::share::Share,
};

use async_trait::async_trait;
use mockall::{automock, mock};

#[automock]
/// Trait that a __store__ for shares of multiplication triples ([`Triple`]) needs to implement.
pub trait TriplePreprocessing<Z: Clone> {
    /// Outputs share of a random triple
    fn next_triple(&mut self) -> anyhow::Result<Triple<Z>> {
        self.next_triple_vec(1)?
            .pop()
            .ok_or_else(|| anyhow_error_and_log("Error accessing 0th triple".to_string()))
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
        self.next_random_vec(1)?
            .pop()
            .ok_or_else(|| anyhow_error_and_log("Error accessing 0th randomness".to_string()))
    }

    /// Constructs a vector of shares of uniformly random elements of the [`Ring`]
    fn next_random_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<Z>>>;

    fn append_randoms(&mut self, randoms: Vec<Share<Z>>);

    fn randoms_len(&self) -> usize;
}

/// Trait for both [`RandomPreprocessing`] and [`TriplePreprocessing`]
pub trait BasePreprocessing<Z: Clone>:
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
}

/// Trait that a __store__ for correlated randomness related to the
/// switch and squash distributed decryption needs to implement.
///
/// Used in [`crate::execution::endpoints::decryption::run_decryption_noiseflood`]
#[async_trait]
pub trait NoiseFloodPreprocessing<const EXTENSION_DEGREE: usize>: Send + Sync
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: Ring,
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
    ) -> anyhow::Result<()>;

    /// Fill the masks by first generating bits via triples and randomness provided by [`BasePreprocessing`]
    async fn fill_from_base_preproc(
        &mut self,
        preprocessing: &mut dyn BasePreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>,
        session: &mut BaseSession,
        num_ctxts: usize,
    ) -> anyhow::Result<()>;

    /// Fill the masks directly from available bits provided by [`BitPreprocessing`],
    /// using [`crate::execution::online::secret_distributions::SecretDistributions`]
    fn fill_from_bits_preproc(
        &mut self,
        bit_preproc: &mut dyn BitPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>,
        num_ctxts: usize,
    ) -> anyhow::Result<()>;
}

impl NoiseBounds {
    pub(crate) fn get_type(&self) -> CorrelatedRandomnessType {
        match self {
            NoiseBounds::LweNoise(_) => CorrelatedRandomnessType::NoiseLwe,
            NoiseBounds::LweHatNoise(_) => CorrelatedRandomnessType::NoiseLweHat,
            NoiseBounds::GlweNoise(_) => CorrelatedRandomnessType::NoiseGlwe,
            NoiseBounds::GlweNoiseSnS(_) => CorrelatedRandomnessType::NoiseGlweSnS,
            NoiseBounds::CompressionKSKNoise(_) => CorrelatedRandomnessType::NoiseCompressionKSK,
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
        session: &mut BaseSession,
        preprocessing_triples: &mut dyn BasePreprocessing<Z>,
        preprocessing_bits: &mut dyn BitPreprocessing<Z>,
    ) -> anyhow::Result<()>;

    fn noise_len(&self, bound: NoiseBounds) -> usize;
}

pub(crate) fn dkg_fill_from_triples_and_bit_preproc<Z: Ring>(
    prep: &mut impl DKGPreprocessing<Z>,
    params: DKGParams,
    preprocessing_base: &mut dyn BasePreprocessing<Z>,
    preprocessing_bits: &mut dyn BitPreprocessing<Z>,
) -> anyhow::Result<()> {
    let params_basics_handles = params.get_params_basics_handle();

    //Generate noise needed for pksk (if needed) and the key switch key
    prep.append_noises(
        RealSecretDistributions::from_noise_info(
            params_basics_handles.all_lwe_noise(),
            preprocessing_bits,
        )?,
        NoiseBounds::LweNoise(params_basics_handles.lwe_tuniform_bound()),
    );

    //Generate noise needed for the pksk (if needed), the bootstrap key
    //and the decompression key
    prep.append_noises(
        RealSecretDistributions::from_noise_info(
            params_basics_handles.all_glwe_noise(),
            preprocessing_bits,
        )?,
        NoiseBounds::GlweNoise(params_basics_handles.glwe_tuniform_bound()),
    );

    // Generate noise needed for compression key
    let ksk_noise = params_basics_handles.all_compression_ksk_noise();
    prep.append_noises(
        RealSecretDistributions::from_noise_info(ksk_noise.clone(), preprocessing_bits)?,
        ksk_noise.bound,
    );

    //Generate noise needed for Switch and Squash bootstrap key if needed
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

    //Generate noise needed for the pk
    prep.append_noises(
        RealSecretDistributions::from_noise_info(
            params_basics_handles.all_lwe_hat_noise(),
            preprocessing_bits,
        )?,
        NoiseBounds::LweHatNoise(params_basics_handles.lwe_hat_tuniform_bound()),
    );

    //Fill in the required number of _raw_ bits
    let num_bits_required = params_basics_handles.num_raw_bits();

    prep.append_bits(preprocessing_bits.next_bit_vec(num_bits_required)?);

    //Fill in the required number of triples
    let num_triples_required = params_basics_handles.total_triples_required()
        - params_basics_handles.total_bits_required();

    prep.append_triples(preprocessing_base.next_triple_vec(num_triples_required)?);

    //Fill in the required number of randomness
    let num_randomness_required = params_basics_handles.total_randomness_required()
        - params_basics_handles.total_bits_required();
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
pub mod orchestrator;
pub mod redis;

use self::redis::{redis_factory, CorrelatedRandomnessType, RedisConf};

use super::triple::Triple;
use crate::algebra::residue_poly::{ResiduePoly128, ResiduePoly64};
use crate::execution::online::preprocessing::memory::memory_factory;
use crate::execution::runtime::session::{BaseSession, SmallSession};
use crate::execution::tfhe_internals::parameters::{DKGParams, TUniformBound};
use crate::{
    algebra::structure_traits::Ring, error::error_handler::anyhow_error_and_log,
    execution::sharing::share::Share,
};

use async_trait::async_trait;
use mockall::{automock, mock};

/// The amount of triples required in a bitdec distributed decryption
pub const TRIPLE_BATCH_SIZE: usize = 1281_usize;
/// The amount of randoms required in a bitdec distributed decryption
pub const RANDOM_BATCH_SIZE: usize = 60_usize;

#[automock]
/// Trait that a __store__ for shares of multiplication triples ([`Triple`]) needs to implement.
pub trait TriplePreprocessing<Z: Ring> {
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
pub trait RandomPreprocessing<Z: Ring> {
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
pub trait BasePreprocessing<R: Ring>:
    TriplePreprocessing<R> + RandomPreprocessing<R> + Send + Sync
{
}

//Can't automock the above
mock! {
    pub BasePreprocessing<Z:Ring> {}
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

pub trait BitPreprocessing<Z: Ring>: Send + Sync {
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
pub trait BitDecPreprocessing:
    BitPreprocessing<ResiduePoly64> + TriplePreprocessing<ResiduePoly64>
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
        preprocessing: &mut dyn BasePreprocessing<ResiduePoly64>,
        session: &mut BaseSession,
        num_ctxts: usize,
    ) -> anyhow::Result<()>;
}

/// Trait that a __store__ for correlated randomness related to the  
/// switch and squash distributed decryption needs to implement.
///
/// Used in [`crate::execution::endpoints::decryption::run_decryption_noiseflood`]
#[async_trait]
pub trait NoiseFloodPreprocessing: Send {
    fn append_masks(&mut self, masks: Vec<ResiduePoly128>);
    fn next_mask(&mut self) -> anyhow::Result<ResiduePoly128>;
    fn next_mask_vec(&mut self, amount: usize) -> anyhow::Result<Vec<ResiduePoly128>>;

    /// Fill the masks directly from the [`crate::execution::small_execution::prss::PRSSState`] available from [`SmallSession`]
    fn fill_from_small_session(
        &mut self,
        session: &mut SmallSession<ResiduePoly128>,
        amount: usize,
    ) -> anyhow::Result<()>;

    /// Fill the masks by first generating bits via triples and randomness provided by [`BasePreprocessing`]
    async fn fill_from_base_preproc(
        &mut self,
        preprocessing: &mut dyn BasePreprocessing<ResiduePoly128>,
        session: &mut BaseSession,
        num_ctxts: usize,
    ) -> anyhow::Result<()>;

    /// Fill the masks directly from available bits provided by [`BitPreprocessing`],
    /// using [`crate::execution::online::secret_distributions::SecretDistributions`]
    fn fill_from_bits_preproc(
        &mut self,
        bit_preproc: &mut dyn BitPreprocessing<ResiduePoly128>,
        num_ctxts: usize,
    ) -> anyhow::Result<()>;
}

#[derive(Debug)]
pub enum NoiseBounds {
    LweNoise(TUniformBound),
    GlweNoise(TUniformBound),
    GlweNoiseSnS(TUniformBound),
}

impl NoiseBounds {
    pub fn get_bound(&self) -> TUniformBound {
        match self {
            NoiseBounds::LweNoise(bound) => *bound,
            NoiseBounds::GlweNoise(bound) => *bound,
            NoiseBounds::GlweNoiseSnS(bound) => *bound,
        }
    }

    pub(crate) fn get_type(&self) -> CorrelatedRandomnessType {
        match self {
            NoiseBounds::LweNoise(_) => CorrelatedRandomnessType::NoiseLwe,
            NoiseBounds::GlweNoise(_) => CorrelatedRandomnessType::NoiseGlwe,
            NoiseBounds::GlweNoiseSnS(_) => CorrelatedRandomnessType::NoiseGlweSnS,
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

    /// __Fill the noise directly from the [`crate::execution::small_execution::prss::PRSSState`] available from [`SmallSession`]
    /// as described in the appendix of the NIST document.__
    /// The bits and triples are generated/pulled from the [`BasePreprocessing`],
    /// we thus need interaction to generate the bits.
    async fn fill_from_base_preproc_small_session_appendix_version(
        &mut self,
        params: DKGParams,
        session: &mut SmallSession<Z>,
        preprocessing: &mut dyn BasePreprocessing<Z>,
    ) -> anyhow::Result<()>;

    /// __Fill the noise directly from the [`crate::execution::small_execution::prss::PRSSState`] available from [`SmallSession`]
    /// as described in the appendix of the NIST document.__
    /// Pull the triples from [`TriplePreprocessing`] and the bits from [`BitPreprocessing`]
    fn fill_from_triples_and_bit_preproc_small_session_appendix_version(
        &mut self,
        params: DKGParams,
        session: &mut SmallSession<Z>,
        preprocessing_triples: &mut dyn BasePreprocessing<Z>,
        preprocessing_bits: &mut dyn BitPreprocessing<Z>,
    ) -> anyhow::Result<()>;

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
}

pub trait PreprocessorFactory: Sync + Send {
    fn create_bit_preprocessing_residue_64(&mut self) -> Box<dyn BitPreprocessing<ResiduePoly64>>;
    fn create_bit_preprocessing_residue_128(&mut self)
        -> Box<dyn BitPreprocessing<ResiduePoly128>>;
    fn create_base_preprocessing_residue_64(&mut self)
        -> Box<dyn BasePreprocessing<ResiduePoly64>>;
    fn create_base_preprocessing_residue_128(
        &mut self,
    ) -> Box<dyn BasePreprocessing<ResiduePoly128>>;
    fn create_bit_decryption_preprocessing(&mut self) -> Box<dyn BitDecPreprocessing>;
    fn create_noise_flood_preprocessing(&mut self) -> Box<dyn NoiseFloodPreprocessing>;
    fn create_dkg_preprocessing_no_sns(&mut self) -> Box<dyn DKGPreprocessing<ResiduePoly64>>;
    fn create_dkg_preprocessing_with_sns(&mut self) -> Box<dyn DKGPreprocessing<ResiduePoly128>>;
}

/// Returns a default factory for the global preprocessor
pub fn create_memory_factory() -> Box<dyn PreprocessorFactory> {
    memory_factory()
}

pub fn create_redis_factory(
    key_prefix: String,
    redis_conf: &RedisConf,
) -> Box<dyn PreprocessorFactory> {
    redis_factory(key_prefix, redis_conf)
}

pub mod dummy;
pub(crate) mod memory;
pub mod orchestrator;
pub mod redis;

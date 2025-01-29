use tonic::async_trait;

use crate::{
    algebra::structure_traits::{ErrorCorrect, Invert, Ring, Solve},
    error::error_handler::anyhow_error_and_log,
    execution::{
        keyset_config::KeySetConfig,
        online::{
            gen_bits::{BitGenEven, RealBitGenEven},
            preprocessing::{
                BasePreprocessing, BitPreprocessing, DKGPreprocessing, NoiseBounds,
                RandomPreprocessing, TriplePreprocessing,
            },
            triple::Triple,
        },
        runtime::session::BaseSession,
        sharing::share::Share,
        small_execution::prf::PRSSConversions,
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
    ) -> anyhow::Result<()> {
        let num_bits_required = params
            .get_params_basics_handle()
            .total_bits_required(keyset_config);

        let mut bit_preproc = InMemoryBitPreprocessing::default();

        bit_preproc.append_bits(
            RealBitGenEven::gen_bits_even(num_bits_required, preprocessing, session).await?,
        );

        self.fill_from_triples_and_bit_preproc(
            params,
            keyset_config,
            session,
            preprocessing,
            &mut bit_preproc,
        )
    }

    /// Fill the noise from [`crate::execution::online::secret_distributions::SecretDistributions`]
    /// where the bits required to do so are pulled from the [`BitPreprocessing`].
    /// The additional bits required are also pulled from [`BitPreprocessing`]
    /// and triples from [`TriplePreprocessing`].
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
        match bound {
            NoiseBounds::LweNoise(_) => self.available_noise_lwe.len(),
            NoiseBounds::LweHatNoise(_) => self.available_noise_lwe_hat.len(),
            NoiseBounds::GlweNoise(_) => self.available_noise_glwe.len(),
            NoiseBounds::GlweNoiseSnS(_) => self.available_noise_oglwe.len(),
            NoiseBounds::CompressionKSKNoise(_) => self.available_noise_compression_key.len(),
        }
    }
}

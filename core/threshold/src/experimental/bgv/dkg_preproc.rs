use tonic::async_trait;

use crate::{
    error::error_handler::anyhow_error_and_log,
    execution::{
        config::BatchParams,
        online::{
            preprocessing::{
                dummy::DummyPreprocessing,
                memory::{InMemoryBasePreprocessing, InMemoryBitPreprocessing},
                BasePreprocessing, BitPreprocessing, RandomPreprocessing, TriplePreprocessing,
            },
            secret_distributions::{RealSecretDistributions, SecretDistributions},
            triple::Triple,
        },
        runtime::sessions::small_session::SmallSession,
        sharing::share::Share,
    },
    experimental::{
        algebra::levels::LevelKsw,
        constants::NEW_HOPE_BOUND,
        gen_bits_odd::{BitGenOdd, RealBitGenOdd},
    },
};

#[async_trait]
impl BGVDkgPreprocessing for DummyPreprocessing {
    async fn fill_from_base_preproc(
        &mut self,
        _poly_size: usize,
        _session: &mut SmallSession<LevelKsw>,
        _preprocessing: &mut dyn BasePreprocessing<LevelKsw>,
    ) -> anyhow::Result<()> {
        unimplemented!("We do not implement filling for DummyPreprocessing")
    }

    fn next_ternary_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<LevelKsw>>> {
        RealSecretDistributions::newhope(amount, 1, self)
    }

    fn next_noise_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<LevelKsw>>> {
        RealSecretDistributions::newhope(amount, NEW_HOPE_BOUND, self)
    }

    fn append_ternary(&mut self, _ternary: Vec<Share<LevelKsw>>) {
        unimplemented!("We do not implement filling for DummyPreprocessing")
    }

    fn append_noise(&mut self, _noise: Vec<Share<LevelKsw>>) {
        unimplemented!("We do not implement filling for DummyPreprocessing")
    }
}

#[async_trait]
pub trait BGVDkgPreprocessing: BasePreprocessing<LevelKsw> {
    fn num_required_triples_randoms(poly_size: usize) -> BatchParams {
        let num_bits = 2 * poly_size + 2 * 2 * poly_size * NEW_HOPE_BOUND;
        let triples = num_bits + poly_size;
        let randoms = num_bits + 2 * poly_size;
        BatchParams { triples, randoms }
    }

    async fn fill_from_base_preproc(
        &mut self,
        poly_size: usize,
        session: &mut SmallSession<LevelKsw>,
        preprocessing: &mut dyn BasePreprocessing<LevelKsw>,
    ) -> anyhow::Result<()>;
    fn next_ternary_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<LevelKsw>>>;
    fn next_noise_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<LevelKsw>>>;
    fn append_ternary(&mut self, ternary: Vec<Share<LevelKsw>>);
    fn append_noise(&mut self, noise: Vec<Share<LevelKsw>>);
}

#[derive(Default)]
pub struct InMemoryBGVDkgPreprocessing {
    in_memory_base: InMemoryBasePreprocessing<LevelKsw>,
    available_ternary: Vec<Share<LevelKsw>>,
    available_noise: Vec<Share<LevelKsw>>,
}

impl TriplePreprocessing<LevelKsw> for InMemoryBGVDkgPreprocessing {
    fn next_triple_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Triple<LevelKsw>>> {
        self.in_memory_base.next_triple_vec(amount)
    }

    fn append_triples(&mut self, triples: Vec<Triple<LevelKsw>>) {
        self.in_memory_base.append_triples(triples)
    }

    fn triples_len(&self) -> usize {
        self.in_memory_base.triples_len()
    }
}

impl RandomPreprocessing<LevelKsw> for InMemoryBGVDkgPreprocessing {
    fn next_random_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<LevelKsw>>> {
        self.in_memory_base.next_random_vec(amount)
    }

    fn append_randoms(&mut self, randoms: Vec<Share<LevelKsw>>) {
        self.in_memory_base.append_randoms(randoms)
    }

    fn randoms_len(&self) -> usize {
        self.in_memory_base.randoms_len()
    }
}

#[async_trait]
impl BGVDkgPreprocessing for InMemoryBGVDkgPreprocessing {
    async fn fill_from_base_preproc(
        &mut self,
        poly_size: usize,
        session: &mut SmallSession<LevelKsw>,
        preprocessing: &mut dyn BasePreprocessing<LevelKsw>,
    ) -> anyhow::Result<()> {
        //NewHope(N,B) takes 2 * N * B bits, and we have:
        // - Newhope(N,1) for the secret key
        // - 2*NewHope(N,B) for the noise
        let num_bits_needed = 2 * poly_size + 2 * 2 * poly_size * NEW_HOPE_BOUND;

        let mut bit_preproc = InMemoryBitPreprocessing::default();
        bit_preproc.append_bits(
            RealBitGenOdd::gen_bits_odd(num_bits_needed, preprocessing, session).await?,
        );

        let ternary_vec = RealSecretDistributions::newhope(poly_size, 1, &mut bit_preproc)?;
        self.available_ternary = ternary_vec;

        let noise_vec =
            RealSecretDistributions::newhope(2 * poly_size, NEW_HOPE_BOUND, &mut bit_preproc)?;
        self.available_noise = noise_vec;

        self.in_memory_base
            .append_triples(preprocessing.next_triple_vec(poly_size)?);

        self.in_memory_base
            .append_randoms(preprocessing.next_random_vec(2 * poly_size)?);

        Ok(())
    }

    fn next_ternary_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<LevelKsw>>> {
        if self.available_ternary.len() >= amount {
            Ok(self.available_ternary.drain(0..amount).collect())
        } else {
            Err(anyhow_error_and_log(format!(
                "Not enough of ternary element to pop {amount}, only have {}",
                self.available_ternary.len()
            )))
        }
    }

    fn next_noise_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<LevelKsw>>> {
        if self.available_noise.len() >= amount {
            Ok(self.available_noise.drain(0..amount).collect())
        } else {
            Err(anyhow_error_and_log(format!(
                "Not enough of ternary element to pop {amount}, only have {}",
                self.available_noise.len()
            )))
        }
    }

    fn append_ternary(&mut self, ternary: Vec<Share<LevelKsw>>) {
        self.available_ternary.extend(ternary);
    }

    fn append_noise(&mut self, noise: Vec<Share<LevelKsw>>) {
        self.available_noise.extend(noise);
    }
}

impl BasePreprocessing<LevelKsw> for InMemoryBGVDkgPreprocessing {}

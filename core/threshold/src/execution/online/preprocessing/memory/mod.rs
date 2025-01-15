use crate::algebra::base_ring::{Z128, Z64};
use crate::algebra::galois_rings::common::ResiduePoly;
use crate::algebra::structure_traits::Ring;
use crate::algebra::structure_traits::{ErrorCorrect, Invert, Solve};
use crate::error::error_handler::anyhow_error_and_log;
use crate::execution::online::preprocessing::memory::bitdec::InMemoryBitDecPreprocessing;
use crate::execution::online::preprocessing::memory::noiseflood::InMemoryNoiseFloodPreprocessing;
use crate::execution::online::preprocessing::BasePreprocessing;
use crate::execution::online::preprocessing::BitPreprocessing;
use crate::execution::online::preprocessing::NoiseFloodPreprocessing;
use crate::execution::online::preprocessing::PreprocessorFactory;
use crate::execution::online::preprocessing::RandomPreprocessing;
use crate::execution::online::preprocessing::TriplePreprocessing;
use crate::execution::online::triple::Triple;
use crate::execution::sharing::share::Share;

use self::dkg::InMemoryDKGPreprocessing;

use super::BitDecPreprocessing;

#[derive(Default)]
struct InMemoryPreprocessorFactory<const EXTENSION_DEGREE: usize>;

impl<const EXTENSION_DEGREE: usize> PreprocessorFactory<EXTENSION_DEGREE>
    for InMemoryPreprocessorFactory<EXTENSION_DEGREE>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
{
    fn create_bit_preprocessing_residue_64(
        &mut self,
    ) -> Box<dyn BitPreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>> {
        Box::<InMemoryBitPreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>>::default()
    }

    fn create_bit_preprocessing_residue_128(
        &mut self,
    ) -> Box<dyn BitPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>> {
        Box::<InMemoryBitPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>>::default()
    }

    fn create_base_preprocessing_residue_64(
        &mut self,
    ) -> Box<dyn BasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>> {
        Box::<InMemoryBasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>>::default()
    }

    fn create_base_preprocessing_residue_128(
        &mut self,
    ) -> Box<dyn BasePreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>> {
        Box::<InMemoryBasePreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>>::default()
    }

    fn create_bit_decryption_preprocessing(
        &mut self,
    ) -> Box<dyn BitDecPreprocessing<EXTENSION_DEGREE>> {
        Box::<InMemoryBitDecPreprocessing<EXTENSION_DEGREE>>::default()
    }

    fn create_noise_flood_preprocessing(
        &mut self,
    ) -> Box<dyn NoiseFloodPreprocessing<EXTENSION_DEGREE>> {
        Box::<InMemoryNoiseFloodPreprocessing<EXTENSION_DEGREE>>::default()
    }

    fn create_dkg_preprocessing_no_sns(
        &mut self,
    ) -> Box<dyn super::DKGPreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>> {
        Box::<InMemoryDKGPreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>>::default()
    }

    fn create_dkg_preprocessing_with_sns(
        &mut self,
    ) -> Box<dyn super::DKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>> {
        Box::<InMemoryDKGPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>>::default()
    }
}

pub fn memory_factory<const EXTENSION_DEGREE: usize>(
) -> Box<dyn PreprocessorFactory<EXTENSION_DEGREE>>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
    ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
{
    Box::<InMemoryPreprocessorFactory<EXTENSION_DEGREE>>::default()
}

#[derive(Default, Clone)]
pub struct InMemoryBitPreprocessing<Z>
where
    Z: Ring,
{
    pub available_bits: Vec<Share<Z>>,
}

impl<Z: Ring> BitPreprocessing<Z> for InMemoryBitPreprocessing<Z> {
    fn append_bits(&mut self, bits: Vec<Share<Z>>) {
        self.available_bits.extend(bits);
    }

    fn next_bit(&mut self) -> anyhow::Result<Share<Z>> {
        self.available_bits
            .pop()
            .ok_or_else(|| anyhow_error_and_log("available_bits is empty".to_string()))
    }

    fn next_bit_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<Z>>> {
        if self.available_bits.len() >= amount {
            Ok(self.available_bits.drain(0..amount).collect())
        } else {
            Err(anyhow_error_and_log(format!(
                "Not enough bits to drain {amount}"
            )))
        }
    }

    fn bits_len(&self) -> usize {
        self.available_bits.len()
    }
}

#[derive(Default, Clone)]
pub struct InMemoryBasePreprocessing<R>
where
    R: Ring,
{
    pub available_triples: Vec<Triple<R>>,
    pub available_randoms: Vec<Share<R>>,
}

impl<Z: Ring> TriplePreprocessing<Z> for InMemoryBasePreprocessing<Z> {
    fn next_triple_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Triple<Z>>> {
        if self.available_triples.len() >= amount {
            Ok(self.available_triples.drain(0..amount).collect())
        } else {
            Err(anyhow_error_and_log(format!(
                "Not enough triples to pop {amount}"
            )))
        }
    }

    fn append_triples(&mut self, triples: Vec<Triple<Z>>) {
        self.available_triples.extend(triples);
    }

    fn triples_len(&self) -> usize {
        self.available_triples.len()
    }
}

impl<Z: Ring> RandomPreprocessing<Z> for InMemoryBasePreprocessing<Z> {
    fn next_random_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<Z>>> {
        if self.available_randoms.len() >= amount {
            Ok(self.available_randoms.drain(0..amount).collect())
        } else {
            Err(anyhow_error_and_log(format!(
                "Not enough randomness to pop {amount}"
            )))
        }
    }

    fn append_randoms(&mut self, randoms: Vec<Share<Z>>) {
        self.available_randoms.extend(randoms);
    }

    fn randoms_len(&self) -> usize {
        self.available_randoms.len()
    }
}

impl<Z: Ring> BasePreprocessing<Z> for InMemoryBasePreprocessing<Z> {}

#[cfg(test)]
mod tests {

    use crate::algebra::base_ring::Z128;
    use crate::algebra::base_ring::Z64;
    use crate::algebra::galois_rings::degree_4::ResiduePolyF4;
    use crate::execution::online::preprocessing::memory::InMemoryBasePreprocessing;
    use crate::execution::online::preprocessing::RandomPreprocessing;
    use crate::execution::online::preprocessing::TriplePreprocessing;
    use crate::execution::online::triple::Triple;
    use crate::execution::runtime::party::Role;
    use crate::execution::sharing::share::Share;
    use itertools::Itertools;
    use paste::paste;
    use std::num::Wrapping;

    macro_rules! test_preprocessing {
        ($z:ty, $u:ty) => {
            paste! {
                // Test what happens when no more triples are preset
                #[test]
                fn [<test_no_more_elements_ $z:lower>]() {
                    let share = Share::new(Role::indexed_by_one(1), ResiduePolyF4::<$z>::from_scalar(Wrapping(1)));
                    let triple = Triple::new(share.clone(), share.clone(), share.clone());
                    const TRIPLE_BATCH_SIZE: usize = 10; // Replace 10 with the desired value

                    let mut preproc = InMemoryBasePreprocessing::<ResiduePolyF4<$z>> {
                        available_triples: (0..TRIPLE_BATCH_SIZE).map(|_i| triple.clone()).collect_vec(),
                        available_randoms: (0..TRIPLE_BATCH_SIZE).map(|_i| share.clone()).collect_vec(),
                    };
                    // Try to use both the method for getting a single triple and a vector
                    let mut triple_res = preproc
                        .next_triple_vec(TRIPLE_BATCH_SIZE - 1)
                        .unwrap();
                    triple_res.push(preproc.next_triple().unwrap());
                    // Similarely for random elements
                    let mut rand_res = preproc
                        .next_random_vec(TRIPLE_BATCH_SIZE - 1)
                        .unwrap();
                    rand_res.push(preproc.next_random().unwrap());
                    // We have now used the entire batch of values and should thus fail
                    assert!(preproc
                        .next_triple()
                        .unwrap_err()
                        .to_string()
                        .contains("Not enough triples to pop 1"));
                    assert!(preproc
                        .next_random()
                        .unwrap_err()
                        .to_string()
                        .contains("Not enough randomness to pop 1"));
                }
            }
        }
    }

    test_preprocessing![Z64, u64];
    test_preprocessing![Z128, u128];
}

mod bitdec;
mod dkg;
mod noiseflood;

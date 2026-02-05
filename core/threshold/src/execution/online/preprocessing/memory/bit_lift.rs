use crate::{
    algebra::{
        base_ring::{Z128, Z64},
        galois_rings::common::ResiduePoly,
        structure_traits::Ring,
    },
    execution::{
        online::{
            preprocessing::{
                memory::{InMemoryBasePreprocessing, InMemoryBitPreprocessing},
                BasePreprocessing, BitPreprocessing, RandomPreprocessing, TriplePreprocessing,
            },
            triple::Triple,
        },
        sharing::share::Share,
    },
};

#[derive(Default, Clone)]
pub struct InMemoryBitLiftPreprocessing<const EXTENSION_DEGREE: usize> {
    bit_preproc: InMemoryBitPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>,
    base_preproc_z64: InMemoryBasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>,
}

impl<const EXTENSION_DEGREE: usize> TriplePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>
    for InMemoryBitLiftPreprocessing<EXTENSION_DEGREE>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
{
    fn next_triple_vec(
        &mut self,
        amount: usize,
    ) -> anyhow::Result<Vec<Triple<ResiduePoly<Z64, EXTENSION_DEGREE>>>> {
        self.base_preproc_z64.next_triple_vec(amount)
    }

    fn append_triples(&mut self, triples: Vec<Triple<ResiduePoly<Z64, EXTENSION_DEGREE>>>) {
        self.base_preproc_z64.append_triples(triples);
    }

    fn triples_len(&self) -> usize {
        self.base_preproc_z64.triples_len()
    }
}

impl<const EXTENSION_DEGREE: usize> RandomPreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>
    for InMemoryBitLiftPreprocessing<EXTENSION_DEGREE>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
{
    fn next_random_vec(
        &mut self,
        amount: usize,
    ) -> anyhow::Result<Vec<Share<ResiduePoly<Z64, EXTENSION_DEGREE>>>> {
        self.base_preproc_z64.next_random_vec(amount)
    }

    fn append_randoms(&mut self, randoms: Vec<Share<ResiduePoly<Z64, EXTENSION_DEGREE>>>) {
        self.base_preproc_z64.append_randoms(randoms);
    }

    fn randoms_len(&self) -> usize {
        self.base_preproc_z64.randoms_len()
    }
}

impl<const EXTENSION_DEGREE: usize> BasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>
    for InMemoryBitLiftPreprocessing<EXTENSION_DEGREE>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: Ring,
{
}

impl<const EXTENSION_DEGREE: usize> BitPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>
    for InMemoryBitLiftPreprocessing<EXTENSION_DEGREE>
where
    ResiduePoly<Z128, EXTENSION_DEGREE>: Ring,
{
    fn append_bits(&mut self, bits: Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>) {
        self.bit_preproc.append_bits(bits);
    }

    fn next_bit(&mut self) -> anyhow::Result<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>> {
        self.bit_preproc.next_bit()
    }

    fn next_bit_vec(
        &mut self,
        amount: usize,
    ) -> anyhow::Result<Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>> {
        self.bit_preproc.next_bit_vec(amount)
    }

    fn bits_len(&self) -> usize {
        self.bit_preproc.bits_len()
    }
}

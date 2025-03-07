use super::RedisPreprocessing;
use super::{BasePreprocessing, TriplePreprocessing};
use crate::algebra::base_ring::Z64;
use crate::algebra::galois_rings::common::ResiduePoly;
use crate::algebra::structure_traits::{ErrorCorrect, Invert, Solve};
use crate::execution::online::gen_bits::BitGenEven;
use crate::execution::online::gen_bits::RealBitGenEven;
use crate::execution::online::preprocessing::BitPreprocessing;
use crate::execution::online::preprocessing::{BitDecPreprocessing, InMemoryBitDecPreprocessing};
use crate::execution::runtime::session::BaseSession;
use async_trait::async_trait;

#[async_trait]
impl<const EXTENSION_DEGREE: usize> BitDecPreprocessing<EXTENSION_DEGREE>
    for RedisPreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>
where
    ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Invert + Solve,
{
    ///Creates enough material (bits and triples) to decrypt **num_ctxt** ciphertexts,
    ///assuming **preprocessing** is filled with enough randomness and triples
    async fn fill_from_base_preproc(
        &mut self,
        preprocessing: &mut dyn BasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>,
        session: &mut BaseSession,
        num_ctxts: usize,
    ) -> anyhow::Result<()> {
        //Need 64 bits per ctxt
        let bit_vec = RealBitGenEven::gen_bits_even(
            self.num_required_bits(num_ctxts),
            preprocessing,
            session,
        )
        .await?;
        self.append_bits(bit_vec);

        let triple_vec = preprocessing.next_triple_vec(self.num_required_triples(num_ctxts))?;

        self.append_triples(triple_vec);

        Ok(())
    }

    fn cast_to_in_memory_impl(
        &mut self,
        num_ctxts: usize,
    ) -> anyhow::Result<InMemoryBitDecPreprocessing<EXTENSION_DEGREE>> {
        // Fetch correlated randomness from redis to memory
        let bits = self.next_bit_vec(self.num_required_bits(num_ctxts))?;
        let triples = self.next_triple_vec(self.num_required_bits(num_ctxts))?;

        Ok(InMemoryBitDecPreprocessing::<EXTENSION_DEGREE> {
            available_triples: triples,
            available_bits: bits,
        })
    }
}

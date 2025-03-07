use crate::algebra::base_ring::Z64;
use crate::algebra::structure_traits::{ErrorCorrect, Invert, Solve};
use crate::{
    algebra::galois_rings::common::ResiduePoly, error::error_handler::anyhow_error_and_log,
    execution::sharing::share::Share,
};

use super::{BasePreprocessing, TriplePreprocessing};
use crate::execution::online::gen_bits::BitGenEven;
use crate::execution::online::gen_bits::RealBitGenEven;
use crate::execution::online::preprocessing::BitPreprocessing;
use crate::execution::online::preprocessing::{BitDecPreprocessing, InMemoryBitDecPreprocessing};
use crate::execution::online::triple::Triple;
use crate::execution::runtime::session::BaseSession;
use async_trait::async_trait;

impl<const EXTENSION_DEGREE: usize> TriplePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>
    for InMemoryBitDecPreprocessing<EXTENSION_DEGREE>
{
    fn next_triple_vec(
        &mut self,
        amount: usize,
    ) -> anyhow::Result<Vec<Triple<ResiduePoly<Z64, EXTENSION_DEGREE>>>> {
        //Code is duplicate of BasePreprocessing
        if self.available_triples.len() >= amount {
            Ok(self.available_triples.drain(0..amount).collect())
        } else {
            Err(anyhow_error_and_log(format!(
                "Not enough triples to pop {amount}, only have {}",
                self.available_triples.len()
            )))
        }
    }

    fn append_triples(&mut self, triples: Vec<Triple<ResiduePoly<Z64, EXTENSION_DEGREE>>>) {
        self.available_triples.extend(triples);
    }

    fn triples_len(&self) -> usize {
        self.available_triples.len()
    }
}

impl<const EXTENSION_DEGREE: usize> BitPreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>
    for InMemoryBitDecPreprocessing<EXTENSION_DEGREE>
{
    fn append_bits(&mut self, bits: Vec<Share<ResiduePoly<Z64, EXTENSION_DEGREE>>>) {
        self.available_bits.extend(bits);
    }

    fn next_bit(&mut self) -> anyhow::Result<Share<ResiduePoly<Z64, EXTENSION_DEGREE>>> {
        self.available_bits
            .pop()
            .ok_or_else(|| anyhow_error_and_log("available_bits is empty".to_string()))
    }

    fn next_bit_vec(
        &mut self,
        amount: usize,
    ) -> anyhow::Result<Vec<Share<ResiduePoly<Z64, EXTENSION_DEGREE>>>> {
        if self.available_bits.len() >= amount {
            let mut res = Vec::with_capacity(amount);
            for _ in 0..amount {
                res.push(self.next_bit()?);
            }
            Ok(res)
        } else {
            Err(anyhow_error_and_log(format!(
                "Not enough bits to pop {amount}"
            )))
        }
    }

    fn bits_len(&self) -> usize {
        self.available_bits.len()
    }
}

#[async_trait]
impl<const EXTENSION_DEGREE: usize> BitDecPreprocessing<EXTENSION_DEGREE>
    for InMemoryBitDecPreprocessing<EXTENSION_DEGREE>
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

    fn cast_to_in_memory_impl(&mut self, num_ctxts: usize) -> anyhow::Result<Self> {
        Ok(Self {
            available_triples: self.next_triple_vec(self.num_required_triples(num_ctxts))?,
            available_bits: self.next_bit_vec(self.num_required_bits(num_ctxts))?,
        })
    }
}

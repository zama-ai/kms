use crate::{
    algebra::residue_poly::ResiduePoly64, error::error_handler::anyhow_error_and_log,
    execution::sharing::share::Share,
};

use super::{BasePreprocessing, TriplePreprocessing};
use crate::execution::online::gen_bits::BitGenEven;
use crate::execution::online::gen_bits::RealBitGenEven;
use crate::execution::online::preprocessing::BitDecPreprocessing;
use crate::execution::online::preprocessing::BitPreprocessing;
use crate::execution::online::triple::Triple;
use crate::execution::runtime::session::BaseSession;
use async_trait::async_trait;

#[derive(Default)]
pub struct InMemoryBitDecPreprocessing {
    available_triples: Vec<Triple<ResiduePoly64>>,
    available_bits: Vec<Share<ResiduePoly64>>,
}

impl Drop for InMemoryBitDecPreprocessing {
    fn drop(&mut self) {
        debug_assert_eq!(self.available_bits.len(), 0);
        debug_assert_eq!(self.available_triples.len(), 0);
    }
}

impl TriplePreprocessing<ResiduePoly64> for InMemoryBitDecPreprocessing {
    fn next_triple_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Triple<ResiduePoly64>>> {
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

    fn append_triples(&mut self, triples: Vec<Triple<ResiduePoly64>>) {
        self.available_triples.extend(triples);
    }

    fn triples_len(&self) -> usize {
        self.available_triples.len()
    }
}

impl BitPreprocessing<ResiduePoly64> for InMemoryBitDecPreprocessing {
    fn append_bits(&mut self, bits: Vec<Share<ResiduePoly64>>) {
        self.available_bits.extend(bits);
    }

    fn next_bit(&mut self) -> anyhow::Result<Share<ResiduePoly64>> {
        self.available_bits
            .pop()
            .ok_or_else(|| anyhow_error_and_log("available_bits is empty".to_string()))
    }

    fn next_bit_vec(&mut self, amount: usize) -> anyhow::Result<Vec<Share<ResiduePoly64>>> {
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
}

#[async_trait]
impl BitDecPreprocessing for InMemoryBitDecPreprocessing {
    ///Creates enough material (bits and triples) to decrypt **num_ctxt** ciphertexts,
    ///assuming **preprocessing** is filled with enough randomness and triples
    async fn fill_from_base_preproc(
        &mut self,
        preprocessing: &mut dyn BasePreprocessing<ResiduePoly64>,
        session: &mut BaseSession,
        num_ctxts: usize,
    ) -> anyhow::Result<()> {
        //Need 64 bits per ctxt
        let bit_vec = RealBitGenEven::gen_bits_even(num_ctxts * 64, preprocessing, session).await?;
        self.append_bits(bit_vec);

        //Need 1217 triples per ctxt
        let triple_vec = preprocessing.next_triple_vec(num_ctxts * 1217)?;
        self.append_triples(triple_vec);

        Ok(())
    }
}

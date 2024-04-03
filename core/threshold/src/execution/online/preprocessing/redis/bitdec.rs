use crate::algebra::residue_poly::ResiduePoly64;

use super::RedisPreprocessing;
use super::{BasePreprocessing, TriplePreprocessing};
use crate::execution::online::gen_bits::BitGenEven;
use crate::execution::online::gen_bits::RealBitGenEven;
use crate::execution::online::preprocessing::BitDecPreprocessing;
use crate::execution::online::preprocessing::BitPreprocessing;
use crate::execution::runtime::session::BaseSession;
use async_trait::async_trait;

#[async_trait]
impl BitDecPreprocessing for RedisPreprocessing<ResiduePoly64> {
    ///Creates enough material (bits and triples) to decrypt **num_ctxt** ciphertexts,
    ///assuming **preprocessing** is filled with enough randomness and triples
    async fn fill_from_base_preproc(
        &mut self,
        preprocessing: &mut dyn BasePreprocessing<ResiduePoly64>,
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
}

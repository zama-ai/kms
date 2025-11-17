use crate::{
    algebra::structure_traits::{ErrorCorrect, Invert, Solve},
    execution::{
        online::{gen_bits::BitGenEven, preprocessing::BasePreprocessing},
        runtime::sessions::base_session::BaseSessionHandles,
        sharing::share::Share,
    },
};

pub struct DummyBitGenEven;

#[tonic::async_trait]
impl BitGenEven for DummyBitGenEven {
    async fn gen_bits_even<
        Z: Solve + Invert + ErrorCorrect,
        Ses: BaseSessionHandles,
        P: BasePreprocessing<Z> + Send + ?Sized,
    >(
        amount: usize,
        preproc: &mut P,
        _session: &mut Ses,
    ) -> anyhow::Result<Vec<Share<Z>>> {
        // we need to correctly drain the preproc material
        let a = preproc.next_random_vec(amount)?;
        let _triples = preproc.next_triple_vec(amount)?;

        // then just return some dummy value, in this case we just return a
        Ok(a)
    }
}

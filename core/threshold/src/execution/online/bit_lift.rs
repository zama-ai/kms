use iterator::Itertools;
use itertools::Itertools;
use tonic::async_trait;

use crate::{
    algebra::{
        base_ring::{Z128, Z64},
        galois_rings::common::{pack_residue_poly, Monomials, ResiduePoly},
        structure_traits::{Ring, Zero},
    },
    execution::{
        online::preprocessing::BitPreprocessing,
        runtime::sessions::base_session::BaseSessionHandles, sharing::share::Share,
    },
};

#[async_trait]
pub trait BitLift {
    /// Lifts a vector of bits shared over a galois extension of Z64 into a vector of bits shared over a galois estension of Z128
    /// # Arguments
    /// * `secret_bit_vector` - Vector of bits shared over a galois extension of Z64
    /// * `preproc` - Randoms bits over the extension of Z128
    /// * `session` - Session handles to use for the execution
    /// # Returns
    /// Vector of bits shared over a galois extension of Z128
    ///
    /// __NOTE: If the input bits are not actually bits (i.e., not in {0,1}), this is very much wrong and insecure !__
    async fn execute<
        const EXTENSION_DEGREE: usize,
        Ses: BaseSessionHandles,
        P: BitPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send + ?Sized,
    >(
        secret_bit_vector: Vec<Share<ResiduePoly<Z64, EXTENSION_DEGREE>>>,
        preproc: &mut P,
        session: &mut Ses,
    ) -> anyhow::Result<Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: Ring + Monomials,
        ResiduePoly<Z128, EXTENSION_DEGREE>: Ring;
}

pub struct SecureBitLift;

#[async_trait]
impl BitLift for SecureBitLift {
    async fn execute<
        const EXTENSION_DEGREE: usize,
        Ses: BaseSessionHandles,
        P: BitPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>> + Send + ?Sized,
    >(
        secret_bit_vector: Vec<Share<ResiduePoly<Z64, EXTENSION_DEGREE>>>,
        preproc: &mut P,
        session: &mut Ses,
    ) -> anyhow::Result<Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: Ring + Monomials,
        ResiduePoly<Z128, EXTENSION_DEGREE>: Ring,
    {
        let amount = secret_bit_vector.len();
        let mut lifted_bits = Vec::with_capacity(secret_bit_vector.len());

        let random_bits_z128 = preproc.next_bit_vec(amount)?;

        // Copy of the randoms bits, except modswitched to Z64 (reminiscent of "dabits")
        // note that they are still the same bits as in Z128
        let random_bits_z64 = random_bits_z128
            .iter()
            .map(|b| Share::new(b.owner(), b.value().to_residuepoly64()))
            .collect::<Vec<Share<ResiduePoly<Z64, EXTENSION_DEGREE>>>>();

        // Pack bits and inputs into every coef of the extension ring
        let packed_secret_bits = pack_residue_poly(
            &(secret_bit_vector
                .into_iter()
                .map(|s| s.value())
                .collect::<Vec<_>>()),
        );

        let packed_random_bits_z64 = pack_residue_poly(
            &(random_bits_z64
                .into_iter()
                .map(|s| s.value())
                .collect::<Vec<_>>()),
        );

        Ok(lifted_bits)
    }
}

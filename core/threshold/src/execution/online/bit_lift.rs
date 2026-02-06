use std::sync::Arc;

use itertools::Itertools;
use tonic::async_trait;

use crate::{
    algebra::{
        base_ring::{Z128, Z64},
        galois_rings::common::{pack_residue_poly, Monomials, ResiduePoly},
        structure_traits::{ErrorCorrect, FromU128},
    },
    execution::{
        online::{
            bit_manipulation::{BatchedBits, Bits},
            preprocessing::{BasePreprocessing, BitPreprocessing},
            triple::open_list,
        },
        runtime::sessions::base_session::BaseSessionHandles,
        sharing::share::Share,
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
        P: BitPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>
            + BasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>
            + Send
            + ?Sized,
    >(
        secret_bit_vector: Vec<Share<ResiduePoly<Z64, EXTENSION_DEGREE>>>,
        preproc: &mut P,
        session: &mut Ses,
    ) -> anyhow::Result<Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Monomials,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect;
}

pub struct SecureBitLift;

#[async_trait]
impl BitLift for SecureBitLift {
    async fn execute<
        const EXTENSION_DEGREE: usize,
        Ses: BaseSessionHandles,
        P: BitPreprocessing<ResiduePoly<Z128, EXTENSION_DEGREE>>
            + BasePreprocessing<ResiduePoly<Z64, EXTENSION_DEGREE>>
            + Send
            + ?Sized,
    >(
        secret_bit_vector: Vec<Share<ResiduePoly<Z64, EXTENSION_DEGREE>>>,
        preproc: &mut P,
        session: &mut Ses,
    ) -> anyhow::Result<Vec<Share<ResiduePoly<Z128, EXTENSION_DEGREE>>>>
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: ErrorCorrect + Monomials,
        ResiduePoly<Z128, EXTENSION_DEGREE>: ErrorCorrect,
    {
        let amount = secret_bit_vector.len();

        let random_bits_z128 = preproc.next_bit_vec(amount)?;

        // Copy of the randoms bits, except modswitched to Z64 (reminiscent of "dabits")
        // note that they are still the same bits as in Z128
        let random_bits_z64 = random_bits_z128
            .iter()
            .map(|b| Share::new(b.owner(), b.value().to_residuepoly64()))
            .collect::<Vec<Share<ResiduePoly<Z64, EXTENSION_DEGREE>>>>();

        // Pack bits and inputs into every coef of the extension ring
        let packed_secret_bits = Arc::new(
            pack_residue_poly(
                &(secret_bit_vector
                    .into_iter()
                    .map(|s| s.value())
                    .collect::<Vec<_>>()),
            )
            .into_iter()
            .map(|x| Share::new(session.my_role(), x))
            .collect_vec(),
        );

        let packed_random_bits_z64 = Arc::new(
            pack_residue_poly(
                &(random_bits_z64
                    .into_iter()
                    .map(|s| s.value())
                    .collect::<Vec<_>>()),
            )
            .into_iter()
            .map(|x| Share::new(session.my_role(), x))
            .collect_vec(),
        );

        // NOTE: This won't work because we need to pack the Z::TWO over all the extension coeffs
        // due to packing above
        // i.e. have to reimplement XOR here for the packed case
        let masked_packed_secret_bits = Bits::xor_list_secret_secret(
            Arc::clone(&packed_secret_bits),
            Arc::clone(&packed_random_bits_z64),
            preproc,
            session,
        )
        .await?;

        // Open the masked bits
        let opened_masked_bits_z64 = open_list(&masked_packed_secret_bits, session).await?;

        // Lift all the results to Z128 and transform to shares
        let opened_masked_packed_bits_z128 = opened_masked_bits_z64
            .into_iter()
            .map(
                |s| ResiduePoly::<Z128, EXTENSION_DEGREE> {
                    coefs: s.coefs.map(|c| Z128::from_u128(c.0 as u128)),
                }, // Lift to Z128
            )
            .collect::<Vec<ResiduePoly<Z128, EXTENSION_DEGREE>>>();

        // Unpack
        let opened_masked_bits_z128 = opened_masked_packed_bits_z128
            .into_iter()
            .flat_map(|packed_poly| packed_poly.coefs.map(ResiduePoly::from_scalar))
            .collect::<Vec<ResiduePoly<Z128, EXTENSION_DEGREE>>>();

        // Remove the mask by xoring, xor secret clear is only available for vec of vec
        // so wrap and unwrap to/from vec of vec
        let unmasked_lifted_bits =
            BatchedBits::xor_list_secret_clear(&[random_bits_z128], &[opened_masked_bits_z128])?
                .remove(0);

        Ok(unmasked_lifted_bits)
    }
}

#[cfg(test)]
mod tests {}

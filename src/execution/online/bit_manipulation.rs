use std::marker::PhantomData;

use crate::execution::online::gen_bits::Solve;
use rand::RngCore;

use crate::algebra::residue_poly::ResiduePoly;
use crate::algebra::structure_traits::{BaseRing, BitExtract, ZConsts};
use crate::execution::sharing::shamir::ShamirRing;
use crate::{
    algebra::structure_traits::Ring, error::error_handler::anyhow_error_and_log,
    execution::runtime::session::BaseSessionHandles,
};

use super::gen_bits::RealBitGenEven;
use super::{preprocessing::Preprocessing, triple::mult_list};
use crate::execution::online::gen_bits::BitGenEven;
use crate::execution::online::triple::open;
use crate::execution::sharing::share::Share;

// Dummy struct used to access the bit manipulation methods
pub struct Bits<Z> {
    _phantom: PhantomData<Z>,
}

type SecretVec<Z> = Vec<Share<Z>>;
type ClearVec<Z> = Vec<Z>;

fn shift_right<Z>(x: &SecretVec<Z>, amount: usize) -> SecretVec<Z>
where
    Z: ZConsts + Ring,
{
    let tail = x.len() - amount;
    let owner = x[0].owner();

    let mut res = Vec::with_capacity(x.len());
    for _i in 0..amount {
        res.push(Share::<Z>::new(owner, Z::ZERO));
    }
    for item in x.iter().take(tail) {
        res.push(*item)
    }
    res
}

impl<Z> Bits<Z>
where
    Z: ShamirRing + ZConsts + Send + Sync,
{
    pub async fn xor_list_secret_clear(
        lhs: &SecretVec<Z>,
        rhs: &ClearVec<Z>,
    ) -> anyhow::Result<SecretVec<Z>> {
        if lhs.len() != rhs.len() {
            anyhow_error_and_log(format!(
                "Inputs to XOR function are of different lenght. LHS is {:?} and RHS is {:?}",
                lhs.len(),
                rhs.len()
            ));
        }
        let mut res = Vec::with_capacity(lhs.len());
        let prods: Vec<_> = lhs.iter().zip(rhs).map(|(x, y)| x * *y).collect();
        for ((cur_left, cur_right), cur_prod) in lhs.iter().zip(rhs).zip(&prods) {
            res.push((cur_left + cur_right) - (cur_prod * ZConsts::TWO));
        }

        Ok(res)
    }

    pub async fn xor_list_secret_secret<
        Rnd: RngCore + Send + Sync,
        Ses: BaseSessionHandles<Rnd>,
        P: Preprocessing<Z>,
    >(
        lhs: &SecretVec<Z>,
        rhs: &SecretVec<Z>,
        preproc: &mut P,
        session: &mut Ses,
    ) -> anyhow::Result<SecretVec<Z>> {
        if lhs.len() != rhs.len() {
            anyhow_error_and_log(format!(
                "Inputs to XOR function are of different lenght. LHS is {:?} and RHS is {:?}",
                lhs.len(),
                rhs.len()
            ));
        }
        let mut res = Vec::with_capacity(lhs.len());
        let triples = preproc.next_triple_vec(lhs.len())?;
        let prods = mult_list(lhs, rhs, triples, session).await?;
        for ((cur_left, cur_right), cur_prod) in lhs.iter().zip(rhs).zip(&prods) {
            res.push((cur_left + cur_right) - (cur_prod * ZConsts::TWO));
        }

        Ok(res)
    }

    pub async fn and_list_secret_secret<
        Rnd: RngCore + Send + Sync,
        Ses: BaseSessionHandles<Rnd>,
        P: Preprocessing<Z>,
    >(
        lhs: &SecretVec<Z>,
        rhs: &SecretVec<Z>,
        preproc: &mut P,
        session: &mut Ses,
    ) -> anyhow::Result<SecretVec<Z>> {
        if lhs.len() != rhs.len() {
            anyhow_error_and_log(format!(
                "Inputs to XOR function are of different lenght. LHS is {:?} and RHS is {:?}",
                lhs.len(),
                rhs.len()
            ));
        }
        let triples = preproc.next_triple_vec(lhs.len())?;
        let prods = mult_list(lhs, rhs, triples, session).await?;
        Ok(prods)
    }

    pub async fn and_list_secret_clear(
        lhs: &SecretVec<Z>,
        rhs: &ClearVec<Z>,
    ) -> anyhow::Result<SecretVec<Z>> {
        if lhs.len() != rhs.len() {
            anyhow_error_and_log(format!(
                "Inputs to XOR function are of different lenght. LHS is {:?} and RHS is {:?}",
                lhs.len(),
                rhs.len()
            ));
        }
        let prods: Vec<_> = lhs.iter().zip(rhs).map(|(x, y)| x * *y).collect();
        Ok(prods)
    }

    pub async fn binary_adder_secret_clear<
        Rnd: RngCore + Send + Sync,
        Ses: BaseSessionHandles<Rnd>,
        P: Preprocessing<Z>,
    >(
        session: &mut Ses,
        lhs: &SecretVec<Z>,
        rhs: &ClearVec<Z>,
        prep: &mut P,
    ) -> anyhow::Result<SecretVec<Z>>
    where
        Z: Ring,
    {
        #![allow(clippy::many_single_char_names)]
        if lhs.len() != rhs.len() {
            anyhow_error_and_log(format!(
                "Inputs to the binary adder are of different lenght. LHS is {:?} and RHS is {:?}",
                lhs.len(),
                rhs.len()
            ));
        }

        // g is part of the generator set, p propagator set
        // A few helpful diagrams:
        // https://www.chessprogramming.org/Kogge-Stone_Algorithm
        // https://inst.eecs.berkeley.edu/~eecs151/sp19/files/lec20-adders.pdf
        //
        // More technical details in here:
        // https://dspace.library.uvic.ca/bitstream/handle/1828/6986/Alghamdi_Abdulmajeed_MEng_2015.pdf

        // The inputs a, b to the P,G computing gate
        // P = P_a and P_b
        // G = G_b xor (G_a and P_b)

        // P, G can be computed in a tree fashion, performing ops on chunks of len 2^i
        // Note the first level is computed as P0 = x ^ y, G0 = x & y;

        let log_r = (Z::CHAR_LOG2 as f64).log2() as usize; // we know that Z::CHAR = 64/128

        let p_store = Bits::xor_list_secret_clear(lhs, rhs).await?;
        let mut g = Bits::and_list_secret_clear(lhs, rhs).await?;
        let mut p = p_store.clone();

        assert_eq!(lhs.len(), Z::CHAR_LOG2);

        for i in 0..log_r {
            // rotate right operation by amount:
            // [ a[0],...,a[R-amount], ...,a[R - 1]
            // [ 0,...,0, a[0], ...,a[R-amount]]
            // computes p << (1<<i)
            let p1 = shift_right(&p, 1 << i);
            // computes g << (1<<i)
            let g1 = shift_right(&g, 1 << i);

            let p_and_g = Bits::and_list_secret_secret(&p, &g1, prep, session).await?;
            // g = g xor p1 and g1
            g = Bits::xor_list_secret_secret(&g, &p_and_g, prep, session).await?;

            // p = p * p1
            p = Bits::and_list_secret_secret(&p, &p1, prep, session).await?;
        }
        // c = g << 1
        let c = shift_right(&g, 1);

        // c xor p_store
        Bits::xor_list_secret_secret(&c, &p_store, prep, session).await
    }

    pub async fn bit_sum(input: &SecretVec<Z>) -> anyhow::Result<Share<Z>>
    where
        Z: std::ops::Shl<usize, Output = Z>,
    {
        if input.is_empty() {
            return Err(anyhow_error_and_log(
                "Cannot do bit summing on an empty list".to_string(),
            ));
        }
        let mut res = Z::ZERO;
        for (i, cur_bit) in input.iter().enumerate() {
            // Compute 2^i
            res += cur_bit.value() << i;
            if cur_bit.owner() != input[0].owner() {
                return Err(anyhow_error_and_log(
                    "Mismatched owners in the values to compute bit sum of".to_string(),
                ));
            }
        }

        Ok(Share::new(input[0].owner(), res))
    }
}

pub async fn bit_dec<
    Z,
    P: Preprocessing<ResiduePoly<Z>>,
    Rnd: RngCore + Send + Sync,
    Ses: BaseSessionHandles<Rnd>,
>(
    session: &mut Ses,
    prep: &mut P,
    input: Share<ResiduePoly<Z>>,
) -> anyhow::Result<SecretVec<ResiduePoly<Z>>>
where
    Z: BaseRing + std::fmt::Display,
    ResiduePoly<Z>: Solve,
    Z: BitExtract,
    P: Send,
{
    let random_bits =
        RealBitGenEven::gen_bits_even::<ResiduePoly<Z>, Rnd, Ses, P>(Z::CHAR_LOG2, prep, session)
            .await?;
    let bitsum = Bits::<ResiduePoly<Z>>::bit_sum(&random_bits).await?;

    let masked = input - bitsum;
    // value is safe to open now

    // opening the mask
    let opened = open(masked, session).await?;

    // TODO(Dragos) We don't need to convert the bit to a ResiduePoly, for efficiency reasons we can keep it a Z64/Z128
    let scalar = opened.to_scalar()?;
    let scalar_bits: Vec<u8> = (0..Z::CHAR_LOG2)
        .map(|bit_idx| scalar.extract_bit(bit_idx))
        .collect();
    let residue_bits: Vec<ResiduePoly<Z>> = scalar_bits
        .iter()
        .map(|bit| ResiduePoly::<Z>::from_scalar(Z::from_u128(*bit as u128)))
        .collect();

    let add_res = Bits::<ResiduePoly<Z>>::binary_adder_secret_clear(
        session,
        &random_bits,
        &residue_bits,
        prep,
    )
    .await?;
    Ok(add_res)
}

#[cfg(test)]
mod tests {
    use std::num::Wrapping;

    use crate::algebra::structure_traits::Ring;
    use crate::execution::sharing::shamir::ShamirSharing;
    use itertools::Itertools;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use rstest::rstest;

    use crate::algebra::base_ring::Z64;
    use crate::algebra::residue_poly::ResiduePoly;
    use crate::execution::online::bit_manipulation::bit_dec;
    use crate::execution::online::bit_manipulation::Bits;
    use crate::execution::online::preprocessing::DummyPreprocessing;
    use crate::execution::online::triple::open_list;
    use crate::execution::runtime::session::ParameterHandles;
    use crate::execution::runtime::session::SmallSession;
    use crate::execution::sharing::share::Share;
    use crate::tests::helper::tests_and_benches::execute_protocol_small;

    /// Helper method to get a sharing of a simple u64 value
    fn get_my_share(val: u64, session: &SmallSession<ResiduePoly<Z64>>) -> Share<ResiduePoly<Z64>> {
        let mut rng = ChaCha20Rng::seed_from_u64(val);
        let secret = ResiduePoly::<Z64>::from_scalar(Wrapping(val));
        let shares = ShamirSharing::share(
            &mut rng,
            secret,
            session.amount_of_parties(),
            session.threshold() as usize,
        )
        .unwrap()
        .shares;
        shares[session.my_role().unwrap().zero_based()]
    }

    #[test]
    fn sunshine_xor() {
        let parties = 4;
        let threshold = 1;
        let plain_lhs: [u64; 5] = [0_u64, 1, 1, 0, 0];
        let plain_rhs: [u64; 5] = [1_u64, 0, 1, 0, 1];
        // Compute reference value, as the xor
        let plain_ref = (0..plain_lhs.len())
            .map(|i| ResiduePoly::from_scalar(Wrapping(plain_lhs[i] ^ plain_rhs[i])))
            .collect_vec();

        let mut task = |mut session: SmallSession<ResiduePoly<Z64>>| async move {
            let lhs = plain_lhs
                .iter()
                .map(|cur_val| get_my_share(*cur_val, &session))
                .collect_vec();
            let rhs = plain_rhs
                .iter()
                .map(|cur_val| get_my_share(*cur_val, &session))
                .collect_vec();
            let mut preprocessing = DummyPreprocessing::<
                ResiduePoly<Z64>,
                ChaCha20Rng,
                SmallSession<ResiduePoly<Z64>>,
            >::new(42, session.clone());
            let bits = Bits::<ResiduePoly<Z64>>::xor_list_secret_secret(
                &lhs,
                &rhs,
                &mut preprocessing,
                &mut session,
            )
            .await
            .unwrap();
            open_list(&bits, &session).await.unwrap()
        };

        let results = execute_protocol_small(parties, threshold as u8, &mut task);

        for cur_res in results {
            // We shared values of 0 and 1, so the XOR should be 1
            for (i, cur_ref) in plain_ref.iter().enumerate() {
                assert_eq!(*cur_ref, cur_res[i]);
            }
        }
    }

    #[test]
    fn sunshine_bitsum() {
        let parties = 4;
        let threshold = 1;

        let plain_input: [u64; 5] = [0_u64, 1, 1, 0, 1];
        // Observe that 10110 = 22
        let ref_val = 22;

        let mut task = |session: SmallSession<ResiduePoly<Z64>>| async move {
            let input = plain_input
                .iter()
                .map(|cur_val| get_my_share(*cur_val, &session))
                .collect_vec();
            let bits = Bits::<ResiduePoly<Z64>>::bit_sum(&input).await.unwrap();
            open_list(&[bits], &session).await.unwrap()[0]
        };

        let results = execute_protocol_small(parties, threshold as u8, &mut task);

        for cur_res in results {
            assert_eq!(ResiduePoly::<Z64>::from_scalar(Wrapping(ref_val)), cur_res);
        }
    }

    #[rstest]
    #[case(12491094489948035603, 5955649583761516015)]
    #[case(1, 9223372036854775808)]
    fn bit_adder(#[case] a: u64, #[case] b: u64) {
        let parties = 4;
        let threshold = 1;

        let ref_val = Wrapping(a) + Wrapping(b);

        let mut task = |mut session: SmallSession<ResiduePoly<Z64>>| async move {
            let mut prep = DummyPreprocessing::<
                ResiduePoly<Z64>,
                ChaCha20Rng,
                SmallSession<ResiduePoly<Z64>>,
            >::new(42, session.clone());

            let input_a = (0..Z64::CHAR_LOG2)
                .map(|bit_idx| get_my_share((a >> bit_idx) & 1, &session))
                .collect_vec();

            let input_b = (0..Z64::CHAR_LOG2)
                .map(|bit_idx| ResiduePoly::from_scalar(Wrapping((b >> bit_idx) & 1)))
                .collect_vec();

            let bits = Bits::<ResiduePoly<Z64>>::binary_adder_secret_clear(
                &mut session,
                &input_a,
                &input_b,
                &mut prep,
            )
            .await
            .unwrap();

            let bit_sum = Bits::<ResiduePoly<Z64>>::bit_sum(&bits).await.unwrap();
            open_list(&[bit_sum], &session).await.unwrap()[0]
        };

        let results = execute_protocol_small(parties, threshold as u8, &mut task);
        for cur_res in results {
            assert_eq!(ResiduePoly::<Z64>::from_scalar(ref_val), cur_res);
        }
    }

    #[rstest]
    #[case(18446744073709551615)]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    #[case(4)]
    fn sunshine_bitdec(#[case] a: u64) {
        let parties = 4;
        let threshold = 1;

        let ref_val: Vec<_> = (0..64).map(|bit_idx| (a >> bit_idx) & 1).collect();

        let mut task = |mut session: SmallSession<ResiduePoly<Z64>>| async move {
            let mut prep = DummyPreprocessing::<
                ResiduePoly<Z64>,
                ChaCha20Rng,
                SmallSession<ResiduePoly<Z64>>,
            >::new(42, session.clone());

            let input_a = get_my_share(a, &session);
            let bits = bit_dec::<Z64, _, _, _>(&mut session, &mut prep, input_a)
                .await
                .unwrap();
            println!(
                "bit dec required {:?} random sharings and {:?} random triples",
                prep.rnd_ctr, prep.trip_ctr
            );
            open_list(&bits, &session).await.unwrap()
        };

        let results = &execute_protocol_small(parties, threshold as u8, &mut task)[0];
        assert_eq!(results.len(), ref_val.len());
        for i in 0..results.len() {
            assert_eq!(
                results[i],
                ResiduePoly::<Z64>::from_scalar(Wrapping(ref_val[i]))
            );
        }
    }
}

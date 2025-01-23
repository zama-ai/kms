use rand::{CryptoRng, Rng};
use std::marker::PhantomData;
use tracing::instrument;

use crate::algebra::galois_rings::common::ResiduePoly;
use crate::algebra::structure_traits::{BaseRing, BitExtract, ErrorCorrect, Solve, ZConsts};
use crate::{
    algebra::structure_traits::Ring, error::error_handler::anyhow_error_and_log,
    execution::runtime::session::BaseSessionHandles,
};

use super::preprocessing::TriplePreprocessing;
use super::triple::mult_list;
use crate::execution::online::preprocessing::BitPreprocessing;
use crate::execution::online::triple::open_list;
use crate::execution::sharing::share::Share;

// Dummy struct used to access the bit manipulation methods
pub struct Bits<Z> {
    _phantom: PhantomData<Z>,
}

// Dummy struct used to access the batched version of bit manipulation methods
pub struct BatchedBits<Z> {
    _phantom: PhantomData<Z>,
}

type SecretVec<Z> = Vec<Share<Z>>;

type BitArray<Z> = Vec<Z>;
type SecretBitArray<Z> = BitArray<Share<Z>>;
type ClearBitArray<Z> = BitArray<Z>;

/// Computes shift right on a secret vector by moving all items to "amount" positions to the right.
/// Note that there is no wrap-around so the first "amount" positions will be 0.
fn shift_right_1d<Z>(x: &SecretVec<Z>, amount: usize) -> SecretVec<Z>
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

/// Applies shift_right_1d to every entry, basically shift rights every entry from a batch
fn shift_right_2d<Z: Ring + ZConsts>(
    x: &[SecretBitArray<Z>],
    amount: usize,
) -> Vec<SecretBitArray<Z>> {
    x.iter()
        .map(|secret| shift_right_1d(secret, amount))
        .collect::<Vec<SecretBitArray<Z>>>()
}

impl<Z> BatchedBits<Z>
where
    Z: Ring + ZConsts + Send + Sync + ErrorCorrect,
{
    /// Takes a 1D array and arranges it into a 2D of size B (batch_size).
    /// Does this by taking consecutive CHAR_LOG2 (64/128) entries and puts them in a single batch
    /// Note that the input comes by flattening that 2D array of size B where each batch has 64/128 entries.
    fn format_to_batch(x: SecretVec<Z>, batch_size: usize) -> Vec<SecretBitArray<Z>> {
        let mut arranged: Vec<SecretBitArray<Z>> = Vec::with_capacity(batch_size);
        for batch_idx in 0..batch_size {
            let entry: Vec<_> = (0..Z::CHAR_LOG2)
                .map(|i| x[batch_idx * Z::CHAR_LOG2 + i])
                .collect();
            arranged.push(entry);
        }
        arranged
    }

    /// Computes XOR(\<a\>,b) for a and b vectors of vectors
    pub fn xor_list_secret_clear(
        lhs: &[SecretBitArray<Z>],
        rhs: &[ClearBitArray<Z>],
    ) -> anyhow::Result<Vec<SecretBitArray<Z>>> {
        if lhs.len() != rhs.len() {
            anyhow_error_and_log(format!(
                "Inputs to XOR function are of different length. LHS is {:?} and RHS is {:?}",
                lhs.len(),
                rhs.len()
            ));
        }

        let mut res = Vec::with_capacity(lhs.len());
        let prods: Vec<_> = lhs
            .iter()
            .zip(rhs)
            .map(|(x, y)| x.iter().zip(y).map(|(xx, yy)| xx * *yy).collect())
            .collect::<Vec<SecretBitArray<Z>>>();

        for ((cur_left, cur_right), cur_prod) in lhs.iter().zip(rhs).zip(&prods) {
            let mut entry = Vec::with_capacity(Z::CHAR_LOG2);
            for ((l_entry, r_entry), prod_entry) in cur_left.iter().zip(cur_right).zip(cur_prod) {
                entry.push((l_entry + r_entry) - (prod_entry * ZConsts::TWO));
            }
            res.push(entry);
        }

        Ok(res)
    }

    /// Computes XOR(\<a\>,\<b\>) for a and b vectors of vectors
    async fn xor_list_secret_secret<
        Rnd: Rng + CryptoRng,
        Ses: BaseSessionHandles<Rnd>,
        P: TriplePreprocessing<Z> + ?Sized,
    >(
        lhs: &[SecretBitArray<Z>],
        rhs: &[SecretBitArray<Z>],
        preproc: &mut P,
        session: &mut Ses,
    ) -> anyhow::Result<Vec<SecretBitArray<Z>>> {
        if lhs.len() != rhs.len() {
            anyhow_error_and_log(format!(
                "Inputs to XOR function are of different lenght. LHS is {:?} and RHS is {:?}",
                lhs.len(),
                rhs.len()
            ));
        }

        let batch_size = lhs.len();

        let lhs = lhs.iter().flatten().cloned().collect::<SecretVec<Z>>();
        let rhs = rhs.iter().flatten().cloned().collect::<SecretVec<Z>>();

        debug_assert_eq!(lhs.len() % Z::CHAR_LOG2, 0);
        debug_assert_eq!(rhs.len() % Z::CHAR_LOG2, 0);

        let flattened = Bits::xor_list_secret_secret(&lhs, &rhs, preproc, session).await?;
        Ok(BatchedBits::format_to_batch(flattened, batch_size))
    }

    async fn and_list_secret_secret<
        Rnd: Rng + CryptoRng,
        Ses: BaseSessionHandles<Rnd>,
        P: TriplePreprocessing<Z> + ?Sized,
    >(
        lhs: &[SecretBitArray<Z>],
        rhs: &[SecretBitArray<Z>],
        preproc: &mut P,
        session: &mut Ses,
    ) -> anyhow::Result<Vec<SecretBitArray<Z>>> {
        if lhs.len() != rhs.len() {
            anyhow_error_and_log(format!(
                "Inputs to XOR function are of different length. LHS is {:?} and RHS is {:?}",
                lhs.len(),
                rhs.len()
            ));
        }
        let batch_size = lhs.len();

        let lhs = lhs.iter().flatten().cloned().collect::<SecretVec<Z>>();
        let rhs = rhs.iter().flatten().cloned().collect::<SecretVec<Z>>();
        let flattened = Bits::and_list_secret_secret(&lhs, &rhs, preproc, session).await?;
        Ok(BatchedBits::format_to_batch(flattened, batch_size))
    }

    /// Computes AND(\<a\>,b) for a and b vectors of vectors
    fn and_list_secret_clear(
        lhs: &[SecretBitArray<Z>],
        rhs: &[ClearBitArray<Z>],
    ) -> anyhow::Result<Vec<SecretBitArray<Z>>> {
        if lhs.len() != rhs.len() {
            anyhow_error_and_log(format!(
                "Inputs to XOR function are of different length. LHS is {:?} and RHS is {:?}",
                lhs.len(),
                rhs.len()
            ));
        }
        let prods: Vec<_> = lhs
            .iter()
            .zip(rhs)
            .map(|(x, y)| x.iter().zip(y).map(|(xx, yy)| xx * *yy).collect())
            .collect::<Vec<SecretBitArray<Z>>>();
        Ok(prods)
    }

    /// This function returns  (lhs1 XOR rhs1, lhs2 AND rhs2) by doing everything using one communication round.
    /// In order to save some communication rounds for bit-decomposition we need to compress XOR and ANDs together in one round.
    /// In order to do this we do one big AND operation using the following
    /// lhs = lhs1 concat lhs2, rhs = rhs1 concat rhs2
    /// (and_left, and_right) = lhs AND rhs
    /// Then lhs1 XOR rhs1 is computed using and_left and other (local) linear operations.
    async fn compressed_xor_and<
        Rnd: Rng + CryptoRng,
        Ses: BaseSessionHandles<Rnd>,
        P: TriplePreprocessing<Z> + ?Sized,
    >(
        lhs1: &[SecretBitArray<Z>],
        rhs1: &[SecretBitArray<Z>],
        lhs2: &[SecretBitArray<Z>],
        rhs2: &[SecretBitArray<Z>],
        preproc: &mut P,
        session: &mut Ses,
    ) -> anyhow::Result<(Vec<SecretBitArray<Z>>, Vec<SecretBitArray<Z>>)> {
        let lhs = lhs1.iter().flatten().cloned().collect::<SecretVec<Z>>();
        let rhs = rhs1.iter().flatten().cloned().collect::<SecretVec<Z>>();

        let lhs_half = lhs2.iter().flatten().cloned().collect::<SecretVec<Z>>();
        let rhs_half = rhs2.iter().flatten().cloned().collect::<SecretVec<Z>>();

        let lhs_all = [lhs.clone(), lhs_half].concat();
        let rhs_all = [rhs.clone(), rhs_half].concat();

        // XOR and AND share the same multiplication
        // XOR(a, b) = a + b - 2*a*b
        // AND(a, b) = a * b
        // so in the first step we just compute a * b for both XOR and AND
        // afterwards we do just linear combinations to compute XOR.
        let ands = Bits::and_list_secret_secret(&lhs_all, &rhs_all, preproc, session).await?;
        let xor_ = Bits::xor_with_prods(&lhs, &rhs, &ands[0..lhs.len()].to_vec());

        let res1 = Self::format_to_batch(xor_, lhs1.len());
        let res2 = Self::format_to_batch(ands[lhs.len()..].to_vec(), lhs2.len());

        Ok((res1, res2))
    }

    #[instrument(name="BitAdd (secret,clear)",skip(session,lhs,rhs,prep),fields(sid=?session.session_id(),own_identity=?session.own_identity(),batch_size=?lhs.len()))]
    async fn binary_adder_secret_clear<
        Rnd: Rng + CryptoRng,
        Ses: BaseSessionHandles<Rnd>,
        P: TriplePreprocessing<Z> + ?Sized,
    >(
        session: &mut Ses,
        lhs: &[BitArray<Share<Z>>],
        rhs: &[BitArray<Z>],
        prep: &mut P,
    ) -> anyhow::Result<Vec<BitArray<Share<Z>>>>
    where
        Z: Ring,
        Z: std::ops::Shl<usize, Output = Z>,
    {
        #![allow(clippy::many_single_char_names)]
        if lhs.len() != rhs.len() {
            anyhow_error_and_log(format!(
                "Inputs to the binary adder are of different lenght. LHS is {:?} and RHS is {:?}",
                lhs.len(),
                rhs.len()
            ));
        }
        let log_r = Z::CHAR_LOG2.ilog2(); // we know that Z::CHAR = 64/128

        let p_store = BatchedBits::xor_list_secret_clear(lhs, rhs)?;
        let mut g = BatchedBits::and_list_secret_clear(lhs, rhs)?;
        let mut p = p_store.clone();

        debug_assert_eq!(lhs[0].len(), Z::CHAR_LOG2);

        for i in 0..log_r {
            // rotate right operation by amount:
            // [ a[0],...,a[R-amount], ...,a[R - 1]
            // [ 0,...,0, a[0], ...,a[R-amount]]
            // computes p << (1<<i)
            let p1 = shift_right_2d(&p, 1 << i);
            // computes g << (1<<i)
            let g1 = shift_right_2d(&g, 1 << i);

            let p_and_g = BatchedBits::and_list_secret_secret(&p, &g1, prep, session).await?;
            // g = g xor p1 and g1
            // p = p * p1
            (g, p) = Self::compressed_xor_and(&g, &p_and_g, &p, &p1, prep, session).await?;
        }
        // c = g << 1
        let c = shift_right_2d(&g, 1);

        // c xor p_store
        BatchedBits::xor_list_secret_secret(&c, &p_store, prep, session).await
    }

    /// This takes in a batch of bit-decomposed partial decryptions and extracts m
    /// For eg, a batch is the bit-decomposition of [t]=[e + Delta * m + Delta/2]
    /// Per batch we get the bits of [t] = [t_0],...,[t_{63}]
    /// To get a b-bit message m, we first retrieve the top most b bits and then
    /// bit-compose them, ie compute sum_{i=0}^{b-1} 2^i * m_i
    /// If the error reached the topmost bit we return 0
    /// o/w we return m
    /// Hence we do a final MUX, depending on the bit b.
    pub async fn extract_ptxts<
        Rnd: Rng + CryptoRng,
        Ses: BaseSessionHandles<Rnd>,
        P: TriplePreprocessing<Z> + ?Sized,
    >(
        partial_decs: Vec<SecretBitArray<Z>>,
        message_mod_bits: usize,
        preproc: &mut P,
        session: &mut Ses,
    ) -> anyhow::Result<SecretVec<Z>>
    where
        Z: std::ops::Shl<usize, Output = Z>,
    {
        let ct_len = Z::CHAR_LOG2;

        let mut sign_bits = Vec::new();
        let mut recomposed_decryptions = Vec::new();

        for partial_dec in partial_decs.iter() {
            let plaintext_bits = &partial_dec[ct_len - (message_mod_bits + 1)..ct_len - 1].to_vec();
            let plaintext_sum = Bits::bit_sum(plaintext_bits)?;
            // if sign_bit == 1, then return 0
            // if sign_bit == 0, return plaintext_sum
            // MUX(sign_bit, 0 || plaintext_sum) <=>
            // sign_bit * 0 + (1 - sign_bit) * plaintext_sum
            // plaintext_sum - sign_bit * plaintext_sum
            let sign_bit = partial_dec[ct_len - 1];
            sign_bits.push(sign_bit);
            recomposed_decryptions.push(plaintext_sum);
        }

        //Perform the MUX described above, on all messages in one round
        let triples = preproc.next_triple_vec(sign_bits.len())?;
        let prods = mult_list(&sign_bits, &recomposed_decryptions, triples, session).await?;

        // compute plaintext_sum - sign_bit * plaintext_sum, final step of the MUX
        let res: Vec<Share<Z>> = prods
            .iter()
            .enumerate()
            .map(|(i, prod)| &recomposed_decryptions[i] - prod)
            .collect();

        Ok(res)
    }
}

impl<Z> Bits<Z>
where
    Z: Ring + ZConsts + Send + Sync + ErrorCorrect,
{
    /// Computes XOR(\<a\>,\<b\>) for a and b vecs given AND(\<a\>,\<b\>)
    fn xor_with_prods(
        lhs: &SecretVec<Z>,
        rhs: &SecretVec<Z>,
        prods: &SecretVec<Z>,
    ) -> SecretVec<Z> {
        let mut res = Vec::with_capacity(lhs.len());
        for ((cur_left, cur_right), cur_prod) in lhs.iter().zip(rhs).zip(prods) {
            res.push((cur_left + cur_right) - (cur_prod * ZConsts::TWO));
        }
        res
    }

    /// Computes XOR(\<a\>,\<b\>) for a and b vecs
    #[instrument(name="XOR", skip(lhs,rhs,preproc,session),fields(sid=?session.session_id(),own_identity=?session.own_identity(),batch_size=?lhs.len()))]
    pub async fn xor_list_secret_secret<
        Rnd: Rng + CryptoRng,
        Ses: BaseSessionHandles<Rnd>,
        P: TriplePreprocessing<Z> + ?Sized,
    >(
        lhs: &SecretVec<Z>,
        rhs: &SecretVec<Z>,
        preproc: &mut P,
        session: &mut Ses,
    ) -> anyhow::Result<SecretVec<Z>> {
        let ands = Self::and_list_secret_secret(lhs, rhs, preproc, session).await?;
        Ok(Self::xor_with_prods(lhs, rhs, &ands))
    }

    /// Computes AND(\<a\>,\<b\>) for a and b vecs
    pub async fn and_list_secret_secret<
        Rnd: Rng + CryptoRng,
        Ses: BaseSessionHandles<Rnd>,
        P: TriplePreprocessing<Z> + ?Sized,
    >(
        lhs: &SecretVec<Z>,
        rhs: &SecretVec<Z>,
        preproc: &mut P,
        session: &mut Ses,
    ) -> anyhow::Result<SecretVec<Z>> {
        if lhs.len() != rhs.len() {
            anyhow_error_and_log(format!(
                "Inputs to XOR function are of different length. LHS is {:?} and RHS is {:?}",
                lhs.len(),
                rhs.len()
            ));
        }
        let triples = preproc.next_triple_vec(lhs.len())?;
        let prods = mult_list(lhs, rhs, triples, session).await?;
        Ok(prods)
    }

    ///Given a vector of shared bits, compute the "bit recomposition"
    #[instrument(name="BitSum",skip(input),fields(batch_size=?input.len()))]
    pub fn bit_sum(input: &SecretVec<Z>) -> anyhow::Result<Share<Z>>
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

/// Bit decomposition of the input, assuming the secret lies in the base ring and not the extension.
#[instrument(name="BitDec",skip(session,prep,inputs),fields(sid=?session.session_id(),own_identity=?session.own_identity(),batch_size=?inputs.len()))]
pub async fn bit_dec_batch<
    Z,
    const EXTENSION_DEGREE: usize,
    P,
    Rnd: Rng + CryptoRng,
    Ses: BaseSessionHandles<Rnd>,
>(
    session: &mut Ses,
    prep: &mut P,
    inputs: SecretVec<ResiduePoly<Z, EXTENSION_DEGREE>>,
) -> anyhow::Result<Vec<SecretBitArray<ResiduePoly<Z, EXTENSION_DEGREE>>>>
where
    Z: BaseRing + std::fmt::Display,
    ResiduePoly<Z, EXTENSION_DEGREE>: Solve + ErrorCorrect,
    Z: BitExtract,
    P: TriplePreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>>
        + BitPreprocessing<ResiduePoly<Z, EXTENSION_DEGREE>>
        + ?Sized
        + Send,
{
    let batch_size = inputs.len();

    //Take random bits from preprocessing
    let mut random_bits = prep.next_bit_vec(Z::CHAR_LOG2 * batch_size)?;
    tracing::debug!("Finished generating the random bits...");

    //For each value, bit recompose random bits to form a mask,
    //keeping in memory both the mask and the individual bits
    let mut masks = Vec::with_capacity(batch_size);
    let mut prep_bits = Vec::<SecretBitArray<ResiduePoly<Z, EXTENSION_DEGREE>>>::new();
    for _ in 0..batch_size {
        let bits_per_entry: Vec<_> = (0..Z::CHAR_LOG2)
            .map(|_| random_bits.pop().unwrap())
            .collect();
        let mask = Bits::<ResiduePoly<Z, EXTENSION_DEGREE>>::bit_sum(&bits_per_entry)?;
        prep_bits.push(bits_per_entry);
        masks.push(mask);
    }

    // Mask the secrets with the masks we've just computed
    let masked_secrets: Vec<_> = inputs
        .iter()
        .zip(masks.iter())
        .map(|(secret, mask)| secret - mask)
        .collect();

    // value are safe to open now
    // opening the masked values
    let opened_masks = open_list(&masked_secrets, session).await?;

    let mut opened_masked_bits = Vec::new();
    for entry in opened_masks {
        //This assumes the secret was in the base ring and not in the extension
        let scalar = entry.to_scalar()?;
        //Bit decompose the masked secret
        let scalar_bits: Vec<u8> = (0..Z::CHAR_LOG2)
            .map(|bit_idx| scalar.extract_bit(bit_idx))
            .collect();
        //Embed the bit decomposition back into the extension ring
        let residue_bits: Vec<ResiduePoly<Z, EXTENSION_DEGREE>> = scalar_bits
            .iter()
            .map(|bit| ResiduePoly::<Z, EXTENSION_DEGREE>::from_scalar(Z::from_u128(*bit as u128)))
            .collect();
        opened_masked_bits.push(residue_bits);
    }

    //Use a binary adder to add back the mask to the masked secret, getting back the secret in binary format
    let add_res = BatchedBits::<ResiduePoly<Z, EXTENSION_DEGREE>>::binary_adder_secret_clear(
        session,
        &prep_bits,
        &opened_masked_bits,
        prep,
    )
    .await?;
    Ok(add_res)
}

#[cfg(test)]
mod tests {
    use std::num::Wrapping;

    use crate::algebra::structure_traits::Ring;
    use crate::execution::sharing::shamir::ShamirSharings;
    use crate::networking::NetworkMode;
    use aes_prng::AesRng;
    use itertools::Itertools;
    use rand::SeedableRng;
    use rstest::rstest;

    use crate::algebra::base_ring::Z64;
    use crate::algebra::galois_rings::degree_4::ResiduePolyF4Z64;
    use crate::execution::online::bit_manipulation::bit_dec_batch;
    use crate::execution::online::bit_manipulation::BatchedBits;
    use crate::execution::online::bit_manipulation::Bits;
    use crate::execution::online::preprocessing::dummy::DummyPreprocessing;
    use crate::execution::online::triple::open_list;
    use crate::execution::runtime::session::ParameterHandles;
    use crate::execution::runtime::session::SmallSession;
    use crate::execution::sharing::shamir::InputOp;
    use crate::execution::sharing::share::Share;
    use crate::tests::helper::tests_and_benches::execute_protocol_small;

    /// Helper method to get a sharing of a simple u64 value
    fn get_my_share(val: u64, session: &SmallSession<ResiduePolyF4Z64>) -> Share<ResiduePolyF4Z64> {
        let mut rng = AesRng::seed_from_u64(val);
        let secret = ResiduePolyF4Z64::from_scalar(Wrapping(val));
        let shares = ShamirSharings::share(
            &mut rng,
            secret,
            session.num_parties(),
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
            .map(|i| ResiduePolyF4Z64::from_scalar(Wrapping(plain_lhs[i] ^ plain_rhs[i])))
            .collect_vec();

        let mut task = |mut session: SmallSession<ResiduePolyF4Z64>| async move {
            let lhs = plain_lhs
                .iter()
                .map(|cur_val| get_my_share(*cur_val, &session))
                .collect_vec();
            let rhs = plain_rhs
                .iter()
                .map(|cur_val| get_my_share(*cur_val, &session))
                .collect_vec();
            let mut preprocessing = DummyPreprocessing::<
                ResiduePolyF4Z64,
                AesRng,
                SmallSession<ResiduePolyF4Z64>,
            >::new(42, session.clone());
            let bits = Bits::<ResiduePolyF4Z64>::xor_list_secret_secret(
                &lhs,
                &rhs,
                &mut preprocessing,
                &mut session,
            )
            .await
            .unwrap();
            open_list(&bits, &session).await.unwrap()
        };

        // we expect 2 rounds: one for the opening during multiplication, one for the opening of the output.
        // Async because preprocessing is Dummy
        //Delay P1 by 1s every round
        let delay_vec = vec![tokio::time::Duration::from_secs(1)];
        let results = execute_protocol_small::<
            _,
            _,
            ResiduePolyF4Z64,
            { ResiduePolyF4Z64::EXTENSION_DEGREE },
        >(
            parties,
            threshold as u8,
            Some(2),
            NetworkMode::Async,
            Some(delay_vec),
            &mut task,
        );

        for cur_res in results {
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
        // Observe that the above input bits are ordered [LSB, ..., MSB]; written in the more common form 10110_2 = 22_10
        let ref_val = 22;

        let mut task = |session: SmallSession<ResiduePolyF4Z64>| async move {
            let input = plain_input
                .iter()
                .map(|cur_val| get_my_share(*cur_val, &session))
                .collect_vec();
            let bits = Bits::<ResiduePolyF4Z64>::bit_sum(&input).unwrap();
            open_list(&[bits], &session).await.unwrap()[0]
        };

        // we expect 1 round: the opening of the output.
        // Async because no preprocessing
        //Delay P1 by 1s every round
        let delay_vec = vec![tokio::time::Duration::from_secs(1)];
        let results = execute_protocol_small::<
            _,
            _,
            ResiduePolyF4Z64,
            { ResiduePolyF4Z64::EXTENSION_DEGREE },
        >(
            parties,
            threshold as u8,
            Some(1),
            NetworkMode::Async,
            Some(delay_vec),
            &mut task,
        );

        for cur_res in results {
            assert_eq!(ResiduePolyF4Z64::from_scalar(Wrapping(ref_val)), cur_res);
        }
    }

    #[rstest]
    #[case(12491094489948035603, 5955649583761516015)]
    #[case(1, 9223372036854775808)]
    fn bit_adder(#[case] a: u64, #[case] b: u64) {
        let parties = 4;
        let threshold = 1;

        let ref_val = Wrapping(a) + Wrapping(b);

        let mut task = |mut session: SmallSession<ResiduePolyF4Z64>| async move {
            let mut prep = DummyPreprocessing::<
                ResiduePolyF4Z64,
                AesRng,
                SmallSession<ResiduePolyF4Z64>,
            >::new(42, session.clone());

            let input_a = (0..Z64::CHAR_LOG2)
                .map(|bit_idx| get_my_share((a >> bit_idx) & 1, &session))
                .collect_vec();
            let input_a = vec![input_a];

            let input_b = (0..Z64::CHAR_LOG2)
                .map(|bit_idx| ResiduePolyF4Z64::from_scalar(Wrapping((b >> bit_idx) & 1)))
                .collect_vec();
            let input_b = vec![input_b];

            let bits = BatchedBits::<ResiduePolyF4Z64>::binary_adder_secret_clear(
                &mut session,
                &input_a,
                &input_b,
                &mut prep,
            )
            .await
            .unwrap();

            let bit_sum = Bits::<ResiduePolyF4Z64>::bit_sum(&bits[0]).unwrap();
            open_list(&[bit_sum], &session).await.unwrap()[0]
        };

        // we expect 2 rounds for each bit of the type (log_2(64)=6), 1 for the final adder XOR and 1 final opening = 2*6 + 1 + 1 = 20 in total.
        let rounds = 2_usize * Z64::CHAR_LOG2.ilog2() as usize + 1 + 1;
        // Async because preprocessing is Dummy
        //Delay P1 by 1s every round
        let delay_vec = vec![tokio::time::Duration::from_secs(1)];
        let results = execute_protocol_small::<
            _,
            _,
            ResiduePolyF4Z64,
            { ResiduePolyF4Z64::EXTENSION_DEGREE },
        >(
            parties,
            threshold as u8,
            Some(rounds),
            NetworkMode::Async,
            Some(delay_vec),
            &mut task,
        );

        for cur_res in results {
            assert_eq!(ResiduePolyF4Z64::from_scalar(ref_val), cur_res);
        }
    }

    #[rstest]
    #[case(1, 1, 1, 0)]
    #[case(321, 3213, 928541, 321952)]
    fn sunshine_compress(#[case] a: u64, #[case] b: u64, #[case] c: u64, #[case] d: u64) {
        let parties = 4;
        let threshold = 1;

        let bits_a: Vec<_> = (0..64).map(|bit_idx| (a >> bit_idx) & 1).collect();
        let bits_b: Vec<_> = (0..64).map(|bit_idx| (b >> bit_idx) & 1).collect();
        let bits_c: Vec<_> = (0..64).map(|bit_idx| (c >> bit_idx) & 1).collect();
        let bits_d: Vec<_> = (0..64).map(|bit_idx| (d >> bit_idx) & 1).collect();

        let mut task = |mut session: SmallSession<ResiduePolyF4Z64>| async move {
            let mut prep = DummyPreprocessing::<
                ResiduePolyF4Z64,
                AesRng,
                SmallSession<ResiduePolyF4Z64>,
            >::new(42, session.clone());

            let input_a = (0..Z64::CHAR_LOG2)
                .map(|bit_idx| get_my_share((a >> bit_idx) & 1, &session))
                .collect_vec();
            let input_a = vec![input_a];

            let input_b = (0..Z64::CHAR_LOG2)
                .map(|bit_idx| get_my_share((b >> bit_idx) & 1, &session))
                .collect_vec();
            let input_b = vec![input_b];

            let input_c = (0..Z64::CHAR_LOG2)
                .map(|bit_idx| get_my_share((c >> bit_idx) & 1, &session))
                .collect_vec();
            let input_c = vec![input_c];

            let input_d = (0..Z64::CHAR_LOG2)
                .map(|bit_idx| get_my_share((d >> bit_idx) & 1, &session))
                .collect_vec();
            let input_d = vec![input_d];

            let (a_xor_b, c_and_d) = BatchedBits::<ResiduePolyF4Z64>::compressed_xor_and(
                &input_a,
                &input_b,
                &input_c,
                &input_d,
                &mut prep,
                &mut session,
            )
            .await
            .unwrap();

            let a_xor_b: Vec<Share<ResiduePolyF4Z64>> = a_xor_b
                .iter()
                .flatten()
                .cloned()
                .collect::<Vec<Share<ResiduePolyF4Z64>>>();
            let opened1 = open_list(&a_xor_b, &session).await.unwrap();

            let target_xor = BatchedBits::<ResiduePolyF4Z64>::xor_list_secret_secret(
                &input_a,
                &input_b,
                &mut prep,
                &mut session,
            )
            .await
            .unwrap();
            let target_xor = target_xor
                .iter()
                .flatten()
                .cloned()
                .collect::<Vec<Share<ResiduePolyF4Z64>>>();
            let opened1_target = open_list(&target_xor, &session).await.unwrap();

            let c_and_d: Vec<Share<ResiduePolyF4Z64>> = c_and_d
                .iter()
                .flatten()
                .cloned()
                .collect::<Vec<Share<ResiduePolyF4Z64>>>();
            let opened2 = open_list(&c_and_d, &session).await.unwrap();

            let target_and = BatchedBits::<ResiduePolyF4Z64>::and_list_secret_secret(
                &input_c,
                &input_d,
                &mut prep,
                &mut session,
            )
            .await
            .unwrap();
            let target_and = target_and
                .iter()
                .flatten()
                .cloned()
                .collect::<Vec<Share<ResiduePolyF4Z64>>>();
            let opened2_target = open_list(&target_and, &session).await.unwrap();

            (opened1, opened1_target, opened2, opened2_target)
        };

        // Async because preprocessing is Dummy
        //Delay P1 by 1s every round
        let delay_vec = vec![tokio::time::Duration::from_secs(1)];
        let results = &execute_protocol_small::<
            _,
            _,
            ResiduePolyF4Z64,
            { ResiduePolyF4Z64::EXTENSION_DEGREE },
        >(
            parties,
            threshold as u8,
            None,
            NetworkMode::Async,
            Some(delay_vec),
            &mut task,
        )[0];
        let (xor1, xor2, and1, and2) = results;
        assert_eq!(xor1, xor2);

        for i in 0..xor1.len() {
            assert_eq!(
                xor1[i],
                ResiduePolyF4Z64::from_scalar(Wrapping(bits_a[i] ^ bits_b[i])),
                "failed xor at index {}",
                i
            );
        }

        assert_eq!(and1, and2);

        for i in 0..and1.len() {
            assert_eq!(
                and1[i],
                ResiduePolyF4Z64::from_scalar(Wrapping(bits_c[i] & bits_d[i])),
                "failed and at index {}",
                i
            );
        }
    }

    #[rstest]
    #[case(18446744073709551615)]
    #[case(1)]
    #[case(2)]
    #[case(3)]
    #[case(4)]
    fn sunshine_batched_bitdec(#[case] a: u64) {
        let parties = 4;
        let threshold = 1;

        let ref_val: Vec<_> = (0..64).map(|bit_idx| (a >> bit_idx) & 1).collect();

        let mut task = |mut session: SmallSession<ResiduePolyF4Z64>| async move {
            let mut prep = DummyPreprocessing::<
                ResiduePolyF4Z64,
                AesRng,
                SmallSession<ResiduePolyF4Z64>,
            >::new(42, session.clone());

            let input_a = get_my_share(a, &session);
            let input_a = vec![input_a];

            let bits = bit_dec_batch::<Z64, { ResiduePolyF4Z64::EXTENSION_DEGREE }, _, _, _>(
                &mut session,
                &mut prep,
                input_a,
            )
            .await
            .unwrap();
            println!(
                "bit dec required {:?} random sharings and {:?} random triples",
                prep.rnd_ctr, prep.trip_ctr
            );
            open_list(&bits[0], &session).await.unwrap()
        };

        //Comment for reviewer, removing 2 rounds because
        //generating bits from DummyPreprocessing is now communication-free
        // Async because preprocessing is Dummy
        //Delay P1 by 1s every round
        let delay_vec = vec![tokio::time::Duration::from_secs(1)];
        let rounds = 2_usize + 1 + 2_usize * Z64::CHAR_LOG2.ilog2() as usize;
        let results = &execute_protocol_small::<
            _,
            _,
            ResiduePolyF4Z64,
            { ResiduePolyF4Z64::EXTENSION_DEGREE },
        >(
            parties,
            threshold as u8,
            Some(rounds),
            NetworkMode::Async,
            Some(delay_vec),
            &mut task,
        )[0];
        assert_eq!(results.len(), ref_val.len());
        for i in 0..results.len() {
            assert_eq!(
                results[i],
                ResiduePolyF4Z64::from_scalar(Wrapping(ref_val[i]))
            );
        }
    }
}

//This file contains code related to algebraric operations
//I put them there as they may not be needed anymore when/if
//part of this code is integrated in tfhe-rs
use itertools::{EitherOrBoth, Itertools};

use crate::{
    algebra::{
        poly::Poly,
        residue_poly::ResiduePoly,
        structure_traits::{BaseRing, Ring, Zero},
    },
    error::error_handler::anyhow_error_and_log,
};

use super::glwe_key::GlweSecretKeyShare;

pub fn slice_semi_reverse_negacyclic_convolution<Z: BaseRing>(
    output: &mut Vec<ResiduePoly<Z>>,
    lhs: &[Z],
    rhs: &[ResiduePoly<Z>],
) -> anyhow::Result<()> {
    debug_assert!(
        lhs.len() == rhs.len(),
        "lhs (len: {}) and rhs (len: {}) must have the same length",
        lhs.len(),
        rhs.len()
    );
    debug_assert!(
        output.len() == lhs.len(),
        "output (len: {}) and lhs (len: {}) must have the same length",
        output.len(),
        lhs.len()
    );
    output.fill(ResiduePoly::ZERO);
    let mut rev_rhs = rhs.to_vec();
    rev_rhs.reverse();
    let lhs_pol = Poly::from_coefs(lhs.to_vec());
    let rhs_pol = Poly::from_coefs(rev_rhs);

    let res = pol_mul_reduce(&lhs_pol, &rhs_pol, output.len())?;
    *output = res.coefs;
    Ok(())
}

pub fn slice_to_polynomials<Z: Ring>(slice: &[Z], pol_size: usize) -> Vec<Poly<Z>> {
    let mut res: Vec<Poly<Z>> = Vec::new();
    for coefs in &slice.iter().chunks(pol_size) {
        let coef = coefs.copied().collect_vec();
        res.push(Poly::from_coefs(coef));
    }
    res
}

pub fn pol_mul_reduce<Z: BaseRing>(
    poly_1: &Poly<Z>,
    poly_2: &Poly<ResiduePoly<Z>>,
    output_size: usize,
) -> anyhow::Result<Poly<ResiduePoly<Z>>> {
    let mut coefs = (0..output_size)
        .map(|_| ResiduePoly::default())
        .collect_vec();

    debug_assert!(
        output_size == poly_1.coefs.len(),
        "Output polynomial size {:?} is not the same as input polynomial1 {:?}.",
        output_size,
        poly_1.coefs.len(),
    );
    debug_assert!(
        output_size == poly_2.coefs.len(),
        "Output polynomial size {:?} is not the same as input polynomial2 {:?}.",
        output_size,
        poly_2.coefs.len(),
    );

    for (lhs_degree, lhs_coef) in poly_1.coefs.iter().enumerate() {
        for (rhs_degree, rhs_coef) in poly_2.coefs.iter().enumerate() {
            let target_degree = lhs_degree + rhs_degree;
            if target_degree < output_size {
                let output_coefficient = coefs.get_mut(target_degree).ok_or_else(|| {
                    anyhow_error_and_log(format!(
                        "coefs of unexpected size, can't get at index {target_degree}"
                    ))
                })?;
                *output_coefficient += *rhs_coef * *lhs_coef;
            } else {
                let target_degree = target_degree % output_size;

                let output_coefficient = coefs.get_mut(target_degree).ok_or_else(|| {
                    anyhow_error_and_log(format!(
                        "coefs of unexpected size, can't get at index {target_degree}"
                    ))
                })?;
                *output_coefficient -= *rhs_coef * *lhs_coef;
            }
        }
    }

    Ok(Poly::from_coefs(coefs))
}

pub fn slice_wrapping_dot_product<Z: BaseRing>(
    lhs: &[Z],
    rhs: &[ResiduePoly<Z>],
) -> anyhow::Result<ResiduePoly<Z>> {
    lhs.iter()
        .zip_longest(rhs.iter())
        .try_fold(ResiduePoly::ZERO, |acc, left_right| {
            if let EitherOrBoth::Both(&left, &right) = left_right {
                Ok(acc + right * left)
            } else {
                Err(anyhow_error_and_log("zip error".to_string()))
            }
        })
}

pub fn polynomial_wrapping_add_multisum_assign<Z: BaseRing>(
    output_body: &mut [ResiduePoly<Z>],
    output_mask: &[Z],
    glwe_secret_key_share: &GlweSecretKeyShare<Z>,
) -> anyhow::Result<()> {
    let pol_dimension = glwe_secret_key_share.polynomial_size.0;
    let mut pol_output_body = Poly::from_coefs(output_body.to_vec());
    let pol_output_mask = slice_to_polynomials(output_mask, pol_dimension);
    let pol_glwe_secret_key_share =
        slice_to_polynomials(&glwe_secret_key_share.data_as_raw_vec(), pol_dimension);

    for poly_1_poly_2 in pol_output_mask
        .iter()
        .zip_longest(pol_glwe_secret_key_share.iter())
    {
        if let EitherOrBoth::Both(poly_1, poly_2) = poly_1_poly_2 {
            pol_output_body = pol_output_body + pol_mul_reduce(poly_1, poly_2, pol_dimension)?;
        } else {
            return Err(anyhow_error_and_log("zip error".to_string()));
        }
    }

    for coef_output_coef_pol in output_body
        .iter_mut()
        .zip_longest(pol_output_body.coefs.iter())
    {
        if let EitherOrBoth::Both(coef_output, coef_pol) = coef_output_coef_pol {
            *coef_output = *coef_pol;
        } else {
            return Err(anyhow_error_and_log("zip error".to_string()));
        }
    }
    Ok(())
}

pub fn slice_wrapping_scalar_mul_assign<Z: BaseRing>(lhs: &mut [ResiduePoly<Z>], rhs: Z) {
    lhs.iter_mut().for_each(|lhs| *lhs = *lhs * rhs);
}

#[cfg(test)]
pub mod tests {
    use std::collections::HashMap;

    use itertools::Itertools;
    use tfhe::core_crypto::entities::{GlweSecretKeyOwned, LweSecretKeyOwned};

    use crate::execution::sharing::shamir::RevealOp;
    use crate::{
        algebra::{residue_poly::ResiduePoly, structure_traits::BaseRing},
        execution::{
            endpoints::keygen::{DKGParams, PrivateKeySet},
            runtime::party::Role,
            sharing::{
                shamir::{ErrorCorrect, ShamirSharings},
                share::Share,
            },
        },
    };

    pub fn reconstruct_glwe_body_vec<Z: BaseRing>(
        input: HashMap<Role, Vec<Share<ResiduePoly<Z>>>>,
        expected_num_glwe_ctxt: usize,
        polynomial_size: usize,
        threshold: usize,
    ) -> Vec<Vec<Z>>
    where
        ResiduePoly<Z>: ErrorCorrect,
    {
        let mut output_body_vec = Vec::new();
        for glwe_ctxt_idx in 0..expected_num_glwe_ctxt {
            let mut body = Vec::new();
            let slice_start_idx = glwe_ctxt_idx * polynomial_size;
            let slice_end_idx = slice_start_idx + polynomial_size;
            for curr_glwe_ctxt_index in slice_start_idx..slice_end_idx {
                let mut vec_body = Vec::new();
                for (_role, values) in input.iter() {
                    vec_body.push(values[curr_glwe_ctxt_index]);
                }
                body.push(
                    ShamirSharings::create(vec_body)
                        .reconstruct(threshold)
                        .unwrap()
                        .to_scalar()
                        .unwrap(),
                );
            }

            output_body_vec.push(body);
        }
        output_body_vec
    }

    pub fn reconstruct_bit_vec<Z: BaseRing>(
        input: HashMap<Role, Vec<Share<ResiduePoly<Z>>>>,
        expected_num_bits: usize,
        threshold: usize,
    ) -> Vec<u64>
    where
        ResiduePoly<Z>: ErrorCorrect,
    {
        let mut output_bit_vec = Vec::new();
        for idx in 0..expected_num_bits {
            let mut vec_bit = Vec::new();
            for (_, values) in input.iter() {
                vec_bit.push(values[idx]);
            }

            let key_bit = ShamirSharings::create(vec_bit)
                .reconstruct(threshold)
                .unwrap()
                .to_scalar()
                .unwrap();

            //Assert we indeed have a bit
            assert_eq!(key_bit * (Z::ONE - key_bit), Z::ZERO);
            if key_bit == Z::ZERO {
                output_bit_vec.push(0_u64);
            } else {
                output_bit_vec.push(1_u64);
            }
        }
        output_bit_vec
    }

    pub fn reconstruct_lwe_secret_key_from_file<Z: BaseRing>(
        parties: usize,
        threshold: usize,
        params: DKGParams,
    ) -> LweSecretKeyOwned<u64>
    where
        ResiduePoly<Z>: ErrorCorrect,
    {
        let mut sk_shares = HashMap::new();
        for party in 0..parties {
            sk_shares.insert(
                Role::indexed_by_zero(party),
                PrivateKeySet::<Z>::read_from_file(format!(
                    "{}/sk_p{}.der",
                    params.get_prefix_path(),
                    party
                ))
                .unwrap(),
            );
        }

        let mut lwe_key_shares = HashMap::new();
        for (role, sk) in sk_shares {
            lwe_key_shares.insert(role, Vec::new());
            let lwe_key_shares = lwe_key_shares.get_mut(&role).unwrap();
            for key_share in sk.lwe_secret_key_share.data.into_iter() {
                (*lwe_key_shares).push(key_share);
            }
        }

        //Reconstruct the keys

        let lwe_key = reconstruct_bit_vec(lwe_key_shares, params.lwe_dimension().0, threshold);
        LweSecretKeyOwned::from_container(lwe_key)
    }

    pub fn reconstruct_glwe_secret_key_from_file<Z: BaseRing>(
        parties: usize,
        threshold: usize,
        params: DKGParams,
    ) -> (GlweSecretKeyOwned<u64>, Option<GlweSecretKeyOwned<u128>>)
    where
        ResiduePoly<Z>: ErrorCorrect,
    {
        let mut sk_shares = HashMap::new();
        for party in 0..parties {
            sk_shares.insert(
                Role::indexed_by_zero(party),
                PrivateKeySet::<Z>::read_from_file(format!(
                    "{}/sk_p{}.der",
                    params.get_prefix_path(),
                    party
                ))
                .unwrap(),
            );
        }

        let mut glwe_key_shares = HashMap::new();
        let mut big_glwe_key_shares = HashMap::new();
        for (role, sk) in sk_shares {
            glwe_key_shares.insert(role, sk.glwe_secret_key_share.data);

            if params.o_flag {
                big_glwe_key_shares.insert(role, sk.glwe_secret_key_share_sns.unwrap().data);
            }
        }

        let glwe_key = reconstruct_bit_vec(glwe_key_shares, params.glwe_sk_num_bits(), threshold);
        let glwe_secret_key =
            GlweSecretKeyOwned::from_container(glwe_key, params.polynomial_size());

        let big_glwe_secret_key = if params.o_flag {
            let big_glwe_key = reconstruct_bit_vec(
                big_glwe_key_shares,
                params.glwe_sk_num_bits_sns().unwrap(),
                threshold,
            )
            .into_iter()
            .map(|bit| bit as u128)
            .collect_vec();
            Some(GlweSecretKeyOwned::from_container(
                big_glwe_key,
                params.o_N.unwrap(),
            ))
        } else {
            None
        };

        (glwe_secret_key, big_glwe_secret_key)
    }
}

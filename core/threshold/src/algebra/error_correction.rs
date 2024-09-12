use super::{
    bivariate::compute_powers,
    gf256::{error_correction, GF256},
    poly::Poly,
    residue_poly::ResiduePoly,
    structure_traits::{BaseRing, ErrorCorrect, RingEmbed, Zero},
};
use crate::algebra::residue_poly::ResiduePoly128;
use crate::algebra::residue_poly::ResiduePoly64;
use crate::algebra::{poly::BitwisePoly, residue_poly::F_DEG};
use crate::error::error_handler::anyhow_error_and_log;
use crate::execution::sharing::shamir::ShamirSharing;
use crate::execution::sharing::shamir::ShamirSharings;
use itertools::Itertools;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::RwLock;

lazy_static! {
    static ref EXCEPTIONAL_SET_STORE128: RwLock<HashMap<(usize, usize), Vec<ResiduePoly128>>> =
        RwLock::new(HashMap::new());
    static ref EXCEPTIONAL_SET_STORE64: RwLock<HashMap<(usize, usize), Vec<ResiduePoly64>>> =
        RwLock::new(HashMap::new());
}

/// Trait used to speed up error correction computation.
///
/// Stores in a table powers of embedded values from {1, ..., n}
/// I.e. for each g \in {1,...,n}, computes g^i for each i \in {0,t}
/// where t (threshold) is the maximum allowed error used in error correction.
pub trait MemoizedExceptionals: Sized + Clone + 'static {
    /// computes g^i = embed(index)^i for each i in {0,degree}
    fn calculate_powers(index: usize, degree: usize) -> anyhow::Result<Vec<Self>>;

    /// Handle for getting storage map for each underlying ring Z64, or Z128.
    fn storage() -> &'static RwLock<HashMap<(usize, usize), Vec<Self>>>;

    /// Computes g^i=embed(index)^i for each i in {0, degree}. If it's already computed
    /// retrieves it from the storage
    fn exceptional_set(index: usize, degree: usize) -> anyhow::Result<Vec<Self>> {
        if let Ok(lock_exceptional_set_store) = Self::storage().read() {
            match lock_exceptional_set_store.get(&(index, degree)) {
                Some(v) => Ok(v.clone()),
                None => {
                    drop(lock_exceptional_set_store);
                    if let Ok(mut lock_exceptional_set_store) = Self::storage().write() {
                        let powers = Self::calculate_powers(index, degree)?;
                        lock_exceptional_set_store.insert((index, degree), powers.clone());
                        Ok(powers)
                    } else {
                        Err(anyhow_error_and_log(
                            "Error writing exceptional store 64".to_string(),
                        ))
                    }
                }
            }
        } else {
            Err(anyhow_error_and_log(
                "Error reading exceptional store".to_string(),
            ))
        }
    }
}

impl MemoizedExceptionals for ResiduePoly64 {
    fn calculate_powers(index: usize, degree: usize) -> anyhow::Result<Vec<Self>> {
        let point = ResiduePoly64::embed_exceptional_set(index)?;
        Ok(compute_powers(point, degree))
    }
    fn storage() -> &'static RwLock<HashMap<(usize, usize), Vec<Self>>> {
        &EXCEPTIONAL_SET_STORE64
    }
}

impl MemoizedExceptionals for ResiduePoly128 {
    fn calculate_powers(index: usize, degree: usize) -> anyhow::Result<Vec<Self>> {
        let point = ResiduePoly128::embed_exceptional_set(index)?;
        Ok(compute_powers(point, degree))
    }
    fn storage() -> &'static RwLock<HashMap<(usize, usize), Vec<Self>>> {
        &EXCEPTIONAL_SET_STORE128
    }
}

/// Lifts binary polynomial p to the big ring and accumulates 2^amount * p into res
fn accumulate_and_lift_bitwise_poly<Z: BaseRing>(
    res: &mut Poly<ResiduePoly<Z>>,
    p: &Poly<GF256>,
    amount: usize,
) {
    while res.coefs.len() < p.coefs.len() {
        res.coefs.push(ResiduePoly::<Z>::ZERO);
    }
    for (i, coef) in p.coefs.iter().enumerate() {
        let c8: u8 = coef.0;
        for d in 0..F_DEG {
            if ((c8 >> d) & 1) != 0 {
                res.coefs[i].coefs[d] += Z::ONE << amount;
            }
        }
    }
}

fn shamir_error_correct<Z: BaseRing>(
    sharing: &ShamirSharings<ResiduePoly<Z>>,
    degree: usize,
    max_errs: usize,
    #[cfg(test)] err_indices: Option<&mut Vec<(usize, usize)>>,
) -> anyhow::Result<Poly<ResiduePoly<Z>>>
where
    ResiduePoly<Z>: MemoizedExceptionals,
    ResiduePoly<Z>: RingEmbed,
{
    // threshold is the degree of the shamir polynomial
    let ring_size: usize = Z::BIT_LENGTH;

    //Start with all values being valid (none of them are Bot)
    let mut y = sharing
        .shares
        .iter()
        .map(|x| (x.value(), true))
        .collect_vec();

    let initial_length = y.len();

    let parties: Vec<_> = sharing
        .shares
        .iter()
        .map(|x| x.owner().one_based())
        .collect();

    let ordered_powers: Vec<Vec<ResiduePoly<Z>>> = parties
        .iter()
        .map(|party_id| ResiduePoly::<Z>::exceptional_set(*party_id, degree))
        .collect::<anyhow::Result<Vec<_>>>()?;

    let mut res = Poly::<ResiduePoly<Z>>::zero();

    for bit_idx in 0..ring_size {
        //Compute z = pi(y/2^i), where Bots are filtered out
        let binary_shares: Vec<ShamirSharing<GF256>> = parties
            .iter()
            .zip(y.iter())
            .filter_map(|(party_id, (sh, is_valid))| {
                if *is_valid {
                    Some(ShamirSharing::<GF256> {
                        share: sh.bit_compose(bit_idx),
                        party_id: *party_id as u8,
                    })
                } else {
                    None
                }
            })
            .collect();

        let num_new_bot = initial_length - binary_shares.len();
        // apply error correction on z
        // fi(X) = a0 + ... a_t * X^t where a0 is the secret bit corresponding to position i
        let fi_mod2 = error_correction(&binary_shares, degree, max_errs - num_new_bot)?;
        let bitwise = BitwisePoly::from(fi_mod2.clone());

        // remove LSBs computed from error correction in GF(256)
        for (j, (item, is_valid)) in y.iter_mut().enumerate() {
            if *is_valid {
                // compute fi(\gamma_1) ..., fi(\gamma_n) \in GR[Z = {2^64/2^128}]
                let offset = bitwise.lazy_eval(&ordered_powers[j]) << bit_idx;
                *item -= offset;

                //Do the divisibility check of pi, only need to do it if the share is currently valid
                *is_valid = item.multiple_pow2(bit_idx + 1);

                //Log at most once, when share becomes invalid
                if !*is_valid {
                    #[cfg(test)]
                    if let Some(&mut ref mut indices) = err_indices {
                        indices.push((j, bit_idx));
                    }
                    tracing::warn!("Share at index {j} is invalid after iteration {bit_idx}");
                }
            }
        }

        accumulate_and_lift_bitwise_poly(&mut res, &fi_mod2, bit_idx);
    }

    Ok(res)
}

impl<Z: BaseRing> ErrorCorrect for ResiduePoly<Z>
where
    ResiduePoly<Z>: MemoizedExceptionals,
    ResiduePoly<Z>: RingEmbed,
{
    //NIST: Level Zero Operation
    ///Perform error correction for the extension ring.
    ///
    /// - sharing is the set of shares we try to reconstruct the secret from
    /// - degree is the degree of the sharing polynomial (either threshold or `2*threshold`)
    /// - max_errs is the maximum number of errors we try to correct for (most often threshold - len(corrupt_set), but can be less than this if degree is `2*threshold`)
    ///
    /// __NOTE__ : We assume values coming from known malicious parties have been excluded by the caller (i.e. values denoted Bot in NIST doc)
    fn error_correct(
        sharing: &ShamirSharings<ResiduePoly<Z>>,
        degree: usize,
        max_errs: usize,
    ) -> anyhow::Result<Poly<ResiduePoly<Z>>> {
        #[cfg(not(test))]
        {
            shamir_error_correct(sharing, degree, max_errs)
        }
        #[cfg(test)]
        {
            shamir_error_correct(sharing, degree, max_errs, None)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::Wrapping;

    use aes_prng::AesRng;
    use rand::SeedableRng;

    use crate::{
        algebra::{
            error_correction::shamir_error_correct,
            residue_poly::ResiduePoly64,
            structure_traits::{FromU128, One, ZConsts, Zero},
        },
        execution::sharing::{
            shamir::{InputOp, ShamirSharings},
            share::Share,
        },
    };

    #[test]
    fn test_divisibility_fail() {
        let num_parties = 4;
        let threshold = 1;
        let mut rng = AesRng::seed_from_u64(0);
        let secret = ResiduePoly64::from_scalar(Wrapping(10));
        let mut sharing = ShamirSharings::share(&mut rng, secret, num_parties, threshold).unwrap();

        assert_eq!(
            secret,
            shamir_error_correct(&sharing, threshold, threshold, None)
                .unwrap()
                .eval(&ResiduePoly64::ZERO)
        );

        let true_share = sharing.shares[0];
        let modified_value = true_share.value() + ResiduePoly64::ONE;
        let modified_share = Share::new(true_share.owner(), modified_value);
        sharing.shares[0] = modified_share;
        let mut err_indices = Vec::new();
        let _ = shamir_error_correct(&sharing, threshold, threshold, Some(&mut err_indices));
        assert_eq!(err_indices[0], (0, 0));

        let modified_value = true_share.value() + ResiduePoly64::TWO;
        let modified_share = Share::new(true_share.owner(), modified_value);
        sharing.shares[0] = modified_share;
        let mut err_indices = Vec::new();
        let _ = shamir_error_correct(&sharing, threshold, threshold, Some(&mut err_indices));
        assert_eq!(err_indices[0], (0, 1));

        let modified_value = true_share.value() + (ResiduePoly64::from_u128(4));
        let modified_share = Share::new(true_share.owner(), modified_value);
        sharing.shares[0] = modified_share;
        let mut err_indices = Vec::new();
        let _ = shamir_error_correct(&sharing, threshold, threshold, Some(&mut err_indices));
        assert_eq!(err_indices[0], (0, 2));
    }
}

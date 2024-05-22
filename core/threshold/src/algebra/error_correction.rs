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

impl<Z: BaseRing> ErrorCorrect for ResiduePoly<Z>
where
    ResiduePoly<Z>: MemoizedExceptionals,
    ResiduePoly<Z>: RingEmbed,
{
    //NIST: Level Zero Operation
    fn error_correct(
        sharing: &ShamirSharings<ResiduePoly<Z>>,
        threshold: usize,
        max_correctable_errs: usize,
    ) -> anyhow::Result<Poly<ResiduePoly<Z>>> {
        // threshold is the degree of the shamir polynomial
        let ring_size: usize = Z::BIT_LENGTH;

        let mut y: Vec<_> = sharing.shares.iter().map(|x| x.value()).collect();
        let parties: Vec<_> = sharing
            .shares
            .iter()
            .map(|x| x.owner().one_based())
            .collect();

        let ordered_powers: Vec<Vec<ResiduePoly<Z>>> = parties
            .iter()
            .map(|party_id| ResiduePoly::<Z>::exceptional_set(*party_id, threshold))
            .collect::<anyhow::Result<Vec<_>>>()?;

        let mut res = Poly::<ResiduePoly<Z>>::zero();

        for bit_idx in 0..ring_size {
            let binary_shares: Vec<ShamirSharing<GF256>> = parties
                .iter()
                .zip(y.iter())
                .map(|(party_id, sh)| ShamirSharing::<GF256> {
                    share: sh.bit_compose(bit_idx),
                    party_id: *party_id as u8,
                })
                .collect();

            // apply error correction on z
            // fi(X) = a0 + ... a_t * X^t where a0 is the secret bit corresponding to position i
            let fi_mod2 = error_correction(&binary_shares, threshold, max_correctable_errs)?;
            let bitwise = BitwisePoly::from(fi_mod2.clone());

            // remove LSBs computed from error correction in GF(256)
            for (j, item) in y.iter_mut().enumerate() {
                // compute fi(\gamma_1) ..., fi(\gamma_n) \in GR[Z = {2^64/2^128}]
                let offset = bitwise.lazy_eval(&ordered_powers[j]) << bit_idx;
                *item -= offset;
            }

            accumulate_and_lift_bitwise_poly(&mut res, &fi_mod2, bit_idx);
        }

        Ok(res)
    }
}

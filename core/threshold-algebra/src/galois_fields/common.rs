use std::num::NonZero;

use crate::{
    poly::lagrange_polynomials, sharing::shamir::ShamirFieldPoly, structure_traits::Field,
    syndrome::decode_syndrome,
};
use itertools::Itertools;

pub(crate) type LagrangeMap<F> = std::collections::HashMap<Vec<F>, Vec<crate::poly::Poly<F>>>;
/// Builds a LagrangeMap containing pre-computed Lagrange polynomials for all sorted subsets
/// of `{embed(1), ..., embed(num_parties)}` with size ≥ `min_threshold + 1`.
pub(crate) fn build_lagrange_map<F: Field>(
    num_parties: NonZero<usize>,
    min_threshold: usize,
) -> anyhow::Result<LagrangeMap<F>> {
    let num_parties = num_parties.get();
    let all_points: Vec<F> = (1..=num_parties)
        .map(F::get_from_exceptional_sequence)
        .collect::<anyhow::Result<Vec<_>>>()?;
    let mut map = LagrangeMap::new();
    for size in (min_threshold + 1)..=num_parties {
        for subset in all_points.iter().combinations(size) {
            let points: Vec<F> = subset.into_iter().copied().collect();
            let polys = lagrange_polynomials(&points);
            map.insert(points, polys);
        }
    }
    Ok(map)
}

#[allow(unused_variables)]
/// Pre-computes Lagrange polynomial stores for all enabled Galois field types.
/// Must be called at startup with the known number of parties and threshold.
///
/// __NOTE__: GF8 and GF16 are small enough that we can pre-compute all possible lagrange basis.
/// so they are skipped here.
pub fn init_all_lagrange_stores(
    num_parties: NonZero<usize>,
    min_threshold: usize,
) -> anyhow::Result<()> {
    #[cfg(feature = "extension_degree_5")]
    super::gf32::LAGRANGE_STORE
        .set(build_lagrange_map(num_parties, min_threshold)?)
        .ok();
    #[cfg(feature = "extension_degree_6")]
    super::gf64::LAGRANGE_STORE
        .set(build_lagrange_map(num_parties, min_threshold)?)
        .ok();
    #[cfg(feature = "extension_degree_7")]
    super::gf128::LAGRANGE_STORE
        .set(build_lagrange_map(num_parties, min_threshold)?)
        .ok();
    #[cfg(feature = "extension_degree_8")]
    super::gf256::LAGRANGE_STORE
        .set(build_lagrange_map(num_parties, min_threshold)?)
        .ok();
    Ok(())
}

pub fn syndrome_decoding_z2<F: Field + From<u8>>(
    parties: &[usize],
    syndrome: &ShamirFieldPoly<F>,
    threshold: usize,
) -> Vec<F> {
    let xs: Vec<F> = parties.iter().map(|s| F::from(*s as u8)).collect();
    let r = parties.len() - (threshold + 1);
    decode_syndrome(syndrome, &xs, r)
}

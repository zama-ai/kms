use std::num::NonZero;

use crate::{
    poly::lagrange_polynomials,
    structure_traits::{Field, Ring},
};
use itertools::Itertools;

/// Map from evaluation points to their precomputed Lagrange polynomials.
pub type LagrangeMap<F> = std::collections::HashMap<Vec<F>, Vec<crate::poly::Poly<F>>>;

/// Builds a LagrangeMap containing pre-computed Lagrange polynomials for all sorted subsets
/// of `{embed(1), ..., embed(num_parties)}` with size ≥ `min_threshold + 1`.
pub fn build_lagrange_map<F: Field>(
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

/// Pre-computes Lagrange polynomial stores for all enabled Galois field types.
/// Must be called at startup with the known number of parties and threshold.
///
/// __NOTE__: GF8 and GF16 are small enough that we can pre-compute all possible lagrange basis.
/// so they are skipped here.
pub fn init_lagrange_stores(
    num_parties: NonZero<usize>,
    min_threshold: usize,
    extension_degree: usize,
) -> anyhow::Result<()> {
    match extension_degree {
        super::gf32::GF32::EXTENSION_DEGREE => super::gf32::LAGRANGE_STORE
            .set(build_lagrange_map(num_parties, min_threshold)?)
            .map_err(|_| anyhow::anyhow!("Failed to set GF32 Lagrange store")),
        super::gf64::GF64::EXTENSION_DEGREE => super::gf64::LAGRANGE_STORE
            .set(build_lagrange_map(num_parties, min_threshold)?)
            .map_err(|_| anyhow::anyhow!("Failed to set GF64 Lagrange store")),
        super::gf128::GF128::EXTENSION_DEGREE => super::gf128::LAGRANGE_STORE
            .set(build_lagrange_map(num_parties, min_threshold)?)
            .map_err(|_| anyhow::anyhow!("Failed to set GF128 Lagrange store")),
        super::gf256::GF256::EXTENSION_DEGREE => super::gf256::LAGRANGE_STORE
            .set(build_lagrange_map(num_parties, min_threshold)?)
            .map_err(|_| anyhow::anyhow!("Failed to set GF256 Lagrange store")),
        _ => Ok(()),
    }
}

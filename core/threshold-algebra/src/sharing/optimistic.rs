//! Optimistic reconstruction of Shamir sharings: interpolate from `degree + 1` shares, accept only if every
//! other share agrees.

use crate::error_correction::ReconstructionHints;
use crate::sharing::shamir::ShamirSharings;
use crate::sharing::share::Share;
use crate::structure_traits::{ErrorCorrect, Ring};

/// The Lagrange constants of an owner set, prepared for the optimistic reconstruction: the normalized basis
/// `δ_i` of the interpolation set, evaluated at `0` and at the points of the remaining owners.
#[derive(Clone, Debug)]
pub struct OptimisticHints<Z> {
    /// Number of interpolation points: `degree + 1`, the first owners in sorted order.
    interpolation: usize,
    /// `δ_i(0)` for the interpolation points `i`, in order: the secret is `Σ_i δ_i(0) · s_i`.
    /// i.e. basis for interpolation at 0
    secret_basis: Vec<Z>,
    /// For each remaining owner `m`, in order: `δ_i(x_m)` for the interpolation points `i`, so that the share
    /// of `m` is consistent iff `s_m = Σ_i δ_i(x_m) · s_i`.
    /// i.e. set of basis for interpolation at α_m for all remaining owners
    checks_basis: Vec<Vec<Z>>,
}

impl<Z: ErrorCorrect> OptimisticHints<Z> {
    /// Prepares the constants for the evaluation points `points` (one per owner) and the sharing degree.
    /// Returns `None` when fewer than `degree + 1` points are given or the ring does not expose unit
    /// inversion ([`ErrorCorrect::invert_unit`]).
    ///
    /// The constants are positional: `points` must be in the owners' sorted order, the order of the shares of
    /// every sharing they are applied to. [`ReconstructionHints`] builds them from its sorted `parties`, and
    /// [`reconstruct_optimistic`] checks the owners of each sharing against those parties, position by
    /// position, before using them.
    pub fn new(points: &[Z], degree: usize) -> Option<Self> {
        let interpolation = degree + 1;
        if points.len() < interpolation {
            return None;
        }
        let basis = &points[..interpolation];
        // δ_i(y) = ∏_{j ≠ i} (y − x_j) / (x_i − x_j) over the interpolation set, i.e. L_i(y) / L_i(x_i) with
        // L_i the monic numerator; the differences of exceptional points are units.
        let denominators: Vec<Z> = basis
            .iter()
            .enumerate()
            .map(|(i, x_i)| {
                basis
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .fold(Z::ONE, |acc, (_, x_j)| acc * (*x_i - *x_j))
            })
            .collect();
        let inverse_denominators = invert_units(&denominators)?;
        let deltas_at = |y: Z| -> Vec<Z> {
            (0..interpolation)
                .map(|i| {
                    basis
                        .iter()
                        .enumerate()
                        .filter(|(j, _)| *j != i)
                        .fold(inverse_denominators[i], |acc, (_, x_j)| acc * (y - *x_j))
                })
                .collect()
        };
        let secret_basis = deltas_at(Z::ZERO);
        let checks_basis = points[interpolation..]
            .iter()
            .map(|x_m| deltas_at(*x_m))
            .collect();
        Some(Self {
            interpolation,
            secret_basis,
            checks_basis,
        })
    }

    /// Number of interpolation points, `degree + 1`.
    pub fn interpolation(&self) -> usize {
        self.interpolation
    }

    /// The constants `δ_i(0)` of the secret, in the order of the interpolation points.
    pub fn secret_constants(&self) -> &[Z] {
        &self.secret_basis
    }

    /// The constants `δ_i(x_m)` of the `m`-th check, in the order of the interpolation points.
    pub fn check_constants(&self) -> &[Vec<Z>] {
        &self.checks_basis
    }

    /// The optimistic reconstruction of one sharing with the owner set the hints were built for: `Some(secret)`
    /// iff every share beyond the interpolation set lies on the interpolated polynomial.
    fn reconstruct(&self, sharing: &ShamirSharings<Z>) -> Option<Z> {
        let interpolation_shares = &sharing.shares[..self.interpolation];
        for (m, check_basis) in self.checks_basis.iter().enumerate() {
            if lagrange_interpolate(check_basis, interpolation_shares)
                != sharing.shares[self.interpolation + m].value()
            {
                return None;
            }
        }
        Some(lagrange_interpolate(
            &self.secret_basis,
            interpolation_shares,
        ))
    }
}

/// The inverses of `units`, with a single ring inversion (Montgomery's trick): invert the product of them all,
/// then peel it apart with the products of their prefixes. The elements must be units (the differences of
/// exceptional points are); `None` when the ring does not expose unit inversion ([`ErrorCorrect::invert_unit`]).
pub fn invert_units<Z: ErrorCorrect>(units: &[Z]) -> Option<Vec<Z>> {
    let prefixes: Vec<Z> = units
        .iter()
        .scan(Z::ONE, |acc, u| {
            *acc *= *u;
            Some(*acc)
        })
        .collect();
    let mut inverse = Z::invert_unit(prefixes.last().copied().unwrap_or(Z::ONE))?;
    let mut inverses = vec![Z::ZERO; units.len()];
    for i in (0..units.len()).rev() {
        // `inverse` is (u_0 ⋯ u_i)^{-1} here.
        inverses[i] = match i {
            0 => inverse,
            _ => inverse * prefixes[i - 1],
        };
        inverse *= units[i];
    }
    Some(inverses)
}

/// `Σ_i lagrange_basis[i] · shares[i].value()`.
fn lagrange_interpolate<Z: Ring>(lagrange_basis: &[Z], shares: &[Share<Z>]) -> Z {
    lagrange_basis
        .iter()
        .zip(shares)
        .fold(Z::ZERO, |acc, (c, s)| acc + *c * s.value())
}

/// Reconstructs `sharing` optimistically: `Some(secret)` when it has at least `min_shares` shares, its owners
/// are those of `hints`, and every share lies on the polynomial interpolated from the first `degree + 1`;
/// `None` otherwise, which sends the sharing to the error-correcting decoder. All sharings of a batch share
/// their owner set, so the constants prepared in `hints` serve every one of them.
pub fn reconstruct_optimistic<Z: ErrorCorrect>(
    sharing: &ShamirSharings<Z>,
    hints: &ReconstructionHints<Z>,
    min_shares: usize,
) -> Option<Z> {
    let optimistic = hints.optimistic()?;
    let eligible = sharing.shares.len() >= min_shares.max(optimistic.interpolation)
        && sharing.shares.len() == hints.parties.len()
        && sharing
            .shares
            .iter()
            .zip(&hints.parties)
            .all(|(share, party)| share.owner() == *party);
    if eligible {
        optimistic.reconstruct(sharing)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::galois_rings::degree_4::{ResiduePolyF4Z64, ResiduePolyF4Z128};
    use crate::galois_rings::degree_8::ResiduePolyF8Z128;
    use crate::sharing::shamir::{InputOp, RevealOp};
    use crate::structure_traits::{One, RingWithExceptionalSequence, Sample, Zero};
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use threshold_types::role::Role;

    fn reconstruct_batch_optimistic<Z: ErrorCorrect>(
        sharings: &[ShamirSharings<Z>],
        hints: &ReconstructionHints<Z>,
        min_shares: usize,
    ) -> Vec<Option<Z>> {
        sharings
            .iter()
            .map(|sharing| reconstruct_optimistic(sharing, hints, min_shares))
            .collect()
    }

    fn sharings<Z: ErrorCorrect + Sample>(
        rng: &mut StdRng,
        count: usize,
        num_parties: usize,
        degree: usize,
    ) -> (Vec<Z>, Vec<ShamirSharings<Z>>) {
        let secrets: Vec<Z> = (0..count).map(|_| Z::sample(rng)).collect();
        let sharings = secrets
            .iter()
            .map(|s| ShamirSharings::share(rng, *s, num_parties, degree).unwrap())
            .collect();
        (secrets, sharings)
    }

    fn corrupt<Z: ErrorCorrect + Sample>(
        rng: &mut StdRng,
        sharing: &mut ShamirSharings<Z>,
        index: usize,
    ) {
        let share = sharing.shares[index];
        let mut wrong = Z::sample(rng);
        while wrong == share.value() {
            wrong = Z::sample(rng);
        }
        sharing.shares[index] = Share::new(share.owner(), wrong);
    }

    fn check_ring<Z: ErrorCorrect + Sample>() {
        let mut rng = StdRng::seed_from_u64(11);
        for (num_parties, threshold) in [(4, 1), (7, 2), (13, 4)] {
            for degree in [threshold, 2 * threshold] {
                for count in [1, 3, 8, 16, 24, 37] {
                    let (secrets, sharings) = sharings::<Z>(&mut rng, count, num_parties, degree);
                    let hints = ReconstructionHints::new(&sharings[0], degree).unwrap();
                    assert!(hints.optimistic().is_some());
                    let got = reconstruct_batch_optimistic(&sharings, &hints, degree + 1);
                    for (lane, (got, secret)) in got.iter().zip(&secrets).enumerate() {
                        assert_eq!(
                            *got,
                            Some(*secret),
                            "n={num_parties} d={degree} lane {lane}"
                        );
                    }
                    // The same values as the decoder.
                    for (sharing, secret) in sharings.iter().zip(&secrets) {
                        assert_eq!(sharing.reconstruct(degree).unwrap(), *secret);
                    }
                }
            }
        }
    }

    #[test]
    fn honest_batches_reconstruct_for_every_ring() {
        check_ring::<ResiduePolyF4Z128>();
        check_ring::<ResiduePolyF4Z64>();
        check_ring::<ResiduePolyF8Z128>();
    }

    #[test]
    fn a_wrong_share_anywhere_is_detected() {
        let mut rng = StdRng::seed_from_u64(12);
        let (num_parties, threshold) = (13, 4);
        for degree in [threshold, 2 * threshold] {
            let (secrets, sharings) =
                sharings::<ResiduePolyF4Z128>(&mut rng, 16, num_parties, degree);
            let hints = ReconstructionHints::new(&sharings[0], degree).unwrap();
            // What the decoder can correct for this degree: (n - degree - 1) / 2 errors.
            let max_errors = threshold.min((num_parties - degree - 1) / 2);
            // One wrong share per sharing, in every position: inside the interpolation set and outside.
            for position in 0..num_parties {
                let mut corrupted = sharings.clone();
                for sharing in corrupted.iter_mut() {
                    corrupt(&mut rng, sharing, position);
                }
                let got = reconstruct_batch_optimistic(&corrupted, &hints, degree + 1);
                assert!(got.iter().all(Option::is_none), "position {position}");
                // The decoder still recovers the secret (one error is within capacity).
                for (sharing, secret) in corrupted.iter().zip(&secrets) {
                    assert_eq!(
                        sharing.error_reconstruct(degree, max_errors).unwrap(),
                        *secret
                    );
                }
            }
            // Only some sharings corrupted: the others are still accepted.
            let mut mixed = sharings.clone();
            for lane in [0, 5, 15] {
                corrupt(&mut rng, &mut mixed[lane], 2);
            }
            let got = reconstruct_batch_optimistic(&mixed, &hints, degree + 1);
            for (lane, got) in got.iter().enumerate() {
                if [0, 5, 15].contains(&lane) {
                    assert!(got.is_none());
                } else {
                    assert_eq!(*got, Some(secrets[lane]));
                }
            }
        }
    }

    /// `t` colluding parties inside the interpolation set agree on a wrong polynomial: the honest shares
    /// outside the set expose it, for any choice of the colluders.
    #[test]
    fn colluding_interpolation_shares_are_detected() {
        let mut rng = StdRng::seed_from_u64(13);
        let (num_parties, threshold, degree) = (13, 4, 4);
        let (secrets, sharings) = sharings::<ResiduePolyF4Z128>(&mut rng, 8, num_parties, degree);
        let hints = ReconstructionHints::new(&sharings[0], degree).unwrap();
        for _ in 0..20 {
            // Pick t distinct positions among the first degree + 1 (and sometimes beyond).
            let mut positions: Vec<usize> = (0..num_parties).collect();
            let mut colluders = Vec::new();
            for _ in 0..threshold {
                let k = rng.gen_range(0..positions.len());
                colluders.push(positions.swap_remove(k));
            }
            let mut corrupted = sharings.clone();
            for sharing in corrupted.iter_mut() {
                // The colluders replace their shares with those of a random polynomial of the right degree
                // through the *wrong* secret: consistent among themselves, inconsistent with honest shares.
                let wrong_secret = ResiduePolyF4Z128::sample(&mut rng);
                let fake =
                    ShamirSharings::share(&mut rng, wrong_secret, num_parties, degree).unwrap();
                for &c in &colluders {
                    sharing.shares[c] = fake.shares[c];
                }
            }
            let got = reconstruct_batch_optimistic(&corrupted, &hints, degree + 1);
            assert!(got.iter().all(Option::is_none), "colluders {colluders:?}");
            for (sharing, secret) in corrupted.iter().zip(&secrets) {
                assert_eq!(
                    sharing.error_reconstruct(degree, threshold).unwrap(),
                    *secret
                );
            }
        }
    }

    #[test]
    fn short_or_foreign_sharings_are_left_to_the_decoder() {
        let mut rng = StdRng::seed_from_u64(14);
        let (num_parties, degree) = (7, 2);
        let (secrets, sharings) = sharings::<ResiduePolyF4Z128>(&mut rng, 4, num_parties, degree);
        let hints = ReconstructionHints::new(&sharings[0], degree).unwrap();
        // Fewer shares than required by the caller's bound.
        assert!(
            reconstruct_batch_optimistic(&sharings, &hints, num_parties + 1)
                .iter()
                .all(Option::is_none)
        );
        // Exactly the bound.
        assert_eq!(
            reconstruct_batch_optimistic(&sharings, &hints, num_parties),
            secrets.iter().map(|s| Some(*s)).collect::<Vec<_>>()
        );
        // A sharing with a different owner set than the hints.
        let mut other = sharings.clone();
        other[1].shares.remove(3);
        let got = reconstruct_batch_optimistic(&other, &hints, degree + 1);
        assert_eq!(got[0], Some(secrets[0]));
        assert_eq!(got[1], None);
        assert_eq!(got[2], Some(secrets[2]));
        // Hints for a subset of the owners (parties dropped) still reconstruct that subset.
        let mut subset = sharings.clone();
        for sharing in subset.iter_mut() {
            sharing.shares.remove(6);
            sharing.shares.remove(0);
        }
        let subset_hints = ReconstructionHints::new(&subset[0], degree).unwrap();
        assert_eq!(
            reconstruct_batch_optimistic(&subset, &subset_hints, degree + 1),
            secrets.iter().map(|s| Some(*s)).collect::<Vec<_>>()
        );
        // Not enough points for the degree: no optimistic hints at all.
        let too_few: Vec<Role> = (1..=degree).map(Role::indexed_from_one).collect();
        let hints =
            ReconstructionHints::<ResiduePolyF4Z128>::from_parties(too_few, degree).unwrap();
        assert!(hints.optimistic().is_none());
    }

    #[test]
    fn lagrange_constants_interpolate() {
        let mut rng = StdRng::seed_from_u64(15);
        let (num_parties, degree) = (13, 8);
        let (secrets, sharings) = sharings::<ResiduePolyF4Z128>(&mut rng, 1, num_parties, degree);
        let hints = ReconstructionHints::new(&sharings[0], degree).unwrap();
        let optimistic = hints.optimistic().unwrap();
        let basis = &sharings[0].shares[..degree + 1];
        assert_eq!(
            lagrange_interpolate(optimistic.secret_constants(), basis),
            secrets[0]
        );
        for (m, check) in optimistic.check_constants().iter().enumerate() {
            assert_eq!(
                lagrange_interpolate(check, basis),
                sharings[0].shares[degree + 1 + m].value()
            );
        }
        assert_eq!(optimistic.interpolation(), degree + 1);
        assert_eq!(optimistic.check_constants().len(), num_parties - degree - 1);
    }

    #[test]
    fn batched_inversion_inverts_every_unit() {
        type Z = ResiduePolyF4Z128;
        let mut rng = StdRng::seed_from_u64(16);
        for count in [0, 1, 2, 5, 13, 40] {
            // Random units: 2·r + x with x a nonzero point of the exceptional sequence, so that the residue
            // modulo the maximal ideal (2) is x ≠ 0.
            let units: Vec<Z> = (0..count)
                .map(|_| {
                    Z::sample(&mut rng) * (Z::ONE + Z::ONE)
                        + Z::get_from_exceptional_sequence(rng.gen_range(1..16)).unwrap()
                })
                .collect();
            let inverses = invert_units(&units).unwrap();
            assert_eq!(inverses.len(), count);
            for (unit, inverse) in units.iter().zip(&inverses) {
                assert_eq!(*unit * *inverse, Z::ONE);
                assert_eq!(Some(*inverse), Z::invert_unit(*unit));
            }
            // A zero anywhere and nothing is inverted.
            let mut mixed = units.clone();
            mixed.insert(count / 2, Z::ZERO);
            assert!(invert_units(&mixed).is_none());
        }
    }
}

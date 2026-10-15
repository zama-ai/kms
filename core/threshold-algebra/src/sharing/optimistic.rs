//! Optimistic reconstruction of Shamir sharings: interpolate from `degree + 1` shares, accept only if every
//! other share agrees.
//!
//! The error-correcting decoder ([`crate::error_correction`]) handles any share pattern with at most
//! `max_errors` wrong shares, at the price of a Gao decoding per bit of the base ring (64 or 128 of them) for
//! every sharing. In the common case no share is wrong, and then the secret is a fixed linear combination of
//! any `degree + 1` shares. This module takes that path first and leaves the decoder as the fallback for the
//! sharings whose shares disagree.
//!
//! # Security
//!
//! Let `Q` be the true sharing polynomial (degree at most `degree`) and `P` the polynomial interpolated from
//! the first `degree + 1` shares received. The result `P(0)` is accepted only if **every** share received lies
//! on `P`. Suppose it does. The honest parties' shares all lie on `Q`, and the callers only reconstruct once at
//! least `degree + 1` honest shares are present (sync and strong-async mode: more than `degree + 2t` parties
//! heard from, at most `t − bots` of the present shares corrupt; weak-async mode: the caller additionally
//! requires more than `degree + t` shares on the polynomial). So `P` and `Q` agree on at least `degree + 1`
//! points of the exceptional sequence, whose Vandermonde matrix is invertible over the ring, hence `P = Q`.
//! An adversary controlling the shares used for interpolation can make `P ≠ Q`, but then at least one honest
//! share is off `P` and the sharing goes to the decoder, exactly as today. When all shares agree the decoder
//! would return `P` as well (the received word is a codeword), so the output of a reconstruction is the same
//! with or without this path; only the cost changes.
//!
//! # Cost
//!
//! The constants `L_i(0)` and `L_i(x_m)` depend only on the owner set and the degree: they are prepared once
//! per [`crate::error_correction::ReconstructionHints`] (on first use) as [`LinearCombinator`]s, and a batch
//! of sharings with the same owners is evaluated 16 sharings at a time in SIMD lanes (AVX-512 IFMA for
//! `ResiduePolyF4Z128`).
//! Per sharing that is `(n − degree)(degree + 1)` ring products, against the decoder's `n` Gao decodings per
//! base-ring bit.

use crate::error_correction::ReconstructionHints;
use crate::lincomb::LinearCombinator;
use crate::sharing::shamir::ShamirSharings;
use crate::structure_traits::ErrorCorrect;

/// Lane count of the batched evaluation: a full AVX-512 IFMA group.
const LANES: usize = 16;

/// The Lagrange constants of an owner set, prepared for the optimistic reconstruction.
#[derive(Clone, Debug)]
pub struct OptimisticHints<Z> {
    /// Number of interpolation points: `degree + 1`, the first owners in sorted order.
    interpolation: usize,
    /// `L_i(0)` for the interpolation points `i`, in order: the secret is `Σ_i L_i(0) · s_i`.
    secret: LinearCombinator<Z>,
    /// For each remaining owner `m`, in order: `L_i(x_m)` for the interpolation points `i`, so that the share
    /// of `m` is consistent iff `s_m = Σ_i L_i(x_m) · s_i`.
    checks: Vec<LinearCombinator<Z>>,
}

impl<Z: ErrorCorrect> OptimisticHints<Z> {
    /// Prepares the constants for the sorted evaluation points `points` (one per owner) and the sharing
    /// degree. Returns `None` when fewer than `degree + 1` points are given or the ring does not expose unit
    /// inversion ([`ErrorCorrect::invert_unit`]).
    pub fn new(points: &[Z], degree: usize) -> Option<Self> {
        let interpolation = degree + 1;
        if points.len() < interpolation {
            return None;
        }
        let basis = &points[..interpolation];
        // L_i(y) = ∏_{j ≠ i} (y − x_j) / (x_i − x_j); the differences of exceptional points are units.
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
        // One inversion for all of them (Montgomery's trick): invert the product of the denominators, then
        // peel it apart with products of their prefixes.
        let prefixes: Vec<Z> = denominators
            .iter()
            .scan(Z::ONE, |acc, d| {
                *acc *= *d;
                Some(*acc)
            })
            .collect();
        let mut inverse = Z::invert_unit(prefixes[interpolation - 1])?;
        let mut inverse_denominators = vec![Z::ZERO; interpolation];
        for i in (0..interpolation).rev() {
            // `inverse` is (d_0 ⋯ d_i)^{-1} here.
            inverse_denominators[i] = match i {
                0 => inverse,
                _ => inverse * prefixes[i - 1],
            };
            inverse *= denominators[i];
        }
        let lagrange_at = |y: Z| -> Vec<Z> {
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
        let secret = LinearCombinator::new(lagrange_at(Z::ZERO));
        let checks = points[interpolation..]
            .iter()
            .map(|x_m| LinearCombinator::new(lagrange_at(*x_m)))
            .collect();
        Some(Self {
            interpolation,
            secret,
            checks,
        })
    }

    /// Number of interpolation points, `degree + 1`.
    pub fn interpolation(&self) -> usize {
        self.interpolation
    }
}

/// Reconstructs each sharing of `sharings` optimistically: `Some(secret)` when the sharing has at least
/// `min_shares` shares, its owners are those of `hints`, and every share lies on the polynomial interpolated
/// from the first `degree + 1`; `None` otherwise, which sends that sharing to the error-correcting decoder.
/// All sharings of a batch share their owner set, so the prepared constants of `hints` apply to all of them.
pub fn reconstruct_batch_optimistic<Z: ErrorCorrect>(
    sharings: &[ShamirSharings<Z>],
    hints: &ReconstructionHints<Z>,
    min_shares: usize,
) -> Vec<Option<Z>> {
    let Some(optimistic) = hints.optimistic() else {
        return vec![None; sharings.len()];
    };
    let mut out = Vec::with_capacity(sharings.len());
    let min_shares = min_shares.max(optimistic.interpolation);
    for group in sharings.chunks(LANES) {
        let eligible = group.iter().all(|sharing| {
            sharing.shares.len() >= min_shares
                && sharing.shares.len() == hints.parties.len()
                && sharing
                    .shares
                    .iter()
                    .zip(&hints.parties)
                    .all(|(share, party)| share.owner() == *party)
        });
        if !eligible {
            // Mixed or short groups are rare (the batch is filled identically); settle them one at a time.
            for sharing in group {
                let ok = sharing.shares.len() >= min_shares
                    && sharing.shares.len() == hints.parties.len()
                    && sharing
                        .shares
                        .iter()
                        .zip(&hints.parties)
                        .all(|(share, party)| share.owner() == *party);
                out.push(if ok {
                    reconstruct_group::<Z, 1>(std::slice::from_ref(sharing), optimistic)[0]
                } else {
                    None
                });
            }
            continue;
        }
        match group.len() {
            LANES => out.extend(reconstruct_group::<Z, LANES>(group, optimistic)),
            8 => out.extend(reconstruct_group::<Z, 8>(group, optimistic)),
            _ => {
                for sharing in group {
                    out.push(
                        reconstruct_group::<Z, 1>(std::slice::from_ref(sharing), optimistic)[0],
                    );
                }
            }
        }
    }
    out
}

/// The optimistic reconstruction of exactly `L` sharings with the owner set of `hints`, one per lane.
fn reconstruct_group<Z: ErrorCorrect, const L: usize>(
    sharings: &[ShamirSharings<Z>],
    hints: &OptimisticHints<Z>,
) -> [Option<Z>; L] {
    debug_assert_eq!(sharings.len(), L);
    let mut secret = hints.secret.accumulator::<L>();
    let mut checks: Vec<_> = hints.checks.iter().map(|c| c.accumulator::<L>()).collect();
    let mut operands = [Z::ZERO; L];
    for i in 0..hints.interpolation {
        for (operand, sharing) in operands.iter_mut().zip(sharings) {
            *operand = sharing.shares[i].value();
        }
        secret.push_elements(&operands);
        for check in checks.iter_mut() {
            check.push_elements(&operands);
        }
    }
    let secrets = secret.finish();
    let mut consistent = [true; L];
    for (m, check) in checks.into_iter().enumerate() {
        let expected = check.finish();
        for (lane, sharing) in sharings.iter().enumerate() {
            if sharing.shares[hints.interpolation + m].value() != expected[lane] {
                consistent[lane] = false;
            }
        }
    }
    std::array::from_fn(|lane| consistent[lane].then_some(secrets[lane]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::galois_rings::degree_4::{ResiduePolyF4Z64, ResiduePolyF4Z128};
    use crate::galois_rings::degree_8::ResiduePolyF8Z128;
    use crate::sharing::shamir::{InputOp, RevealOp};
    use crate::sharing::share::Share;
    use crate::structure_traits::Sample;
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use threshold_types::role::Role;

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
                // 24 = 16 + 8 (a full group and a half one), 37 = 16 + 16 + 5 (five single sharings).
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
            // Only some lanes corrupted: the others are still accepted.
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
        let values: Vec<ResiduePolyF4Z128> = sharings[0].shares[..degree + 1]
            .iter()
            .map(|s| s.value())
            .collect();
        assert_eq!(
            LinearCombinator::naive(optimistic.secret.constants(), &values),
            secrets[0]
        );
        for (m, check) in optimistic.checks.iter().enumerate() {
            assert_eq!(
                LinearCombinator::naive(check.constants(), &values),
                sharings[0].shares[degree + 1 + m].value()
            );
        }
        assert_eq!(optimistic.interpolation(), degree + 1);
        assert_eq!(optimistic.checks.len(), num_parties - degree - 1);
    }
}

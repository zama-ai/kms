use super::{
    galois_rings::common::{LutMulReduction, ResiduePoly},
    poly::{BitWiseEval, Poly, gao_decoding, gao_decoding_with_field_hints, lagrange_polynomials},
    structure_traits::{
        BaseRing, ErrorCorrect, Field, QuotientMaximalIdeal, RingWithExceptionalSequence,
    },
};
use error_utils::anyhow_error_and_log;

use super::sharing::shamir::ShamirFieldPoly;
use super::sharing::shamir::ShamirSharings;
use super::sharing::share::Share;
use crate::poly::BitwisePoly;
use itertools::Itertools;
use std::collections::HashMap;
use std::sync::RwLock;
use threshold_types::role::Role;

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

/// Precomputed field-level data for Lagrange interpolation and Gao decoding.
///
/// These depend only on the set of evaluation points (i.e. the party identities),
/// not on the actual share values, so they can be reused across many sharings.
pub struct FieldHints<F: Field> {
    /// Field-level embedded evaluation points: `F::embed_role_to_exceptional_sequence(party_i)`.
    pub embedded_points: Vec<F>,
    /// Lagrange basis polynomials `L_i(X)` for the embedded points.
    pub lagrange_polys: Vec<Poly<F>>,
    /// Vanishing polynomial `∏(X - x_i)`.
    pub vanishing_poly: Poly<F>,
}

impl<F: Field> FieldHints<F> {
    /// Build field-level hints from a set of parties.
    pub fn new(parties: &[Role]) -> anyhow::Result<Self> {
        let embedded_points: Vec<F> = parties
            .iter()
            .map(|p| F::embed_role_to_exceptional_sequence(p))
            .try_collect()?;
        let lagrange_polys = if let Some(cached) = F::cached_lagrange_polys(&embedded_points) {
            cached.to_vec()
        } else {
            lagrange_polynomials(&embedded_points)
        };
        let vanishing_poly = Self::compute_vanishing_poly(&embedded_points);
        Ok(Self {
            embedded_points,
            lagrange_polys,
            vanishing_poly,
        })
    }

    fn compute_vanishing_poly(points: &[F]) -> Poly<F> {
        let mut g = Poly::one();
        for xi in points.iter() {
            g = g * Poly::from_coefs(vec![-*xi, F::ONE]);
        }
        g
    }
}

/// Precomputed data that depends only on the set of contributing parties
/// and the degree of the sharing polynomial — not on any share values.
///
/// When reconstructing many [`ShamirSharings`] that share the same owner set
/// and degree, build this once and pass it to each reconstruction call.
pub struct ReconstructionHints<Z: ErrorCorrect> {
    /// The sorted set of party roles that contributed shares.
    pub parties: Vec<Role>,
    /// The degree of the sharing polynomial (threshold or 2×threshold).
    pub degree: usize,
    /// Ring-level embedded evaluation points: `Z::embed_role_to_exceptional_sequence(party_i)`.
    pub embedded_points: Vec<Z>,
    /// `exceptional_powers[i][j]` = `embedded_points[i]^j` for `j` in `0..=degree`.
    ///
    /// Used in the Hensel-lift loop of `shamir_error_correct`.
    pub exceptional_powers: Vec<Vec<Z>>,
    /// Field-level hints for Lagrange interpolation / Gao decoding.
    pub field_hints: FieldHints<Z::ReconstructionField>,
}

impl<Z: ErrorCorrect> ReconstructionHints<Z> {
    /// Build hints from the owner set of a sharing and a degree.
    ///
    /// Typically called once before iterating over a batch of sharings.
    /// Computes exceptional powers directly from the embedded points.
    pub fn new(sharing: &ShamirSharings<Z>, degree: usize) -> anyhow::Result<Self> {
        let parties: Vec<Role> = sharing.shares.iter().map(|s| s.owner()).collect();
        Self::from_parties(&parties, degree)
    }

    /// Build hints from an explicit list of parties and a degree.
    ///
    /// Computes exceptional powers directly from the embedded points.
    pub fn from_parties(parties: &[Role], degree: usize) -> anyhow::Result<Self> {
        let embedded_points: Vec<Z> = parties
            .iter()
            .map(|p| Z::embed_role_to_exceptional_sequence(p))
            .try_collect()?;
        let exceptional_powers: Vec<Vec<Z>> = embedded_points
            .iter()
            .map(|point| {
                let mut powers = Vec::with_capacity(degree + 1);
                let mut current = Z::ONE;
                powers.push(current);
                for _ in 1..=degree {
                    current *= *point;
                    powers.push(current);
                }
                powers
            })
            .collect();
        let field_hints = FieldHints::new(parties)?;
        Ok(Self {
            parties: parties.to_vec(),
            degree,
            embedded_points,
            exceptional_powers,
            field_hints,
        })
    }
}

impl<Z: ErrorCorrect + MemoizedExceptionals> ReconstructionHints<Z> {
    /// Like [`Self::from_parties`] but fetches exceptional powers from the
    /// [`MemoizedExceptionals`] cache instead of recomputing them.
    pub fn from_parties_cached(parties: &[Role], degree: usize) -> anyhow::Result<Self> {
        let embedded_points: Vec<Z> = parties
            .iter()
            .map(|p| Z::embed_role_to_exceptional_sequence(p))
            .try_collect()?;
        let exceptional_powers: Vec<Vec<Z>> = parties
            .iter()
            .map(|p| Z::exceptional_set(p.one_based(), degree))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let field_hints = FieldHints::new(parties)?;
        Ok(Self {
            parties: parties.to_vec(),
            degree,
            embedded_points,
            exceptional_powers,
            field_hints,
        })
    }
}

/// Lifts binary polynomial p to the big ring and accumulates 2^amount * p into res
fn accumulate_and_lift_bitwise_poly<Z: BaseRing, const EXTENSION_DEGREE: usize>(
    res: &mut Poly<ResiduePoly<Z, EXTENSION_DEGREE>>,
    p: &Poly<<ResiduePoly<Z, EXTENSION_DEGREE> as QuotientMaximalIdeal>::QuotientOutput>,
    amount: usize,
) where
    ResiduePoly<Z, EXTENSION_DEGREE>: QuotientMaximalIdeal,
{
    for (i, coef) in p.coefs().iter().enumerate() {
        let c8: u8 = (*coef).into();
        for d in 0..EXTENSION_DEGREE {
            if ((c8 >> d) & 1) != 0 {
                // NOTE: get_mut will not panic here because it'll create extra coefficients if needed
                res.get_mut(i).coefs[d] += Z::ONE << amount;
            }
        }
    }
}

fn shamir_error_correct<Z: BaseRing, const EXTENSION_DEGREE: usize>(
    sharing: &ShamirSharings<ResiduePoly<Z, EXTENSION_DEGREE>>,
    degree: usize,
    max_errs: usize,
    #[cfg(test)] err_indices: Option<&mut Vec<(threshold_types::role::Role, usize)>>,
) -> anyhow::Result<Poly<ResiduePoly<Z, EXTENSION_DEGREE>>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: MemoizedExceptionals,
    ResiduePoly<Z, EXTENSION_DEGREE>: RingWithExceptionalSequence,
    ResiduePoly<Z, EXTENSION_DEGREE>: QuotientMaximalIdeal,
    ResiduePoly<Z, EXTENSION_DEGREE>: LutMulReduction<Z>,
    BitwisePoly:
        From<Poly<<ResiduePoly<Z, EXTENSION_DEGREE> as QuotientMaximalIdeal>::QuotientOutput>>,
    BitwisePoly: BitWiseEval<Z, EXTENSION_DEGREE>,
{
    // threshold is the degree of the shamir polynomial
    let ring_size: usize = Z::BIT_LENGTH;

    //Start with all values being valid (none of them are Bot)
    let mut shares_with_validity = sharing
        .shares
        .iter()
        .map(|x| (*x, true))
        .collect::<Vec<_>>();

    let initial_length = shares_with_validity.len();

    let parties: Vec<_> = sharing
        .shares
        .iter()
        .map(|x| x.owner().one_based())
        .collect();

    let ordered_powers: Vec<Vec<ResiduePoly<Z, EXTENSION_DEGREE>>> = parties
        .iter()
        .map(|party_id| ResiduePoly::<Z, EXTENSION_DEGREE>::exceptional_set(*party_id, degree))
        .collect::<anyhow::Result<Vec<_>>>()?;

    let mut res = Poly::<ResiduePoly<Z, EXTENSION_DEGREE>>::zero();

    for bit_idx in 0..ring_size {
        //Compute z = pi(y/2^i), where Bots are filtered out
        let binary_shares: Vec<
            Share<<ResiduePoly<Z, EXTENSION_DEGREE> as QuotientMaximalIdeal>::QuotientOutput>,
        > = shares_with_validity
            .iter()
            .filter_map(|(sh, is_valid)| {
                if *is_valid {
                    Some(Share::<
                        <ResiduePoly<Z, EXTENSION_DEGREE> as QuotientMaximalIdeal>::QuotientOutput,
                    >::new(
                        sh.owner(), sh.value().bit_compose(bit_idx)
                    ))
                } else {
                    None
                }
            })
            .collect();

        let num_new_bot = initial_length - binary_shares.len();
        // apply error correction on z
        // fi(X) = a0 + ... a_t * X^t where a0 is the secret bit corresponding to position i
        let fi_mod2 = error_correction(binary_shares, degree, max_errs - num_new_bot)?;
        let bitwise = BitwisePoly::from(fi_mod2.clone());

        // remove LSBs computed from error correction in GF(256)
        for (j, (share, is_valid)) in shares_with_validity.iter_mut().enumerate() {
            if *is_valid {
                // compute fi(\gamma_1) ..., fi(\gamma_n) \in GR[Z = {2^64/2^128}]
                let offset = bitwise.lazy_eval(&ordered_powers[j]) << bit_idx;
                *share -= offset;

                //Do the divisibility check of pi, only need to do it if the share is currently valid
                *is_valid = share.value().multiple_pow2(bit_idx + 1);

                //Log at most once, when share becomes invalid
                if !*is_valid {
                    #[cfg(test)]
                    if let Some(&mut ref mut indices) = err_indices {
                        indices.push((share.owner(), bit_idx));
                    }
                    tracing::warn!("Share at index {j} is invalid after iteration {bit_idx}");
                }
            }
        }

        accumulate_and_lift_bitwise_poly(&mut res, &fi_mod2, bit_idx);
    }

    Ok(res)
}

/// Like [`shamir_error_correct`] but reuses precomputed [`ReconstructionHints`].
///
/// The exceptional powers and field hints are taken from the hints structure instead of being
/// recomputed, and the field hints are reused across Hensel-lift iterations as long as no
/// party is evicted.
fn shamir_error_correct_with_hints<Z: BaseRing, const EXTENSION_DEGREE: usize>(
    sharing: &ShamirSharings<ResiduePoly<Z, EXTENSION_DEGREE>>,
    degree: usize,
    max_errs: usize,
    hints: &ReconstructionHints<ResiduePoly<Z, EXTENSION_DEGREE>>,
) -> anyhow::Result<Poly<ResiduePoly<Z, EXTENSION_DEGREE>>>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: MemoizedExceptionals,
    ResiduePoly<Z, EXTENSION_DEGREE>:
        ErrorCorrect<ReconstructionField = <ResiduePoly<Z, EXTENSION_DEGREE> as QuotientMaximalIdeal>::QuotientOutput>,
    ResiduePoly<Z, EXTENSION_DEGREE>: RingWithExceptionalSequence,
    ResiduePoly<Z, EXTENSION_DEGREE>: QuotientMaximalIdeal,
    ResiduePoly<Z, EXTENSION_DEGREE>: LutMulReduction<Z>,
    BitwisePoly:
        From<Poly<<ResiduePoly<Z, EXTENSION_DEGREE> as QuotientMaximalIdeal>::QuotientOutput>>,
    BitwisePoly: BitWiseEval<Z, EXTENSION_DEGREE>,
{
    let ring_size: usize = Z::BIT_LENGTH;

    let mut shares_with_validity = sharing
        .shares
        .iter()
        .map(|x| (*x, true))
        .collect::<Vec<_>>();

    let initial_length = shares_with_validity.len();

    // Use exceptional powers from hints (avoids RwLock + clone per party).
    let ordered_powers = &hints.exceptional_powers;

    let mut res = Poly::<ResiduePoly<Z, EXTENSION_DEGREE>>::zero();

    // Track whether any party has been evicted. As long as no eviction has happened
    // the field hints (Lagrange polys, vanishing poly) remain valid.
    let mut validity_changed = false;
    // Lazily computed field hints for the reduced valid set after evictions.
    let mut fallback_field_hints: Option<
        FieldHints<<ResiduePoly<Z, EXTENSION_DEGREE> as QuotientMaximalIdeal>::QuotientOutput>,
    > = None;

    for bit_idx in 0..ring_size {
        let binary_shares: Vec<
            Share<<ResiduePoly<Z, EXTENSION_DEGREE> as QuotientMaximalIdeal>::QuotientOutput>,
        > = shares_with_validity
            .iter()
            .filter_map(|(sh, is_valid)| {
                if *is_valid {
                    Some(Share::<
                        <ResiduePoly<Z, EXTENSION_DEGREE> as QuotientMaximalIdeal>::QuotientOutput,
                    >::new(
                        sh.owner(), sh.value().bit_compose(bit_idx)
                    ))
                } else {
                    None
                }
            })
            .collect();

        let num_new_bot = initial_length - binary_shares.len();

        let fi_mod2 = if !validity_changed {
            // All parties still valid — use the precomputed field hints.
            error_correction_with_field_hints(
                binary_shares,
                degree,
                max_errs - num_new_bot,
                &hints.field_hints,
            )?
        } else {
            // Some parties were evicted — recompute field hints for the new valid set
            // (or reuse previously computed fallback if validity hasn't changed again).
            if fallback_field_hints.is_none() {
                let valid_parties: Vec<Role> = shares_with_validity
                    .iter()
                    .filter_map(|(sh, valid)| if *valid { Some(sh.owner()) } else { None })
                    .collect();
                fallback_field_hints = Some(FieldHints::new(&valid_parties)?);
            }
            error_correction_with_field_hints(
                binary_shares,
                degree,
                max_errs - num_new_bot,
                fallback_field_hints.as_ref().unwrap(),
            )?
        };
        let bitwise = BitwisePoly::from(fi_mod2.clone());

        let mut evicted_this_round = false;
        for (j, (share, is_valid)) in shares_with_validity.iter_mut().enumerate() {
            if *is_valid {
                let offset = bitwise.lazy_eval(&ordered_powers[j]) << bit_idx;
                *share -= offset;

                *is_valid = share.value().multiple_pow2(bit_idx + 1);

                if !*is_valid {
                    tracing::warn!("Share at index {j} is invalid after iteration {bit_idx}");
                    evicted_this_round = true;
                }
            }
        }

        if evicted_this_round {
            validity_changed = true;
            // Invalidate fallback hints so they get recomputed for the new valid set.
            fallback_field_hints = None;
        }

        accumulate_and_lift_bitwise_poly(&mut res, &fi_mod2, bit_idx);
    }

    Ok(res)
}

impl<Z: BaseRing, const EXTENSION_DEGREE: usize> ErrorCorrect for ResiduePoly<Z, EXTENSION_DEGREE>
where
    ResiduePoly<Z, EXTENSION_DEGREE>: MemoizedExceptionals,
    ResiduePoly<Z, EXTENSION_DEGREE>: RingWithExceptionalSequence,
    ResiduePoly<Z, EXTENSION_DEGREE>: QuotientMaximalIdeal,
    ResiduePoly<Z, EXTENSION_DEGREE>: LutMulReduction<Z>,
    BitwisePoly:
        From<Poly<<ResiduePoly<Z, EXTENSION_DEGREE> as QuotientMaximalIdeal>::QuotientOutput>>,
    BitwisePoly: BitWiseEval<Z, EXTENSION_DEGREE>,
{
    type ReconstructionField =
        <ResiduePoly<Z, EXTENSION_DEGREE> as QuotientMaximalIdeal>::QuotientOutput;

    //NIST: Level Zero Operation
    ///Perform error correction for the extension ring.
    ///
    /// - sharing is the set of shares we try to reconstruct the secret from
    /// - degree is the degree of the sharing polynomial (either threshold or `2*threshold`)
    /// - max_errs is the maximum number of errors we try to correct for (most often threshold - len(corrupt_set), but can be less than this if degree is `2*threshold`)
    ///
    /// __NOTE__ : We assume values coming from known malicious parties have been excluded by the caller (i.e. values denoted Bot in NIST doc)
    fn error_correct(
        sharing: &ShamirSharings<Self>,
        degree: usize,
        max_errs: usize,
    ) -> anyhow::Result<Poly<Self>> {
        #[cfg(not(test))]
        {
            shamir_error_correct(sharing, degree, max_errs)
        }
        #[cfg(test)]
        {
            shamir_error_correct(sharing, degree, max_errs, None)
        }
    }

    fn error_correct_with_hints(
        sharing: &ShamirSharings<Self>,
        degree: usize,
        max_errs: usize,
        hints: &ReconstructionHints<Self>,
    ) -> anyhow::Result<Poly<Self>> {
        shamir_error_correct_with_hints(sharing, degree, max_errs, hints)
    }
}

pub fn error_correction<F: Field>(
    shares: Vec<Share<F>>,
    degree: usize,
    max_errs: usize,
) -> anyhow::Result<ShamirFieldPoly<F>> {
    let xs: Vec<F> = shares
        .iter()
        .map(|s| F::embed_role_to_exceptional_sequence(&s.owner()))
        .try_collect()?;
    let ys: Vec<F> = shares.into_iter().map(|s| s.take_value()).collect();

    // call Gao decoding with the shares as points/values, set Gao parameter k = v = degree+1
    gao_decoding(&xs, &ys, degree + 1, max_errs)
}

/// Like [`error_correction`] but reuses precomputed [`FieldHints`] to avoid redundant
/// embedding, Lagrange polynomial, and vanishing polynomial computations.
///
/// `field_hints` must have been built from the same set of parties that own the `shares`.
pub fn error_correction_with_field_hints<F: Field>(
    shares: Vec<Share<F>>,
    degree: usize,
    max_errs: usize,
    field_hints: &FieldHints<F>,
) -> anyhow::Result<ShamirFieldPoly<F>> {
    let ys: Vec<F> = shares.into_iter().map(|s| s.take_value()).collect();

    gao_decoding_with_field_hints(
        &field_hints.embedded_points,
        &ys,
        degree + 1,
        max_errs,
        &field_hints.lagrange_polys,
        &field_hints.vanishing_poly,
    )
}

#[cfg(test)]
mod tests {
    use std::num::Wrapping;
    use threshold_types::role::Role;

    use aes_prng::AesRng;
    use rand::SeedableRng;

    #[cfg(feature = "extension_degree_3")]
    use crate::galois_fields::gf8::GF8;
    #[cfg(feature = "extension_degree_5")]
    use crate::galois_fields::gf32::GF32;
    #[cfg(feature = "extension_degree_6")]
    use crate::galois_fields::gf64::GF64;
    #[cfg(feature = "extension_degree_7")]
    use crate::galois_fields::gf128::GF128;
    #[cfg(feature = "extension_degree_8")]
    use crate::galois_fields::gf256::GF256;
    use crate::{
        base_ring::Z64,
        error_correction::{error_correction, shamir_error_correct},
        galois_fields::gf16::GF16,
        galois_rings::common::{LutMulReduction, ResiduePoly},
        poly::{BitWiseEval, BitwisePoly, Poly},
        sharing::{
            shamir::{InputOp, ShamirFieldPoly, ShamirSharings},
            share::Share,
        },
        structure_traits::{
            Field, FromU128, One, QuotientMaximalIdeal, RingWithExceptionalSequence, ZConsts, Zero,
        },
    };

    use super::MemoizedExceptionals;

    #[test]
    fn test_divisibility_fail_f4() {
        test_divisibility_fail::<4>();
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    fn test_divisibility_fail_f3() {
        test_divisibility_fail::<3>();
    }

    #[cfg(feature = "extension_degree_5")]
    #[test]
    fn test_divisibility_fail_f5() {
        test_divisibility_fail::<5>();
    }

    #[cfg(feature = "extension_degree_6")]
    #[test]
    fn test_divisibility_fail_f6() {
        test_divisibility_fail::<6>();
    }

    #[cfg(feature = "extension_degree_7")]
    #[test]
    fn test_divisibility_fail_f7() {
        test_divisibility_fail::<7>();
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    fn test_divisibility_fail_f8() {
        test_divisibility_fail::<8>();
    }

    fn test_divisibility_fail<const EXTENSION_DEGREE: usize>()
    where
        ResiduePoly<Z64, EXTENSION_DEGREE>: MemoizedExceptionals,
        ResiduePoly<Z64, EXTENSION_DEGREE>: RingWithExceptionalSequence,
        ResiduePoly<Z64, EXTENSION_DEGREE>: QuotientMaximalIdeal,
        ResiduePoly<Z64, EXTENSION_DEGREE>: LutMulReduction<Z64>,
        BitwisePoly: From<
            Poly<<ResiduePoly<Z64, EXTENSION_DEGREE> as QuotientMaximalIdeal>::QuotientOutput>,
        >,
        BitwisePoly: BitWiseEval<Z64, EXTENSION_DEGREE>,
    {
        let num_parties = 4;
        let threshold = 1;
        let mut rng = AesRng::seed_from_u64(0);
        let secret = ResiduePoly::<Z64, EXTENSION_DEGREE>::from_scalar(Wrapping(10));
        let mut sharing = ShamirSharings::share(&mut rng, secret, num_parties, threshold).unwrap();

        assert_eq!(
            secret,
            shamir_error_correct(&sharing, threshold, threshold, None)
                .unwrap()
                .eval(&ResiduePoly::<Z64, EXTENSION_DEGREE>::ZERO)
        );

        let true_share = sharing.shares[0];
        let modified_value = true_share.value() + ResiduePoly::<Z64, EXTENSION_DEGREE>::ONE;
        let modified_share = Share::new(true_share.owner(), modified_value);
        sharing.shares[0] = modified_share;
        let mut err_indices = Vec::new();
        let _ = shamir_error_correct(&sharing, threshold, threshold, Some(&mut err_indices));
        assert_eq!(err_indices[0], (Role::indexed_from_zero(0), 0));

        let modified_value = true_share.value() + ResiduePoly::<Z64, EXTENSION_DEGREE>::TWO;
        let modified_share = Share::new(true_share.owner(), modified_value);
        sharing.shares[0] = modified_share;
        let mut err_indices = Vec::new();
        let _ = shamir_error_correct(&sharing, threshold, threshold, Some(&mut err_indices));
        assert_eq!(err_indices[0], (Role::indexed_from_zero(0), 1));

        let modified_value =
            true_share.value() + (ResiduePoly::<Z64, EXTENSION_DEGREE>::from_u128(4));
        let modified_share = Share::new(true_share.owner(), modified_value);
        sharing.shares[0] = modified_share;
        let mut err_indices = Vec::new();
        let _ = shamir_error_correct(&sharing, threshold, threshold, Some(&mut err_indices));
        assert_eq!(err_indices[0], (Role::indexed_from_zero(0), 2));
    }

    #[test]
    fn test_error_correction_f4() {
        test_error_correction::<GF16>();
    }

    #[cfg(feature = "extension_degree_3")]
    #[test]
    fn test_error_correction_f3() {
        test_error_correction::<GF8>();
    }

    #[cfg(feature = "extension_degree_5")]
    #[test]
    fn test_error_correction_f5() {
        test_error_correction::<GF32>();
    }

    #[cfg(feature = "extension_degree_6")]
    #[test]
    fn test_error_correction_f6() {
        test_error_correction::<GF64>();
    }

    #[cfg(feature = "extension_degree_7")]
    #[test]
    fn test_error_correction_f7() {
        test_error_correction::<GF128>();
    }

    #[cfg(feature = "extension_degree_8")]
    #[test]
    fn test_error_correction_f8() {
        test_error_correction::<GF256>();
    }

    fn test_error_correction<BaseField: Field>() {
        let f = ShamirFieldPoly::<BaseField>::from_coefs(vec![
            BaseField::from_u128(25),
            BaseField::from_u128(2),
            BaseField::from_u128(233),
        ]);

        let num_parties = 7;
        let threshold = f.coefs().len() - 1; // = 2 here
        let max_err = (num_parties - threshold) / 2; // = 2 here

        let mut shares: Vec<_> = (1..=num_parties)
            .map(|x| {
                let party = Role::indexed_from_one(x);
                let point = f.eval(&BaseField::embed_role_to_exceptional_sequence(&party).unwrap());
                Share::<BaseField>::new(party, point)
            })
            .collect();

        // modify shares of parties 1 and 2
        shares[1] += BaseField::from_u128(9);
        shares[2] += BaseField::from_u128(254);

        let secret_poly = error_correction(shares, threshold, max_err).unwrap();
        assert_eq!(secret_poly, f);
    }
}

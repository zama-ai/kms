use super::{
    galois_rings::common::{LutMulReduction, ResiduePoly},
    structure_traits::{Field, Invert, One, Ring, RingWithExceptionalSequence, Sample, Zero},
};
use error_utils::anyhow_error_and_log;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::ops::{Add, AddAssign, Div, Mul, Sub, SubAssign};

/// Generic polynomial struct
/// Constructing the polynomial should be done using `Poly::from_coefs`
/// since it compresses the polynomial by removing leading zeros.
#[derive(Serialize, Deserialize, Hash, Clone, Default, Debug)]
pub struct Poly<F> {
    coefs: Vec<F>,
}

/// A borrowed view of a polynomial whose coefficients are interpreted as bit strings.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BitWisePoly<'a, F> {
    poly: &'a Poly<F>,
}

impl<'a, F> From<&'a Poly<F>> for BitWisePoly<'a, F> {
    fn from(poly: &'a Poly<F>) -> Self {
        Self { poly }
    }
}

impl<F> BitWisePoly<'_, F> {
    /// Return the borrowed field coefficients.
    pub(crate) fn coefs(&self) -> &[F] {
        self.poly.coefs()
    }
}

/// Evaluate a bitwise polynomial over `GF(2^EXTENSION_DEGREE)` at a Galois-ring point.
/// The evaluation lifts each coefficient to `GR(2^k, EXTENSION_DEGREE)` on demand.
pub trait BitWiseEval<Z, const EXTENSION_DEGREE: usize>
where
    Z: Zero + for<'a> AddAssign<&'a Z> + Copy + Clone,
    ResiduePoly<Z, EXTENSION_DEGREE>: LutMulReduction<Z>,
{
    fn lazy_eval(
        &self,
        powers: &[ResiduePoly<Z, EXTENSION_DEGREE>],
    ) -> ResiduePoly<Z, EXTENSION_DEGREE>;
}

/// Generic implementation of [BitWiseEval::lazy_eval].
///
/// Each coefficient is a `GF(2^EXTENSION_DEGREE)` element packed into a `u8`, so `EXTENSION_DEGREE`
/// is at most 8. The result is the unreduced product of two polynomials with `EXTENSION_DEGREE`
/// coefficients each, so `PRODUCT_LENGTH` is at least `2 * EXTENSION_DEGREE - 1`. Both bounds are
/// checked at compile time.
pub(crate) fn bitwise_eval_coefficients<
    Z,
    F,
    const EXTENSION_DEGREE: usize,
    const PRODUCT_LENGTH: usize,
>(
    coefs: &[F],
    powers: &[ResiduePoly<Z, EXTENSION_DEGREE>],
) -> [Z; PRODUCT_LENGTH]
where
    Z: Zero + for<'a> AddAssign<&'a Z> + Copy + Clone,
    F: Copy + Into<u8>,
{
    // Surplus powers are harmless (the missing high coefficients are zero and contribute nothing),
    // so only the other direction is an error — and it can only be a bug.
    assert!(
        coefs.len() <= powers.len(),
        "Not enough powers supplied for bitwise evaluation. Only {:?} are supplied but {:?} are needed.",
        powers.len(),
        coefs.len()
    );

    const {
        assert!(
            EXTENSION_DEGREE <= u8::BITS as usize,
            "bitwise_eval_coefficients requires EXTENSION_DEGREE <= 8 (coefficients are stored in a u8)"
        );
        // `result[power_idx + bit_idx]` below reaches index `2 * EXTENSION_DEGREE - 2` at most,
        // because both `power_idx` and `bit_idx` are below `EXTENSION_DEGREE`.
        assert!(
            PRODUCT_LENGTH >= 2 * EXTENSION_DEGREE - 1,
            "bitwise_eval_coefficients requires PRODUCT_LENGTH >= 2 * EXTENSION_DEGREE - 1"
        );
    }

    let mut result = [Z::ZERO; PRODUCT_LENGTH];
    for (coef, power) in coefs.iter().zip(powers) {
        // Bit b of this byte is the lifted ring coefficient of X^b; bits >= D are always clear.
        let coef: u8 = (*coef).into();
        for bit_idx in 0..EXTENSION_DEGREE {
            if ((coef >> bit_idx) & 1) == 1 {
                // Multiplying by a 1 bit is a shift by X^bit_idx, i.e. add `power` into `result`
                // offset by bit_idx. A 0 bit contributes nothing, so it is simply skipped.
                for (power_idx, power_coef) in power.coefs.iter().enumerate() {
                    result[power_idx + bit_idx] += power_coef;
                }
            }
        }
    }
    result
}

impl<Z> Poly<Z> {
    pub fn coef(&self, idx: usize) -> Z
    where
        Z: Zero + Copy,
    {
        if idx < self.coefs.len() {
            self.coefs[idx]
        } else {
            Z::ZERO
        }
    }

    pub fn coefs(&self) -> &[Z] {
        &self.coefs
    }

    pub fn set_coef(&mut self, idx: usize, value: Z)
    where
        Z: Zero + Copy,
    {
        if idx < self.coefs.len() {
            self.coefs[idx] = value;
        } else {
            // extend the coefficients vector with zeros if needed
            self.coefs.resize(idx + 1, Z::ZERO);
            self.coefs[idx] = value;
        }
    }

    /// Return coefficients as a mutable slice.
    #[inline(always)]
    pub(crate) fn coefs_mut(&mut self) -> &mut [Z] {
        &mut self.coefs
    }

    pub fn get_mut(&mut self, idx: usize) -> &mut Z
    where
        Z: Zero + Copy,
    {
        if idx < self.coefs.len() {
            &mut self.coefs[idx]
        } else {
            self.set_coef(idx, Z::ZERO);
            self.get_mut(idx)
        }
    }

    pub fn into_container(self) -> Vec<Z> {
        self.coefs
    }
}

impl<Z> Poly<Z>
where
    Z: RingWithExceptionalSequence,
    Z: Invert,
{
    ///Outputs a vector of the monomials (X - embed(party_id))/(party_id)
    /// for all party_id in \[num_parties\]
    /// as well as the vector of party's points
    ///
    /// **NOTE: THE VECTOR IS ZERO INDEXED**
    pub fn normalized_parties_root(num_parties: usize) -> anyhow::Result<(Vec<Self>, Vec<Z>)> {
        // compute lifted, negated and inverted gamma values once, i.e. Lagrange coefficients
        //TODO: This could be memoized
        let mut inv_coefs = (1..=num_parties)
            .map(|idx| {
                let gamma = Z::get_from_exceptional_sequence(idx)?;
                Z::invert(Z::ZERO - gamma)
            })
            .collect::<Result<Vec<_>, _>>()?;
        inv_coefs.insert(0, Z::ZERO);

        // embed party IDs as invertible x-points on the polynomial
        //TODO: This could be memoized
        let x_coords: Vec<_> = (0..=num_parties)
            .map(Z::get_from_exceptional_sequence)
            .collect::<Result<Vec<_>, _>>()?;

        // compute additive inverse of embedded party IDs
        //TODO: This could be memoized
        let neg_parties: Vec<_> = (0..=num_parties)
            .map(|p| Self::from_coefs(vec![Z::ZERO - x_coords[p]]))
            .collect::<Vec<_>>();

        // make a polynomial F(X)=X
        let x = Self::from_coefs(vec![Z::ZERO, Z::ONE]);
        let mut res = Vec::<Self>::with_capacity(num_parties);
        for p in 1..=num_parties {
            res.push((x.clone() + neg_parties[p].clone()) * Self::from_coefs(vec![inv_coefs[p]]))
        }
        Ok((res, x_coords))
    }
}

impl<R: PartialEq + Zero> PartialEq for Poly<R> {
    fn eq(&self, other: &Self) -> bool {
        let common_len = usize::min(self.coefs.len(), other.coefs.len());
        for i in 0..common_len {
            if self.coefs[i] != other.coefs[i] {
                return false;
            }
        }
        let longest = if self.coefs.len() >= other.coefs.len() {
            &self.coefs
        } else {
            &other.coefs
        };
        for coef in longest.iter().skip(common_len) {
            if coef != &R::ZERO {
                return false;
            }
        }
        true
    }
}

impl<R: Eq + Zero> Eq for Poly<R> {}

impl<F> Poly<F>
where
    F: Zero,
    F: Copy,
    F: Mul<F, Output = F>,
    F: Add<F, Output = F>,
{
    /// evaluate the polynomial at a given point
    pub fn eval(&self, point: &F) -> F {
        let mut res = F::ZERO;
        for coef in self.coefs.iter().rev() {
            res = res * *point + *coef;
        }
        res
    }
}
impl<F> Poly<F>
where
    F: Zero,
    F: PartialEq,
{
    pub fn from_coefs(coefs: Vec<F>) -> Self {
        let mut poly = Poly { coefs };
        poly.compress();
        poly
    }

    /// Construct a [`Poly`] from coefficients without compression.
    ///
    /// Callers must guarantee that `coefs` is canonical: either the zero-polynomial or with a non-zero last
    /// coefficient.
    pub(crate) fn from_coefs_unchecked(coefs: Vec<F>) -> Self {
        Poly { coefs }
    }

    pub fn pop(&mut self) -> Option<F> {
        if self.coefs.is_empty() {
            None
        } else {
            let last = self.coefs.pop().unwrap();
            Some(last)
        }
    }

    /// remove zero-coefficients from the highest degree variables
    pub(crate) fn compress(&mut self) {
        while let Some(c) = self.coefs.last() {
            if c == &F::ZERO {
                self.coefs.pop();
            } else {
                break;
            }
        }
    }
}

impl<F> Poly<F>
where
    F: Zero,
    F: PartialEq,
    F: Copy,
{
    /// the degree of the polynomial, i.e., the highest exponent of the variable whose coefficient is not zero.
    pub fn deg(&self) -> usize {
        for (i, item) in self.coefs.iter().enumerate().rev() {
            if item != &F::ZERO {
                return i;
            }
        }
        0
    }

    /// check if poly is all-zero
    pub fn is_zero(&self) -> bool {
        for c in self.coefs.iter() {
            if c != &F::ZERO {
                return false;
            }
        }
        true
    }

    /// return a poly that is constant zero
    pub const fn zero() -> Self {
        Poly {
            // an empty polynomial is considered zero
            coefs: vec![],
        }
    }

    /// Returns the zero polynomial with space reserved for `capacity` coefficients.
    ///
    /// Unlike [`Poly::zeros`], the result is compressed. The reserved space lets in-place updates
    /// grow the polynomial up to `capacity` coefficients without a reallocation.
    pub(crate) fn zero_with_capacity(capacity: usize) -> Self {
        Poly {
            coefs: Vec::with_capacity(capacity),
        }
    }

    /// return a poly that is constant zero and has n zero coefficients
    ///
    /// Note that this polynomial is *not* compressed!
    /// The caller should make sure compress is called
    /// at the end of the operation that uses this zero polynoimal.
    pub(crate) fn zeros(n: usize) -> Self {
        Poly {
            coefs: vec![F::ZERO; n],
        }
    }

    /// return the highest non-zero coefficient, or zero else
    fn highest_coefficient(&self) -> F {
        for c in self.coefs.iter().rev() {
            if c != &F::ZERO {
                return *c;
            }
        }
        F::ZERO
    }
}

impl<F: Field> Poly<F> {
    pub fn formal_derivative(&self) -> Self {
        if self.deg() > 0 {
            let mut coefs = self.coefs[1..].to_vec();
            let mut mul = F::ONE;
            for c in &mut coefs {
                *c *= mul;
                mul += F::ONE;
            }
            return Poly { coefs };
        }
        Poly {
            coefs: vec![F::ZERO],
        }
    }
}

impl<F> Poly<F>
where
    F: One,
{
    pub fn one() -> Self {
        Poly {
            coefs: vec![F::ONE],
        }
    }
}

impl<F> Poly<F>
where
    F: Sample,
    F: Zero + One,
    F: PartialEq,
{
    /// sample a random poly of given degree with `zero_coef` as fixed value for the constant term
    pub fn sample_random_with_fixed_constant<U: Rng + CryptoRng>(
        rng: &mut U,
        zero_coef: F,
        degree: usize,
    ) -> Self {
        let mut coefs: Vec<_> = (0..degree).map(|_| F::sample(rng)).collect();
        coefs.insert(0, zero_coef);
        Poly::from_coefs(coefs)
    }
}

impl<R: Ring> Add<&Poly<R>> for &Poly<R> {
    type Output = Poly<R>;
    fn add(self, other: &Poly<R>) -> Self::Output {
        let max_len = usize::max(self.coefs.len(), other.coefs.len());
        let mut res = Poly::zeros(max_len);
        for i in 0..max_len {
            if i < self.coefs.len() {
                res.coefs[i] += self.coefs[i];
            }
            if i < other.coefs.len() {
                res.coefs[i] += other.coefs[i];
            }
        }
        res.compress();
        res
    }
}

impl<F> Add<Poly<F>> for Poly<F>
where
    F: Add<F, Output = F>,
    F: PartialEq,
    F: Copy,
    F: Zero,
{
    type Output = Poly<F>;
    fn add(self, other: Poly<F>) -> Self::Output {
        let (mut longest, shortest) = if self.coefs.len() >= other.coefs.len() {
            (self, other)
        } else {
            (other, self)
        };
        for i in 0..shortest.coefs.len() {
            longest.coefs[i] = longest.coefs[i] + shortest.coefs[i];
        }
        longest.compress();
        longest
    }
}

impl<F> Sub<Poly<F>> for Poly<F>
where
    F: Copy,
    F: Zero,
    F: SubAssign,
    F: PartialEq,
{
    type Output = Poly<F>;
    fn sub(self, other: Poly<F>) -> Self::Output {
        let mut res = Poly::<F>::zeros(std::cmp::max(self.coefs.len(), other.coefs.len()));
        for (idx, coef) in self.coefs.iter().enumerate() {
            res.coefs[idx] = *coef;
        }
        for (idx, coef) in other.coefs.iter().enumerate() {
            res.coefs[idx] -= *coef;
        }
        res.compress();
        res
    }
}

impl<R: Ring> Mul<Poly<R>> for Poly<R> {
    type Output = Poly<R>;
    fn mul(self, other: Poly<R>) -> Self::Output {
        let mut extended = Poly::zeros(self.coefs.len() + other.coefs.len() - 1);
        for (i, xi) in self.coefs.iter().enumerate() {
            for (j, xj) in other.coefs.iter().enumerate() {
                extended.coefs[i + j] += *xi * *xj;
            }
        }
        extended.compress();
        extended
    }
}

impl<R: Ring> Mul<&Poly<R>> for &Poly<R> {
    type Output = Poly<R>;
    fn mul(self, other: &Poly<R>) -> Self::Output {
        let mut extended = Poly::zeros(self.coefs.len() + other.coefs.len() - 1);
        for (i, xi) in self.coefs.iter().enumerate() {
            for (j, xj) in other.coefs.iter().enumerate() {
                extended.coefs[i + j] += *xi * *xj;
            }
        }
        extended.compress();
        extended
    }
}

impl<R: Ring> Mul<Poly<R>> for &Poly<R> {
    type Output = Poly<R>;
    fn mul(self, other: Poly<R>) -> Self::Output {
        // TODO we could reuse other
        let mut extended = Poly::zeros(self.coefs.len() + other.coefs.len() - 1);
        for (i, xi) in self.coefs.iter().enumerate() {
            for (j, xj) in other.coefs.iter().enumerate() {
                extended.coefs[i + j] += *xi * *xj;
            }
        }
        extended.compress();
        extended
    }
}

impl<R: Ring> Mul<&R> for &Poly<R> {
    type Output = Poly<R>;
    fn mul(self, other: &R) -> Self::Output {
        let mut res = Poly::zeros(self.coefs.len());
        for (i, xi) in self.coefs.iter().enumerate() {
            res.coefs[i] = *xi * *other;
        }
        res.compress();
        res
    }
}

impl<R: Ring> Mul<&R> for Poly<R> {
    type Output = Poly<R>;
    fn mul(mut self, other: &R) -> Self::Output {
        for i in 0..self.coefs.len() {
            self.coefs[i] *= *other;
        }
        self.compress();
        self
    }
}

impl<F: Field> Div<&F> for &Poly<F> {
    type Output = Poly<F>;
    fn div(self, other: &F) -> Self::Output {
        let mut res = Poly::zeros(self.coefs.len());
        for (i, xi) in self.coefs.iter().enumerate() {
            res.coefs[i] = *xi / *other;
        }
        res.compress();
        res
    }
}

impl<F: Field> Div<&F> for Poly<F> {
    type Output = Poly<F>;
    fn div(mut self, other: &F) -> Self::Output {
        for i in 0..self.coefs.len() {
            self.coefs[i] /= *other;
        }
        self.compress();
        self
    }
}

impl<F: Field> Div<&Poly<F>> for &Poly<F> {
    type Output = (Poly<F>, Poly<F>);
    fn div(self, other: &Poly<F>) -> Self::Output {
        quo_rem(self.clone(), other)
    }
}

impl<F: Field> Div<Poly<F>> for Poly<F> {
    type Output = (Poly<F>, Poly<F>);
    fn div(self, other: Poly<F>) -> Self::Output {
        quo_rem(self, &other)
    }
}

impl<F: Field> Div<&Poly<F>> for Poly<F> {
    type Output = (Poly<F>, Poly<F>);
    fn div(self, other: &Poly<F>) -> Self::Output {
        quo_rem(self, other)
    }
}

/// computes quotient `q` and remainder `r` for dividing `a / b`, s.t. `a = q*b + r`
/// Assume the input polynomials are compressed, i.e., no leading zeros.
fn quo_rem<F: Field>(a: Poly<F>, b: &Poly<F>) -> (Poly<F>, Poly<F>) {
    let a_len = a.deg() + 1;
    let b_len = b.deg() + 1;

    if b_len == 1 && b.coef(0) == F::ZERO {
        panic!("division by 0 in quo_rem");
    }

    if a_len == 1 && a.coef(0) == F::ZERO {
        return (Poly::zero(), Poly::zero());
    }

    let t = b.highest_coefficient().invert();

    let mut q = Poly::zeros(a_len);
    let mut r = a;

    if a_len >= b_len {
        for i in (0..=(a_len - b_len)).rev() {
            q.coefs[i] = r.coefs[i + b_len - 1] * t;
            for j in 0..b_len {
                r.coefs[i + j] -= q.coefs[i] * b.coefs[j];
            }
        }
    }
    q.compress();
    r.compress();
    (q, r)
}

/// Computes `(quotient, remainder) = remainder / divisor`, reusing the `quotient` and `remainder`
/// allocations.
///
/// Panics when `divisor` is zero, which is a bug in the caller.
fn quo_rem_assign<F: Field>(remainder: &mut Poly<F>, divisor: &Poly<F>, quotient: &mut Poly<F>) {
    assert!(!divisor.is_zero(), "division by 0 in quo_rem");

    let remainder_len = remainder.deg() + 1;
    let divisor_len = divisor.deg() + 1;

    // A zero remainder, or one of lower degree than the divisor, is already reduced and has a zero
    // quotient. The zero remainder needs its own check because its `coefs` can be empty, which the
    // loop below cannot index.
    let remainder_is_zero = remainder_len == 1 && remainder.coef(0) == F::ZERO;
    if remainder_is_zero || remainder_len < divisor_len {
        quotient.coefs.clear();
        remainder.compress();
        return;
    }

    // Schoolbook long division, from the highest quotient coefficient down. In round `i` the leading
    // term of the remainder is `remainder[i + deg(divisor)] * X^(i + deg(divisor))`. Dividing that
    // coefficient by the leading coefficient of the divisor gives `quotient[i]`, and subtracting
    // `quotient[i] * X^i * divisor` cancels the leading term. Every quotient coefficient is written,
    // so no stale value from a previous call survives.
    let quotient_len = remainder_len - divisor_len + 1;
    quotient.coefs.resize(quotient_len, F::ZERO);
    let inverse_leading = divisor.highest_coefficient().invert();
    for i in (0..quotient_len).rev() {
        quotient.coefs[i] = remainder.coefs[i + divisor_len - 1] * inverse_leading;
        for j in 0..divisor_len {
            remainder.coefs[i + j] -= quotient.coefs[i] * divisor.coefs[j];
        }
    }
    quotient.compress();
    remainder.compress();
}

/// Compute `target -= lhs * rhs` coefficient-wise without allocating the product polynomial.
fn sub_mul_assign<F: Field>(target: &mut Poly<F>, lhs: &Poly<F>, rhs: &Poly<F>) {
    if lhs.is_zero() || rhs.is_zero() {
        return;
    }

    let product_len = lhs.coefs.len() + rhs.coefs.len() - 1;
    if target.coefs.len() < product_len {
        target.coefs.resize(product_len, F::ZERO);
    }
    for (i, lhs_coef) in lhs.coefs.iter().enumerate() {
        for (j, rhs_coef) in rhs.coefs.iter().enumerate() {
            target.coefs[i + j] -= *lhs_coef * *rhs_coef;
        }
    }
    target.compress();
}

/// Build the vanishing polynomial `V(Z) = ∏_j (Z - points[j])` (monic, degree `points.len()`).
/// We do so iteratively, starting from the low to the high coefficients, so that the leading coefficient is always 1 (monic).
/// Then for each subsequent point, we multiply the running product by `(Z - alpha)`.
/// That is, we use the recursion for coefficient of degree k: c'_k = c_{k−1} − alpha * c_k,
/// where c'_k is the new coefficient of degree k after multiplying by `(Z - alpha)`.
/// Concretely we observe that the coefficient c_{k−1} comes from the Z * part and the −alpha * c_k from the −alpha * part.
pub(crate) fn vanishing_poly<F: Ring>(points: &[F]) -> Poly<F> {
    // Master poly V(Z) = ∏_j (Z - alpha_j), low-to-high, monic, degree n.
    let mut coefs = Vec::with_capacity(points.len() + 1);
    // The leading coefficient is always 1 (monic), so we can start with that.
    coefs.push(F::ONE);
    // Proceed iteratively, multiplying the running product by (Z - alpha) for each point.
    for &alpha in points {
        // Add the next leading coefficient (which is again 1) to start with
        coefs.push(F::ONE);
        let m = coefs.len() - 1;
        // Multiply the running product by (Z − alpha): coef[k] <- coef[k-1] − alpha * coef[k].
        // Walk high to low so coef[k-1] still holds its pre-update value when we read it, thus allow in-place updates.
        for k in (1..m).rev() {
            coefs[k] = coefs[k - 1] - alpha * coefs[k];
        }
        // Handle the constant term separately since it has no coefₖ₋₁ to read from.
        coefs[0] = -(alpha * coefs[0]);
    }
    // coefs is canonical because it's monic and the leading coef is F::ONE
    Poly::from_coefs_unchecked(coefs)
}

/// Divide out the linear factor `(Z - root)` to drop the degree by one. Computes `v / (Z - root)` by synthetic division.
///
/// `root` must be a root of `v` (exact, zero-remainder division); `v` must be canonical, so the quotient has degree
/// WARNING: `deg(v) - 1`. `v` must have degree at least 1.
///
/// The computation is iterative and in-place and computes q(Z) = v(Z) / (Z - root) by synthetic division.
/// More concretely q(Z) is computed incrementally, from most significant, to least significant coefficient,
/// as q_{k−1} = v_k + root * q_k, where v_k, q_k are the k-th coefficients of v(Z) and q(Z) respectively.
pub(crate) fn deflate_root<F: Ring>(v: &Poly<F>, root: F) -> Poly<F> {
    // This is provably the case for the current 2 callsites.
    assert!(
        v.coefs.len() >= 2,
        "deflate_root requires deg(v) >= 1, got {:?}",
        v.coefs.len()
    );
    let vc = &v.coefs; // The coefficients of v(Z)
    let deg = vc.len() - 1;
    let mut qc = vec![F::ZERO; deg]; // The coefficients of q(Z)
    qc[deg - 1] = vc[deg]; // leading coefficient drops straight down since the result, q(Z), is one degree lower than the input v(Z)
    for k in (0..deg - 1).rev() {
        // iterate from highest coefficients to lowest in the incremental result since qc[k+1] has already been fully computed
        qc[k] = vc[k + 1] + root * qc[k + 1]; // I.e. q_{k−1} = v_k + root * q_k
    }
    assert!(vc[0] + root * qc[0] == F::ZERO, "remainder must vanish");
    // Invariant: coefs is canonical because the leading coef == vc[deg] (nonzero)
    Poly::from_coefs_unchecked(qc)
}

/// Compute the Lagrange basis polynomials for the given points: `basis_i(Z) = L_i(Z) / L_i(x_i)` where `L_i = V / (Z -
/// x_i)`.
///
/// Builds the vanishing polynomial `V` once and deflates each root. The denominator `L_i(x_i) = ∏_{j != i}(x_i - x_j)`
/// is just `L_i` evaluated at `x_i`.
/// WARNING: This function requires `points.len() >= 2`
pub fn lagrange_polynomials<F: Field>(points: &[F]) -> Vec<Poly<F>> {
    let v = vanishing_poly(points);
    points
        .iter()
        .map(|&xi| {
            // Observe that `li` is the numerator of the basis polynomial
            let li = deflate_root(&v, xi); // L_i(Z) = V / (Z - x_i)
            // Observe `inv` is the denominator, already inverted
            let inv = li.eval(&xi).invert(); // 1/ L_i(x_i)
            li * &inv
        })
        .collect()
}

#[cfg(test)]
mod lagrange_basis_tests {
    use super::*;
    use crate::galois_fields::gf16::GF16;
    use crate::structure_traits::FromU128;

    /// The defining property of a Lagrange basis: `basis_i(x_j) == δ_ij` (1 when i == j, else 0).
    #[test]
    fn lagrange_polynomials_form_a_delta_basis() {
        for n in [1usize, 4, 7, 13] {
            let pts: Vec<GF16> = (1..=n as u128).map(GF16::from_u128).collect();
            let basis = lagrange_polynomials(&pts);
            for (i, li) in basis.iter().enumerate() {
                for (j, xj) in pts.iter().enumerate() {
                    let expected = if i == j { GF16::ONE } else { GF16::ZERO };
                    assert_eq!(li.eval(xj), expected, "basis_{i}(x_{j}) at n={n}");
                }
            }
        }
    }
}

/// Interpolates the polynomial through the x-coordinates `points` and the y-coordinates `values`.
///
/// `values` is consumed as a stream and must yield exactly one value per point. Uses the memoized
/// Lagrange basis for `points` when one is available, otherwise builds it.
pub fn lagrange_interpolation<F, I>(points: &[F], values: I) -> anyhow::Result<Poly<F>>
where
    F: Field,
    I: IntoIterator<Item = F>,
{
    if let Some(cached) = F::cached_lagrange_polys(points) {
        lagrange_interpolation_with_polys(cached, values)
    } else {
        lagrange_interpolation_with_polys(lagrange_polynomials(points), values)
    }
}

/// Interpolates a polynomial from pre-computed Lagrange basis polynomials and the y-coordinates
/// `values`.
///
/// `values` is consumed as a stream, so callers do not need to collect the y-coordinates into a
/// buffer. It must yield exactly one value per basis polynomial.
pub fn lagrange_interpolation_with_polys<F, I>(
    lagrange_polys: impl AsRef<[Poly<F>]>,
    values: I,
) -> anyhow::Result<Poly<F>>
where
    F: Field,
    I: IntoIterator<Item = F>,
{
    let lagrange_polys = lagrange_polys.as_ref();
    let mut values = values.into_iter();

    // res = Σ_i lagrange_polys[i] * values[i], accumulated coefficient-wise into a single buffer. This function runs
    // once per bit, ring_size times per opened value, so this is a hot spot for reconstruction.
    //
    // Each Lagrange basis poly over these `n` points has degree exactly n-1 (n coefficients), so the interpolant has at
    // most `n` coefficients.
    let mut coefs = vec![F::ZERO; lagrange_polys.len()];
    for li in lagrange_polys {
        let Some(vi) = values.next() else {
            return Err(anyhow_error_and_log(
                "Lagrange interpolation failure: mismatch between number of points and values"
                    .to_string(),
            ));
        };
        for (acc, lc) in coefs.iter_mut().zip(li.coefs.iter()) {
            *acc += *lc * vi;
        }
    }
    if values.next().is_some() {
        return Err(anyhow_error_and_log(
            "Lagrange interpolation failure: mismatch between number of points and values"
                .to_string(),
        ));
    }
    Ok(Poly::from_coefs(coefs))
}

/// Runs the extended Euclidean algorithm for `a` and `b` until `deg(r1) < stop`.
///
/// Precondition: `deg(b) >= stop`. The loop then runs at least once and reads `a`, which is why
/// `a` is cloned up front. When `deg(b) < stop` the result is `(b, 1)`, and the caller returns
/// that without calling this function.
///
/// Returns the low-degree remainder `r1` and its Bézout cofactor `t1` with
/// respect to the original `b`.
fn partial_xgcd<F: Field>(a: &Poly<F>, b: Poly<F>, stop: usize) -> (Poly<F>, Poly<F>) {
    let mut r0 = a.clone();
    let mut r1 = b;

    // Invariant: each remainder is `a * s + b * t`; we only track `t`. The cofactors and the
    // quotient are updated in place, so they are allocated once with room for `deg(a) + 1`
    // coefficients.
    let capacity = a.coefs.len();
    let mut t0 = Poly::zero_with_capacity(capacity);
    let mut t1 = Poly::zero_with_capacity(capacity);
    t1.coefs.push(F::ONE);
    let mut q = Poly::zero_with_capacity(capacity);

    while r1.deg() >= stop {
        // Turn r0 into the next remainder and reuse q's allocation across every EEA round.
        quo_rem_assign(&mut r0, &r1, &mut q);
        // Turn t0 into the next cofactor directly, without materializing q * t1 or t2.
        sub_mul_assign(&mut t0, &q, &t1);

        std::mem::swap(&mut r0, &mut r1);
        std::mem::swap(&mut t0, &mut t1);
    }

    (r1, t1)
}

/// Common tail of [`gao_decoding`] and [`gao_decoding_with_field_hints`].
///
/// Given the interpolation polynomial `r` (through the points/values) and the vanishing
/// polynomial `g = prod(X - xi)` — however they were obtained — run the partial extended
/// Euclidean algorithm and recover the message polynomial, with the usual error/degree checks.
/// `n` is the number of evaluation points and `k` the RS dimension (`degree + 1`).
fn gao_decoding_common<F: Field>(
    n: usize,
    k: usize,
    max_errors: usize,
    r: Poly<F>,
    g: &Poly<F>,
) -> anyhow::Result<Poly<F>> {
    // d = n - k + 1
    let d = (n + 1).checked_sub(k).ok_or_else(|| {
        anyhow_error_and_log(format!(
            "Gao decoding failure: overflow computing d with n={n} points and dimension k={k}"
        ))
    })?;

    // We are expecting to correct more than what can be done:
    // Gao can only correct up to (d-1)/2 errors
    if 2 * max_errors >= d {
        return Err(anyhow_error_and_log(format!(
            "Gao decoding failure: expected max number of errors ({max_errors}) is too large for given code parameters n={n}, k={k}, d={d}: can correct at most {} errors",
            d.saturating_sub(1) / 2
        )));
    }

    // apply EEA to compute q0, q1 such that
    // q1 = gcd(g, r) = g * t + r * q0, with q1 | g and q1 | r.
    // q1 and q0 are called g(x) and v(x), respectively, in the Gao paper.
    // q0 = v(x) is the error locator polynomial; its roots are the error positions xi.
    let gcd_stop = (n + k) / 2;

    // The "honest parties" fast path: if the interpolant through all n points already has degree below the Gao stop
    // bound it *is* the message — any polynomial that low-degree and consistent with all n points must equal G when the
    // error count is within the correctable bound. partial_xgcd would return (r, 1).
    if r.deg() < gcd_stop {
        return if r.deg() >= k {
            Err(anyhow_error_and_log(format!(
                "Gao decoding failure: Division result is of too high degree {}, but should be at most {}.",
                r.deg(),
                k - 1
            )))
        } else {
            Ok(r)
        };
    }

    let (q1, q0) = partial_xgcd(g, r, gcd_stop);

    // abort early if we have too many errors
    if q0.deg() > max_errors {
        return Err(anyhow_error_and_log(format!(
            "Gao decoding failure: Allowed at most {max_errors} errors but xgcd factor degree indicates {}.",
            q0.deg()
        )));
    }

    // h is called f_1(x) in the Gao paper.
    let (h, rem) = if q0.deg() == 0 && q0.coef(0) != F::ZERO {
        // q0 is a nonzero constant c (the common no-error case: the xgcd cofactor is the unit poly).
        // Then q1 / q0 = q1 * c⁻¹ exactly, with zero remainder — divide by the scalar in place
        // instead of allocating a fresh quotient via long division.
        (q1 / &q0.coef(0), Poly::zero())
    } else {
        q1 / &q0
    };

    if !rem.is_zero() {
        Err(anyhow_error_and_log(format!(
            "Gao decoding failure: Division remainder is not zero but {rem:?}."
        )))
    } else if h.deg() >= k {
        Err(anyhow_error_and_log(format!(
            "Gao decoding failure: Division result is of too high degree {}, but should be at most {}.",
            h.deg(),
            k - 1
        )))
    } else {
        Ok(h)
    }
}

//NIST: Level Zero Operation
/// Runs Gao decoding algorithm.
///
/// - `points` holds the x-coordinates
/// - `values` yields the y-coordinates, exactly one per point
/// - `k` such that we apply error correction to a polynomial of degree < k
///   (usually degree = threshold in our scheme, but it can be 2*threshold in some cases)
/// - `max_errors` is the maximum number of errors we try to correct for (most often threshold - len(corrupt_set), but can be less than this if degree is 2*threshold)
///
/// __NOTE__ : We assume values already identified as errors have been excluded by the caller (i.e. values denoted Bot in NIST doc)
pub fn gao_decoding<F, I>(
    points: &[F],
    values: I,
    k: usize,
    max_errors: usize,
) -> anyhow::Result<Poly<F>>
where
    F: Field,
    I: IntoIterator<Item = F>,
{
    // in the literature we find (n, k, d) codes
    // parameter k is called v in the NIST doc (the RS dimension)
    // this means that n is the number of points xi for which we have some values yi
    // yi ~= G(xi)), where deg(G) <= k-1
    let n = points.len();

    // R \in F[X] such that R(xi) = yi. Called g_1(x) in the Gao paper.
    // The interpolation fails when `values` does not yield exactly one value per point.
    let r = lagrange_interpolation(points, values)?;

    // G = prod(X - xi) where xi is party i's index. Called g_0(x) in the Gao paper.
    // note that deg(G) >= deg(R)
    let g = vanishing_poly(points);

    gao_decoding_common(n, k, max_errors, r, &g)
}

/// Like [`gao_decoding`] but reuses precomputed Lagrange polynomials and the vanishing polynomial
/// from [`FieldHints`](crate::error_correction::FieldHints).
///
/// The caller must ensure that `lagrange_polys` and `vanishing_poly` were built from the same
/// `points` slice passed here. `values` must yield exactly one value per point.
pub fn gao_decoding_with_field_hints<F, I>(
    points: &[F],
    values: I,
    k: usize,
    max_errors: usize,
    lagrange_polys: &[Poly<F>],
    vanishing_poly: &Poly<F>,
) -> anyhow::Result<Poly<F>>
where
    F: Field,
    I: IntoIterator<Item = F>,
{
    let n = points.len();

    // R = interpolation polynomial through (points, values), using the precomputed Lagrange basis.
    // The interpolation fails when `values` does not yield exactly one value per basis polynomial.
    let r = lagrange_interpolation_with_polys(lagrange_polys, values)?;

    // partial_xgcd only clones "G" if the EEA loop actually runs, which is quite rare.
    gao_decoding_common(n, k, max_errors, r, vanishing_poly)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_correction::{FieldHints, MemoizedExceptionals};
    use crate::galois_fields::gf16::GF16;
    use crate::galois_rings::degree_4::ResiduePolyF4Z128;
    use proptest::prelude::*;
    use rstest::rstest;
    use threshold_types::role::Role;

    #[test]
    fn test_lagrange_mod2() {
        let poly = Poly {
            coefs: vec![
                GF16::from(11),
                GF16::from(2),
                GF16::from(3),
                GF16::from(5),
                GF16::from(9),
            ],
        };
        let xs = vec![
            GF16::from(0),
            GF16::from(1),
            GF16::from(3),
            GF16::from(4),
            GF16::from(2),
        ];

        // we need at least degree + 1 points to interpolate
        assert!(xs.len() > poly.deg());

        let ys: Vec<_> = xs.iter().map(|x| poly.eval(x)).collect();
        let interpolated = lagrange_interpolation(&xs, ys.iter().copied());
        assert_eq!(poly, interpolated.unwrap());

        let with_polys =
            lagrange_interpolation_with_polys(lagrange_polynomials(&xs), ys.iter().copied())
                .unwrap();
        assert_eq!(poly, with_polys);

        let mismatch = lagrange_interpolation_with_polys(
            lagrange_polynomials(&xs),
            ys.iter().copied().take(ys.len() - 1),
        )
        .unwrap_err();
        assert!(mismatch.to_string().contains(
            "Lagrange interpolation failure: mismatch between number of points and values"
        ));
    }

    #[rstest]
    #[case(vec![GF16::from(7),
                GF16::from(4),
                GF16::from(5),
                GF16::from(4)],
            vec![GF16::from(1), GF16::from(0), GF16::from(1)],
    )]
    #[case(vec![GF16::from(15), GF16::from(12)],
        vec![GF16::from(1)])]
    fn test_poly_divmod(#[case] coefs_a: Vec<GF16>, #[case] coefs_b: Vec<GF16>) {
        let a = Poly { coefs: coefs_a };
        let b = Poly { coefs: coefs_b };

        let (q, r) = a.clone() / b.clone();

        assert_eq!(q * b + r, a);
    }

    proptest! {
        #[test]
        fn test_fuzzy_divmod((coefs_a, coefs_b) in (
            proptest::collection::vec(any::<u8>().prop_map(GF16::from), 1..10),
            proptest::collection::vec(any::<u8>().prop_map(GF16::from), 1..10)
        )) {

            let a = Poly::from_coefs(coefs_a);
            let b = Poly::from_coefs(coefs_b);

            if !b.is_zero() {
                let (q, r) = a.clone() / b.clone();
                assert_eq!(q.clone() * b.clone() + r.clone(), a);

                let mut in_place_r = a.clone();
                let mut in_place_q = Poly::zero();
                quo_rem_assign(&mut in_place_r, &b, &mut in_place_q);
                assert_eq!(in_place_q, q);
                assert_eq!(in_place_r, r);
            }

        }
    }

    fn partial_xgcd_allocating<F: Field>(
        a: &Poly<F>,
        b: Poly<F>,
        stop: usize,
    ) -> (Poly<F>, Poly<F>) {
        let mut r0 = a.clone();
        let mut r1 = b;
        let mut t0 = Poly::zero();
        let mut t1 = Poly::one();

        while r1.deg() >= stop {
            let (q, r2) = &r0 / &r1;
            let t2 = t0 - (&q * &t1);
            r0 = r1;
            r1 = r2;
            t0 = t1;
            t1 = t2;
        }
        (r1, t1)
    }

    proptest! {
        #[test]
        fn in_place_partial_xgcd_matches_allocating_version(
            coefs_a in proptest::collection::vec(any::<u8>().prop_map(GF16::from), 2..10),
            coefs_b in proptest::collection::vec(any::<u8>().prop_map(GF16::from), 2..9),
            stop in 1usize..8,
        ) {
            let a = Poly::from_coefs(coefs_a);
            let b = Poly::from_coefs(coefs_b);
            prop_assume!(!b.is_zero());
            prop_assume!(a.deg() >= b.deg());
            prop_assume!(b.deg() >= stop);

            let expected = partial_xgcd_allocating(&a, b.clone(), stop);
            let actual = partial_xgcd(&a, b, stop);
            prop_assert_eq!(actual, expected);
        }
    }

    #[test]
    #[should_panic(expected = "division by 0 in quo_rem")]
    fn test_specific_panic() {
        let a = Poly::from_coefs(vec![GF16::from(15), GF16::from(3)]);
        let b = Poly::from_coefs(vec![GF16::from(0)]);
        let (_q, _r) = a / b;
    }

    #[test]
    fn test_gao_decoding() {
        let f = Poly {
            coefs: vec![GF16::from(7), GF16::from(13), GF16::from(2)],
        };
        let roles = vec![
            Role::indexed_from_one(2),
            Role::indexed_from_one(3),
            Role::indexed_from_one(4),
            Role::indexed_from_one(5),
            Role::indexed_from_one(6),
            Role::indexed_from_one(7),
            Role::indexed_from_one(8),
        ];

        let xs = roles
            .iter()
            .map(|r| GF16::from(r.one_based() as u8))
            .collect::<Vec<_>>();

        let mut ys: Vec<_> = xs.iter().map(|x| f.eval(x)).collect();

        tracing::debug!(
            "n={}, v={}, r=detect={}, correct={}",
            xs.len(),
            f.coefs.len(),
            xs.len() - f.coefs.len(),
            (xs.len() - f.coefs.len()) / 2
        );

        // add an error
        ys[0] += GF16::from(3);
        ys[1] += GF16::from(4);
        let polynomial = gao_decoding(&xs, ys.iter().copied(), f.coefs.len(), 2).unwrap();
        assert_eq!(polynomial.eval(&GF16::from(0)), GF16::from(7));

        let field_hint = FieldHints::new(&roles).unwrap();
        let polynomial_with_hint = gao_decoding_with_field_hints(
            &xs,
            ys.iter().copied(),
            f.coefs.len(),
            2,
            &field_hint.lagrange_polys,
            &field_hint.vanishing_poly,
        )
        .unwrap();
        assert_eq!(polynomial_with_hint.eval(&GF16::from(0)), GF16::from(7));
    }

    #[test]
    fn test_gao_decoding_failure() {
        let f = Poly {
            coefs: vec![GF16::from(7), GF16::from(3), GF16::from(8)],
        };
        let roles = vec![
            Role::indexed_from_one(2),
            Role::indexed_from_one(3),
            Role::indexed_from_one(4),
            Role::indexed_from_one(5),
            Role::indexed_from_one(6),
            Role::indexed_from_one(7),
        ];

        let xs = roles
            .iter()
            .map(|r| GF16::from(r.one_based() as u8))
            .collect::<Vec<_>>();

        let mut ys: Vec<_> = xs.iter().map(|x| f.eval(x)).collect();
        // adding two errors
        ys[0] += GF16::from(2);
        ys[1] += GF16::from(5);
        let r = gao_decoding(&xs, ys.iter().copied(), 3, 1)
            .unwrap_err()
            .to_string();
        assert!(r.contains(
            "Gao decoding failure: Allowed at most 1 errors but xgcd factor degree indicates 2."
        ));

        let field_hint = FieldHints::new(&roles).unwrap();
        let r_with_hint = gao_decoding_with_field_hints(
            &xs,
            ys.iter().copied(),
            3,
            1,
            &field_hint.lagrange_polys,
            &field_hint.vanishing_poly,
        )
        .unwrap_err()
        .to_string();
        assert!(r_with_hint.contains(
            "Gao decoding failure: Allowed at most 1 errors but xgcd factor degree indicates 2."
        ));
    }

    #[test]
    fn test_formal_derivative() {
        // f(x) = 7 + 3x + 8x^2 + 2x^3
        let f = Poly {
            coefs: vec![GF16::from(7), GF16::from(3), GF16::from(8), GF16::from(2)],
        };

        // f'(x) = 3 + 0x + 2x^2 (Note: addition in GF16 is XOR)
        let f1 = Poly {
            coefs: vec![GF16::from(3), GF16::from(0), GF16::from(2)],
        };

        // f''(x) = 0
        let f2 = Poly::zero();

        assert_eq!(f1, f.formal_derivative());
        assert_eq!(f2, f1.formal_derivative());
        assert_eq!(f2, f2.formal_derivative()); // derivative of zero is still zero
    }

    #[test]
    fn test_polynomial_bitwise_eval() {
        let f = Poly {
            coefs: vec![GF16::from(7), GF16::from(3), GF16::from(8)],
        };
        let bitwise = BitWisePoly::from(&f);
        let degree = f.coefs.len();

        let shifted_pos = 10;
        let lifted_f = ResiduePolyF4Z128::shamir_bit_lift(&f, shifted_pos).unwrap();

        let party_ids = [0, 1, 2, 3, 4, 5];
        let ring_evals: Vec<ResiduePolyF4Z128> = party_ids
            .iter()
            .map(|id| {
                let embedded_xi = ResiduePolyF4Z128::get_from_exceptional_sequence(*id)?;
                Ok(lifted_f.eval(&embedded_xi))
            })
            .collect::<anyhow::Result<Vec<_>>>()
            .unwrap();

        for party_id in party_ids {
            assert_eq!(
                ring_evals[party_id],
                bitwise.lazy_eval(&ResiduePolyF4Z128::exceptional_set(party_id, degree).unwrap())
                    << 10,
                "party with index {party_id} failed with wrong evaluation"
            );
        }
    }

    #[test]
    fn test_compress() {
        let mut poly = Poly {
            coefs: vec![GF16::from(3), GF16::from(0), GF16::from(0)],
        };
        poly.compress();
        assert_eq!(poly.coefs, vec![GF16::from(3)]);

        let mut poly2 = Poly {
            coefs: vec![GF16::from(0)],
        };
        poly2.compress();
        assert_eq!(poly2.coefs, vec![]);
    }
}

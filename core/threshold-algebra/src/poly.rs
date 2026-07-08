use super::{
    galois_rings::common::{LutMulReduction, ResiduePoly},
    structure_traits::{Field, Invert, One, Ring, RingWithExceptionalSequence, Sample, Zero},
};
use error_utils::anyhow_error_and_log;
use itertools::Itertools;
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

/// Polynomial struct where all coefficients are bit-strings.
/// We use this as a helper to optimize the reconstruction algorithms
/// where we need to lift binary polynomials into the full ring domain.
#[derive(Serialize, Deserialize, Hash, Clone, Default, Debug)]
pub struct BitwisePoly {
    coefs: Vec<u8>,
}

impl From<Poly<super::galois_fields::gf8::GF8>> for BitwisePoly {
    fn from(poly: Poly<super::galois_fields::gf8::GF8>) -> BitwisePoly {
        let coefs: Vec<u8> = poly.coefs.iter().map(|coef_2| coef_2.0).collect();
        BitwisePoly { coefs }
    }
}

impl From<Poly<super::galois_fields::gf16::GF16>> for BitwisePoly {
    fn from(poly: Poly<super::galois_fields::gf16::GF16>) -> BitwisePoly {
        let coefs: Vec<u8> = poly.coefs.iter().map(|coef_2| coef_2.0).collect();
        BitwisePoly { coefs }
    }
}

impl From<Poly<super::galois_fields::gf32::GF32>> for BitwisePoly {
    fn from(poly: Poly<super::galois_fields::gf32::GF32>) -> BitwisePoly {
        let coefs: Vec<u8> = poly.coefs.iter().map(|coef_2| coef_2.0).collect();
        BitwisePoly { coefs }
    }
}

impl From<Poly<super::galois_fields::gf64::GF64>> for BitwisePoly {
    fn from(poly: Poly<super::galois_fields::gf64::GF64>) -> BitwisePoly {
        let coefs: Vec<u8> = poly.coefs.iter().map(|coef_2| coef_2.0).collect();
        BitwisePoly { coefs }
    }
}

impl From<Poly<super::galois_fields::gf128::GF128>> for BitwisePoly {
    fn from(poly: Poly<super::galois_fields::gf128::GF128>) -> BitwisePoly {
        let coefs: Vec<u8> = poly.coefs.iter().map(|coef_2| coef_2.0).collect();
        BitwisePoly { coefs }
    }
}

impl From<Poly<super::galois_fields::gf256::GF256>> for BitwisePoly {
    fn from(poly: Poly<super::galois_fields::gf256::GF256>) -> BitwisePoly {
        let coefs: Vec<u8> = poly.coefs.iter().map(|coef_2| coef_2.0).collect();
        BitwisePoly { coefs }
    }
}

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

impl BitwisePoly {
    pub fn coef(&self, idx: usize) -> u8 {
        if idx < self.coefs.len() {
            self.coefs[idx]
        } else {
            0
        }
    }

    pub fn coefs(&self) -> &[u8] {
        &self.coefs
    }

    pub fn set_coef(&mut self, idx: usize, value: u8) {
        if idx < self.coefs.len() {
            self.coefs[idx] = value;
        } else {
            // extend the coefficients vector with zeros if needed
            self.coefs.resize(idx + 1, 0);
            self.coefs[idx] = value;
        }
    }

    /// Overwrite the coefficients from `poly`, reusing this buffer's existing allocation.
    ///
    /// Each field coefficient is reduced to its byte representation — the same value the
    /// `From<Poly<GFx>>` impls produce (those map `coef.0`; `Into<u8>` is the identity on the
    /// stored byte) — but `clear` + `extend` keeps the `Vec`'s capacity, so the hot reconstruction
    /// loop reuses one buffer across all bits instead of allocating a fresh `BitwisePoly` per bit.
    pub fn overwrite_from_poly<F: Into<u8> + Copy>(&mut self, poly: &Poly<F>) {
        self.coefs.clear();
        self.coefs.extend(poly.coefs().iter().map(|c| (*c).into()));
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

    /// return a poly that is constant zero and has n zero coefficients
    ///
    /// Note that this polynomial is *not* compressed!
    /// The caller should make sure compress is called
    /// at the end of the operation that uses this zero polynoimal.
    fn zeros(n: usize) -> Self {
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

/// Build the vanishing polynomial `V(Z) = ∏_j (Z - points[j])` (monic, degree `points.len()`).
pub(crate) fn vanishing_poly<F: Ring>(points: &[F]) -> Poly<F> {
    // Master poly V(Z) = ∏_j (Z - alpha_j), low-to-high, monic, degree n.
    let mut coefs = Vec::with_capacity(points.len() + 1);
    coefs.push(F::ONE);
    for &alfa in points {
        coefs.push(F::ONE); // leading coef is always 1 (monic), no multiply needed
        let m = coefs.len() - 1;
        // Multiply the running product by (Z − alfa): coefₖ <- coefₖ₋₁ − alfa·coefₖ.
        // Walk high to low so coefₖ₋₁ still holds its pre-update value when we read it.
        for k in (1..m).rev() {
            coefs[k] = coefs[k - 1] - alfa * coefs[k];
        }
        coefs[0] = -(alfa * coefs[0]);
    }
    // coefs is canonical because it's monic and the leading coef is F::ONE
    Poly::from_coefs_unchecked(coefs)
}

/// Divide out the linear factor `(Z - root)` to drop the degree by one. Computes `v / (Z - root)` by synthetic division.
///
/// `root` must be a root of `v` (exact, zero-remainder division); `v` must be canonical, so the quotient has degree
/// `deg(v) - 1`.
pub(crate) fn deflate_root<F: Ring>(v: &Poly<F>, root: F) -> Poly<F> {
    // Each L_i = V / (Z - alpha_i) via synthetic division (deflation).
    let vc = &v.coefs;
    let deg = vc.len() - 1;
    let mut coefs = vec![F::ZERO; deg];
    coefs[deg - 1] = vc[deg]; // leading coef drops straight down
    for k in (0..deg - 1).rev() {
        coefs[k] = vc[k + 1] + root * coefs[k + 1];
    }
    debug_assert!(vc[0] + root * coefs[0] == F::ZERO, "remainder must vanish");
    // Invariant: coefs is canonical because the leading coef == vc[deg] (nonzero)
    Poly::from_coefs_unchecked(coefs)
}

/// Compute the Lagrange basis polynomials for the given points: `basis_i(Z) = L_i(Z) / L_i(x_i)`
/// where `L_i = V / (Z - x_i)`.
///
/// Builds the vanishing polynomial `V` once and deflates each root. The
/// denominator `L_i(x_i) = ∏_{j != i}(x_i - x_j)` is just `L_i` evaluated at `x_i`.
pub fn lagrange_polynomials<F: Field>(points: &[F]) -> Vec<Poly<F>> {
    let v = vanishing_poly(points);
    points
        .iter()
        .map(|&xi| {
            let li = deflate_root(&v, xi); // L_i(Z) = V / (Z - x_i)
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

/// interpolate a polynomial through coordinates where points holds the x-coordinates and values holds the y-coordinates
pub fn lagrange_interpolation<F: Field>(points: &[F], values: &[F]) -> anyhow::Result<Poly<F>> {
    if let Some(cached) = F::cached_lagrange_polys(points) {
        lagrange_interpolation_with_polys(cached, values)
    } else {
        lagrange_interpolation_with_polys(lagrange_polynomials(points), values)
    }
}

/// interpolate a polynomial using pre-computed Lagrange basis polynomials and y-coordinates
pub fn lagrange_interpolation_with_polys<F: Field>(
    lagrange_polys: impl AsRef<[Poly<F>]>,
    values: &[F],
) -> anyhow::Result<Poly<F>> {
    let lagrange_polys = lagrange_polys.as_ref();
    if lagrange_polys.len() != values.len() {
        return Err(anyhow_error_and_log(
            "Lagrange interpolation failure: mismatch between number of points and values"
                .to_string(),
        ));
    }

    // res = Σ_i lagrange_polys[i] * values[i], accumulated coefficient-wise into a single buffer. This function runs
    // once per bit, ring_size times per opened value, so this is a hot spot for reconstruction.
    //
    // Each Lagrange basis poly over these `n` points has degree exactly n-1 (n coefficients), so the interpolant has at
    // most `n` coefficients.
    let mut coefs = vec![F::ZERO; lagrange_polys.len()];
    for (li, vi) in lagrange_polys.iter().zip_eq(values.iter()) {
        for (acc, lc) in coefs.iter_mut().zip(li.coefs.iter()) {
            *acc += *lc * *vi;
        }
    }
    Ok(Poly::from_coefs(coefs))
}

/// Runs the extended Euclidean algorithm for `a` and `b` until `deg(r1) < stop`.
///
/// Precondition: `deg(b) >= stop`. Callers should ensure `deg(b) < stop`. This code runs the loop at least once and `a`
/// is always read — hence `a` is cloned up front.
///
/// Returns the low-degree remainder `r1` and its Bézout cofactor `t1` with
/// respect to the original `b`.
fn partial_xgcd<F: Field>(a: &Poly<F>, b: Poly<F>, stop: usize) -> (Poly<F>, Poly<F>) {
    let mut r0 = a.clone();
    let mut r1 = b;

    // Invariant: each remainder is `a * s + b * t`; we only track `t`.
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
    let d = (n + 1)
        .checked_sub(k)
        .ok_or_else(|| anyhow_error_and_log("Gao decoding failure: overflow computing d"))?;

    // We are expecting to correct more than what can be done:
    // Gao can only correct up to (d-1)/2 errors
    if 2 * max_errors >= d {
        return Err(anyhow_error_and_log(
            "Gao decoding failure: expected max number of errors is too large for given code parameters".to_string(),
        ));
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
/// - `values` holds the y-coordinates
/// - `k` such that we apply error correction to a polynomial of degree < k
///   (usually degree = threshold in our scheme, but it can be 2*threshold in some cases)
/// - `max_errors` is the maximum number of errors we try to correct for (most often threshold - len(corrupt_set), but can be less than this if degree is 2*threshold)
///
/// __NOTE__ : We assume values already identified as errors have been excluded by the caller (i.e. values denoted Bot in NIST doc)
pub fn gao_decoding<F: Field>(
    points: &[F],
    values: &[F],
    k: usize,
    max_errors: usize,
) -> anyhow::Result<Poly<F>> {
    // in the literature we find (n, k, d) codes
    // parameter k is called v in the NIST doc (the RS dimension)
    // this means that n is the number of points xi for which we have some values yi
    // yi ~= G(xi)), where deg(G) <= k-1
    let n = points.len();

    // sanity check for parameter sizes
    if values.len() != points.len() {
        return Err(anyhow_error_and_log(
            "Gao decoding failure: mismatch between number of values and points".to_string(),
        ));
    }

    // R \in F[X] such that R(xi) = yi. Called g_1(x) in the Gao paper.
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
/// `points` slice passed here.
pub fn gao_decoding_with_field_hints<F: Field>(
    points: &[F],
    values: &[F],
    k: usize,
    max_errors: usize,
    lagrange_polys: &[Poly<F>],
    vanishing_poly: &Poly<F>,
) -> anyhow::Result<Poly<F>> {
    let n = points.len();

    if values.len() != points.len() {
        return Err(anyhow_error_and_log(
            "Gao decoding failure: mismatch between number of values and points".to_string(),
        ));
    }

    // R = interpolation polynomial through (points, values), using the precomputed Lagrange basis.
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
        let interpolated = lagrange_interpolation(&xs, &ys);
        assert_eq!(poly, interpolated.unwrap());
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
                assert_eq!(q * b + r, a);
            }

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
        let polynomial = gao_decoding(&xs, &ys, f.coefs.len(), 2).unwrap();
        assert_eq!(polynomial.eval(&GF16::from(0)), GF16::from(7));

        let field_hint = FieldHints::new(&roles).unwrap();
        let polynomial_with_hint = gao_decoding_with_field_hints(
            &xs,
            &ys,
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
        let r = gao_decoding(&xs, &ys, 3, 1).unwrap_err().to_string();
        assert!(r.contains(
            "Gao decoding failure: Allowed at most 1 errors but xgcd factor degree indicates 2."
        ));

        let field_hint = FieldHints::new(&roles).unwrap();
        let r_with_hint = gao_decoding_with_field_hints(
            &xs,
            &ys,
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
    fn test_bitwise_poly() {
        let f = Poly {
            coefs: vec![GF16::from(7), GF16::from(3), GF16::from(8)],
        };
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

        let bitwise = BitwisePoly::from(f);

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

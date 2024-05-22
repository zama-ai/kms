use crate::algebra::structure_traits::{One, ZConsts};
use crate::algebra::structure_traits::{Sample, Zero};
use crate::experimental::algebra::integers::{IntQ, ModReduction, ZeroCenteredRem};
use crate::experimental::algebra::ntt::hadamard_product;
use crate::experimental::algebra::ntt::Const;
use crate::experimental::algebra::ntt::NTTConstants;
use crate::experimental::algebra::ntt::{ntt_inv, ntt_iter2};
use crate::experimental::random::approximate_gaussian;
use crypto_bigint::Limb;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::ops::Add;
use std::ops::Sub;
use std::ops::{Div, Mul};

#[derive(Debug, Clone)]
pub enum TernaryEntry {
    NegativeOne,
    Zero,
    PositiveOne,
}

#[derive(Debug, Clone)]
pub struct TernaryElement {
    pub data: Vec<TernaryEntry>,
}

/// Cyclotomic polynomial mod Q, degree N
/// Supports mul via FFT.
#[derive(PartialEq, Serialize, Deserialize, Clone, Debug)]
pub struct RqElement<T, N> {
    pub data: Vec<T>,
    _degree: PhantomData<N>,
}

/// Simply polynomial with coefficients in T
/// Supports multiplying with scalars (degree zero poly)
/// Additions coefficient wise and (integer) division by scalar.
#[derive(Clone, Debug, PartialEq)]
pub struct RingElement<T> {
    pub data: Vec<T>,
}

impl<T, N> From<TernaryElement> for RqElement<T, N>
where
    T: ZConsts,
    T: One + Zero,
    N: Const,
{
    fn from(x: TernaryElement) -> Self {
        let data: Vec<_> = x
            .data
            .iter()
            .map(|entry| match entry {
                TernaryEntry::NegativeOne => T::MAX,
                TernaryEntry::Zero => T::ZERO,
                TernaryEntry::PositiveOne => T::ONE,
            })
            .collect();
        debug_assert_eq!(data.len(), N::VALUE);
        RqElement {
            data,
            _degree: PhantomData,
        }
    }
}

impl<T, N> From<RingElement<T>> for RqElement<T, N>
where
    N: Const,
{
    fn from(x: RingElement<T>) -> Self {
        debug_assert_eq!(x.data.len(), N::VALUE);
        RqElement {
            data: x.data,
            _degree: PhantomData,
        }
    }
}

impl<T, N> From<Vec<T>> for RqElement<T, N>
where
    N: Const,
{
    fn from(x: Vec<T>) -> Self {
        debug_assert_eq!(x.len(), N::VALUE);
        RqElement {
            data: x,
            _degree: PhantomData,
        }
    }
}

impl<T> From<Vec<T>> for RingElement<T> {
    fn from(x: Vec<T>) -> Self {
        RingElement { data: x }
    }
}

impl<T, N> From<RqElement<T, N>> for RingElement<IntQ>
where
    IntQ: From<T>,
    T: Clone,
{
    fn from(value: RqElement<T, N>) -> Self {
        let data: Vec<_> = value.data.iter().map(|v| IntQ::from(v.clone())).collect();
        RingElement { data }
    }
}

impl<T, N> From<&RqElement<T, N>> for RingElement<IntQ>
where
    IntQ: From<T>,
    T: Clone,
{
    fn from(value: &RqElement<T, N>) -> Self {
        let data: Vec<_> = value.data.iter().map(|v| IntQ::from(v.clone())).collect();
        RingElement { data }
    }
}

impl From<RingElement<Limb>> for RingElement<IntQ> {
    fn from(value: RingElement<Limb>) -> Self {
        let data: Vec<_> = value.data.iter().map(|v| IntQ::from(v.0)).collect();
        RingElement { data }
    }
}

impl NewHopeSampler for TernaryElement {
    fn new_hope_sample<R: Rng + CryptoRng>(rng: &mut R, bound: usize, degree: usize) -> Self {
        let data: Vec<TernaryEntry> = (0..degree)
            .map(|_| approximate_gaussian(rng, bound))
            .collect();
        TernaryElement { data }
    }
}

impl<T, N> RqElement<T, N>
where
    T: Sample,
    N: Const,
{
    pub fn sample_random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let data: Vec<T> = (0..N::VALUE).map(|_| T::sample(rng)).collect();
        RqElement {
            data,
            _degree: PhantomData,
        }
    }
}
pub trait NewHopeSampler {
    fn new_hope_sample<R: Rng + CryptoRng>(rng: &mut R, bound: usize, degree: usize) -> Self;
}

impl<T, N> NewHopeSampler for RqElement<T, N>
where
    T: ZConsts + One + Zero,
    RqElement<T, N>: From<TernaryElement>,
{
    fn new_hope_sample<R: Rng + CryptoRng>(rng: &mut R, bound: usize, degree: usize) -> Self {
        let ternary = TernaryElement::new_hope_sample(rng, bound, degree);
        RqElement::<T, N>::from(ternary)
    }
}

impl<T, N> Mul for RqElement<T, N>
where
    N: NTTConstants<T>,
    N: Const,
    T: One + Mul<Output = T>,
    T: Sub<Output = T>,
    T: Add<Output = T>,
    T: Clone,
    T: Copy,
    T: Mul<T, Output = T>,
    T: for<'l> Mul<&'l T, Output = T>,
{
    type Output = RqElement<T, N>;
    fn mul(self: RqElement<T, N>, rhs: RqElement<T, N>) -> Self::Output {
        let mut a = self.data;
        let mut b = rhs.data;

        ntt_iter2(&mut a, N::VALUE, N::THETA);
        ntt_iter2(&mut b, N::VALUE, N::THETA);

        let mut c_fft: Vec<T> = hadamard_product(&a, b);
        ntt_inv::<T, N>(&mut c_fft, N::VALUE);

        RqElement {
            data: c_fft,
            _degree: self._degree,
        }
    }
}

impl<T, N> Mul<RqElement<T, N>> for &RqElement<T, N>
where
    N: NTTConstants<T>,
    N: Const,
    T: One + Mul<Output = T>,
    T: Sub<Output = T>,
    T: Add<Output = T>,
    T: Clone,
    for<'r> T: Mul<&'r T, Output = T>,
{
    type Output = RqElement<T, N>;
    fn mul(self, rhs: RqElement<T, N>) -> Self::Output {
        let mut a = self.data.clone();
        let mut b = rhs.data.clone();

        ntt_iter2(&mut a, N::VALUE, N::THETA);
        ntt_iter2(&mut b, N::VALUE, N::THETA);

        let mut c_fft: Vec<T> = hadamard_product(&a, b);
        ntt_inv::<T, N>(&mut c_fft, N::VALUE);

        RqElement {
            data: c_fft,
            _degree: self._degree,
        }
    }
}

impl<T, N> Mul<&RqElement<T, N>> for &RqElement<T, N>
where
    N: NTTConstants<T>,
    N: Const,
    T: One + Mul<Output = T>,
    T: Sub<Output = T>,
    T: Add<Output = T>,
    T: Clone,
    for<'r> T: Mul<&'r T, Output = T>,
{
    type Output = RqElement<T, N>;
    fn mul(self, rhs: &RqElement<T, N>) -> Self::Output {
        let mut a = self.data.clone();
        let mut b = rhs.data.clone();

        ntt_iter2(&mut a, N::VALUE, N::THETA);
        ntt_iter2(&mut b, N::VALUE, N::THETA);

        let mut c_fft: Vec<T> = hadamard_product(&a, b);
        ntt_inv::<T, N>(&mut c_fft, N::VALUE);

        RqElement {
            data: c_fft,
            _degree: self._degree,
        }
    }
}

impl<T, N> Mul<&RqElement<T, N>> for RqElement<T, N>
where
    N: NTTConstants<T>,
    N: Const,
    T: One + Mul<Output = T>,
    T: Sub<Output = T>,
    T: Add<Output = T>,
    T: Clone,
    for<'r> T: Mul<&'r T, Output = T>,
{
    type Output = RqElement<T, N>;
    fn mul(self, rhs: &RqElement<T, N>) -> Self::Output {
        let mut a = self.data.clone();
        let mut b = rhs.data.clone();

        ntt_iter2(&mut a, N::VALUE, N::THETA);
        ntt_iter2(&mut b, N::VALUE, N::THETA);

        let mut c_fft: Vec<T> = hadamard_product(&a, b);
        ntt_inv::<T, N>(&mut c_fft, N::VALUE);

        RqElement {
            data: c_fft,
            _degree: self._degree,
        }
    }
}

impl<T, N> Mul<&T> for RqElement<T, N>
where
    N: NTTConstants<T>,
    N: Const,
    for<'l, 'r> &'l T: Mul<&'r T, Output = T>,
{
    type Output = RqElement<T, N>;
    fn mul(self, rhs: &T) -> Self::Output {
        let data: Vec<_> = self.data.iter().map(|v| v * rhs).collect();
        RqElement {
            data,
            _degree: self._degree,
        }
    }
}

impl<T, N> Add for RqElement<T, N>
where
    T: Add<Output = T>,
    T: Copy,
    N: Const,
{
    type Output = RqElement<T, N>;
    fn add(self, rhs: Self) -> Self::Output {
        let a: Vec<_> = self
            .data
            .iter()
            .enumerate()
            .map(|(i, v)| *v + rhs.data[i])
            .collect();
        RqElement::<T, N>::from(a)
    }
}

impl<T, N> Sub for RqElement<T, N>
where
    N: Const,
    for<'l, 'r> &'l T: Sub<&'r T, Output = T>,
{
    type Output = RqElement<T, N>;
    fn sub(self, rhs: Self) -> Self::Output {
        debug_assert_eq!(self.data.len(), rhs.data.len());
        let a: Vec<_> = self
            .data
            .iter()
            .enumerate()
            .map(|(i, v)| v - &rhs.data[i])
            .collect();
        RqElement::<T, N>::from(a)
    }
}

impl<T, N> Sub<&RqElement<T, N>> for &RqElement<T, N>
where
    N: Const,
    T: Sub<T, Output = T>,
    T: Copy,
{
    type Output = RqElement<T, N>;
    fn sub(self, rhs: &RqElement<T, N>) -> Self::Output {
        debug_assert_eq!(self.data.len(), rhs.data.len());
        let mut a = Vec::with_capacity(N::VALUE);
        for i in 0..N::VALUE {
            a.push(self.data[i] - rhs.data[i])
        }
        RqElement::<T, N>::from(a)
    }
}

#[allow(clippy::suspicious_arithmetic_impl)]
impl Div<&IntQ> for &RingElement<IntQ> {
    type Output = RingElement<IntQ>;
    fn div(self, rhs: &IntQ) -> Self::Output {
        let data: Vec<IntQ> = self.data.iter().map(|v| v / rhs).collect();
        RingElement { data }
    }
}

impl<T> Sub<RingElement<T>> for RingElement<T>
where
    T: Sub<T, Output = T>,
    T: Copy,
{
    type Output = RingElement<T>;

    fn sub(self, rhs: RingElement<T>) -> Self::Output {
        let data = self
            .data
            .iter()
            .zip(rhs.data)
            .map(|(x, y)| *x - y)
            .collect();
        RingElement { data }
    }
}

impl<'l, 'r, T> Sub<&'r RingElement<T>> for &'l RingElement<T>
where
    T: Sub<T, Output = T>,
    T: Copy,
{
    type Output = RingElement<T>;

    fn sub(self: &'l RingElement<T>, rhs: &'r RingElement<T>) -> Self::Output {
        let data: Vec<_> = self
            .data
            .iter()
            .zip(&rhs.data)
            .map(|(x, y)| *x - *y)
            .collect();
        RingElement { data }
    }
}

impl<'l, 'r, T> Add<&'r RingElement<T>> for &'l RingElement<T>
where
    &'l T: Add<&'r T, Output = T>,
{
    type Output = RingElement<T>;

    fn add(self, rhs: &'r RingElement<T>) -> Self::Output {
        let data: Vec<_> = self
            .data
            .iter()
            .zip(&rhs.data)
            .map(|(x, y)| x + y)
            .collect();
        RingElement { data }
    }
}

impl<T> ModReduction<T> for RingElement<IntQ>
where
    IntQ: ModReduction<T, Output = T>,
{
    type Output = RingElement<T>;
    fn mod_reduction(&self) -> Self::Output {
        let data: Vec<_> = self.data.iter().map(|v| v.mod_reduction()).collect();
        RingElement { data }
    }
}

impl ZeroCenteredRem for RingElement<IntQ> {
    type Output = RingElement<Limb>;
    fn zero_centered_rem(&self, dest_mod: crypto_bigint::NonZero<Limb>) -> Self::Output {
        let data: Vec<Limb> = self
            .data
            .iter()
            .map(|v| v.zero_centered_rem(dest_mod))
            .collect();
        RingElement { data }
    }
}

impl Mul<IntQ> for RingElement<IntQ> {
    type Output = RingElement<IntQ>;
    fn mul(self, rhs: IntQ) -> Self::Output {
        let data: Vec<_> = self.data.iter().map(|v| *v * rhs).collect();
        RingElement { data }
    }
}

impl<'l, 'r> Mul<&'r IntQ> for &'l RingElement<IntQ> {
    type Output = RingElement<IntQ>;
    fn mul(self, rhs: &'r IntQ) -> Self::Output {
        let data: Vec<_> = self.data.iter().map(|v| v * rhs).collect();
        RingElement { data }
    }
}

impl Add<RingElement<IntQ>> for RingElement<IntQ> {
    type Output = RingElement<IntQ>;
    fn add(self, rhs: RingElement<IntQ>) -> Self::Output {
        debug_assert_eq!(self.data.len(), rhs.data.len());
        let data = self
            .data
            .iter()
            .zip(rhs.data)
            .map(|(x, y)| *x + y)
            .collect();
        RingElement { data }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebra::structure_traits::FromU128;
    use crate::experimental::algebra::levels::LevelOne;
    use crypto_bigint::NonZero;

    fn level_one_mapping(x: &i128) -> LevelOne {
        if *x < 0 {
            LevelOne::MAX * LevelOne::from_u128(-x as u128)
        } else {
            LevelOne::from_u128(*x as u128)
        }
    }

    #[test]
    fn test_ring_add() {
        let a = [-5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5].to_vec();
        let b = [-5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5].to_vec();

        let c: Vec<_> = a.iter().zip(b.iter()).map(|(aa, bb)| aa + bb).collect();

        let ai: Vec<IntQ> = a.iter().map(|x| IntQ::from_i64(*x)).collect();
        let bi: Vec<IntQ> = b.iter().map(|x| IntQ::from_i64(*x)).collect();
        let ci: Vec<IntQ> = c.iter().map(|x| IntQ::from_i64(*x)).collect();

        let ar = RingElement { data: ai };
        let br = RingElement { data: bi };
        let cr = RingElement { data: ci };
        assert_eq!(ar + br, cr);
    }

    #[test]
    fn test_mod_reduction() {
        let a = [-5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5].to_vec();
        let ai = a.iter().map(|x| IntQ::from_i64(*x)).collect();
        let air = RingElement { data: ai };
        let reduced: RingElement<LevelOne> = air.mod_reduction();
        let a_level_one: Vec<_> = a.iter().map(|x| level_one_mapping(&(*x as i128))).collect();
        assert_eq!(reduced, RingElement { data: a_level_one });
    }

    #[test]
    fn test_limb_negative_reduction() {
        // tests whether a % mod p == ar.zero_centered_rem
        let a = [-5, -4, -3, -2, -1, 0, 1, 2, 3, 4, 5].to_vec();
        let ai = a.iter().map(|x| IntQ::from_i64(*x)).collect();
        let ar = RingElement { data: ai };

        let pmod = 3_u64;

        let pt_limb = NonZero::new(Limb(pmod)).unwrap();
        let a_ring_mod = ar.zero_centered_rem(pt_limb);
        assert_eq!(
            a_ring_mod.data,
            [
                Limb(1),
                Limb(2),
                Limb(0),
                Limb(1),
                Limb(2),
                Limb(0),
                Limb(1),
                Limb(2),
                Limb(0),
                Limb(1),
                Limb(2),
            ]
            .to_vec()
        );
    }
}

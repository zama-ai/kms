use super::bgv_algebra::CryptoModulus;
use super::bgv_algebra::GenericModulus;
use super::bgv_algebra::LevelOne;
use crypto_bigint::Limb;
use crypto_bigint::NonZero;
use crypto_bigint::Odd;
use crypto_bigint::Uint;
use crypto_bigint::Zero;
use crypto_bigint::U128;
use crypto_bigint::U896;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::ops::Add;
use std::ops::Div;
use std::ops::Mul;
use std::ops::Neg;
use std::ops::Sub;

pub(crate) type UnderlyingIntT = U896;

#[derive(Serialize, Deserialize, Hash, Default, Clone, Copy, Eq, PartialEq)]
pub struct IntQ {
    pub is_negative: bool,
    pub data: UnderlyingIntT,
}

impl Debug for IntQ {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntQ")
            .field("is_negative", &self.is_negative)
            .field("data", &self.data)
            .finish()
    }
}

impl IntQ {
    pub fn negative(&self) -> bool {
        self.is_negative
    }

    pub fn sign(&self) -> i8 {
        if self.is_negative {
            -1
        } else {
            1
        }
    }

    pub fn from_i64(x: i64) -> Self {
        Self {
            data: UnderlyingIntT::from_u64(x.unsigned_abs()),
            is_negative: x.is_negative(),
        }
    }
}

impl<T, const U: usize> From<T> for IntQ
where
    T: CryptoModulus<Modulus = crypto_bigint::Uint<U>, OddModulus = crypto_bigint::Odd<Uint<U>>>,
{
    fn from(value: T) -> Self {
        let (is_negative, absolute_val) = compute_abs(value.as_raw(), *T::R);
        IntQ {
            is_negative,
            data: (&absolute_val).into(),
        }
    }
}

#[cfg(target_pointer_width = "64")]
impl From<IntQ> for u64 {
    fn from(value: IntQ) -> Self {
        let words = value.data.to_words();
        for word in words.iter().skip(1) {
            assert_eq!(*word, 0)
        }
        words[0]
    }
}

impl From<u64> for IntQ {
    fn from(value: u64) -> Self {
        IntQ {
            is_negative: false,
            data: UnderlyingIntT::from_u64(value),
        }
    }
}

// Trait to convert value from [0, p) to Integer number
pub trait PositiveConv<T> {
    fn from_non_centered(value: &T) -> Self;
}

impl<T, const U: usize> PositiveConv<T> for IntQ
where
    T: CryptoModulus<Modulus = crypto_bigint::Uint<U>, OddModulus = crypto_bigint::Odd<Uint<U>>>,
{
    fn from_non_centered(value: &T) -> Self {
        IntQ {
            is_negative: false,
            data: value.as_raw().into(),
        }
    }
}

pub trait ZeroCenteredRem {
    type Output;
    fn zero_centered_rem(&self, dest_mod: NonZero<Limb>) -> Self::Output;
}

pub(crate) fn compute_abs<const L: usize>(x: &Uint<L>, modulus: Uint<L>) -> (bool, Uint<L>) {
    let half_mod = modulus.shr(1);
    let is_negative = x > &half_mod;

    let absolute_val = match is_negative {
        false => *x,
        true => modulus - *x,
    };
    (is_negative, absolute_val)
}

impl Mul for IntQ {
    type Output = IntQ;
    fn mul(self, rhs: Self) -> Self::Output {
        let sign = self.sign() * rhs.sign();
        let ret = self.data * rhs.data;
        IntQ {
            data: ret,
            is_negative: sign < 0 && ret.is_zero().unwrap_u8() == 0,
        }
    }
}

impl<'l, 'r> Mul<&'r IntQ> for &'l IntQ {
    type Output = IntQ;
    fn mul(self, rhs: &'r IntQ) -> Self::Output {
        let sign = self.sign() * rhs.sign();
        let ret = self.data * rhs.data;
        IntQ {
            data: ret,
            is_negative: sign < 0 && ret.is_zero().unwrap_u8() == 0,
        }
    }
}

impl Sub for IntQ {
    type Output = IntQ;
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self::Output {
        self + rhs.neg()
    }
}

impl<'l, 'r> Sub<&'r IntQ> for &'l IntQ {
    type Output = IntQ;
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: &'r IntQ) -> Self::Output {
        self + &rhs.neg()
    }
}

impl Neg for IntQ {
    type Output = IntQ;
    fn neg(self) -> Self::Output {
        IntQ {
            data: self.data,
            is_negative: !self.negative(),
        }
    }
}

impl Neg for &IntQ {
    type Output = IntQ;
    fn neg(self) -> Self::Output {
        IntQ {
            data: self.data,
            is_negative: !self.negative(),
        }
    }
}

impl Add for IntQ {
    type Output = IntQ;
    fn add(self, rhs: Self) -> Self::Output {
        let (is_negative, data) = {
            match (self.negative(), rhs.negative()) {
                (true, true) => (true, self.data + rhs.data),
                (true, false) => {
                    if rhs.data >= self.data {
                        (false, rhs.data - self.data)
                    } else {
                        (true, self.data - rhs.data)
                    }
                }
                (false, true) => {
                    if self.data >= rhs.data {
                        (false, self.data - rhs.data)
                    } else {
                        (true, rhs.data - self.data)
                    }
                }
                (false, false) => (false, self.data + rhs.data),
            }
        };
        IntQ { data, is_negative }
    }
}

impl<'l, 'r> Add<&'r IntQ> for &'l IntQ {
    type Output = IntQ;
    fn add(self, rhs: &'r IntQ) -> Self::Output {
        let (is_negative, data) = {
            match (self.negative(), rhs.negative()) {
                (true, true) => (true, self.data + rhs.data),
                (true, false) => {
                    if rhs.data >= self.data {
                        (false, rhs.data - self.data)
                    } else {
                        (true, self.data - rhs.data)
                    }
                }
                (false, true) => {
                    if self.data >= rhs.data {
                        (false, self.data - rhs.data)
                    } else {
                        (true, rhs.data - self.data)
                    }
                }
                (false, false) => (false, self.data + rhs.data),
            }
        };
        IntQ { data, is_negative }
    }
}

impl Div<&IntQ> for &IntQ {
    type Output = IntQ;
    fn div(self, rhs: &IntQ) -> Self::Output {
        let nz = rhs.data.to_nz().unwrap();
        let (q, _r) = self.data.div_rem_vartime(&nz);
        IntQ {
            is_negative: self.is_negative && !bool::from(q.is_zero()),
            data: q,
        }
    }
}

impl ZeroCenteredRem for IntQ {
    type Output = Limb;
    fn zero_centered_rem(&self, dest_mod: NonZero<Limb>) -> Self::Output {
        let mut rem = self.data.rem_limb(dest_mod);
        if self.is_negative && rem.0 != 0 {
            rem = *dest_mod.as_ref() - rem;
        }
        rem
    }
}

/// this computes abs(x) mod q * sign(x) % LevelOne::R
impl<T> ModReduction<T> for IntQ
where
    T: CryptoModulus<Modulus = U128, OddModulus = Odd<U128>>,
{
    type Output = LevelOne;
    fn mod_reduction(&self) -> Self::Output {
        // assuming inputs are bounded by q since are computed from division
        let x: Uint<2> = (&(self.data)).into();
        let cheap_mod = x.rem(T::R.as_nz_ref());

        if self.is_negative {
            GenericModulus(cheap_mod.neg_mod(&T::R))
        } else {
            GenericModulus(cheap_mod)
        }
    }
}

pub trait ModReduction<T> {
    type Output;
    fn mod_reduction(&self) -> Self::Output;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algebra::structure_traits::Sample;
    use crate::experimental::bgv_algebra::LevelEll;
    use crate::experimental::cyclotomic::{RingElement, RqElement};
    use crate::experimental::ntt::{Const, N65536};
    use aes_prng::AesRng;
    use rand::SeedableRng;

    #[test]
    fn test_rem_limb() {
        let mut rng = AesRng::seed_from_u64(0);

        let mut a = Vec::with_capacity(N65536::VALUE);
        let mut b = Vec::with_capacity(N65536::VALUE);
        for _ in 0..N65536::VALUE {
            let val = LevelEll::sample(&mut rng);
            a.push(val);
            let words = val.0.as_words();
            b.push(words[0] as u128 + ((words[0] as u128) << 64));
        }

        let pt_limb = NonZero::new(Limb(65537_u64)).unwrap();
        let a_modq = RqElement::<_, N65536>::from(a);
        let a_int = RingElement::<IntQ>::from(a_modq);
        let rem = a_int.clone().zero_centered_rem(pt_limb);

        for (i, item) in rem.data.iter().enumerate() {
            assert_eq!(*item, Limb((b[i] % 65537) as u64));
        }
    }
}

use std::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use rand::RngCore;
use serde::{Deserialize, Serialize};

pub trait Zero {
    const ZERO: Self;
}

pub trait One {
    const ONE: Self;
}

pub trait ZConsts {
    const TWO: Self;
    const THREE: Self;
    const MAX: Self;
}

/// Sample random element(s)
pub trait Sample {
    fn sample<R: RngCore>(rng: &mut R) -> Self;
}

pub trait Ring: 'static
where
    Self: Serialize,
    Self: for<'a> Deserialize<'a>,
    Self: std::hash::Hash,
    Self: std::fmt::Debug,
    Self: Send,
    Self: Sync,
    Self: Default,
    Self: Sized,
    Self: Copy,
    Self: Eq,
    Self: PartialEq,
    Self: Sample,
    Self: Zero + One,
    Self: Add<Self, Output = Self>,
    Self: Add<Self, Output = Self> + AddAssign<Self>,
    Self: Sub<Self, Output = Self> + SubAssign<Self>,
    Self: Mul<Self, Output = Self> + MulAssign<Self>,
    Self: std::iter::Sum,
    Self: FromU128,
    Self: Neg<Output = Self>,
{
    const BIT_LENGTH: usize;
    // Base 2 log of characteristic of the ring
    const CHAR_LOG2: usize;
    fn to_byte_vec(&self) -> Vec<u8>;
}

pub trait FromU128 {
    fn from_u128(value: u128) -> Self;
}

pub trait BitExtract {
    fn extract_bit(self, bit_idx: usize) -> u8;
}

pub trait BaseRing:
    Ring
    + BitExtract
    + ZConsts
    + std::ops::BitAnd<Self, Output = Self>
    + std::ops::Shl<usize, Output = Self>
{
}

pub trait Field
where
    Self: Ring + Div<Self, Output = Self> + DivAssign<Self>,
{
}

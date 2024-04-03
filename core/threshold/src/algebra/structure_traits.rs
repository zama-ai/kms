use super::poly::Poly;
use crate::execution::{runtime::party::Role, sharing::shamir::ShamirSharings};
use rand::CryptoRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::Display,
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

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
    fn sample<R: Rng + CryptoRng>(rng: &mut R) -> Self;
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
    + for<'a> AddAssign<&'a Self>
    + Display
{
}

pub trait Field
where
    Self: Ring + Div<Self, Output = Self> + DivAssign<Self>,
{
    fn memoize_lagrange(points: &[Self]) -> anyhow::Result<Vec<Poly<Self>>>;

    /// computes the multiplicative inverse of the field element
    fn invert(&self) -> Self;
}

///Trait required to be able to reconstruct a shamir sharing
pub trait Syndrome: Ring {
    fn syndrome_decode(
        syndrome_poly: Poly<Self>,
        parties: &[Role],
        threshold: usize,
    ) -> anyhow::Result<Vec<Self>>;
    fn syndrome_compute(
        sharing: &ShamirSharings<Self>,
        threshold: usize,
    ) -> anyhow::Result<Poly<Self>>;
}

pub trait HenselLiftInverse: Sized {
    fn invert(self) -> anyhow::Result<Self>;
}

pub trait RingEmbed: Sized {
    fn embed_exceptional_set(idx: usize) -> anyhow::Result<Self>;
}

pub trait ErrorCorrect: Ring {
    fn error_correct(
        sharing: &ShamirSharings<Self>,
        threshold: usize,
        max_correctable_errs: usize,
    ) -> anyhow::Result<Poly<Self>>;
}

pub trait Derive: Sized {
    fn derive_challenges_from_coinflip(
        x: &Self,
        g: usize,
        l: usize,
        roles: &[Role],
    ) -> HashMap<Role, Vec<Self>>;
}

pub trait Solve: Sized + ZConsts {
    fn solve(v: &Self) -> anyhow::Result<Self>;
}

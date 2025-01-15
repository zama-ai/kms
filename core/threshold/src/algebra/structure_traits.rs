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
    // Degree of the extension
    const EXTENSION_DEGREE: usize;
    // Number of random bits required to sample a uniform element of the base ring
    const NUM_BITS_STAT_SEC_BASE_RING: usize;
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

pub trait QuotientMaximalIdeal: Ring {
    type QuotientOutput: Field + From<u8> + Into<u8>;
    const QUOTIENT_OUTPUT_SIZE: usize;

    fn bit_compose(&self, idx_bit: usize) -> Self::QuotientOutput;

    fn bit_lift(x: Self::QuotientOutput, pos: usize) -> anyhow::Result<Self>;

    fn bit_lift_from_idx(idx: usize, pos: usize) -> anyhow::Result<Self>;

    fn embed_quotient_exceptional_set(x: Self::QuotientOutput) -> anyhow::Result<Self>;
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

pub trait Invert: Sized {
    fn invert(self) -> anyhow::Result<Self>;
}

pub trait RingEmbed: Sized {
    fn embed_exceptional_set(idx: usize) -> anyhow::Result<Self>;
}

pub trait ErrorCorrect: Ring + RingEmbed {
    ///Perform error correction.
    /// degree is the degree of the sharing polynomial (either threshold or 2*threshold)
    /// max_errs is the maximum number of errors we try to correct for (most often threshold - len(corrupt_set), but can be less than this if degree is 2*threshold)
    ///
    /// __NOTE__ : We assume values coming from known malicious parties have been excluded by the caller (i.e. values denoted Bot in NIST doc)
    fn error_correct(
        sharing: &ShamirSharings<Self>,
        degree: usize,
        max_errs: usize,
    ) -> anyhow::Result<Poly<Self>>;
}

pub trait Derive: Sized {
    /// Domain separator for the function `derive_challenges_from_coinflip`.
    ///
    /// "LDS" stands for local double sharing
    /// but this is also used for local single sharing in the NIST spec.
    const DSEP_LDS: &[u8] = b"LDS";
    const LOG_SIZE_EXCEPTIONAL_SET: usize;
    /// This is known as H_{LDS} from the NIST spec.
    fn derive_challenges_from_coinflip(
        x: &Self,
        g: u8,
        l: usize,
        roles: &[Role],
    ) -> HashMap<Role, Vec<Self>>;
}

pub trait Solve: Sized + ZConsts {
    fn solve(v: &Self) -> anyhow::Result<Self>;
}

pub trait Solve1: Sized {
    fn solve_1(v: &Self) -> anyhow::Result<Self>;
}

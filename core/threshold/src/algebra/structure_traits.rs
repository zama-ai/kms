use super::poly::Poly;
use crate::execution::{runtime::party::Role, sharing::shamir::ShamirSharings};
use crate::hashing::DomainSep;
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
    Self: RingWithExceptionalSequence + Div<Self, Output = Self> + DivAssign<Self>,
{
    fn memoize_lagrange(points: &[Self]) -> anyhow::Result<Vec<Poly<Self>>>;

    /// computes the multiplicative inverse of the field element
    fn invert(&self) -> Self {
        Self::ONE / *self
    }
}

pub trait QuotientMaximalIdeal: Ring {
    type QuotientOutput: Field + From<u8> + Into<u8>;
    const QUOTIENT_OUTPUT_SIZE: usize;

    fn bit_compose(&self, idx_bit: usize) -> Self::QuotientOutput;

    fn bit_lift(x: Self::QuotientOutput, pos: usize) -> anyhow::Result<Self>;

    fn bit_lift_from_idx(idx: usize, pos: usize) -> anyhow::Result<Self>;

    fn embed_quotient_exceptional_sequence(x: Self::QuotientOutput) -> anyhow::Result<Self>;
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

pub trait RingWithExceptionalSequence: Ring + Sized {
    /// Get the element from the exceptional sequence by its index.
    /// NOTE: We really want to index into the sequence and not do a modular operation
    /// here to prevent any bug.
    fn get_from_exceptional_sequence(idx: usize) -> anyhow::Result<Self>;

    /// Embed the Role (starting at index 1) from the exceptional sequence into the ring.
    fn embed_role_to_exceptional_sequence(role: &Role) -> anyhow::Result<Self> {
        Self::get_from_exceptional_sequence(role.one_based())
    }
}

pub trait ErrorCorrect: RingWithExceptionalSequence {
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
    /// "LDS"/"LDSHARNG" stands for local double sharing
    /// but this is also used for local single sharing in the NIST spec.
    const DSEP_LDS: DomainSep = *b"LDSHARNG";
    const LOG_SIZE_EXCEPTIONAL_SET: usize;
    /// This is known as H_{LDS} from the NIST spec.
    fn derive_challenges_from_coinflip(
        x: &Self,
        g: u8,
        l: usize,
        roles: &[Role],
    ) -> HashMap<Role, Vec<Self>>;
}

/// Implement the Solve function defined in NIST doc (Fig.36)
pub trait Solve: Sized + ZConsts {
    fn solve(v: &Self) -> anyhow::Result<Self>;
}

/// Implement the Solve_1 function defined in NIST doc.
/// and used for Solve (Fig.36)
/// Solves X^2 + X = v (mod 2)
pub trait Solve1: Sized {
    fn solve_1(v: &Self) -> anyhow::Result<Self>;
}

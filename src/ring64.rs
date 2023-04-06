use rand::RngCore;
use std::ops::{Add, Mul, Sub};

use crate::poly_shamir::Sharing;

/// This struct is used for single-party plaintext evaluation of a circuit
#[derive(Debug, Clone)]
pub struct Ring64 {
    pub value: u64,
}

impl Sharing for Ring64 {
    fn reveal(&self, _threshold: usize) -> u64 {
        self.value
    }

    fn share<R: RngCore>(
        _rng: &mut R,
        secret: u64,
        _num_parties: usize,
        _threshold: usize,
    ) -> Ring64 {
        Ring64 { value: secret }
    }
}

impl Add<Ring64> for Ring64 {
    type Output = Ring64;
    fn add(self, rhs: Ring64) -> Self::Output {
        Ring64 {
            value: self.value + rhs.value,
        }
    }
}

impl<'l> Add<&'l Ring64> for &'l Ring64 {
    type Output = Ring64;
    fn add(self, rhs: &'l Ring64) -> Self::Output {
        Ring64 {
            value: self.value + rhs.value,
        }
    }
}

impl<'l> Sub<&'l Ring64> for &'l Ring64 {
    type Output = Ring64;
    fn sub(self, rhs: &'l Ring64) -> Self::Output {
        Ring64 {
            value: self.value.wrapping_sub(rhs.value),
        }
    }
}

impl<'l> Mul<&'l Ring64> for &'l Ring64 {
    type Output = Ring64;
    fn mul(self, rhs: &'l Ring64) -> Self::Output {
        Ring64 {
            value: self.value.wrapping_mul(rhs.value),
        }
    }
}

impl<'l> Mul<u64> for &'l Ring64 {
    type Output = Ring64;
    fn mul(self, rhs: u64) -> Self::Output {
        Ring64 {
            value: self.value * rhs,
        }
    }
}

impl<'l> Add<u64> for &'l Ring64 {
    type Output = Ring64;
    fn add(self, rhs: u64) -> Self::Output {
        Ring64 {
            value: self.value.wrapping_add(rhs),
        }
    }
}

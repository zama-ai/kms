use rand::Rng;
use std::num::Wrapping;

use super::structure_traits::{BaseRing, BitExtract, FromU128, One, Ring, Sample, ZConsts, Zero};

macro_rules! ring_impl {
    ($z:ty, $u:ty, $l:expr) => {
        impl Zero for $z {
            const ZERO: Self = Wrapping(0);
        }

        impl One for $z {
            const ONE: Self = Wrapping(1);
        }

        impl ZConsts for $z {
            const TWO: Self = Wrapping(2);
            const THREE: Self = Wrapping(3);
            const MAX: Self = Wrapping(<$u>::MAX);
        }

        impl Sample for $z {
            fn sample<R: Rng>(rng: &mut R) -> Self {
                rng.gen::<$z>()
            }
        }

        impl Ring for $z {
            const BIT_LENGTH: usize = $l;
            const CHAR_LOG2: usize = $l;
            const EXTENSION_DEGREE: usize = 1;
            const NUM_BITS_STAT_SEC_BASE_RING: usize = $l;
            fn to_byte_vec(&self) -> Vec<u8> {
                self.0.to_le_bytes().to_vec()
            }
        }
    };
}

pub type Z64 = Wrapping<u64>;
pub type Z128 = Wrapping<u128>;
pub trait ToZ64 {
    fn to_z64(self) -> Z64;
}

impl ToZ64 for Z64 {
    fn to_z64(self) -> Z64 {
        self
    }
}

impl ToZ64 for Z128 {
    fn to_z64(self) -> Z64 {
        Z64::from_u128(self.0)
    }
}

impl BaseRing for Z128 {}
impl BaseRing for Z64 {}

impl BitExtract for Z128 {
    #[inline(always)]
    fn extract_bit(self, bit_idx: usize) -> u8 {
        ((self.0 >> bit_idx) & 1) as u8
    }
}

impl FromU128 for Z128 {
    #[inline(always)]
    fn from_u128(value: u128) -> Self {
        Wrapping(value)
    }
}

impl BitExtract for Z64 {
    #[inline(always)]
    fn extract_bit(self, bit_idx: usize) -> u8 {
        ((self.0 >> bit_idx) & 1) as u8
    }
}

impl FromU128 for Z64 {
    #[inline(always)]
    fn from_u128(value: u128) -> Self {
        Wrapping(value as u64)
    }
}

ring_impl!(Z64, u64, 64);
ring_impl!(Z128, u128, 128);

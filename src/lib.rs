use crate::poly::Ring;
use rand::RngCore;
use std::num::Wrapping;

pub mod bit_generation;
pub mod choreography;
pub mod circuit;
pub mod commitment;
pub mod computation;
pub mod execution;
pub mod file_handling;
pub mod gf256;
pub mod lwe;
pub mod networking;
pub mod poly;
pub mod residue_poly;
pub mod shamir;
pub mod tests;
pub mod value;
pub use tokio;
pub mod algebra;
pub mod error;
pub mod sharing;

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
            fn sample<R: RngCore>(rng: &mut R) -> Self {
                use rand::Rng;
                rng.gen::<$z>()
            }
        }

        impl Ring for $z {
            const BIT_LENGTH: usize = $l;
        }
    };
}

pub type Z64 = Wrapping<u64>;
pub type Z128 = Wrapping<u128>;

ring_impl!(Z64, u64, 64);
ring_impl!(Z128, u128, 128);

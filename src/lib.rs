use rand::RngCore;
use std::num::Wrapping;

pub mod choreography;
pub mod circuit;
pub mod computation;
pub mod execution;
pub mod gf256;
pub mod lwe;
pub mod networking;
pub mod poly;
pub mod residue_poly;
pub mod shamir;
pub mod value;

pub use tokio;

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

pub trait Ring {
    const RING_SIZE: usize;
}

/// Sample random element(s)
pub trait Sample {
    fn sample<R: RngCore>(rng: &mut R) -> Self;
}

macro_rules! ring_impl {
    ($z:ty, $u:ty, $l:expr) => {
        impl Zero for $z {
            const ZERO: $z = Wrapping(0);
        }

        impl One for $z {
            const ONE: $z = Wrapping(1);
        }

        impl ZConsts for $z {
            const TWO: $z = Wrapping(2);
            const THREE: $z = Wrapping(3);
            const MAX: $z = Wrapping(<$u>::MAX);
        }

        impl Ring for $z {
            const RING_SIZE: usize = $l;
        }

        impl Sample for $z {
            fn sample<R: RngCore>(rng: &mut R) -> Self {
                use rand::Rng;
                rng.gen::<$z>()
            }
        }
    };
}

pub type Z64 = Wrapping<u64>;
pub type Z128 = Wrapping<u128>;

ring_impl!(Z64, u64, 64);
ring_impl!(Z128, u128, 128);

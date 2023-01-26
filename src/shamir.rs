use std::collections::hash_map;
use std::convert::TryFrom;
use std::ops::{Add, Mul, Sub};
use std::str::FromStr;

use aes_prng::AesRng;
use rand::SeedableRng;

pub(crate) struct ShamirSharing {
    pub(crate) share: u64,
}

impl ShamirSharing {
    pub fn reveal(&self) -> u64 {
        self.share
    }
}

impl Add<ShamirSharing> for ShamirSharing {
    type Output = ShamirSharing;
    fn add(self, rhs: ShamirSharing) -> Self::Output {
        ShamirSharing {
            share: self.share + rhs.share,
        }
    }
}

impl<'l> Add<&'l ShamirSharing> for &'l ShamirSharing {
    type Output = ShamirSharing;
    fn add(self, rhs: &'l ShamirSharing) -> Self::Output {
        ShamirSharing {
            share: self.share + rhs.share,
        }
    }
}

impl<'l> Sub<&'l ShamirSharing> for &'l ShamirSharing {
    type Output = ShamirSharing;
    fn sub(self, rhs: &'l ShamirSharing) -> Self::Output {
        ShamirSharing {
            share: self.share.wrapping_sub(rhs.share),
        }
    }
}

impl<'l> Mul<&'l ShamirSharing> for &'l ShamirSharing {
    type Output = ShamirSharing;
    fn mul(self, rhs: &'l ShamirSharing) -> Self::Output {
        ShamirSharing {
            // TODO(Dragos) this will need some rework :D
            share: self.share.wrapping_mul(rhs.share),
        }
    }
}

impl<'l> Mul<u64> for &'l ShamirSharing {
    type Output = ShamirSharing;
    fn mul(self, rhs: u64) -> Self::Output {
        ShamirSharing {
            share: self.share * rhs,
        }
    }
}

impl<'l> Add<u64> for &'l ShamirSharing {
    type Output = ShamirSharing;
    fn add(self, rhs: u64) -> Self::Output {
        ShamirSharing {
            share: self.share.wrapping_add(rhs),
        }
    }
}

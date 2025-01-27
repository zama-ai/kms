use std::collections::HashMap;

use crate::{algebra::poly::lagrange_polynomials, error::error_handler::anyhow_error_and_log};

use crate::algebra::{
    poly::Poly,
    structure_traits::{Field, FromU128, One, Ring, Sample, Zero},
};
use g2p::{g2p, GaloisField};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::ops::Neg;
use std::sync::RwLock;

g2p!(
    GF32,
    5,
    // Polynomial X^5 + X^2 + 1
    modulus: 0b100101,
);

impl Zero for GF32 {
    const ZERO: Self = <GF32 as GaloisField>::ZERO;
}

impl One for GF32 {
    const ONE: Self = <GF32 as GaloisField>::ONE;
}

impl Sample for GF32 {
    fn sample<R: rand::Rng>(rng: &mut R) -> Self {
        let mut candidate = [0_u8; 1];
        rng.fill_bytes(candidate.as_mut());
        GF32::from(candidate[0])
    }
}
impl Default for GF32 {
    fn default() -> Self {
        <GF32 as Zero>::ZERO
    }
}

impl Serialize for GF32 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for GF32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(GF32(u8::deserialize(deserializer)?))
    }
}

impl std::hash::Hash for GF32 {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl std::iter::Sum for GF32 {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(<GF32 as Zero>::ZERO, |acc, x| acc + x)
    }
}

impl FromU128 for GF32 {
    fn from_u128(value: u128) -> Self {
        GF32::from(value as u8)
    }
}

impl Ring for GF32 {
    const BIT_LENGTH: usize = 5;
    const CHAR_LOG2: usize = 1;
    const EXTENSION_DEGREE: usize = 5;
    const NUM_BITS_STAT_SEC_BASE_RING: usize = 1;

    fn to_byte_vec(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }
}

impl Neg for GF32 {
    type Output = Self;
    fn neg(self) -> Self::Output {
        // Subtraction and addition in GF32 are identical and just an XOR.
        // That means we can just return the element itself when we want the additive inverse.
        self
    }
}

lazy_static! {
    static ref LAGRANGE_STORE: RwLock<HashMap<Vec<GF32>, Vec<Poly<GF32>>>> =
        RwLock::new(HashMap::new());
}

impl Field for GF32 {
    fn memoize_lagrange(points: &[Self]) -> anyhow::Result<Vec<Poly<Self>>> {
        if let Ok(lock_lagrange_store) = LAGRANGE_STORE.read() {
            match lock_lagrange_store.get(points) {
                Some(v) => Ok(v.clone()),
                None => {
                    drop(lock_lagrange_store);
                    if let Ok(mut lock_lagrange_store) = LAGRANGE_STORE.write() {
                        let lagrange_pols = lagrange_polynomials(points);
                        lock_lagrange_store.insert(points.to_vec(), lagrange_pols.clone());
                        Ok(lagrange_pols)
                    } else {
                        Err(anyhow_error_and_log(
                            "Error writing LAGRANGE_STORE".to_string(),
                        ))
                    }
                }
            }
        } else {
            Err(anyhow_error_and_log(
                "Error reading LAGRANGE_STORE".to_string(),
            ))
        }
    }

    fn invert(&self) -> Self {
        <GF32 as GaloisField>::ONE / *self
    }
}

/// Computes the vector which is input ^ (2^i) for i=0..max_power.
/// I.e. input, input^2, input^4, input^8, ...
pub fn two_powers(input: GF32, max_power: usize) -> Vec<GF32> {
    let mut res = Vec::with_capacity(max_power);
    let mut temp = input;
    res.push(temp);
    for _i in 1..max_power {
        temp = temp * temp;
        res.push(temp);
    }
    res
}

lazy_static::lazy_static! {
    //Pre-compute the set S defined in Fig.58 (i.e. GF32 from generator X)
    pub static ref GF32_FROM_GENERATOR : Vec<GF32> =
    {

        let generator = GF32::from(2);
         (0..32)
            .scan(GF32::from(1), |state, idx| {
                let res = if idx == 31 { GF32::from(0) } else { *state };
                *state = res * generator;
                Some(res)
            })
            .collect()
    };
}

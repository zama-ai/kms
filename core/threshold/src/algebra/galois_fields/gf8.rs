use std::collections::HashMap;

use crate::{algebra::poly::lagrange_polynomials, error::error_handler::anyhow_error_and_log};

use crate::algebra::{
    poly::Poly,
    structure_traits::{Field, FromU128, One, Ring, Sample, Zero},
};
use g2p::{g2p, GaloisField};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::sync::RwLock;

g2p!(
    GF8,
    3,
    // Polynomial X^3 + X + 1
    modulus: 0b1011,
);

impl Zero for GF8 {
    const ZERO: Self = <GF8 as GaloisField>::ZERO;
}

impl One for GF8 {
    const ONE: Self = <GF8 as GaloisField>::ONE;
}

impl Sample for GF8 {
    fn sample<R: rand::Rng>(rng: &mut R) -> Self {
        let mut candidate = [0_u8; 1];
        rng.fill_bytes(candidate.as_mut());
        GF8::from(candidate[0])
    }
}
impl Default for GF8 {
    fn default() -> Self {
        <GF8 as Zero>::ZERO
    }
}

impl Serialize for GF8 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for GF8 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(GF8(u8::deserialize(deserializer)?))
    }
}

impl FromU128 for GF8 {
    fn from_u128(value: u128) -> Self {
        GF8::from(value as u8)
    }
}

impl Ring for GF8 {
    const BIT_LENGTH: usize = 3;
    const CHAR_LOG2: usize = 1;
    const EXTENSION_DEGREE: usize = 3;
    const NUM_BITS_STAT_SEC_BASE_RING: usize = 1;

    fn to_byte_vec(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }
}

lazy_static! {
    static ref LAGRANGE_STORE: RwLock<HashMap<Vec<GF8>, Vec<Poly<GF8>>>> =
        RwLock::new(HashMap::new());
}

impl Field for GF8 {
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
        <GF8 as GaloisField>::ONE / *self
    }
}

/// Computes the vector which is input ^ (2^i) for i=0..max_power.
/// I.e. input, input^2, input^4, input^8, ...
pub fn two_powers(input: GF8, max_power: usize) -> Vec<GF8> {
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
    //Pre-compute the set S defined in Fig.58 (i.e. GF8 from generator X)
    pub static ref GF8_FROM_GENERATOR : Vec<GF8> =
    {

        let generator = GF8::from(2);
         (0..8)
            .scan(GF8::from(1), |state, idx| {
                let res = if idx == 7 { GF8::from(0) } else { *state };
                *state = res * generator;
                Some(res)
            })
            .collect()
    };
}

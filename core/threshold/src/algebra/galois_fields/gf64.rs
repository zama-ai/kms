use std::collections::HashMap;

use crate::{algebra::poly::lagrange_polynomials, error::error_handler::anyhow_error_and_log};

use crate::algebra::{
    poly::Poly,
    structure_traits::{Field, FromU128, One, Ring, RingWithExceptionalSequence, Sample, Zero},
};
use g2p::{g2p, GaloisField};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::sync::RwLock;

g2p!(
    GF64,
    6,
    // Polynomial X^6 + X + 1
    modulus: 0b1000011,
);

impl Zero for GF64 {
    const ZERO: Self = <GF64 as GaloisField>::ZERO;
}

impl One for GF64 {
    const ONE: Self = <GF64 as GaloisField>::ONE;
}

impl Sample for GF64 {
    fn sample<R: rand::Rng>(rng: &mut R) -> Self {
        let mut candidate = [0_u8; 1];
        rng.fill_bytes(candidate.as_mut());
        GF64::from(candidate[0])
    }
}
impl Default for GF64 {
    fn default() -> Self {
        <GF64 as Zero>::ZERO
    }
}

impl Serialize for GF64 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for GF64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(GF64(u8::deserialize(deserializer)?))
    }
}

impl FromU128 for GF64 {
    fn from_u128(value: u128) -> Self {
        GF64::from(value as u8)
    }
}

impl Ring for GF64 {
    const BIT_LENGTH: usize = 6;
    const CHAR_LOG2: usize = 1;
    const EXTENSION_DEGREE: usize = 6;
    const NUM_BITS_STAT_SEC_BASE_RING: usize = 1;

    fn to_byte_vec(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }
}

const EXCEPTIONAL_SEQUENCE_SIZE: usize = 1 << GF64::BIT_LENGTH;

impl RingWithExceptionalSequence for GF64 {
    fn get_from_exceptional_sequence(idx: usize) -> anyhow::Result<Self> {
        if idx >= EXCEPTIONAL_SEQUENCE_SIZE {
            Err(anyhow::anyhow!(
                "Index out of bounds for GF64 exceptional sequence"
            ))
        } else {
            Ok(GF64::from(idx as u8))
        }
    }
}

lazy_static! {
    static ref LAGRANGE_STORE: RwLock<HashMap<Vec<GF64>, Vec<Poly<GF64>>>> =
        RwLock::new(HashMap::new());
}

impl Field for GF64 {
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
}

/// Computes the vector which is input ^ (2^i) for i=0..max_power.
/// I.e. input, input^2, input^4, input^8, ...
pub fn two_powers(input: GF64, max_power: usize) -> Vec<GF64> {
    let mut res = Vec::with_capacity(max_power);
    let mut temp = input;
    res.push(temp);
    for _i in 1..max_power {
        temp = temp * temp;
        res.push(temp);
    }
    res
}

// Expansion of inner loop needed for computing the initial value of x for Newton-Raphson.
// Computed using the following code:
// const TRACE_ONE: GF64 = GF64(32); // ... which is an element with trace 1
// fn compute_inner_loop() -> [GF64; 3] {
//     let delta_powers = two_powers(TRACE_ONE, D);
//     let mut inner_loop: [GF64; (D - 1) as usize] = [GF64(0); (D - 1) as usize];
//     for i in 0..(D - 1) {
//         let mut inner_temp = GF64::from(0);
//         for j in i + 1..D {
//             inner_temp += delta_powers[j as usize];
//         }
//         inner_loop[i as usize] = inner_temp;
//     }
//     inner_loop
// }

pub static GF64_NEWTON_INNER_LOOP: [GF64; 5] = [GF64(33), GF64(17), GF64(45), GF64(2), GF64(36)];

lazy_static::lazy_static! {
    //Pre-compute the set S defined in Fig.58 (i.e. GF64 from generator X)
    pub static ref GF64_FROM_GENERATOR : Vec<GF64> =
    {

        let generator = GF64::from(2);
         (0..64)
            .scan(GF64::from(1), |state, idx| {
                let res = if idx == 63 { GF64::from(0) } else { *state };
                *state = res * generator;
                Some(res)
            })
            .collect()
    };
}

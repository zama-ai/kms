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
    GF256,
    8,
    modulus: 0b_1_0001_1011,
);

impl Zero for GF256 {
    const ZERO: Self = <GF256 as GaloisField>::ZERO;
}

impl One for GF256 {
    const ONE: Self = <GF256 as GaloisField>::ONE;
}

impl Sample for GF256 {
    fn sample<R: rand::Rng>(rng: &mut R) -> Self {
        let mut candidate = [0_u8; 1];
        rng.fill_bytes(candidate.as_mut());
        GF256::from(candidate[0])
    }
}
impl Default for GF256 {
    fn default() -> Self {
        <GF256 as Zero>::ZERO
    }
}

impl Serialize for GF256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for GF256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(GF256(u8::deserialize(deserializer)?))
    }
}

impl std::hash::Hash for GF256 {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl std::iter::Sum for GF256 {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(<GF256 as Zero>::ZERO, |acc, x| acc + x)
    }
}

impl FromU128 for GF256 {
    fn from_u128(value: u128) -> Self {
        GF256::from(value as u8)
    }
}

impl Ring for GF256 {
    const BIT_LENGTH: usize = 8;
    const CHAR_LOG2: usize = 1;
    const EXTENSION_DEGREE: usize = 8;
    const NUM_BITS_STAT_SEC_BASE_RING: usize = 1;

    fn to_byte_vec(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }
}

impl Neg for GF256 {
    type Output = Self;
    fn neg(self) -> Self::Output {
        // Subtraction and addition in GF256 are identical and just an XOR.
        // That means we can just return the element itself when we want the additive inverse.
        self
    }
}

lazy_static! {
    static ref LAGRANGE_STORE: RwLock<HashMap<Vec<GF256>, Vec<Poly<GF256>>>> =
        RwLock::new(HashMap::new());
}

impl Field for GF256 {
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
        <GF256 as GaloisField>::ONE / *self
    }
}

/// Computes the vector which is input ^ (2^i) for i=0..max_power.
/// I.e. input, input^2, input^4, input^8, ...
pub fn two_powers(input: GF256, max_power: usize) -> Vec<GF256> {
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
// const TRACE_ONE: GF256 = GF256(42); // ... which is an element with trace 1
// fn compute_inner_loop() -> [GF256; 7] {
//     let delta_powers = two_powers(TRACE_ONE, D);
//     let mut inner_loop: [GF256; (D - 1) as usize] = [GF256(0); (D - 1) as usize];
//     for i in 0..(D - 1) {
//         let mut inner_temp = GF256::from(0);
//         for j in i + 1..D {
//             inner_temp += delta_powers[j as usize];
//         }
//         inner_loop[i as usize] = inner_temp;
//     }
//     inner_loop
// }
pub static GF256_NEWTON_INNER_LOOP: [GF256; 7] = [
    GF256(43),
    GF256(3),
    GF256(47),
    GF256(19),
    GF256(52),
    GF256(77),
    GF256(208),
];

lazy_static::lazy_static! {
    //Pre-compute the set S defined in Fig.58 (i.e. GF256 from generator X+1)
    pub static ref GF256_FROM_GENERATOR : Vec<GF256> =
    {

        let generator = GF256::from(3);
         (0..256)
            .scan(GF256::from(1), |state, idx| {
                let res = if idx == 255 { GF256::from(0) } else { *state };
                *state = res * generator;
                Some(res)
            })
            .collect()
    };
}

use crate::poly::lagrange_polynomials;
use crate::{
    poly::Poly,
    structure_traits::{Field, FromU128, One, Ring, RingWithExceptionalSequence, Sample, Zero},
};
use g2p::{GaloisField, g2p};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

g2p!(
    GF128,
    7,
    // Polynomial X^7 + X + 1
    modulus: 0b10000011,
);

impl Zero for GF128 {
    const ZERO: Self = <GF128 as GaloisField>::ZERO;
}

impl One for GF128 {
    const ONE: Self = <GF128 as GaloisField>::ONE;
}

impl Sample for GF128 {
    fn sample<R: rand::Rng>(rng: &mut R) -> Self {
        let mut candidate = [0_u8; 1];
        rng.fill_bytes(candidate.as_mut());
        GF128::from(candidate[0])
    }
}
impl Default for GF128 {
    fn default() -> Self {
        <GF128 as Zero>::ZERO
    }
}

impl Serialize for GF128 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for GF128 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(GF128(u8::deserialize(deserializer)?))
    }
}

impl FromU128 for GF128 {
    fn from_u128(value: u128) -> Self {
        GF128::from(value as u8)
    }
}

impl Ring for GF128 {
    const BIT_LENGTH: usize = 7;
    const CHAR_LOG2: usize = 1;
    const EXTENSION_DEGREE: usize = 7;
    const NUM_BITS_STAT_SEC_BASE_RING: usize = 1;

    fn to_byte_vec(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }
}

const EXCEPTIONAL_SEQUENCE_SIZE: usize = 1 << GF128::BIT_LENGTH;

impl RingWithExceptionalSequence for GF128 {
    fn get_from_exceptional_sequence(idx: usize) -> anyhow::Result<Self> {
        if idx >= EXCEPTIONAL_SEQUENCE_SIZE {
            Err(anyhow::anyhow!(
                "Index out of bounds for GF128 exceptional sequence"
            ))
        } else {
            Ok(GF128::from(idx as u8))
        }
    }
}

#[cfg(not(test))]
use std::sync::OnceLock;

#[cfg(not(test))]
static LAGRANGE_STORE: OnceLock<Vec<Poly<GF128>>> = OnceLock::new();

impl Field for GF128 {
    fn memoize_lagrange(points: &[Self]) -> Vec<Poly<Self>> {
        #[cfg(test)]
        {
            lagrange_polynomials(points)
        }
        #[cfg(not(test))]
        {
            LAGRANGE_STORE
                .get_or_init(|| lagrange_polynomials(points))
                .clone()
        }
    }
}

/// Computes the vector which is input ^ (2^i) for i=0..max_power.
/// I.e. input, input^2, input^4, input^8, ...
pub fn two_powers(input: GF128, max_power: usize) -> Vec<GF128> {
    let mut res = Vec::with_capacity(max_power);
    let mut temp = input;
    res.push(temp);
    for _i in 1..max_power {
        temp = temp * temp;
        res.push(temp);
    }
    res
}

//Pre-compute the set S defined in Fig.58 (i.e. GF128 from generator X)
pub static GF128_FROM_GENERATOR: LazyLock<Vec<GF128>> = LazyLock::new(|| {
    let generator = GF128::from(2);
    (0..128)
        .scan(GF128::from(1), |state, idx| {
            let res = if idx == 127 { GF128::from(0) } else { *state };
            *state = res * generator;
            Some(res)
        })
        .collect()
});

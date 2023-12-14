use super::{
    poly::{gao_decoding, Poly},
    structure_traits::{Field, One, Ring, Sample, Zero},
};
use g2p::{g2p, GaloisField};
use serde::{Deserialize, Serialize};

g2p!(
    GF256,
    8,
    modulus: 0b_1_0001_1011,
);

#[derive(Clone, PartialEq, Debug)]
pub struct ShamirZ2Sharing {
    pub share: GF256,
    pub party_id: u8,
}

impl Zero for GF256 {
    const ZERO: Self = <GF256 as GaloisField>::ZERO;
}

impl One for GF256 {
    const ONE: Self = <GF256 as GaloisField>::ONE;
}

impl Sample for GF256 {
    fn sample<R: rand::RngCore>(rng: &mut R) -> Self {
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

impl Ring for GF256 {
    const BIT_LENGTH: usize = 8;

    fn to_byte_vec(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }
}
impl Field for GF256 {}

pub type ShamirZ2Poly = Poly<GF256>;

pub fn error_correction(
    shares: &[ShamirZ2Sharing],
    threshold: usize,
    max_error_count: usize,
) -> anyhow::Result<ShamirZ2Poly> {
    let xs: Vec<GF256> = shares.iter().map(|s| GF256::from(s.party_id)).collect();
    let ys: Vec<GF256> = shares.iter().map(|s| s.share).collect();

    gao_decoding(&xs, &ys, threshold + 1, max_error_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_correction() {
        let f = ShamirZ2Poly {
            coefs: vec![GF256::from(25), GF256::from(1), GF256::from(1)],
        };
        let party_ids = [1_u8, 2, 3, 4, 5, 6];

        let mut shares: Vec<_> = party_ids
            .iter()
            .map(|x| ShamirZ2Sharing {
                share: f.eval(&GF256::from(*x)),
                party_id: *x,
            })
            .collect();

        // modify share of party with index 1
        shares[1].share += <GF256 as GaloisField>::ONE;

        let secret_poly = error_correction(&shares, 2, 1).unwrap();
        assert_eq!(secret_poly, f);
    }
}

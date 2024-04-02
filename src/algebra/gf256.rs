use std::collections::HashMap;

use crate::{
    algebra::poly::lagrange_polynomials, error::error_handler::anyhow_error_and_log,
    execution::sharing::shamir::ShamirFieldPoly,
};

use super::{
    poly::{gao_decoding, Poly},
    structure_traits::{Field, FromU128, One, Ring, Sample, Zero},
    syndrome::decode_syndrome,
};
use crate::execution::sharing::shamir::ShamirSharing;
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

pub fn error_correction<F: Field>(
    shares: &[ShamirSharing<F>],
    threshold: usize,
    max_correctable_errs: usize,
) -> anyhow::Result<ShamirFieldPoly<F>> {
    let xs: Vec<F> = shares
        .iter()
        .map(|s| F::from_u128(s.party_id.into()))
        .collect();
    let ys: Vec<F> = shares.iter().map(|s| s.share).collect();

    // call Gao decoding with the shares as points/values, set Gao parameter k = v = threshold+1
    gao_decoding(&xs, &ys, threshold + 1, max_correctable_errs)
}

pub fn syndrome_decoding_z2(
    parties: &[usize],
    syndrome: &ShamirFieldPoly<GF256>,
    threshold: usize,
) -> Vec<GF256> {
    let xs: Vec<GF256> = parties.iter().map(|s| GF256::from(*s as u8)).collect();
    let r = parties.len() - (threshold + 1);
    decode_syndrome(syndrome, &xs, r)
}

#[cfg(test)]
mod tests {
    use crate::execution::sharing::shamir::ShamirFieldPoly;

    use super::*;

    #[test]
    fn test_error_correction() {
        let f = ShamirFieldPoly::<GF256> {
            coefs: vec![GF256::from(25), GF256::from(2), GF256::from(233)],
        };

        let num_parties = 7;
        let threshold = f.coefs.len() - 1; // = 2 here
        let max_err = (num_parties as usize - threshold) / 2; // = 2 here

        let mut shares: Vec<_> = (1..=num_parties)
            .map(|x| ShamirSharing::<GF256> {
                share: f.eval(&GF256::from(x)),
                party_id: x,
            })
            .collect();

        // modify shares of parties 1 and 2
        shares[1].share += GF256::from(9);
        shares[2].share += GF256::from(254);

        let secret_poly = error_correction(&shares, threshold, max_err).unwrap();
        assert_eq!(secret_poly, f);
    }
}

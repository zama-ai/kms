use crate::poly::{gao_decoding, Field, Poly};
use anyhow::anyhow;
use g2p::{g2p, GaloisField};

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

impl Field for GF256 {
    const ZERO: Self = <GF256 as GaloisField>::ZERO;
    const ONE: Self = <GF256 as GaloisField>::ONE;
}

pub type ShamirZ2Poly = Poly<GF256>;

pub fn error_correction(
    shares: &[ShamirZ2Sharing],
    threshold: usize,
    max_error_count: usize,
) -> anyhow::Result<ShamirZ2Poly> {
    let xs: Vec<GF256> = shares.iter().map(|s| GF256::from(s.party_id)).collect();
    let ys: Vec<GF256> = shares.iter().map(|s| s.share).collect();

    if let Some(polynomial) = gao_decoding(&xs, &ys, threshold + 1, max_error_count) {
        Ok(polynomial)
    } else {
        Err(anyhow!(format!(
            "Cannot recover polynomial in GF(256) with threshold {threshold} and max_error_count: {max_error_count}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_correction() {
        let f = ShamirZ2Poly {
            coefs: vec![GF256::from(25), GF256::from(1), GF256::from(1)],
        };
        let party_ids = vec![1_u8, 2, 3, 4, 5, 6];

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

use crate::lwe::{gen_player_share, keygen};
use crate::residue_poly::ResiduePoly;
use crate::value::Value;
use crate::{Zero, Z128};
use aes_prng::AesRng;
use rand::SeedableRng;
use std::num::Wrapping;

pub(crate) fn ddec_prep(
    seed: u64,
    big_ell: usize,
    message: u8,
    player_id: usize,
    threshold: usize,
) -> anyhow::Result<Value> {
    // initialize rng to compute keygen, encryption and secret shared bits
    let mut rng = AesRng::seed_from_u64(seed);

    // generate secret key share and pk
    let (sk_share, pk) = keygen(&mut rng, big_ell, player_id, threshold)?;

    // compute encryption of message
    let offset = std::num::Wrapping(1_u128 << 121);
    let ct = pk.encrypt(&mut rng, offset, message);

    let a_time_s = (0..big_ell).fold(ResiduePoly::<Z128>::ZERO, |acc, column| {
        acc + (sk_share.s[column] * ct.a[column])
    });
    // b - a*s
    let partial_dec = a_time_s * Wrapping(u128::MAX) + ct.b[0];

    // noise bounds taken from paper
    let log_bd = 70_usize;
    let pow = 47_usize;

    // sample shared bits
    let b = log_bd + pow;
    let shared_bits: Vec<_> = (0..b)
        .map(|_| {
            let bit_share = gen_player_share(&mut rng, Wrapping(0), threshold, player_id)?;
            Ok::<_, anyhow::Error>(bit_share)
        })
        .collect::<anyhow::Result<Vec<_>, _>>()?;

    let composed_bits = (0..b).fold(ResiduePoly::<Z128>::ZERO, |acc, index| {
        acc + shared_bits[index] * (Wrapping(1_u128) << index)
    });
    Ok(Value::IndexedShare128((
        player_id,
        partial_dec + composed_bits,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::err_reconstruct;
    use tracing_test::traced_test;

    #[traced_test]
    #[test]
    fn test_prep() {
        let seed = 42_u64;
        let big_ell = 10;
        let message = 4;
        let threshold = 1;

        let preps: Vec<_> = (1..5)
            .map(|player_id| ddec_prep(seed, big_ell, message, player_id, threshold).unwrap())
            .collect();
        let rec = err_reconstruct(&preps, threshold, 0).unwrap();
        match rec {
            Value::Ring128(value) => {
                assert_eq!(value >> 121, Wrapping(message as u128));
            }
            _ => unimplemented!(),
        }
    }
}

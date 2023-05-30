use super::prss::PRSSState;
use crate::execution::{LOG_BD, POW};
use crate::lwe::{gen_player_share, keygen, Ciphertext};
use crate::residue_poly::ResiduePoly;
use crate::value::Value;
use crate::{Zero, Z128};
use aes_prng::AesRng;
use rand::{RngCore, SeedableRng};
use std::num::Wrapping;
use std::time::{Duration, Instant};

fn partial_decrypt(
    sk_share: crate::lwe::SharedSecretKey,
    ct: Ciphertext,
    big_ell: usize,
) -> anyhow::Result<ResiduePoly<Z128>> {
    let a_time_s = (0..big_ell).fold(ResiduePoly::<Z128>::ZERO, |acc, column| {
        acc + (sk_share.s[column] * ct.a[column])
    });
    // b - a*s
    Ok(a_time_s * Wrapping(u128::MAX) + ct.b[0])
}

fn prepare_key_and_ct<R: RngCore>(
    mut rng: &mut R,
    big_ell: usize,
    message: u8,
    player_id: usize,
    threshold: usize,
) -> anyhow::Result<(crate::lwe::SharedSecretKey, Ciphertext)> {
    // generate secret key share and pk
    let (sk_share, pk) = keygen(rng, big_ell, player_id, threshold)?;

    // compute encryption of message
    let offset = std::num::Wrapping(1_u128 << 121);
    let ct = pk.encrypt(&mut rng, offset, message);
    Ok((sk_share, ct))
}

pub(crate) fn ddec_prep(
    seed: u64,
    big_ell: usize,
    message: u8,
    player_id: usize,
    threshold: usize,
) -> anyhow::Result<(Value, Duration)> {
    // initialize rng to compute keygen, encryption and secret shared bits
    let mut rng = AesRng::seed_from_u64(seed);

    let init_start_timer = Instant::now();

    let (sk_share, ct) = prepare_key_and_ct(&mut rng, big_ell, message, player_id, threshold)?;

    let init_stop_timer = Instant::now();
    let elapsed_time = init_stop_timer.duration_since(init_start_timer);
    tracing::info!("Init time was {:?} microseconds", elapsed_time.as_micros());

    let partial_dec = partial_decrypt(sk_share, ct, big_ell)?;

    // sample shared bits
    let b = (LOG_BD + POW) as usize;
    let shared_bits: Vec<_> = (0..2 * b)
        .map(|_| {
            let bit_share = gen_player_share(&mut rng, Wrapping(0), threshold, player_id)?;
            Ok::<_, anyhow::Error>(bit_share)
        })
        .collect::<anyhow::Result<Vec<_>, _>>()?;

    let composed_bits = (0..b).fold(ResiduePoly::<Z128>::ZERO, |acc, index| {
        acc + (shared_bits[index] + shared_bits[b + index]) * (Wrapping(1_u128) << index)
    });

    Ok((
        Value::IndexedShare128((player_id, partial_dec + composed_bits)),
        elapsed_time,
    ))
}

pub(crate) fn prss_prep(
    seed: u64,
    big_ell: usize,
    message: u8,
    player_id: usize,
    threshold: usize,
    prss_state: &mut PRSSState,
) -> anyhow::Result<(Value, Duration)> {
    // initialize rng to compute keygen, encryption and secret shared bits
    let mut rng = AesRng::seed_from_u64(seed);

    let init_start_timer = Instant::now();

    let (sk_share, ct) = prepare_key_and_ct(&mut rng, big_ell, message, player_id, threshold)?;

    let init_stop_timer = Instant::now();
    let elapsed_time = init_stop_timer.duration_since(init_start_timer);
    tracing::info!("Init time was {:?} us", elapsed_time.as_micros());

    let partial_dec = partial_decrypt(sk_share, ct, big_ell)?;
    let composed_bits = prss_state.next(player_id)?;

    Ok((
        Value::IndexedShare128((player_id, partial_dec + composed_bits)),
        elapsed_time,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::prss::PRSSSetup;
    use crate::{computation::SessionId, value::err_reconstruct};
    use tracing_test::traced_test;

    #[traced_test]
    #[test]
    fn test_prep() {
        let seed = 42_u64;
        let big_ell = 10;
        let message = 4;
        let threshold = 1;

        let preps: Vec<_> = (1..5)
            .map(|player_id| {
                ddec_prep(seed, big_ell, message, player_id, threshold)
                    .unwrap()
                    .0
            })
            .collect();
        let rec = err_reconstruct(&preps, threshold, 0).unwrap();
        match rec {
            Value::Ring128(value) => {
                assert_eq!(value >> 121, Wrapping(message as u128));
            }
            _ => unimplemented!(),
        }
    }

    #[traced_test]
    #[test]
    fn test_prssprep() {
        let seed = 42_u64;
        let big_ell = 10;
        let message = 5;
        let threshold = 1;
        let num_parties = 4;
        let sid = SessionId::from(12345);

        let preps: Vec<_> = (1..=num_parties)
            .map(|player_id| {
                //each player has their own prss state inside their session.
                let mut rng = AesRng::seed_from_u64(444);
                let prss_setup = PRSSSetup::epoch_init(num_parties, threshold, &mut rng);
                let mut state = prss_setup.new_session(sid);

                prss_prep(seed, big_ell, message, player_id, threshold, &mut state)
                    .unwrap()
                    .0
            })
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

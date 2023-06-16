use super::prss::PRSSState;
use crate::execution::constants::{LOG_BD, POW};
use crate::lwe::{gen_single_party_share, Ciphertext, SecretKeyShare};
use crate::residue_poly::ResiduePoly;
use crate::value::Value;
use crate::{Zero, Z128};
use aes_prng::AesRng;
use rand::SeedableRng;
use std::num::Wrapping;

fn partial_decrypt(sk_share: SecretKeyShare, ct: &Ciphertext) -> anyhow::Result<ResiduePoly<Z128>> {
    let a_time_s = (0..sk_share.s.len()).fold(ResiduePoly::<Z128>::ZERO, |acc, column| {
        acc + (sk_share.s[column] * ct.a[column])
    });
    // b - a*s
    Ok(a_time_s * Wrapping(u128::MAX) + ct.b[0])
}

pub(crate) fn ddec_prep(
    seed: u64,
    party_id: usize,
    threshold: usize,
    sk_share: SecretKeyShare,
    ct: &Ciphertext,
) -> anyhow::Result<Value> {
    // initialize rng to compute keygen, encryption and secret shared bits
    let mut rng = AesRng::seed_from_u64(seed);

    let partial_dec = partial_decrypt(sk_share, ct)?;

    // sample shared bits
    let b = (LOG_BD + POW) as usize;
    let shared_bits: Vec<_> = (0..2 * b)
        .map(|_| {
            let bit_share = gen_single_party_share(&mut rng, Wrapping(0), threshold, party_id)?;
            Ok::<_, anyhow::Error>(bit_share)
        })
        .collect::<anyhow::Result<Vec<_>, _>>()?;

    let composed_bits = (0..b).fold(ResiduePoly::<Z128>::ZERO, |acc, index| {
        acc + (shared_bits[index] + shared_bits[b + index]) * (Wrapping(1_u128) << index)
    });

    Ok(Value::IndexedShare128((
        party_id,
        partial_dec + composed_bits,
    )))
}

pub(crate) fn prss_prep(
    party_id: usize,
    prss_state: &mut PRSSState,
    sk_share: SecretKeyShare,
    ct: &Ciphertext,
) -> anyhow::Result<Value> {
    let partial_dec = partial_decrypt(sk_share, ct)?;
    let composed_bits = prss_state.next(party_id)?;

    Ok(Value::IndexedShare128((
        party_id,
        partial_dec + composed_bits,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::{Circuit, Operation, Operator};
    use crate::execution::distributed::{DecryptionMode, DistributedTestRuntime};
    use crate::execution::party::Identity;
    use crate::execution::prss::PRSSSetup;
    use crate::lwe::{keygen_all_party_shares, keygen_single_party_share};
    use crate::{computation::SessionId, value::err_reconstruct};
    use tracing_test::traced_test;

    #[traced_test]
    #[test]
    fn test_prep() {
        let seed = 42_u64;
        let big_ell = 10;
        let message = 4;
        let threshold = 1;
        let plaintext_bits = 4;
        let offset = 127 - plaintext_bits;

        let preps: Vec<_> = (1..5)
            .map(|party_id| {
                let mut rng = AesRng::seed_from_u64(seed);
                let (sks, pk) = keygen_single_party_share(
                    &mut rng,
                    big_ell,
                    plaintext_bits,
                    party_id,
                    threshold,
                )
                .unwrap();

                let ct = pk.encrypt(&mut rng, message);

                ddec_prep(seed, party_id, threshold, sks, &ct).unwrap()
            })
            .collect();
        let rec = err_reconstruct(&preps, threshold, 0).unwrap();
        match rec {
            Value::Ring128(value) => {
                assert_eq!(value >> offset as usize, Wrapping(message as u128));
            }
            _ => unimplemented!(),
        }
    }

    #[traced_test]
    #[test]
    fn test_prssprep() {
        let big_ell = 10;
        let message = 5;
        let threshold = 1;
        let num_parties = 4;
        let plaintext_bits = 4;
        let sid = SessionId::from(12345);

        let offset = 127 - plaintext_bits;

        let preps: Vec<_> = (1..=num_parties)
            .map(|party_id| {
                //each party has their own prss state inside their session.
                let mut rng = AesRng::seed_from_u64(444);
                let prss_setup = PRSSSetup::epoch_init(num_parties, threshold, &mut rng);
                let mut state = prss_setup.new_session(sid);
                let (sks, pk) = keygen_single_party_share(
                    &mut rng,
                    big_ell,
                    plaintext_bits,
                    party_id,
                    threshold,
                )
                .unwrap();

                let ct = pk.encrypt(&mut rng, message);

                prss_prep(party_id, &mut state, sks, &ct).unwrap()
            })
            .collect();
        let rec = err_reconstruct(&preps, threshold, 0).unwrap();
        match rec {
            Value::Ring128(value) => {
                assert_eq!(value >> offset as usize, Wrapping(message as u128));
            }
            _ => unimplemented!(),
        }
    }

    #[test]
    fn test_ddec2_distributed_local() {
        let circuit = Circuit {
            operations: vec![
                Operation {
                    operator: Operator::DistPrep,
                    operands: vec![String::from("s0"), String::from("678")],
                },
                Operation {
                    operator: Operator::Open,
                    operands: vec![
                        String::from("3"),
                        String::from("false"),
                        String::from("c0"),
                        String::from("s0"),
                    ],
                },
                Operation {
                    operator: Operator::ShrCI,
                    operands: vec![String::from("c1"), String::from("c0"), String::from("123")],
                },
                Operation {
                    operator: Operator::PrintRegPlain,
                    operands: vec![String::from("c1")],
                },
            ],
            input_wires: vec![],
        };
        let identities = vec![
            Identity("localhost:5000".to_string()),
            Identity("localhost:5001".to_string()),
            Identity("localhost:5002".to_string()),
            Identity("localhost:5003".to_string()),
            Identity("localhost:5004".to_string()),
            Identity("localhost:5005".to_string()),
            Identity("localhost:5006".to_string()),
            Identity("localhost:5007".to_string()),
            Identity("localhost:5008".to_string()),
            Identity("localhost:5009".to_string()),
        ];
        let threshold = 3;
        let num_parties = 10;
        let mut rng = AesRng::seed_from_u64(444);
        let msg = 12;
        let plaintext_bits = 4;
        let ell = 10;

        let prss_setup = None;

        // generate keys
        let (key_shares, pk) =
            keygen_all_party_shares(&mut rng, ell, plaintext_bits, num_parties, threshold).unwrap();
        let ct = pk.encrypt(&mut rng, msg);

        let runtime =
            DistributedTestRuntime::new(identities, threshold as u8, prss_setup, Some(key_shares));

        // test DDec2 with circuit evaluation
        let results_circ = runtime
            .evaluate_circuit(&circuit, Some(ct.clone()))
            .unwrap();
        let out_circ = &results_circ[&Identity("localhost:5000".to_string())];

        // test DDec2 with decryption endpoint
        let results_dec = runtime
            .threshold_decrypt(ct, DecryptionMode::Proto2Decrypt)
            .unwrap();
        let out_dec = &results_dec[&Identity("localhost:5000".to_string())];

        assert_eq!(out_circ[0], Value::Ring128(std::num::Wrapping(msg as u128)));
        assert_eq!(out_dec[0], Value::Ring128(std::num::Wrapping(msg as u128)));
    }
}

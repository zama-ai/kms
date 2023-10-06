use super::prss::PRSSState;
use crate::lwe::{
    gen_single_party_share, Ciphertext128, Ciphertext128Block, Ciphertext64, Ciphertext64Block,
    CiphertextParameters, SecretKeyShare,
};
use crate::residue_poly::ResiduePoly;
use crate::value::Value;
use crate::{
    execution::constants::{LOG_BD, POW},
    lwe::BootstrappingKey,
};
use crate::{Zero, Z128};
use aes_prng::AesRng;
use rand::SeedableRng;
use std::num::Wrapping;
use tfhe::core_crypto::prelude::*;
use tfhe::core_crypto::prelude::{
    lwe_ciphertext_modulus_switch_up, programmable_bootstrap_f128_lwe_ciphertext, CastFrom,
    GlweCiphertextOwned, GlweSize, LweCiphertext, UnsignedTorus,
};
use tfhe::shortint::prelude::PolynomialSize;

fn partial_decrypt(
    sk_share: &SecretKeyShare,
    ct: &Ciphertext128Block,
) -> anyhow::Result<ResiduePoly<Z128>> {
    // NOTE eventually this secret key share will be a vector of ResiduePoly<Z128> elements
    let (mask, body) = ct.get_mask_and_body();
    let a_time_s =
        (0..sk_share.input_key_share.len()).fold(ResiduePoly::<Z128>::ZERO, |acc, column| {
            acc + sk_share.input_key_share[column]
                * ResiduePoly::from_scalar(Wrapping(mask.as_ref()[column]))
        });
    // b-a*ssp
    let res = a_time_s * Wrapping(u128::MAX) + ResiduePoly::from_scalar(Wrapping(*body.data));
    Ok(res)
}

pub(crate) fn ddec_prep(
    seed: u64,
    party_id: usize,
    threshold: usize,
    sk_share: &SecretKeyShare,
    ct: &Ciphertext128Block,
) -> anyhow::Result<Value> {
    // initialize rng to compute keygen, encryption and secret shared bits
    // TODO should be larger seed
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
    sk_share: &SecretKeyShare,
    ct: &Ciphertext128Block,
) -> anyhow::Result<Value> {
    let partial_dec = partial_decrypt(sk_share, ct)?;
    let composed_bits = prss_state.next(party_id)?;

    Ok(Value::IndexedShare128((
        party_id,
        partial_dec + composed_bits,
    )))
}

// TODO is this the general correct formula? should be:
// output_lwe_secret_key.lwe_dimension().to_lwe_size(),
// and
// output_lwe_secret_key_out.lwe_dimension().to_lwe_size(),
fn pbs_cipher_size<S>(params: &CiphertextParameters<S>) -> LweSize
where
    S: UnsignedInteger,
{
    LweSize(1 + params.glwe_dimension.0 * params.polynomial_size.0)
}

/// Converts a ciphertext over a 64 bit domain to a ciphertext over a 128 bit domain (which is needed for secure threshold decryption).
/// Convertion is done using a precreated convertion key [ck].
/// Observe that the decryption key will be different after convertion, since [ck] is actually a key-switching key.
pub fn to_large_ciphertext(ck: &BootstrappingKey, small_ct: &Ciphertext64) -> Ciphertext128 {
    let mut res = Vec::with_capacity(small_ct.len());
    for current_block in small_ct {
        res.push(to_large_ciphertext_block(ck, current_block));
    }
    res
}

/// Converts a single ciphertext block over a 64 bit domain to a ciphertext block over a 128 bit domain (which is needed for secure threshold decryption).
/// Convertion is done using a precreated convertion key, [ck].
/// Observe that the decryption key will be different after convertion, since [ck] is actually a key-switching key.
pub fn to_large_ciphertext_block(
    ck: &BootstrappingKey,
    small_ct: &Ciphertext64Block,
) -> Ciphertext128Block {
    // Accumulator definition
    let delta = 1_u64
        << (u64::BITS
            - 1
            - ck.threshold_lwe_parameters
                .input_cipher_parameters
                .message_modulus_log
                .0 as u32);
    let msg_modulus = 1_u64
        << ck
            .threshold_lwe_parameters
            .input_cipher_parameters
            .message_modulus_log
            .0;

    let f_out = |x: u128| x;
    let delta_u128 = (delta as u128) << 64;
    let accumulator_out: GlweCiphertextOwned<u128> = generate_accumulator(
        ck.threshold_lwe_parameters
            .output_cipher_parameters
            .polynomial_size,
        ck.threshold_lwe_parameters
            .output_cipher_parameters
            .glwe_dimension
            .to_glwe_size(),
        msg_modulus.cast_into(),
        ck.threshold_lwe_parameters
            .output_cipher_parameters
            .ciphertext_modulus,
        delta_u128,
        f_out,
    );

    // TODO these steps should not be needed here. They only execute the usual bootstrapping method on the ciphertext
    // pk.fbsk_in
    // pk.ksk_in
    // let f_in = |x: u64| x;
    // let accumulator_in: GlweCiphertextOwned<u64> = generate_accumulator(
    //     pk.threshold_lwe_parameters
    //         .input_cipher_parameters
    //         .polynomial_size,
    //     pk.threshold_lwe_parameters
    //         .input_cipher_parameters
    //         .glwe_dimension
    //         .to_glwe_size(),
    //     msg_modulus.cast_into(),
    //     pk.threshold_lwe_parameters
    //         .input_cipher_parameters
    //         .ciphertext_modulus,
    //     delta,
    //     f_in,
    // );
    // let mut pbs_ct = LweCiphertext::new(
    //     0_u64,
    //     pbs_cipher_size(&pk.threshold_lwe_parameters.input_cipher_parameters),
    //     pk.threshold_lwe_parameters
    //         .input_cipher_parameters
    //         .ciphertext_modulus,
    // );
    // programmable_bootstrap_lwe_ciphertext(small_ct, &mut pbs_ct, &accumulator_in, &pk.fbsk_in);
    // let mut ksk_ct_in = LweCiphertext::new(
    //     0u64,
    //     pk.ksk_in.output_lwe_size(),
    //     pk.ksk_in.ciphertext_modulus(),
    // );
    // keyswitch_lwe_ciphertext(&pk.ksk_in, &pbs_ct, &mut ksk_ct_in);

    //MSUP
    let mut ms_output_lwe =
        LweCiphertext::new(0_u128, small_ct.lwe_size(), CiphertextModulus::new_native());
    lwe_ciphertext_modulus_switch_up(&mut ms_output_lwe, small_ct);

    let mut out_pbs_ct = LweCiphertext::new(
        0_u128,
        pbs_cipher_size(&ck.threshold_lwe_parameters.output_cipher_parameters),
        ck.threshold_lwe_parameters
            .output_cipher_parameters
            .ciphertext_modulus,
    );
    programmable_bootstrap_f128_lwe_ciphertext(
        &ms_output_lwe,
        &mut out_pbs_ct,
        &accumulator_out,
        &ck.fbsk_out,
    );
    out_pbs_ct
}

// Here we will define a helper function to generate an accumulator for a PBS
fn generate_accumulator<F, Scalar: UnsignedTorus + CastFrom<usize>>(
    polynomial_size: PolynomialSize,
    glwe_size: GlweSize,
    message_modulus: usize,
    ciphertext_modulus: CiphertextModulus<Scalar>,
    delta: Scalar,
    f: F,
) -> GlweCiphertextOwned<Scalar>
where
    F: Fn(Scalar) -> Scalar,
{
    // N/(p/2) = size of each block, to correct noise from the input we introduce the
    // notion of box, which manages redundancy to yield a denoised value
    // for several noisy values around a true input value.
    let box_size = polynomial_size.0 / message_modulus;

    // Create the accumulator
    let mut accumulator_scalar = vec![Scalar::ZERO; polynomial_size.0];

    // Fill each box with the encoded denoised value
    for i in 0..message_modulus {
        let index = i * box_size;
        accumulator_scalar[index..index + box_size]
            .iter_mut()
            .for_each(|a| *a = f(Scalar::cast_from(i)) * delta);
    }

    let half_box_size = box_size / 2;

    // Negate the first half_box_size coefficients to manage negacyclicity and rotate
    for a_i in accumulator_scalar[0..half_box_size].iter_mut() {
        *a_i = (*a_i).wrapping_neg();
    }

    // Rotate the accumulator
    accumulator_scalar.rotate_left(half_box_size);

    let accumulator_plaintext = PlaintextList::from_container(accumulator_scalar);

    allocate_and_trivially_encrypt_new_glwe_ciphertext(
        glwe_size,
        &accumulator_plaintext,
        ciphertext_modulus,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::{Circuit, Operation, Operator};
    use crate::execution::distributed::{DecryptionMode, DistributedTestRuntime};
    use crate::execution::party::Identity;
    use crate::execution::prss::PRSSSetup;
    use crate::execution::random::get_rng;
    use crate::file_handling::{read_as_json, read_element};
    use crate::lwe::{
        keygen_all_party_shares, keygen_single_party_share, value_to_message, KeyPair, KeySet,
        ThresholdLWEParameters,
    };

    use crate::tests::test_data_setup::tests::{
        DEFAULT_KEY_PATH, DEFAULT_PARAM_PATH, TEST_KEY_PATH, TEST_PARAM_PATH,
    };
    use crate::{computation::SessionId, value::err_reconstruct};
    use tracing_test::traced_test;

    #[traced_test]
    #[test]
    fn reconstruct_key() {
        let parties = 5;
        let keyset = read_element(TEST_KEY_PATH.to_string()).unwrap();
        let shares =
            keygen_all_party_shares(&keyset, &mut AesRng::seed_from_u64(0), parties, 1).unwrap();
        let mut first_bit_shares = Vec::with_capacity(parties);
        (0..parties).for_each(|i| {
            first_bit_shares.push(Value::IndexedShare128((
                i + 1,
                *shares[i].input_key_share.get(0).unwrap(),
            )));
        });

        let rec: Value = err_reconstruct(&first_bit_shares, 1, 0).unwrap();
        let inner_rec = match rec {
            Value::Ring128(v) => v,
            _ => unimplemented!(),
        };
        assert_eq!(
            keyset.sk.lwe_secret_key_128.into_container()[0],
            inner_rec.0
        );
    }

    #[traced_test]
    #[test]
    fn test_prep() {
        let seed = 0_u64;
        let parties = 4;
        let message = 15;
        let threshold = 1;
        let params: ThresholdLWEParameters = read_as_json(DEFAULT_PARAM_PATH.to_string()).unwrap();
        let mut rng = AesRng::seed_from_u64(seed);
        let keyset = read_element(DEFAULT_KEY_PATH.to_string()).unwrap();
        let sk_shares = keygen_all_party_shares(&keyset, &mut rng, parties, threshold).unwrap();

        let ct = keyset.pk.encrypt_block(&mut rng, message);
        let large_ct = to_large_ciphertext_block(&keyset.ck, &ct);

        let preps: Vec<_> = (1..=parties)
            .map(|party_id| {
                ddec_prep(
                    seed,
                    party_id,
                    threshold,
                    &sk_shares[party_id - 1],
                    &large_ct,
                )
                .unwrap()
            })
            .collect();
        let rec = err_reconstruct(&preps, threshold, 0).unwrap();
        let recovered_message =
            value_to_message(rec, params.input_cipher_parameters.message_modulus_log.0);
        assert_eq!(recovered_message.unwrap().0, message as u128);
    }

    #[traced_test]
    #[test]
    fn test_prssprep() {
        let message = 3;
        let threshold = 1;
        let num_parties = 4;
        let sid = SessionId::from(12345);
        let params: ThresholdLWEParameters = read_as_json(TEST_PARAM_PATH.to_string()).unwrap();
        let keyset: KeySet = read_element(TEST_KEY_PATH.to_string()).unwrap();
        let mut enc_rng = AesRng::seed_from_u64(444);
        let ct = keyset.pk.encrypt_block(&mut enc_rng, message);
        let large_ct = to_large_ciphertext_block(&keyset.ck, &ct);

        let preps: Vec<_> = (1..=num_parties)
            .map(|party_id| {
                //each party has their own prss state inside their session.
                let mut rng = AesRng::seed_from_u64(444);
                let prss_setup =
                    PRSSSetup::testing_party_epoch_init(num_parties, threshold, &mut rng, party_id)
                        .unwrap();
                let mut state = prss_setup.new_prss_session_state(sid);
                let sks =
                    keygen_single_party_share(&keyset, &mut rng, party_id, threshold).unwrap();
                prss_prep(party_id, &mut state, &sks, &large_ct).unwrap()
            })
            .collect();
        let rec = err_reconstruct(&preps, threshold, 0).unwrap();
        let recovered_message =
            value_to_message(rec, params.input_cipher_parameters.message_modulus_log.0);
        assert_eq!(recovered_message.unwrap().0, message as u128);
    }

    #[test]
    fn test_ddec2_distributed_local() {
        let threshold = 3;
        let num_parties = 10;
        let msg: u8 = 3;
        let keyset: KeySet = read_element(TEST_KEY_PATH.to_string()).unwrap();
        let circuit = Circuit {
            operations: vec![
                Operation {
                    operator: Operator::DistPrep,
                    operands: vec![String::from("s0"), String::from("678")], // Use a random value for seed (678) in the distprep taking the message as input
                },
                Operation {
                    operator: Operator::Open,
                    operands: vec![
                        String::from("3"),     // Ignored
                        String::from("false"), // Ignored
                        String::from("c0"),    // Register we store in
                        String::from("s0"),    // Register we read
                    ],
                },
                Operation {
                    operator: Operator::ShrCIRound, // Rounded right shift
                    // Stores the result in c1, reads from c0, and shifts it 123=127-2*2 to restore the actual message in the 4 bit-plaintext supported by a single ciphertext
                    operands: vec![String::from("c1"), String::from("c0"), String::from("123")],
                },
                Operation {
                    operator: Operator::PrintRegPlain, // Output the value
                    operands: vec![
                        String::from("c1"), // From index c1
                        keyset
                            .pk
                            .threshold_lwe_parameters
                            .input_cipher_parameters
                            .usable_message_modulus_log
                            .0
                            .to_string(), // Bits in message
                    ],
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

        let mut rng = AesRng::seed_from_u64(42);
        // generate keys
        let key_shares =
            keygen_all_party_shares(&keyset, &mut rng, num_parties, threshold).unwrap();
        let ct = keyset.pk.encrypt_w_bitlimit(&mut rng, msg, 2);
        let large_ct = to_large_ciphertext(&keyset.ck, &ct);

        let mut runtime = DistributedTestRuntime::new(identities, threshold as u8);

        runtime.setup_keys(key_shares);

        // test DDec2 with circuit evaluation
        let results_circ = runtime
            .evaluate_circuit(&circuit, Some(large_ct.clone()))
            .unwrap();
        let out_circ = &results_circ[&Identity("localhost:5000".to_string())];

        // test DDec2 with decryption endpoint
        let results_dec = runtime
            .threshold_decrypt(large_ct, DecryptionMode::Proto2Decrypt)
            .unwrap();
        let out_dec = &results_dec[&Identity("localhost:5000".to_string())];

        let ref_res = Value::Ring128(std::num::Wrapping(msg as u128));
        assert_eq!(out_dec[0], ref_res);
        assert!(out_circ[0] == ref_res);
    }

    #[traced_test]
    #[test]
    fn sunshine_domain_switching() {
        let keyset: KeySet = read_element(TEST_KEY_PATH.to_string()).unwrap();
        let keypair = KeyPair {
            sk: keyset.sk,
            pk: keyset.pk,
        };
        let message = (1
            << keypair
                .pk
                .threshold_lwe_parameters
                .input_cipher_parameters
                .message_modulus_log
                .0)
            - 1;
        let small_ct = keypair.pk.encrypt_block(&mut get_rng(), message);
        let large_ct = to_large_ciphertext_block(&keyset.ck, &small_ct);
        let res_small = keypair.sk.decrypt_block_64(&small_ct);
        let res_large = keypair.sk.decrypt_block_128(&large_ct);
        assert_eq!(message as u128, res_small.0);
        assert_eq!(message as u128, res_large.0);
    }
}

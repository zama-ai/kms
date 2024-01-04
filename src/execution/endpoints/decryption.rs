use std::{collections::HashMap, num::Wrapping, sync::Arc};

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use tfhe::core_crypto::prelude::*;
use tfhe::core_crypto::prelude::{
    lwe_ciphertext_modulus_switch_up, programmable_bootstrap_f128_lwe_ciphertext, CastFrom,
    GlweCiphertextOwned, GlweSize, LweCiphertext, UnsignedTorus,
};
use tfhe::integer::block_decomposition::BlockRecomposer;
use tfhe::shortint::prelude::PolynomialSize;

use tokio::task::JoinSet;

use crate::execution::runtime::session::SmallSessionHandles;
use crate::execution::sharing::open::robust_opens_to;
use crate::execution::small_execution::agree_random::RealAgreeRandom;
use crate::execution::small_execution::prss::PRSSSetup;
use crate::{
    algebra::{
        base_ring::{Z128, Z64},
        residue_poly::ResiduePoly128,
        structure_traits::Zero,
    },
    computation::SessionId,
    error::error_handler::anyhow_error_and_log,
    execution::{
        constants::{BD1, INPUT_PARTY_ID, LOG_BD, STATSEC},
        large_execution::offline::{
            BatchParams, RealLargePreprocessing, TrueDoubleSharing, TrueSingleSharing,
        },
        online::secret_distributions::{RealSecretDistributions, SecretDistributions},
        runtime::{
            party::{Identity, Role},
            session::{
                BaseSessionHandles, DecryptionMode, LargeSession, ParameterHandles,
                SessionParameters, SmallSession,
            },
            test_runtime::DistributedTestRuntime,
        },
    },
    lwe::{
        from_expanded_msg, BootstrappingKey, Ciphertext128, Ciphertext128Block, Ciphertext64,
        Ciphertext64Block, CiphertextParameters, SecretKeyShare,
    },
};

/// test the threshold decryption
pub fn threshold_decrypt(
    runtime: &DistributedTestRuntime<ResiduePoly128>,
    ct: Ciphertext128,
    mode: DecryptionMode,
) -> anyhow::Result<HashMap<Identity, Vec<Z64>>> {
    // TODO(Dragos) replaced this with a random sid
    let session_id = SessionId(2);

    let rt = tokio::runtime::Runtime::new()?;
    let _guard = rt.enter();

    let mut set = JoinSet::new();
    for (index_id, identity) in runtime.identities.clone().into_iter().enumerate() {
        let role_assignments = runtime.role_assignments.clone();
        let net = Arc::clone(&runtime.user_nets[index_id]);
        let threshold = runtime.threshold;

        let prss_setup = runtime
            .prss_setups
            .as_ref()
            .map(|per_party| per_party[&index_id].clone());

        let party_keyshare = runtime
            .keyshares
            .clone()
            .map(|ks| ks[index_id].clone())
            .ok_or_else(|| {
                anyhow_error_and_log("key share not set during decryption".to_string())
            })?;

        let ct = ct.clone();
        let mode = mode.clone();
        match mode {
            DecryptionMode::LargeDecrypt => {
                set.spawn(async move {
                    let session_params = SessionParameters::new(
                        threshold,
                        session_id,
                        identity.clone(),
                        role_assignments,
                    )
                    .unwrap();
                    let mut session = LargeSession::new(session_params, net).unwrap();
                    let out = run_decryption_large(&mut session, &party_keyshare, ct)
                        .await
                        .unwrap();
                    (identity, out)
                });
            }
            DecryptionMode::PRSSDecrypt => {
                set.spawn(async move {
                    let mut session = SmallSession::new(
                        session_id,
                        role_assignments,
                        net,
                        threshold,
                        prss_setup,
                        identity.clone(),
                        Some(ChaCha20Rng::from_entropy()),
                    )
                    .unwrap();

                    let prss_setup = PRSSSetup::init_with_abort::<
                        RealAgreeRandom,
                        ChaCha20Rng,
                        SmallSession<ResiduePoly128>,
                    >(&mut session)
                    .await
                    .unwrap();

                    session.set_prss(Some(
                        prss_setup.new_prss_session_state(session.session_id()),
                    ));

                    let out = run_decryption_small(&mut session, &party_keyshare, ct)
                        .await
                        .unwrap();
                    (identity, out)
                });
            }
        }
    }

    let results = rt.block_on(async {
        let mut results = HashMap::new();
        while let Some(v) = set.join_next().await {
            let (identity, val) = v.unwrap();
            results.insert(identity, val);
        }
        results
    });
    Ok(results)
}

/// Helper function that takes a vector of decrypted plaintexts (each of [bits_in_block] plaintext bits)
/// and combine them into the integer message (u128) of many bits.
fn combine(bits_in_block: u32, decryptions: Vec<Z128>) -> anyhow::Result<u128> {
    let mut recomposer = BlockRecomposer::<u128>::new(bits_in_block);

    for block in decryptions {
        if !recomposer.add_unmasked(block.0) {
            // End of T::BITS reached no need to try more
            // recomposition
            break;
        };
    }
    Ok(recomposer.value())
}

async fn open_masked_ptxts<R: RngCore + Send, S: BaseSessionHandles<R>>(
    session: &S,
    res: Vec<ResiduePoly128>,
    keyshares: &SecretKeyShare,
) -> anyhow::Result<Vec<Z128>> {
    let own_role = session.my_role()?;
    let openeds = robust_opens_to(
        session,
        &res,
        session.threshold() as usize,
        &own_role,
        INPUT_PARTY_ID,
    )
    .await?;

    if own_role.one_based() == INPUT_PARTY_ID {
        let message_mod_bits = keyshares
            .threshold_lwe_parameters
            .output_cipher_parameters
            .message_modulus_log
            .0;
        // shift
        let mut out = Vec::with_capacity(res.len());
        match openeds {
            Some(openeds) => {
                for opened in openeds {
                    let v_scalar = opened.to_scalar()?;
                    out.push(from_expanded_msg(v_scalar.0, message_mod_bits));
                }
            }
            _ => {
                return Err(anyhow_error_and_log(
                    "Right shift not possible - no opened value".to_string(),
                ))
            }
        };
        return Ok(out);
    }
    Ok(vec![Wrapping(0)])
}

fn combine_blocks(
    own_role: &Role,
    keyshares: &SecretKeyShare,
    partial_decrypted: Vec<Z128>,
) -> anyhow::Result<Vec<Z64>> {
    let mut outputs = Vec::new();
    if own_role.one_based() == INPUT_PARTY_ID {
        let bits_in_block = keyshares
            .threshold_lwe_parameters
            .output_cipher_parameters
            .usable_message_modulus_log
            .0;
        let res = match combine(bits_in_block as u32, partial_decrypted) {
            Ok(res) => res,
            Err(error) => {
                eprint!("Panicked in combining {error}");
                return Err(anyhow_error_and_log(format!(
                    "Panicked in combining {error}"
                )));
            }
        };
        outputs.push(Wrapping(res as u64));
    }
    Ok(outputs)
}

pub async fn run_decryption_large(
    session: &mut LargeSession,
    keyshares: &SecretKeyShare,
    ciphertext: Ciphertext128,
) -> anyhow::Result<Vec<Z64>> {
    let own_role = session.my_role()?;

    //Compute what we need from offline
    let bound = (STATSEC + LOG_BD) as usize;
    let nb_ctxt = ciphertext.len();
    //Need 2 uniform per ctxt, each uniform requires bound+2 bits
    //each bit requires 1 triple and 1 random
    let nb_preproc = 2 * nb_ctxt * (bound + 2);
    let batch_size = BatchParams {
        triple_batch_size: nb_preproc,
        random_batch_size: nb_preproc,
    };
    //Init nlarge offline once for all
    let mut large_preproc = RealLargePreprocessing::<ResiduePoly128>::init(
        session,
        Some(batch_size),
        TrueSingleSharing::default(),
        TrueDoubleSharing::default(),
    )
    .await?;
    //Get all the necessary uniform random
    let u_randoms =
        RealSecretDistributions::t_uniform(2 * nb_ctxt, bound, &mut large_preproc, session).await?;

    let mut shared_masked_ptxts = Vec::with_capacity(ciphertext.len());
    for (idx, current_ct_block) in ciphertext.iter().enumerate() {
        let partial_decrypt = partial_decrypt(keyshares, current_ct_block)?;
        let t = u_randoms[2 * idx] + u_randoms[2 * idx + 1];
        let res = partial_decrypt + t.value();

        shared_masked_ptxts.push(res);
        //partial_decrypted.push(open_masked_ptxt(session, res, keyshares).await?);
    }
    let partial_decrypted = open_masked_ptxts(session, shared_masked_ptxts, keyshares).await?;
    combine_blocks(&own_role, keyshares, partial_decrypted)
}

/// run decryption
pub async fn run_decryption_small(
    session: &mut SmallSession<ResiduePoly128>,
    keyshares: &SecretKeyShare,
    ciphertext: Ciphertext128,
) -> anyhow::Result<Vec<Z64>> {
    let own_role = session.my_role()?;

    let mut shared_masked_ptxts = Vec::with_capacity(ciphertext.len());
    for current_ct_block in ciphertext {
        let prss_state = session
            .prss_state
            .as_mut()
            .ok_or_else(|| anyhow_error_and_log("PRSS_State not initialized".to_string()))?;

        let partial_dec = partial_decrypt(keyshares, &current_ct_block)?;
        let composed_bits = prss_state.mask_next(own_role.one_based(), BD1)?;
        let res = partial_dec + composed_bits;

        shared_masked_ptxts.push(res);
    }

    let partial_decrypted = open_masked_ptxts(session, shared_masked_ptxts, keyshares).await?;
    combine_blocks(&own_role, keyshares, partial_decrypted)
}

pub fn partial_decrypt(
    sk_share: &SecretKeyShare,
    ct: &Ciphertext128Block,
) -> anyhow::Result<ResiduePoly128> {
    // NOTE eventually this secret key share will be a vector of ResiduePoly128 elements
    let (mask, body) = ct.get_mask_and_body();
    let a_time_s = (0..sk_share.input_key_share.len()).fold(ResiduePoly128::ZERO, |acc, column| {
        acc + sk_share.input_key_share[column]
            * ResiduePoly128::from_scalar(Wrapping(mask.as_ref()[column]))
    });
    // b-<a, s>
    let res = ResiduePoly128::from_scalar(Wrapping(*body.data)) - a_time_s;
    Ok(res)
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
/// Conversion is done using a precreated conversion key [ck].
/// Observe that the decryption key will be different after conversion, since [ck] is actually a key-switching key.
pub fn to_large_ciphertext(ck: &BootstrappingKey, small_ct: &Ciphertext64) -> Ciphertext128 {
    let mut res = Vec::with_capacity(small_ct.len());
    for current_block in small_ct {
        res.push(to_large_ciphertext_block(ck, current_block));
    }
    res
}

/// Converts a single ciphertext block over a 64 bit domain to a ciphertext block over a 128 bit domain (which is needed for secure threshold decryption).
/// Conversion is done using a precreated conversion key, [ck].
/// Observe that the decryption key will be different after conversion, since [ck] is actually a key-switching key.
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
    use aes_prng::AesRng;
    use rand::SeedableRng;

    use crate::{
        execution::{
            endpoints::decryption::{
                threshold_decrypt, to_large_ciphertext, to_large_ciphertext_block,
            },
            random::get_rng,
            runtime::{
                party::{Identity, Role},
                session::DecryptionMode,
                test_runtime::{generate_fixed_identities, DistributedTestRuntime},
            },
            sharing::{shamir::ShamirSharing, share::Share},
        },
        file_handling::read_element,
        lwe::{keygen_all_party_shares, KeyPair, KeySet},
        tests::test_data_setup::tests::TEST_KEY_PATH,
    };
    #[test]
    fn reconstruct_key() {
        let parties = 5;
        let keyset = read_element(TEST_KEY_PATH.to_string()).unwrap();
        let shares =
            keygen_all_party_shares(&keyset, &mut AesRng::seed_from_u64(0), parties, 1).unwrap();
        let mut first_bit_shares = Vec::with_capacity(parties);
        (0..parties).for_each(|i| {
            first_bit_shares.push(Share::new(
                Role::indexed_by_zero(i),
                *shares[i].input_key_share.get(0).unwrap(),
            ));
        });
        let first_bit_sharing = ShamirSharing::create(first_bit_shares);
        let rec = first_bit_sharing.err_reconstruct(1, 0).unwrap();
        let inner_rec = rec.to_scalar().unwrap();
        assert_eq!(
            keyset.sk.lwe_secret_key_128.into_container()[0],
            inner_rec.0
        );
    }

    #[test]
    fn test_large_threshold_decrypt() {
        let threshold = 1;
        let num_parties = 5;
        let msg: u8 = 3;
        let keyset: KeySet = read_element(TEST_KEY_PATH.to_string()).unwrap();

        let mut rng = AesRng::seed_from_u64(42);
        // generate keys
        let key_shares =
            keygen_all_party_shares(&keyset, &mut rng, num_parties, threshold).unwrap();
        let ct = keyset.pk.encrypt_w_bitlimit(&mut rng, msg, 2);
        let large_ct = to_large_ciphertext(&keyset.ck, &ct);

        let identities = generate_fixed_identities(num_parties);
        let mut runtime = DistributedTestRuntime::new(identities, threshold as u8);

        runtime.setup_keys(key_shares);

        let results_dec =
            threshold_decrypt(&runtime, large_ct, DecryptionMode::LargeDecrypt).unwrap();
        let out_dec = &results_dec[&Identity("localhost:5000".to_string())];

        let ref_res = std::num::Wrapping(msg as u64);
        assert_eq!(out_dec[0], ref_res);
    }

    #[test]
    fn test_small_threshold_decrypt() {
        let threshold = 1;
        let num_parties = 4;
        let msg: u8 = 3;
        let keyset: KeySet = read_element(TEST_KEY_PATH.to_string()).unwrap();

        let mut rng = AesRng::seed_from_u64(42);
        // generate keys
        let key_shares =
            keygen_all_party_shares(&keyset, &mut rng, num_parties, threshold).unwrap();
        let ct = keyset.pk.encrypt_w_bitlimit(&mut rng, msg, 2);
        let large_ct = to_large_ciphertext(&keyset.ck, &ct);

        let identities = generate_fixed_identities(num_parties);
        let mut runtime = DistributedTestRuntime::new(identities, threshold as u8);

        runtime.setup_keys(key_shares);

        let results_dec =
            threshold_decrypt(&runtime, large_ct, DecryptionMode::PRSSDecrypt).unwrap();
        let out_dec = &results_dec[&Identity("localhost:5000".to_string())];

        let ref_res = std::num::Wrapping(msg as u64);
        assert_eq!(out_dec[0], ref_res);
    }

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

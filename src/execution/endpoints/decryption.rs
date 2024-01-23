use std::{collections::HashMap, num::Wrapping, sync::Arc};

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::execution::config::BatchParams;
use crate::execution::large_execution::offline::LargePreprocessing;
use crate::execution::online::bit_manipulation::{bit_dec_batch, BatchedBits};
use crate::execution::online::preprocessing::Preprocessing;
use crate::execution::runtime::party::RoleAssignment;
use crate::execution::runtime::session::NetworkingImpl;
use crate::execution::runtime::session::SmallSession64;
use crate::execution::runtime::session::SmallSessionHandles;
use crate::execution::sharing::open::robust_opens_to;
use crate::execution::sharing::shamir::ShamirRing;
use crate::execution::sharing::share::Share;
use crate::execution::small_execution::agree_random::RealAgreeRandom;
use crate::execution::small_execution::offline::SmallPreprocessing;
use crate::execution::small_execution::prss::PRSSSetup;
use crate::lwe::combine128;
use crate::lwe::to_large_ciphertext;
use crate::{
    algebra::{
        base_ring::{Z128, Z64},
        residue_poly::ResiduePoly128,
        residue_poly::ResiduePoly64,
        structure_traits::Zero,
    },
    computation::SessionId,
    error::error_handler::anyhow_error_and_log,
    execution::{
        constants::{BD1, INPUT_PARTY_ID, LOG_BD, STATSEC},
        large_execution::offline::{RealLargePreprocessing, TrueDoubleSharing, TrueSingleSharing},
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
        from_expanded_msg, Ciphertext128, Ciphertext128Block, Ciphertext64, Ciphertext64Block,
        SecretKeyShare,
    },
};
use tokio::task::JoinSet;

/// Takes as input plaintexts blocks m1, ..., mN revealed to INPUT_PARTY_ID
/// which we call partial decryptions each of B bits
/// and uses tfhe block recomposer to get back the u64 plaintext.
fn combine_plaintext_blocks(
    own_role: &Role,
    bits_in_block: usize,
    partial_decrypted: Vec<Z128>,
) -> anyhow::Result<Vec<Z64>> {
    let mut outputs = Vec::new();
    if own_role.one_based() == INPUT_PARTY_ID {
        let res = match combine128(bits_in_block as u32, partial_decrypted) {
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

async fn setup_small_session<Z: ShamirRing>(
    session_id: SessionId,
    role_assignments: RoleAssignment,
    threshold: u8,
    network: NetworkingImpl,
    identity: Identity,
) -> SmallSession<Z> {
    let mut session = SmallSession::<Z>::new(
        session_id,
        role_assignments,
        network,
        threshold,
        None,
        identity.clone(),
        Some(ChaCha20Rng::from_entropy()),
    )
    .unwrap();

    let prss_setup =
        PRSSSetup::init_with_abort::<RealAgreeRandom, ChaCha20Rng, SmallSession<Z>>(&mut session)
            .await
            .unwrap();

    session.set_prss(Some(
        prss_setup.new_prss_session_state(session.session_id()),
    ));

    session
}

pub async fn init_prep_bitdec_small(
    session: &mut SmallSession64,
    num_ctxts: usize,
) -> SmallPreprocessing<ResiduePoly64, RealAgreeRandom> {
    let bitdec_batch = BatchParams {
        triples: 1280 * num_ctxts + num_ctxts,
        randoms: 64 * num_ctxts,
    };

    SmallPreprocessing::<ResiduePoly64, RealAgreeRandom>::init(session, bitdec_batch)
        .await
        .unwrap()
}

pub async fn init_prep_bitdec_large(
    session: &mut LargeSession,
    num_ctxts: usize,
) -> RealLargePreprocessing<ResiduePoly64> {
    let bitdec_batch = BatchParams {
        triples: 1280 * num_ctxts + num_ctxts,
        randoms: 64 * num_ctxts,
    };

    LargePreprocessing::<
        ResiduePoly64,
        TrueSingleSharing<ResiduePoly64>,
        TrueDoubleSharing<ResiduePoly64>,
    >::init(
        session,
        bitdec_batch,
        TrueSingleSharing::default(),
        TrueDoubleSharing::default(),
    )
    .await
    .unwrap()
}

/// test the threshold decryption
pub fn threshold_decrypt64<Z: ShamirRing>(
    runtime: &DistributedTestRuntime<Z>,
    ct: Ciphertext64,
    mode: DecryptionMode,
) -> anyhow::Result<HashMap<Identity, Vec<Z64>>> {
    let session_id = SessionId(1);

    let rt = tokio::runtime::Runtime::new()?;
    let _guard = rt.enter();

    let mut set = JoinSet::new();

    for (index_id, identity) in runtime.identities.clone().into_iter().enumerate() {
        let role_assignments = runtime.role_assignments.clone();
        let net = Arc::clone(&runtime.user_nets[index_id]);
        let threshold = runtime.threshold;

        let party_keyshare = runtime
            .keyshares
            .clone()
            .map(|ks| ks[index_id].clone())
            .ok_or_else(|| {
                anyhow_error_and_log("key share not set during decryption".to_string())
            })?;

        let ct = ct.clone();

        match mode {
            DecryptionMode::PRSSDecrypt => {
                let keyset_ck = runtime.get_ck();
                set.spawn(async move {
                    let large_ct = to_large_ciphertext(&keyset_ck, &ct);
                    let mut session = setup_small_session::<ResiduePoly128>(
                        session_id,
                        role_assignments,
                        threshold,
                        net,
                        identity.clone(),
                    )
                    .await;
                    let out = run_decryption_small(&mut session, &party_keyshare, large_ct)
                        .await
                        .unwrap();
                    (identity, out)
                });
            }
            DecryptionMode::LargeDecrypt => {
                let keyset_ck = runtime.get_ck();
                set.spawn(async move {
                    let large_ct = to_large_ciphertext(&keyset_ck, &ct);
                    let session_params = SessionParameters::new(
                        threshold,
                        session_id,
                        identity.clone(),
                        role_assignments,
                    )
                    .unwrap();
                    let mut session = LargeSession::new(session_params, net).unwrap();
                    let out = run_decryption_large(&mut session, &party_keyshare, large_ct)
                        .await
                        .unwrap();
                    (identity, out)
                });
            }
            DecryptionMode::BitDecLargeDecrypt => {
                set.spawn(async move {
                    let session_params = SessionParameters::new(
                        threshold,
                        session_id,
                        identity.clone(),
                        role_assignments,
                    )
                    .unwrap();
                    let mut session = LargeSession::new(session_params, net).unwrap();
                    let mut prep = init_prep_bitdec_large(&mut session, ct.len()).await;
                    let out = run_decryption_bitdec(&mut session, &mut prep, &party_keyshare, ct)
                        .await
                        .unwrap();

                    (identity, out)
                });
            }
            DecryptionMode::BitDecSmallDecrypt => {
                set.spawn(async move {
                    let mut session = setup_small_session::<ResiduePoly64>(
                        session_id,
                        role_assignments,
                        threshold,
                        net,
                        identity.clone(),
                    )
                    .await;
                    let mut prep = init_prep_bitdec_small(&mut session, ct.len()).await;
                    let out = run_decryption_bitdec(&mut session, &mut prep, &party_keyshare, ct)
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

async fn open_bit_composed_ptxts<R: RngCore + Send, S: BaseSessionHandles<R>>(
    session: &S,
    res: Vec<ResiduePoly64>,
) -> anyhow::Result<Vec<Z64>> {
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
        let mut out = Vec::with_capacity(res.len());
        match openeds {
            Some(openeds) => {
                for opened in openeds {
                    let v_scalar = opened.to_scalar()?;
                    out.push(v_scalar);
                }
            }
            _ => {
                return Err(anyhow_error_and_log(
                    "Error receiving shares for reconstructing bit-composed message".to_string(),
                ))
            }
        };
        return Ok(out);
    }
    Ok(vec![Wrapping(0)])
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
        triples: nb_preproc,
        randoms: nb_preproc,
    };
    //Init nlarge offline once for all
    let mut large_preproc = RealLargePreprocessing::<ResiduePoly128>::init(
        session,
        batch_size,
        TrueSingleSharing::default(),
        TrueDoubleSharing::default(),
    )
    .await?;
    //Get all the necessary uniform random
    let u_randoms =
        RealSecretDistributions::t_uniform(2 * nb_ctxt, bound, &mut large_preproc, session).await?;

    let mut shared_masked_ptxts = Vec::with_capacity(ciphertext.len());
    for (idx, current_ct_block) in ciphertext.iter().enumerate() {
        let partial_decrypt = partial_decrypt128(keyshares, current_ct_block)?;
        let t = u_randoms[2 * idx] + u_randoms[2 * idx + 1];
        let res = partial_decrypt + t.value();

        shared_masked_ptxts.push(res);
        //partial_decrypted.push(open_masked_ptxt(session, res, keyshares).await?);
    }
    let partial_decrypted = open_masked_ptxts(session, shared_masked_ptxts, keyshares).await?;
    let bits_in_block = keyshares
        .threshold_lwe_parameters
        .output_cipher_parameters
        .message_modulus_log
        .0;
    combine_plaintext_blocks(&own_role, bits_in_block, partial_decrypted)
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

        let partial_dec = partial_decrypt128(keyshares, &current_ct_block)?;
        let composed_bits = prss_state.mask_next(own_role.one_based(), BD1)?;
        let res = partial_dec + composed_bits;

        shared_masked_ptxts.push(res);
    }

    let partial_decrypted = open_masked_ptxts(session, shared_masked_ptxts, keyshares).await?;

    let bits_in_block = keyshares
        .threshold_lwe_parameters
        .output_cipher_parameters
        .message_modulus_log
        .0;

    combine_plaintext_blocks(&own_role, bits_in_block, partial_decrypted)
}

// run decryption with bit-decomposition
pub async fn run_decryption_bitdec<
    P: Preprocessing<ResiduePoly64> + std::marker::Send,
    Rnd: RngCore + Send + Sync,
    Ses: BaseSessionHandles<Rnd>,
>(
    session: &mut Ses,
    prep: &mut P,
    keyshares: &SecretKeyShare,
    ciphertext: Ciphertext64,
) -> anyhow::Result<Vec<Z64>> {
    let own_role = session.my_role()?;

    let mut shared_ptxts = Vec::with_capacity(ciphertext.len());
    for current_ct_block in ciphertext {
        let partial_dec = partial_decrypt64(keyshares, &current_ct_block)?;
        shared_ptxts.push(Share::new(own_role, partial_dec));
    }

    let bits = bit_dec_batch::<Z64, P, _, _>(session, prep, shared_ptxts)
        .await
        .unwrap();

    let message_mod_bits = keyshares
        .threshold_lwe_parameters
        .input_cipher_parameters
        .message_modulus_log
        .0;

    // bit-compose the plaintexts
    let ptxt_sums = BatchedBits::extract_ptxts(bits, message_mod_bits, prep, session).await?;
    let ptxt_sums: Vec<_> = ptxt_sums.iter().map(|ptxt_sum| ptxt_sum.value()).collect();

    // output results to party 0
    let ptxts64 = open_bit_composed_ptxts(session, ptxt_sums).await?;
    let ptxts128: Vec<_> = ptxts64
        .iter()
        .map(|ptxt| Wrapping(ptxt.0 as u128))
        .collect();

    // combine outputs to form the decrypted integer on party 0
    combine_plaintext_blocks(&own_role, message_mod_bits, ptxts128)
}

/// computes b - <a, s> with no rounding of the noise. This is used for noise flooding decryption
pub fn partial_decrypt128(
    sk_share: &SecretKeyShare,
    ct: &Ciphertext128Block,
) -> anyhow::Result<ResiduePoly128> {
    // NOTE eventually this secret key share will be a vector of ResiduePoly128 elements
    let (mask, body) = ct.get_mask_and_body();
    let a_time_s =
        (0..sk_share.input_key_share128.len()).fold(ResiduePoly128::ZERO, |acc, column| {
            acc + sk_share.input_key_share128[column]
                * ResiduePoly128::from_scalar(Wrapping(mask.as_ref()[column]))
        });
    // b-<a, s>
    let res = ResiduePoly128::from_scalar(Wrapping(*body.data)) - a_time_s;
    Ok(res)
}

// computes b - <a, s> + \Delta/2 for the bitwise decryption method
pub fn partial_decrypt64(
    sk_share: &SecretKeyShare,
    ct: &Ciphertext64Block,
) -> anyhow::Result<ResiduePoly64> {
    let ciphertext_modulus = 64;
    let (mask, body) = ct.get_mask_and_body();
    let key_share64 = sk_share.input_key_share64.clone();
    let a_time_s = (0..key_share64.len()).fold(ResiduePoly64::ZERO, |acc, column| {
        acc + key_share64[column] * ResiduePoly64::from_scalar(Wrapping(mask.as_ref()[column]))
    });
    // b-<a, s>
    let delta_pad_bits = ciphertext_modulus
        - (sk_share
            .threshold_lwe_parameters
            .input_cipher_parameters
            .message_modulus_log
            .0
            + 1);
    let delta_pad_half = (1_u64 << delta_pad_bits) >> 1;
    let scalar_delta_half = ResiduePoly64::from_scalar(Wrapping(delta_pad_half));
    let res = ResiduePoly64::from_scalar(Wrapping(*body.data)) - a_time_s + scalar_delta_half;
    Ok(res)
}

#[cfg(test)]
mod tests {
    use aes_prng::AesRng;
    use rand::SeedableRng;

    use crate::{
        algebra::residue_poly::{ResiduePoly128, ResiduePoly64},
        execution::{
            endpoints::decryption::threshold_decrypt64,
            runtime::{
                party::{Identity, Role},
                session::DecryptionMode,
                test_runtime::{generate_fixed_identities, DistributedTestRuntime},
            },
            sharing::{shamir::ShamirSharing, share::Share},
        },
        file_handling::read_element,
        lwe::{keygen_all_party_shares, KeySet},
        tests::test_data_setup::tests::TEST_KEY_PATH,
    };
    use std::sync::Arc;

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
                *shares[i].input_key_share128.get(0).unwrap(),
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
        let ct = keyset.pk.encrypt_w_bitlimit(&mut rng, msg, 4);

        let identities = generate_fixed_identities(num_parties);
        let mut runtime = DistributedTestRuntime::new(identities, threshold as u8);

        runtime.setup_cks(Arc::new(keyset.ck.clone()));
        runtime.setup_sks(key_shares);

        let results_dec =
            threshold_decrypt64::<ResiduePoly128>(&runtime, ct, DecryptionMode::LargeDecrypt)
                .unwrap();
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

        let identities = generate_fixed_identities(num_parties);
        let mut runtime = DistributedTestRuntime::new(identities, threshold as u8);

        runtime.setup_cks(Arc::new(keyset.ck.clone()));
        runtime.setup_sks(key_shares);

        let results_dec =
            threshold_decrypt64::<ResiduePoly128>(&runtime, ct, DecryptionMode::PRSSDecrypt)
                .unwrap();
        let out_dec = &results_dec[&Identity("localhost:5000".to_string())];

        let ref_res = std::num::Wrapping(msg as u64);
        assert_eq!(out_dec[0], ref_res);
    }

    #[test]
    fn test_small_bitdec_threshold_decrypt() {
        let threshold = 1;
        let num_parties = 5;
        let msg: u8 = 3;
        let keyset: KeySet = read_element(TEST_KEY_PATH.to_string()).unwrap();

        let mut rng = AesRng::seed_from_u64(42);
        // generate keys
        let key_shares =
            keygen_all_party_shares(&keyset, &mut rng, num_parties, threshold).unwrap();
        let ct = keyset.pk.encrypt_w_bitlimit(&mut rng, msg, 2);

        let identities = generate_fixed_identities(num_parties);
        let mut runtime = DistributedTestRuntime::<ResiduePoly64>::new(identities, threshold as u8);

        runtime.setup_sks(key_shares);

        let results_dec =
            threshold_decrypt64(&runtime, ct, DecryptionMode::BitDecSmallDecrypt).unwrap();
        let out_dec = &results_dec[&Identity("localhost:5000".to_string())];

        let ref_res = std::num::Wrapping(msg as u64);
        assert_eq!(out_dec[0], ref_res);
    }

    #[test]
    fn test_large_bitdec_threshold_decrypt() {
        let threshold = 1;
        let num_parties = 5;
        let msg: u8 = 15;
        let keyset: KeySet = read_element(TEST_KEY_PATH.to_string()).unwrap();

        let mut rng = AesRng::seed_from_u64(42);
        // generate keys
        let key_shares =
            keygen_all_party_shares(&keyset, &mut rng, num_parties, threshold).unwrap();
        let ct = keyset.pk.encrypt_w_bitlimit(&mut rng, msg, 4);

        let identities = generate_fixed_identities(num_parties);
        let mut runtime = DistributedTestRuntime::<ResiduePoly64>::new(identities, threshold as u8);

        runtime.setup_sks(key_shares);

        let results_dec =
            threshold_decrypt64(&runtime, ct, DecryptionMode::BitDecSmallDecrypt).unwrap();
        let out_dec = &results_dec[&Identity("localhost:5000".to_string())];

        let ref_res = std::num::Wrapping(msg as u64);
        assert_eq!(out_dec[0], ref_res);
    }
}

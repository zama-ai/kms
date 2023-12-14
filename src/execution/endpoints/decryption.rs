use std::{collections::HashMap, num::Wrapping, sync::Arc};

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tfhe::integer::block_decomposition::BlockRecomposer;
use tokio::task::JoinSet;

use crate::{
    algebra::{
        base_ring::{Z128, Z64},
        residue_poly::ResiduePoly128,
    },
    computation::SessionId,
    error::error_handler::anyhow_error_and_log,
    execution::{
        constants::INPUT_PARTY_ID,
        runtime::{
            party::Identity,
            session::{
                BaseSessionHandles, DecryptionMode, ParameterHandles, SmallSession, ToBaseSession,
            },
            test_runtime::DistributedTestRuntime,
        },
        sharing::open::robust_open_to,
        small_execution::prep::{ddec_prep, prss_prep},
    },
    lwe::{from_expanded_msg, Ciphertext128, SecretKeyShare},
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

        // TODO currently things only work with the static seed rng
        set.spawn(async move {
            let mut session = SmallSession::new(
                session_id,
                role_assignments,
                net,
                threshold,
                prss_setup,
                identity.clone(),
                Some(ChaCha20Rng::seed_from_u64(0)),
            )
            .unwrap();
            let out = run_decryption(&mut session, &party_keyshare, ct, mode)
                .await
                .unwrap();
            (identity, out)
        });
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

/// run decryption
pub async fn run_decryption(
    session: &mut SmallSession<ResiduePoly128>,
    keyshares: &SecretKeyShare,
    ciphertext: Ciphertext128,
    mode: DecryptionMode,
) -> anyhow::Result<Vec<Z64>> {
    let mut outputs = Vec::new();
    let threshold = session.threshold() as usize;
    let own_role = session.my_role()?;

    let mut partial_decrypted = Vec::with_capacity(ciphertext.len());
    for current_ct_block in ciphertext {
        let res = match mode {
            DecryptionMode::PRSSDecrypt => {
                let prss_state = session.prss_state.as_mut().ok_or_else(|| {
                    anyhow_error_and_log("PRSS_State not initialized".to_string())
                })?;

                prss_prep(
                    own_role.one_based(),
                    prss_state,
                    keyshares,
                    &current_ct_block,
                )?
            }
            DecryptionMode::Proto2Decrypt => ddec_prep(
                session.rng(),
                own_role.one_based(),
                threshold,
                keyshares,
                &current_ct_block,
            )?,
        };

        let opened = robust_open_to(
            &session.to_base_session(),
            res,
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
            let c = match opened {
                Some(v) => {
                    let v_scalar = v.to_scalar()?;
                    from_expanded_msg(v_scalar.0, message_mod_bits)
                }
                _ => {
                    return Err(anyhow_error_and_log(
                        "Right shift not possible - no opened value".to_string(),
                    ))
                }
            };
            partial_decrypted.push(c);
        }
    }
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
        outputs.push(Wrapping::<u64>(res.try_into()?));
    }

    Ok(outputs)
}

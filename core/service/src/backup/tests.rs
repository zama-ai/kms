use super::{custodian, error::BackupError, operator::Operator};
use crate::{
    backup::{
        custodian::{
            InternalCustodianContext, InternalCustodianRecoveryOutput,
            InternalCustodianSetupMessage,
        },
        operator::{InnerOperatorBackupOutput, RecoveryValidationMaterial},
        seed_phrase::{custodian_from_seed_phrase, seed_phrase_from_rng},
    },
    consts::DEFAULT_MPC_CONTEXT,
    cryptography::{
        encryption::{
            Encryption, PkeScheme, PkeSchemeType, UnifiedPrivateEncKey, UnifiedPublicEncKey,
        },
        signatures::{PublicSigKey, gen_sig_keys},
    },
    engine::base::derive_request_id,
};
use aes_prng::AesRng;
use itertools::Itertools;
use kms_grpc::{RequestId, kms::v1::CustodianContext};
use proptest::prelude::*;
use rand::{SeedableRng, rngs::OsRng};
use std::collections::BTreeMap;
use threshold_types::role::Role;

#[test]
fn operator_setup() {
    let mut rng = OsRng;
    let custodian_count = 10usize;
    let custodian_threshold = 3usize;

    // *setup*
    // custodians generate signing keys and encryption keys
    // those are sent to the operators
    let custodians: Vec<_> = (0..custodian_count)
        .map(|i| {
            let custodian_role = Role::indexed_from_zero(i);
            let (_verification_key, signing_key) = gen_sig_keys(&mut rng);
            let mut enc = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
            let (dec_key, enc_key) = enc.keygen().unwrap();
            custodian::Custodian::new(custodian_role, signing_key, enc_key, dec_key).unwrap()
        })
        .collect();
    let custodian_messages: Vec<_> = custodians
        .iter()
        .enumerate()
        .map(|(i, c)| {
            c.generate_setup_message(&mut rng, format!("Operator test name {i}"))
                .unwrap()
        })
        .collect();

    // use the wrong header for one party. This should not cause a failure
    {
        let mut wrong_custodian_messages = custodian_messages.clone();
        wrong_custodian_messages[0].header.push('z');

        let (_verification_key, signing_key) = gen_sig_keys(&mut rng);
        let operator = Operator::new_for_sharing(
            wrong_custodian_messages,
            signing_key,
            custodian_threshold,
            custodian_count,
        );
        let operator = operator.unwrap();
        // The invalid-header message should have been filtered out
        assert_eq!(operator.num_custodian_keys(), custodian_count - 1);
    }

    // use the wrong timestamp, setup should not fail
    {
        let mut wrong_custodian_messages = custodian_messages.clone();
        wrong_custodian_messages[1].timestamp += 24 * 3700;

        let (_verification_key, signing_key) = gen_sig_keys(&mut rng);
        let operator = Operator::new_for_sharing(
            wrong_custodian_messages,
            signing_key,
            custodian_threshold,
            custodian_count,
        );
        let operator = operator.unwrap();
        // The invalid-timestamp message should have been filtered out
        assert_eq!(operator.num_custodian_keys(), custodian_count - 1);
    }
}

#[test]
fn custodian_reencrypt() {
    let custodian_count = 3usize;
    let custodian_threshold = 1usize;
    let operator_count = 4usize;
    let secret_len = 32usize;
    let backup_id = RequestId::from_bytes([8u8; crate::consts::ID_LENGTH]);
    let mpc_context_id = *DEFAULT_MPC_CONTEXT;

    let mut rng = OsRng;

    let custodians: Vec<_> = (0..custodian_count)
        .map(|i| {
            let custodian_role = Role::indexed_from_zero(i);
            let (_verification_key, signing_key) = gen_sig_keys(&mut rng);
            let mut enc = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
            let (dec_key, enc_key) = enc.keygen().unwrap();
            custodian::Custodian::new(custodian_role, signing_key, enc_key, dec_key).unwrap()
        })
        .collect();
    let custodian_messages: Vec<_> = custodians
        .iter()
        .enumerate()
        .map(|(i, c)| {
            c.generate_setup_message(&mut rng, format!("Custodian test name {i}"))
                .unwrap()
        })
        .collect();
    let operators: Vec<_> = (0..operator_count)
        .map(|_i| {
            let (_verification_key, signing_key) = gen_sig_keys(&mut rng);
            Operator::new_for_sharing(
                custodian_messages.clone(),
                signing_key,
                custodian_threshold,
                custodian_count,
            )
            .unwrap()
        })
        .collect();

    // operators have some data, secret share and then encrypt for each custodian
    let secrets = (0..operator_count)
        .map(|_| {
            let mut buf = vec![0u8; secret_len];
            rng.fill_bytes(&mut buf);
            buf
        })
        .collect::<Vec<_>>();

    // signcrypt_results[i].ct_shares[j] should go to custodian j, for all i
    let signcrypt_results = operators
        .iter()
        .zip_eq(&secrets)
        .map(|(operator, secret)| {
            operator
                .secret_share_and_signcrypt(&mut rng, secret, backup_id, mpc_context_id)
                .unwrap()
        })
        .collect::<Vec<_>>();

    let verification_key = operators[0].verification_key();

    let mut enc = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
    let (_ephemeral_dec_key, ephemeral_enc_key) = enc.keygen().unwrap();

    // tweak the ciphertext, so that signature verification fails
    {
        let operator_role = Role::indexed_from_zero(0);
        let mut bad_results = signcrypt_results.clone();
        if let Some(z) = bad_results[0].ct_shares.get_mut(&operator_role) {
            z.signcryption.payload[0] ^= 1;
        }

        let err = custodians[0]
            .verify_reencrypt(
                &mut rng,
                bad_results[0].ct_shares.get(&operator_role).unwrap(),
                verification_key,
                &ephemeral_enc_key,
            )
            .unwrap_err();
        assert!(matches!(err, BackupError::CustodianRecoveryError));
    }

    // tweak the signature, so that signature verification also fails
    {
        let operator_role = Role::indexed_from_zero(0);
        let mut bad_results = signcrypt_results.clone();
        if let Some(z) = bad_results[0].ct_shares.get_mut(&operator_role) {
            z.signcryption.payload[0] ^= 1;
        }

        let err = custodians[0]
            .verify_reencrypt(
                &mut rng,
                bad_results[0].ct_shares.get(&operator_role).unwrap(),
                verification_key,
                &ephemeral_enc_key,
            )
            .unwrap_err();
        assert!(matches!(err, BackupError::CustodianRecoveryError));
    }

    // no tweaks, all should pass
    {
        let operator_role = Role::indexed_from_zero(0);
        let _ = custodians[0]
            .verify_reencrypt(
                &mut rng,
                signcrypt_results[0].ct_shares.get(&operator_role).unwrap(),
                verification_key,
                &ephemeral_enc_key,
            )
            .unwrap();
    }
}

#[rstest::rstest]
#[case(4, 5, 2)]
#[case(4, 3, 1)]
#[case(13, 3, 1)]
fn full_flow(
    #[case] operator_count: usize,
    #[case] custodian_count: usize,
    #[case] custodian_threshold: usize,
) {
    let mut rng = AesRng::seed_from_u64(1337);
    let backup_id = derive_request_id(std::stringify!(full_flow)).unwrap();

    let (setup_msgs, mnemonics) = generate_setup_messages(&mut rng, custodian_count);
    let (operators, payload_for_custodians) = operator_handle_init(
        &mut rng,
        &setup_msgs,
        &backup_id,
        operator_count,
        custodian_threshold,
        custodian_count,
    );
    let ops_addresses = operators.keys();
    let backups = custodian_recover(
        &mut rng,
        &mnemonics,
        &payload_for_custodians,
        custodian_threshold,
    );
    assert!(backups.len() == operator_count);
    let recovered_secrets = operator_recover(&backups, &operators);
    assert!(recovered_secrets.len() == operator_count);

    for op_addr in ops_addresses {
        assert!(recovered_secrets.contains_key(op_addr));
        let cur_priv_key = operators.get(op_addr).unwrap().2.clone();
        assert_eq!(
            recovered_secrets[op_addr],
            bc2wrap::serialize(&cur_priv_key).unwrap()
        );
    }
}

#[test]
fn full_flow_drop_msg() {
    let mut rng = AesRng::seed_from_u64(1337);
    let backup_id = derive_request_id(std::stringify!(full_flow_drop_msg)).unwrap();
    let operator_count = 4usize;
    let custodian_count = 5usize;
    let custodian_threshold = 2usize;

    let (setup_msgs, mnemonics) = generate_setup_messages(&mut rng, custodian_count);
    let (operators, payload_for_custodians) = operator_handle_init(
        &mut rng,
        &setup_msgs,
        &backup_id,
        operator_count,
        custodian_threshold,
        custodian_count,
    );
    let op_addresses = operators.keys();
    // Drop first and last custodian
    let mnemonics_dropped: BTreeMap<Role, String> = mnemonics
        .iter()
        // Drop custodians 1 and 5, the maximum allowed
        .filter_map(|(k, v)| {
            if *k == Role::indexed_from_one(1) || *k == Role::indexed_from_one(5) {
                None
            } else {
                Some((*k, v.clone()))
            }
        })
        .collect();
    assert!(mnemonics_dropped.len() > custodian_threshold);
    let backups = custodian_recover(
        &mut rng,
        &mnemonics_dropped,
        &payload_for_custodians,
        custodian_threshold,
    );
    assert!(backups.len() == operator_count);
    let recovered_secrets = operator_recover(&backups, &operators);
    assert!(recovered_secrets.len() == operator_count);

    for addr in op_addresses {
        assert!(recovered_secrets.contains_key(addr));
        let cur_priv_key = operators.get(addr).unwrap().2.clone();
        assert_eq!(
            recovered_secrets[addr],
            bc2wrap::serialize(&cur_priv_key).unwrap()
        );
    }
}

#[test]
#[should_panic]
fn full_flow_malicious_custodian_not_enough() {
    let mut rng = AesRng::seed_from_u64(1337);
    let backup_id = derive_request_id(std::stringify!(full_flow_malicious_custodian)).unwrap();
    let operator_count = 4usize;
    let custodian_count = 5usize;
    let custodian_threshold = 2usize;

    let (setup_msgs, _mnemonics) = generate_setup_messages(&mut rng, custodian_count);
    // Change one custodian's setup messages to an invalid one

    let mut setup_msgs_malicious = setup_msgs.clone();
    // Remove 2nd setup message
    setup_msgs_malicious.remove(1);
    // Remove 3nd setup message
    setup_msgs_malicious.remove(1);
    // Remove 4nd setup message
    setup_msgs_malicious.remove(1);
    // Should panic because we need at least 3 custodians.
    let _ = operator_handle_init(
        &mut rng,
        &setup_msgs_malicious,
        &backup_id,
        operator_count,
        custodian_threshold,
        custodian_count,
    );
}

#[test]
fn full_flow_malicious_custodian_init() {
    let mut rng = AesRng::seed_from_u64(1337);
    let backup_id = derive_request_id(std::stringify!(full_flow_malicious_custodian)).unwrap();
    let operator_count = 4usize;
    let custodian_count = 5usize;
    let custodian_threshold = 2usize;

    let (setup_msgs, _mnemonics) = generate_setup_messages(&mut rng, custodian_count);
    // Change one custodian's setup messages to an invalid one
    let mut setup_msgs_malicious = setup_msgs.clone();
    // Remove 2nd setup message
    setup_msgs_malicious.remove(1);
    // Should be fine since we just need at least 2+1 = 3 custodians
    for _op_idx in 1..=operator_count {
        let (_verification_key, signing_key) = gen_sig_keys(&mut rng);
        let operator = Operator::new_for_sharing(
            setup_msgs_malicious.to_vec(),
            signing_key.clone(),
            custodian_threshold,
            custodian_count,
        )
        .unwrap();
        // Verify the missing custodian was detected (only 4 of 5 accepted)
        assert_eq!(operator.num_custodian_keys(), custodian_count - 1);
        let mut enc = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (backup_priv_key, _backup_enc_key) = enc.keygen().unwrap();
        let result = operator
            .secret_share_and_signcrypt(
                &mut rng,
                &bc2wrap::serialize(&backup_priv_key).unwrap(),
                backup_id,
                *DEFAULT_MPC_CONTEXT,
            )
            .unwrap();
        assert!(
            result.skipped_roles.contains(&Role::indexed_from_one(2)),
            "expected role 2 to be skipped (removed custodian): {:?}",
            result.skipped_roles
        );
    }
}

#[test]
fn full_flow_malicious_custodian_second() {
    let mut rng = AesRng::seed_from_u64(1337);
    let backup_id = derive_request_id(std::stringify!(full_flow_malicious_custodian)).unwrap();
    let operator_count = 4usize;
    let custodian_count = 5usize;
    let custodian_threshold = 2usize;

    let (setup_msgs, mnemonics) = generate_setup_messages(&mut rng, custodian_count);
    let (operators, payload_for_custodians) = operator_handle_init(
        &mut rng,
        &setup_msgs,
        &backup_id,
        operator_count,
        custodian_threshold,
        custodian_count,
    );
    let op_addresses = operators.keys().cloned().collect::<Vec<_>>();

    // Change one custodian's mnemonic to an invalid one
    {
        let mut mnemonics_malicious = mnemonics.clone();
        // Update the 3rd custodian to an incorrect mnemonic
        let _= mnemonics_malicious.insert(
            Role::indexed_from_one(3),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                .to_string());
        let backups = custodian_recover(
            &mut rng,
            &mnemonics_malicious,
            &payload_for_custodians,
            custodian_threshold,
        );
        // We should still be able to recover even though one custodian is malicious
        assert!(backups.len() == operator_count);
        let recovered_secrets = operator_recover(&backups, &operators);
        assert!(recovered_secrets.len() == operator_count);

        for op_addr in &op_addresses {
            assert!(recovered_secrets.contains_key(op_addr));
            let cur_priv_key = operators.get(op_addr).unwrap().2.clone();
            assert_eq!(
                recovered_secrets[op_addr],
                bc2wrap::serialize(&cur_priv_key).unwrap()
            );
        }
    }

    // Drop middle custodian and set the first one to something malicious
    {
        let mnemonics_malicious_dropped = mnemonics.clone();
        let mut mnemonics_malicious_dropped: BTreeMap<Role, String> = mnemonics_malicious_dropped
            .iter()
            // Drop custodian 3
            .filter_map(|(k, v)| {
                if *k != Role::indexed_from_one(3) {
                    Some((*k, v.clone()))
                } else {
                    None
                }
            })
            .collect();
        // Update the first custodian to an incorrect mnemonic
        let _=  mnemonics_malicious_dropped.insert(
            Role::indexed_from_one(1),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
                .to_string());
        let backups = custodian_recover(
            &mut rng,
            &mnemonics_malicious_dropped,
            &payload_for_custodians,
            custodian_threshold,
        );
        assert!(backups.len() == operator_count);
        let recovered_secrets = operator_recover(&backups, &operators);
        assert!(recovered_secrets.len() == operator_count);

        for op_addr in &op_addresses {
            assert!(recovered_secrets.contains_key(op_addr));
            let cur_priv_key = operators.get(op_addr).unwrap().2.clone();
            assert_eq!(
                recovered_secrets[op_addr],
                bc2wrap::serialize(&cur_priv_key).unwrap()
            );
        }
    }
}

#[test]
fn full_flow_malicious_operator() {
    let mut rng = AesRng::seed_from_u64(1337);
    let backup_id = derive_request_id(std::stringify!(full_flow_malicious_operator)).unwrap();
    let operator_count = 4usize;
    let custodian_count = 5usize;
    let custodian_threshold = 2usize;

    let (setup_msgs, mnemonics) = generate_setup_messages(&mut rng, custodian_count);
    let (operators, payload_for_custodians) = operator_handle_init(
        &mut rng,
        &setup_msgs,
        &backup_id,
        operator_count,
        custodian_threshold,
        custodian_count,
    );
    let op_addresses = operators.keys().cloned().collect::<Vec<_>>();

    // Drop one operator's init messages and set another to something malicious
    {
        let mut payload_for_custodians_malicious = payload_for_custodians.clone();

        // Remove the 3rd operator's payload
        let op_to_remove = &op_addresses[2];
        let _ = payload_for_custodians_malicious.remove(op_to_remove);

        // Change the first one maliciously by flipping a bit in each ciphertext
        let op_malicious = &op_addresses[0];
        let (first_verf_key, first_backup_key, mut first_backup) = payload_for_custodians_malicious
            .get(op_malicious)
            .unwrap()
            .clone();
        first_backup.iter_mut().for_each(|(_, v)| {
            v.signcryption.payload[0] ^= 1;
        });
        let _ = payload_for_custodians_malicious.insert(
            op_malicious.clone(),
            (first_verf_key, first_backup_key, first_backup),
        );

        let backups = custodian_recover(
            &mut rng,
            &mnemonics,
            &payload_for_custodians_malicious,
            custodian_threshold,
        );
        // One missing and one malicious operator
        assert!(backups.len() == operator_count - 2);
        let recovered_secrets = operator_recover(&backups, &operators);
        assert!(recovered_secrets.len() == operator_count - 2);

        for (cur_role, cur_secret) in recovered_secrets {
            let cur_priv_key = operators.get(&cur_role).unwrap().2.clone();
            assert_eq!(cur_secret, bc2wrap::serialize(&cur_priv_key).unwrap());
        }
    }
}

fn generate_setup_messages(
    rng: &mut AesRng,
    custodian_count: usize,
) -> (Vec<InternalCustodianSetupMessage>, BTreeMap<Role, String>) {
    let mut setup_msgs = Vec::new();
    let mut mnemonics = BTreeMap::new();
    for idx in 1..=custodian_count {
        let custodian_role = Role::indexed_from_one(idx);
        let mnemonic = seed_phrase_from_rng(rng).unwrap();
        let cur_cus = custodian_from_seed_phrase(&mnemonic, custodian_role).unwrap();
        setup_msgs.push(
            cur_cus
                .generate_setup_message(rng, format!("cus-{}", idx))
                .unwrap(),
        );
        mnemonics.insert(custodian_role, mnemonic);
    }
    (setup_msgs, mnemonics)
}

/// Emulate the honest operators' execute of `CustodianRecoveryInit` by
/// returning two maps; one with the material to return to the custodians and
/// one with the material of the emulated operators' internal state (needed to continue the backup recovery protocol).
fn operator_handle_init(
    rng: &mut AesRng,
    setup_msgs: &[InternalCustodianSetupMessage],
    backup_id: &RequestId,
    operator_count: usize,
    custodian_threshold: usize,
    custodian_count: usize,
) -> (OperatorsMap, CustodianBackupsMap) {
    // note that PublicSigKey cannot be used as BTreeMap key directly since it's not Ord
    let mut payload_for_custodians = BTreeMap::new();
    let mut operators = BTreeMap::new();
    let cus_context = CustodianContext {
        custodian_nodes: setup_msgs
            .iter()
            .map(|msg| msg.to_owned().try_into().unwrap())
            .collect(),
        custodian_context_id: Some((*backup_id).into()),
        threshold: custodian_threshold as u32,
    };
    for _op_idx in 1..=operator_count {
        let (verification_key, signing_key) = gen_sig_keys(rng);
        let operator = Operator::new_for_sharing(
            setup_msgs.to_vec(),
            signing_key.clone(),
            custodian_threshold,
            custodian_count,
        )
        .unwrap();
        let mut enc = Encryption::new(PkeSchemeType::MlKem512, rng);
        let (backup_dec_key, backup_enc_key) = enc.keygen().unwrap();
        let signcrypt_result = operator
            .secret_share_and_signcrypt(
                rng,
                &bc2wrap::serialize(&backup_dec_key).unwrap(),
                *backup_id,
                *DEFAULT_MPC_CONTEXT,
            )
            .unwrap();
        let cur_op_output = signcrypt_result.ct_shares;
        let cur_comm = signcrypt_result.commitments;
        let operator_cus_context =
            InternalCustodianContext::new(cus_context.clone(), backup_enc_key.clone()).unwrap();
        let validation_material = RecoveryValidationMaterial::new(
            cur_op_output.to_owned(),
            cur_comm.to_owned(),
            operator_cus_context,
            &signing_key,
            *DEFAULT_MPC_CONTEXT,
        )
        .unwrap();
        operators.insert(
            verification_key.verf_key_id(),
            (
                operator,
                validation_material,
                backup_dec_key,
                backup_enc_key.clone(),
            ),
        );
        payload_for_custodians.insert(
            verification_key.verf_key_id(),
            (verification_key, backup_enc_key, cur_op_output),
        );
    }
    (operators, payload_for_custodians)
}

// Operator address to verification key, ephemeral key and backup ct map
type CustodianBackupsMap = BTreeMap<
    Vec<u8>,
    (
        PublicSigKey,
        UnifiedPublicEncKey,
        BTreeMap<Role, InnerOperatorBackupOutput>,
    ),
>;

// Operator address to (Operator, validation material, ephemeral decryption key)
type OperatorsMap = BTreeMap<
    Vec<u8>,
    (
        Operator,
        RecoveryValidationMaterial,
        UnifiedPrivateEncKey,
        UnifiedPublicEncKey,
    ),
>;

fn custodian_recover(
    rng: &mut AesRng,
    mnemonics: &BTreeMap<Role, String>, // keyed by custodian role
    backups: &CustodianBackupsMap, // Operator role to verf key, ephemeral key and backup ct map
    custodian_threshold: usize,
) -> BTreeMap<Vec<u8>, BTreeMap<Role, InternalCustodianRecoveryOutput>> {
    let mut res = BTreeMap::new();
    for (cur_operator_address, (verification_key, ephemeral_enc_key, cur_backup)) in backups {
        let mut cur_operator_res = BTreeMap::new();
        for (cur_cus_role, cur_mnemonic) in mnemonics {
            let custodian = custodian_from_seed_phrase(cur_mnemonic, *cur_cus_role).unwrap();
            // what is recovered is a reencryption
            match custodian.verify_reencrypt(
                rng,
                cur_backup.get(cur_cus_role).unwrap(),
                verification_key,
                ephemeral_enc_key,
            ) {
                Ok(cur_res) => cur_operator_res.insert(*cur_cus_role, cur_res),
                Err(_) => {
                    continue;
                } // Skip if re-encryption fails
            };
        }
        // Only insert if we have enough re-encryptions
        if cur_operator_res.len() > custodian_threshold {
            res.insert(cur_operator_address.clone(), cur_operator_res);
        }
    }
    res
}

fn operator_recover(
    reencryptions: &BTreeMap<Vec<u8>, BTreeMap<Role, InternalCustodianRecoveryOutput>>,
    operators: &OperatorsMap,
) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let mut res = BTreeMap::new();
    for (cur_op_addr, (cur_op, cur_com, cur_emphemeral_dec, cur_ephemeral_enc)) in operators {
        if let Some(cur_reencs) = reencryptions.get(cur_op_addr) {
            let reencs_vec: Vec<_> = cur_reencs.values().cloned().collect();
            match cur_op.verify_and_recover(
                &reencs_vec,
                cur_com,
                cur_emphemeral_dec,
                cur_ephemeral_enc,
            ) {
                Ok(plaintext) => res.insert(cur_op_addr.clone(), plaintext),
                Err(_) => continue, // Skip if recovery fails
            };
        }
    }
    res
}

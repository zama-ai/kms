use super::{custodian, error::BackupError, operator::Operator};
use crate::{
    backup::{
        custodian::{InternalCustodianContext, InternalCustodianSetupMessage},
        operator::{InnerOperatorBackupOutput, RecoveryValidationMaterial},
        seed_phrase::{custodian_from_seed_phrase, seed_phrase_from_rng},
    },
    cryptography::internal_crypto_types::{
        gen_sig_keys, Encryption, EncryptionScheme, EncryptionSchemeType, PublicSigKey,
        UnifiedPrivateEncKey, UnifiedPublicEncKey,
    },
    engine::base::derive_request_id,
};
use aes_prng::AesRng;
use itertools::Itertools;
use kms_grpc::{kms::v1::CustodianContext, rpc_types::InternalCustodianRecoveryOutput, RequestId};
use proptest::prelude::*;
use rand::{rngs::OsRng, SeedableRng};
use std::collections::BTreeMap;
use threshold_fhe::execution::runtime::party::Role;

#[tracing_test::traced_test]
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
            let mut enc = Encryption::new(EncryptionSchemeType::MlKem512, &mut rng);
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
        let operator = Operator::new(
            Role::indexed_from_zero(0),
            wrong_custodian_messages,
            signing_key,
            custodian_threshold,
            custodian_count,
        );
        assert!(operator.is_ok());
        assert!(logs_contain(
            "Invalid header in custodian setup message from custodian 1"
        ));
    }

    // use the wrong timestamp, setup should not fail
    {
        let mut wrong_custodian_messages = custodian_messages.clone();
        wrong_custodian_messages[1].timestamp += 24 * 3700;

        let (_verification_key, signing_key) = gen_sig_keys(&mut rng);
        let operator = Operator::new(
            Role::indexed_from_zero(0),
            wrong_custodian_messages,
            signing_key,
            custodian_threshold,
            custodian_count,
        );
        assert!(operator.is_ok());
        assert!(logs_contain(
            "Invalid timestamp in custodian setup message from custodian 2"
        ));
    }
}

#[test]
fn custodian_reencrypt() {
    let custodian_count = 3usize;
    let custodian_threshold = 1usize;
    let operator_count = 4usize;
    let secret_len = 32usize;
    let backup_id = RequestId::from_bytes([8u8; crate::consts::ID_LENGTH]);

    let mut rng = OsRng;

    let custodians: Vec<_> = (0..custodian_count)
        .map(|i| {
            let custodian_role = Role::indexed_from_zero(i);
            let (_verification_key, signing_key) = gen_sig_keys(&mut rng);
            let mut enc = Encryption::new(EncryptionSchemeType::MlKem512, &mut rng);
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
        .map(|i| {
            let operator_role = Role::indexed_from_zero(i);
            let (_verification_key, signing_key) = gen_sig_keys(&mut rng);
            Operator::new(
                operator_role,
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

    // cts[i][j] should go to custodian j, for all i
    let cts = operators
        .iter()
        .zip_eq(&secrets)
        .map(|(operator, secret)| {
            operator
                .secret_share_and_encrypt(&mut rng, secret, backup_id)
                .unwrap()
        })
        .collect::<Vec<_>>();

    let verification_key = operators[0].verification_key();
    let mut enc = Encryption::new(EncryptionSchemeType::MlKem512, &mut rng);
    let (_ephemeral_dec_key, ephemeral_enc_key) = enc.keygen().unwrap();

    // tweak the ciphertext, so that signature verification fails
    {
        let operator_role = Role::indexed_from_zero(0);
        let mut bad_cts = cts.clone();
        if let Some(z) = bad_cts[0].0.get_mut(&operator_role) {
            z.ciphertext.cipher[0] ^= 1;
        }

        let err = custodians[0]
            .verify_reencrypt(
                &mut rng,
                bad_cts[0].0.get(&operator_role).unwrap(),
                verification_key,
                &ephemeral_enc_key,
                backup_id,
                operator_role,
            )
            .unwrap_err();
        assert!(matches!(err, BackupError::SignatureVerificationError(..)));
    }

    // tweak the signature, so that signature verification also fails
    {
        let operator_role = Role::indexed_from_zero(0);
        let mut bad_cts = cts.clone();
        if let Some(z) = bad_cts[0].0.get_mut(&operator_role) {
            z.signature[0] ^= 1;
        }

        let err = custodians[0]
            .verify_reencrypt(
                &mut rng,
                bad_cts[0].0.get(&operator_role).unwrap(),
                verification_key,
                &ephemeral_enc_key,
                backup_id,
                operator_role,
            )
            .unwrap_err();
        assert!(matches!(err, BackupError::SignatureVerificationError(..)));
    }

    // use the wrong backup_id
    {
        let operator_role = Role::indexed_from_zero(0);
        let bad_backup_id = RequestId::from_bytes([7u8; crate::consts::ID_LENGTH]);
        let err = custodians[0]
            .verify_reencrypt(
                &mut rng,
                cts[0].0.get(&operator_role).unwrap(),
                verification_key,
                &ephemeral_enc_key,
                bad_backup_id,
                operator_role,
            )
            .unwrap_err();
        assert!(matches!(err, BackupError::CustodianRecoveryError));
    }

    // use the wrong operator_role
    {
        let operator_role = Role::indexed_from_zero(0);
        let wrong_operator_role = Role::indexed_from_zero(1);
        let err = custodians[0]
            .verify_reencrypt(
                &mut rng,
                cts[0].0.get(&operator_role).unwrap(),
                verification_key,
                &ephemeral_enc_key,
                backup_id,
                wrong_operator_role,
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
                cts[0].0.get(&operator_role).unwrap(),
                verification_key,
                &ephemeral_enc_key,
                backup_id,
                operator_role,
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
    let backups = custodian_recover(
        &mut rng,
        &backup_id,
        &mnemonics,
        &payload_for_custodians,
        custodian_threshold,
    );
    assert!(backups.len() == operator_count);
    let recovered_secrets = operator_recover(&backups, &operators, &backup_id);
    assert!(recovered_secrets.len() == operator_count);

    for idx in 1..=operator_count {
        let role = Role::indexed_from_one(idx);
        assert!(recovered_secrets.contains_key(&role));
        let cur_priv_key = operators.get(&role).unwrap().2.clone();
        assert_eq!(
            recovered_secrets[&role],
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
        &backup_id,
        &mnemonics_dropped,
        &payload_for_custodians,
        custodian_threshold,
    );
    assert!(backups.len() == operator_count);
    let recovered_secrets = operator_recover(&backups, &operators, &backup_id);
    assert!(recovered_secrets.len() == operator_count);

    for idx in 1..=operator_count {
        let role = Role::indexed_from_one(idx);
        assert!(recovered_secrets.contains_key(&role));
        let cur_priv_key = operators.get(&role).unwrap().2.clone();
        assert_eq!(
            recovered_secrets[&role],
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

#[tracing_test::traced_test]
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
    for op_idx in 1..=operator_count {
        let operator_role = Role::indexed_from_one(op_idx);
        let (_verification_key, signing_key) = gen_sig_keys(&mut rng);
        let operator = Operator::new(
            operator_role,
            setup_msgs_malicious.to_vec(),
            signing_key.clone(),
            custodian_threshold,
            custodian_count,
        )
        .unwrap();
        let mut enc = Encryption::new(EncryptionSchemeType::MlKem512, &mut rng);
        let (backup_priv_key, _backup_enc_key) = enc.keygen().unwrap();
        let res = operator.secret_share_and_encrypt(
            &mut rng,
            &bc2wrap::serialize(&backup_priv_key).unwrap(),
            backup_id,
        );
        assert!(res.is_ok());
    }
    // Check that we indeed get a warning about the malicious custodian
    assert!(logs_contain(
        "An incorrect amount of custodian messages were received"
    ));
    assert!(logs_contain("Could not find custodian keys for role 2"));
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
            &backup_id,
            &mnemonics_malicious,
            &payload_for_custodians,
            custodian_threshold,
        );
        // We should still be able to recover even though one custodian is malicious
        assert!(backups.len() == operator_count);
        let recovered_secrets = operator_recover(&backups, &operators, &backup_id);
        assert!(recovered_secrets.len() == operator_count);

        for idx in 1..=operator_count {
            let role = Role::indexed_from_one(idx);
            assert!(recovered_secrets.contains_key(&role));
            let cur_priv_key = operators.get(&role).unwrap().2.clone();
            assert_eq!(
                recovered_secrets[&role],
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
            &backup_id,
            &mnemonics_malicious_dropped,
            &payload_for_custodians,
            custodian_threshold,
        );
        assert!(backups.len() == operator_count);
        let recovered_secrets = operator_recover(&backups, &operators, &backup_id);
        assert!(recovered_secrets.len() == operator_count);

        for idx in 1..=operator_count {
            let role = Role::indexed_from_one(idx);
            assert!(recovered_secrets.contains_key(&role));
            let cur_priv_key = operators.get(&role).unwrap().2.clone();
            assert_eq!(
                recovered_secrets[&role],
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
    // Drop one operator's init messages and set another to something malicious
    {
        let mut payload_for_custodians_malicious = payload_for_custodians.clone();
        // Remove the 3rd operator's payload
        let _ = payload_for_custodians_malicious.remove(&Role::indexed_from_one(3));
        // Change the first one maliciously by flipping a bit in each ciphertext
        let (first_verf_key, first_backup_key, mut first_backup) = payload_for_custodians_malicious
            .get(&Role::indexed_from_one(1))
            .unwrap()
            .clone();
        first_backup.iter_mut().for_each(|(_, v)| {
            v.ciphertext.cipher[0] ^= 1;
        });
        let _ = payload_for_custodians_malicious.insert(
            Role::indexed_from_one(1),
            (first_verf_key, first_backup_key, first_backup),
        );

        let backups = custodian_recover(
            &mut rng,
            &backup_id,
            &mnemonics,
            &payload_for_custodians_malicious,
            custodian_threshold,
        );
        // One missing and one malicious operator
        assert!(backups.len() == operator_count - 2);
        let recovered_secrets = operator_recover(&backups, &operators, &backup_id);
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
#[allow(clippy::type_complexity)]
fn operator_handle_init(
    rng: &mut AesRng,
    setup_msgs: &[InternalCustodianSetupMessage],
    backup_id: &RequestId,
    operator_count: usize,
    custodian_threshold: usize,
    custodian_count: usize,
) -> (
    BTreeMap<Role, (Operator, RecoveryValidationMaterial, UnifiedPrivateEncKey)>, // Operator role to (Operator, validation material, ephemeral decryption key)
    BTreeMap<
        Role,
        (
            PublicSigKey,
            UnifiedPublicEncKey,
            BTreeMap<Role, InnerOperatorBackupOutput>,
        ),
    >, // Operator role to verf key, ephemeral key and backup ct map
) {
    let mut payload_for_custodians = BTreeMap::new();
    let mut operators = BTreeMap::new();
    let cus_context = CustodianContext {
        custodian_nodes: setup_msgs
            .iter()
            .map(|msg| msg.to_owned().try_into().unwrap())
            .collect(),
        context_id: Some((*backup_id).into()),
        previous_context_id: None,
        threshold: custodian_threshold as u32,
    };
    for op_idx in 1..=operator_count {
        let operator_role = Role::indexed_from_one(op_idx);
        let (verification_key, signing_key) = gen_sig_keys(rng);
        let operator = Operator::new(
            operator_role,
            setup_msgs.to_vec(),
            signing_key.clone(),
            custodian_threshold,
            custodian_count,
        )
        .unwrap();
        let mut enc = Encryption::new(EncryptionSchemeType::MlKem512, rng);
        let (backup_dec_key, backup_enc_key) = enc.keygen().unwrap();
        let (cur_op_output, cur_comm) = operator
            .secret_share_and_encrypt(
                rng,
                &bc2wrap::serialize(&backup_dec_key).unwrap(),
                *backup_id,
            )
            .unwrap();
        let operator_cus_context =
            InternalCustodianContext::new(cus_context.clone(), backup_enc_key.clone()).unwrap();
        let validation_material = RecoveryValidationMaterial::new(
            cur_comm.to_owned(),
            operator_cus_context,
            &signing_key,
        )
        .unwrap();
        operators.insert(
            operator_role,
            (operator, validation_material, backup_dec_key),
        );
        payload_for_custodians.insert(
            operator_role,
            (verification_key, backup_enc_key, cur_op_output),
        );
    }
    (operators, payload_for_custodians)
}

fn custodian_recover(
    rng: &mut AesRng,
    backup_id: &RequestId,
    mnemonics: &BTreeMap<Role, String>,
    backups: &BTreeMap<
        Role,
        (
            PublicSigKey,
            UnifiedPublicEncKey,
            BTreeMap<Role, InnerOperatorBackupOutput>,
        ),
    >, // Operator role to verf key, ephemeral key and backup ct map
    custodian_threshold: usize,
) -> BTreeMap<Role, BTreeMap<Role, InternalCustodianRecoveryOutput>> {
    let mut res = BTreeMap::new();
    for (cur_operator_role, (verification_key, ephemeral_enc_key, cur_backup)) in backups {
        let mut cur_operator_res = BTreeMap::new();
        for (cur_cus_role, cur_mnemonic) in mnemonics {
            let custodian = custodian_from_seed_phrase(cur_mnemonic, *cur_cus_role).unwrap();
            // what is recovered is a reencryption
            match custodian.verify_reencrypt(
                rng,
                cur_backup.get(cur_cus_role).unwrap(),
                verification_key,
                ephemeral_enc_key,
                *backup_id,
                *cur_operator_role,
            ) {
                Ok(cur_res) => cur_operator_res.insert(*cur_cus_role, cur_res),
                Err(_) => {
                    continue;
                } // Skip if re-encryption fails
            };
        }
        // Only insert if we have enough re-encryptions
        if cur_operator_res.len() > custodian_threshold {
            res.insert(*cur_operator_role, cur_operator_res);
        }
    }
    res
}

fn operator_recover(
    reencryptions: &BTreeMap<Role, BTreeMap<Role, InternalCustodianRecoveryOutput>>,
    operators: &BTreeMap<Role, (Operator, RecoveryValidationMaterial, UnifiedPrivateEncKey)>,
    backup_id: &RequestId,
) -> BTreeMap<Role, Vec<u8>> {
    let mut res = BTreeMap::new();
    for (cur_op_role, (cur_op, cur_com, cur_emphemeral)) in operators {
        if let Some(cur_reencs) = reencryptions.get(cur_op_role) {
            let reencs_vec: Vec<_> = cur_reencs.values().cloned().collect();
            match cur_op.verify_and_recover(&reencs_vec, cur_com, *backup_id, cur_emphemeral) {
                Ok(plaintext) => res.insert(*cur_op_role, plaintext),
                Err(_) => continue, // Skip if recovery fails
            };
        }
    }
    res
}

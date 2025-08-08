use std::collections::BTreeMap;

use aes_prng::AesRng;
use itertools::Itertools;
use kms_grpc::RequestId;
use proptest::prelude::*;
use rand::{rngs::OsRng, SeedableRng};
use threshold_fhe::execution::runtime::party::Role;

use crate::{
    backup::{
        operator::BackupCommitments,
        seed_phrase::{custodian_from_seed_phrase, seed_phrase_from_rng},
    },
    cryptography::{
        backup_pke,
        internal_crypto_types::{gen_sig_keys, PublicSigKey},
    },
};

use super::{custodian, error::BackupError, operator::Operator};

enum DropShares {
    NoDrop,
    DropFront,
    DropBack,
}

const TEST_PARAMS: [(usize, usize, DropShares); 5] = [
    (4, 1, DropShares::NoDrop),
    (4, 1, DropShares::DropFront),
    (4, 1, DropShares::DropBack),
    (7, 3, DropShares::DropBack),
    (10, 4, DropShares::DropBack),
];

// run the full flow without the smart contract component
#[test]
fn full_flow() {
    for (custodian_count, custodian_threshold, drop_share_config) in TEST_PARAMS {
        let operator_count = 4usize;
        let secret_len = 32usize;
        let backup_id = RequestId::from_bytes([8u8; crate::consts::ID_LENGTH]);

        let mut rng = AesRng::seed_from_u64(1337);
        // *setup*
        // custodians generate signing keys and encryption keys
        // those are sent to the operators
        let custodians: Vec<_> = (0..custodian_count)
            .map(|i| {
                let custodian_role = Role::indexed_from_zero(i);
                let mnemonic = seed_phrase_from_rng(&mut rng).unwrap();
                custodian_from_seed_phrase(&mnemonic, custodian_role).unwrap()
            })
            .collect();
        let custodian_messages: Vec<_> = custodians
            .iter()
            .map(|c| {
                c.generate_setup_message(&mut rng, "Custodian test name".to_string())
                    .unwrap()
            })
            .collect();
        let operators: Vec<_> = (0..operator_count)
            .map(|i| {
                let operator_role = Role::indexed_from_zero(i);
                let (verification_key, signing_key) = gen_sig_keys(&mut rng);
                let (public_key, private_key) = backup_pke::keygen(&mut rng).unwrap();
                Operator::new(
                    operator_role,
                    custodian_messages.clone(),
                    signing_key,
                    verification_key,
                    private_key,
                    public_key,
                    custodian_threshold,
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

        // TODO secret material validation

        // *recovery*
        // 1. custodian obtains the operator public keys and encrypted shares.
        // 2. reencrypt and sign the shares
        let reencrypted_cts = operators
            .iter()
            .zip_eq(&cts)
            .map(|(operator, ct)| {
                // reencrypted ciphertexts ciphertexts for one operator
                (
                    custodians
                        .iter()
                        .map(|custodian| {
                            let custodian_role = custodian.role();
                            let backup = ct.get(&custodian_role).unwrap();
                            let verification_key = operator.verification_key();
                            let operator_pk = operator.public_key();
                            let operator_role = operator.role();

                            // what is recovered is a reencryption
                            (
                                custodian_role,
                                custodian
                                    .verify_reencrypt(
                                        &mut rng,
                                        backup,
                                        verification_key,
                                        operator_pk,
                                        backup_id,
                                        operator_role,
                                    )
                                    .unwrap(),
                            )
                        })
                        .collect::<BTreeMap<_, _>>(),
                    ct.iter()
                        .map(|(k, v)| (*k, v.commitment.clone()))
                        .collect::<BTreeMap<_, _>>(),
                )
            })
            .collect::<Vec<_>>();

        // 3. the parties do reconstruction
        let recovered_secrets: Vec<Vec<u8>> = operators
            .iter()
            .zip_eq(reencrypted_cts)
            .map(|(operator, (mut reencrypted_ct, commitments))| {
                // optionally remove elements during recovery
                // we need to keep t + 1 shares, so remove n - (t + 1)
                for _ in 0..(custodian_count - custodian_threshold - 1) {
                    match drop_share_config {
                        DropShares::NoDrop => { /* do nothing */ }
                        DropShares::DropFront => {
                            let _ = reencrypted_ct.pop_first().unwrap();
                        }
                        DropShares::DropBack => {
                            let _ = reencrypted_ct.pop_last().unwrap();
                        }
                    }
                }
                operator
                    .verify_and_recover(
                        &reencrypted_ct,
                        &BackupCommitments::from_btree(commitments),
                        backup_id,
                    )
                    .unwrap()
            })
            .collect();
        assert_eq!(recovered_secrets, secrets);
    }
}

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
            let (verification_key, signing_key) = gen_sig_keys(&mut rng);
            let (public_key, private_key) = backup_pke::keygen(&mut rng).unwrap();
            custodian::Custodian::new(
                custodian_role,
                signing_key,
                verification_key,
                private_key,
                public_key,
            )
            .unwrap()
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

    // use the wrong operator ID
    {
        let mut wrong_custodian_messages = custodian_messages.clone();
        wrong_custodian_messages[0].custodian_role = Role::indexed_from_zero(1);
        let (verification_key, signing_key) = gen_sig_keys(&mut rng);
        let (public_key, private_key) = backup_pke::keygen(&mut rng).unwrap();
        let operator = Operator::new(
            Role::indexed_from_zero(0),
            wrong_custodian_messages,
            signing_key,
            verification_key,
            private_key,
            public_key,
            custodian_threshold,
        );
        assert!(matches!(
            operator.unwrap_err(),
            BackupError::CustodianSetupError
        ));
    }

    // use the wrong header, setup should fail
    {
        let mut wrong_custodian_messages = custodian_messages.clone();
        wrong_custodian_messages[0].header.push('z');

        let (verification_key, signing_key) = gen_sig_keys(&mut rng);
        let (public_key, private_key) = backup_pke::keygen(&mut rng).unwrap();
        let operator = Operator::new(
            Role::indexed_from_zero(0),
            wrong_custodian_messages,
            signing_key,
            verification_key,
            private_key,
            public_key,
            custodian_threshold,
        );
        assert!(matches!(
            operator.unwrap_err(),
            BackupError::CustodianSetupError,
        ));
    }

    // use the wrong timestamp, setup should fail
    {
        let mut wrong_custodian_messages = custodian_messages.clone();
        wrong_custodian_messages[0].timestamp += 3700;

        let (verification_key, signing_key) = gen_sig_keys(&mut rng);
        let (public_key, private_key) = backup_pke::keygen(&mut rng).unwrap();
        let operator = Operator::new(
            Role::indexed_from_zero(0),
            wrong_custodian_messages,
            signing_key,
            verification_key,
            private_key,
            public_key,
            custodian_threshold,
        );
        assert!(matches!(
            operator.unwrap_err(),
            BackupError::CustodianSetupError,
        ));
    }

    // no tweaks, all should pass
    {
        let (verification_key, signing_key) = gen_sig_keys(&mut rng);
        let (public_key, private_key) = backup_pke::keygen(&mut rng).unwrap();
        let _ = Operator::new(
            Role::indexed_from_zero(0),
            custodian_messages,
            signing_key,
            verification_key,
            private_key,
            public_key,
            custodian_threshold,
        )
        .unwrap();
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
            let (verification_key, signing_key) = gen_sig_keys(&mut rng);
            let (public_key, private_key) = backup_pke::keygen(&mut rng).unwrap();
            custodian::Custodian::new(
                custodian_role,
                signing_key,
                verification_key,
                private_key,
                public_key,
            )
            .unwrap()
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
            let (verification_key, signing_key) = gen_sig_keys(&mut rng);
            let (public_key, private_key) = backup_pke::keygen(&mut rng).unwrap();
            Operator::new(
                operator_role,
                custodian_messages.clone(),
                signing_key,
                verification_key,
                private_key,
                public_key,
                custodian_threshold,
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
    let operator_pk = operators[0].public_key();

    // tweak the ciphertext, so that signature verification fails
    {
        let operator_role = Role::indexed_from_zero(0);
        let mut bad_cts = cts.clone();
        if let Some(z) = bad_cts[0].get_mut(&operator_role) {
            z.ciphertext[0] ^= 1;
        }

        let err = custodians[0]
            .verify_reencrypt(
                &mut rng,
                bad_cts[0].get(&operator_role).unwrap(),
                verification_key,
                operator_pk,
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
        if let Some(z) = bad_cts[0].get_mut(&operator_role) {
            z.signature[0] ^= 1;
        }

        let err = custodians[0]
            .verify_reencrypt(
                &mut rng,
                bad_cts[0].get(&operator_role).unwrap(),
                verification_key,
                operator_pk,
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
                cts[0].get(&operator_role).unwrap(),
                verification_key,
                operator_pk,
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
                cts[0].get(&operator_role).unwrap(),
                verification_key,
                operator_pk,
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
                cts[0].get(&operator_role).unwrap(),
                verification_key,
                operator_pk,
                backup_id,
                operator_role,
            )
            .unwrap();
    }
}

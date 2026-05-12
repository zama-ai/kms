use assert_cmd::{Command, assert::OutputAssertExt};
use std::fs;
use test_utils_service::integration_test;
use test_utils_service::persistent_traces;

const KMS_SERVER: &str = "kms-server";
const KMS_GEN_KEYS: &str = "kms-gen-keys";
const KMS_INIT: &str = "kms-init";

#[cfg(test)]
mod kms_init_binary_test {
    use super::*;

    #[test]
    #[integration_test]
    fn help() {
        Command::cargo_bin(KMS_INIT)
            .unwrap()
            .arg("--help")
            .output()
            .unwrap()
            .assert()
            .success();
    }

    #[test]
    #[integration_test]
    fn init() {
        let buf = Command::cargo_bin(KMS_INIT)
            .unwrap()
            .arg("-a")
            .arg("http://127.0.0.1:41555")
            .output()
            .unwrap()
            .stderr;
        let s = String::from_utf8(buf).expect("invalid utf-8");
        assert!(s.contains("Connection refused"));
    }
}

#[cfg(test)]
mod kms_gen_keys_binary_test {
    use tempfile::tempdir;

    use super::*;

    fn kms_gen_keys_command() -> Command {
        let mut command = Command::cargo_bin(KMS_GEN_KEYS).unwrap();
        // Integration tests run with quiet-by-default test logging, but these
        // subprocess assertions intentionally depend on child `info!` output.
        // Clear inherited filter overrides so the child's verbose preset wins.
        // To override this for debugging, set `KMS_TEST_LOG_CONSOLE_FILTER`
        // on this command with the same syntax as `RUST_LOG`.
        command
            .env("KMS_TEST_LOG_MODE", "verbose")
            .env_remove("KMS_TEST_LOG_FILTER")
            .env_remove("KMS_TEST_LOG_CONSOLE_FILTER")
            .env_remove("RUST_LOG");
        command
    }

    #[test]
    #[integration_test]
    fn help() {
        Command::cargo_bin(KMS_GEN_KEYS)
            .unwrap()
            .arg("--help")
            .output()
            .unwrap()
            .assert()
            .success();

        Command::cargo_bin(KMS_GEN_KEYS)
            .unwrap()
            .arg("centralized")
            .arg("--help")
            .output()
            .unwrap()
            .assert()
            .success();

        Command::cargo_bin(KMS_GEN_KEYS)
            .unwrap()
            .arg("threshold")
            .arg("--help")
            .output()
            .unwrap()
            .assert()
            .success();
    }

    #[test]
    #[integration_test]
    fn central_signing_keys_overwrite() {
        // Both invocations must share storage so the second run sees the keys
        // written by the first.
        let temp_dir_priv = tempdir().unwrap();
        let temp_dir_pub = tempdir().unwrap();
        let output = kms_gen_keys_command()
            .arg("--private-storage=file")
            .arg("--private-file-path")
            .arg(temp_dir_priv.path())
            .arg("--public-storage=file")
            .arg("--public-file-path")
            .arg(temp_dir_pub.path())
            .arg("--overwrite")
            .arg("centralized")
            .output()
            .unwrap();
        let log = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success());
        assert!(log.contains("Deleting VerfKey under request ID"));
        assert!(log.contains("Deleting SigningKey under request ID "));
        assert!(log.contains(
            "Successfully stored public centralized server signing key under the handle"
        ));

        let new_output = kms_gen_keys_command()
            .arg("--private-storage=file")
            .arg("--private-file-path")
            .arg(temp_dir_priv.path())
            .arg("--public-storage=file")
            .arg("--public-file-path")
            .arg(temp_dir_pub.path())
            .arg("centralized")
            .output()
            .unwrap();
        assert!(new_output.status.success());
        let new_log = String::from_utf8_lossy(&new_output.stdout);
        assert!(new_log.contains("Signing keys already exist, skipping generation"));
    }

    #[test]
    #[integration_test]
    fn central_signing_address_format() {
        let temp_dir_priv = tempdir().unwrap();
        let temp_dir_pub = tempdir().unwrap();
        let output = kms_gen_keys_command()
            .arg("--private-storage=file")
            .arg("--private-file-path")
            .arg(temp_dir_priv.path())
            .arg("--public-storage=file")
            .arg("--public-file-path")
            .arg(temp_dir_pub.path())
            .arg("centralized")
            .output()
            .unwrap();

        let log = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success());
        assert!(log.contains("Successfully stored ethereum address 0x"));
        assert!(
            log.contains("under the handle 60b7070add74be3827160aa635fb255eeeeb88586c4debf7ab1134ddceb4beee in storage")
        );

        let mut adress_path = temp_dir_pub.path().to_path_buf();
        adress_path.push(
            "PUB/VerfAddress/60b7070add74be3827160aa635fb255eeeeb88586c4debf7ab1134ddceb4beee",
        );

        // read address from file
        let address = fs::read_to_string(adress_path).expect("Unable to read Verification Address");

        // make sure its well-formed (starts with 0x and has 40 hex digits) and can be decoded
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);
        hex::decode(address[2..].to_lowercase()).unwrap();
    }

    #[test]
    #[integration_test]
    fn threshold_wrong_num_parties() {
        let temp_dir_priv = tempdir().unwrap();
        let temp_dir_pub = tempdir().unwrap();

        // the command below should fail because --num-parties should be
        // greater or equal to 2
        let output = Command::cargo_bin(KMS_GEN_KEYS)
            .unwrap()
            .arg("--private-storage=file")
            .arg("--private-file-path")
            .arg(temp_dir_priv.path())
            .arg("--public-storage=file")
            .arg("--public-file-path")
            .arg(temp_dir_pub.path())
            .arg("threshold")
            .arg("--num-parties=1")
            .output()
            .unwrap();

        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("the number of parties should be larger or equal to 2")
        );
    }

    #[test]
    #[integration_test]
    fn threshold_signing_key_wrong_party_id() {
        let temp_dir_priv = tempdir().unwrap();
        let temp_dir_pub = tempdir().unwrap();

        // the command below should fail because `--num-parties` default to 4
        // but we're asking the CLI to generate a key for party 5
        let output = Command::cargo_bin(KMS_GEN_KEYS)
            .unwrap()
            .arg("--private-storage=file")
            .arg("--private-file-path")
            .arg(temp_dir_priv.path())
            .arg("--public-storage=file")
            .arg("--public-file-path")
            .arg(temp_dir_pub.path())
            .arg("threshold")
            .arg("--signing-key-party-id=5")
            .output()
            .unwrap();

        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("party ID (5) cannot be greater than num_parties (4)")
        );
    }

    #[test]
    #[integration_test]
    #[persistent_traces]
    fn threshold_signing_key() {
        let temp_dir_priv = tempdir().unwrap();
        let temp_dir_pub = tempdir().unwrap();

        // finally we run the command with the right args
        let output = kms_gen_keys_command()
            .arg("--private-storage=file")
            .arg("--private-file-path")
            .arg(temp_dir_priv.path())
            .arg("--public-storage=file")
            .arg("--public-file-path")
            .arg(temp_dir_pub.path())
            .arg("threshold")
            .arg("--signing-key-party-id=5")
            .arg("--num-parties=5")
            .output()
            .unwrap();

        assert!(output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("Successfully stored ethereum address 0x")
        );
    }

    #[cfg(feature = "s3_tests")]
    #[test]
    #[integration_test]
    fn central_s3() {
        use kms_lib::vault::storage::s3::{AWS_REGION, AWS_S3_ENDPOINT, BUCKET_NAME};

        // Unique S3 prefix per run so concurrent CI invocations of this test
        // don't fight each other on the shared bucket.
        let s3_prefix = format!(
            "central_s3_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let temp_dir_priv = tempdir().unwrap();

        // Test the following command:
        // cargo run --bin kms-gen-keys -- --aws-region eu-north-1 --public-storage=s3 --public-s3-bucket ci-kms-key-test --public-s3-prefix=<unique> --private-storage=file --private-file-path=<tempdir> --overwrite --deterministic centralized
        let output = kms_gen_keys_command()
            .arg(format!("--aws-region={AWS_REGION}"))
            .arg(format!("--aws-s3-endpoint={AWS_S3_ENDPOINT}"))
            .arg("--public-storage=s3")
            .arg("--public-s3-bucket")
            .arg(BUCKET_NAME)
            .arg("--public-s3-prefix")
            .arg(&s3_prefix)
            .arg("--private-storage=file")
            .arg("--private-file-path")
            .arg(temp_dir_priv.path())
            .arg("--overwrite")
            .arg("--deterministic")
            .arg("centralized")
            .output()
            .unwrap();
        let log = String::from_utf8_lossy(&output.stdout);
        let err_log = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() {
            tracing::error!(
                status = %output.status,
                stdout = %log,
                stderr = %err_log,
                "kms-gen-keys centralized S3 integration command failed"
            );
        }
        assert!(output.status.success());
        assert!(log.contains("Successfully stored public centralized server signing key under the handle 60b7070add74be3827160aa635fb255eeeeb88586c4debf7ab1134ddceb4beee in storage \"S3 storage with"));
        assert!(log.contains("Successfully stored private centralized server signing key under the handle 60b7070add74be3827160aa635fb255eeeeb88586c4debf7ab1134ddceb4beee in storage \"file storage with"));
    }
}

#[cfg(test)]
mod kms_server_binary_test {
    use super::*;

    #[test]
    #[integration_test]
    fn help() {
        Command::cargo_bin(KMS_SERVER)
            .unwrap()
            .arg("--help")
            .output()
            .unwrap()
            .assert()
            .success();
    }
}

#[cfg(test)]
mod kms_custodian_binary_tests {
    use aes_prng::AesRng;
    use assert_cmd::Command;
    use kms_grpc::{RequestId, kms::v1::CustodianContext};
    use kms_lib::{
        backup::{
            KMS_CUSTODIAN, SEED_PHRASE_DESC,
            custodian::{
                InternalCustodianContext, InternalCustodianRecoveryOutput,
                InternalCustodianSetupMessage,
            },
            operator::{InternalRecoveryRequest, Operator, RecoveryValidationMaterial},
            seed_phrase::custodian_from_seed_phrase,
        },
        consts::DEFAULT_MPC_CONTEXT,
        cryptography::{
            encryption::{
                Encryption, PkeScheme, PkeSchemeType, UnifiedPrivateEncKey, UnifiedPublicEncKey,
            },
            signatures::gen_sig_keys,
        },
        engine::base::derive_request_id,
        util::file_handling::{safe_read_element_versioned, safe_write_element_versioned},
    };
    use rand::SeedableRng;
    use std::path::MAIN_SEPARATOR;
    use std::{collections::BTreeMap, path::Path, thread};
    use threshold_types::role::Role;

    fn run_custodian_cli(commands: Vec<String>) -> String {
        test_utils::test_logging::init_test_logging();
        let h = thread::spawn(|| {
            let mut cmd = Command::cargo_bin(KMS_CUSTODIAN).unwrap();
            for arg in commands {
                cmd.arg(arg);
            }
            let out = cmd.output();
            assert!(out.is_ok(), "Command failed to execute");
            out
        });

        let out = h.join().unwrap().unwrap();
        let output_string = String::from_utf8_lossy(&out.stdout);
        let errors = String::from_utf8_lossy(&out.stderr);
        if !out.status.success() || !errors.is_empty() {
            tracing::error!(
                status = %out.status,
                stdout = %output_string,
                stderr = %errors,
                "kms-custodian integration command returned unexpected output"
            );
        }
        assert!(
            out.status.success(),
            "Command did not execute successfully: {} : {}",
            out.status,
            errors
        );
        assert!(errors.is_empty());
        output_string.trim().to_owned()
    }

    fn extract_seed_phrase(output: &str) -> &str {
        let seed_phrase_line = output.lines().find(|line| line.contains(SEED_PHRASE_DESC));
        seed_phrase_line
            .unwrap()
            .split_at(SEED_PHRASE_DESC.len())
            .1
            .trim()
    }

    #[test]
    fn sunshine_generate() {
        let temp_dir = tempfile::tempdir().unwrap();
        let (seed_phrase, _setup_msgs) = generate_custodian_keys_to_file(temp_dir.path(), 1);
        let (seed_phrase2, _setup_msgs) = generate_custodian_keys_to_file(temp_dir.path(), 1);

        // Ensure that randomness is always sampled on top of given randomness
        assert_ne!(seed_phrase, seed_phrase2);
    }

    #[test]
    fn sunshine_verify() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir
            .path()
            .join(format!("custodian-1{MAIN_SEPARATOR}setup_msg.bin"));
        let (seed_phrase, _setup_msgs) = generate_custodian_keys_to_file(temp_dir.path(), 1);
        let verf_command = vec![
            "verify".to_string(),
            "--seed-phrase".to_string(),
            seed_phrase.to_string(),
            "--path".to_string(),
            path.to_str().unwrap().to_string(),
        ];
        // Note that `run_commands` validate that the command executed successfully
        let _verf_out = run_custodian_cli(verf_command);
    }

    #[tokio::test]
    async fn sunshine_decrypt_custodian() {
        let threshold = 1;
        let amount_custodians = 2 * threshold + 1; // Minimum amount of custodians is 2 * threshold + 1
        let amount_operators = 4;
        let backup_id = derive_request_id("backuptest").unwrap();

        let temp_dir = tempfile::tempdir().unwrap();

        // Generate custodian keys
        let mut setup_msgs = Vec::new();
        let mut seed_phrases: Vec<_> = Vec::new();
        for custodian_index in 1..=amount_custodians {
            let (seed_phrase, setup_msg) =
                generate_custodian_keys_to_file(temp_dir.path(), custodian_index);
            setup_msgs.push(setup_msg);
            seed_phrases.push(seed_phrase);
        }

        // Generate operator keys along with the message to be backed up
        struct OperatorData {
            operator: Operator,
            commitment: RecoveryValidationMaterial,
            ephemeral_keys: (UnifiedPrivateEncKey, UnifiedPublicEncKey),
            backup_dec_key: UnifiedPrivateEncKey,
            operator_id: usize,
        }
        let mut operator_data = vec![];
        for operator_index in 1..=amount_operators {
            let (cur_commitments, operator, cur_ephemeral_keys, backup_dec) = make_backup_sunshine(
                temp_dir.path(),
                threshold,
                operator_index,
                setup_msgs.clone(),
                backup_id,
            )
            .await;
            operator_data.push(OperatorData {
                operator,
                commitment: cur_commitments,
                ephemeral_keys: cur_ephemeral_keys,
                backup_dec_key: backup_dec,
                operator_id: operator_index,
            });
        }

        // Decrypt
        for custodian_index in 1..=amount_custodians {
            for operator_index in 1..=amount_operators {
                let request_path = temp_dir.path().join(format!(
                    "operator-{operator_index}{MAIN_SEPARATOR}{backup_id}-request.bin"
                ));
                let recovery_path = temp_dir.path().join(format!(
                    "operator-{operator_index}{MAIN_SEPARATOR}{backup_id}-recovered-keys-from-{custodian_index}.bin"
                ));
                let operator_verf_path = temp_dir.path().join(format!(
                    "operator-{operator_index}{MAIN_SEPARATOR}{backup_id}-verf_key.bin"
                ));
                let decrypt_command = vec![
                    "decrypt".to_string(),
                    "--seed-phrase".to_string(),
                    seed_phrases[custodian_index - 1].to_string(),
                    "--custodian-role".to_string(),
                    custodian_index.to_string(),
                    "--operator-verf-key".to_string(),
                    operator_verf_path.to_str().unwrap().to_string(),
                    "--mpc-context-id".to_string(),
                    DEFAULT_MPC_CONTEXT.to_string(),
                    "-b".to_string(),
                    request_path.to_str().unwrap().to_string(),
                    "-o".to_string(),
                    recovery_path.to_str().unwrap().to_string(),
                ];
                let _verf_out = run_custodian_cli(decrypt_command);
            }
        }

        // Validate the decryption
        for OperatorData {
            operator,
            commitment,
            ephemeral_keys,
            backup_dec_key,
            operator_id,
        } in operator_data
        {
            let (dec_key, enc_key) = ephemeral_keys;
            let cur_res = decrypt_recovery(
                temp_dir.path(),
                amount_custodians,
                &operator,
                operator_id,
                &commitment,
                backup_id,
                &dec_key,
                &enc_key,
            )
            .await;
            assert_eq!(
                cur_res,
                bc2wrap::serialize(&backup_dec_key).unwrap(),
                "Decryption did not match expected data for operator {}",
                operator.verification_key().address(),
            );
        }
    }

    fn generate_custodian_keys_to_file(
        root_path: &Path,
        custodian_index: usize,
    ) -> (String, InternalCustodianSetupMessage) {
        let final_dir = root_path.join(format!(
            "custodian-{custodian_index}{MAIN_SEPARATOR}setup_msg.bin"
        ));
        let gen_command = vec![
            "generate".to_string(),
            "--randomness".to_string(),
            "123456".to_string(),
            "--custodian-role".to_string(),
            custodian_index.to_string(),
            "--custodian-name".to_string(),
            format!("skynet-{custodian_index}"),
            "--path".to_string(),
            final_dir.to_str().unwrap().to_string(),
        ];
        let gen_out = run_custodian_cli(gen_command.clone());
        let seed_phrase = extract_seed_phrase(gen_out.as_ref());
        let role = Role::indexed_from_one(custodian_index);
        let custodian = custodian_from_seed_phrase(seed_phrase, role).unwrap();
        let mut rng = AesRng::seed_from_u64(40);
        let setup_msg = custodian
            .generate_setup_message(&mut rng, "Homer Simpson".to_string())
            .unwrap();
        (seed_phrase.to_string(), setup_msg)
    }

    async fn make_backup_sunshine(
        root_path: &Path,
        threshold: usize,
        operator_id: usize, // not actual operator ID, just for managing where the files go
        setup_msgs: Vec<InternalCustodianSetupMessage>,
        backup_id: RequestId,
    ) -> (
        RecoveryValidationMaterial,
        Operator,
        (UnifiedPrivateEncKey, UnifiedPublicEncKey),
        UnifiedPrivateEncKey,
    ) {
        let amount_custodians = setup_msgs.len();
        let mut rng = AesRng::seed_from_u64(40);
        // Note that in the actual deployment, the operator keys are generated before the encryption keys
        let (verification_key, signing_key) = gen_sig_keys(&mut rng);

        let request_path = root_path.join(format!(
            "operator-{operator_id}{MAIN_SEPARATOR}{backup_id}-request.bin",
        ));
        let operator_verf_path = root_path.join(format!(
            "operator-{operator_id}{MAIN_SEPARATOR}{backup_id}-verf_key.bin",
        ));

        let mut enc = Encryption::new(PkeSchemeType::MlKem512, &mut rng);
        let (ephemeral_priv_key, ephemeral_pub_key) = enc.keygen().unwrap();
        let operator: Operator = Operator::new_for_sharing(
            setup_msgs.clone(),
            signing_key.clone(),
            threshold,
            setup_msgs.len(),
        )
        .unwrap();
        let (backup_ske, backup_pke) = enc.keygen().unwrap();
        let signcrypt_result = operator
            .secret_share_and_signcrypt(
                &mut rng,
                &bc2wrap::serialize(&backup_ske).unwrap(),
                backup_id,
            )
            .unwrap();
        let ct_map = signcrypt_result.ct_shares;
        let commitments = signcrypt_result.commitments;
        let custodian_context = InternalCustodianContext::new(
            CustodianContext {
                custodian_nodes: setup_msgs
                    .iter()
                    .map(|cur| cur.to_owned().try_into().unwrap())
                    .collect(),
                custodian_context_id: Some(backup_id.into()),
                threshold: threshold as u32,
            },
            backup_pke,
        )
        .unwrap();
        let validation_material = RecoveryValidationMaterial::new(
            ct_map.clone(),
            commitments.clone(),
            custodian_context,
            &signing_key,
            *DEFAULT_MPC_CONTEXT,
        )
        .unwrap();
        let mut ciphertexts = BTreeMap::new();
        for custodian_index in 1..=amount_custodians {
            let custodian_role = Role::indexed_from_one(custodian_index);
            let ct = ct_map.get(&custodian_role).unwrap();
            ciphertexts.insert(custodian_role, ct.to_owned());
        }
        let recovery_request = InternalRecoveryRequest::new(
            ephemeral_pub_key.clone(),
            ciphertexts,
            backup_id,
            verification_key.clone(),
        )
        .unwrap();
        safe_write_element_versioned(&Path::new(&operator_verf_path), &verification_key)
            .await
            .unwrap();
        safe_write_element_versioned(&Path::new(&request_path), &recovery_request)
            .await
            .unwrap();
        (
            validation_material,
            operator,
            (ephemeral_priv_key, ephemeral_pub_key),
            backup_ske,
        )
    }

    #[allow(clippy::too_many_arguments)]
    async fn decrypt_recovery(
        root_path: &Path,
        amount_custodians: usize,
        operator: &Operator,
        operator_id: usize,
        recovery_material: &RecoveryValidationMaterial,
        backup_id: RequestId,
        ephem_dec_key: &UnifiedPrivateEncKey,
        ephem_enc_key: &UnifiedPublicEncKey,
    ) -> Vec<u8> {
        let mut outputs = Vec::new();
        for custodian_index in 1..=amount_custodians {
            let recovery_path = root_path.join(format!(
                "operator-{}{MAIN_SEPARATOR}{backup_id}-recovered-keys-from-{custodian_index}.bin",
                operator_id,
            ));
            let payload: InternalCustodianRecoveryOutput =
                safe_read_element_versioned(&Path::new(&recovery_path))
                    .await
                    .unwrap();
            outputs.push(payload);
        }
        operator
            .verify_and_recover(
                &outputs,
                recovery_material,
                backup_id,
                ephem_dec_key,
                ephem_enc_key,
            )
            .unwrap()
    }
}

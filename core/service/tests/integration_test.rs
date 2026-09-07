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
    use kms_lib::{
        consts::{SIGNING_KEY_ID, signing_material_id},
        cryptography::signatures::SigningSchemeType,
    };
    use std::path::{Path, PathBuf};
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

    fn write_file_storage_config(
        config_dir: &tempfile::TempDir,
        private_path: &Path,
        public_path: &Path,
        keygen_options: &str,
        threshold_config: Option<&str>,
    ) -> PathBuf {
        let config_path = config_dir.path().join("kms-gen-keys.toml");
        fs::write(
            &config_path,
            format!(
                r#"
[keygen]
{keygen_options}
{threshold_config}
[public_vault.storage.file]
path = "{public_path}"

[private_vault.storage.file]
path = "{private_path}"
"#,
                public_path = public_path.display(),
                private_path = private_path.display(),
                threshold_config = threshold_config.unwrap_or_default(),
            ),
        )
        .unwrap();
        config_path
    }

    /// Runs `kms-gen-keys` once with `overwrite = true`, asserts it succeeds, and
    /// returns its stdout log.
    fn run_centralized_overwrite(
        config_dir: &tempfile::TempDir,
        temp_dir_priv: &tempfile::TempDir,
        temp_dir_pub: &tempfile::TempDir,
    ) -> String {
        let config_path = write_file_storage_config(
            config_dir,
            temp_dir_priv.path(),
            temp_dir_pub.path(),
            "overwrite = true",
            None,
        );
        let output = kms_gen_keys_command()
            .arg("--config-file")
            .arg(config_path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).into_owned()
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
    }

    #[test]
    #[integration_test]
    fn server_config_is_rejected() {
        let output = Command::cargo_bin(KMS_GEN_KEYS)
            .unwrap()
            .arg("--config-file")
            .arg("config/default_1.toml")
            .output()
            .unwrap();

        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("expected a [keygen] section"));
    }

    #[test]
    #[integration_test]
    fn central_signing_keys_overwrite() {
        // All invocations must share storage so each run sees the keys written
        // by the previous one.
        let (temp_dir_priv, temp_dir_pub, config_dir) =
            (tempdir().unwrap(), tempdir().unwrap(), tempdir().unwrap());
        let log = run_centralized_overwrite(&config_dir, &temp_dir_priv, &temp_dir_pub);
        assert!(log.contains("Deleting published verification material from public storage"));
        assert!(log.contains("Deleting SigningKey under request ID "));
        assert!(log.contains("Deleting SigningSeed under request ID "));
        assert!(log.contains(
            "Successfully stored private centralized server signing key under the handle"
        ));
        assert!(log.contains(&format!(
            "Stored {} TypedVerfKey under the handle {}",
            SigningSchemeType::Ecdsa256k1,
            signing_material_id(SigningSchemeType::Ecdsa256k1)
        )));

        let config_path = write_file_storage_config(
            &config_dir,
            temp_dir_priv.path(),
            temp_dir_pub.path(),
            "",
            None,
        );
        let new_output = kms_gen_keys_command()
            .arg("--config-file")
            .arg(config_path)
            .output()
            .unwrap();
        assert!(new_output.status.success());
        let new_log = String::from_utf8_lossy(&new_output.stdout);
        assert!(new_log.contains("Signing keys already exist, skipping generation"));

        // A second `overwrite = true` run against the same, now-populated storage
        // must also succeed: it has to purge the per-scheme material alongside
        // the legacy VerfKey/VerfAddress/CACert/SigningKey handles before
        // regenerating, or key generation would fail against its own leftovers.
        let overwrite_again_log =
            run_centralized_overwrite(&config_dir, &temp_dir_priv, &temp_dir_pub);
        assert!(
            overwrite_again_log
                .contains("Deleting published verification material from public storage")
        );
        assert!(overwrite_again_log.contains(
            "Successfully stored private centralized server signing key under the handle"
        ));
        assert!(overwrite_again_log.contains(&format!(
            "Stored {} TypedVerfKey under the handle {}",
            SigningSchemeType::Ecdsa256k1,
            signing_material_id(SigningSchemeType::Ecdsa256k1)
        )));
    }

    /// `repopulate = true` restores verification material from the existing ECDSA
    /// signing key without needing `overwrite`, covering the case where storage was
    /// partially purged (e.g. public storage restored without the corresponding
    /// private-storage snapshot).
    #[test]
    #[integration_test]
    fn central_repopulate_after_partial_purge() {
        let (temp_dir_priv, temp_dir_pub, config_dir) =
            (tempdir().unwrap(), tempdir().unwrap(), tempdir().unwrap());
        run_centralized_overwrite(&config_dir, &temp_dir_priv, &temp_dir_pub);

        let signing_key_id = signing_material_id(SigningSchemeType::Ecdsa256k1);
        let purged: Vec<PathBuf> = [
            // A per-scheme object, keyed by the scheme's own handle.
            temp_dir_pub
                .path()
                .join("PUB/TypedVerfKey")
                .join(signing_material_id(SigningSchemeType::Ed25519).to_string()),
            temp_dir_pub
                .path()
                .join("PUB/TypedVerfAddress")
                .join(signing_material_id(SigningSchemeType::MlDsa65).to_string()),
            // The deprecated ECDSA-only pair, keyed by the signing-key handle.
            temp_dir_pub
                .path()
                .join("PUB/VerfKey")
                .join(signing_key_id.to_string()),
            temp_dir_pub
                .path()
                .join("PUB/VerfAddress")
                .join(signing_key_id.to_string()),
        ]
        .into();
        for path in &purged {
            assert!(path.exists(), "{} was never written", path.display());
            fs::remove_file(path).unwrap();
        }

        let config_path = write_file_storage_config(
            &config_dir,
            temp_dir_priv.path(),
            temp_dir_pub.path(),
            "repopulate = true",
            None,
        );
        let output = kms_gen_keys_command()
            .arg("--config-file")
            .arg(config_path)
            .output()
            .unwrap();
        let log = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(log.contains("Repopulated verification material"));
        for path in &purged {
            assert!(
                path.exists(),
                "{} was not restored by repopulate",
                path.display()
            );
        }
    }

    /// `repopulate = true` has nothing to derive from without the ECDSA signing key,
    /// so it must fail with a clear message rather than write partial material
    #[test]
    #[integration_test]
    fn central_repopulate_without_signing_key_fails() {
        let (temp_dir_priv, temp_dir_pub, config_dir) =
            (tempdir().unwrap(), tempdir().unwrap(), tempdir().unwrap());
        let config_path = write_file_storage_config(
            &config_dir,
            temp_dir_priv.path(),
            temp_dir_pub.path(),
            "repopulate = true",
            None,
        );
        let output = kms_gen_keys_command()
            .arg("--config-file")
            .arg(config_path)
            .output()
            .unwrap();

        assert!(!output.status.success());
        assert!(
            !temp_dir_pub.path().join("PUB/TypedVerfKey").exists(),
            "verification material was written without a signing key to derive it from"
        );
    }

    /// `repopulate = true` derives every non-ECDSA scheme from the root signing
    /// seed, so a node that kept its ECDSA key but lost the seed must fail up
    /// front rather than publish an ECDSA-only layout.
    #[test]
    #[integration_test]
    fn central_repopulate_without_root_seed_fails() {
        let (temp_dir_priv, temp_dir_pub, config_dir) =
            (tempdir().unwrap(), tempdir().unwrap(), tempdir().unwrap());
        run_centralized_overwrite(&config_dir, &temp_dir_priv, &temp_dir_pub);

        // The state this guards against: the ECDSA identity survives, the seed
        // every other scheme descends from does not.
        let seed_path = temp_dir_priv
            .path()
            .join("PRIV/SigningSeed")
            .join(SIGNING_KEY_ID.to_string());
        assert!(seed_path.exists(), "the seed was never written");
        fs::remove_file(&seed_path).unwrap();

        // Purge one non-ECDSA object, so "nothing was published" below means
        // something.
        let purged = temp_dir_pub
            .path()
            .join("PUB/TypedVerfKey")
            .join(signing_material_id(SigningSchemeType::Ed25519).to_string());
        assert!(purged.exists(), "{} was never written", purged.display());
        fs::remove_file(&purged).unwrap();

        let config_path = write_file_storage_config(
            &config_dir,
            temp_dir_priv.path(),
            temp_dir_pub.path(),
            "repopulate = true",
            None,
        );
        let output = kms_gen_keys_command()
            .arg("--config-file")
            .arg(config_path)
            .output()
            .unwrap();

        assert!(!output.status.success());
        let err_log = String::from_utf8_lossy(&output.stderr);
        assert!(
            err_log.contains("SigningSeed") && err_log.contains("kms-gen-keys"),
            "the failure does not name the missing seed: {err_log}"
        );
        assert!(
            !purged.exists(),
            "verification material was published without a root seed to derive it from"
        );
    }

    /// `show_existing = true` lists both halves of the private signing identity
    /// and the per-scheme public material, and deletes nothing.
    #[test]
    #[integration_test]
    fn central_show_existing_lists_the_signing_identity() {
        let (temp_dir_priv, temp_dir_pub, config_dir) =
            (tempdir().unwrap(), tempdir().unwrap(), tempdir().unwrap());
        run_centralized_overwrite(&config_dir, &temp_dir_priv, &temp_dir_pub);

        let config_path = write_file_storage_config(
            &config_dir,
            temp_dir_priv.path(),
            temp_dir_pub.path(),
            "show_existing = true",
            None,
        );
        let output = kms_gen_keys_command()
            .arg("--config-file")
            .arg(config_path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let log = String::from_utf8_lossy(&output.stdout);

        for data_type in ["SigningKey", "SigningSeed"] {
            let expected = format!("{data_type}, {}", *SIGNING_KEY_ID);
            assert!(
                log.contains(&expected),
                "{expected:?} is missing from {log}"
            );
        }
        let expected = format!(
            "TypedVerfKey, {}",
            signing_material_id(SigningSchemeType::MlDsa65)
        );
        assert!(
            log.contains(&expected),
            "{expected:?} is missing from {log}"
        );

        // Showing is read-only.
        assert!(
            temp_dir_priv
                .path()
                .join("PRIV/SigningSeed")
                .join(SIGNING_KEY_ID.to_string())
                .exists(),
            "show_existing deleted the root signing seed"
        );
    }

    #[test]
    #[integration_test]
    fn central_signing_address_format() {
        let (temp_dir_priv, temp_dir_pub, config_dir) =
            (tempdir().unwrap(), tempdir().unwrap(), tempdir().unwrap());
        let config_path = write_file_storage_config(
            &config_dir,
            temp_dir_priv.path(),
            temp_dir_pub.path(),
            "",
            None,
        );
        let output = kms_gen_keys_command()
            .arg("--config-file")
            .arg(config_path)
            .output()
            .unwrap();

        let log = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success());
        assert!(log.contains(&format!(
            "Stored {} VerfAddress under the handle {} in storage",
            SigningSchemeType::Ecdsa256k1,
            signing_material_id(SigningSchemeType::Ecdsa256k1)
        )));

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
    fn threshold_party_id_validation() {
        for (case, threshold_config, expected_err) in [
            (
                "party id 0 is rejected, since parties are 1-indexed",
                r#"
[threshold]
my_id = 0
tls_subject = "kms-party"

"#,
                "invalid kms-gen-keys config",
            ),
            (
                "a [threshold] section without a party id is rejected",
                r#"
[threshold]
tls_subject = "kms-party"

"#,
                "threshold.my_id",
            ),
        ] {
            let (temp_dir_priv, temp_dir_pub, config_dir) =
                (tempdir().unwrap(), tempdir().unwrap(), tempdir().unwrap());
            let config_path = write_file_storage_config(
                &config_dir,
                temp_dir_priv.path(),
                temp_dir_pub.path(),
                "",
                Some(threshold_config),
            );
            let output = Command::cargo_bin(KMS_GEN_KEYS)
                .unwrap()
                .arg("--config-file")
                .arg(config_path)
                .output()
                .unwrap();

            assert!(!output.status.success(), "{case}: expected a failure");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains(expected_err),
                "{case}: stderr did not mention {expected_err}: {stderr}"
            );
        }
    }

    #[test]
    #[integration_test]
    #[persistent_traces]
    fn threshold_signing_key() {
        let (temp_dir_priv, temp_dir_pub, config_dir) =
            (tempdir().unwrap(), tempdir().unwrap(), tempdir().unwrap());
        let config_path = write_file_storage_config(
            &config_dir,
            temp_dir_priv.path(),
            temp_dir_pub.path(),
            "",
            Some(
                r#"
[threshold]
my_id = 5
tls_subject = "kms-party"

"#,
            ),
        );

        let output = kms_gen_keys_command()
            .arg("--config-file")
            .arg(config_path)
            .output()
            .unwrap();

        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains(&format!(
            "Stored {} VerfAddress under the handle {} in storage",
            SigningSchemeType::Ecdsa256k1,
            signing_material_id(SigningSchemeType::Ecdsa256k1)
        )));
    }

    /// Deterministic centralized key generation persists both the public and private signing keys
    /// under the expected fixed handle.
    ///
    /// Formerly `central_s3`, which wrote the public vault to a live MinIO endpoint. The S3
    /// storage layer is now covered by in-process mock unit tests
    /// (`vault::storage::s3::tests`), so this exercises only the binary + config wiring against
    /// the file backend.
    #[test]
    #[integration_test]
    fn central_deterministic_signing_keys() {
        let (temp_dir_priv, temp_dir_pub, config_dir) =
            (tempdir().unwrap(), tempdir().unwrap(), tempdir().unwrap());
        let config_path = write_file_storage_config(
            &config_dir,
            temp_dir_priv.path(),
            temp_dir_pub.path(),
            "deterministic = true\noverwrite = true",
            None,
        );
        let output = kms_gen_keys_command()
            .arg("--config-file")
            .arg(config_path)
            .output()
            .unwrap();
        let log = String::from_utf8_lossy(&output.stdout);
        let err_log = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() {
            tracing::error!(
                status = %output.status,
                stdout = %log,
                stderr = %err_log,
                "kms-gen-keys centralized deterministic command failed"
            );
        }
        assert!(output.status.success());
        assert!(log.contains("Successfully stored private centralized server signing key under the handle 60b7070add74be3827160aa635fb255eeeeb88586c4debf7ab1134ddceb4beee in storage \"file storage with"));
        // The public ECDSA material of the same identity, at the same handle, in
        // both the canonical and the deprecated location.
        for folder in ["TypedVerfKey", "VerfKey"] {
            assert!(log.contains(&format!(
                "Stored {} {folder} under the handle {} in storage \"file storage with",
                SigningSchemeType::Ecdsa256k1,
                signing_material_id(SigningSchemeType::Ecdsa256k1)
            )));
        }
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

    #[test]
    #[integration_test]
    fn keygen_config_is_rejected() {
        let config_dir = tempfile::tempdir().unwrap();
        let config_path = config_dir.path().join("kms-gen-keys.toml");
        fs::write(
            &config_path,
            r#"
[keygen]

[public_vault.storage.file]
path = "/tmp"

[private_vault.storage.file]
path = "/tmp"
"#,
        )
        .unwrap();

        let output = Command::cargo_bin(KMS_SERVER)
            .unwrap()
            .arg("--config-file")
            .arg(config_path)
            .output()
            .unwrap();

        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("expected a [service] section"));
    }
}

#[cfg(test)]
mod kms_custodian_binary_tests {
    use aes_prng::AesRng;
    use assert_cmd::Command;
    use kms_grpc::{RequestId, kms::v1::CustodianContext};
    use kms_lib::{
        backup::{
            KMS_CUSTODIAN, RECOVERY_OUTPUT_DESC, SEED_PHRASE_DESC,
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
        engine::utils::{base64_deserialize, base64_serialize},
    };
    use rand::SeedableRng;
    use std::{collections::BTreeMap, thread};
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
        let (seed_phrase, _setup_msgs) = generate_custodian_keys(1);
        let (seed_phrase2, _setup_msgs) = generate_custodian_keys(1);

        // Ensure that randomness is always sampled on top of given randomness
        assert_ne!(seed_phrase, seed_phrase2);
    }

    #[test]
    fn sunshine_verify() {
        let (seed_phrase, setup_msg) = generate_custodian_keys(1);
        let serialized_setup_msg = base64_serialize(&setup_msg).unwrap();
        let verf_command = vec![
            "verify".to_string(),
            "--seed-phrase".to_string(),
            seed_phrase.to_string(),
            "--setup-msg".to_string(),
            serialized_setup_msg,
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

        // Generate custodian keys
        let mut setup_msgs = Vec::new();
        let mut seed_phrases: Vec<_> = Vec::new();
        for custodian_index in 1..=amount_custodians {
            let (seed_phrase, setup_msg) = generate_custodian_keys(custodian_index);
            setup_msgs.push(setup_msg);
            seed_phrases.push(seed_phrase);
        }

        // Generate operator keys along with the message to be backed up
        struct OperatorData {
            operator: Operator,
            commitment: RecoveryValidationMaterial,
            ephemeral_keys: (UnifiedPrivateEncKey, UnifiedPublicEncKey),
            backup_dec_key: UnifiedPrivateEncKey,
            /// base64-encoded recovery request the operator hands to each custodian
            recovery_request: String,
        }
        let mut operator_data = vec![];
        for _operator_index in 1..=amount_operators {
            let (cur_commitments, operator, cur_ephemeral_keys, backup_dec, recovery_request) =
                make_backup_sunshine(threshold, setup_msgs.clone(), backup_id).await;
            operator_data.push(OperatorData {
                operator,
                commitment: cur_commitments,
                ephemeral_keys: cur_ephemeral_keys,
                backup_dec_key: backup_dec,
                recovery_request,
            });
        }

        // Decrypt: each custodian re-encrypts its share for every operator. The custodian
        // output is printed to stdout as base64, collected per operator (in custodian order).
        let mut recovery_outputs: Vec<Vec<String>> = vec![Vec::new(); amount_operators];
        for custodian_index in 1..=amount_custodians {
            for (operator_index, data) in operator_data.iter().enumerate() {
                let decrypt_command = vec![
                    "decrypt".to_string(),
                    "--seed-phrase".to_string(),
                    seed_phrases[custodian_index - 1].to_string(),
                    "--custodian-role".to_string(),
                    custodian_index.to_string(),
                    "-b".to_string(),
                    data.recovery_request.clone(),
                ];
                let decrypt_out = run_custodian_cli(decrypt_command);
                recovery_outputs[operator_index].push(extract_decryption_payload(&decrypt_out));
            }
        }

        // Validate the decryption
        for (operator_index, op_data) in operator_data.into_iter().enumerate() {
            let OperatorData {
                operator,
                commitment,
                ephemeral_keys,
                backup_dec_key,
                ..
            } = op_data;
            let (dec_key, enc_key) = ephemeral_keys;
            let cur_res = decrypt_recovery(
                &recovery_outputs[operator_index],
                &operator,
                &commitment,
                &dec_key,
                &enc_key,
            );
            assert_eq!(
                cur_res,
                bc2wrap::serialize(&backup_dec_key).unwrap(),
                "Decryption did not match expected data for operator {}",
                operator.verification_key().address(),
            );
        }
    }

    fn extract_decryption_payload(output: &str) -> String {
        let payload_line = output
            .lines()
            .find(|line| line.contains(RECOVERY_OUTPUT_DESC))
            .expect("a successful decryption prints the recovery output");
        payload_line
            .split_at(payload_line.find(RECOVERY_OUTPUT_DESC).unwrap() + RECOVERY_OUTPUT_DESC.len())
            .1
            .trim()
            .to_string()
    }

    fn generate_custodian_keys(custodian_index: usize) -> (String, InternalCustodianSetupMessage) {
        let gen_command = vec![
            "generate".to_string(),
            "--randomness".to_string(),
            "123456".to_string(),
            "--custodian-role".to_string(),
            custodian_index.to_string(),
            "--custodian-name".to_string(),
            format!("skynet-{custodian_index}"),
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
        threshold: usize,
        setup_msgs: Vec<InternalCustodianSetupMessage>,
        backup_id: RequestId,
    ) -> (
        RecoveryValidationMaterial,
        Operator,
        (UnifiedPrivateEncKey, UnifiedPublicEncKey),
        UnifiedPrivateEncKey,
        String,
    ) {
        let amount_custodians = setup_msgs.len();
        let mut rng = AesRng::seed_from_u64(40);
        // Note that in the actual deployment, the operator keys are generated before the encryption keys
        let (verification_key, signing_key) = gen_sig_keys(&mut rng);

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
                *DEFAULT_MPC_CONTEXT,
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
            verification_key.clone(),
            ciphertexts,
        )
        .unwrap();
        let serialized_recovery_request = base64_serialize(&recovery_request).unwrap();
        (
            validation_material,
            operator,
            (ephemeral_priv_key, ephemeral_pub_key),
            backup_ske,
            serialized_recovery_request,
        )
    }

    fn decrypt_recovery(
        custodian_outputs: &[String],
        operator: &Operator,
        recovery_material: &RecoveryValidationMaterial,
        ephem_dec_key: &UnifiedPrivateEncKey,
        ephem_enc_key: &UnifiedPublicEncKey,
    ) -> Vec<u8> {
        let outputs: Vec<InternalCustodianRecoveryOutput> = custodian_outputs
            .iter()
            .map(|cur| base64_deserialize(cur).unwrap())
            .collect();
        operator
            .verify_and_recover(&outputs, recovery_material, ephem_dec_key, ephem_enc_key)
            .unwrap()
            .to_vec()
    }
}

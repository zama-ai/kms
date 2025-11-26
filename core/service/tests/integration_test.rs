use assert_cmd::{assert::OutputAssertExt, Command};
use kms_lib::consts::{
    KEY_PATH_PREFIX, PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL, PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL,
};
use kms_lib::vault::storage::{file::FileStorage, StorageType};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::str::FromStr;
use std::{fs, thread, time::Duration};
use sysinfo::System;
use tests_utils::integration_test;
use tests_utils::persistent_traces;
use threshold_fhe::conf::party::CertificatePaths;

const KMS_SERVER: &str = "kms-server";
const KMS_GEN_KEYS: &str = "kms-gen-keys";
const KMS_GEN_TLS_CERTS: &str = "kms-gen-tls-certs";
const KMS_INIT: &str = "kms-init";

/// Kill processes based on the executable name.
/// Note that tests using this function should run in serial mode
/// otherwise this function may kill processes in other tests.
fn kill_process(process_name: &str) {
    let mut sys = System::new_all();
    sys.refresh_all();

    for (pid, process) in sys.processes() {
        // exe returns the path to the process
        if let Some(path) = process.exe() {
            if let Some(s) = path.to_str() {
                if s.contains(process_name) {
                    println!(
                        "killing process {process_name} with pid {pid}: ok={}",
                        process.kill()
                    );
                }
            }
        }
    }
}

fn purge_file_storage(storage: &FileStorage) {
    let dir = storage.root_dir();
    if dir.exists() {
        fs::remove_dir_all(dir).unwrap();
    }
}

// We purge the centralized storage and the threshold storage for party-1
// since the CLI test only use default_1.toml.
fn purge_all() {
    let priv_storage = FileStorage::new(None, StorageType::PRIV, None).unwrap();
    let pub_storage = FileStorage::new(None, StorageType::PUB, None).unwrap();
    purge_file_storage(&priv_storage);
    purge_file_storage(&pub_storage);

    let priv_storage = FileStorage::new(
        None,
        StorageType::PRIV,
        PRIVATE_STORAGE_PREFIX_THRESHOLD_ALL[0].as_deref(),
    )
    .unwrap();
    let pub_storage = FileStorage::new(
        None,
        StorageType::PUB,
        PUBLIC_STORAGE_PREFIX_THRESHOLD_ALL[0].as_deref(),
    )
    .unwrap();
    purge_file_storage(&priv_storage);
    purge_file_storage(&pub_storage);

    let key_dir = PathBuf::from_str(KEY_PATH_PREFIX).unwrap();
    if key_dir.exists() {
        fs::remove_dir_all(key_dir).unwrap();
    }
}

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
    use tokio::fs::read_dir;

    use super::*;

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

    fn gen_key(arg: &str) {
        purge_all();
        Command::cargo_bin(KMS_GEN_KEYS)
            .unwrap()
            .arg("--param-test")
            .arg(arg)
            .output()
            .unwrap()
            .assert()
            .success();
    }

    #[test]
    #[serial_test::serial]
    #[integration_test]
    #[persistent_traces]
    fn gen_key_centralized() {
        gen_key("centralized")
    }

    #[test]
    #[serial_test::serial]
    #[integration_test]
    #[persistent_traces]
    fn gen_key_threshold() {
        gen_key("threshold")
    }

    async fn gen_key_tempdir(arg: &str) {
        let temp_dir_priv = tempdir().unwrap();
        let temp_dir_pub = tempdir().unwrap();
        Command::cargo_bin(KMS_GEN_KEYS)
            .unwrap()
            .arg("--param-test")
            .arg("--private-storage=file")
            .arg("--private-file-path")
            .arg(temp_dir_priv.path())
            .arg("--public-storage=file")
            .arg("--public-file-path")
            .arg(temp_dir_pub.path())
            .arg(arg)
            .output()
            .unwrap()
            .assert()
            .success();

        // NOTE, it's important to take the reference here otherwise
        // the tempdir value will be dropped and the destructor would be called
        let mut dir_priv = read_dir(&temp_dir_priv).await.unwrap();
        let mut dir_pub = read_dir(&temp_dir_pub).await.unwrap();

        // unwrap should succeed because the directory should not be empty
        _ = dir_priv.next_entry().await.unwrap();
        _ = dir_pub.next_entry().await.unwrap();
    }

    #[tokio::test]
    #[integration_test]
    #[persistent_traces]
    async fn gen_key_tempdir_centralized() {
        gen_key_tempdir("centralized").await
    }

    #[tokio::test]
    #[integration_test]
    #[persistent_traces]
    async fn gen_key_tempdir_threshold() {
        gen_key_tempdir("threshold").await
    }

    #[test]
    #[serial_test::serial]
    #[integration_test]
    fn central_signing_keys_overwrite() {
        let output = Command::cargo_bin(KMS_GEN_KEYS)
            .unwrap()
            .arg("--param-test")
            .arg("--cmd=signing-keys")
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

        let new_output = Command::cargo_bin(KMS_GEN_KEYS)
            .unwrap()
            .arg("--param-test")
            .arg("--cmd=signing-keys")
            .arg("centralized")
            .output()
            .unwrap();
        assert!(new_output.status.success());
        let new_log = String::from_utf8_lossy(&new_output.stdout);
        assert!(new_log.contains("Signing keys already exist, skipping generation"));
    }

    #[test]
    #[serial_test::serial]
    #[integration_test]
    fn central_signing_address_format() {
        let temp_dir_priv = tempdir().unwrap();
        let temp_dir_pub = tempdir().unwrap();
        let output = Command::cargo_bin(KMS_GEN_KEYS)
            .unwrap()
            .arg("--param-test")
            .arg("--private-storage=file")
            .arg("--private-file-path")
            .arg(temp_dir_priv.path())
            .arg("--public-storage=file")
            .arg("--public-file-path")
            .arg(temp_dir_pub.path())
            .arg("--cmd=signing-keys")
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
    #[serial_test::serial]
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
        assert!(String::from_utf8_lossy(&output.stderr)
            .contains("the number of parties should be larger or equal to 2"));
    }

    #[test]
    #[serial_test::serial]
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
            .arg("--cmd=signing-keys")
            .arg("threshold")
            .arg("--signing-key-party-id=5")
            .output()
            .unwrap();

        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr)
            .contains("party ID (5) cannot be greater than num_parties (4)"));
    }

    #[test]
    #[serial_test::serial]
    #[integration_test]
    #[persistent_traces]
    fn threshold_signing_key() {
        let temp_dir_priv = tempdir().unwrap();
        let temp_dir_pub = tempdir().unwrap();

        // finally we run the command with the right args
        let output = Command::cargo_bin(KMS_GEN_KEYS)
            .unwrap()
            .arg("--private-storage=file")
            .arg("--private-file-path")
            .arg(temp_dir_priv.path())
            .arg("--public-storage=file")
            .arg("--public-file-path")
            .arg(temp_dir_pub.path())
            .arg("--cmd=signing-keys")
            .arg("threshold")
            .arg("--signing-key-party-id=5")
            .arg("--num-parties=5")
            .output()
            .unwrap();

        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout)
            .contains("Successfully stored ethereum address 0x"));
    }

    #[cfg(feature = "s3_tests")]
    #[test]
    #[serial_test::serial]
    #[integration_test]
    fn central_s3() {
        use kms_lib::vault::storage::s3::{AWS_REGION, AWS_S3_ENDPOINT, BUCKET_NAME};

        // Test the following command:
        // cargo run --features testing  --bin kms-gen-keys -- --param-test --aws-region eu-north-1 --public-storage=s3 --public-s3-bucket ci-kms-key-test --public-s3-prefix=central_s3 --private-storage=file --private-file-path=./temp/keys/ --cmd=signing-keys --overwrite --deterministic
        let output = Command::cargo_bin(KMS_GEN_KEYS)
            .unwrap()
            .arg("--param-test")
            .arg(format!("--aws-region={AWS_REGION}"))
            .arg(format!("--aws-s3-endpoint={AWS_S3_ENDPOINT}"))
            .arg("--public-storage=s3")
            .arg("--public-s3-bucket")
            .arg(BUCKET_NAME)
            .arg("--public-s3-prefix")
            .arg("central_s3")
            .arg("--private-storage=file")
            .arg("--private-file-path")
            .arg("./temp/keys/")
            .arg("--cmd=signing-keys")
            .arg("--overwrite")
            .arg("--deterministic")
            .arg("centralized")
            .output()
            .unwrap();
        let log = String::from_utf8_lossy(&output.stdout);
        let err_log = String::from_utf8_lossy(&output.stderr);
        println!("Command output: {log}");
        println!("Command error output: {err_log}");
        assert!(output.status.success());
        assert!(log.contains("Successfully stored public centralized server signing key under the handle 60b7070add74be3827160aa635fb255eeeeb88586c4debf7ab1134ddceb4beee in storage \"S3 storage with"));
        assert!(log.contains("Successfully stored private centralized server signing key under the handle 60b7070add74be3827160aa635fb255eeeeb88586c4debf7ab1134ddceb4beee in storage \"file storage with"));
    }
}

#[cfg(test)]
mod kms_server_binary_test {
    use super::*;

    fn kill_kms_server() {
        kill_process(KMS_SERVER)
    }

    #[test]
    #[serial_test::serial]
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

    fn run_subcommand_no_args(config_file: &str) {
        // Spawn with correct arguments and check it does not
        // die within 5 seconds.
        // Note that the join handle cannot kill the thread,
        // so we need [kill_kms_server] for it.
        let config_file = config_file.to_string();
        let h = thread::spawn(|| {
            let out = Command::cargo_bin(KMS_SERVER)
                .unwrap()
                .arg("--config-file")
                .arg(config_file)
                .output();
            // Debug output of failing tests
            println!("Command output: {out:?}");
        });

        thread::sleep(Duration::from_secs(5));
        assert!(!h.is_finished());

        kill_kms_server();
        h.join().unwrap();

        // We need to manually delete the storage every time
        // since it might affect other tests (in other modules).
        purge_all();
    }

    #[test]
    #[serial_test::serial]
    #[integration_test]
    #[persistent_traces]
    fn subcommand_dev_centralized() {
        purge_all();
        Command::cargo_bin(KMS_GEN_KEYS)
            .unwrap()
            .arg("--param-test")
            .arg("centralized")
            .output()
            .unwrap()
            .assert()
            .success();
        run_subcommand_no_args("config/default_centralized.toml");
    }

    #[test]
    #[serial_test::serial]
    #[integration_test]
    #[persistent_traces]
    fn subcommand_dev_threshold() {
        purge_all();
        Command::cargo_bin(KMS_GEN_KEYS)
            .unwrap()
            .arg("--param-test")
            .arg("threshold")
            .output()
            .unwrap()
            .assert()
            .success();

        // NOTE that we use the cert directory instead of
        // a temporary directory because kms-server binary
        // doesn't know about the temporary directory since
        // its configuration is loaded from a file.
        Command::cargo_bin(KMS_GEN_TLS_CERTS)
            .unwrap()
            .arg("-o")
            .arg("certs")
            .arg("--ca-prefix")
            .arg("p")
            .arg("--ca-count")
            .arg("4")
            .output()
            .unwrap()
            .assert()
            .success();
        run_subcommand_no_args("config/default_1.toml");
    }

    #[test]
    #[serial_test::serial]
    fn test_cert_paths() {
        // make a temporary directory for the certificates
        let all_rwx = std::fs::Permissions::from_mode(0o777);
        let temp_dir = tempfile::Builder::new()
            .prefix(
                &std::env::current_dir()
                    .unwrap()
                    .as_path()
                    .join("cert-paths-test"),
            )
            .permissions(all_rwx)
            .tempdir()
            .unwrap();
        let actual_permissions = temp_dir.path().metadata().unwrap().permissions();
        println!(
            "temp_dir path: {:?}, permission: {:o}",
            temp_dir.path(),
            actual_permissions.mode()
        );

        // Note that we're testing the type `CertificatePaths`
        // which is from core/threshold but using the binary in core/service.
        Command::cargo_bin(KMS_GEN_TLS_CERTS)
            .unwrap()
            .args([
                "--ca-prefix=p",
                "--ca-count=4",
                "-o",
                temp_dir.path().to_str().unwrap(),
            ])
            .output()
            .expect("failed to execute process");

        let cert_path = temp_dir.path().join("cert_p1.pem");
        let key_path = temp_dir.path().join("key_p1.pem");

        let cert_paths = CertificatePaths {
            cert: cert_path.to_str().unwrap().to_string(),
            key: key_path.to_str().unwrap().to_string(),
            calist: [
                "cert_p1.pem,",
                "cert_p2.pem,",
                "cert_p3.pem,",
                "cert_p4.pem",
            ]
            .map(|suffix| temp_dir.path().join(suffix).to_str().unwrap().to_string())
            .concat(),
        };

        assert!(cert_paths.get_certificate().is_ok());
        assert!(cert_paths.get_identity().is_ok());
        assert!(cert_paths.get_flattened_ca_list().is_ok());
        for i in 0..4 {
            // note that party IDs start at 1
            let pid = i + 1;
            assert!(cert_paths.get_ca_by_name(&format!("p{pid}")).is_ok());
        }
        assert!(cert_paths.get_ca_by_name("p5").is_err());

        // using localhost should fail too because it's not a part of the issuer
        assert!(cert_paths.get_ca_by_name("localhost").is_err());
    }
}

#[cfg(test)]
mod kms_custodian_binary_tests {
    use aes_prng::AesRng;
    use assert_cmd::Command;
    use kms_grpc::{kms::v1::CustodianContext, RequestId};
    use kms_lib::{
        backup::{
            custodian::{
                InternalCustodianContext, InternalCustodianRecoveryOutput,
                InternalCustodianSetupMessage,
            },
            operator::{InternalRecoveryRequest, Operator, RecoveryValidationMaterial},
            seed_phrase::custodian_from_seed_phrase,
            KMS_CUSTODIAN, SEED_PHRASE_DESC,
        },
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
    use threshold_fhe::execution::runtime::party::Role;

    fn run_custodian_cli(commands: Vec<String>) -> String {
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
        println!("Command output: {output_string}");
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
    #[serial_test::serial]
    fn sunshine_generate() {
        let temp_dir = tempfile::tempdir().unwrap();
        let (seed_phrase, _setup_msgs) = generate_custodian_keys_to_file(temp_dir.path(), 1);
        let (seed_phrase2, _setup_msgs) = generate_custodian_keys_to_file(temp_dir.path(), 1);

        // Ensure that randomness is always sampled on top of given randomness
        assert_ne!(seed_phrase, seed_phrase2);
    }

    #[test]
    #[serial_test::serial]
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

    #[tracing_test::traced_test]
    #[tokio::test]
    #[serial_test::serial]
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
        let (ct_map, commitments) = operator
            .secret_share_and_signcrypt(
                &mut rng,
                &bc2wrap::serialize(&backup_ske).unwrap(),
                backup_id,
            )
            .unwrap();
        let custodian_context = InternalCustodianContext::new(
            CustodianContext {
                custodian_nodes: setup_msgs
                    .iter()
                    .map(|cur| cur.to_owned().try_into().unwrap())
                    .collect(),
                context_id: Some(backup_id.into()),
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

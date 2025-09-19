use assert_cmd::{assert::OutputAssertExt, Command};
use kms_lib::consts::KEY_PATH_PREFIX;
use kms_lib::vault::storage::{file::FileStorage, StorageType};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::str::FromStr;
use std::{fs, thread, time::Duration};
use sysinfo::System;
use tests_utils::integration_test;
use tests_utils::persistent_traces;
use threshold_fhe::{conf::party::CertificatePaths, execution::runtime::party::Role};

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

    let role = Some(Role::indexed_from_one(1));
    let priv_storage = FileStorage::new(None, StorageType::PRIV, role).unwrap();
    let pub_storage = FileStorage::new(None, StorageType::PUB, role).unwrap();
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
        assert!(log.contains("Successfully stored public server signing key under the handle"));

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
        assert!(log.contains("Successfully stored public server signing key under the handle 60b7070add74be3827160aa635fb255eeeeb88586c4debf7ab1134ddceb4beee in storage \"S3 storage with"));
        assert!(log.contains("Successfully stored private central server signing key under the handle 60b7070add74be3827160aa635fb255eeeeb88586c4debf7ab1134ddceb4beee in storage \"file storage with"));
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

use assert_cmd::{assert::OutputAssertExt, Command};
use kms_lib::consts::KEY_PATH_PREFIX;
use kms_lib::storage::{file::FileStorage, StorageType};
use std::path::PathBuf;
use std::str::FromStr;
use std::{fs, thread, time::Duration};
use sysinfo::System;
use test_utils::integration_test;

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

    let i = 1usize;
    let priv_storage = FileStorage::new(None, StorageType::PRIV, Some(i)).unwrap();
    let pub_storage = FileStorage::new(None, StorageType::PUB, Some(i)).unwrap();
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
    use std::fs::read_dir;
    use tempfile::tempdir;

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
    fn gen_key_centralized() {
        gen_key("centralized")
    }

    #[test]
    #[serial_test::serial]
    #[integration_test]
    fn gen_key_threshold() {
        gen_key("threshold")
    }

    fn gen_key_tempdir(arg: &str) {
        let temp_dir_priv = tempdir().unwrap();
        let temp_dir_pub = tempdir().unwrap();
        Command::cargo_bin(KMS_GEN_KEYS)
            .unwrap()
            .arg("--param-test")
            .arg("--priv-url")
            .arg(format!("file://{}", temp_dir_priv.path().display()))
            .arg("--pub-url")
            .arg(format!("file://{}", temp_dir_pub.path().display()))
            .arg(arg)
            .output()
            .unwrap()
            .assert()
            .success();

        // NOTE, it's important to take the reference here otherwise
        // the tempdir value will be dropped and the destructor would be called
        let mut dir_priv = read_dir(&temp_dir_priv).unwrap();
        let mut dir_pub = read_dir(&temp_dir_pub).unwrap();

        // unwrap should succeed because the directory should not be empty
        _ = dir_priv.next().unwrap();
        _ = dir_pub.next().unwrap();
    }

    #[test]
    #[integration_test]
    fn gen_key_tempdir_centralized() {
        gen_key_tempdir("centralized")
    }

    #[test]
    #[integration_test]
    fn gen_key_tempdir_threshold() {
        gen_key_tempdir("threshold")
    }
}

#[cfg(test)]
mod kms_server_binary_test {
    use tempfile::tempdir;

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
            println!("Command output: {:?}", out);
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
    #[integration_test]
    fn central_signing_keys_overwrite() {
        let output = Command::cargo_bin(KMS_GEN_KEYS)
            .unwrap()
            .arg("--centralized")
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
            .arg("--priv-url")
            .arg(format!("file://{}", temp_dir_priv.path().display()))
            .arg("--pub-url")
            .arg(format!("file://{}", temp_dir_pub.path().display()))
            .arg("--cmd=signing-keys")
            .arg("centralized")
            .output()
            .unwrap();

        let log = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success());
        assert!(log.contains("Successfully stored ethereum address 0x"));
        assert!(
            log.contains("under the handle e164d9de0bec6656928726433cc56bef6ee8417a in storage")
        );

        let mut adress_path = temp_dir_pub.path().to_path_buf();
        adress_path.push("PUB/VerfAddress/e164d9de0bec6656928726433cc56bef6ee8417a");

        // read address from file
        let address = fs::read_to_string(adress_path).expect("Unable to read Verification Address");

        // make sure its well-formed (starts with 0x and has 40 hex digits)
        assert!(address.starts_with("0x"));
        assert_eq!(address.len(), 42);
        hex::decode(address[2..].to_lowercase()).unwrap();
    }

    #[cfg(feature = "s3_tests")]
    #[test]
    #[serial_test::serial]
    #[integration_test]
    fn central_s3() {
        use kms_lib::storage::s3::{AWS_REGION, AWS_S3_ENDPOINT, BUCKET_NAME};

        let s3_url = format!("s3://{}/central_s3/", BUCKET_NAME);
        let file_url = "file://temp/keys/";
        // Test the following command:
        // cargo run --features testing  --bin kms-gen-keys -- --centralized --param-test --aws-region eu-north-1 --pub-url=s3://jot2re-kms-key-test/central_s3/ --priv-url=file://temp/keys/ --cmd=signing-keys --overwrite --deterministic
        let output = Command::cargo_bin(KMS_GEN_KEYS)
            .unwrap()
            .arg("--centralized")
            .arg("--param-test")
            .arg(format!("--aws-region={}", AWS_REGION))
            .arg(format!("--aws-s3-endpoint={}", AWS_S3_ENDPOINT))
            .arg(format!("--pub-url={}", s3_url))
            .arg(format!("--priv-url={}", file_url))
            .arg("--cmd=signing-keys")
            .arg("--overwrite")
            .arg("--deterministic")
            .output()
            .unwrap();
        let log = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success());
        assert!(log.contains("Successfully stored public server signing key under the handle e164d9de0bec6656928726433cc56bef6ee8417a with storage \"S3 storage with bucket"));
        assert!(log.contains("Successfully stored public server signing key under the handle e164d9de0bec6656928726433cc56bef6ee8417a with storage \"file storage with"));
    }
}

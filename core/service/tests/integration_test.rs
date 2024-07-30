use assert_cmd::{assert::OutputAssertExt, Command};
use kms_lib::consts::KEY_PATH_PREFIX;
use kms_lib::storage::{FileStorage, StorageType};
use std::path::PathBuf;
use std::str::FromStr;
use std::{fs, thread, time::Duration};
use sysinfo::System;

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
    let priv_storage = FileStorage::new_centralized(None, StorageType::PRIV).unwrap();
    let pub_storage = FileStorage::new_centralized(None, StorageType::PUB).unwrap();
    purge_file_storage(&priv_storage);
    purge_file_storage(&pub_storage);

    let i = 1usize;
    let priv_storage = FileStorage::new_threshold(None, StorageType::PRIV, i).unwrap();
    let pub_storage = FileStorage::new_threshold(None, StorageType::PUB, i).unwrap();
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
    fn init() {
        let buf = Command::cargo_bin(KMS_INIT)
            .unwrap()
            .arg("-a")
            .arg("http://127.0.0.1:55555")
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
            .arg(arg)
            .arg("--param-path")
            .arg("parameters/small_test_params.json")
            .output()
            .unwrap()
            .assert()
            .success();
    }

    #[test]
    #[serial_test::serial]
    fn gen_key_centralized() {
        gen_key("centralized")
    }

    #[test]
    #[serial_test::serial]
    fn gen_key_threshold() {
        gen_key("threshold")
    }

    fn gen_key_tempdir(arg: &str) {
        let temp_dir_priv = tempdir().unwrap();
        let temp_dir_pub = tempdir().unwrap();
        Command::cargo_bin(KMS_GEN_KEYS)
            .unwrap()
            .arg(arg)
            .arg("--param-path")
            .arg("parameters/small_test_params.json")
            .arg("--priv-url")
            .arg(format!("file://{}", temp_dir_priv.path().display()))
            .arg("--pub-url")
            .arg(format!("file://{}", temp_dir_pub.path().display()))
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
    fn gen_key_tempdir_centralized() {
        gen_key_tempdir("centralized")
    }

    #[test]
    fn gen_key_tempdir_threshold() {
        gen_key_tempdir("threshold")
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
    fn help() {
        Command::cargo_bin(KMS_SERVER)
            .unwrap()
            .arg("--help")
            .output()
            .unwrap()
            .assert()
            .success();

        // check the subcommands
        Command::cargo_bin(KMS_SERVER)
            .unwrap()
            .arg("threshold")
            .arg("--help")
            .output()
            .unwrap()
            .assert()
            .success();
        Command::cargo_bin(KMS_SERVER)
            .unwrap()
            .arg("centralized")
            .arg("--help")
            .output()
            .unwrap()
            .assert()
            .success();
        Command::cargo_bin(KMS_SERVER)
            .unwrap()
            .arg("nitro-enclave-proxy")
            .arg("--help")
            .output()
            .unwrap()
            .assert()
            .success();
    }

    fn run_subcommand_no_args(config_file: &str, exec_mode: &str) {
        purge_all();
        if exec_mode == "threshold" {
            Command::cargo_bin(KMS_GEN_KEYS)
                .unwrap()
                .arg("threshold")
                .arg("--param-path")
                .arg("parameters/small_test_params.json")
                .output()
                .unwrap()
                .assert()
                .success();

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
        } else {
            Command::cargo_bin(KMS_GEN_KEYS)
                .unwrap()
                .arg("centralized")
                .arg("--param-path")
                .arg("parameters/small_test_params.json")
                .output()
                .unwrap()
                .assert()
                .success();
        }

        // Spawn with correct arguments and check it does not
        // die within 5 seconds.
        // Note that the join handle cannot kill the thread,
        // so we need [kill_kms_server] for it.
        let exec_mode = exec_mode.to_string(); // clone this to pass into thread
        let config_file = config_file.to_string();
        let h = thread::spawn(|| {
            let out = Command::cargo_bin(KMS_SERVER)
                .unwrap()
                .arg(exec_mode)
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
    fn subcommand_dev_centralized() {
        run_subcommand_no_args("config/default_centralized.toml", "centralized");
    }

    #[test]
    #[serial_test::serial]
    fn subcommand_dev_threshold() {
        run_subcommand_no_args("config/default_1.toml", "threshold");
    }

    // NOTE: this test is ignored because it won't run on a non-nitro environment
    // find another way to test it, e.g., mock the missing devices like `/dev/nsm`
    #[test]
    #[ignore]
    #[serial_test::serial]
    fn subcommand_enclave() {
        run_subcommand_no_args("enclave", "centralized")
    }
}

use assert_cmd::{assert::OutputAssertExt, Command};
use kms_lib::consts::{AMOUNT_PARTIES, KEY_PATH_PREFIX, TMP_PATH_PREFIX};
use kms_lib::storage::{FileStorage, StorageType};
use std::path::PathBuf;
use std::str::FromStr;
use std::{fs, thread, time::Duration};
use sysinfo::System;

const KMS_SERVER: &str = "kms-server";
const KMS_GEN_KEYS: &str = "kms-gen-keys";

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
    let dir = storage.root_dir().unwrap();
    if dir.exists() {
        fs::remove_dir_all(dir).unwrap();
    }
}

fn purge_all() {
    let priv_storage = FileStorage::new_central(StorageType::PRIV);
    let pub_storage = FileStorage::new_central(StorageType::PUB);
    purge_file_storage(&priv_storage);
    purge_file_storage(&pub_storage);
    for i in 1..=AMOUNT_PARTIES {
        let priv_storage = FileStorage::new_threshold(StorageType::PRIV, i);
        let pub_storage = FileStorage::new_threshold(StorageType::PUB, i);
        purge_file_storage(&priv_storage);
        purge_file_storage(&pub_storage);
    }

    let tmp_dir = PathBuf::from_str(TMP_PATH_PREFIX).unwrap();
    if tmp_dir.exists() {
        fs::remove_dir_all(tmp_dir).unwrap();
    }

    let key_dir = PathBuf::from_str(KEY_PATH_PREFIX).unwrap();
    if key_dir.exists() {
        fs::remove_dir_all(key_dir).unwrap();
    }
}

#[cfg(test)]
mod kms_gen_keys_binary_test {
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

    #[test]
    fn gen_key() {
        Command::cargo_bin(KMS_GEN_KEYS)
            .unwrap()
            .arg("centralized")
            .arg("--param-path")
            .arg("parameters/small_test_params.json")
            .output()
            .unwrap()
            .assert()
            .success();

        Command::cargo_bin(KMS_GEN_KEYS)
            .unwrap()
            .arg("threshold")
            .arg("--param-path")
            .arg("parameters/small_test_params.json")
            .output()
            .unwrap()
            .assert()
            .success();
    }
}

#[cfg(test)]
mod kms_server_binary_test {
    use std::{path::PathBuf, str::FromStr};

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
            .arg("dev")
            .arg("--help")
            .output()
            .unwrap()
            .assert()
            .success();
        Command::cargo_bin(KMS_SERVER)
            .unwrap()
            .arg("proxy")
            .arg("--help")
            .output()
            .unwrap()
            .assert()
            .success();
        Command::cargo_bin(KMS_SERVER)
            .unwrap()
            .arg("enclave")
            .arg("--help")
            .output()
            .unwrap()
            .assert()
            .success();
    }

    fn run_subcommand_no_args(storage_mode: &str, exec_mode: &str) {
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
        let storage_mode = storage_mode.to_string();
        let h = thread::spawn(|| {
            let _ = Command::cargo_bin(KMS_SERVER)
                .unwrap()
                .arg(storage_mode)
                .arg(exec_mode)
                .output();
        });

        thread::sleep(Duration::from_secs(5));
        assert!(!h.is_finished());

        kill_kms_server();
        h.join().unwrap();

        // We need to manually delete the storage every time
        // since it might affect other tests (in other modules).
        purge_all();

        let tmp_dir = PathBuf::from_str(TMP_PATH_PREFIX).unwrap();
        if tmp_dir.exists() {
            fs::remove_dir_all(tmp_dir).unwrap();
        }
    }

    #[test]
    #[serial_test::serial]
    fn subcommand_dev_centralized() {
        run_subcommand_no_args("dev", "centralized");
    }

    #[test]
    #[serial_test::serial]
    fn subcommand_dev_threshold() {
        run_subcommand_no_args("dev", "threshold");
    }

    #[test]
    #[serial_test::serial]
    fn subcommand_proxy_centralized() {
        run_subcommand_no_args("proxy", "centralized");
    }

    #[test]
    fn subcommand_proxy_threshold() {
        // we expect this test to fail since it's not implemented
        Command::cargo_bin(KMS_SERVER)
            .unwrap()
            .arg("proxy")
            .arg("threshold")
            .output()
            .unwrap()
            .assert()
            .failure();
    }

    #[test]
    #[ignore]
    #[serial_test::serial]
    fn subcommand_enclave() {
        // TODO this test is ignored because it won't run on a non-nitro environment
        // find another way to test it, e.g., mock the missing devices like `/dev/nsm`
        run_subcommand_no_args("enclave", "centralized")
    }
}

use assert_cmd::{assert::OutputAssertExt, Command};
use std::{thread, time::Duration};
use sysinfo::System;

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

#[cfg(test)]
mod kms_server_binary_test {
    use super::*;
    const KMS_BIN_NAME: &str = "kms-server";

    fn kill_kms_server() {
        kill_process(KMS_BIN_NAME)
    }

    #[test]
    #[serial_test::serial]
    fn help() {
        Command::cargo_bin(KMS_BIN_NAME)
            .unwrap()
            .arg("--help")
            .output()
            .unwrap()
            .assert()
            .success();

        // check the subcommands
        Command::cargo_bin(KMS_BIN_NAME)
            .unwrap()
            .arg("dev")
            .arg("--help")
            .output()
            .unwrap()
            .assert()
            .success();
        Command::cargo_bin(KMS_BIN_NAME)
            .unwrap()
            .arg("proxy")
            .arg("--help")
            .output()
            .unwrap()
            .assert()
            .success();
        Command::cargo_bin(KMS_BIN_NAME)
            .unwrap()
            .arg("enclave")
            .arg("--help")
            .output()
            .unwrap()
            .assert()
            .success();
    }

    fn run_subcommand_no_args(subcommand: &str) {
        // Spawn with correct arguments and check it does not
        // die within 5 seconds.
        // Note that the join handle cannot kill the thread,
        // so we need [kill_kms_server] for it.
        let subcommand = subcommand.to_string(); // clone this to pass into thread
        let h = thread::spawn(|| {
            let _ = Command::cargo_bin(KMS_BIN_NAME)
                .unwrap()
                .arg(subcommand)
                .output();
        });

        thread::sleep(Duration::from_secs(5));
        assert!(!h.is_finished());

        kill_kms_server();
        h.join().unwrap();
    }

    #[test]
    #[serial_test::serial]
    fn subcommand_dev() {
        run_subcommand_no_args("dev")
    }

    #[test]
    #[serial_test::serial]
    fn subcommand_proxy() {
        run_subcommand_no_args("proxy")
    }

    #[test]
    #[ignore]
    #[serial_test::serial]
    fn subcommand_enclave() {
        // TODO this test is ignored because it won't run on a non-nitro environment
        // find another way to test it, e.g., mock the missing devices like `/dev/nsm`
        run_subcommand_no_args("enclave")
    }
}

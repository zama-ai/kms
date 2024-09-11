use serial_test::serial;
use simulator::*;
use std::path::Path;
use std::string::String;
use test_context::{test_context, AsyncTestContext};
use tests_utils::{DockerCompose, KMSMode};
use tokio::fs;

const BOOTSTRAP_TIME_TO_SLEEP: u64 = 20;

struct DockerComposeCentralizedContext {
    pub cmd: DockerCompose,
    pub test_dir: std::path::PathBuf,
}

impl AsyncTestContext for DockerComposeCentralizedContext {
    async fn setup() -> Self {
        // Probably dangerous in the case of concurrent tests
        // We should probably create a folder per-test and add it to the test context
        let test_dir = std::path::Path::new("tests/data");
        fs::create_dir_all(test_dir).await.unwrap();
        DockerComposeCentralizedContext {
            cmd: DockerCompose::new(KMSMode::Centralized),
            test_dir: test_dir.to_path_buf(),
        }
    }

    async fn teardown(self) {
        fs::remove_dir_all(self.test_dir).await.unwrap();
        drop(self.cmd);
    }
}

struct DockerComposeThresholdContext {
    pub cmd: DockerCompose,
    pub test_dir: std::path::PathBuf,
}

impl AsyncTestContext for DockerComposeThresholdContext {
    async fn setup() -> Self {
        let test_dir = std::path::Path::new("tests/data");
        fs::create_dir_all(test_dir).await.unwrap();
        DockerComposeThresholdContext {
            cmd: DockerCompose::new(KMSMode::Threshold),
            test_dir: test_dir.to_path_buf(),
        }
    }

    async fn teardown(self) {
        fs::remove_dir_all(self.test_dir).await.unwrap();
        drop(self.cmd);
    }
}

#[test_context(DockerComposeCentralizedContext)]
#[tokio::test]
#[serial(docker)]
async fn test_decryption_centralized(ctx: &mut DockerComposeCentralizedContext) {
    // Wait for contract to be in-chain
    // TODO: add status check for contract in-chain
    tokio::time::sleep(tokio::time::Duration::from_secs(BOOTSTRAP_TIME_TO_SLEEP)).await;

    let path_to_config = ctx
        .cmd
        .cmd
        .root_path
        .clone()
        .join("blockchain/simulator/config/local_centralized.toml");

    let config = Config {
        file_conf: Some(String::from(path_to_config.to_str().unwrap())),
        command: Command::Decrypt(Execute { to_encrypt: 7_u8 }),
    };

    let keys_folder: &Path = Path::new("tests/data/keys");

    main_from_config(&config.file_conf.unwrap(), &config.command, keys_folder)
        .await
        .unwrap();
}

#[test_context(DockerComposeThresholdContext)]
#[tokio::test]
#[serial(docker)]
async fn test_decryption_threshold(ctx: &mut DockerComposeThresholdContext) {
    // Wait for contract to be in-chain
    // TODO: add status check for contract in-chain
    tokio::time::sleep(tokio::time::Duration::from_secs(BOOTSTRAP_TIME_TO_SLEEP)).await;

    let path_to_config = ctx
        .cmd
        .cmd
        .root_path
        .clone()
        .join("blockchain/simulator/config/local_threshold.toml");

    let config = Config {
        file_conf: Some(String::from(path_to_config.to_str().unwrap())),
        command: Command::Decrypt(Execute { to_encrypt: 7_u8 }),
    };
    let keys_folder: &Path = Path::new("tests/data/keys");

    main_from_config(&config.file_conf.unwrap(), &config.command, keys_folder)
        .await
        .unwrap();
}

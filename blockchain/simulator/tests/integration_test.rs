use serial_test::serial;
use simulator::*;
use std::path::Path;
use std::path::PathBuf;
use std::string::String;
use test_context::{test_context, AsyncTestContext};
use tests_utils::{DockerCompose, KMSMode};
use tokio::fs;

/// IMPORTANT: These integration tests require Docker running and images build.
/// You can build the images by running the following commands from the root of the repo:
/// ```
/// docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-threshold.yml build
/// docker compose -vvv -f docker-compose-kms-base.yml -f docker-compose-kms-centralized.yml build
/// ```
/// Any issue might be related to the fact that some obsolete Docker images exist.

const BOOTSTRAP_TIME_TO_SLEEP: u64 = 150; // Wait a 2min30s for everything to setup properly

trait DockerComposeContext {
    fn root_path(&self) -> PathBuf;
    fn config_path(&self) -> &str;
}

struct DockerComposeCentralizedContext {
    pub cmd: DockerCompose,
    pub test_dir: std::path::PathBuf,
}

impl DockerComposeContext for DockerComposeCentralizedContext {
    fn root_path(&self) -> PathBuf {
        self.cmd.cmd.root_path.clone()
    }

    fn config_path(&self) -> &str {
        "blockchain/simulator/config/local_centralized.toml"
    }
}

impl AsyncTestContext for DockerComposeCentralizedContext {
    async fn setup() -> Self {
        // TODO: probably dangerous in the case of concurrent tests
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

impl DockerComposeContext for DockerComposeThresholdContext {
    fn root_path(&self) -> PathBuf {
        self.cmd.cmd.root_path.clone()
    }

    fn config_path(&self) -> &str {
        "blockchain/simulator/config/local_threshold.toml"
    }
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

async fn test_template<T: DockerComposeContext>(ctx: &mut T, commands: Vec<Command>) {
    // Wait for contract to be in-chain
    // TODO: add status check for contract in-chain
    tokio::time::sleep(tokio::time::Duration::from_secs(BOOTSTRAP_TIME_TO_SLEEP)).await;

    let path_to_config = ctx.root_path().join(ctx.config_path());

    let keys_folder: &Path = Path::new("tests/data/keys");

    for command in commands {
        let config = Config {
            file_conf: Some(String::from(path_to_config.to_str().unwrap())),
            command,
        };

        main_from_config(&config.file_conf.unwrap(), &config.command, keys_folder)
            .await
            .unwrap();

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}

#[test_context(DockerComposeCentralizedContext)]
#[tokio::test]
#[serial(docker)]
async fn test_centralized(ctx: &mut DockerComposeCentralizedContext) {
    let commands = vec![
        Command::InsecureKeyGen(Nothing {}),
        Command::Decrypt(CryptExecute {
            to_encrypt: 7_u8,
            compressed: false,
        }),
        Command::Decrypt(CryptExecute {
            to_encrypt: 10_u8,
            compressed: true,
        }),
        Command::ReEncrypt(CryptExecute {
            to_encrypt: 9_u8,
            compressed: false,
        }),
        Command::ReEncrypt(CryptExecute {
            to_encrypt: 13_u8,
            compressed: true,
        }),
        Command::CrsGen(CrsExecute { max_num_bits: 1 }),
        Command::VerifyProvenCt(VerifyProvenCtExecute {
            to_encrypt: 41,
            crs_id: None,
            key_id: None,
        }),
    ];
    test_template(ctx, commands).await
}

#[test_context(DockerComposeThresholdContext)]
#[tokio::test]
#[serial(docker)]
async fn test_threshold(ctx: &mut DockerComposeThresholdContext) {
    let commands = vec![
        Command::InsecureKeyGen(Nothing {}),
        Command::CrsGen(CrsExecute { max_num_bits: 1 }),
        Command::Decrypt(CryptExecute {
            to_encrypt: 7_u8,
            compressed: false,
        }),
        Command::Decrypt(CryptExecute {
            to_encrypt: 32_u8,
            compressed: true,
        }),
        Command::ReEncrypt(CryptExecute {
            to_encrypt: 9_u8,
            compressed: false,
        }),
        Command::ReEncrypt(CryptExecute {
            to_encrypt: 28_u8,
            compressed: true,
        }),
        Command::VerifyProvenCt(VerifyProvenCtExecute {
            to_encrypt: 41,
            crs_id: None,
            key_id: None,
        }),
    ];
    test_template(ctx, commands).await
}

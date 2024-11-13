use events::kms::OperationValue;
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

const BOOTSTRAP_TIME_TO_SLEEP: u64 = 60;

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

async fn key_and_crs_gen<T: DockerComposeContext>(ctx: &mut T) -> (String, String) {
    // Wait for contract to be in-chain
    // TODO: add status check for contract in-chain
    tokio::time::sleep(tokio::time::Duration::from_secs(BOOTSTRAP_TIME_TO_SLEEP)).await;

    let path_to_config = ctx.root_path().join(ctx.config_path());

    let keys_folder: &Path = Path::new("tests/data/keys");

    let config = Config {
        file_conf: Some(String::from(path_to_config.to_str().unwrap())),
        command: SimulatorCommand::InsecureKeyGen(NoParameters {}),
        logs: true,
        max_iter: 200,
    };
    println!("Doing key-gen");
    let key_gen_results = main_from_config(
        &config.file_conf.unwrap(),
        &config.command,
        keys_folder,
        Some(config.max_iter),
    )
    .await
    .unwrap();
    println!("Key-gen done");

    let config = Config {
        file_conf: Some(String::from(path_to_config.to_str().unwrap())),
        command: SimulatorCommand::CrsGen(CrsParameters { max_num_bits: 256 }),
        logs: true,
        max_iter: 200,
    };

    let key_ids: Vec<String> = match key_gen_results {
        Some(values) => values
            .iter()
            .map(|x| match x {
                OperationValue::KeyGenResponse(key_gen_response) => {
                    key_gen_response.request_id().to_hex()
                }
                _ => panic!("Not all responses are KeyGenResponses"),
            })
            .collect(),
        _ => panic!("Error doing keygen"),
    };

    println!("Doing CRS-gen");
    let crs_gen_results = main_from_config(
        &config.file_conf.unwrap(),
        &config.command,
        keys_folder,
        Some(config.max_iter),
    )
    .await
    .unwrap();
    println!("CRS-gen done");
    let crs_ids: Vec<String> = match crs_gen_results {
        Some(values) => values
            .iter()
            .map(|x| match x {
                OperationValue::CrsGenResponse(crs_gen_response) => {
                    String::from(crs_gen_response.request_id())
                }
                _ => panic!("Not all responses are crsGenResponses"),
            })
            .collect(),
        _ => panic!("Error doing crsgen"),
    };
    let crs_id = crs_ids.first().expect("CRS id is None").to_lowercase();
    let key_id = key_ids.first().expect("Key id is None").to_lowercase();
    (key_id.to_string(), crs_id.to_string())
}

async fn test_template<T: DockerComposeContext>(ctx: &mut T, commands: Vec<SimulatorCommand>) {
    // Wait for contract to be in-chain
    // TODO: add status check for contract in-chain
    tokio::time::sleep(tokio::time::Duration::from_secs(BOOTSTRAP_TIME_TO_SLEEP)).await;

    let path_to_config = ctx.root_path().join(ctx.config_path());

    let keys_folder: &Path = Path::new("tests/data/keys");

    for command in commands {
        let config = Config {
            file_conf: Some(String::from(path_to_config.to_str().unwrap())),
            command,
            logs: true,
            max_iter: 50,
        };

        main_from_config(
            &config.file_conf.unwrap(),
            &config.command,
            keys_folder,
            Some(50),
        )
        .await
        .unwrap();

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}

#[test_context(DockerComposeCentralizedContext)]
#[tokio::test]
#[serial(docker)]
async fn test_centralized(ctx: &mut DockerComposeCentralizedContext) {
    init_logging();
    let (key_id, crs_id) = key_and_crs_gen(ctx).await;

    let commands = vec![
        SimulatorCommand::Decrypt(CipherParameters {
            to_encrypt: 7_u8,
            compressed: false,
            crs_id: crs_id.clone(),
            key_id: key_id.clone(),
        }),
        SimulatorCommand::Decrypt(CipherParameters {
            to_encrypt: 10_u8,
            compressed: true,
            crs_id: crs_id.clone(),
            key_id: key_id.clone(),
        }),
        SimulatorCommand::ReEncrypt(CipherParameters {
            to_encrypt: 9_u8,
            compressed: false,
            crs_id: crs_id.clone(),
            key_id: key_id.clone(),
        }),
        SimulatorCommand::ReEncrypt(CipherParameters {
            to_encrypt: 13_u8,
            compressed: true,
            crs_id: crs_id.clone(),
            key_id: key_id.clone(),
        }),
        SimulatorCommand::VerifyProvenCt(VerifyProvenCtParameters {
            to_encrypt: 41,
            crs_id: crs_id.clone(),
            key_id: key_id.clone(),
        }),
    ];
    test_template(ctx, commands).await
}

#[test_context(DockerComposeThresholdContext)]
#[tokio::test]
#[serial(docker)]
async fn test_threshold(ctx: &mut DockerComposeThresholdContext) {
    init_logging();
    let (key_id, crs_id) = key_and_crs_gen(ctx).await;

    let commands = vec![
        SimulatorCommand::Decrypt(CipherParameters {
            to_encrypt: 7_u8,
            compressed: false,
            crs_id: crs_id.clone(),
            key_id: key_id.clone(),
        }),
        SimulatorCommand::Decrypt(CipherParameters {
            to_encrypt: 32_u8,
            compressed: true,
            crs_id: crs_id.clone(),
            key_id: key_id.clone(),
        }),
        SimulatorCommand::ReEncrypt(CipherParameters {
            to_encrypt: 9_u8,
            compressed: false,
            crs_id: crs_id.clone(),
            key_id: key_id.clone(),
        }),
        SimulatorCommand::ReEncrypt(CipherParameters {
            to_encrypt: 28_u8,
            compressed: true,
            crs_id: crs_id.clone(),
            key_id: key_id.clone(),
        }),
        SimulatorCommand::VerifyProvenCt(VerifyProvenCtParameters {
            to_encrypt: 41,
            crs_id: crs_id.clone(),
            key_id: key_id.clone(),
        }),
    ];
    test_template(ctx, commands).await
}

use assert_cmd::Command;
use cc_tests_utils::{DockerCompose, KMSMode};
use kms_core_client::mpc_context::create_test_context_info_from_core_config;
use kms_core_client::*;
use kms_grpc::identifiers::EpochId;
use kms_grpc::rpc_types::PubDataType;
use kms_grpc::ContextId;
use kms_grpc::KeyId;
use kms_grpc::RequestId;
use kms_lib::backup::SEED_PHRASE_DESC;
use kms_lib::consts::ID_LENGTH;
use kms_lib::consts::SAFE_SER_SIZE_LIMIT;
use kms_lib::consts::SIGNING_KEY_ID;
use kms_lib::engine::base::safe_serialize_hash_element_versioned;
use kms_lib::engine::base::DSEP_PUBDATA_KEY;
use kms_lib::util::key_setup::test_tools::load_material_from_pub_storage;
use kms_lib::util::key_setup::test_tools::load_pk_from_pub_storage;
use serial_test::serial;
use std::fs::create_dir_all;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process::Output;
use std::str::FromStr;
use std::string::String;
use test_context::futures::future::join_all;
use test_context::{test_context, AsyncTestContext};
use tfhe::safe_serialization;

// IMPORTANT: These integration tests require Docker running and images build.
// You can build the images by running the following commands from the root of the repo:
// ```
// docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml build
// docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-centralized.yml build
// ```
// Any issue might be related to the fact that some obsolete Docker images exist.

// We use the following naming convention:
// - centralized tests have "centralized" in their name
// - threshold tests have "threshold" in their name
// - nightly tests are marked with "nightly_tests" in their name.
// We use this to filter tests in CI runs.

trait DockerComposeManager {
    fn root_path(&self) -> PathBuf;
    fn config_path(&self) -> &str;

    #[cfg(test)]
    /// Defaults to the same as config_path, can be overridden if needed.
    fn alternative_config_path(&self) -> &str {
        self.config_path()
    }
}

struct DockerComposeCentralized {
    pub cmd: DockerCompose,
}

impl DockerComposeManager for DockerComposeCentralized {
    fn root_path(&self) -> PathBuf {
        self.cmd.cmd.root_path.clone()
    }

    fn config_path(&self) -> &str {
        "core-client/config/client_local_centralized.toml"
    }
}

impl AsyncTestContext for DockerComposeCentralized {
    async fn setup() -> Self {
        DockerComposeCentralized {
            cmd: DockerCompose::new(KMSMode::Centralized),
        }
    }

    async fn teardown(self) {
        drop(self.cmd);
    }
}

struct DockerComposeCentralizedCustodian {
    pub cmd: DockerCompose,
}

impl DockerComposeManager for DockerComposeCentralizedCustodian {
    fn root_path(&self) -> PathBuf {
        self.cmd.cmd.root_path.clone()
    }

    fn config_path(&self) -> &str {
        "core-client/config/client_local_centralized.toml"
    }
}

impl AsyncTestContext for DockerComposeCentralizedCustodian {
    async fn setup() -> Self {
        DockerComposeCentralizedCustodian {
            cmd: DockerCompose::new(KMSMode::CentralizedCustodian),
        }
    }

    async fn teardown(self) {
        drop(self.cmd);
    }
}

struct DockerComposeThresholdDefault {
    pub cmd: DockerCompose,
}

impl DockerComposeManager for DockerComposeThresholdDefault {
    fn root_path(&self) -> PathBuf {
        self.cmd.cmd.root_path.clone()
    }

    fn config_path(&self) -> &str {
        "core-client/config/client_local_threshold.toml"
    }
}

impl AsyncTestContext for DockerComposeThresholdDefault {
    async fn setup() -> Self {
        Self {
            cmd: DockerCompose::new(KMSMode::ThresholdDefaultParameter),
        }
    }

    async fn teardown(self) {
        drop(self.cmd);
    }
}

struct DockerComposeThresholdTest {
    pub cmd: DockerCompose,
}

impl DockerComposeManager for DockerComposeThresholdTest {
    fn root_path(&self) -> PathBuf {
        self.cmd.cmd.root_path.clone()
    }

    fn config_path(&self) -> &str {
        "core-client/config/client_local_threshold.toml"
    }
}

impl AsyncTestContext for DockerComposeThresholdTest {
    async fn setup() -> Self {
        Self {
            cmd: DockerCompose::new(KMSMode::ThresholdTestParameter),
        }
    }

    async fn teardown(self) {
        drop(self.cmd);
    }
}

struct DockerComposeThresholdTestNoInit {
    pub cmd: DockerCompose,
}

impl DockerComposeManager for DockerComposeThresholdTestNoInit {
    fn root_path(&self) -> PathBuf {
        self.cmd.cmd.root_path.clone()
    }

    fn config_path(&self) -> &str {
        "core-client/config/client_local_threshold.toml"
    }
}

impl AsyncTestContext for DockerComposeThresholdTestNoInit {
    async fn setup() -> Self {
        Self {
            cmd: DockerCompose::new(KMSMode::ThresholdTestParameterNoInit),
        }
    }

    async fn teardown(self) {
        drop(self.cmd);
    }
}

struct DockerComposeThresholdTestNoInitSixParty {
    pub cmd: DockerCompose,
}

impl DockerComposeManager for DockerComposeThresholdTestNoInitSixParty {
    fn root_path(&self) -> PathBuf {
        self.cmd.cmd.root_path.clone()
    }

    fn config_path(&self) -> &str {
        "core-client/config/client_local_threshold.toml"
    }

    #[cfg(test)]
    fn alternative_config_path(&self) -> &str {
        "core-client/config/client_local_threshold_alternative.toml"
    }
}

impl AsyncTestContext for DockerComposeThresholdTestNoInitSixParty {
    async fn setup() -> Self {
        Self {
            cmd: DockerCompose::new(KMSMode::ThresholdTestParameterNoInitSixParty),
        }
    }

    async fn teardown(self) {
        drop(self.cmd);
    }
}

struct DockerComposeThresholdCustodianTest {
    pub cmd: DockerCompose,
}

impl DockerComposeManager for DockerComposeThresholdCustodianTest {
    fn root_path(&self) -> PathBuf {
        self.cmd.cmd.root_path.clone()
    }

    fn config_path(&self) -> &str {
        "core-client/config/client_local_threshold.toml"
    }
}

impl AsyncTestContext for DockerComposeThresholdCustodianTest {
    async fn setup() -> Self {
        Self {
            cmd: DockerCompose::new(KMSMode::ThresholdCustodianTestParameter),
        }
    }

    async fn teardown(self) {
        drop(self.cmd);
    }
}

async fn insecure_key_gen<T: DockerComposeManager>(ctx: &T, test_path: &Path) -> String {
    let path_to_config = ctx.root_path().join(ctx.config_path());
    let config = CmdConfig {
        file_conf: Some(String::from(path_to_config.to_str().unwrap())),
        command: CCCommand::InsecureKeyGen(InsecureKeyGenParameters {
            shared_args: SharedKeyGenParameters::default(),
        }),
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Doing insecure key-gen");
    let key_gen_results = execute_cmd(&config, test_path).await.unwrap();
    println!("Insecure key-gen done");

    assert_eq!(key_gen_results.len(), 1);
    let key_id = match key_gen_results.first().unwrap() {
        (Some(value), _) => value,
        _ => panic!("Error doing insecure keygen"),
    };

    key_id.to_string()
}

async fn crs_gen<T: DockerComposeManager>(
    ctx: &T,
    test_path: &Path,
    insecure_crs_gen: bool,
) -> String {
    let path_to_config = ctx.root_path().join(ctx.config_path());
    let command = match insecure_crs_gen {
        true => CCCommand::InsecureCrsGen(CrsParameters { max_num_bits: 2048 }),
        false => CCCommand::CrsGen(CrsParameters { max_num_bits: 2048 }),
    };
    let config = CmdConfig {
        file_conf: Some(String::from(path_to_config.to_str().unwrap())),
        command,
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Doing CRS-gen");
    let crs_gen_results = execute_cmd(&config, test_path).await.unwrap();
    println!("CRS-gen done");
    assert_eq!(crs_gen_results.len(), 1);
    let crs_id = match crs_gen_results.first().unwrap() {
        (Some(value), _) => value,
        _ => panic!("Error doing keygen"),
    };

    crs_id.to_string()
}

async fn real_preproc(
    config_path: &str,
    test_path: &Path,
    context_id: Option<ContextId>,
    epoch_id: Option<EpochId>,
) -> anyhow::Result<Option<RequestId>> {
    let config = CmdConfig {
        file_conf: Some(config_path.to_string()),
        command: CCCommand::PreprocKeyGen(KeyGenPreprocParameters {
            context_id,
            epoch_id,
        }),
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };
    println!("Doing preprocessing");
    let mut preproc_result = execute_cmd(&config, test_path)
        .await
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    assert_eq!(preproc_result.len(), 1);
    preproc_result
        .pop()
        .map(|(preproc_id, _)| preproc_id)
        .ok_or(anyhow::anyhow!("missing preproc result"))
}

async fn real_preproc_and_keygen(
    config_path: &str,
    test_path: &Path,
    context_id: Option<ContextId>,
    epoch_id: Option<EpochId>,
) -> (String, String) {
    let preproc_id = real_preproc(config_path, test_path, context_id, epoch_id)
        .await
        .unwrap();
    println!("Preprocessing done with ID {preproc_id:?}");
    let config = CmdConfig {
        file_conf: Some(config_path.to_string()),
        command: CCCommand::KeyGen(KeyGenParameters {
            preproc_id: preproc_id.unwrap(),
            shared_args: SharedKeyGenParameters {
                keyset_type: None,
                context_id,
                epoch_id,
            },
        }),
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };
    println!("Doing key-gen");
    let key_gen_results = execute_cmd(&config, test_path).await.unwrap();
    println!("Key-gen done");
    assert_eq!(key_gen_results.len(), 1);

    let key_id = match key_gen_results.first().unwrap() {
        (Some(value), _) => value,
        _ => panic!("Error doing keygen"),
    };

    (key_id.to_string(), preproc_id.unwrap().to_string())
}

async fn restore_from_backup<T: DockerComposeManager>(ctx: &T, test_path: &Path) -> String {
    let path_to_config = ctx.root_path().join(ctx.config_path());

    let init_command = CCCommand::BackupRestore(NoParameters {});
    let init_config = CmdConfig {
        file_conf: Some(String::from(path_to_config.to_str().unwrap())),
        command: init_command,
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Doing restore from backup");
    let restore_from_backup_results = execute_cmd(&init_config, test_path).await.unwrap();
    println!("Restore from backup done");
    assert_eq!(restore_from_backup_results.len(), 1);
    // No backup ID is returned since restore_from_backup can also be used without custodians
    assert_eq!(restore_from_backup_results.first().unwrap().0, None);
    "".to_string()
}

async fn test_template<T: DockerComposeManager>(
    ctx: &T,
    commands: Vec<CCCommand>,
    test_path: &Path,
) {
    let path_to_config = ctx.root_path().join(ctx.config_path());
    for command in commands {
        let config = CmdConfig {
            file_conf: Some(String::from(path_to_config.to_str().unwrap())),
            command: command.clone(),
            logs: true,
            max_iter: 500,
            expect_all_responses: true,
            download_all: false,
        };

        let results = execute_cmd(&config, test_path).await.unwrap();

        //Make sure load is as expected
        match &command {
            CCCommand::PublicDecrypt(cipher_arguments)
            | CCCommand::UserDecrypt(cipher_arguments) => {
                let num_expected_results = cipher_arguments.get_num_requests();
                assert_eq!(results.len(), num_expected_results);
            }
            _ => {}
        }

        //Also test the get result commands
        let req_id = results[0].0;

        let get_res_command = match command {
            CCCommand::PreprocKeyGen(_no_parameters) => {
                CCCommand::PreprocKeyGenResult(ResultParameters {
                    request_id: req_id.unwrap(),
                })
            }
            CCCommand::KeyGen(_key_gen_parameters) => CCCommand::KeyGenResult(ResultParameters {
                request_id: req_id.unwrap(),
            }),
            CCCommand::InsecureKeyGen(_insecure_key_gen_parameters) => {
                CCCommand::InsecureKeyGenResult(ResultParameters {
                    request_id: req_id.unwrap(),
                })
            }
            CCCommand::PublicDecrypt(_cipher_arguments) => {
                CCCommand::PublicDecryptResult(ResultParameters {
                    request_id: req_id.unwrap(),
                })
            }
            CCCommand::CrsGen(_crs_parameters) => CCCommand::CrsGenResult(ResultParameters {
                request_id: req_id.unwrap(),
            }),
            CCCommand::InsecureCrsGen(_crs_parameters) => {
                CCCommand::InsecureCrsGenResult(ResultParameters {
                    request_id: req_id.unwrap(),
                })
            }
            _ => CCCommand::DoNothing(NoParameters {}),
        };

        let expect_result = !matches!(&get_res_command, CCCommand::DoNothing(_));

        if expect_result {
            let config = CmdConfig {
                file_conf: Some(String::from(path_to_config.to_str().unwrap())),
                command: get_res_command,
                logs: true,
                max_iter: 500,
                expect_all_responses: true,
                download_all: false,
            };

            //We query result on a single request id, so should get a single result
            let mut results_bis = execute_cmd(&config, test_path).await.unwrap();
            assert_eq!(results_bis.len(), 1);
            let (sid_bis, result_bis) = results_bis.remove(0);

            for (sid, result) in results {
                if sid_bis == sid {
                    assert_eq!(result_bis, result);
                }
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}

async fn new_custodian_context<T: DockerComposeManager>(
    ctx: &T,
    test_path: &Path,
    custodian_threshold: u32,
    setup_msg_paths: Vec<PathBuf>,
) -> String {
    let path_to_config = ctx.root_path().join(ctx.config_path());
    let command = CCCommand::NewCustodianContext(NewCustodianContextParameters {
        threshold: custodian_threshold,
        setup_msg_paths,
    });
    let init_config = CmdConfig {
        file_conf: Some(String::from(path_to_config.to_str().unwrap())),
        command,
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Doing new custodian context");
    let backup_init_results = execute_cmd(&init_config, test_path).await.unwrap();
    println!("New custodian context done");
    assert_eq!(backup_init_results.len(), 1);
    let res_id = match backup_init_results.first().unwrap() {
        (Some(value), _) => value,
        _ => panic!("Error doing new custodian context"),
    };

    res_id.to_string()
}

async fn store_mpc_context_in_file(context_path: &Path, config_path: &Path, context_id: ContextId) {
    let cc_conf: CoreClientConfig = observability::conf::Settings::builder()
        .path(config_path.to_str().unwrap())
        .env_prefix("CORE_CLIENT")
        .build()
        .init_conf()
        .unwrap();

    let context = create_test_context_info_from_core_config(context_id, &cc_conf)
        .await
        .unwrap();
    println!(
        "Storing context \n{:?}\nto file {:?}",
        context, context_path
    );

    let mut buf = Vec::new();
    safe_serialization::safe_serialize(&context, &mut buf, SAFE_SER_SIZE_LIMIT).unwrap();

    let mut file = std::fs::File::create(context_path).unwrap();
    file.write_all(&buf).unwrap();
}

// expect the context path to already hold some context
async fn new_mpc_context(context_path: &Path, config_path: &Path, test_path: &Path) {
    let command = CCCommand::NewMpcContext(NewMpcContextParameters::SerializedContextPath(
        ContextPath {
            input_path: context_path.to_path_buf(),
        },
    ));
    let init_config = CmdConfig {
        file_conf: Some(String::from(config_path.to_str().unwrap())),
        command,
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    let context_switch_result = execute_cmd(&init_config, test_path).await.unwrap();
    assert_eq!(context_switch_result.len(), 1);
}

async fn destroy_mpc_context(context_id: &ContextId, config_path: &Path, test_path: &Path) {
    let command = CCCommand::DestroyMpcContext(DestroyMpcContextParameters {
        context_id: *context_id,
    });
    let init_config = CmdConfig {
        file_conf: Some(String::from(config_path.to_str().unwrap())),
        command,
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    let context_destroy_result = execute_cmd(&init_config, test_path).await.unwrap();
    assert_eq!(context_destroy_result.len(), 1);
}

// expect the context to already exist in the KMS servers
async fn new_prss(context_id: ContextId, epoch_id: EpochId, config_path: &Path, test_path: &Path) {
    let command = CCCommand::PrssInit(PrssInitParameters {
        context_id,
        epoch_id,
    });
    let init_config = CmdConfig {
        file_conf: Some(String::from(config_path.to_str().unwrap())),
        command,
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    let prss_result = execute_cmd(&init_config, test_path).await.unwrap();
    assert_eq!(prss_result.len(), 1);
}

async fn generate_custodian_keys_to_file(
    temp_dir: &Path,
    amount_custodians: usize,
    threshold: bool,
) -> (Vec<String>, Vec<PathBuf>) {
    let mut seeds = Vec::new();
    let mut setup_msgs_paths = Vec::new();
    // Use the first server to just play custodian in the tests
    let container_name = if threshold {
        "zama-core-threshold-dev-kms-core-1-1".to_string()
    } else {
        "zama-core-centralized-dev-kms-core-1".to_string()
    };
    for cus_idx in 1..=amount_custodians {
        let cur_setup_path = temp_dir
            .join("CUSTODIAN")
            .join("setup-msg")
            .join(format!("setup-{}", cus_idx));
        // Ensure the dir exists locally
        assert!(create_dir_all(cur_setup_path.parent().unwrap()).is_ok());
        // Ensure the temp dir exists on docker as well. For simplicity we just use the same dir as locally
        let mkdir_docker = Command::new("docker")
            .arg("exec")
            .arg(&container_name)
            .arg("mkdir")
            .arg("-p")
            .arg(cur_setup_path.parent().unwrap()) // Use the parent since the path is to the specific file for this custodian
            .output()
            .unwrap();
        assert!(mkdir_docker.status.success());
        // NOTE the KMS Custodian is a separate binary needed for the full integration test flow.
        // Ensure that it is compiled and up to date before running the test
        let args = [
            "generate",
            "--randomness",
            "123456",
            "--custodian-role",
            &cus_idx.to_string(),
            "--custodian-name",
            &format!("skynet-{cus_idx}"),
            "--path",
            cur_setup_path.to_str().unwrap(),
        ];
        let cmd_output = Command::new("docker")
            .arg("exec")
            .arg(&container_name)
            .arg("/app/kms/core/service/bin/kms-custodian")
            .args(args)
            .output()
            .unwrap();
        assert!(cmd_output.status.success());
        let seed_phrase = extract_seed_phrase(cmd_output);
        seeds.push(seed_phrase);
        // Copy the files from docker to the local file system
        let cp_output = Command::new("docker")
            .arg("cp")
            .arg(format!(
                "{}:{}",
                &container_name,
                cur_setup_path.to_str().unwrap()
            ))
            .arg(cur_setup_path.to_str().unwrap())
            .output()
            .unwrap();
        assert!(cp_output.status.success());
        setup_msgs_paths.push(cur_setup_path);
    }
    (seeds, setup_msgs_paths)
}

fn extract_seed_phrase(out: Output) -> String {
    let errors = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "Command did not execute successfully: {} : {}",
        out.status,
        errors
    );
    assert!(errors.is_empty());
    let output_string = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    let seed_phrase_line = output_string
        .lines()
        .find(|line| line.contains(SEED_PHRASE_DESC));
    seed_phrase_line
        .unwrap()
        .split_at(SEED_PHRASE_DESC.len())
        .1
        .trim()
        .to_string()
}

async fn custodian_backup_init<T: DockerComposeManager>(
    ctx: &T,
    test_path: &Path,
    operator_recovery_resp_paths: Vec<PathBuf>,
) -> String {
    let path_to_config = ctx.root_path().join(ctx.config_path());

    let init_command = CCCommand::CustodianRecoveryInit(RecoveryInitParameters {
        operator_recovery_resp_paths,
        overwrite_ephemeral_key: false,
    });
    let init_config = CmdConfig {
        file_conf: Some(String::from(path_to_config.to_str().unwrap())),
        command: init_command,
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Doing backup init");
    let backup_init_results = execute_cmd(&init_config, test_path).await.unwrap();
    println!("Backup init done");
    assert_eq!(backup_init_results.len(), 1);
    let res_id = match backup_init_results.first().unwrap() {
        (Some(value), _) => value,
        _ => panic!("Error doing backup init"),
    };

    res_id.to_string()
}

async fn custodian_reencrypt(
    temp_dir: &Path,
    amount_operators: usize,
    amount_custodians: usize,
    backup_id: RequestId,
    seeds: &[String],
    recovery_paths: &[PathBuf],
) -> Vec<PathBuf> {
    let mut response_paths = Vec::new();
    for operator_index in 1..=amount_operators {
        let pub_prefix = if amount_operators == 1 {
            "PUB".to_string()
        } else {
            format!("PUB-p{}", operator_index)
        };
        let container_name = if amount_operators > 1 {
            format!("zama-core-threshold-dev-kms-core-{operator_index}-1")
        } else {
            "zama-core-centralized-dev-kms-core-1".to_string()
        };
        let cur_recovery_path = &recovery_paths[operator_index - 1];
        // Ensure the temp dir exists on docker as well. For simplicity we just use the same dir as locally
        let mkdir_docker = Command::new("docker")
            .arg("exec")
            .arg(&container_name)
            .arg("mkdir")
            .arg("-p")
            .arg(cur_recovery_path.parent().unwrap())
            .output()
            .unwrap();
        assert!(mkdir_docker.status.success());
        // Copy the previous responses from local to docker
        let cp_output_local_resp = Command::new("docker")
            .arg("cp")
            .arg(cur_recovery_path.to_str().unwrap())
            .arg(format!(
                "{}:{}",
                &container_name,
                cur_recovery_path.to_str().unwrap()
            ))
            .output()
            .unwrap();
        assert!(cp_output_local_resp.status.success());

        for custodian_index in 1..=amount_custodians {
            let cur_response_path = &temp_dir
                .join("CUSTODIAN")
                .join("response")
                .join(backup_id.to_string())
                .join(format!(
                    "recovery-response-{}-{}",
                    operator_index, custodian_index,
                ));
            assert!(create_dir_all(cur_response_path.parent().unwrap()).is_ok());
            // Ensure the temp dir exists on docker
            let mkdir_docker = Command::new("docker")
                .arg("exec")
                .arg(&container_name)
                .arg("mkdir")
                .arg("-p")
                .arg(cur_response_path.parent().unwrap())
                .output()
                .unwrap();
            assert!(mkdir_docker.status.success());
            let verf_path = temp_dir
                .join(&pub_prefix)
                .join(PubDataType::VerfKey.to_string())
                .join(SIGNING_KEY_ID.to_string());
            let mkdir_docker = Command::new("docker")
                .arg("exec")
                .arg(&container_name)
                .arg("mkdir")
                .arg("-p")
                .arg(verf_path.parent().unwrap())
                .output()
                .unwrap();
            assert!(mkdir_docker.status.success());
            let cp_output = Command::new("docker")
                .arg("cp")
                .arg(verf_path.to_str().unwrap())
                .arg(format!(
                    "{}:{}",
                    &container_name,
                    verf_path.to_str().unwrap()
                ))
                .output()
                .unwrap();
            assert!(cp_output.status.success());
            // NOTE the KMS Custodian is a separate binary needed for the full integration test flow.
            // Ensure that it is compiled and up to date before running the test
            // NOTE the KMS Custodian is a separate binary needed for the full integration test flow.
            // Ensure that it is compiled and up to date before running the test
            let args = [
                "decrypt",
                "--seed-phrase",
                &seeds[custodian_index - 1],
                "--custodian-role",
                &custodian_index.to_string(),
                "--operator-verf-key",
                verf_path.to_str().unwrap(),
                "-b",
                cur_recovery_path.to_str().unwrap(),
                "-o",
                cur_response_path.to_str().unwrap(),
            ];
            let cmd_output = Command::new("docker")
                .arg("exec")
                .arg(&container_name)
                .arg("/app/kms/core/service/bin/kms-custodian")
                .args(args)
                .output()
                .unwrap();
            println!(
                "Custodian re-encrypt output: {}",
                String::from_utf8_lossy(&cmd_output.stdout)
            );
            println!(
                "Custodian re-encrypt errors: {}",
                String::from_utf8_lossy(&cmd_output.stderr)
            );
            assert!(cmd_output.status.success());
            // Copy the response files from docker to the local file system
            let cp_output_resp = Command::new("docker")
                .arg("cp")
                .arg(format!(
                    "{}:{}",
                    &container_name,
                    cur_response_path.to_str().unwrap()
                ))
                .arg(cur_response_path.to_str().unwrap())
                .output()
                .unwrap();
            assert!(cp_output_resp.status.success());
            response_paths.push(cur_response_path.to_owned());
        }
    }
    response_paths
}

async fn custodian_backup_recovery<T: DockerComposeManager>(
    ctx: &T,
    test_path: &Path,
    custodian_recovery_outputs: Vec<PathBuf>,
    backup_id: RequestId,
) -> String {
    let path_to_config = ctx.root_path().join(ctx.config_path());
    let command = CCCommand::CustodianBackupRecovery(RecoveryParameters {
        custodian_context_id: backup_id,
        custodian_recovery_outputs,
    });
    let init_config = CmdConfig {
        file_conf: Some(String::from(path_to_config.to_str().unwrap())),
        command,
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Doing backup recovery");
    let backup_recovery_results = execute_cmd(&init_config, test_path).await.unwrap();
    println!("Backup init recovery");
    assert_eq!(backup_recovery_results.len(), 1);
    let res_id = match backup_recovery_results.first().unwrap() {
        (Some(value), _) => value,
        _ => panic!("Error doing backup recovery"),
    };

    res_id.to_string()
}

#[test_context(DockerComposeCentralized)]
#[tokio::test]
#[serial(docker)]
async fn test_centralized_insecure(ctx: &DockerComposeCentralized) {
    init_testing();
    let temp_dir = tempfile::tempdir().unwrap();
    let keys_folder = temp_dir.path();
    let key_id = insecure_key_gen(ctx, keys_folder).await;
    integration_test_commands(ctx, key_id).await;
}

#[test_context(DockerComposeCentralized)]
#[tokio::test]
#[serial(docker)]
async fn test_centralized_crsgen_secure(ctx: &DockerComposeCentralized) {
    init_testing();
    let temp_dir = tempfile::tempdir().unwrap();
    let keys_folder = temp_dir.path();
    let crs_id = crs_gen(ctx, keys_folder, false).await;
    // hex string with double the length of ID_LENGTH
    assert_eq!(crs_id.len(), ID_LENGTH * 2);
}

// Test restore without custodians
#[test_context(DockerComposeCentralized)]
#[tokio::test]
#[serial(docker)]
async fn test_centralized_restore_from_backup(ctx: &DockerComposeCentralized) {
    init_testing();
    let temp_dir = tempfile::tempdir().unwrap();
    let keys_folder = temp_dir.path();
    let _crs_id = crs_gen(ctx, keys_folder, true).await;
    let _ = restore_from_backup(ctx, keys_folder).await;
    // Observe that we cannot modify the state of the servers, so we cannot really validate the restore.
    // However we are testing this in the service/client tests. Hence this tests is mainly to ensure that the outer
    // end points, and content returned from the KMS to the custodians, work as expected.
}

#[test_context(DockerComposeCentralizedCustodian)]
#[tokio::test]
#[serial(docker)]
async fn test_centralized_custodian_backup(ctx: &DockerComposeCentralizedCustodian) {
    init_testing();
    let amount_custodians = 5;
    let custodian_threshold = 2;
    let temp_dir = tempfile::tempdir().unwrap();
    let temp_path = temp_dir.path();
    let (seeds, setup_msg_paths) =
        generate_custodian_keys_to_file(temp_path, amount_custodians, false).await;
    let cus_backup_id =
        new_custodian_context(ctx, temp_path, custodian_threshold, setup_msg_paths).await;
    let operator_recovery_resp_path = temp_path
        .join("CUSTODIAN")
        .join("recovery")
        .join(&cus_backup_id)
        .join("central");
    // Ensure the dir exists locally
    assert!(create_dir_all(operator_recovery_resp_path.parent().unwrap()).is_ok());
    let init_backup_id =
        custodian_backup_init(ctx, temp_path, vec![operator_recovery_resp_path.clone()]).await;
    assert_eq!(cus_backup_id, init_backup_id);
    let recovery_output_paths = custodian_reencrypt(
        temp_path,
        1,
        amount_custodians,
        init_backup_id.try_into().unwrap(),
        &seeds,
        &[operator_recovery_resp_path],
    )
    .await;
    let recovery_backup_id = custodian_backup_recovery(
        ctx,
        temp_path,
        recovery_output_paths,
        RequestId::from_str(&cus_backup_id).unwrap(),
    )
    .await;
    assert_eq!(cus_backup_id, recovery_backup_id);
    let _ = restore_from_backup(ctx, temp_path).await;
    // Observe that we cannot modify the state of the servers, so we cannot really validate the restore.
    // However we are testing this in the service/client tests. Hence this tests is mainly to ensure that the outer
    // end points, and content returned from the KMS to the custodians, work as expected.
}

#[test_context(DockerComposeThresholdDefault)]
#[tokio::test]
#[serial(docker)]
async fn test_threshold_insecure(ctx: &DockerComposeThresholdDefault) {
    init_testing();
    let temp_dir = tempfile::tempdir().unwrap();
    let keys_folder = temp_dir.path();
    let key_id = insecure_key_gen(ctx, keys_folder).await;
    integration_test_commands(ctx, key_id).await;
}

async fn integration_test_commands<T: DockerComposeManager>(ctx: &T, key_id: String) {
    let temp_dir = tempfile::tempdir().unwrap();
    let keys_folder = temp_dir.path();
    let ctxt_path: &Path = Path::new("tests/data/test_encrypt_cipher.txt");
    let ctxt_with_sns_path: &Path = Path::new("tests/data/test_encrypt_cipher_with_sns.txt");
    // some commands are tested twice to see the cache in action
    let key_id = KeyId::from_str(&key_id).expect("CCCommand failed for KeyId");
    let commands = vec![
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0x1".to_string(),
            data_type: FheType::Ebool,
            no_compression: false,
            no_precompute_sns: true,
            key_id,
            context_id: None,
            batch_size: 1,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
        CCCommand::UserDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0x1".to_string(),
            data_type: FheType::Ebool,
            no_compression: false,
            no_precompute_sns: true,
            key_id,
            context_id: None,
            batch_size: 1,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0x6F".to_string(),
            data_type: FheType::Euint8,
            no_compression: true,
            no_precompute_sns: true,
            key_id,
            context_id: None,
            batch_size: 3,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0x6F".to_string(),
            data_type: FheType::Euint8,
            no_compression: false,
            no_precompute_sns: true,
            key_id,
            context_id: None,
            batch_size: 3,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0xFFFF".to_string(),
            data_type: FheType::Euint16,
            no_compression: false,
            no_precompute_sns: true,
            key_id,
            context_id: None,
            batch_size: 1,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0x96BF913158B2F39228DF1CA037D537E521CE14B95D225928E4E9B5305EC4592B"
                .to_string(),
            data_type: FheType::Euint256,
            no_compression: false,
            no_precompute_sns: true,
            key_id,
            context_id: None,
            batch_size: 1,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
        CCCommand::UserDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0xC958D835E4B1922CE9B13BAD322CF67D81CE14B95D225928E4E9B5305EC4592C"
                .to_string(),
            data_type: FheType::Euint256,
            no_compression: false,
            no_precompute_sns: true,
            key_id,
            context_id: None,
            batch_size: 1,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
        CCCommand::Encrypt(CipherParameters {
            to_encrypt: "0xC958D835E4B1922CE9B13BAD322CF67D8E06CDA1B9ECF0395689B5305EC4592D"
                .to_string(),
            data_type: FheType::Euint256,
            no_compression: false,
            no_precompute_sns: true,
            key_id,
            context_id: None,
            batch_size: 1,
            num_requests: 1,
            ciphertext_output_path: Some(ctxt_path.to_path_buf()),
        }),
        CCCommand::PublicDecrypt(CipherArguments::FromFile(CipherFile {
            input_path: ctxt_path.to_path_buf(),
            batch_size: 1,
            num_requests: 3,
        })),
        CCCommand::UserDecrypt(CipherArguments::FromFile(CipherFile {
            input_path: ctxt_path.to_path_buf(),
            batch_size: 1,
            num_requests: 3,
        })),
    ];

    let commands_for_sns_precompute = vec![
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0x1".to_string(),
            data_type: FheType::Ebool,
            no_compression: true,
            no_precompute_sns: false,
            key_id,
            context_id: None,
            batch_size: 2,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
        CCCommand::UserDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0x78".to_string(),
            data_type: FheType::Euint8,
            no_compression: true,
            no_precompute_sns: false,
            key_id,
            context_id: None,
            batch_size: 2,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
        CCCommand::UserDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0x1".to_string(),
            data_type: FheType::Ebool,
            no_compression: true,
            no_precompute_sns: false,
            key_id,
            context_id: None,
            batch_size: 1,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0x6F".to_string(),
            data_type: FheType::Euint8,
            no_compression: true,
            no_precompute_sns: false,
            key_id,
            context_id: None,
            batch_size: 1,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0xC958D835E4B1922CE9B13BAD322CF67D8E06CDA1B9ECF03956822D0D186F7820"
                .to_string(),
            data_type: FheType::Euint256,
            no_compression: true,
            no_precompute_sns: false,
            key_id,
            context_id: None,
            batch_size: 1,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
        CCCommand::UserDecrypt(CipherArguments::FromArgs(CipherParameters {
            to_encrypt: "0xC9BF913158B2F39228DF1CA037D537E521CE14B95D225928E4E9B5305EC4592F"
                .to_string(),
            data_type: FheType::Euint256,
            no_compression: true,
            no_precompute_sns: false,
            key_id,
            context_id: None,
            batch_size: 1,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
        CCCommand::Encrypt(CipherParameters {
            to_encrypt: "0xC958D835E4B1922CE9B13CA037D537E521CE14B95D225928E4E9B5305EC4592E"
                .to_string(),
            data_type: FheType::Euint256,
            no_compression: true,
            no_precompute_sns: false,
            key_id,
            context_id: None,
            batch_size: 1,
            num_requests: 1,
            ciphertext_output_path: Some(ctxt_with_sns_path.to_path_buf()),
        }),
        CCCommand::PublicDecrypt(CipherArguments::FromFile(CipherFile {
            input_path: ctxt_with_sns_path.to_path_buf(),
            batch_size: 1,
            num_requests: 3,
        })),
        CCCommand::UserDecrypt(CipherArguments::FromFile(CipherFile {
            input_path: ctxt_with_sns_path.to_path_buf(),
            batch_size: 1,
            num_requests: 3,
        })),
    ];

    test_template(
        ctx,
        [commands, commands_for_sns_precompute].concat(),
        keys_folder,
    )
    .await
}

fn config_path_from_context(ctx: &impl DockerComposeManager) -> String {
    ctx.root_path()
        .join(ctx.config_path())
        .to_str()
        .unwrap()
        .to_string()
}

#[test_context(DockerComposeThresholdTest)]
#[tokio::test]
#[serial(docker)]
async fn nightly_tests_threshold_sequential_preproc_keygen(ctx: &DockerComposeThresholdTest) {
    init_testing();
    let temp_dir = tempfile::tempdir().unwrap();
    let keys_folder = temp_dir.path();
    let config_path = config_path_from_context(ctx);
    let key_id_1 = real_preproc_and_keygen(&config_path, keys_folder, None, None).await;
    let key_id_2 = real_preproc_and_keygen(&config_path, keys_folder, None, None).await;
    assert_ne!(key_id_1, key_id_2);
}

#[test_context(DockerComposeThresholdTest)]
#[tokio::test]
#[serial(docker)]
async fn test_threshold_concurrent_preproc_keygen(ctx: &DockerComposeThresholdTest) {
    init_testing();
    let temp_dir = tempfile::tempdir().unwrap();
    let keys_folder = temp_dir.path();
    let config_path = config_path_from_context(ctx);
    let _ = join_all([
        real_preproc_and_keygen(&config_path, keys_folder, None, None),
        real_preproc_and_keygen(&config_path, keys_folder, None, None),
    ])
    .await;
}

#[test_context(DockerComposeThresholdDefault)]
#[tokio::test]
#[serial(docker)]
async fn nightly_tests_threshold_sequential_crs(ctx: &DockerComposeThresholdDefault) {
    init_testing();
    let temp_dir = tempfile::tempdir().unwrap();
    let keys_folder = temp_dir.path();
    let crs_id_1 = crs_gen(ctx, keys_folder, false).await;
    let crs_id_2 = crs_gen(ctx, keys_folder, false).await;
    assert_ne!(crs_id_1, crs_id_2);
}

#[test_context(DockerComposeThresholdDefault)]
#[tokio::test]
#[serial(docker)]
async fn test_threshold_concurrent_crs(ctx: &DockerComposeThresholdDefault) {
    init_testing();
    let temp_dir = tempfile::tempdir().unwrap();
    let keys_folder = temp_dir.path();
    let res = join_all([
        crs_gen(ctx, keys_folder, false),
        crs_gen(ctx, keys_folder, false),
    ])
    .await;
    assert_ne!(res[0], res[1]);
}

// Test restore without custodians
#[test_context(DockerComposeThresholdTest)]
#[tokio::test]
#[serial(docker)]
async fn test_threshold_restore_from_backup(ctx: &DockerComposeThresholdTest) {
    init_testing();
    let temp_dir = tempfile::tempdir().unwrap();
    let keys_folder = temp_dir.path();
    let _crs_id = crs_gen(ctx, keys_folder, true).await;
    let _ = restore_from_backup(ctx, keys_folder).await;
    // We don't have endpoints that allow us to purge the generate material within the docker images
    // so we can here only test that the end points are alive and acting as expected, rather than validating that
    // data gets restored. Instead tests in the client within core have tests for validating this
}

#[test_context(DockerComposeThresholdCustodianTest)]
#[tokio::test]
#[serial(docker)]
async fn test_threshold_custodian_backup(ctx: &DockerComposeThresholdCustodianTest) {
    init_testing();
    let amount_custodians = 5;
    let custodian_threshold = 2;
    let amount_operators = 4; // TODO should not be hardcoded but not sure how I can get it easily
    let temp_dir = tempfile::tempdir().unwrap();
    let temp_path = temp_dir.path();
    let (seeds, setup_msg_paths) =
        generate_custodian_keys_to_file(temp_path, amount_custodians, true).await;
    let cus_backup_id =
        new_custodian_context(ctx, temp_path, custodian_threshold, setup_msg_paths).await;
    // Paths to where the results of the backup init will be stored
    let mut operator_recovery_resp_paths = Vec::new();
    for cur_op_idx in 1..=amount_operators {
        let cur_resp_path = temp_path
            .join("CUSTODIAN")
            .join("recovery")
            .join(&cus_backup_id)
            .join(cur_op_idx.to_string());
        // Ensure the dir exists locally
        assert!(create_dir_all(cur_resp_path.parent().unwrap()).is_ok());
        operator_recovery_resp_paths.push(cur_resp_path);
    }
    let init_backup_id =
        custodian_backup_init(ctx, temp_path, operator_recovery_resp_paths.clone()).await;
    assert_eq!(cus_backup_id, init_backup_id);
    let recovery_output_paths = custodian_reencrypt(
        temp_path,
        amount_operators,
        amount_custodians,
        init_backup_id.try_into().unwrap(),
        &seeds,
        &operator_recovery_resp_paths,
    )
    .await;
    let recovery_backup_id = custodian_backup_recovery(
        ctx,
        temp_path,
        recovery_output_paths,
        RequestId::from_str(&cus_backup_id).unwrap(),
    )
    .await;
    assert_eq!(cus_backup_id, recovery_backup_id);
    let _ = restore_from_backup(ctx, temp_path).await;
    // Observe that we cannot modify the state of the servers, so we cannot really validate recovery.
    // However we are testing this in the service/client. Hence this tests is mainly to ensure that the outer
    // end points and content returned from the KMS to the custodians work as expected.
}

#[test_context(DockerComposeThresholdTest)]
#[tokio::test]
#[serial(docker)]
async fn test_threshold_mpc_context_switch(ctx: &DockerComposeThresholdTest) {
    init_testing();
    let temp_dir = tempfile::tempdir().unwrap();
    let test_path = temp_dir.path();
    let context_path = temp_dir.path().join("mpc_context.bin");
    let config_path = ctx.root_path().join(ctx.config_path());
    // do insecure keygen
    let key_id = insecure_key_gen(ctx, test_path).await;

    // create and store mpc context
    let context_id =
        ContextId::from_str("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1222222222")
            .unwrap();
    store_mpc_context_in_file(&context_path, &config_path, context_id).await;

    // do the context switch
    new_mpc_context(&context_path, &config_path, test_path).await;

    // try to do ddec in the new context
    let ddec_command = CCCommand::PublicDecrypt(CipherArguments::FromArgs(CipherParameters {
        to_encrypt: "0x1".to_string(),
        data_type: FheType::Ebool,
        no_compression: false,
        no_precompute_sns: true,
        key_id: KeyId::from_str(&key_id).unwrap(),
        context_id: Some(context_id),
        batch_size: 1,
        num_requests: 1,
        ciphertext_output_path: None,
    }));
    test_template(ctx, vec![ddec_command], test_path).await;
}

// Start from mpc parties that are not initialized (no prss or context).
#[test_context(DockerComposeThresholdTestNoInit)]
#[tokio::test]
#[serial(docker)]
async fn test_threshold_mpc_context_init(ctx: &DockerComposeThresholdTestNoInit) {
    init_testing();
    let temp_dir = tempfile::tempdir().unwrap();
    let test_path = temp_dir.path();
    let context_path = temp_dir.path().join("mpc_context.bin");
    let config_path = ctx.root_path().join(ctx.config_path());

    // create and store mpc context
    let context_id =
        ContextId::from_str("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1222223333")
            .unwrap();
    store_mpc_context_in_file(&context_path, &config_path, context_id).await;

    // create the new context
    new_mpc_context(&context_path, &config_path, test_path).await;

    // create PRSS
    let epoch_id =
        EpochId::from_str("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1222224444")
            .unwrap();
    new_prss(context_id, epoch_id, &config_path, test_path).await;

    // do preproc and keygen (which should use the prss)
    let _ = real_preproc_and_keygen(
        config_path.to_str().unwrap(),
        test_path,
        Some(context_id),
        Some(epoch_id),
    )
    .await;
}

#[test_context(DockerComposeThresholdTestNoInitSixParty)]
#[tokio::test]
#[serial(docker)]
async fn test_threshold_mpc_context_switch_6(ctx: &DockerComposeThresholdTestNoInitSixParty) {
    init_testing();
    let config_path = ctx.root_path().join(ctx.config_path());
    let alternative_config_path = ctx.root_path().join(ctx.alternative_config_path());

    // first mpc context with parties 1, 2, 3, 4
    // note that this is defined by the normal config path
    {
        let temp_dir = tempfile::tempdir().unwrap();
        let test_path = temp_dir.path();
        let context_path = temp_dir.path().join("mpc_context.bin");

        // create and store mpc context
        let context_id =
            ContextId::from_str("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1222223333")
                .unwrap();
        store_mpc_context_in_file(&context_path, &config_path, context_id).await;

        // create the new context
        new_mpc_context(&context_path, &config_path, test_path).await;

        // create PRSS
        let epoch_id =
            EpochId::from_str("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1222224444")
                .unwrap();
        new_prss(context_id, epoch_id, &config_path, test_path).await;
    }

    // second mpc context with parties 5, 6, 3, 4
    {
        let temp_dir = tempfile::tempdir().unwrap();
        let test_path = temp_dir.path();
        let context_path = temp_dir.path().join("mpc_context.bin");

        // create and store mpc context
        let context_id =
            ContextId::from_str("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1222225555")
                .unwrap();
        store_mpc_context_in_file(&context_path, &alternative_config_path, context_id).await;

        // create the new context
        new_mpc_context(&context_path, &alternative_config_path, test_path).await;

        // create PRSS
        let epoch_id =
            EpochId::from_str("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1222226666")
                .unwrap();
        new_prss(context_id, epoch_id, &alternative_config_path, test_path).await;

        // do preproc and keygen (which should use the prss)
        let _ = real_preproc_and_keygen(
            alternative_config_path.to_str().unwrap(),
            test_path,
            Some(context_id),
            Some(epoch_id),
        )
        .await;

        // delete context
        destroy_mpc_context(&context_id, &alternative_config_path, test_path).await;

        // check whether the context is deleted by running keygen, which should fail
        let err = real_preproc(
            alternative_config_path.to_str().unwrap(),
            test_path,
            Some(context_id),
            Some(epoch_id),
        )
        .await
        .unwrap_err();
        assert!(err
            .to_string()
            .contains(&format!("context {context_id} not found")));
    }
}

#[test_context(DockerComposeThresholdTestNoInit)]
#[tokio::test]
#[serial(docker)]
async fn test_threshold_reshare(ctx: &DockerComposeThresholdTestNoInit) {
    init_testing();
    let temp_dir = tempfile::tempdir().unwrap();
    let test_path = temp_dir.path();
    let context_path = temp_dir.path().join("mpc_context.bin");
    let config_path = ctx.root_path().join(ctx.config_path());

    // create and store mpc context
    let context_id =
        ContextId::from_str("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1222225555")
            .unwrap();
    store_mpc_context_in_file(&context_path, &config_path, context_id).await;

    // create the new context
    new_mpc_context(&context_path, &config_path, test_path).await;

    // create PRSS
    let epoch_id =
        EpochId::from_str("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1222226666")
            .unwrap();
    new_prss(context_id, epoch_id, &config_path, test_path).await;

    // do preproc and keygen (which should use the prss)
    let (key_id, preproc_id) = real_preproc_and_keygen(
        config_path.to_str().unwrap(),
        test_path,
        Some(context_id),
        Some(epoch_id),
    )
    .await;

    // download the key materials
    let cc_conf: CoreClientConfig = observability::conf::Settings::builder()
        .path(config_path.to_str().unwrap())
        .env_prefix("CORE_CLIENT")
        .build()
        .init_conf()
        .unwrap();

    let ids = fetch_public_elements(
        &key_id,
        &[PubDataType::ServerKey, PubDataType::PublicKey],
        &cc_conf,
        test_path,
        false,
    )
    .await
    .unwrap();

    // read the key materials from file
    let key_id = RequestId::from_str(&key_id).unwrap();
    let object_folder = &cc_conf.cores[ids[0] - 1].object_folder;
    let public_key = load_pk_from_pub_storage(Some(test_path), &key_id, Some(object_folder)).await;
    let server_key: tfhe::ServerKey = load_material_from_pub_storage(
        Some(test_path),
        &key_id,
        PubDataType::ServerKey,
        Some(object_folder),
    )
    .await;

    // compute the digests
    let server_key_digest =
        hex::encode(safe_serialize_hash_element_versioned(&DSEP_PUBDATA_KEY, &server_key).unwrap());
    let public_key_digest =
        hex::encode(safe_serialize_hash_element_versioned(&DSEP_PUBDATA_KEY, &public_key).unwrap());

    // create the resharing request
    let config = CmdConfig {
        file_conf: Some(String::from(config_path.to_str().unwrap())),
        command: CCCommand::Reshare(ReshareParameters {
            key_id,
            preproc_id: RequestId::from_str(&preproc_id).unwrap(),
            from_context_id: Some(context_id),
            from_epoch_id: Some(epoch_id),
            server_key_digest,
            public_key_digest,
        }),
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
        download_all: false,
    };

    println!("Doing resharing");
    let resharing_result = execute_cmd(&config, test_path).await.unwrap();

    println!("Resharing result: {:?}", resharing_result);
    assert_eq!(resharing_result.len(), 2);

    // the second element should be the key id
    assert_eq!(resharing_result[1].0.unwrap(), key_id);
}

///////// FULL GEN TESTS//////////
//////////////////////////////////

#[test_context(DockerComposeThresholdDefault)]
#[tokio::test]
#[serial(docker)]
async fn full_gen_tests_default_threshold_sequential_preproc_keygen(
    ctx: &DockerComposeThresholdDefault,
) {
    init_testing();
    let temp_dir = tempfile::tempdir().unwrap();
    let keys_folder = temp_dir.path();
    let config_path = config_path_from_context(ctx);
    let key_id_1 = real_preproc_and_keygen(&config_path, keys_folder, None, None).await;
    let key_id_2 = real_preproc_and_keygen(&config_path, keys_folder, None, None).await;
    assert_ne!(key_id_1, key_id_2);
}

#[test_context(DockerComposeThresholdDefault)]
#[tokio::test]
#[serial(docker)]
async fn full_gen_tests_default_threshold_sequential_crs(ctx: &DockerComposeThresholdDefault) {
    init_testing();
    let temp_dir = tempfile::tempdir().unwrap();
    let keys_folder = temp_dir.path();
    let crs_id_1 = crs_gen(ctx, keys_folder, false).await;
    let crs_id_2 = crs_gen(ctx, keys_folder, false).await;
    assert_ne!(crs_id_1, crs_id_2);
}

use aes_prng::AesRng;
use cc_tests_utils::{DockerCompose, KMSMode};
use kms_core_client::*;
use kms_grpc::rpc_types::PubDataType;
use kms_grpc::KeyId;
use kms_grpc::RequestId;
use kms_lib::backup::custodian::Custodian;
use kms_lib::backup::operator::InternalRecoveryRequest;
use kms_lib::backup::seed_phrase::custodian_from_seed_phrase;
use kms_lib::backup::seed_phrase::seed_phrase_from_rng;
use kms_lib::consts::SIGNING_KEY_ID;
use kms_lib::cryptography::backup_pke::BackupPrivateKey;
use kms_lib::cryptography::internal_crypto_types::PrivateSigKey;
use kms_lib::util::file_handling::safe_read_element_versioned;
use kms_lib::util::file_handling::safe_write_element_versioned;
use kms_lib::vault::storage::file::FileStorage;
use kms_lib::vault::storage::StorageReader;
use kms_lib::vault::storage::StorageType;
use rand::SeedableRng;
use serial_test::serial;
use std::path::Path;
use std::path::PathBuf;
use std::path::MAIN_SEPARATOR;
use std::str::FromStr;
use std::string::String;
use test_context::futures::future::join_all;
use test_context::{test_context, AsyncTestContext};
use threshold_fhe::execution::runtime::party::Role;

// IMPORTANT: These integration tests require Docker running and images build.
// You can build the images by running the following commands from the root of the repo:
// ```
// docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml build
// docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-threshold-custodian.yml build
// docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-centralized.yml build
// docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-centralized-custodian.yml build
// ```
// Any issue might be related to the fact that some obsolete Docker images exist.

trait DockerComposeContext {
    fn root_path(&self) -> PathBuf;
    fn config_path(&self) -> &str;
}

struct DockerComposeCentralizedContext {
    pub cmd: DockerCompose,
}

impl DockerComposeContext for DockerComposeCentralizedContext {
    fn root_path(&self) -> PathBuf {
        self.cmd.cmd.root_path.clone()
    }

    fn config_path(&self) -> &str {
        "core-client/config/client_local_centralized.toml"
    }
}

impl AsyncTestContext for DockerComposeCentralizedContext {
    async fn setup() -> Self {
        DockerComposeCentralizedContext {
            cmd: DockerCompose::new(KMSMode::Centralized),
        }
    }

    async fn teardown(self) {
        drop(self.cmd);
    }
}

struct DockerComposeCentralizedCustodianContext {
    pub cmd: DockerCompose,
}

impl DockerComposeContext for DockerComposeCentralizedCustodianContext {
    fn root_path(&self) -> PathBuf {
        self.cmd.cmd.root_path.clone()
    }

    fn config_path(&self) -> &str {
        "core-client/config/client_local_centralized.toml"
    }
}

impl AsyncTestContext for DockerComposeCentralizedCustodianContext {
    async fn setup() -> Self {
        DockerComposeCentralizedCustodianContext {
            cmd: DockerCompose::new(KMSMode::CentralizedCustodian),
        }
    }

    async fn teardown(self) {
        drop(self.cmd);
    }
}

struct DockerComposeThresholdContextDefault {
    pub cmd: DockerCompose,
}

impl DockerComposeContext for DockerComposeThresholdContextDefault {
    fn root_path(&self) -> PathBuf {
        self.cmd.cmd.root_path.clone()
    }

    fn config_path(&self) -> &str {
        "core-client/config/client_local_threshold.toml"
    }
}

impl AsyncTestContext for DockerComposeThresholdContextDefault {
    async fn setup() -> Self {
        Self {
            cmd: DockerCompose::new(KMSMode::ThresholdDefaultParameter),
        }
    }

    async fn teardown(self) {
        drop(self.cmd);
    }
}

struct DockerComposeThresholdContextTest {
    pub cmd: DockerCompose,
}

impl DockerComposeContext for DockerComposeThresholdContextTest {
    fn root_path(&self) -> PathBuf {
        self.cmd.cmd.root_path.clone()
    }

    fn config_path(&self) -> &str {
        "core-client/config/client_local_threshold.toml"
    }
}

impl AsyncTestContext for DockerComposeThresholdContextTest {
    async fn setup() -> Self {
        Self {
            cmd: DockerCompose::new(KMSMode::ThresholdTestParameter),
        }
    }

    async fn teardown(self) {
        drop(self.cmd);
    }
}
struct DockerComposeThresholdCustodianContextTest {
    pub cmd: DockerCompose,
}

impl DockerComposeContext for DockerComposeThresholdCustodianContextTest {
    fn root_path(&self) -> PathBuf {
        self.cmd.cmd.root_path.clone()
    }

    fn config_path(&self) -> &str {
        "core-client/config/client_local_threshold.toml"
    }
}

impl AsyncTestContext for DockerComposeThresholdCustodianContextTest {
    async fn setup() -> Self {
        Self {
            cmd: DockerCompose::new(KMSMode::ThresholdCustodianTestParameter),
        }
    }

    async fn teardown(self) {
        drop(self.cmd);
    }
}

async fn insecure_key_gen<T: DockerComposeContext>(ctx: &T) -> String {
    let path_to_config = ctx.root_path().join(ctx.config_path());

    let keys_folder: &Path = Path::new("tests/data/keys");

    let config = CmdConfig {
        file_conf: Some(String::from(path_to_config.to_str().unwrap())),
        command: CCCommand::InsecureKeyGen(InsecureKeyGenParameters {
            shared_args: SharedKeyGenParameters::default(),
        }),
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
    };
    println!("Doing insecure key-gen");
    let key_gen_results = execute_cmd(&config, keys_folder).await.unwrap();
    println!("Insecure key-gen done");

    assert_eq!(key_gen_results.len(), 1);
    let key_id = match key_gen_results.first().unwrap() {
        (Some(value), _) => value,
        _ => panic!("Error doing insecure keygen"),
    };

    key_id.to_string()
}

async fn key_and_crs_gen<T: DockerComposeContext>(
    ctx: &mut T,
    insecure_crs_gen: bool,
) -> (String, String) {
    let key_id = insecure_key_gen(ctx).await;
    let crs_id = crs_gen(ctx, insecure_crs_gen).await;
    (key_id, crs_id)
}

async fn crs_gen<T: DockerComposeContext>(ctx: &T, insecure_crs_gen: bool) -> String {
    let path_to_config = ctx.root_path().join(ctx.config_path());

    let keys_folder: &Path = Path::new("tests/data/keys");

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
    };

    println!("Doing CRS-gen");
    let crs_gen_results = execute_cmd(&config, keys_folder).await.unwrap();
    println!("CRS-gen done");
    assert_eq!(crs_gen_results.len(), 1);
    let crs_id = match crs_gen_results.first().unwrap() {
        (Some(value), _) => value,
        _ => panic!("Error doing keygen"),
    };

    crs_id.to_string()
}

async fn real_preproc_and_keygen(config_path: &str) -> String {
    let keys_folder: &Path = Path::new("tests/data/keys");

    let config = CmdConfig {
        file_conf: Some(config_path.to_string()),
        command: CCCommand::PreprocKeyGen(NoParameters {}),
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
    };
    println!("Doing preprocessing");
    let mut preproc_result = execute_cmd(&config, keys_folder).await.unwrap();
    assert_eq!(preproc_result.len(), 1);
    let (preproc_id, _) = preproc_result.pop().unwrap();
    println!("Preprocessing done with ID {preproc_id:?}");

    let config = CmdConfig {
        file_conf: Some(config_path.to_string()),
        command: CCCommand::KeyGen(KeyGenParameters {
            preproc_id: preproc_id.unwrap(),
            shared_args: SharedKeyGenParameters::default(),
        }),
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
    };
    println!("Doing key-gen");
    let key_gen_results = execute_cmd(&config, keys_folder).await.unwrap();
    println!("Key-gen done");
    assert_eq!(key_gen_results.len(), 1);

    let key_id = match key_gen_results.first().unwrap() {
        (Some(value), _) => value,
        _ => panic!("Error doing keygen"),
    };

    key_id.to_string()
}

async fn backup_restore<T: DockerComposeContext>(ctx: &T) -> String {
    let path_to_config = ctx.root_path().join(ctx.config_path());

    let keys_folder: &Path = Path::new("tests/data/keys");

    let init_command = CCCommand::BackupRestore(NoParameters {});
    let init_config = CmdConfig {
        file_conf: Some(String::from(path_to_config.to_str().unwrap())),
        command: init_command,
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
    };

    println!("Doing backup restore");
    let backup_restore_results = execute_cmd(&init_config, keys_folder).await.unwrap();
    println!("Backup restore done");
    assert_eq!(backup_restore_results.len(), 1);
    // No backup ID is returned since backup_restore can also be used without custodians
    assert_eq!(backup_restore_results.first().unwrap().0, None);
    "".to_string()
}

async fn new_custodian_context<T: DockerComposeContext>(
    ctx: &T,
    custodian_threshold: u32,
    setup_msg_paths: Vec<PathBuf>,
) -> String {
    let path_to_config = ctx.root_path().join(ctx.config_path());

    let keys_folder: &Path = Path::new("tests/data/keys");
    let command = CCCommand::NewCustodianContext(NewCustodianContextParameters {
        threshold: custodian_threshold,
        setup_msg_path: setup_msg_paths,
    });
    let init_config = CmdConfig {
        file_conf: Some(String::from(path_to_config.to_str().unwrap())),
        command,
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
    };

    println!("Doing new custodian context");
    let backup_init_results = execute_cmd(&init_config, keys_folder).await.unwrap();
    println!("New custodian context done");
    assert_eq!(backup_init_results.len(), 1);
    let res_id = match backup_init_results.first().unwrap() {
        (Some(value), _) => value,
        _ => panic!("Error doing new custodian context"),
    };

    res_id.to_string()
}

async fn custodian_backup_init<T: DockerComposeContext>(ctx: &T) -> String {
    let path_to_config = ctx.root_path().join(ctx.config_path());

    let keys_folder: &Path = Path::new("tests/data/keys");

    let init_command = CCCommand::CustodianRecoveryInit(NoParameters {}); //todo path should be given as arugment
    let init_config = CmdConfig {
        file_conf: Some(String::from(path_to_config.to_str().unwrap())),
        command: init_command,
        logs: true,
        max_iter: 200,
        expect_all_responses: true,
    };

    println!("Doing backup init");
    let backup_init_results = execute_cmd(&init_config, keys_folder).await.unwrap();
    println!("Backup init done");
    assert_eq!(backup_init_results.len(), 1);
    let res_id = match backup_init_results.first().unwrap() {
        (Some(value), _) => value,
        _ => panic!("Error doing backup init"),
    };

    res_id.to_string()
}

async fn custodian_backup_recovery<T: DockerComposeContext>(
    ctx: &T,
    rng: &mut AesRng,
    amount_operators: usize,
    backup_id: RequestId,
    seeds: Vec<String>,
) -> String {
    let path_to_config = ctx.root_path().join(ctx.config_path());
    let keys_folder: &Path = Path::new("tests/data/keys");
    let mut custodian_recovery_outputs = Vec::new();
    for op_idx in 1..=amount_operators {
        let pub_store = FileStorage::new(
            Some(keys_folder),
            StorageType::PUB,
            Some(Role::indexed_from_one(op_idx)),
        )
        .unwrap();
        let verf_key = pub_store
            .read_data(&SIGNING_KEY_ID, &PubDataType::VerfKey.to_string())
            .await
            .unwrap();

        let path = keys_folder
            .join("CUSTODIAN")
            .join("recovery")
            .join(format!("{}{MAIN_SEPARATOR}{}", backup_id, op_idx));
        let cur_rec_req: InternalRecoveryRequest = safe_read_element_versioned(path).await.unwrap();
        assert_eq!(cur_rec_req.operator_role(), Role::indexed_from_one(op_idx));
        for cus_idx in 1..=seeds.len() {
            let custodian =
                custodian_from_seed_phrase(&seeds[cus_idx - 1], Role::indexed_from_one(cus_idx))
                    .expect("Failed to reconstruct custodians");
            let cur_rec_output = custodian
                .verify_reencrypt(
                    rng,
                    cur_rec_req.ciphertexts()[&Role::indexed_from_one(cus_idx)],
                    &verf_key,
                    cur_rec_req.encryption_key(),
                    cur_rec_req.backup_id(),
                    cur_rec_req.operator_role(),
                )
                .unwrap();
            let cur_path = keys_folder
                .join("CUSTODIAN")
                .join("response")
                .join(format!("recovery-response-{}-{}", op_idx, cus_idx,));
            safe_write_element_versioned(&cur_path, &cur_rec_output)
                .await
                .unwrap();
            custodian_recovery_outputs.push(cur_path);
        }
    }

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
    };

    println!("Doing backup recovery");
    let backup_recovery_results = execute_cmd(&init_config, keys_folder).await.unwrap();
    println!("Backup init recovery");
    assert_eq!(backup_recovery_results.len(), 1);
    let res_id = match backup_recovery_results.first().unwrap() {
        (Some(value), _) => value,
        _ => panic!("Error doing backup recovery"),
    };

    res_id.to_string()
}

async fn test_template<T: DockerComposeContext>(ctx: &mut T, commands: Vec<CCCommand>) {
    let path_to_config = ctx.root_path().join(ctx.config_path());

    let keys_folder: &Path = Path::new("tests/data/keys");

    for command in commands {
        let config = CmdConfig {
            file_conf: Some(String::from(path_to_config.to_str().unwrap())),
            command: command.clone(),
            logs: true,
            max_iter: 500,
            expect_all_responses: true,
        };

        let results = execute_cmd(&config, keys_folder).await.unwrap();

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
            };

            //We query result on a single request id, so should get a single result
            let mut results_bis = execute_cmd(&config, keys_folder).await.unwrap();
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

#[test_context(DockerComposeCentralizedContext)]
#[tokio::test]
#[serial(docker)]
async fn test_centralized_secure(ctx: &mut DockerComposeCentralizedContext) {
    init_testing();
    let (key_id, _crs_id) = key_and_crs_gen(ctx, false).await;
    integration_test_commands(ctx, key_id).await;
}

#[test_context(DockerComposeCentralizedContext)]
#[tokio::test]
#[serial(docker)]
async fn test_centralized_insecure(ctx: &mut DockerComposeCentralizedContext) {
    init_testing();
    let (key_id, _crs_id) = key_and_crs_gen(ctx, true).await;
    integration_test_commands(ctx, key_id).await;
}

// Test restore without custodians
#[test_context(DockerComposeCentralizedContext)]
#[tokio::test]
#[serial(docker)]
async fn test_centralized_backup_restore(ctx: &DockerComposeCentralizedContext) {
    init_testing();
    let _crs_id = crs_gen(ctx, true).await;
    let _ = backup_restore(ctx).await;
    // Observe that we cannot modify the state of the servers, so we cannot really validate the restore.
    // However we are testing this in the service/client. Hence this tests is mainly to ensure that the outer
    // end points and content returned from the KMS to the custodians work as expected.
}

#[test_context(DockerComposeCentralizedCustodianContext)]
#[tokio::test]
#[serial(docker)]
async fn test_centrals_custodian_backup(ctx: &DockerComposeCentralizedCustodianContext) {
    init_testing();
    // We don't have endpoints that allow us to purge the generate material within the docker images
    // so we can here only test that the end points are alive and acting as expected, rather than validating that
    // data gets restored. Instead test in the client within core have tests for validating this
    // First setup context, then back up init, use the result with the custodian client and then call recovery
    // Start by setting up the custodians
    let amount_custodians = 5;
    let custodian_threshold = 2;
    let amount_operators = 4; // TODO should not be hardcoded but not sure how I can get it easily
    let mut rng = AesRng::seed_from_u64(41);
    let keys_folder: &Path = Path::new("tests/data/keys");
    let (seeds, setup_msg_paths) =
        generate_custodian_keys_to_file(&mut rng, keys_folder, amount_custodians).await;
    let cus_backup_id = new_custodian_context(ctx, custodian_threshold, setup_msg_paths).await;
    let init_backup_id = custodian_backup_init(ctx).await;
    assert_eq!(cus_backup_id, init_backup_id);
    let recovery_backup_id = custodian_backup_recovery(
        ctx,
        &mut rng,
        amount_operators,
        RequestId::from_str(&cus_backup_id).unwrap(),
        seeds,
    )
    .await;
    assert_eq!(cus_backup_id, recovery_backup_id);
    let _ = backup_restore(ctx).await;
    // Observe that we cannot modify the state of the servers, so we cannot really validate recovery.
    // However we are testing this in the service/client. Hence this tests is mainly to ensure that the outer
    // end points and content returned from the KMS to the custodians work as expected.
}

#[ignore]
#[test_context(DockerComposeThresholdContextDefault)]
#[tokio::test]
#[serial(docker)]
async fn test_threshold_secure(ctx: &mut DockerComposeThresholdContextDefault) {
    init_testing();
    let (key_id, _crs_id) = key_and_crs_gen(ctx, false).await;
    integration_test_commands(ctx, key_id).await;
}

#[test_context(DockerComposeThresholdContextDefault)]
#[tokio::test]
#[serial(docker)]
async fn test_threshold_insecure(ctx: &mut DockerComposeThresholdContextDefault) {
    init_testing();
    let (key_id, _crs_id) = key_and_crs_gen(ctx, true).await;
    integration_test_commands(ctx, key_id).await;
}

async fn integration_test_commands<T: DockerComposeContext>(ctx: &mut T, key_id: String) {
    let ctxt_path: &Path = Path::new("tests/data/test_encrypt_cipher.txt");
    let ctxt_with_sns_path: &Path = Path::new("tests/data/test_encrypt_cipher_with_sns.txt");
    // some commands are tested twice to see the cache in action
    let key_id = KeyId::from_str(&key_id).expect("CCCommand failed for KeyId");
    let commands = vec![
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(
            CipherParameters {
            to_encrypt: "0x1".to_string(),
            data_type: FheType::Ebool,
            compression: true,
            precompute_sns: false,
            key_id,
            batch_size: 1,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
        CCCommand::UserDecrypt(CipherArguments::FromArgs(
            CipherParameters{
            to_encrypt: "0x1".to_string(),
            data_type: FheType::Ebool,
            compression: true,
            precompute_sns: false,
            key_id,
            batch_size: 1,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(
            CipherParameters{
            to_encrypt: "0x6F".to_string(),
            data_type: FheType::Euint8,
            compression: false,
            precompute_sns: false,
            key_id,
            batch_size: 3,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(
            CipherParameters{
            to_encrypt: "0x6F".to_string(),
            data_type: FheType::Euint8,
            compression: true,
            precompute_sns: false,
            key_id,
            batch_size: 3,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(
            CipherParameters{
            to_encrypt: "0xFFFF".to_string(),
            data_type: FheType::Euint16,
            compression: true,
            precompute_sns: false,
            key_id,
            batch_size: 1,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(
            CipherParameters{
            to_encrypt: "0xC958D835E4B1922CE9B13BAD322CF67D8E06CDA1B9ECF03956822D0D186F78D196BF913158B2F39228DF1CA037D537E521CE14B95D225928E4E9B5305EC45921".to_string(),
            data_type: FheType::Euint1024,
            compression: true,
            precompute_sns: false,
            key_id,
            batch_size: 1,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
        CCCommand::UserDecrypt(CipherArguments::FromArgs(
            CipherParameters{
            to_encrypt: "0xC958D835E4B1922CE9B13BAD322CF67D8E06CDA1B9ECF03956822D0D186F78D196BF913158B2F39228DF1CA037D537E521CE14B95D225928E4E9B5305EC45921".to_string(),
            data_type: FheType::Euint1024,
            compression: true,
            precompute_sns: false,
            key_id,
            batch_size: 1,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
        CCCommand::Encrypt(
            CipherParameters{
                to_encrypt: "0xC958D835E4B1922CE9B13BAD322CF67D8E06CDA1B9ECF03956822D0D186F78D196BF913158B2F39228DF1CA037D537E521CE14B95D225928E4E9B5305EC45921".to_string(),
                data_type: FheType::Euint1024,
                compression: true,
                precompute_sns: false,
                key_id,
                batch_size: 1,
                num_requests: 1,
                ciphertext_output_path: Some(ctxt_path.to_path_buf()),
            }
        ),
        CCCommand::PublicDecrypt(CipherArguments::FromFile(
            CipherFile {
                input_path: ctxt_path.to_path_buf(),
                batch_size: 1,
                num_requests: 3,
        })),
        CCCommand::UserDecrypt(CipherArguments::FromFile(
            CipherFile {
                input_path: ctxt_path.to_path_buf(),
                batch_size: 1,
                num_requests: 3,
        })),
    ];

    let commands_for_sns_precompute = vec![
            CCCommand::PublicDecrypt(CipherArguments::FromArgs(
            CipherParameters{
            to_encrypt: "0x1".to_string(),
            data_type: FheType::Ebool,
            compression: false,
            precompute_sns: true,
            key_id,
            batch_size: 2,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
        CCCommand::UserDecrypt(CipherArguments::FromArgs(
            CipherParameters{
            to_encrypt: "0x78".to_string(),
            data_type: FheType::Euint8,
            compression: false,
            precompute_sns: true,
            key_id,
            batch_size: 2,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
        CCCommand::UserDecrypt(CipherArguments::FromArgs(
            CipherParameters{
            to_encrypt: "0x1".to_string(),
            data_type: FheType::Ebool,
            compression: false,
            precompute_sns: true,
            key_id,
            batch_size: 1,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(
            CipherParameters{
            to_encrypt: "0x6F".to_string(),
            data_type: FheType::Euint8,
            compression: false,
            precompute_sns: true,
            key_id,
            batch_size: 1,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
        CCCommand::PublicDecrypt(CipherArguments::FromArgs(
            CipherParameters{
            to_encrypt: "0xC958D835E4B1922CE9B13BAD322CF67D8E06CDA1B9ECF03956822D0D186F78D196BF913158B2F39228DF1CA037D537E521CE14B95D225928E4E9B5305EC45921".to_string(),
            data_type: FheType::Euint1024,
            compression: false,
            precompute_sns: true,
            key_id,
            batch_size: 1,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
        CCCommand::UserDecrypt(CipherArguments::FromArgs(
            CipherParameters{
            to_encrypt: "0xC958D835E4B1922CE9B13BAD322CF67D8E06CDA1B9ECF03956822D0D186F78D196BF913158B2F39228DF1CA037D537E521CE14B95D225928E4E9B5305EC45921".to_string(),
            data_type: FheType::Euint1024,
            compression: false,
            precompute_sns: true,
            key_id,
            batch_size: 1,
            num_requests: 1,
            ciphertext_output_path: None,
        })),
        CCCommand::Encrypt(
            CipherParameters{
                to_encrypt: "0xC958D835E4B1922CE9B13BAD322CF67D8E06CDA1B9ECF03956822D0D186F78D196BF913158B2F39228DF1CA037D537E521CE14B95D225928E4E9B5305EC45921".to_string(),
                data_type: FheType::Euint1024,
                compression: false,
                precompute_sns: true,
                key_id,
                batch_size: 1,
            num_requests: 1,
                ciphertext_output_path: Some(ctxt_with_sns_path.to_path_buf()),
            }
        ),
        CCCommand::PublicDecrypt(CipherArguments::FromFile(
            CipherFile {
                input_path: ctxt_with_sns_path.to_path_buf(),
                batch_size: 1,
                num_requests: 3,
        })),
        CCCommand::UserDecrypt(CipherArguments::FromFile(
            CipherFile {
                input_path: ctxt_with_sns_path.to_path_buf(),
                batch_size: 1,
                num_requests: 3,
        })),
    ];

    test_template(ctx, [commands, commands_for_sns_precompute].concat()).await
}

fn config_path_from_context(ctx: &impl DockerComposeContext) -> String {
    ctx.root_path()
        .join(ctx.config_path())
        .to_str()
        .unwrap()
        .to_string()
}

#[test_context(DockerComposeThresholdContextTest)]
#[tokio::test]
#[serial(docker)]
async fn test_threshold_sequential_preproc_keygen(ctx: &DockerComposeThresholdContextTest) {
    init_testing();
    let config_path = config_path_from_context(ctx);
    let key_id_1 = real_preproc_and_keygen(&config_path).await;
    let key_id_2 = real_preproc_and_keygen(&config_path).await;
    assert_ne!(key_id_1, key_id_2);
}

#[test_context(DockerComposeThresholdContextTest)]
#[tokio::test]
#[serial(docker)]
async fn test_threshold_concurrent_preproc_keygen(ctx: &DockerComposeThresholdContextTest) {
    init_testing();
    let config_path = config_path_from_context(ctx);
    let _ = join_all([
        real_preproc_and_keygen(&config_path),
        real_preproc_and_keygen(&config_path),
    ])
    .await;
}

#[test_context(DockerComposeThresholdContextDefault)]
#[tokio::test]
#[serial(docker)]
async fn test_threshold_sequential_crs(ctx: &DockerComposeThresholdContextDefault) {
    init_testing();
    let crs_id_1 = crs_gen(ctx, false).await;
    let crs_id_2 = crs_gen(ctx, false).await;
    assert_ne!(crs_id_1, crs_id_2);
}

#[test_context(DockerComposeThresholdContextDefault)]
#[tokio::test]
#[serial(docker)]
async fn test_threshold_concurrent_crs(ctx: &DockerComposeThresholdContextDefault) {
    init_testing();
    let res = join_all([crs_gen(ctx, false), crs_gen(ctx, false)]).await;
    assert_ne!(res[0], res[1]);
}

// Test restore without custodians
#[test_context(DockerComposeThresholdContextTest)]
#[tokio::test]
#[serial(docker)]
async fn test_threshold_backup_restore(ctx: &DockerComposeThresholdContextTest) {
    init_testing();
    let _crs_id = crs_gen(ctx, true).await;
    let _ = backup_restore(ctx).await;
    // Observe that we cannot modify the state of the servers, so we cannot really validate the restore.
    // However we are testing this in the service/client. Hence this tests is mainly to ensure that the outer
    // end points and content returned from the KMS to the custodians work as expected.
}

#[test_context(DockerComposeThresholdCustodianContextTest)]
#[tokio::test]
#[serial(docker)]
async fn test_threshold_custodian_backup(ctx: &DockerComposeThresholdCustodianContextTest) {
    init_testing();
    // We don't have endpoints that allow us to purge the generate material within the docker images
    // so we can here only test that the end points are alive and acting as expected, rather than validating that
    // data gets restored. Instead test in the client within core have tests for validating this
    // First setup context, then back up init, use the result with the custodian client and then call recovery
    // Start by setting up the custodians
    let amount_custodians = 5;
    let custodian_threshold = 2;
    let amount_operators = 4; // TODO should not be hardcoded but not sure how I can get it easily
    let mut rng = AesRng::seed_from_u64(41);
    let keys_folder: &Path = Path::new("tests/data/keys");
    let (seeds, setup_msg_paths) =
        generate_custodian_keys_to_file(&mut rng, keys_folder, amount_custodians).await;
    let cus_backup_id = new_custodian_context(ctx, custodian_threshold, setup_msg_paths).await;
    let init_backup_id = custodian_backup_init(ctx).await;
    assert_eq!(cus_backup_id, init_backup_id);
    let recovery_backup_id = custodian_backup_recovery(
        ctx,
        &mut rng,
        amount_operators,
        RequestId::from_str(&cus_backup_id).unwrap(),
        seeds,
    )
    .await;
    assert_eq!(cus_backup_id, recovery_backup_id);
    let _ = backup_restore(ctx).await;
    // Observe that we cannot modify the state of the servers, so we cannot really validate recovery.
    // However we are testing this in the service/client. Hence this tests is mainly to ensure that the outer
    // end points and content returned from the KMS to the custodians work as expected.
}

async fn generate_custodian_keys_to_file(
    rng: &mut AesRng,
    root_path: &Path,
    amount_custodians: usize,
) -> (Vec<String>, Vec<PathBuf>) {
    let mut seeds = Vec::new();
    let mut paths = Vec::new();
    for cur_idx in 1..=amount_custodians {
        let role = Role::indexed_from_one(cur_idx);
        let mnemonic = seed_phrase_from_rng(rng).expect("Failed to generate seed phrase");
        let custodian: Custodian<PrivateSigKey, BackupPrivateKey> =
            custodian_from_seed_phrase(&mnemonic, role).unwrap();
        let setup_msg = custodian
            .generate_setup_message(rng, format!("CUSTODIAN_{cur_idx}"))
            .unwrap();
        let path = root_path.join("CUSTODIAN").join("setup-msg").join(format!(
            "setup-{}", //{MAIN_SEPARATOR}{}",
            // cur_rec_req.backup_id(),
            cur_idx
        ));
        safe_write_element_versioned(&path, &setup_msg)
            .await
            .unwrap();
        seeds.push(mnemonic);
        paths.push(path);
    }
    (seeds, paths)
}

///////// FULL GEN TESTS//////////
//////////////////////////////////

#[test_context(DockerComposeThresholdContextDefault)]
#[tokio::test]
#[serial(docker)]
async fn full_gen_tests_default_threshold_sequential_preproc_keygen(
    ctx: &DockerComposeThresholdContextDefault,
) {
    init_testing();
    let config_path = config_path_from_context(ctx);
    let key_id_1 = real_preproc_and_keygen(&config_path).await;
    let key_id_2 = real_preproc_and_keygen(&config_path).await;
    assert_ne!(key_id_1, key_id_2);
}

#[test_context(DockerComposeThresholdContextDefault)]
#[tokio::test]
#[serial(docker)]
async fn full_gen_tests_default_threshold_sequential_crs(
    ctx: &DockerComposeThresholdContextDefault,
) {
    init_testing();
    let crs_id_1 = crs_gen(ctx, false).await;
    let crs_id_2 = crs_gen(ctx, false).await;
    assert_ne!(crs_id_1, crs_id_2);
}

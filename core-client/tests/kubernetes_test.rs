use cc_tests_utils::{KMSMode, Kubernetes};
use kms_core_client::*;
use kms_grpc::KeyId;
use serial_test::serial;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::string::String;
use test_context::{test_context, AsyncTestContext};

trait KubernetesContext {
    fn root_path(&self) -> PathBuf;
    fn config_path(&self) -> &str;
}

struct KubernetesThresholdContextDefault {
    pub cmd: Kubernetes,
}

impl KubernetesContext for KubernetesThresholdContextDefault {
    fn root_path(&self) -> PathBuf {
        self.cmd.cmd.root_path.clone()
    }

    fn config_path(&self) -> &str {
        "core-client/config/client_local_threshold.toml"
    }
}

impl AsyncTestContext for KubernetesThresholdContextDefault {
    async fn setup() -> Self {
        KubernetesThresholdContextDefault {
            cmd: Kubernetes::new(KMSMode::ThresholdDefaultParameter)
                .expect("Failed to create Kubernetes test context"),
        }
    }

    async fn teardown(self) {
        drop(self.cmd);
    }
}

async fn insecure_key_gen<T: KubernetesContext>(ctx: &T, test_path: &Path) -> String {
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

async fn key_and_crs_gen<T: KubernetesContext>(
    ctx: &mut T,
    test_path: &Path,
    insecure_crs_gen: bool,
) -> (String, String) {
    let key_id = insecure_key_gen(ctx, test_path).await;
    let crs_id = crs_gen(ctx, test_path, insecure_crs_gen).await;
    (key_id, crs_id)
}

async fn crs_gen<T: KubernetesContext>(
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

async fn test_template<T: KubernetesContext>(
    ctx: &mut T,
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

#[test_context(KubernetesThresholdContextDefault)]
#[tokio::test]
#[serial(docker)]
async fn test_threshold_insecure(ctx: &mut KubernetesThresholdContextDefault) {
    init_testing();
    println!("Setting up test environment...");
    let temp_dir = tempfile::tempdir().unwrap();
    let keys_folder = temp_dir.path();
    let (key_id, _crs_id) = key_and_crs_gen(ctx, keys_folder, true).await;
    integration_test_commands(ctx, key_id).await;
}

async fn integration_test_commands<T: KubernetesContext>(ctx: &mut T, key_id: String) {
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

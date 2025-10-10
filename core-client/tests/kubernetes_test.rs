use kms_core_client::*;
use std::path::Path;
use std::string::String;

async fn insecure_key_gen(test_path: &Path) -> String {
    let path_to_config = Path::new("core-client/config/client_local_threshold.toml");
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

async fn crs_gen(test_path: &Path) -> String {
    let path_to_config = Path::new("core-client/config/client_local_threshold.toml");
    let command = CCCommand::CrsGen(CrsParameters { max_num_bits: 2048 });
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

#[tokio::test]
async fn test_threshold_insecure() {
    init_testing();
    let temp_dir = tempfile::tempdir().unwrap();
    let keys_folder = temp_dir.path();
    let _key_id = insecure_key_gen(keys_folder).await;
    let _crs_id = crs_gen(keys_folder).await;
}

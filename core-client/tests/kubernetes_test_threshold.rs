use kms_core_client::*;
use std::path::Path;
use std::path::PathBuf;
use std::string::String;

fn root_path() -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    PathBuf::from(manifest_dir)
        .parent()
        .expect("Failed to get parent directory")
        .to_path_buf()
}

fn config_path() -> String {
    "core-client/config/client_local_kind_threshold.toml".to_string()
}

async fn insecure_key_gen(test_path: &Path) -> String {
    let path_to_config = root_path().join(config_path());
    let config = CmdConfig {
        file_conf: Some(vec![String::from(path_to_config.to_str().unwrap())]),
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
    let path_to_config = root_path().join(config_path());
    let command = CCCommand::CrsGen(CrsParameters { max_num_bits: 2048 });
    let config = CmdConfig {
        file_conf: Some(vec![String::from(path_to_config.to_str().unwrap())]),
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

// NOTE: The typo here is on purpose to avoid it matching
// on some CI filter.
// Having k8 in the name is also on purpose for the same reason.
#[tokio::test]
async fn test_k8s_threshld_insecure() {
    init_testing();
    let temp_dir = tempfile::tempdir().unwrap();
    let keys_folder = temp_dir.path();
    let _key_id = insecure_key_gen(keys_folder).await;
    let _crs_id = crs_gen(keys_folder).await;
}

#[tokio::test]
async fn full_gen_tests_k8s_default_threshld_sequential_crs() {
    init_testing();
    let temp_dir = tempfile::tempdir().unwrap();
    let keys_folder = temp_dir.path();
    let crs_id_1 = crs_gen(keys_folder).await;
    let crs_id_2 = crs_gen(keys_folder).await;
    assert_ne!(crs_id_1, crs_id_2);
}

//! Main file to run for generating all the versioned data for all kms-core versions.

use backward_compatibility::{
    data_0_11::V0_11,
    data_dir,
    generate::{store_metadata, KMSCoreVersion},
    TestMetadataDD, TestMetadataKMS, TestMetadataKmsGrpc, Testcase,
    DISTRIBUTED_DECRYPTION_MODULE_NAME, KMS_GRPC_MODULE_NAME, KMS_MODULE_NAME, PRNG_SEED,
};

// Type aliases
type KmsTestcases = Vec<Testcase<TestMetadataKMS>>;
type KmsGrpcTestcases = Vec<Testcase<TestMetadataKmsGrpc>>;
type DdTestcases = Vec<Testcase<TestMetadataDD>>;

fn gen_testcases<Vers: KMSCoreVersion, Metadata, F>(
    gen_data_fn: F,
    module_name: &str,
) -> Vec<Testcase<Metadata>>
where
    F: Fn() -> Vec<Metadata>,
    Metadata: Clone,
{
    let tests = gen_data_fn();

    tests
        .iter()
        .map(|metadata| Testcase {
            kms_core_version_min: Vers::VERSION_NUMBER.to_string(),
            kms_core_module: module_name.to_string(),
            metadata: metadata.clone(),
        })
        .collect()
}

fn gen_all_data<Vers: KMSCoreVersion>() -> (KmsTestcases, KmsGrpcTestcases, DdTestcases) {
    // Seed TFHE-rs' key generation PRNG
    Vers::seed_prng(PRNG_SEED);

    let kms_testcases =
        gen_testcases::<Vers, TestMetadataKMS, _>(Vers::gen_kms_data, KMS_MODULE_NAME);

    let kms_grpc_testcases = gen_testcases::<Vers, TestMetadataKmsGrpc, _>(
        Vers::gen_kms_grpc_data,
        KMS_GRPC_MODULE_NAME,
    );

    let dd_testcases = gen_testcases::<Vers, TestMetadataDD, _>(
        Vers::gen_distributed_decryption_data,
        DISTRIBUTED_DECRYPTION_MODULE_NAME,
    );

    (kms_testcases, kms_grpc_testcases, dd_testcases)
}

fn main() {
    let (kms_testcases, kms_grpc_testcases, dd_testcases) = gen_all_data::<V0_11>();

    // Use module name as the filename prefix
    store_metadata(&kms_testcases, data_dir().join("kms.ron"));
    store_metadata(&kms_grpc_testcases, data_dir().join("kms-grpc.ron"));
    store_metadata(&dd_testcases, data_dir().join("distributed-decryption.ron"));
}

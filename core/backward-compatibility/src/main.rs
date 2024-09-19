//! Main file to run for generating all the versioned data for all kms-core versions.

use kms_core_backward_compatibility::{
    data_0_9::V0_9,
    data_dir,
    generate::{store_metadata, KMSCoreVersion},
    TestMetadataDD, TestMetadataKMS, Testcase, DISTRIBUTED_DECRYPTION_MODULE_NAME, KMS_MODULE_NAME,
    PRNG_SEED,
};

fn gen_all_data<Vers: KMSCoreVersion>() -> (
    Vec<Testcase<TestMetadataKMS>>,
    Vec<Testcase<TestMetadataDD>>,
) {
    // Seed TFHE-rs' key generation PRNG
    Vers::seed_prng(PRNG_SEED);

    let kms_tests = Vers::gen_kms_data();

    let kms_testcases: Vec<Testcase<TestMetadataKMS>> = kms_tests
        .iter()
        .map(|metadata| Testcase {
            kms_core_version_min: Vers::VERSION_NUMBER.to_string(),
            kms_core_module: KMS_MODULE_NAME.to_string(),
            metadata: metadata.clone(),
        })
        .collect();

    let dd_tests = Vers::gen_distributed_decryption_data();

    let dd_testcases: Vec<Testcase<TestMetadataDD>> = dd_tests
        .iter()
        .map(|metadata| Testcase {
            kms_core_version_min: Vers::VERSION_NUMBER.to_string(),
            kms_core_module: DISTRIBUTED_DECRYPTION_MODULE_NAME.to_string(),
            metadata: metadata.clone(),
        })
        .collect();

    (kms_testcases, dd_testcases)
}

fn main() {
    let (kms_testcases, dd_testcases) = gen_all_data::<V0_9>();

    store_metadata(&kms_testcases, data_dir().join("kms.ron"));
    store_metadata(&dd_testcases, data_dir().join("distributed_decryption.ron"));
}

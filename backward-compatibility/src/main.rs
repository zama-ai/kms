//! Main file to run for generating all the versioned data for all kms-core versions.

use backward_compatibility::{
    data_0_9::V0_9,
    data_dir,
    generate::{store_metadata, KMSCoreVersion},
    TestMetadataDD, TestMetadataEvents, TestMetadataKMS, Testcase,
    DISTRIBUTED_DECRYPTION_MODULE_NAME, EVENTS_MODULE_NAME, KMS_MODULE_NAME, PRNG_SEED,
};

// Type aliases
type KmsTestcases = Vec<Testcase<TestMetadataKMS>>;
type DdTestcases = Vec<Testcase<TestMetadataDD>>;
type EventsTestcases = Vec<Testcase<TestMetadataEvents>>;

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

fn gen_all_data<Vers: KMSCoreVersion>() -> (KmsTestcases, DdTestcases, EventsTestcases) {
    // Seed TFHE-rs' key generation PRNG
    Vers::seed_prng(PRNG_SEED);

    let kms_testcases =
        gen_testcases::<Vers, TestMetadataKMS, _>(Vers::gen_kms_data, KMS_MODULE_NAME);

    let dd_testcases = gen_testcases::<Vers, TestMetadataDD, _>(
        Vers::gen_distributed_decryption_data,
        DISTRIBUTED_DECRYPTION_MODULE_NAME,
    );

    let events_testcases =
        gen_testcases::<Vers, TestMetadataEvents, _>(Vers::gen_events_data, EVENTS_MODULE_NAME);

    (kms_testcases, dd_testcases, events_testcases)
}

fn main() {
    let (kms_testcases, dd_testcases, events_testcases) = gen_all_data::<V0_9>();

    store_metadata(&kms_testcases, data_dir().join("kms.ron"));
    store_metadata(&dd_testcases, data_dir().join("distributed_decryption.ron"));
    store_metadata(&events_testcases, data_dir().join("events.ron"));
}

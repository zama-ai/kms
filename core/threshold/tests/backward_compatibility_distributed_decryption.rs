//! Tests breaking change in serialized data by trying to load historical data stored in `backward-compatibility/data`.
//! For each kms-core module, there is a folder with some serialized messages and a [ron](https://github.com/ron-rs/ron)
//! file. The ron file stores some metadata that are parsed in this test. These metadata tells
//! what to test for each message.

use backward_compatibility::{
    data_dir,
    load::{DataFormat, TestFailure, TestResult, TestSuccess},
    tests::{run_all_tests, TestedModule},
    PRSSSetupTest, TestMetadataDD, TestType, Testcase,
};
use distributed_decryption::{
    algebra::{
        residue_poly::{ResiduePoly128, ResiduePoly64},
        structure_traits::{Invert, Ring, RingEmbed},
    },
    execution::{runtime::party::Role, small_execution::prss::PRSSSetup},
    tests::helper::testing::{get_dummy_prss_setup, get_networkless_base_session_for_parties},
};
use kms_common::load_and_unversionize;
use serde::Serialize;
use std::{env, path::Path};

use tfhe_versionable::Unversionize;

fn compare_prss_setup<Z>(
    dir: &Path,
    test: &PRSSSetupTest,
    format: DataFormat,
    poly_size: u16,
) -> Result<TestSuccess, TestFailure>
where
    Z: Default + Clone + Serialize + Ring + RingEmbed + Invert,
    PRSSSetup<Z>: Unversionize,
{
    let role = Role::indexed_by_one(test.role_i);
    let base_session = get_networkless_base_session_for_parties(test.amount, test.threshold, role);

    let original_versionized: PRSSSetup<Z> = load_and_unversionize(dir, test, format)?;
    let new_versionized = get_dummy_prss_setup::<Z>(base_session);

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid PRSS setup with residue poly size {:?}:\n Expected :\n{:?}\nGot:\n{:?}",
                poly_size, original_versionized, new_versionized
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

fn test_prss_setup(
    dir: &Path,
    test: &PRSSSetupTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    match test.residue_poly_size {
        64 => compare_prss_setup::<ResiduePoly64>(dir, test, format, 64),
        128 => compare_prss_setup::<ResiduePoly128>(dir, test, format, 128),
        _ => Err(test.failure(
            "Invalid residue poly size for PRSS setup: residue_poly_size must be 64 or 128"
                .to_string(),
            format,
        )),
    }
}

struct DistributedDecryption;

impl TestedModule for DistributedDecryption {
    type Metadata = TestMetadataDD;
    const METADATA_FILE: &'static str = "distributed_decryption.ron";

    fn run_test<P: AsRef<Path>>(
        test_dir: P,
        testcase: &Testcase<Self::Metadata>,
        format: DataFormat,
    ) -> TestResult {
        match &testcase.metadata {
            Self::Metadata::PRSSSetup(test) => {
                test_prss_setup(test_dir.as_ref(), test, format).into()
            }
        }
    }
}

// Backward compatibility tests are skipped until we have a proper stable version
#[test]
#[ignore]
fn test_backward_compatibility_distributed_decryption() {
    let pkg_version = env!("CARGO_PKG_VERSION");

    let base_data_dir = data_dir();

    let results = run_all_tests::<DistributedDecryption>(&base_data_dir, pkg_version);

    if results.iter().any(|r| r.is_failure()) {
        panic!("Backward compatibility tests for the distributed decryption module failed")
    }
}

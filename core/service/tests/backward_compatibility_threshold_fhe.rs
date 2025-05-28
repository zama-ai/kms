//! Tests breaking change in serialized data by trying to load historical data stored in `backward-compatibility/data`.
//! For each kms-core module, there is a folder with some serialized messages and a [ron](https://github.com/ron-rs/ron)
//! file. The ron file stores some metadata that are parsed in this test. These metadata tells
//! what to test for each message.

mod common;
use common::load_and_unversionize;

use aes_prng::AesRng;
use backward_compatibility::{
    data_dir,
    load::{DataFormat, TestFailure, TestResult, TestSuccess},
    tests::{run_all_tests, TestedModule},
    PRSSSetupTest, PrfKeyTest, TestMetadataDD, TestType, Testcase,
};
use rand::{RngCore, SeedableRng};
use std::{env, path::Path};
use tfhe_versionable::Unversionize;
use threshold_fhe::{
    algebra::{
        galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64},
        structure_traits::{ErrorCorrect, Invert},
    },
    execution::{
        runtime::party::Role,
        small_execution::{
            prf::{PRSSConversions, PrfKey},
            prss::PRSSSetup,
        },
    },
    tests::helper::testing::{get_dummy_prss_setup, get_networkless_base_session_for_parties},
};

fn compare_prss_setup<Z>(
    dir: &Path,
    test: &PRSSSetupTest,
    format: DataFormat,
    poly_size: u16,
) -> Result<TestSuccess, TestFailure>
where
    Z: ErrorCorrect + Invert + PRSSConversions,
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
        64 => compare_prss_setup::<ResiduePolyF4Z64>(dir, test, format, 64),
        128 => compare_prss_setup::<ResiduePolyF4Z128>(dir, test, format, 128),
        _ => Err(test.failure(
            "Invalid residue poly size for PRSS setup: residue_poly_size must be 64 or 128"
                .to_string(),
            format,
        )),
    }
}

fn test_prf_key(
    dir: &Path,
    test: &PrfKeyTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: PrfKey = load_and_unversionize(dir, test, format)?;
    let mut buf = [0u8; 16];
    let mut rng = AesRng::from_seed(test.seed.to_le_bytes());
    rng.fill_bytes(&mut buf);

    let new_versionized = PrfKey(buf);
    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid prf key:\n Expected :\n{:?}\nGot:\n{:?}",
                original_versionized, new_versionized
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

struct ThresholdFhe;
impl TestedModule for ThresholdFhe {
    type Metadata = TestMetadataDD;
    const METADATA_FILE: &'static str = "threshold-fhe.ron";

    fn run_test<P: AsRef<Path>>(
        test_dir: P,
        testcase: &Testcase<Self::Metadata>,
        format: DataFormat,
    ) -> TestResult {
        match &testcase.metadata {
            Self::Metadata::PRSSSetup(test) => {
                test_prss_setup(test_dir.as_ref(), test, format).into()
            }
            Self::Metadata::PrfKey(test) => test_prf_key(test_dir.as_ref(), test, format).into(),
        }
    }
}

#[test]
fn test_backward_compatibility_threshold_fhe() {
    let pkg_version = env!("CARGO_PKG_VERSION");

    let base_data_dir = data_dir();

    let results = run_all_tests::<ThresholdFhe>(&base_data_dir, pkg_version);

    if results.iter().any(|r| r.is_failure()) {
        panic!("Backward compatibility tests for the threshold fhe module failed")
    }
}

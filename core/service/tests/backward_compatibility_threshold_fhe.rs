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
    PRSSSetupTest, PrfKeyTest, PrssSetTest, ShareTest, TestMetadataDD, TestType, Testcase,
};
use rand::{RngCore, SeedableRng};
use std::{env, path::Path};
use tfhe_versionable::Unversionize;
use tfhe_versionable::Upgrade;
use threshold_fhe::{
    algebra::{
        galois_rings::degree_4::{ResiduePolyF4Z128, ResiduePolyF4Z64},
        structure_traits::{ErrorCorrect, Invert, Ring},
    },
    execution::{
        runtime::party::Role,
        sharing::share::Share,
        small_execution::{
            prf::{PRSSConversions, PrfKey},
            prss::{PRSSSetup, PrssSet, PrssSetV0},
        },
    },
    tests::helper::testing::{get_dummy_prss_setup, get_networkless_base_session_for_parties},
};

use crate::common::load_and_unversionize_auxiliary;

#[allow(dead_code)]
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
    let role = Role::indexed_from_one(test.role_i);
    let base_session = get_networkless_base_session_for_parties(test.amount, test.threshold, role);

    let original_versionized: PRSSSetup<Z> = load_and_unversionize(dir, test, format)?;
    let new_versionized = get_dummy_prss_setup::<Z>(base_session);

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid PRSS setup with residue poly size {poly_size:?}:\n Expected :\n{original_versionized:?}\nGot:\n{new_versionized:?}"
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

#[allow(dead_code)]
fn compare_prss_set<Z>(
    dir: &Path,
    test: &PrssSetTest,
    format: DataFormat,
    poly_size: u16,
) -> Result<TestSuccess, TestFailure>
where
    Z: Ring,
    PrssSet<Z>: Unversionize,
{
    let original_current: PrssSet<Z> = load_and_unversionize(dir, test, format)?;
    let original_legacy: PrssSet<Z> =
        load_and_unversionize_auxiliary(dir, test, &test.legacy_filename, format)?;

    let mut rng = AesRng::seed_from_u64(test.state);
    let mut party_set = Vec::new();
    for i in 1..=test.amount_parties {
        party_set.push(Role::indexed_from_one(i));
    }

    let mut set_key = [0u8; 16];
    rng.fill_bytes(&mut set_key);

    let mut f_a_points = Vec::new();
    for _ in 0..test.amount_points {
        f_a_points.push(Z::from_u128(rng.next_u64() as u128));
    }

    let new_current = PrssSet::<Z> {
        parties: party_set.clone(),
        set_key: PrfKey(set_key.clone()),
        f_a_points: f_a_points.clone(),
    };
    let new_legacy = PrssSetV0::<Z> {
        parties: party_set.iter().map(|r| r.one_based()).collect(),
        set_key: PrfKey(set_key.clone()),
        f_a_points,
    };

    if original_legacy != new_legacy.clone().upgrade().unwrap() {
        return Err(test.failure(
            format!(
                "Invalid legacy prss set with residue poly size {poly_size:?}:\n Expected :\n{original_legacy:?}\nGot:\n{new_legacy:?}"
            ),
            format,
        ));
    }

    if original_current != new_current {
        Err(test.failure(
            format!("Invalid prss set with residue poly size {poly_size:?}:\n Expected :\n{original_current:?}\nGot:\n{new_current:?}"),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

#[allow(dead_code)]
fn compare_share<Z>(
    dir: &Path,
    test: &ShareTest,
    format: DataFormat,
    poly_size: u16,
) -> Result<TestSuccess, TestFailure>
where
    Z: Ring,
    Share<Z>: Unversionize,
{
    let role = Role::indexed_from_one(test.owner);

    let original_versionized: Share<Z> = load_and_unversionize(dir, test, format)?;
    let val = Z::from_u128(test.value);
    let new_versionized = Share::<Z>::new(role, val);

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid share with residue poly size {poly_size:?}:\n Expected :\n{original_versionized:?}\nGot:\n{new_versionized:?}"
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

#[allow(dead_code)]
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

fn test_prss_set(
    dir: &Path,
    test: &PrssSetTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    match test.residue_poly_size {
        64 => compare_prss_set::<ResiduePolyF4Z64>(dir, test, format, 64),
        128 => compare_prss_set::<ResiduePolyF4Z128>(dir, test, format, 128),
        _ => Err(test.failure(
            "Invalid residue poly size for prss set: residue_poly_size must be 64 or 128"
                .to_string(),
            format,
        )),
    }
}

fn test_share(
    dir: &Path,
    test: &ShareTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    match test.residue_poly_size {
        64 => compare_share::<ResiduePolyF4Z64>(dir, test, format, 64),
        128 => compare_share::<ResiduePolyF4Z128>(dir, test, format, 128),
        _ => Err(test.failure(
            "Invalid residue poly size for sharing: residue_poly_size must be 64 or 128"
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
                "Invalid prf key:\n Expected :\n{original_versionized:?}\nGot:\n{new_versionized:?}"
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
            Self::Metadata::PrssSet(test) => test_prss_set(test_dir.as_ref(), test, format).into(),
            Self::Metadata::Share(test) => test_share(test_dir.as_ref(), test, format).into(),
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

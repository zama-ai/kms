# kms-core backwards compatibility

This repo is heavily inspired by the work done in the [tfhe-backward-compat-data](https://github.com/zama-ai/tfhe-backward-compat-data) project and was adapted to kms-core.
It contains various objects that have been versioned and serialized.
The goal is to detect in the CI when the version of a type should be updated because a breaking change has been added.

The objects are serialized using bincode only because it supports large arrays and is vulnerable to different sets of breaking changes. Each object is stored with a set of metadata to verify that the values are loaded correctly.

For any additional documentation, feel free to take a look at the [tfhe-backward-compat-data](https://github.com/zama-ai/tfhe-backward-compat-data) project.

## Usage

At the repo's root, run the following command

```shell
make test-backward-compatibility
```

This will load the objects versioned with the versions set in this module and check if they can be loaded correctly with the current state of kms-core.

## Versioning this module

The tests in this module are by definition forward compatible (they should run on any future kms-core release). They are also backward compatible (allowing tests to be run on past kms-core versions, for example to bisect a bug), mostly because the kms-core test driver will simply ignore any unknown test types and only load tests for versions inferior to its own.

However, this does not allow changes to be made to the test metadata scheme itself. In such a case, new data should be generated.

## Data generation

To re-generate the data, run the binary target within this module (not at the kms-core's root, because it is not included in the workspace):

```shell
cargo run --features="generate" --release
```

TFHE-rs' prng is seeded with a fixed seed, so the data should be identical at each generation. However, the actual serialized objects might be different because bincode does not serialize HashMap in a deterministic way (see: [this issue](https://github.com/TyOverby/bincode/issues/514)).

## Adding a test for an existing type

To add a new test for a type that is already tested, you need to:

- go to the `data_x_y.rs` file (where "x.y" is the kms-core version of the tested data)
- create a const global variable with the metadata for that test
- create a `gen_...` method in the appropriate struct (ex: `KmsV0_9` for KMS objects)
- instantiate the object you want to test in it.
  - If some private functions are needed to do so, the simplest solution is to copy paste them in a `helper_x_y.rs` file (you might need to create this file). Else, make them public or available under the "testing" feature and update the target commit of kms-core in this module. Be aware that is this requires updating the version, you need to add it instead and keep the old one as well.
  - If some auxiliary data is needed for the test, make sure to serialize it using `store_versioned_auxiliary` macro
- serialize it using the `store_versioned_test` macro
- return the metadata of your test
- update the `gen_vvv_data` method (where "vvv" is the module where your new type is defined) for the main struct (ex: `V0_9`) by calling your new method within the returned vector

The test will then be automatically selected when running `make test_backward_compatibility`.

### Example

```rust
// 1. Define the metadata associated with the test
const PRIVATE_SIG_KEY_TEST: PrivateSigKeyTest = PrivateSigKeyTest {
    test_filename: Cow::Borrowed("private_sig_key"),
    state: 100,
};

impl KmsV0_9 {
    // ...
    // Other generation methods
    // ...

    fn gen_private_sig_key(dir: &PathBuf) -> TestMetadataKMS {
        // 2. Create the type
        let mut rng = AesRng::seed_from_u64(PRIVATE_SIG_KEY_TEST.state);
        let (_, private_sig_key) = gen_sig_keys(&mut rng);

        // 3. Store it
        store_versioned_test!(&private_sig_key, dir, &PRIVATE_SIG_KEY_TEST.test_filename);

        // 4. Return the metadata
        TestMetadataKMS::PrivateSigKey(PRIVATE_SIG_KEY_TEST)
    }
}

impl KMSCoreVersion for V0_9 {
    // ...
    // Impl of trait
    // ...

    fn gen_kms_data() -> Vec<TestMetadataKMS> {
        // ...
        // Init code and generation of other tests
        // ...

        // 5. Call the generation method and return the metadata
        vec![
            // ...
            KmsV0_9::gen_private_sig_key(&dir),
            // ...
            // Other generation methods for KMS
            // ...
        ]

    }
}
```

## Adding a test for a new type

### In this module

To add a test for a type that has not yet been tested, you should:

- got to `libs.rs`:
  - create a new struct that implements the `TestType` trait. Only the `test_filename` field is required, the others are metadata used to instantiate and check the new type. However, they should not use any kms-core internal type
  - add it to the `TestMetadataZzz` enum, where `Zzz` is the name of the module to test
- add a new testcase using the procedure in the previous paragraph. If the type comes from a new module, you should also:
  - go to `lib.rs` and create a new `TestMetadataZzz` module
  - go to `data_x_y.rs` and create a new `gen_vvv_data` method
  - go to `main.rs`:
    - modify `gen_all_data` to include and return the new tests
    - retrieve the new tests in `main()` and store them using `store_metadata` along a different and related file name

### Example

```rust
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PrivateSigKeyTest {
    pub test_filename: Cow<'static, str>,
    pub state: u64,
}

impl TestType for PrivateSigKeyTest {
    fn module(&self) -> String {
        KMS_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "PrivateSigKey".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Display)]
pub enum TestMetadataKMS {
    // ...
    PrivateSigKey(PrivateSigKeyTest),
    // ...
    // All other supported types for KMS
    // ...
}
```

### In the tests

In the tested module, you should update the test (ex: `kms-core/core/threshold/tests/backward_compatibility_kms.rs`) to handle your new test type. To do this, create a function that first loads and unversionizes the serialized object, and then checks its value against a new instantiated object generated thanks to the provided metadata:

### Example

```rust
fn test_private_sig_key(
    dir: &Path,
    test: &PrivateSigKeyTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: PrivateSigKey = load_and_unversionize(dir, test, format)?;

    let mut rng = AesRng::seed_from_u64(test.state);
    let (_, new_versionized) = gen_sig_keys(&mut rng);

    if original_versionized != new_versionized {
        Err(test.failure(
            format!(
                "Invalid private sig key:\n Expected :\n{:?}\nGot:\n{:?}",
                original_versionized, new_versionized
            ),
            format,
        ))
    } else {
        Ok(test.success(format))
    }
}

// ...
// Other tests
// ...

impl TestedModule for KMS {
    type Metadata = TestMetadataKMS;
    const METADATA_FILE: &'static str = "kms.ron";

    fn run_test<P: AsRef<Path>>(
        test_dir: P,
        testcase: &Testcase<Self::Metadata>,
        format: DataFormat,
    ) -> TestResult {
        match &testcase.metadata {
            // ...
            Self::Metadata::PrivateSigKey(test) => {
                test_private_sig_key(test_dir.as_ref(), test, format).into()
            }
            // ...
            // Match all other tests for KMS
            // ...
        }
    }
}

```

## Adding a new kms-core release

To add data for a new released version of kms-core, you should:

- add a dependency to that version in the `Cargo.toml` of this module. This dependency should only be enabled with the `generate` feature to avoid conflicts during testing
- create a new `data_x_y.rs` file
- implement the `KMSCoreVersion` trait for the new version. You can use the code in `data_0_9.rs` as an example
- go to `main.rs`, call `gen_all_data` within the `main()` function using the new version and then extend the different `zzz_testcases`

In `data_x_y.rs`:

```rust
pub struct V0_X;

impl KMSCoreVersion for V0_X {
    const VERSION_NUMBER: &'static str = "0.x";

    // ...
    // Implement the trait
    // ...
}
```

In `main.rs`:

```rust
fn main() {
    let (kms_testcases, dd_testcases) = gen_all_data::<V0_9>();
    let (kms_testcases_0_x, dd_testcases_0_x) = gen_all_data::<V0_X>();

    kms_testcases.extend(kms_testcases_0_x);
    dd_testcases.extend(dd_testcases_0_x);

    // ...
}
```

## Using the test data

The data is stored using git-lfs, so be sure to clone the kms-core repo with lfs first. To be able to parse the metadata and check if the loaded data is valid, you should add this module (`backward-compatibility`) as a dependency with the `load` and `tests` features enabled.

## Adding a new version to a versionized type

When some breaking changes are added to a versionized type, you should update several things. Let's say that the type only had a `V0` version, then you should:

- add a new version `v1` to the `XXXVersioned` enum associated to the type `XXX` (ex: `PrivateSigKeyVersioned` for `PrivateSigKey`)
- **keep** the `PrivateSigKey` old definition and rename it to `PrivateSigKeyV0`
- replace the `Versionize` derive trait with the `Version` one (import if from `tfhe-versionable` if needed)
- remove the `#[versionize(XXXVersioned)]` attribute
- add your new `XXX` type (ex: `PrivateSigKey`) definition and add both the `Versionize` derive trait and the `#[versionize(XXXVersioned)]` attribute to it
- implement the `Upgrade` trait for the old definition (ex: `PrivateSigKeyV0`)

It is import to understand that the old definition **must not** be changed whenever there's a breaking change. Also, only the latest definition should be annotated with both versionize macros.

It should look like the following:

```rust
#[derive(..., VersionsDispatch)]
pub enum PrivateSigKeyVersioned {
    V0(PrivateSigKeyV0),
    V1(PrivateSigKey),
}

// Old definition
#[derive(..., Version)]
pub struct PrivateSigKeyV0 {
    sk: WrappedSigningKey,
}

// New definition
#[derive(..., Versionize)]
#[versionize(PrivateSigKeyVersioned)]
pub struct PrivateSigKey {
    // New definition
}

impl Upgrade<PrivateSigKey> for PrivateSigKeyV0 {
    type Error = Infallible;

    fn upgrade(self) -> Result<PrivateSigKey, Self::Error> {
        Ok(PrivateSigKey {
            // New definition
        })
    }
}
```

For more in depth scenarios, you can take a look at the [tfhe-rs examples](https://github.com/zama-ai/tfhe-rs/tree/main/utils/tfhe-versionable/examples).

## Updating the test without testing backward compatibility

If you want to update the test data _without_ actually testing for backward compatibility, you can follow the following steps:

1. In the PR (PR1) that contains breaking changes for backward compatibility, disable the related backward test
1. Once PR1 is merged, create a new PR (PR2) where you update the Cargo.toml of the backward crate with the commit hash that correspond to PR1 being merged to `main`
1. Then you run `cargo run --features="generate"` as described above to generate new testing objects
1. Re-enable the backward compatibility tests that were disabled in PR1
1. Push the changes to PR2 and the tests should pass

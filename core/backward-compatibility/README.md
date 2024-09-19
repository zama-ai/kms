# kms-core backwards compatibility
This repo is heavily inspired by the work done in the [tfhe-backward-compat-data](https://github.com/zama-ai/tfhe-backward-compat-data) project and was adapted to kms-core.
It contains various objects that have been versioned and serialized.
The goal is to detect in the CI when the version of a type should be updated because a breaking change has been added.

The objects are serialized using bincode only because it supports large arrays and is vulnerable to different sets of breaking changes. Each object is stored with a set of metadata to verify that the values are loaded correctly.

For any additional documentation, feel free to take a look at the [tfhe-backward-compat-data](https://github.com/zama-ai/tfhe-backward-compat-data) project.

# Usage
At the repo's root, run the following command
```shell
make test_backward_compatibility
```
This will load the objects versioned with the versions set in this module and check if they can be loaded correctly with the current state of kms-core.

# Versioning this module
The tests in this module are by definition forward compatible (they should run on any future kms-core release). They are also backward compatible (allowing tests to be run on past kms-core versions, for example to bisect a bug), mostly because the kms-core test driver will simply ignore any unknown test types and only load tests for versions inferior to its own.

However, this does not allow changes to be made to the test metadata scheme itself. In such a case, new data should be generated.

# Data generation
To re-generate the data, run the binary target within this module (not at the kms-core's root, because it is not included in the workspace): 

```shell
cargo run --features="generate" --release
``` 

TFHE-rs' prng is seeded with a fixed seed, so the data should be identical at each generation. However, the actual serialized objects might be different because bincode does not serialize HashMap in a deterministic way (see: [this issue](https://github.com/TyOverby/bincode/issues/514)).

# Adding a test for an existing type
To add a new test for a type that is already tested, you need to: 
- go to the `data_x_y.rs` file (where "x.y" is the kms-core version of the tested data)
- create a const global variable with the metadata for that test
- update the `gen_vvv_data` method (where "vvv" is the module where your new type is defined)
- instantiate the object you want to test. If some private functions are needed to do so, the simplest solution is to copy paste them in a `helper_x_y.rs` file (you might need to create this file). Else, make them public or available under the "testing" feature and update the target commit of kms-core in this module. Be aware that is this requires updating the version, you need to add it instead and keep the old one as well.
- serialize it using the `store_versioned_test` macro
- add the metadata of your test to the vector returned by the method

The test will then be automatically selected when running `make test_backward_compatibility`.

## Example
```rust
// 1. Define the metadata associated with the test
const PUBLIC_PARAMETER_TEST: PublicParameterTest = PublicParameterTest {
    test_filename: Cow::Borrowed("public_parameter"),
    witness_dim: 2,
    max_num_bits: Some(1),
};

impl KMSCoreVersion for V0_9 {
    // ...
    // Impl of trait
    // ...

    fn gen_distributed_decryption_data() -> Vec<TestMetadataDD> {
        // ...
        // Init code and generation of other tests
        // ...

        // 2. Create the type
        let public_parameter = PublicParameter::new(PUBLIC_PARAMETER_TEST.witness_dim, PUBLIC_PARAMETER_TEST.max_num_bits);

        // 3. Store it
        store_versioned_test!(
            &public_parameter,
            &dir,
            &PUBLIC_PARAMETER_TEST.test_filename
        );

        // 4. Return the metadata
        vec![
            TestMetadataDD::PublicParameter(PUBLIC_PARAMETER_TEST),
            // ...
            // Metadata for other tests for Distributed Decryption
            // ...
        ]

    }
}
```

# Adding a test for a new type

## In this module
To add a test for a type that has not yet been tested, you should:
- got to `libs.rs`:
    - create a new struct that implements the `TestType` trait. Only the `test_filename` field is required, the others are metadata used to instantiate and check the new type. However, they should not use any kms-core internal type
    - add it to the `TestMetadataZzz` enum, where `Zzz` is the name of the module to test
- add a new testcase using the procedure in the previous paragraph. If the type comes from a new module, you should also:
    - go to `lib.rs` and create a new `TestMetadataZzz` module  
    - go to `data_x_y.rs` and create a new `gen_vvv_data` method
    - go to `main.rs`:
        - generate the new tests and modify `gen_all_data` so that it returns the new tests in addition to the other ones
        - retrieve the new tests in `main()` and store them using `store_metadata` along a different and related file name

### Example
```rust
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicParameterTest {
    pub test_filename: Cow<'static, str>,
    pub witness_dim: usize,
    pub max_num_bits: Option<u32>,
}

impl TestType for PublicParameterTest {
    fn module(&self) -> String {
        DISTRIBUTED_DECRYPTION_MODULE_NAME.to_string()
    }

    fn target_type(&self) -> String {
        "PublicParameter".to_string()
    }

    fn test_filename(&self) -> String {
        self.test_filename.to_string()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Display)]
pub enum TestMetadataDD {
    // ...
    PublicParameter(PublicParameterTest),
    // ...
    // All other supported types for Distributed Decryption
    // ...
}
```

## In the tests
In the tested module, you should update the test (ex: `kms-core/core/threshold/tests/backward-compatibility.rs`) to handle your new test type. To do this, create a function that first loads and unversionizes the serialized object, and then checks its value against a new instantiated object generated thanks to the provided metadata:

### Example
```rust
pub fn test_public_parameter(
    dir: &Path,
    test: &PublicParameterTest,
    format: DataFormat,
) -> Result<TestSuccess, TestFailure> {
    let original_versionized: PublicParameter = load_and_unversionize(dir, test, format)?;
    let new_versionized = PublicParameter::new(test.witness_dim, test.max_num_bits);

    if new_versionized != original_versionized {
        Err(test.failure(
            format!(
                "Invalid public parameter:\n Expected :\n{:?}\nGot:\n{:?}",
                new_versionized, original_versionized
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

impl TestedModule for DistributedDecryption {
    const METADATA_FILE: &'static str = "distributed_decryption.ron";

    fn run_test<P: AsRef<Path>>(
        test_dir: P,
        testcase: &Testcase<Self::Metadata>,
        format: DataFormat,
    ) -> TestResult {
        match &testcase.metadata {
            Self::Metadata::PublicParameter(test) => {
                test_public_parameter(test_dir.as_ref(), test, format).into()
            }
            // ...
            // Match all other tests for Distributed Decryption
            // ...
        }
    }
}
```

# Adding a new kms-core release
To add data for a new released version of kms-core, you should:
- add a dependency to that version in the `Cargo.toml` of this module. This dependency should only be enabled with the `generate` feature to avoid conflicts during testing
- create a new `data_x_y.rs` file
- implement the `KMSCoreVersion` trait for the new version. You can use the code in `data_0_9.rs` as an example
- go to `main.rs` and extend the different `zzz_testcases` with this new version within the `main()` function

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

# Using the test data
The data is stored using git-lfs, so be sure to clone the kms-core repo with lfs first. To be able to parse the metadata and check if the loaded data is valid, you should add this module (`kms-core-backward-compatibility`) as a dependency with the `load` and `tests` features enabled.


# Adding a new version to a versionized type
When some breaking changes are added to a versionized type, you should update several things. Let's say that the type only had a `V0` version, then you should:
- add a new version `v1` to the `XXXVersioned` enum associated to the type `XXX` (ex: `PublicParameterVersioned` for `PublicParameter`)
- **keep** the `PublicParameter` old definition and rename it to `PublicParameterV0`
- replace the `Versionize` derive trait with the `Version` one (import if from `tfhe-versionable` if needed)
- remove the `#[versionize(XXXVersioned)]` attribute
- add your new `XXX` type (ex: `PublicParameter`) definition and add both the `Versionize` derive trait and the `#[versionize(XXXVersioned)]` attribute to it

It is import to understand that the old definition **must not** be changed whenever there's a breaking change. Also, only the latest definition should be annotated with both versionize macros.

It should look like the following:
```rust
#[derive(..., VersionsDispatch)]
pub enum PublicParameterVersioned {
    V0(PublicParameterV0),
    V0(PublicParameter),
}

// Old definition
#[derive(..., Version)]
pub struct PublicParameterV0 {
    round: usize,
    inner: WrappedG1G2s,
}

// New definition
#[derive(..., Versionize)]
#[versionize(PublicParameterVersioned)]
pub struct PublicParameter {
    // New definition
}
```

For more in depth scenarios, you can take a look at the [tfhe-rs examples](https://github.com/zama-ai/tfhe-rs/tree/main/utils/tfhe-versionable/examples).
# KMS Core Backward Compatibility

This repo is heavily inspired by the work done in the [tfhe-backward-compat-data](https://github.com/zama-ai/tfhe-backward-compat-data) project and was adapted to kms-core.
It contains various objects that have been versioned and serialized.
The goal is to detect in the CI when the version of a type should be updated because a breaking change has been made.

The approach is a two-step process:
1. Generate versioned objects serialized in a certain (older) version of the project
2. Run tests and ensure that newer versions of the project can load and process these older objects properly.

The objects are serialized using bincode only because it supports large arrays and is vulnerable to different sets of breaking changes. Each object is stored with a set of metadata to verify that the values are loaded correctly.

For any additional documentation, feel free to take a look at the [tfhe-backward-compat-data](https://github.com/zama-ai/tfhe-backward-compat-data) project.

## Testing backward compatibility

At the repo's root, run the following command to run the backwards compatibility tests:

```shell
make test-backward-compatibility
```

This will load existing objects from git LFS versioned with the versions set in this module and check if they can be loaded correctly with the current state of kms-core.

## Checking for breaking changes using snapshots

The breaking-change tests are complemented by a Dylint snapshot check for types that derive `VersionsDispatch`.
The snapshot check compares the current branch against a base ref (usually main) and reports:
- removed version variants as errors, because old serialized data could no longer be deserialized;
- removed versioned enums, changed versioned type layouts, changed upgrade bodies, and removed upgrades as warnings for review;
- new versioned enums, variants, and upgrades as neutral changes.

At the repo's root, run:

```shell
make backward-snapshot-check BASE_REF=origin/main
```

To generate a markdown report:

```shell
make backward-snapshot-report BASE_REF=origin/main OUTPUT_FILE=/tmp/kms-backward-snapshot-report.md
```

Snapshots are generated into temporary directories from `BASE_REF` and the current checkout.

Internally, the make command uses the `ci/scripts/backward_snapshot.sh`, which
in turn uses a binary from tfhe-rs `tfhe-backward-compat-checker` to detect
breaking changes. More documentation can be found by running
`ci/scripts/backward_snapshot.sh --help`.


## Versioning this module

The tests in this module are by definition forward compatible (they should run on any future kms-core release). They are also backward compatible (allowing tests to be run on past kms-core versions, for example to bisect a bug), mostly because the kms-core test driver will simply ignore any unknown test types and only load tests for versions inferior to its own.

However, this does not allow changes to be made to the test metadata scheme itself. In such a case, new data should be generated.

## Data generation

**Note:** Data generation has been moved to separate version-specific crates to avoid dependency conflicts:
- `backward-compatibility/generate-v0.11.0` - For KMS v0.11.0
- `backward-compatibility/generate-v0.11.1` - For KMS v0.11.1
- `backward-compatibility/generate-v0.13.0` - For KMS v0.13.0
- `backward-compatibility/generate-v0.13.10` - For KMS v0.13.10
- `backward-compatibility/generate-v0.13.20` - For KMS v0.13.20
- `backward-compatibility/generate-v0.14.0` - For KMS v0.14.0

Each generator uses the exact dependencies from its target KMS version.

To re-generate data for all **deterministic** versions (recommended — frozen versions are intentionally skipped, see [Data Determinism](#data-determinism) below):

```shell
make generate-backward-compatibility-all
```

Or generate for a specific version with an existing Makefile target:

```shell
# Generate only v0.13.0 data
make generate-backward-compatibility-v0.13.0

# Generate only v0.13.10 data
make generate-backward-compatibility-v0.13.10

# Generate only v0.13.20 data
make generate-backward-compatibility-v0.13.20

# Generate only v0.14.0 data
make generate-backward-compatibility-v0.14.0

```
WARNING: Frozen-version targets are for exceptional investigation only. They can produce non-deterministic bytes and may append duplicate metadata with older generator code. Changes based on generating a frozen version should NEVER be committed to the repo.

**Direct cargo commands:**
The make commands are aliases for changing the directory to the respective `generate-vX.Y.Z` directory and then running `cargo run --release`, i.e. for `v0.14.0` the command is:
```shell
cd backward-compatibility/generate-v0.14.0 && cargo run --release
```

Older frozen generator crates such as `generate-v0.11.0` and `generate-v0.11.1` still exist for historical inspection, but they do not have Makefile targets.

### Testing Generated Data

After generating new testing data, test it **without** pulling LFS (which would overwrite your changes):

```shell
# Use this target - it skips the LFS pull and uses locally generated files
make test-backward-compatibility-local

# Or run directly
cargo test --test 'backward_compatibility_*' -- --include-ignored
```

⚠️ **Important**: Do **not** use `make test-backward-compatibility` immediately after generating data, as it pulls LFS files first and will overwrite your newly generated data!

### Data Determinism

Generator output falls into two categories:

- **Frozen** (currently `0.11.0`, `0.11.1`, `0.13.0`, `0.13.10`, `0.13.20`): produced by generators that were non-deterministic across runs (e.g. `HashMap` iteration order — see [this bincode issue](https://github.com/TyOverby/bincode/issues/514) — or `SystemTime::now()` baked into serialized fields). Their `.bcode` files and `.ron` entries are committed via Git LFS and **must not** be regenerated as part of normal workflow — re-running their generators would produce different bytes for the same logical content. `make generate-backward-compatibility-all` skips these.
- **Deterministic** (any version added going forward): produced by generators that yield byte-identical output across runs. Their entries can be safely regenerated by `-all`.

The two lists live in the root `Makefile` as `FROZEN_BWC_VERSIONS` and `DETERMINISTIC_BWC_VERSIONS`.

### Why separate generator crates?

The backward compatibility system needs to:
1. **Generate** test data using old KMS versions (e.g., v0.11.0, v0.11.1)
2. **Load and verify** that this old data can be processed with the current KMS version

These operations require conflicting dependency versions. Additionally, **even patch versions can have incompatible dependencies**:
- v0.11.0 uses: alloy 1.1.2, tfhe 1.3.2, tfhe-versionable 0.6.0
- v0.11.1 uses: alloy 1.3.1, tfhe 1.3.3, tfhe-versionable 0.6.1

By maintaining separate generator crates per version, we can:
- Generate data with exact old KMS dependencies
- Test that data with the current KMS version
- Avoid dependency conflicts that prevent regeneration
- Ensure accurate backward compatibility testing

### Metadata Merging

Generators merge into existing metadata files rather than overwriting them, so multiple versions can coexist in a single `.ron`:

```ron
// backward-compatibility/data/kms.ron
[
    (kms_core_version_min: "0.11.0", ...),  // From generate-v0.11.0
    (kms_core_version_min: "0.11.1", ...),  // From generate-v0.11.1
]
```

Deterministic generators (`generate-v0.14.0` and later) works as follows: any existing entries whose `kms_core_version_min` matches a version being written are dropped first, then the freshly generated entries are appended. Entries for other versions — notably the frozen ones — are preserved verbatim. This is what makes `make generate-backward-compatibility-all` idempotent: re-running it does not accumulate duplicate rows for the deterministic versions it regenerates, while still leaving frozen-version entries intact.

The older frozen generators (`generate-v0.11.0` … `generate-v0.13.20`) use a plain append, which is one reason re-running them can produce duplicate `.ron` rows and why they must not be run as part of normal workflow (see [Data Determinism](#data-determinism)).

The `make generate-backward-compatibility-all` target only cleans and regenerates **deterministic** versions (listed in `DETERMINISTIC_BWC_VERSIONS` in the root `Makefile`). **Frozen** versions (`FROZEN_BWC_VERSIONS`, currently everything up to and including `0.13.20`) are left untouched — their data dirs are preserved and their generators are not invoked. The shared `.ron` files are never deleted by `-all`, so committed frozen entries survive across regenerations.

## Adding a test for an existing type

To add a test for a type that is already tested, you need to:

- go to the appropriate generator crate (e.g., `backward-compatibility/generate-v0.11.1/src/data_0_11.rs`) for the version you're testing
- create a const global variable with the metadata for that test
- create a `gen_...` method in the appropriate struct (ex: `KmsV0_11` for KMS objects)
- instantiate the object you want to test in it
  - If some private functions are needed to do so, the simplest solution is to copy paste them in a `helper_x_y.rs` file (you might need to create this file). Else, make them public or available under the "testing" feature and update the target commit of kms-core in this module. Be aware that if this requires updating the version, you need to add it instead and keep the old one as well.
  - If some _auxiliary_ data is needed for the test, make sure to serialize it using `store_versioned_auxiliary!` macro
- serialize it using the `store_versioned_test!` macro
- return the metadata of your test
- update the `gen_*_data` method (where "`*`" is the module where your new type is defined, e.g. `gen_kms_data`, `gen_kms_grpc_data`, `gen_threshold_fhe_data`) for the main struct (ex: `V0_11`) by calling your new method within the returned vector

The test will then be automatically selected when running `make test-backward-compatibility`.

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

If the type you are testing is already present in the releases already being tested for backwards compatibility (i.e. there is an appropriate `data_0_XX_X.rs` file and associated `Cargo.toml` that checks out a specific version of the KMS) then proceed to the next section.
If the type is new and does not exist in any release already, then start [here](#Adding-a-new-kms-core-release) instead, before proceeding to the next section.
Furthermore, be aware that in this situation you will likely end up in a catch-22 situation when you want to test a LFS release of the KMS that does not already exist. To circumvent this you can use a specific commit from the KMS repo instead of a release. For example by replacing this part in the toml file:
```
kms_0_13_0 = { git = "https://github.com/zama-ai/kms.git", package = "kms", rev = "v0.13.0"}
kms_grpc_0_13_0 = { git = "https://github.com/zama-ai/kms.git", package = "kms-grpc", rev = "v0.13.0"}
threshold_fhe_0_13_0 = { git = "https://github.com/zama-ai/kms.git", package = "threshold-fhe", rev = "v0.13.0", features = [
    "testing",
] }
```
with this
```
kms_0_13_0 = { git = "https://github.com/zama-ai/kms.git", package = "kms", rev = "e924c61"}
kms_grpc_0_13_0 = { git = "https://github.com/zama-ai/kms.git", package = "kms-grpc", rev = "e924c61"}
threshold_fhe_0_13_0 = { git = "https://github.com/zama-ai/kms.git", package = "threshold-fhe", rev = "e924c61", features = [
    "testing",
] }
```

Then you need to generate the data to test, e.g. running `make generate-backward-compatibility-v0.13.0`.

### In the backward-compatibility module

To add a test for a type that has not yet been tested, you should:

- go to `backward-compatibility/src/lib.rs`:
  - create a new struct that implements the `TestType` trait. Only the `test_filename` field is required, the others are metadata used to instantiate and check the new type. However, they should not use any kms-core internal type
  - add it to the `TestMetadataMOD` enum, where `MOD` is the name of the module to test
- add a new testcase in the appropriate generator crate using the procedure in the previous paragraph. If the type comes from a new module, you should also:
  - go to `backward-compatibility/src/lib.rs` and create a new `TestMetadataZzz` module
  - go to the generator's `src/data_x_y.rs` and create a new `gen_*_data` method (e.g. `gen_kms_data`, `gen_kms_grpc_data`, `gen_threshold_fhe_data`)
  - go to the generator's `src/main.rs`:
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

In the tested module, you should update the test (ex: `kms-core/core/threshold/tests/backward_compatibility_kms.rs`) to handle your new test type.
To do this, create a function that first loads and unversionizes the serialized object, and then checks its value against a new instantiated object generated thanks to the provided metadata:

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

## Coverage gate for `VersionsDispatch` enums

A test at [`core/service/tests/versioned_enum_coverage.rs`](../../core/service/tests/versioned_enum_coverage.rs) runs as part of the `core/service` test suite, but its scan is workspace-wide: it uses `cargo metadata` to enumerate every workspace member and statically inspects each one for `#[derive(VersionsDispatch)]` enums, enforcing two invariants:

1. **Contiguous variants** — variants must be named `V0`, `V1`, `V2`, … in order.
2. **Fixture coverage** — every dispatch type (with its `Versions` suffix stripped) must appear as a variant of one of the `TestMetadata*` enums backing `backward-compatibility/data/{kms,kms-grpc,threshold-fhe}.ron`, *or* be explicitly listed in the `ALLOW_UNCOVERED` constant in the same test file.

The default expectation when you add a new `#[derive(VersionsDispatch)]` enum is to add a direct `.ron` fixture for it, as described in [Adding a test for a new type](#adding-a-test-for-a-new-type). `ALLOW_UNCOVERED` is for inner types that are only reachable as fields of a parent type that already has a fixture.

### Updating `ALLOW_UNCOVERED`

The `ALLOW_UNCOVERED` list is found in [`core/service/tests/versioned_enum_coverage.rs`](../../core/service/tests/versioned_enum_coverage.rs)
where each entry must carry a comment that records:

- **Who uses it** — one parent struct/enum that contains the type as a field, or the precise way the type is otherwise reached (e.g. as a signcrypted payload). One example is enough — you don't need to enumerate every parent.
- **Who covers it** — one `*Test` fixture in `backward-compatibility/src/lib.rs` whose serialized output transitively exercises the type.

Example:

```rust
// Field of ThresholdFheKeys.public_material.
// Covered via ThresholdFheKeysTest.
"PublicKeyMaterial",
```

⚠️ **The list is manually curated and not self-verifying.** If a developer later starts serializing one of these types directly — or removes the parent field that used to carry it — the coverage gate keeps passing (the type is still on the allowlist) while no `.ron` fixture actually exercises it. The result is a silent backward-compatibility gap.

**Whenever you touch a type listed in `ALLOW_UNCOVERED`, re-audit its entry:**

- If the type is now serialized at a top level (e.g. as a stored object, a gRPC field body, or the root of a new fixture), **remove it from `ALLOW_UNCOVERED` and add a direct fixture** following [Adding a test for a new type](#adding-a-test-for-a-new-type).
- If the parent named in the comment no longer carries the type, rewrite the comment to point at the current parent — or, if no parent remains, remove the entry.
- If the type is deleted, remove the entry: stale allowlist names go unmatched and silently rot.

Tracking ticket for replacing this manual list with structural reachability checks: [zama-ai/kms-internal#3028](https://github.com/zama-ai/kms-internal/issues/3028).

## Adding a new kms-core release

⚠️ **Important**: Before adding a new version, check for dependency compatibility. See [`backward-compatibility/ADDING_NEW_VERSIONS.md`](../../backward-compatibility/ADDING_NEW_VERSIONS.md) for detailed instructions.

Any non-determinism the new generator inherits from `kms-core` itself (e.g., a new versioned struct that contains a `HashMap`, or a struct field populated from `SystemTime::now()`) must be fixed in `kms-core` via a fresh version bump before the corresponding generator can be added to `DETERMINISTIC_BWC_VERSIONS`. The freeze convention exists precisely because retroactively fixing non-determinism in old generators is not safe — old data on disk would no longer match.

To add data for a new released version of kms-core, you should:

- **Check compatibility**: Verify the new version's dependencies (especially `serde`, `alloy`, `tfhe`) are compatible with existing generator versions
- **If compatible**: Add to existing generator (e.g., add v0.12.0 to `generate-v0.11.1` if dependencies match)
- **If incompatible**: Create a new generator crate (e.g., `generate-v0.12.0`)

See [`backward-compatibility/ADDING_NEW_VERSIONS.md`](../../backward-compatibility/ADDING_NEW_VERSIONS.md) for detailed instructions.

**For a new generator crate:**
1. Copy an existing generator: `cp -r generate-v0.11.1 generate-v0.12.0`
2. Update `Cargo.toml`: package name, version, and KMS dependencies
3. Update `src/data_0_11.rs`: imports and `VERSION_NUMBER`
4. Add to `Makefile`:
   - Append the new version number (e.g. `0.14.0`) to `DETERMINISTIC_BWC_VERSIONS`. **Do not** add it to `FROZEN_BWC_VERSIONS` — that list is closed at `0.13.20`.
   - Add a `generate-backward-compatibility-v0.14.0` recipe matching the existing pattern.
   - Add the crate to the root `Cargo.toml` exclude list.
5. Test: `make generate-backward-compatibility-all`

In the generator's `src/data_x_y.rs`:

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

- add a new version `v1` to the `XXXVersions` enum associated to the type `XXX` (ex: `PrivateSigKeyVersions` for `PrivateSigKey`)
- **keep** the `PrivateSigKey` old definition and rename it to `PrivateSigKeyV0`
- replace the `Versionize` derive trait with the `Version` one (import if from `tfhe-versionable` if needed)
- remove the `#[versionize(XXXVersions)]` attribute
- add your new `XXX` type (ex: `PrivateSigKey`) definition and add both the `Versionize` derive trait and the `#[versionize(XXXVersions)]` attribute to it
- implement the `Upgrade` trait for the old definition (ex: `PrivateSigKeyV0`)

It is important to understand that the old definition **must not** be changed whenever there's a breaking change. Also, only the latest definition should be annotated with both versionize macros.

It should look like the following:

```rust
#[derive(..., VersionsDispatch)]
pub enum PrivateSigKeyVersions {
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
#[versionize(PrivateSigKeyVersions)]
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

For more in-depth scenarios, you can take a look at the [tfhe-rs examples](https://github.com/zama-ai/tfhe-rs/tree/main/utils/tfhe-versionable/examples).

## Updating the test without testing backward compatibility

If you want to update the test data _without_ actually testing for backward compatibility, you can follow these steps:

1. In the PR (PR1) that contains breaking changes for backward compatibility, disable the related backward test
1. Once PR1 is merged, create a new PR (PR2) where you update the appropriate generator's `Cargo.toml` (e.g., `backward-compatibility/generate-v0.11.1/Cargo.toml`) with the commit hash that correspond to PR1 being merged to `main`
1. Then you run `make generate-backward-compatibility-all` to regenerate testing objects for all versions
1. Re-enable the backward compatibility tests that were disabled in PR1
1. Push the changes to PR2 and the tests should pass

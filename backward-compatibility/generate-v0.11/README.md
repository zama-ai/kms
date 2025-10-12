# Backward Compatibility Data Generation

This crate is responsible for generating test data for backward compatibility tests. It is **separate** from the parent `backward-compatibility` crate to avoid dependency conflicts between old and new versions of KMS dependencies.

## Purpose

The `backward-compatibility` crate needs to:
1. **Generate** test data using old KMS versions (e.g., v0.11.1)
2. **Load and test** that data with the current KMS version

These two operations require conflicting dependency versions (e.g., different versions of `cfg_if`, `serde`, `tfhe`, etc.), which cannot coexist in the same crate due to Cargo's dependency resolution.

## Solution

By separating generation into version-specific subdirectory crates:
- **`backward-compatibility/generate-v0.11`**: Contains v0.11.x-specific dependencies and data generation logic
- **`backward-compatibility`**: Contains only loading/testing logic with current dependencies

This allows us to:
- Generate data with old KMS versions without conflicts
- Test that data with the current KMS version
- Avoid the dependency version conflicts that previously prevented regeneration

## How It Works

The backward compatibility system operates in two independent phases:

### 1. **Data Generation** (Development/Manual)
Uses **old KMS code** (v0.11.1) to create serialized test data:
```bash
cd backward-compatibility/generate-v0.11
cargo run --release
```
- Runs in isolation with v0.11.1 dependencies
- Generates versioned binary data files
- Stores data in `../data/` directory

### 2. **Data Verification** (CI/Testing)
Uses **current KMS code** to load and verify the old data:
```bash
make test-backward-compatibility        # CI: pulls LFS data first
make test-backward-compatibility-local  # Dev: uses local data
```
- Runs with current workspace dependencies
- Loads old serialized data
- Verifies it deserializes correctly with current code

**Key Benefit**: Both processes maintain completely independent dependency trees, eliminating version conflicts while ensuring backward compatibility across KMS releases.

## Quick Reference

**Complete workflow for regenerating and testing data:**

```bash
# 1. Generate new data
make generate-backward-compatibility-v0.11

# 2. Test the new data (without LFS pull)
make test-backward-compatibility-local

# 3. Review changes
git status
git diff backward-compatibility/data/

# 4. Commit if tests pass
git add backward-compatibility/data/
git commit -m "Regenerate backward compatibility data for v0.11"
```

## Usage

### Generating Test Data

To regenerate backward compatibility test data, you can use either:

**Option 1: Using Make (from repository root)**
```bash
make generate-backward-compatibility-v0.11
```

**Option 2: Direct cargo command**
```bash
cd backward-compatibility/generate-v0.11
cargo run --release
```

This will:
1. Import the specified old KMS versions (currently v0.11.1 as of 2025-10-10)
2. Generate test data for all supported types
3. Store the data in `../data/`
4. Create metadata files describing the tests

### Testing Generated Data

After generating data, test it **without** pulling LFS (which would overwrite your changes):

```bash
# From repository root
make test-backward-compatibility-local

# Or directly
cargo test --test 'backward_compatibility_*' -- --include-ignored
```

⚠️ **Important**: Don't use `make test-backward-compatibility` after generating, as it pulls LFS files first and will overwrite your newly generated data!

### Adding a New Version

⚠️ **Important**: Before adding a new version, check if its dependencies are compatible with existing versions in this generator. If there are conflicts (e.g., different major versions of `serde`, `cfg-if`, etc.), you may need to create a separate generator crate.

**See the detailed guide**: [`../ADDING_NEW_VERSIONS.md`](../ADDING_NEW_VERSIONS.md)

**Quick steps for compatible versions:**

1. Add the version dependencies to `Cargo.toml`:
```toml
kms_0_12 = { git = "https://github.com/zama-ai/kms.git", package = "kms", rev = "v0.12.0" }
# ... other dependencies
```

2. Create `src/data_0_12.rs` implementing the `KMSCoreVersion` trait

3. Update `src/main.rs` to generate data for the new version

4. Run the generator to create the test data

**If dependencies conflict**: Follow the instructions in [`ADDING_NEW_VERSIONS.md`](../ADDING_NEW_VERSIONS.md) to create a separate generator crate.

## Architecture

- **`src/generate.rs`**: Common utilities for data generation and storage
- **`src/data_0_11.rs`**: Version-specific generation logic for v0.11
- **`src/main.rs`**: Binary entry point that orchestrates generation
- **`src/lib.rs`**: Library interface for shared functionality

## Versioning

This crate's version (`0.11.1`) matches the KMS version it generates data for, not the current workspace version. This makes it immediately clear which KMS versions this generator handles.

**Naming Pattern:**
- Package name: `backward-compatibility-generate-v0-11` (note: dash `-`, not dot `.` in version)
- Directory: `generate-v0.11` (dots allowed in directory names)
- Version: `0.11.1` (matches KMS version it generates)

**Examples:**
- `backward-compatibility-generate-v0-11` version `0.11.1` → Generates for KMS v0.11.x
- `backward-compatibility-generate-v0-13` version `0.13.0` → Would generate for KMS v0.13.x (future)

## Related Issue

This refactoring addresses the long-term fix described in issue #2759, which identified that dependency conflicts prevented regenerating backward compatibility test data.

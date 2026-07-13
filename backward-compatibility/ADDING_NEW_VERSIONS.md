# Adding New KMS Versions to Backward Compatibility Tests

## Quick Start

When adding a new KMS version (e.g., v0.14.0), follow these steps:

### Step 1: Check Dependency Compatibility

Before adding a new version, verify it's compatible with existing generator versions:

```bash
# Check key dependencies in the new release
curl -s "https://raw.githubusercontent.com/zama-ai/kms/v0.14.0/Cargo.toml" | grep -E "serde|alloy|tfhe"

# Compare with the most recent deterministic generator (currently v0.14.0)
grep -E "serde|alloy|tfhe" backward-compatibility/generate-v0.14.0/Cargo.toml
```

**Key dependencies to check:**
- `serde` (most likely to have breaking changes)
- `alloy-*` (alloy-primitives, alloy-sol-types)
- `tfhe` / `tfhe-versionable`
- `bincode`

### Step 2A: If Dependencies Are Compatible

Add the version to the most recent compatible deterministic generator (e.g., `generate-v0.14.0`):

1. **Add dependencies** to `backward-compatibility/generate-v0.14.0/Cargo.toml`:
```toml
kms_0_14_0 = { git = "https://github.com/zama-ai/kms.git", package = "kms", rev = "v0.14.0" }
kms_grpc_0_14_0 = { git = "https://github.com/zama-ai/kms.git", package = "kms-grpc", rev = "v0.14.0" }
algebra_0_14_0 = { git = "https://github.com/zama-ai/kms.git", package = "threshold-algebra", default-features = false, rev = "v0.14.0" }
threshold_execution_0_14_0 = { git = "https://github.com/zama-ai/kms.git", package = "threshold-execution", default-features = false, rev = "v0.14.0", features = ["testing"] }
# and so on, see the examples in kms/backward-compatibility/generate-vX.X.X/Cargo.toml
```

2. **Create** `backward-compatibility/generate-v0.14.0/src/data_0_14.rs` implementing `KMSCoreVersion` trait

3. **Update** `backward-compatibility/generate-v0.14.0/src/main.rs` to generate data for v0.14.0

4. **Update** root `Makefile`:
   - Add v0.14.0 to `DETERMINISTIC_BWC_VERSIONS`
   - Add a `generate-backward-compatibility-v0.14.0` target if this version has its own generator crate

5. **Generate the data**:
```bash
# From repository root - generates all versions
make generate-backward-compatibility-all
```

6. **Test the generated data** (without pulling LFS):
```bash
make test-backward-compatibility-local
```

⚠️ **Important**: Always use `make generate-backward-compatibility-all` for normal regeneration. It skips frozen versions and refreshes only the deterministic versions listed in `DETERMINISTIC_BWC_VERSIONS`.

### Step 2B: If Dependencies Are Incompatible

Create a new generator crate for the incompatible version:

1. **Copy the closest previous generator**:

For eaxample:

```bash
cp -r backward-compatibility/generate-v0.13.20 backward-compatibility/generate-v0.14.0
```

2. **Update** `backward-compatibility/generate-v0.14.0/Cargo.toml`:
   - Package name: `backward-compatibility-generate-v0-14-0` (use dashes, include patch version)
   - Package version: `0.14.0` (matches the KMS version exactly)
   - Update all KMS dependencies to v0.14.0 (or to the release commit if the tag is not available yet)
   - Update dependency versions (serde, alloy, tfhe) to match v0.14.0's requirements

3. **Update** the copied source files:
   - Rename `backward-compatibility/generate-v0.14.0/src/data_0_13.rs` to `data_0_14.rs`
   - Change imports from `kms_0_13_20`, `kms_grpc_0_13_20`, and sibling aliases to their `0_14_0` names
   - Update `VERSION_NUMBER` to `"0.14.0"`
   - Update `src/lib.rs` and `src/main.rs` module names and imports to use `data_0_14`
   - Fix any API changes between v0.13.20 and v0.14.0

4. **Update** root `Cargo.toml` to exclude the new generator:
```toml
exclude = [
    "backward-compatibility",
    "backward-compatibility/generate-v0.11.0",
    "backward-compatibility/generate-v0.11.1",
    "backward-compatibility/generate-v0.13.0",
    "backward-compatibility/generate-v0.13.10",
    "backward-compatibility/generate-v0.13.20",
    "backward-compatibility/generate-v0.14.0",  # Add this
]
```

5. **Update** root `Makefile`:
```makefile
DETERMINISTIC_BWC_VERSIONS := 0.14.0

generate-backward-compatibility-v0.14.0:
	cd backward-compatibility/generate-v0.14.0 && cargo run --release
```

6. **Do not add the new version to `FROZEN_BWC_VERSIONS`** unless the generator is known to be non-deterministic and the generated data is intentionally frozen (some excptions on this rule is if we have to make backport some fixes and make a minor release from one of the v0.13.x versions). `clean-backward-compatibility-data` derives deterministic data directories from `DETERMINISTIC_BWC_VERSIONS`.
In more detail, the kms code initially had versioned data structures that could not be serialized deterministically (e.g., due to the use of `HashMap`), this made changes harder to review because a lot of the backward compatibility data would change during re-generation. To fix this issue, we made sure all versioned data had deterministic serialization for v0.14.0 and later, and froze all prior backward compatibility data, defined in `FROZEN_BWC_VERSIONS`.

7. **Test the new generator**:
```bash
make generate-backward-compatibility-all
make test-backward-compatibility-local
```

8. **Update** this compatibility matrix below

## Version Compatibility Matrix

| Generator Crate | Package Name | KMS Versions | Key Dependencies | Status |
|----------------|--------------|--------------|------------------|--------|
| `generate-v0.11.0` | `backward-compatibility-generate-v0-11-0` | v0.11.0 | serde 1.0.219, alloy 1.1.2, tfhe 1.3.2 | Frozen |
| `generate-v0.11.1` | `backward-compatibility-generate-v0-11-1` | v0.11.1 | serde 1.0.226, alloy 1.3.1, tfhe 1.3.3 | Frozen |
| `generate-v0.13.0` | `backward-compatibility-generate-v0-13-0` | v0.13.0 | — | Frozen |
| `generate-v0.13.10` | `backward-compatibility-generate-v0-13-10` | v0.13.10 | — | Frozen |
| `generate-v0.13.20` | `backward-compatibility-generate-v0-13-20` | v0.13.20 | — | Frozen |
| `generate-v0.14.0` | `backward-compatibility-generate-v0-14-0` | v0.14.0 | tfhe-versionable 0.7.0, tfhe 1.6.1, alloy 1.4.1, serde 1.0.228 | Deterministic |

**Note**: v0.11.0 and v0.11.1 require separate generators due to incompatible alloy and tfhe versions.

## When to Create a New Generator

Create a new generator crate when:

1. **Major dependency version change**: New KMS version uses incompatible major versions (e.g., serde 1.x → 2.x)
2. **Cargo resolution fails**: Adding the new version causes compilation errors
3. **Conflicting transitive dependencies**: Even if direct deps match, transitive deps may conflict

## Testing Compatibility

Before committing, verify the generator builds:

```bash
cd backward-compatibility/generate-v0.14.0
cargo check
cargo build --release
```

If you see errors like:
```
error: failed to select a version for `serde`
```

This indicates incompatibility - create a new generator crate.

## Regenerating All Data

To regenerate data for all versions:

```bash
# Recommended: Generate all versions at once
make generate-backward-compatibility-all
```

This will:
1. Clean deterministic-version data directories
2. Run the deterministic generators listed in `DETERMINISTIC_BWC_VERSIONS`
3. Replace metadata entries for regenerated versions while preserving frozen entries

Or run individual generators:
```bash
make generate-backward-compatibility-v0.14.0
```

⚠️ **Important**: Frozen generator crates can still be run directly for historical investigation, but their output may be non-deterministic and should not be committed. Additionally, running deterministic generators is idempotent for all generators listed in `DETERMINISTIC_BWC_VERSIONS` and if that is not the case, it must be fixed.

## Best Practices

1. **Always check compatibility first** - saves time and prevents issues
2. **Use exact version numbers** - `generate-v0.11.0` not `generate-v0.11`
3. **One version per generator for incompatible deps** - don't mix incompatible versions
4. **Document version ranges** - update the compatibility matrix above
5. **Test after adding** - verify both generation and loading work
6. **Update this document** - keep the compatibility matrix current
7. **Version the generator crate** - set the crate version to match the KMS version exactly (e.g., `generate-v0.11.0` should be version `0.11.0`)
8. **Use `make generate-backward-compatibility-all`** - refreshes deterministic data while preserving frozen entries

## Troubleshooting

### Error: "failed to select a version for X"

**Cause**: Dependency version conflict between KMS versions

**Solution**: Create a new generator crate (Step 2B above)

### Error: "cannot find type X in crate Y"

**Cause**: API changes between KMS versions

**Solution**: Update the generation code in `data_x_y.rs` to use the correct API for that version

### Error: "feature X is not available"

**Cause**: Feature flags changed between versions

**Solution**: Update the feature flags in `Cargo.toml` for that version's dependencies

# Adding New KMS Versions to Backward Compatibility Tests

## Quick Start

When adding a new KMS version (e.g., v0.12.0), follow these steps:

### Step 1: Check Dependency Compatibility

Before adding a new version, verify it's compatible with existing generator versions:

```bash
# Check key dependencies in the new release
curl -s "https://raw.githubusercontent.com/zama-ai/kms/v0.12.0/Cargo.toml" | grep -E "serde|alloy|tfhe"

# Compare with the most recent generator (v0.11.1)
grep -E "serde|alloy|tfhe" backward-compatibility/generate-v0.11.1/Cargo.toml
```

**Key dependencies to check:**
- `serde` (most likely to have breaking changes)
- `alloy-*` (alloy-primitives, alloy-sol-types)
- `tfhe` / `tfhe-versionable`
- `bincode`

### Step 2A: If Dependencies Are Compatible

Add the version to the most recent compatible generator (e.g., `generate-v0.11.1`):

1. **Add dependencies** to `backward-compatibility/generate-v0.11.1/Cargo.toml`:
```toml
kms_0_12_0 = { git = "https://github.com/zama-ai/kms.git", package = "kms", rev = "v0.12.0" }
kms_grpc_0_12_0 = { git = "https://github.com/zama-ai/kms.git", package = "kms-grpc", rev = "v0.12.0" }
threshold_fhe_0_12_0 = { git = "https://github.com/zama-ai/kms.git", package = "threshold-fhe", rev = "v0.12.0", features = ["testing"] }
```

2. **Create** `backward-compatibility/generate-v0.11.1/src/data_0_12.rs` implementing `KMSCoreVersion` trait

3. **Update** `backward-compatibility/generate-v0.11.1/src/main.rs` to generate data for v0.12.0

4. **Update** root `Makefile` to add v0.12.0 target (optional, for individual generation)

5. **Generate the data**:
```bash
# From repository root - generates all versions
make generate-backward-compatibility-all
```

6. **Test the generated data** (without pulling LFS):
```bash
make test-backward-compatibility-local
```

⚠️ **Important**: Always use `make generate-backward-compatibility-all` to ensure all versions are regenerated with merged metadata!

### Step 2B: If Dependencies Are Incompatible

Create a new generator crate for the incompatible version:

1. **Copy the most recent generator**:
```bash
cp -r backward-compatibility/generate-v0.11.1 backward-compatibility/generate-v0.12.0
```

2. **Update** `backward-compatibility/generate-v0.12.0/Cargo.toml`:
   - Package name: `backward-compatibility-generate-v0-12-0` (use dashes, include patch version)
   - Package version: `0.12.0` (matches the KMS version exactly)
   - Update all KMS dependencies to v0.12.0
   - Update dependency versions (serde, alloy, tfhe) to match v0.12.0's requirements

3. **Update** `backward-compatibility/generate-v0.12.0/src/data_0_11.rs`:
   - Change imports from `kms_0_11_1` to `kms_0_12_0` (or rename file to `data_0_12.rs`)
   - Update `VERSION_NUMBER` to `"0.12.0"`
   - Fix any API changes between v0.11.1 and v0.12.0

4. **Update** root `Cargo.toml` to exclude the new generator:
```toml
exclude = [
    "backward-compatibility",
    "backward-compatibility/generate-v0.11.0",
    "backward-compatibility/generate-v0.11.1",
    "backward-compatibility/generate-v0.12.0"  # Add this
]
```

5. **Update** root `Makefile`:
```makefile
generate-backward-compatibility-v0.12.0:
	cd backward-compatibility/generate-v0.12.0 && cargo run --release

generate-backward-compatibility-all: clean-backward-compatibility-data \
    generate-backward-compatibility-v0.11.0 \
    generate-backward-compatibility-v0.11.1 \
    generate-backward-compatibility-v0.12.0  # Add this
	@echo "✅ Generated backward compatibility data for all versions"
```

6. **Update** `clean-backward-compatibility-data` target in Makefile:
```makefile
clean-backward-compatibility-data:
	rm -f backward-compatibility/data/*.ron
	rm -rf backward-compatibility/data/0_11_0
	rm -rf backward-compatibility/data/0_11_1
	rm -rf backward-compatibility/data/0_12_0  # Add this
```

7. **Test the new generator**:
```bash
make generate-backward-compatibility-all
make test-backward-compatibility-local
```

8. **Update** this compatibility matrix below

## Version Compatibility Matrix

| Generator Crate | Package Name | KMS Versions | Key Dependencies | Status |
|----------------|--------------|--------------|------------------|--------|
| `generate-v0.11.0` | `backward-compatibility-generate-v0-11-0` | v0.11.0 | serde 1.0.219, alloy 1.1.2, tfhe 1.3.2 | ✅ Active |
| `generate-v0.11.1` | `backward-compatibility-generate-v0-11-1` | v0.11.1 | serde 1.0.226, alloy 1.3.1, tfhe 1.3.3 | ✅ Active |
| `generate-v0.12.0` | `backward-compatibility-generate-v0-12-0` | v0.12.0+ | TBD | 🚧 Future (when needed) |

**Note**: v0.11.0 and v0.11.1 require separate generators due to incompatible alloy and tfhe versions.

## When to Create a New Generator

Create a new generator crate when:

1. **Major dependency version change**: New KMS version uses incompatible major versions (e.g., serde 1.x → 2.x)
2. **Cargo resolution fails**: Adding the new version causes compilation errors
3. **Conflicting transitive dependencies**: Even if direct deps match, transitive deps may conflict

## Testing Compatibility

Before committing, verify the generator builds:

```bash
cd backward-compatibility/generate-v0.11
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
1. Clean old data files
2. Run each generator in sequence (v0.11.0, v0.11.1, etc.)
3. Merge metadata from all versions into combined `.ron` files

Or run individual generators:
```bash
make generate-backward-compatibility-v0.11.0
make generate-backward-compatibility-v0.11.1
```

⚠️ **Important**: When running individual generators, they will append to existing metadata. Always clean first with `make clean-backward-compatibility-data` to avoid duplicates.

## Best Practices

1. **Always check compatibility first** - saves time and prevents issues
2. **Use exact version numbers** - `generate-v0.11.0` not `generate-v0.11`
3. **One version per generator for incompatible deps** - don't mix incompatible versions
4. **Document version ranges** - update the compatibility matrix above
5. **Test after adding** - verify both generation and loading work
6. **Update this document** - keep the compatibility matrix current
7. **Version the generator crate** - set the crate version to match the KMS version exactly (e.g., `generate-v0.11.0` should be version `0.11.0`)
8. **Use `make generate-backward-compatibility-all`** - ensures proper metadata merging

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

# Adding New KMS Versions to Backward Compatibility Tests

## Quick Start

When adding a new KMS version (e.g., v0.12), follow these steps:

### Step 1: Check Dependency Compatibility

Before adding a new version, verify it's compatible with existing versions in the generator:

```bash
# Check the serde version in the new release
curl -s "https://raw.githubusercontent.com/zama-ai/kms/v0.12.0/Cargo.toml" | grep "serde ="

# Compare with current generator dependencies
grep "serde =" backward-compatibility/generate-v0.11/Cargo.toml
```

**Key dependencies to check:**
- `serde` (most likely to have breaking changes)
- `cfg-if`
- `bincode`
- `tfhe` / `tfhe-versionable`

### Step 2A: If Dependencies Are Compatible

Add the version to the existing `generate-v0.11` crate:

1. **Add dependencies** to `backward-compatibility/generate-v0.11/Cargo.toml`:
```toml
kms_0_12 = { git = "https://github.com/zama-ai/kms.git", package = "kms", rev = "v0.12.0" }
kms_grpc_0_12 = { git = "https://github.com/zama-ai/kms.git", package = "kms-grpc", rev = "v0.12.0" }
threshold_fhe_0_12 = { git = "https://github.com/zama-ai/kms.git", package = "threshold-fhe", rev = "v0.12.0", features = ["testing"] }
```

2. **Create** `backward-compatibility/generate-v0.11/src/data_0_12.rs` implementing `KMSCoreVersion` trait

3. **Update** `backward-compatibility/generate-v0.11/src/main.rs` to generate data for v0.12

4. **Generate the data**:
```bash
# From repository root
make generate-backward-compatibility-v0.11

# Or directly
cd backward-compatibility/generate-v0.11
cargo run --release
```

5. **Test the generated data** (without pulling LFS):
```bash
# From repository root
make test-backward-compatibility-local

# Or directly
cargo test --test 'backward_compatibility_*' -- --include-ignored
```

⚠️ **Important**: Use `test-backward-compatibility-local` (not `test-backward-compatibility`) to avoid overwriting your generated data with LFS files!

### Step 2B: If Dependencies Are Incompatible

Create a new generator crate for the incompatible version:

1. **Create new directory**:
```bash
mkdir -p backward-compatibility/generate-v0.13
```

2. **Copy and modify** the existing generator:
```bash
cp -r backward-compatibility/generate-v0.11/* backward-compatibility/generate-v0.13/
```

3. **Update** `backward-compatibility/generate-v0.13/Cargo.toml`:
   - Update package name to `backward-compatibility-generate-v0-13` (note: use dash, not dot)
   - Update package version to `0.13.0` (matches the KMS version it generates)
   - Update dependency versions to match v0.13

4. **Update** `Cargo.toml` at repo root to exclude the new generator:
```toml
exclude = [
    "backward-compatibility",
    "backward-compatibility/generate-v0.11",
    "backward-compatibility/generate-v0.13"  # Add this
]
```

5. **Update** `backward-compatibility/generate-v0.13/src/main.rs`:
   - Keep only the v0.13 generation logic
   - Remove older version logic

6. **Document** in this file which generator handles which versions

## Version Compatibility Matrix

| Generator Crate | Package Name | KMS Versions | Serde Version | Status |
|----------------|--------------|--------------|---------------|--------|
| `generate-v0.11` | `backward-compatibility-generate-v0-11` | v0.11.x, v0.12.x | 1.0.210-1.0.226 | ✅ Active |
| `generate-v0.13` | `backward-compatibility-generate-v0-13` | v0.13.x+ | 2.0.x | 🚧 Future (when needed) |

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
# For v0.11 and v0.12 (compatible versions)
make generate-backward-compatibility-v0.11

# For v0.13+ (if incompatible generator exists in the future)
make generate-backward-compatibility-v0.13
```

Or run directly:
```bash
cd backward-compatibility/generate-v0.11
cargo run --release
```

## Best Practices

1. **Always check compatibility first** - saves time and prevents issues
2. **Document version ranges** - update the compatibility matrix above
3. **Keep generators minimal** - only include necessary versions
4. **Test after adding** - verify both generation and loading work
5. **Update this document** - keep the compatibility matrix current
6. **Version the generator crate** - set the crate version to match the KMS version it generates (e.g., `generate-v0.11` should be version `0.11.1`)

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

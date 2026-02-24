# KMS Integration Tests

## Quick Reference

| Test Type | Command |
|-----------|---------|
| **Native (fast)** | `cargo test --test integration_test_isolated --features testing` |
| **Native (threshold PRSS tests)** | `cargo nextest run --test integration_test_isolated --features threshold_tests` |
| **K8s Threshold (kind)** | `cargo test --test kubernetes_test_threshold_isolated --features kind_tests` |
| **K8s Centralized (kind)** | `cargo test --test kubernetes_test_centralized_isolated --features kind_tests` |

## Folder Layout

- `tests/integration/` — native integration tests (no Kind cluster required)
- `tests/kind-testing/` — Kubernetes/Kind integration tests

## Feature flags (what they enable)

- `testing`
  - Enables test helper code used by integration tests.
- `threshold_tests`
  - Implies `testing`.
  - Enables threshold PRSS tests in `tests/integration/integration_test_isolated.rs`.
  - Compiles setup helpers that run threshold servers with `run_prss=true`
    (`setup_isolated_threshold_cli_test_with_prss*`).
  - Enables PRSS-heavy flows/tests (preproc+keygen, MPC context init/switch,
    reshare, full-gen default preproc).
  - Only gates code/tests; it does **not** generate test material by itself.
  - **Does not** enable Kind/Kubernetes tests.
- `kind_tests`
  - Implies `testing`.
  - Enables Kubernetes/Kind test binaries under `tests/kind-testing/`.
  - Requires a running Kind cluster.

### `threshold_tests` and pre-generated material

- `threshold_tests` turns on `run_prss=true` setup paths; servers load PRSS from test material at startup.
- For **Test** params, missing PRSS can be initialized live.
- For **Default** params (`setup_isolated_threshold_cli_test_with_prss_default` / `full_gen_tests_default_*`), PRSS must be pre-generated in `test-material/default`. Missing PRSS for Default material is a **hard error** — setup fails immediately with a message pointing to `make generate-test-material-default`.
- Some `threshold_tests` generate PRSS live during the test (via `new_prss_isolated`) instead of loading it at startup — these do **not** require pre-generated PRSS.
  - Examples: `test_threshold_mpc_context_init`, `test_threshold_mpc_context_switch_6`, `test_threshold_reshare`.
- Tests using Default params without PRSS (`run_prss=false`) do **not** use PRSS at all — no pre-generated material needed.
- Generate Default PRSS locally with `make generate-test-material-default` (or `make generate-test-material-all`).

### Test gating patterns

Two patterns are used — which one to pick depends on whether the test body calls feature-gated helpers:

- **`#[cfg(feature = "threshold_tests")]` on the fn** — use when the test body calls helpers that only exist with the feature (e.g. `setup_*_with_prss`, `real_preproc_and_keygen_isolated`). The test is invisible to `cargo test` without the feature.
- **`#[cfg_attr(not(feature = "threshold_tests"), ignore)]` on the fn** — use when the test body compiles without the feature (e.g. tests using `setup_isolated_threshold_cli_test_signing_only` + `new_prss_isolated`). The test is visible but skipped without the feature.

### Test naming conventions (CI skip rules)

CI uses `--skip` prefix matching to exclude certain test groups from regular runs:
- `nightly_*` — skipped in regular CI, run only in nightly schedule
- `full_gen_tests_*` — skipped in regular CI, run only in nightly schedule
- `k8s_*` — skipped in native CI, run only in Kind cluster CI
- `isolated_test_example` — demo test, always skipped in CI

---

## Writing Native Isolated Tests

Native tests spawn KMS servers in-process. See `integration/integration_test_isolated.rs` for full documentation.

```rust
#[tokio::test]
async fn test_my_feature() -> Result<()> {
    // Setup returns (TempDir, ServerHandle, config_path)
    let (_dir, _server, config) = setup_isolated_centralized_cli_test("my_test").await?;
    
    // Run CLI command
    let output = Command::new(env!("CARGO_BIN_EXE_kms-core-client"))
        .args(["--config", config.to_str().unwrap(), "your-command"])
        .output()?;
    
    assert!(output.status.success());
    Ok(())
}
```

**Centralized setup variants:**
- `setup_isolated_centralized_cli_test` — basic centralized test
- `setup_isolated_centralized_cli_test_with_backup` — with backup vault
- `setup_isolated_centralized_cli_test_with_custodian_backup` — with custodian backup vault

**Threshold setup variants** (all take `party_count: usize`):
- `setup_isolated_threshold_cli_test` — basic threshold test
- `setup_isolated_threshold_cli_test_signing_only` — signing without pre-loaded PRSS
- `setup_isolated_threshold_cli_test_with_prss` — PRSS-enabled setup (`run_prss=true`) for preprocessing/keygen flows (requires `threshold_tests`)
- `setup_isolated_threshold_cli_test_with_backup` — with backup vault
- `setup_isolated_threshold_cli_test_with_custodian_backup` — with custodian backup vault
- `setup_isolated_threshold_cli_test_default` — Default FHE params, no PRSS (`run_prss=false`)
- `setup_isolated_threshold_cli_test_with_prss_default` — Default FHE + PRSS-enabled setup (`run_prss=true`; requires `threshold_tests` and pre-generated Default PRSS)

---

## Writing K8s Tests

K8s tests connect to a real kind cluster.

**Prerequisites:**
```bash
# Start kind cluster (threshold mode with TLS enabled by default)
./ci/scripts/deploy.sh --target kind-local --deployment-type threshold --block
```

**Which file to use:**
- **Threshold tests** → `core-client/tests/kind-testing/kubernetes_test_threshold_isolated.rs`
- **Centralized tests** → `core-client/tests/kind-testing/kubernetes_test_centralized_isolated.rs`

### Example Test (Threshold)

```rust
/// Test that keygen and CRS generation work correctly in K8s cluster.
#[tokio::test]
async fn k8s_test_keygen_and_crs() {
    let ctx = K8sTestContext::new("k8s_test_keygen_and_crs");

    // Generate FHE key
    let key_id = ctx.insecure_keygen().await;
    assert!(!key_id.is_empty(), "Key generation should return valid ID");

    // Generate CRS (Common Reference String)
    let crs_id = ctx.crs_gen().await;
    assert!(!crs_id.is_empty(), "CRS generation should return valid ID");

    // Verify they are different (independent operations)
    assert_ne!(key_id, crs_id, "Key ID and CRS ID should be different");

    ctx.pass();
}
```

### K8sTestContext Methods

| Method | Description |
|--------|-------------|
| `insecure_keygen()` | Generate FHE key |
| `crs_gen()` | Generate CRS |
| `execute(command)` | Run any CLI command |
| `pass()` | Mark test passed |

---

## See Also

- `integration/integration_test_isolated.rs` - Native test examples and full documentation
- `.github/workflows/kind-testing.yml` - K8s CI workflow

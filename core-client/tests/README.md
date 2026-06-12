# KMS Integration Tests

## Quick Reference

| Test Type | Command |
|-----------|---------|
| **Native (fast)** | `cargo test --test integration_test --features testing` |
| **Native (threshold preprocessing tests)** | `cargo nextest run --test integration_test --features threshold_tests` |
| **K8s Threshold (kind)** | `cargo test --test kubernetes_test_threshold --features kind_tests` |
| **K8s Centralized (kind)** | `cargo test --test kubernetes_test_centralized --features kind_tests` |

## Folder Layout

- `tests/integration/` — native integration tests (no Kind cluster required)
- `tests/kind-testing/` — Kubernetes/Kind integration tests

## Feature flags (what they enable)

- `testing`
  - Enables test helper code used by integration tests.
- `threshold_tests`
  - Implies `testing`.
  - Enables threshold preprocessing and keygen tests in `tests/integration/integration_test.rs`.
  - Compiles setup helpers that run threshold servers with `ensure_default_prss=true`
    (`setup_isolated_threshold_cli_test_with_prss*`).
  - Enables preprocessing-heavy flows/tests (preproc+keygen, MPC context init/switch,
    reshare, full-gen default preproc).
  - Only gates code/tests; it does **not** generate test material by itself.
  - **Does not** enable Kind/Kubernetes tests.
- `kind_tests`
  - Implies `testing`.
  - Enables Kubernetes/Kind test binaries under `tests/kind-testing/`.
  - Requires a running Kind cluster.

### `threshold_tests` and pre-generated material

- `threshold_tests` enables tests that require pre-generated material: **PRSS** (generated at server startup via `ensure_default_prss=true`) and **keygen preprocessing material** (offline DKG phase, required by `nightly_full_gen_tests_default_*`).
- For **Test** params, missing PRSS can be initialized live. For **Default** params, both PRSS and keygen preprocessing material must be pre-generated — missing either is a hard error.
- Some tests generate PRSS live during the test (via `new_prss`) — these do not require pre-generated PRSS. Used by MPC context init/switch and reshare tests.
- Generate the production-like required secure material (aka "default") with:
  `cargo run -p generate-test-material -- --output ./test-material --profile secure --parties 4,13`.

### Test gating patterns

Two patterns are used — which one to pick depends on whether the test body calls feature-gated helpers:

- **`#[cfg(feature = "threshold_tests")]` on the fn** — use when the test body calls helpers that only exist with the feature (e.g. `setup_*_with_prss`, `real_preproc_and_keygen`). The test is invisible to `cargo test` without the feature.
- **`#[cfg_attr(not(feature = "threshold_tests"), ignore)]` on the fn** — use when the test body compiles without the feature (e.g. tests using `setup_isolated_threshold_cli_test_signing_only` + `new_prss`). The test is visible but skipped without the feature.

### Test naming conventions (CI skip rules)

CI uses `--skip` prefix matching to exclude certain test groups from regular runs:
- `nightly_*` — skipped in regular CI, run only in nightly schedule
- `k8s_*` — skipped in native CI, run only in Kind cluster CI
- `isolated_test_example` — demo test, always skipped in CI

### CLI commands (`CCCommand`)

The client binary accepts these commands (passed as `CCCommand` in tests via `execute_cmd`). The `execute_cmd` helper automatically polls the corresponding `*Result` variant — test code only needs the initiating command.

| Command | Description | Requires epoch | Requires PRSS |
|---------|-------------|----------------|---------------|
| `InsecureKeyGen` | Threshold DKG with dummy preprocessing (insecure) | ✅ | ❌ |
| `KeyGen` | Threshold DKG with preprocessing (secure) | ✅ | ✅ |
| `PreprocKeyGen` | Offline preprocessing phase for DKG | ✅ | ✅ |
| `CrsGen` | Generate CRS (ZK ceremony, secure) | ✅ | ✅ |
| `InsecureCrsGen` | Generate CRS (insecure, no ZK) | ✅ | ❌ |
| `PublicDecrypt` | Public-key decryption | ✅ | ❌ |
| `UserDecrypt` | User-key decryption | ✅ | ❌ |
| `Encrypt` | Encrypt plaintext locally; fetches public FHE key from server | ❌ | ❌ |
| `NewEpoch` | Initialize an epoch (new PRSS and resharing of keys) | ❌ | ❌ |
| `NewMpcContext` | Register a new MPC context | ❌ | ❌ |
| `DestroyMpcContext` | Remove an MPC context | ❌ | ❌ |
| `DestroyMpcEpoch` | Remove an epoch | ❌ | ❌ |
| `BackupRestore` | Restore keys from backup vault | ❌ | ❌ |
| `NewCustodianContext` | Set up custodian key-recovery context | ❌ | ❌ |
| `CustodianRecoveryInit` | Initiate custodian recovery | ❌ | ❌ |
| `CustodianBackupRecovery` | Complete custodian recovery | ❌ | ❌ |
| `GetOperatorPublicKey` | Fetch operator verification key | ❌ | ❌ |

---

## Writing Native Isolated Tests

Native tests spawn KMS servers in-process. See `integration/integration_test.rs` for full documentation.

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
- `setup_isolated_threshold_cli_test_with_prss` — PRSS-enabled setup (`ensure_default_prss=true`) for preprocessing/keygen flows (requires `threshold_tests`)
- `setup_isolated_threshold_cli_test_with_backup` — with backup vault
- `setup_isolated_threshold_cli_test_with_custodian_backup` — with custodian backup vault
- `setup_isolated_threshold_cli_test_default` — Default FHE params, no PRSS (`ensure_default_prss=false`)
- `setup_isolated_threshold_cli_test_with_prss_default` — Default FHE + PRSS-enabled setup (`ensure_default_prss=true`; requires `threshold_tests` and pre-generated Default PRSS)

---

## Writing K8s Tests

K8s tests connect to a real kind cluster.

**Prerequisites:**
```bash
# Start kind cluster (threshold mode with TLS enabled by default)
./ci/scripts/deploy.sh --target kind-local --deployment-type threshold --block
```

**Which file to use:**
- **Threshold tests** → `core-client/tests/kind-testing/kubernetes_test_threshold.rs`
- **Centralized tests** → `core-client/tests/kind-testing/kubernetes_test_centralized.rs`

### Writing a K8s test

K8s tests use `K8sTestContext`, a lightweight struct defined at the top of each `kubernetes_test_*.rs` file. There is no server setup code — the cluster must already be running before the tests start. The current threshold tests cover: basic keygen+CRS, keygen uniqueness, CRS uniqueness, a full end-to-end keygen→encrypt→decrypt round-trip, and a multi-type scenario (encrypt `Ebool` and `Euint8` with the same key).

Test names must start with `k8s_` so that CI can skip them in non-Kind environments via `--skip k8s_`.

#### Example

```rust
#[tokio::test]
async fn k8s_test_keygen_and_crs() {
    let ctx = K8sTestContext::new("k8s_test_keygen_and_crs");

    let key_id = ctx.insecure_keygen().await;
    assert!(!key_id.is_empty(), "Key ID must not be empty");

    let crs_id = ctx.crs_gen().await;
    assert!(!crs_id.is_empty(), "CRS ID must not be empty");

    ctx.pass();
}
```

#### `K8sTestContext` methods

| Method | Description |
|--------|-------------|
| `new(name)` | Create context, print test header |
| `insecure_keygen()` | Run `InsecureKeyGen`, return key ID |
| `crs_gen()` | Run `CrsGen`, return CRS ID |
| `encrypt(key_id, plaintext, FheType)` | Fetch public FHE key from cluster, encrypt locally, write ciphertext to workspace; returns `EncryptionResult` (path + original plaintext + type) |
| `public_decrypt_from_file(enc)` | Send ciphertext from `EncryptionResult` to threshold parties, verify result matches original — panics on mismatch; returns `DecryptionResult` (party response count) |
| `workspace()` | Path to the per-test temp directory; use directly to inspect or reference output files (e.g. ciphertext files written by `encrypt()`) |
| `execute(CCCommand)` | Run any CLI command, return results |
| `config_path()` | Path to cluster config TOML |
| `pass(self)` | Print elapsed time and PASSED summary |

---

## See Also

- `integration/integration_test.rs` - Native test examples and full documentation
- `.github/workflows/kind-testing.yml` - K8s CI workflow

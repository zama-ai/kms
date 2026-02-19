# KMS Integration Tests

## Quick Reference

| Test Type | Command |
|-----------|---------|
| **Native (fast)** | `cargo test --test integration_test_isolated --features testing` |
| **K8s Threshold** | `cargo test --test kubernetes_test_threshold_isolated --features k8s_tests,testing` |
| **K8s Centralized** | `cargo test --test kubernetes_test_centralized_isolated --features k8s_tests,testing` |

---

## Writing Native Isolated Tests

Native tests spawn KMS servers in-process. See `integration_test_isolated.rs` for full documentation.

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
- `setup_isolated_threshold_cli_test_with_prss` — with PRSS setup (requires `k8s_tests` feature)
- `setup_isolated_threshold_cli_test_with_backup` — with backup vault
- `setup_isolated_threshold_cli_test_with_custodian_backup` — with custodian backup vault
- `setup_isolated_threshold_cli_test_default` — with Default FHE parameters
- `setup_isolated_threshold_cli_test_with_prss_default` — Default FHE + PRSS (requires `k8s_tests` feature)

---

## Writing K8s Tests

K8s tests connect to a real kind cluster.

**Prerequisites:**
```bash
# Start kind cluster (threshold mode with TLS enabled by default)
./ci/scripts/deploy.sh --target kind-local --deployment-type threshold --block
```

**Which file to use:**
- **Threshold tests** → `core-client/tests/kubernetes_test_threshold_isolated.rs`
- **Centralized tests** → `core-client/tests/kubernetes_test_centralized_isolated.rs`

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

- `integration_test_isolated.rs` - Native test examples and full documentation
- `.github/workflows/kind-testing.yml` - K8s CI workflow

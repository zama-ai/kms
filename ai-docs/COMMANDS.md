# Commands

Run from the repository root unless stated otherwise. See [EDITING.md](./EDITING.md#verification) for required checks.
Use the [Makefile](../Makefile) for target definitions, [README](../README.md) for prerequisites, and [rust-toolchain.toml](../rust-toolchain.toml) for the toolchain.

## Test selection

CI runs `cargo nextest run --profile ci --no-fail-fast`, one process per test. Prefer `cargo nextest run` locally so results match CI; it takes the same feature, package, and name-filter arguments as `cargo test`. Nextest skips doctests: run `cargo test --doc` for those.

| Command | Scope / caveat |
|---|---|
| `cargo nextest run -F testing` | Secure/default surface; some integration tests require Redis |
| `cargo nextest run -F testing --lib` | Unit tests; excludes Redis integration tests |
| `cargo nextest run -F testing -p <crate> <pattern>` | Focused test |
| `cargo nextest run -p kms-core-client -F e2e` | Client e2e, including insecure keygen and CRS |
| `cargo nextest run -p kms-core-client -F e2e,slow_tests` | Adds PRSS, preprocessing, insecure fast paths |
| `cargo nextest run -F slow_tests` | Full slow suite; can take hours |
| `cargo bench -p kms --bench meta_store --features testing` | Metastore microbenchmarks; append `-- --save-baseline before` or `-- --baseline before` |

## Feature flags

| Feature | Effect |
|---|---|
| `testing` | Exposes test helper APIs across crate boundaries. |
| `slow_tests` | Enables the long-running suite; implies `testing`. |
| `insecure` (`kms`, `kms-core-client`) | Development RPCs and mock enclave support. Forwards `threshold-networking/insecure`, which permits plaintext core-to-core transport and mock attestation. Debugging and testing only. |
| `e2e` (`kms-core-client`) | Client end-to-end tests; implies `testing` and `insecure`. |
| `non-wasm` (`kms`, default) | Native build. Code under `#[cfg(not(feature = "non-wasm"))]`, such as `core/service/src/client/js_api.rs`, is the wasm surface and is invisible to default builds. |

`make lint-package PACKAGE=<crate>` is a narrower lint, not full validation.
Dylint: `make install-dylint`, then `make lint-dylint`.

## Backward compatibility

- `make test-backward-compatibility`: pulls LFS, then tests stored vectors.
- `make test-backward-compatibility-local`: tests local vectors without LFS pull. **Use after regeneration; the other target overwrites generated data.**
- `make backward-snapshot-check BASE_REF=origin/main`: detects removed variants and suspicious layout/upgrade changes.
- `make backward-snapshot-report BASE_REF=origin/main OUTPUT_FILE=/tmp/kms-backward-snapshot-report.md`: writes the report.
- `make generate-backward-compatibility-all`: regenerates only deterministic versions.
- `make generate-backward-compatibility-v0.16.0`: example single-version regeneration.
- `make clean-backward-compatibility-data`: removes deterministic data; preserves frozen directories and shared `.ron` manifests.

The Makefile's `FROZEN_BWC_VERSIONS` must not be regenerated during normal work: their generators are nondeterministic.
Frozen-version target output must not be committed; it can append duplicate manifest entries.
See the [compatibility guide](../docs/developer/backward_compatibility.md) and [release procedure](../backward-compatibility/ADDING_NEW_VERSIONS.md).

## Other workflows

- Compose: [docker-compose.md](../docker-compose.md); Makefile targets `build-compose-*`, `start-compose-*`, `stop-compose-*`. **Stop targets remove volumes and orphans.**
- Custodian backup in compose: `KMS_DOCKER_BACKUP_SECRET_SHARING=true make start-compose-threshold`.
- Test material: `make generate-test-material-{all,default,testing}`; `make clean-test-material` removes `test-material`.
- Client commands/configs: [core-client guide](../docs/guides/core_client.md); run from `core-client/`.
- LFS: `make check-git-lfs`, `make pull-lfs-files`.

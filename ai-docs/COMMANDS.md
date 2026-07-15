# Commands

Commands that come up during ordinary work in this repo. All commands are expected to be run from the repository root unless noted otherwise.

Toolchain is pinned to Rust `1.97.0` via [`rust-toolchain.toml`](../rust-toolchain.toml). System prerequisites: `protoc`, `pkgconfig`, `openssl`, Docker.

## Build and lint

Build the workspace:

```
cargo build
```

Format + full lint. This mirrors CI; run before presenting any change as done (see [EDITING.md](./EDITING.md) — Build verification):

```
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
```

All-features clippy as a Makefile target:

```
make lint
```

Lint a single crate:

```
make lint-package PACKAGE=<crate-name>
```

Installing and running dylint:

```
make install-dylint
make lint-dylint
```


## Testing

Typical test run — uses the `testing` feature, includes unit and integration tests (some integration tests need Redis running locally):

```
cargo test -F testing
```

Skip the integration tests that need Redis (unit tests only):

```
cargo test -F testing --lib
```

Full slow suite (can take hours):

```
cargo test -F slow_tests
```

Narrow to a single test by name pattern, scoped to a crate:

```
cargo test -F testing -p <crate> <pattern>
```

Unit tests live alongside source in `#[cfg(test)]` blocks. Integration tests live in each crate's `tests/` directory, notably `core/service/tests/` and `core/threshold/tests/integration_redis.rs`.

## Backward compatibility

Run BC tests against stored LFS vectors (pulls LFS first, then runs the tests):

```
make test-backward-compatibility
```

Run against locally regenerated vectors — does NOT pull LFS:

```
make test-backward-compatibility-local
```

Generate and compare `VersionsDispatch` snapshots between a base ref and the current checkout. This detects removed version variants and suspicious type-layout or upgrade-body changes:

```
make backward-snapshot-check BASE_REF=origin/main
make backward-snapshot-report BASE_REF=origin/main OUTPUT_FILE=/tmp/kms-backward-snapshot-report.md
```

Direct cargo invocation (what the make targets call under the hood):

```
cargo test --test 'backward_compatibility_*' -- --include-ignored
```

Regenerate vectors. Versions are split into two lists in the `Makefile`:

- `FROZEN_BWC_VERSIONS` — currently `0.11.0`, `0.11.1`, `0.13.0`, `0.13.10`, `0.13.20`. Generators were non-deterministic across runs, so the committed `.bcode` files and `.ron` entries are the source of truth and must not be regenerated as part of normal workflow.
- `DETERMINISTIC_BWC_VERSIONS` — `0.14.0` and future versions. Re-running produces byte-identical output.

Regenerate all deterministic versions (cleans only deterministic data dirs first, then runs their generators; frozen versions are left untouched):

```
make generate-backward-compatibility-all
```

Regenerate for a single deterministic version:

```
make generate-backward-compatibility-v0.14.0
```

Per-version targets also exist for the frozen versions `v0.13.0`, `v0.13.10`, and `v0.13.20` (no targets for `v0.11.0` / `v0.11.1` — their generator crates are kept only for historical inspection). These frozen-version targets are for exceptional investigation only; running them can produce non-deterministic bytes and append duplicate metadata to the shared `.ron` files, so their output must not be committed.

Remove generated BC data for deterministic versions only — frozen data dirs and all shared `.ron` files are preserved:

```
make clean-backward-compatibility-data
```

**Gotcha**: do not run `make test-backward-compatibility` right after generating — the LFS pull will overwrite newly generated data. Use the `-local` variant.

Background and authoring workflow: [docs/developer/backward_compatibility.md](../docs/developer/backward_compatibility.md). Adding a new release: [backward-compatibility/ADDING_NEW_VERSIONS.md](../backward-compatibility/ADDING_NEW_VERSIONS.md).

## Test material generation

```
make generate-test-material-all       # insecure + secure profiles, all party counts
make generate-test-material-default   # secure profile, parties 4,13
make generate-test-material-testing   # insecure profile, parties 4
make validate-test-material           # validate material on disk
make clean-test-material              # remove ./test-material
```

## Local deployment (Docker compose)

Build compose images:

```
make build-compose-base
make build-compose-threshold
make build-compose-centralized
```

Start / stop a 4-party threshold cluster (detached, waits for readiness; `stop` removes volumes and orphans):

```
make start-compose-threshold
make stop-compose-threshold
```

Start / stop the centralized single-node variant:

```
make start-compose-centralized
make stop-compose-centralized
```

Threshold cluster with telemetry sidecars (Jaeger / Prometheus):

```
make start-compose-threshold-telemetry
make stop-compose-threshold-telemetry
```

Custodian-based backup requires an env var at startup:

```
KMS_DOCKER_BACKUP_SECRET_SHARING=true make start-compose-threshold
```

## Running the client (core-client)

All from the `core-client/` directory:

```
cd core-client
cargo run -- --help
cargo run -- -f config/client_local_threshold.toml crs-gen
```

When using the core client for custodian backup CLI management instead use:
```
cd core-client
cargo run -- --help
cargo run -- -f config/client_local_threshold_custodian_backup.toml new-custodian-context
```

More: [docs/guides/core_client.md](../docs/guides/core_client.md).

## Git / LFS

Git LFS is required for BC test vectors and for the `backward-compatibility/data/*.bincode` files.

```
make check-git-lfs   # verify git-lfs is installed
make pull-lfs-files  # or: git lfs pull
```

Branch naming and commit/PR title rules: [GIT.md](./GIT.md).

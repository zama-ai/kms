# Editing rules

## Process and scope

- Inspect exports, immediate callers, and shared helpers (`util`-named files) before adding code.
- State your assumptions. If unsure, inspect first, then ask your human; do not guess. Stop and name confusion instead of pushing through.
- Explain major changes before implementing them. Use the smallest diff; avoid unrelated cleanup, reformatting, refactors of working code, and single-use abstractions. No large rewrites or copy-paste outside test code.
- Match repository structure and established style. When two patterns conflict, follow the more recent, better-tested one, explain why, and flag the other.
- Crypto, MPC, serialization, consensus, compatibility, or security-sensitive code: preserve existing behavior, including wire formats, parameter choices, and transcript and hash inputs. Changes here require an explicit design decision from your human.
- Alert your human before removing a working feature, and when an architecture or protocol-flow change needs a parallel tech-spec PR.
- Update affected docs and rustdoc. When CLI code or configuration changes, update the docs (`.md`) and deployment configs (`.yml`, `.toml`) to match. Update [ARCHITECTURE.md](./ARCHITECTURE.md) only when its map or invariants change. Report errors in docs you read.
- Preserve correct comments; document every `pub` item. Follow [PROSE.md](./PROSE.md).
- Self-review per [Review](#review). Report changes, verification, and remaining work accurately: "completed" and "tests pass" must be literally true.
- Prefer `git mv` for moves.

## Errors

- Validate early, at the boundary. Never panic on bad or adversarial input.
- Attach tracing context where an error is constructed; the log line alone must identify where and why it failed.
- Panic on invariant bugs. Explain why `panic!` / `expect` cannot fire in correct execution unless obvious.
- Prefer descriptive `expect` over `unwrap`; tests may use `unwrap`.
- Use strong types at module and service boundaries (`enum`, `Duration`, `Url`, `PathBuf`, `IpAddr`, …), parsed at the edge. Public errors are typed (e.g. `thiserror`) and actionable; no `anyhow::Error` across crate boundaries.

## Compatibility and API

- Keep internal protobuf and core-to-core communication compatible: a KMS released from `main` after your change must still talk to the previous release.
- Preserve backward compatibility. Version all non-test data in public, private, and backup storage with `tfhe-versionable`.
- Before changing persisted types, read the [compatibility guide](../docs/developer/backward_compatibility.md) and [harness overview](./ARCHITECTURE.md#backward-compatibility).
- Modifying or removing existing gRPC fields, or changing their data format, is breaking: alert your human for infra and downstream tracking.
- Service API or gRPC return-data changes also require matching `core-client` changes and a breaking-change marker ([GIT.md](./GIT.md)).

## Review

- Review the task's diff; exclude changes merged from `main`.
- Check analogous paths for matching changes: `purge_crs_data` ↔ `purge_key_data`, `*_threshold` ↔ `*_centralized`, S3 ↔ filesystem storage.
- Check for deadlocks, livelocks, TOCTOU, and other concurrency issues, especially around the locks and lifecycle leases in [ARCHITECTURE.md](./ARCHITECTURE.md).
- Remove code that the change made dead.
- Use one name per concept across the touched files.
- Check comments for the common failures: narrating the change, commenting trivial code, and comments the change made stale.
- Check the [PR checklist](../.github/PULL_REQUEST_TEMPLATE.md); flag applicable items you cannot verify.
- For security review, follow the [trust model](./ARCHITECTURE.md#communication-interfaces-and-trust-model), including its not-findings list. Cross-reference [OWASP ASVS](https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/OWASP_Application_Security_Verification_Standard_5.0.0_en.pdf) and the [MPC pitfalls](https://mpcsec.org/SKILL.md).

## Verification

- Update or add tests when you change behavior. Never break existing tests intentionally.
- Every `pub` and `pub(crate)` item needs at least one positive test; critical code also needs negative tests. Reject trivial or redundant tests. Changes to production code must not reduce coverage.
- Prefer reusable scaffolding and stubs over duplicated per-test setup.
- Run affected tests, including non-`slow_tests` tests in modified files, before reporting completion.

For code, dependency, or build changes, also run:

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
```

For documentation-only changes, check the diff, links, and consistency; Cargo checks are unnecessary.
Disclose narrower checks, failures, and checks not run. See [COMMANDS.md](./COMMANDS.md) for test features and compatibility traps.

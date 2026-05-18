# Editing rules

Rules for changing code, config, or docs in this repo. Tight by design — read every line.

## Process

- State assumptions; if unsure, inspect first, then ask. Don't guess.
- Explain major changes before implementing. Stop and name confusion rather than push through.
- Before adding code, read exports, immediate callers, and shared utilities — "looks orthogonal" is dangerous.
- On finish: summarize what's done, verified, and left. "Completed" / "tests pass" must be literal — never silently skip.
- Update all affected docs, including function rustdoc and the relevant section of [ARCHITECTURE.md](./ARCHITECTURE.md).
- If you spot errors in any doc you read, tell your human.
- Architecture or protocol-flow changes → alert human that a parallel PR is needed in the tech-spec repo.
- Always self-review per [REVIEW.md](./REVIEW.md).

## Scope of changes

- Smallest diff that solves the task. No extra features, no abstractions for single-use code, no drive-by cleanup or reformatting, no refactors of working code.
- **Crypto / MPC / serialization / consensus / compat / security-sensitive code: preserve existing behavior — wire formats, parameter choices, transcript/hash inputs.** Changes here require an explicit design decision from your human.
- No large rewrites or copy-paste except in test code.
- Match existing style. If two patterns contradict, pick the more recent/tested one, explain why, flag the other.
- Respect folder structure ([ARCHITECTURE.md](./ARCHITECTURE.md)). Reuse helpers from `util`-named files instead of duplicating.
- Prefer `git mv` over `mv` to preserve history.

## Comments and docs

- Preserve existing comments unless wrong. Update comments adjacent to changed code if they'd become inaccurate.
- Every `pub` item needs a rustdoc comment.

## Removing features

- Removing a working feature/function → explicitly notify your human.

## Error handling

- Validate early. Don't defer checks.
- Bad input / adversarial errors: log with enough detail that the log line alone identifies where and why. Never panic on these.
- Construct-time tracing — attach context where the error is built, not where it's received.
- Bugs (unreachable branches, OOB on known-size vec, etc.) should panic.
- Every `panic!` / `expect` needs a comment explaining why it can't fire in correct execution, unless obvious from context.
- Prefer `expect("descriptive message")` over bare `unwrap()`. Tests may `unwrap()` for brevity.

## Backward compatibility

- Always preserve backward compatibility. Any non-test data persisted to public/private/backup storage must be versioned with `tfhe-versionable`. Before touching a persisted type, read [docs/developer/backward_compatibility.md](../docs/developer/backward_compatibility.md) and follow the freeze-and-replay harness in [ARCHITECTURE.md](./ARCHITECTURE.md) "Backward compatibility".

## gRPC and service API changes

- Any modify/remove/data-format change to existing gRPC fields is breaking → alert human (infra + downstream tracking).
- Changes to the KMS service API or gRPC return data → also update the `core-client` crate and mark the change breaking.
- See "gRPC surface" in [ARCHITECTURE.md](./ARCHITECTURE.md).

## Build verification

Run after any change; must be clean:

```
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
```

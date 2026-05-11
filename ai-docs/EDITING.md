# Editing rules

Rules for changing code, configuration, or documentation in this repository.

## Process

- State assumptions explicitly. If uncertain, first inspect the relevant code/docs/tests. If uncertainty remains and affects correctness, ask rather than guess.
- Present multiple interpretations when ambiguity exists.
- Stop when confused. Name what's unclear.
- Define success criteria. Loop until verified.
- Always explain major changes before implementing them.
- Before adding code, read exports, immediate callers, shared utilities. "Looks orthogonal" is dangerous. If unsure why code is structured a way, ask.
- Summarize what was done, what's verified, what's left. Don't continue from a state you can't describe back.
- Default to surfacing uncertainty, not hiding it. "Completed" is wrong if anything was skipped silently. "Tests pass" is wrong if any were skipped. 
- It is fine to iterate: make a working change in a first pass, then re-read the agent rule files and bring the result into compliance before presenting it.
- When finishing any task, update all affected documentation — function doc comments, markdown files, deployment configs, and the relevant sections of [ARCHITECTURE.md](./ARCHITECTURE.md).
- If you find errors or incorrect information in any documentation or markdown file you read in this project, notify your human.
- Always review your changes — see [REVIEW.md](./REVIEW.md).
- If you make changes that affect the architecture or protocol flows, alert your human that a parallel PR must be opened in the tech-spec repo documenting these changes.

## Scope of changes

- Modify the smallest amount of code necessary.
- No features beyond what was asked. No abstractions for single-use code.
- For cryptographic, MPC, serialization, consensus, compatibility, or security-sensitive code, preserve existing behavior. In particular including wire formats, parameter choices, and transcript/hash inputs. The only exception is if explicitely requested to change these, even in this case, request an explicit design choice from your human.
- Do not make large rewrites, and do not copy-paste code, unless explicitly instructed to do so or unless you are working in test code. Prefer focused changes.
- Touch only what you must. Clean up only your own mess.
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor what isn't broken. Match existing style.
- If two patterns contradict, pick one (more recent / more tested). Explain why. Flag the other for cleanup.
- Don't blend conflicting patterns.
- Respect the existing folder structure (see [ARCHITECTURE.md](./ARCHITECTURE.md)).
- Reuse existing utilities instead of duplicating logic. Check `util` (or similarly named) files for helpers before writing new ones.
- Always try to preserve git history when possible, so prefer `git mv` to `mv` or rewriting code.

## Comments and docs

- Preserve existing comments unless they are incorrect.
- Sanity-check comments adjacent to code you modify, and update them if they would otherwise become inaccurate.
- Every new public (`pub`) item must have a rustdoc comment.

## Removing features

- If removing working features or functions, explicitly notify your human about this.

## Error handling

- Validate potential errors (e.g. malformed data) as early as possible; do not defer checks.
- Errors caused by bad input or adversarial behavior must not panic. Log them with enough detail that the log line alone identifies where and why the error occurred.
- Tracing of errors should happen at the point where the error gets constructed, not when it is received by the caller.
- Errors that can only occur because of a bug should panic. For example: an out-of-bounds index on a vector of known size, or a `None` in a branch that should be unreachable.
- Every `panic!` or `expect` must be accompanied by a comment explaining why the failure is a bug and cannot happen in correct execution — unless the reason is obvious in context.
- Prefer `expect("...")` with a descriptive message over a bare `unwrap()` (the only exception is in tests, where unwrap is normally preferred for conciseness).

## Backward compatibility

- Always preserve backward compatibility. Any data (that is not test data) persisted to public, private, or backup storage/vaults must be versioned using `tfhe-versionable`. Read [docs/developer/backward_compatibility.md](../docs/developer/backward_compatibility.md) before touching a persisted type, and follow the freeze-and-replay harness described in the "Backward compatibility" section of [ARCHITECTURE.md](./ARCHITECTURE.md).

## gRPC and service API changes

- For gRPC endpoints, any modification, removal, or data-format change of existing fields is a breaking change. You MUST alert your human so that infra and downstream teams can be notified and tracking issues opened.
- When changing the KMS service API, or changing data returned by any gRPC call, also update the `core-client` crate and mark the change as breaking.
- See the "gRPC surface" section of [ARCHITECTURE.md](./ARCHITECTURE.md) for context on the surface you are touching.

## Build verification

After any change, verify it compiles and lints cleanly:

```
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
```

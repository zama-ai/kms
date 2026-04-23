This file defines rules and expectations for AI coding agents working in this repository.

It is fine to iterate: make a working change in a first pass, then re-read this file and bring the result into compliance before presenting it.

## Key files

Start by skimming these — they orient the rest of your work:

- [README.md](README.md) — project overview and how to build / test.
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution workflow.
- [docs/SUMMARY.md](docs/SUMMARY.md) — index into the `docs/` tree which contains non-ai specific, general human readable project documentation.
- [docs/developer/backward_compatibility.md](docs/developer/backward_compatibility.md) — mandatory reading before changing any persisted type.
- [ARCHITECTURE.md](./ai-docs/ARCHITECTURE.md) — system architecture, workspace layout, backup and backward-compatibility subsystems.
- [TESTING.md](./ai-docs/TESTING.md) - rules and guidelines for managing tests.
- [GIT.md](./ai-docs/GIT.md) - rules and guidelines for using Git.
- [REVIEW.md](./ai-docs/REVIEW.md) - rules and guidelines for how to review your work, or an entire branch/pull request
- [DEPENDENCIES.md](./ai-docs/DEPENDENCIES.md) - rules and guidelines for how to review your work, or an entire branch/pull request.

## General Principles

"Your human" below means the maintainer who invoked you / the PR reviewer. When a rule says "alert your human", surface the fact clearly in chat and — if the work has reached a PR — call it out in the PR description.

- Always explain major changes before implementing them.
- When uncertain about requirements, ask clarifying questions. Do not guess.
- If you make changes that affect the architecture or protocol flows, alert your human that a parallel PR must be opened in the tech-spec repo documenting these changes.
- Do not introduce new dependencies without explicit confirmation by your human. See [Dependencies](#dependencies).
- Dependency updates must be handled in a separate PR that contains no code changes beyond what is strictly necessary to absorb the update. See [Dependencies](#dependencies).
- Error handling:
    - Validate potential errors (e.g. malformed data) as early as possible; do not defer checks.
    - Errors caused by bad input or adversarial behavior must not panic. Log them with enough detail that the log line alone identifies where and why the error occurred.
    - Errors that can only occur because of a bug should panic. For example: an out-of-bounds index on a vector of known size, or a `None` in a branch that should be unreachable.
    - Every `panic!`, `unwrap`, or `expect` must be accompanied by a comment explaining why the failure is a bug and cannot happen in correct execution — unless the reason is obvious in context.
    - Prefer `expect("...")` with a descriptive message over bare `unwrap()`.
- After any change, verify it compiles and lints cleanly:
    ```
    cargo fmt
    cargo clippy --all-targets --all-features -- -D warnings
    ```
- For gRPC endpoints, any modification, removal, or data-format change of existing fields is a breaking change. You MUST alert your human so that infra and downstream teams can be notified and tracking issues opened.
- Always ensure your branch is up to date with `main` before making changes.
- Do NOT force-push after your PR has received an initial human review.
- When finishing any task, update all affected documentation — function doc comments, markdown files, deployment configs, and the relevant sections of [ARCHITECTURE.md](ARCHITECTURE.md).
- Always review your changes — see [Review](#review).
- If you find errors or incorrect information in any documentation or markdown file you read in this project, notify your human.


## Folders to ignore

Do not read folders named `target`, `keys`, or `temp`; their contents are generated and not useful to you. Likewise, build artifacts under `backward-compatibility/target/` and LFS-tracked binaries under `backward-compatibility/data/*.bincode` are not human-readable and should not be opened.
The only exception is if explcitiely asked, or just to check for existence of specific files as part of debugging. 

## Editing Rules
- Modify the smallest amount of code necessary.
- Do not make large rewrites, and do not copy-paste code, unless explicitly instructed to do so or unless you are working in test code. Prefer focused changes.
- Do not rewrite entire files unless explicitly asked.
- Preserve existing comments unless they are incorrect.
- Sanity-check comments adjacent to code you modify, and update them if they would otherwise become inaccurate.
- Every new public (`pub`) item must have a rustdoc comment.
- If removing working features or functions make sure to explicitely notify your human about this.
- Always preserve backward compatibility. Any data persisted to public, private, or backup storage/vaults must be versioned using `tfhe-versionable`. Read [docs/developer/backward_compatibility.md](docs/developer/backward_compatibility.md) before touching a persisted type, and follow the freeze-and-replay harness described in the "Backward compatibility" section of [ARCHITECTURE.md](ARCHITECTURE.md).
- When changing the KMS service API, or changing data returned by any gRPC call, also update the `core-client` crate and mark the change as breaking.

## Architecture
Read the [ARCHITECTURE.md](./ai-docs/ARCHITECTURE.md) to learn the architecture and folder structure of the project.

- Respect the existing folder structure.
- Avoid introducing new patterns without justification.
- Reuse existing utilities instead of duplicating logic. Check `util` (or similarly named) files for helpers before writing new ones.

## Safety
- Never expose secrets or API keys.
- Avoid destructive commands (e.g. deleting files, dropping data, force-pushing).
- Ask before running migrations or performing large refactors.
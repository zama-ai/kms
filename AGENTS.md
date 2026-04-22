This file defines rules and expectations for AI coding agents working in this repository.

It is fine to iterate: make a working change in a first pass, then re-read this file and bring the result into compliance before presenting it.

## Key files

Start by skimming these — they orient the rest of your work:

- [README.md](README.md) — project overview and how to build / test.
- [ARCHITECTURE.md](ARCHITECTURE.md) — system architecture, workspace layout, backup and backward-compatibility subsystems.
- [docs/SUMMARY.md](docs/SUMMARY.md) — index into the `docs/` tree.
- [docs/developer/backward_compatibility.md](docs/developer/backward_compatibility.md) — mandatory reading before changing any persisted type.
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution workflow.

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
- Do not remove working features or functions. Instead, notify your human about potentially dead code.
- Always preserve backward compatibility. Any data persisted to public, private, or backup storage/vaults must be versioned using `tfhe-versionable`. Read [docs/developer/backward_compatibility.md](docs/developer/backward_compatibility.md) before touching a persisted type, and follow the freeze-and-replay harness described in the "Backward compatibility" section of [ARCHITECTURE.md](ARCHITECTURE.md).
- When changing the KMS service API, or changing data returned by any gRPC call, also update the `core-client` crate and mark the change as breaking.

## Testing
- If tests exist, update or add tests when changing behavior.
- Never break existing tests intentionally.
- Run tests before suggesting that work is complete.
- Every public (`pub`) item must have at least one positive ("sunshine") unit test.
- Every public (`pub`) item should also have negative tests.
- Changes to production code must not reduce test coverage.
- Prefer reusable scaffolding and stubs over large, duplicative per-test setup/teardown.
- Refactoring existing tests to use new scaffolding or stubs is welcome when it reduces duplication.

## Architecture
- Respect the existing folder structure.
- Avoid introducing new patterns without justification.
- Reuse existing utilities instead of duplicating logic. Check `util` (or similarly named) files for helpers before writing new ones.

## Safety
- Never expose secrets or API keys.
- Avoid destructive commands (e.g. deleting files, dropping data, force-pushing).
- Ask before running migrations or performing large refactors.

## Branches and Commit Messages

Branch names for new PRs must take the form:
```
<your name>/<type>/<issue-number>/<issue description>
```
where `<type>` is the conventional-commit type, `<issue-number>` is the GitHub issue number, and `<issue description>` is a short description. Example: `tore/feat/423/zk-grpc-handles`.

Commit messages use the form:
```
<type>(<component>): <short summary>
```
Append `!` after `<type>` to flag a breaking change. Example: `feat!(grpc): change decryption api`.

## Review

When reviewing changes — whether a single commit or an entire branch — perform the following steps:

- Verify every rule in this file is satisfied.
- Validate that every item on the [pull-request template](.github/PULL_REQUEST_TEMPLATE.md) can be checked off. Alert your human of any changes that you cannot personally verify.
- Check for code that is now dead and can be removed.
- Check that variable names and comments are consistent with the surrounding code — identical semantic concepts should share names across the files touched.
- For functions with changed signatures or logic, check whether sibling functions need matching changes. Examples: a change to `purge_crs_data` probably implies a change to `purge_key_data`; a change to a `*_threshold` function usually has a matching `*_central` / `*_centralized` function.
- Check that refactors and functional changes have been applied in every analogous place. Threshold-side changes usually need centralized-side counterparts; S3-storage changes usually need filesystem-storage counterparts.
- If CLI code or configuration files changed, validate that docs (markdown) and deployment configs (yml, toml) have been updated consistently.
- Check for new security vulnerabilities. Cross-reference [OWASP ASVS](https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/OWASP_Application_Security_Verification_Standard_5.0.0_en.pdf) and the [MPC pitfalls repo](https://github.com/rot256/mpc-pitfalls).

## Dependencies

We have strict rules about dependencies, mostly for security reasons.

- Never update a dependency version as part of a regular PR. Dependency updates must go in their own PR.
- Do not update a dependency unless the update is required for a feature we need, a bug we have hit, or a known security issue.
- Do not add new dependencies without discussing with the team.
- When a new dependency is added, document in `Cargo.toml` why it is needed and why it is considered trusted.

To judge whether a dependency or a dependency update is trusted, read the section "Dependency Update Questionnaire (only if deps changed or added)" in the [pull-request template](.github/PULL_REQUEST_TEMPLATE.md).
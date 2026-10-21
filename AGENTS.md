# AGENTS.md

Rules and expectations for AI coding agents working in this repository. This file is the index — all rules live in the topic files listed below. Read the files that apply to your task before starting.

## Glossary

"Your human" means the maintainer who invoked you / the PR reviewer. When a rule says "alert your human", surface the fact clearly in chat and — if the work has reached a PR — call it out in the PR description.

## Topic files

- [ARCHITECTURE.md](./ai-docs/ARCHITECTURE.md) — trust summary, code map, and cross-module invariants. Read the code map and task-relevant sections before changing service structure, persisted types, storage, or protocol flows. Apply the trust summary in every review; read the linked trust model before security review.
- [EDITING.md](./ai-docs/EDITING.md) — rules for every change: process and scope, error handling, compatibility and gRPC changes, review checklist, tests, and the required fmt/clippy checks. Read before making any change or reviewing one.
- [PROSE.md](./ai-docs/PROSE.md) — how to write prose: code comments and rustdoc, markdown files, GitHub issues and PR text, and chat replies to your human. Read before you write any of them.
- [COMMANDS.md](./ai-docs/COMMANDS.md) — test selection, feature flags, backward-compatibility targets, and pointers for compose, test material, the client, and LFS. Read before running tests or Makefile targets.
- [GIT.md](./ai-docs/GIT.md) — branch names, commit and PR title format, branch sync, force-push. Read before naming a branch or writing a commit message or PR title.
- [DEPENDENCIES.md](./ai-docs/DEPENDENCIES.md) — rules for adding or updating dependencies. Read before changing `[dependencies]` in any `Cargo.toml`, or `Cargo.lock`.
- [SAFETY.md](./ai-docs/SAFETY.md) — secrets and destructive actions. Read before deleting files or data, force-pushing, running migrations, or starting a large refactor.

## Other useful entry points

- [README.md](README.md) — project overview and how to build / test.
- [CONTRIBUTING.md](CONTRIBUTING.md) — human contribution workflow.
- [docs/SUMMARY.md](docs/SUMMARY.md) — index into the `docs/` tree of general, human-readable project documentation.

## Folders to ignore

Do not read folders named `target`, `keys`, or `temp`; their contents are generated and not useful to you. Likewise, build artifacts under `backward-compatibility/target/` and LFS-tracked binaries under `backward-compatibility/data/*.bincode` are not human-readable and should not be opened. The only exception is if explicitly asked, or just to check for existence of specific files as part of debugging.

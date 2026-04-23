# AGENTS.md

Rules and expectations for AI coding agents working in this repository. This file is the index — all rules live in the topic files listed below. Read the files that apply to your task before starting.

## Glossary

"Your human" means the maintainer who invoked you / the PR reviewer. When a rule says "alert your human", surface the fact clearly in chat and — if the work has reached a PR — call it out in the PR description.

## Topic files

- [ARCHITECTURE.md](./ai-docs/ARCHITECTURE.md) — system architecture, workspace layout, gRPC surface, backup, backward-compatibility subsystem. Read before any change that touches service structure, persisted types, or protocol flows.
- [EDITING.md](./ai-docs/EDITING.md) — rules for making changes: scope, comments, error handling, backward compatibility, gRPC/API changes, build verification, and general process (when to explain, ask, alert, update docs).
- [COMMANDS.md](./ai-docs/COMMANDS.md) — build, test, lint, backward-compatibility, docker-compose, and client commands in one place.
- [TESTING.md](./ai-docs/TESTING.md) — test requirements and conventions.
- [GIT.md](./ai-docs/GIT.md) — branch naming, commit messages, branch-sync and force-push rules.
- [REVIEW.md](./ai-docs/REVIEW.md) — how to review your own work, a commit, or an entire branch / pull request.
- [DEPENDENCIES.md](./ai-docs/DEPENDENCIES.md) — rules for adding or updating dependencies.
- [SAFETY.md](./ai-docs/SAFETY.md) — safety / destructive-action rules.

## Other useful entry points

- [README.md](README.md) — project overview and how to build / test.
- [CONTRIBUTING.md](CONTRIBUTING.md) — human contribution workflow.
- [docs/SUMMARY.md](docs/SUMMARY.md) — index into the `docs/` tree of general, human-readable project documentation.

## Folders to ignore

Do not read folders named `target`, `keys`, or `temp`; their contents are generated and not useful to you. Likewise, build artifacts under `backward-compatibility/target/` and LFS-tracked binaries under `backward-compatibility/data/*.bincode` are not human-readable and should not be opened. The only exception is if explicitly asked, or just to check for existence of specific files as part of debugging.

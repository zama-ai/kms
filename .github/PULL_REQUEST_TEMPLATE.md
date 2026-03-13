## Description of changes
<!-- Please explain the changes you made -->

## Issue ticket number and link
<!-- Add a reference to the issue fixed if available -->

## PR Checklist
<!-- Review each item and tick all that apply. Explain any exceptions in the description. -->
I attest that all checked items are satisfied. Any deviation is clearly justified above.
- [ ] Title follows conventional commits (e.g. `chore: ...`).
- [ ] Tests added for every new pub item and test coverage has not decreased.
- [ ] Public APIs and non-obvious logic documented; unfinished work marked as `TODO(#issue)`.
- [ ] `unwrap`/`expect`/`panic` only in tests or for invariant bugs (documented if present).
- [ ] No dependency version changes OR (if changed) only minimal required fixes.
- [ ] No architectural protocol changes OR linked spec PR/issue provided.
- [ ] No breaking deployment config changes OR `devops` label + infra notified + infra-team reviewer assigned.
- [ ] No breaking gRPC / serialized data changes OR commit marked with `!` and affected teams notified.
- [ ] No modifications to existing versionized structs OR backward compatibility tests updated.
- [ ] No critical business logic / crypto changes OR ≥2 reviewers assigned.
- [ ] No new sensitive data fields added OR `Zeroize` + `ZeroizeOnDrop` implemented.
- [ ] No new public storage data OR data is verifiable (signature / digest).
- [ ] No `unsafe`; if unavoidable: minimal, justified, documented, and test/fuzz covered.
- [ ] Strongly typed boundaries: typed inputs validated at the edge; no untyped values or errors cross modules.
- [ ] Self-review completed.

### Dependency Update Questionnaire (only if deps changed or added)
Answer in the `Cargo.toml` next to the dependency (or here if updating):
1. Ownership changes or suspicious concentration?
2. Low popularity?
3. Unusual version jump?
4. Lacking documentation?
5. Missing CI?
6. No security / disclosure policy?
7. Significant size increase?

More details and explanations for the checklist and dependency updates can be found in [CONTRIBUTING.md](../CONTRIBUTING.md#6-pr-checklist)

## Description
<!-- Explain what changed and why. -->

### Related issue(s)
<!-- Reference the issue fixed if available (e.g. "Closes #1234"). -->

## PR Checklist
Tick all that apply — by ticking I attest the item holds; justify any deviation in the description above.
- [ ] Title follows conventional commits (e.g. `chore: ...`).
- [ ] Tests added for every new `pub` item and test coverage has not decreased.
- [ ] Public APIs and non-obvious logic documented; unfinished work marked `TODO(#issue)`.
- [ ] `unwrap`/`expect`/`panic` only in tests or for invariant bugs (documented if present).
- [ ] No dependency version changes OR (if changed) only minimal required fixes.
- [ ] No architectural protocol changes OR linked spec PR/issue provided.
- [ ] No breaking deployment config / Helm chart / telemetry changes OR `devops` label + infra notified + review requested.
- [ ] No breaking gRPC / serialized data changes OR commit marked with `!` and affected teams notified.
- [ ] No modifications to existing versionized structs OR backward compatibility tests updated.
- [ ] No critical business logic / crypto changes OR ≥2 reviewers assigned.
- [ ] No new sensitive data fields OR `Zeroize` + `ZeroizeOnDrop` implemented.
- [ ] No new public storage data OR data is verifiable (signature / digest).
- [ ] No `unsafe`; if unavoidable: minimal, justified, documented, and test/fuzz covered.
- [ ] Strongly typed boundaries: typed inputs validated at the edge; no untyped values or errors cross modules.
- [ ] Self-review completed.

### Dependency Update Questionnaire (only if deps changed or added)
<!-- Answer next to the dependency in `Cargo.toml`, or here: -->
1. Ownership changes or suspicious concentration?
2. Low popularity?
3. Unusual version jump?
4. Lacking documentation?
5. Missing CI?
6. No security / disclosure policy?
7. Significant size increase?

More details in [CONTRIBUTING.md](../CONTRIBUTING.md) and [AGENTS.md](../AGENTS.md).

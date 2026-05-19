When reviewing changes — whether a single commit or an entire branch — ignore any changes merged in from `main`, and then perform the following steps:

- Verify every rule in this file is satisfied.
- Validate that every item on the [pull-request template](.github/PULL_REQUEST_TEMPLATE.md) can be checked off. Flag any items you cannot personally verify.
- Remove code that is now dead.
- Public and `pub(crate)` methods have positive tests; critical code also has negative tests. Reject trivial or redundant tests.
- Check for deadlocks, livelocks, TOCTOU, and other concurrency issues.
- Variable names and comments are consistent across touched files — identical semantic concepts share names.
- When changing a function or pattern, check whether siblings and analogous implementations need matching changes. Examples: `purge_crs_data` ↔ `purge_key_data`; `*_threshold` ↔ `*_central` / `*_centralized`; S3-storage ↔ filesystem-storage.
- If CLI code or configuration changed, update docs (`md`) and deployment configs (`yml`, `toml`) consistently.
- No internal protobuf/comms compatibility breaks — a KMS released from `main` after this PR can still talk to the previous release.
- Strong types at module/service boundaries (`enum`, `Duration`, `Url`, `PathBuf`, `IpAddr`, …) validated/parsed at the edge — no untyped/loosely-typed input crosses boundaries.
- Public errors are typed (e.g. `thiserror`) with actionable messages; no `anyhow::Error` across crate boundaries.
- Check for new security vulnerabilities. Cross-reference [OWASP ASVS](https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/OWASP_Application_Security_Verification_Standard_5.0.0_en.pdf) and the [MPC pitfalls](https://mpcsec.org/SKILL.md).
When reviewing changes — whether a single commit or an entire branch — perform the following steps:

- Verify every rule in this file is satisfied.
- Validate that every item on the [pull-request template](.github/PULL_REQUEST_TEMPLATE.md) can be checked off. Alert your human of any changes that you cannot personally verify.
- Check for code that is now dead and can be removed.
- Ensure that all public methods and pub crate methods have positive tests and that critical code segments also have sufficient negative testing.
- Ensure there are no trivial or redundant tests added.
- Check that variable names and comments are consistent with the surrounding code — identical semantic concepts should share names across the files touched.
- For functions with changed signatures or logic, check whether sibling functions need matching changes. Examples: a change to `purge_crs_data` probably implies a change to `purge_key_data`; a change to a `*_threshold` function usually has a matching `*_central` / `*_centralized` function.
- Check that refactors and functional changes have been applied in every analogous place. Threshold-side changes usually need centralized-side counterparts; S3-storage changes usually need filesystem-storage counterparts.
- If CLI code or configuration files changed, validate that docs (markdown) and deployment configs (yml, toml) have been updated consistently.
- Check for new security vulnerabilities. Cross-reference [OWASP ASVS](https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/OWASP_Application_Security_Verification_Standard_5.0.0_en.pdf) and the [MPC pitfalls repo](https://github.com/rot256/mpc-pitfalls).
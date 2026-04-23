We have strict rules about dependencies, mostly for security reasons.

- Never update a dependency version as part of a regular PR. Dependency updates must go in their own PR and contain no code changes beyond what is strictly necessary to absorb the update.
- Do not update a dependency unless the update is required for a feature we need, a bug we have hit, or a known security issue.
- Do not add new dependencies without discussing with the team.
- When a new dependency is added, document in `Cargo.toml` why it is needed and why it is considered trusted.

To judge whether a dependency or a dependency update is trusted, read the section "Dependency Update Questionnaire (only if deps changed or added)" in the [pull-request template](.github/PULL_REQUEST_TEMPLATE.md) and evaluate the questions asked there to make a judgement.
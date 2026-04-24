# Git rules

## Branch naming

Branch names for new PRs must take the form:

```
<your name>/<type>/<issue-number>/<issue description>
```

where `<type>` is the conventional-commit type, `<issue-number>` is the GitHub issue number, and `<issue description>` is a short description. Example: `tore/feat/423/zk-grpc-handles`.

## Commit messages and PR titles

Commit messages and PR titles must use the form:

```
<type>(<component>): <short summary>
```

Append `!` after `<type>` to flag a breaking change. Example: `feat!(grpc): change decryption api`.

## Workflow rules

- Always ensure your branch is up to date with `main` before making changes.
- Do NOT force-push after your PR has received an initial human review.

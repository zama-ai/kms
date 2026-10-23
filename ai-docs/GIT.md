# Git

- New PR branches: `<name>/<type>/<issue-number>/<short-description>`, e.g. `tore/feat/423/zk-grpc-handles`.
- Commits and PR titles: `<type>(<component>): <summary>`, where `<type>` is a Conventional Commits type.
- Mark a breaking change with `!` directly after `<type>`, before the scope: `feat!(grpc): change decryption api`. This differs from the Conventional Commits form `feat(grpc)!:`.
- Bring the branch up to date with `main` before changes.
- Never force-push after the PR's initial human review.

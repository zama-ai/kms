# Prose

Applies to comments, docs, PRs, issues, and chat. [EDITING.md](./EDITING.md) and [GIT.md](./GIT.md) take precedence.

- Use short, direct sentences, active voice, and consistent repository terminology. One instruction per sentence; terse lists are fine in rule files and templates.
- Report concrete results and counts: "3 of 12 tests fail", not "some tests fail". Explain what changed and why. Avoid filler, praise, diff narration, and marketing words such as "robust", "seamless", "comprehensive", or "significantly".
- Comment code that a competent reader cannot follow from the code alone; leave trivial code uncommented. Comments explain non-obvious constraints, invariants, units, ownership, or valid ranges. Do not restate the item's name.
- Describe current behavior, not change history: no "new", "now", "currently", "for now", "no longer", PR numbers, or dates in comments. Report the change to your human instead. Do not address reviewers.
- Keep function docs brief and local to that function; link to callees instead of repeating their internals.
- Start rustdoc with a one-sentence present-tense summary ("Returns the signature over `payload`."), not "This function". Document non-obvious errors and panics; use `[Type]` links where possible.
- Cite a spec, paper, or issue for crypto and protocol constraints; omit derivations.
- Preserve accurate comments and move them with their code. Do not reword a correct comment. Use `TODO(#<issue-number>): <what is missing>`.
- Use verified relative links within repository Markdown. Index new `ai-docs/` files in [AGENTS.md](../AGENTS.md).

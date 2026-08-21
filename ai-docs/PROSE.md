# Prose rules

Rules for every kind of prose you write in this repo: code comments and rustdoc, commit messages, PR and issue descriptions, markdown files, and chat replies to your human.

## Which rules apply where

- Write full-sentence prose with the [STE](#simplified-technical-english) rules. This covers rustdoc, block comments, markdown body text, issue and PR descriptions, and chat replies.
- Terse, list-style rule files (this file, the other files in `ai-docs/`, and the templates in `.github/`) are exempt from the STE sentence-completeness rule. Match the style already in the file you edit.
- A rule in [EDITING.md](./EDITING.md) or [GIT.md](./GIT.md) wins over a rule here. Those files say *what* to write; this file says *how* to write it.

## Code comments and inline docs

- Comment the code that a competent reader cannot follow from the code alone. Examples: nested closures with filters, a non-obvious order of operations, a bound that comes from the protocol, a workaround for an upstream bug. Leave trivial code uncommented.
- Describe the code as it is now. Do not describe your change, and do not compare against the old code. Avoid comments such as "function A no longer does X, so we call function Y first", and avoid "new", "now", "currently", "for now", PR numbers and dates. Report your change to your human instead.
- Do not address the reviewer or your human in a comment.
- Document the function in front of you, not the ones it calls. If function A calls function B, link to B instead of describing the internals of B.
- Do not restate the name of the item. `/// The config.` on `config: Config` adds nothing. State the invariant, the unit, the ownership or the valid range instead.
- Keep a function comment to a few sentences.
- Reference the specification, the paper or the issue for a cryptographic or protocol constraint. Do not repeat the derivation in a comment.
- Mark unfinished work as `TODO(#<issue-number>): <what is missing>`.
- Start a rustdoc comment with one summary sentence in the simple present tense: "Returns the signature over `payload`." Do not start with "This function".
- Document the error and panic conditions when the signature does not make them obvious.
- Use a rustdoc link (`[Type]`) when the target is in scope.
- When you move code, move its comment with it.
- Edit an existing comment only when your change makes it wrong, incomplete or misleading. Leave a correct comment alone, even when you prefer other words.

## Reports to your human

- Give numbers instead of adjectives. Write "3 of 12 tests fail", not "some tests fail".
- Do not open with filler or with praise. Do not use marketing words such as "robust", "seamless", "comprehensive" or "significantly".
- Do not repeat the diff back to your human. Say what changed, and why it changed.

## Markdown files

- Link to another file in this repo with a relative path. Check that the path resolves.
- Add an index entry in [AGENTS.md](../AGENTS.md) when you add a file to `ai-docs/`.

## Simplified Technical English

- Give one meaning to each word, and use each word as one part of speech only. Do not introduce a synonym for a concept that the repo already names.
- Write no more than three words in a multi-word noun.
- Use these verb forms only:
    - The infinitive form
    - The imperative form
    - The simple present tense
    - The simple past tense
    - The simple future tense
    - The past participle, and only as an adjective
- Do not build complex verb constructions with auxiliary verbs.
- Use the "-ing" form of a verb only as a technical noun, or as a modifier in a technical noun.
- Use the active voice. In descriptive text, use the passive voice only when the actor is unknown or not relevant.
- Write short sentences. Use no more than 20 words in an instruction, and no more than 25 words in descriptive text.
- Write complete sentences. Do not remove the verb, the subject or the article to make the text shorter.
- Write one instruction per sentence.
- Describe the WHAT not the HOW unless instructed otherwise. 

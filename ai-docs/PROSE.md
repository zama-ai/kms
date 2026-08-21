# Prose rules

Rules for every kind of prose you write in this repo: code comments and rustdoc, commit messages, PR and issue descriptions, markdown files, and chat replies to your human.

## Which rules apply where

- Write full-sentence prose with the [STE](#simplified-technical-english) rules. This covers rustdoc, block comments, markdown body text, issue and PR descriptions, and chat replies.
- Code comments have extra rules. See [Code comments](#code-comments).
- Chat replies, commit messages, PR descriptions and issue descriptions have extra rules. See [Reports to your human](#reports-to-your-human).
- Terse, list-style rule files (this file, the other files in `ai-docs/`, and the templates in `.github/`) are exempt from the STE sentence-completeness rule. When you edit one of these files, match the style already in it.
- A rule in [EDITING.md](./EDITING.md) or [GIT.md](./GIT.md) wins over a rule here. Those files say *what* to write; this file says *how* to write it.

## Code comments

Content:

- Do not comment trivial code. A single function call with a descriptive name needs no comment.
- Do comment code that a competent reader cannot follow from the code alone. Examples: nested closures with filters, a non-obvious order of operations, a bound that comes from the protocol, a workaround for an upstream bug.
- Describe the code as it is now. Do not describe your change, and do not compare against the old code. Avoid comments such as "function A no longer does X, so we call function Y first". Report your change to your human instead.
- Do not write comments that only make sense while the change is fresh. Avoid "new", "now", "currently", "for now", "recently", "as of", PR numbers and dates.
- Do not address the reviewer or your human in a comment. That text belongs in chat or in the PR description.
- Keep a function comment to a few sentences. If you cannot describe a function in a few sentences, the function does too much. Tell your human instead of writing a long comment.
- Document the function in front of you, not the ones it calls. If function A calls function B, do not describe the internals of B in the comment on A. Link to B instead.
- Do not restate the name of the item. `/// The config.` on `config: Config` adds nothing. State the invariant, the unit, the ownership or the valid range instead. Every `pub` item still needs a rustdoc comment ([EDITING.md](./EDITING.md)).
- Use the same words as the code and the neighbouring files. One concept keeps one name.
- Reference the specification, the paper or the issue for a cryptographic or protocol constraint. Do not repeat the derivation in a comment.
- Mark unfinished work as `TODO(#<issue-number>): <what is missing>`. Do not write a `TODO` without an issue number.
- Do not comment out code. Delete it. Git keeps the history.

Form:

- Use `///` for rustdoc on an item, and `//` for an implementation note inside a body.
- Start a rustdoc comment with one summary sentence in the simple present tense: "Returns the signature over `payload`." Do not start with "This function".
- Put the details after the summary sentence, separated by a blank line.
- Document the error and panic conditions when the signature does not make them obvious. [EDITING.md](./EDITING.md) requires a comment on every `panic!` and `expect`.
- Put the comment immediately above the code it describes. When you move code, move its comment.
- Write symbol names in backticks. Use rustdoc links (`[Type]`) when the target is in scope.

Existing comments:

- Edit an existing comment only when your change makes it wrong, incomplete or misleading. Leave a correct comment alone, even when you prefer other words.
- Fix a comment that your change makes inaccurate. This is required, not optional.

## Reports to your human

- Give the answer or the outcome first. Give the detail after it.
- Report only what you verified. "Tests pass" and "completed" must be literal.
- Name what you did not do, and why.
- Give numbers instead of adjectives. Write "3 of 12 tests fail", not "some tests fail".
- State uncertainty as uncertainty. Say what you assumed.
- Do not open with filler or with praise. Do not use marketing words such as "robust", "seamless", "comprehensive" or "significantly".
- Do not repeat the diff back to your human. Say what changed, and why it changed.
- Use emoji only in a file that already uses them.
- Write commit messages and PR titles in the form that [GIT.md](./GIT.md) gives.

## Markdown files

- Put a blank line after each heading, and between paragraphs and lists.
- End the file with a newline. Leave no trailing whitespace.
- Match the heading depth, the list marker and the punctuation of the file you edit.
- Link to another file in this repo with a relative path. Check that the path resolves.
- Add an index entry in [AGENTS.md](../AGENTS.md) when you add a file to `ai-docs/`.

## Simplified Technical English

These rules come from Simplified Technical English (STE). Apply them to full-sentence prose.

- Give one meaning to each word, and use each word as one part of speech only. Do not introduce a synonym for a concept that the repo already names.
- Make instructions clear and specific.
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
- Use a vertical list for complex text.
- Write one instruction per sentence.
- Write one topic per paragraph.
- Write no more than six sentences in a paragraph.
- Start a safety instruction with the command or with the condition.

This file defines rules and expectations for AI coding agents working in this repository.

You are always free to make any changes freely initially in a first pass, then go through your solution and change it according to the rules described in this file. 

## Key files 
README.md
ARCHITECTURE.md
docs/SUMMERY.md

## General Principles
- Always explain major changes before implementing them.
- When uncertain about requirements, ask clarifying questions. Do not guess! 
- If you make changes that affect the architecture or protocol flows, then alert your human that a parallel PR has to been open in the tech-spec repo documenting these changes.
- Do not introduce new dependencies without explicit confirmation by your human that this is allowed.
- If you are updating any dependencies, then the PR must not contain any code changes beyond what is strictly necessary to fix any compatibility issues with the update. I.e. dependency updates must be handled in separate PRs. See [this section](#dependencies).
- Error handling must be done according to the following rules:
    - Checks for potential errors, e.g. malformed data, should happen as soon as possible and not be deferred down the line.
    - When the error is because of bad input or adversaries behavior no panic should happen. Instead the error should be logged appropriately and with sufficient detail to uniquely figure out where it happened and why.
    - Errors that can only happen because of a bug should cause a panic. E.g. and index-out-of-bound exception on a vector that has a known size, or a None value in a segment of code that should never be executed if this is the case.
    - Whenever a panic happens or an error is unwraped a comment should explain why this is indeed a bug.
    - In fact, unless the unwrap() is in an obvious place in the code and it can be inferred from the context what it wrong, it is preferred to use expect() with a detailed error message that explains the details.
- After making a change always ensure the everything still compiles and there is no lint. Specifically run `cargo fmt && cargo clippy --all-targets --all-features -- -D warnings` and handle any issues.
- For the gRPC end-points any modification of existing fields, or removal of existing fields, or change of the data format for existing fields should be considered a breaking change! You MUST alert your human to this s.t. infra and other relevant teams can be notified and issues be made to handle this. 
- Always ensure that your branch is up to date with `main` before making changes!
- Do NOT force-push after your PR received an initial human review!
- When finishing ANY task, make sure that any documentation is updated as well. This includes function comments, but also any markdown file. 
- Always review your changes, see [this section](#review).
- Always notify your human if you find errors or wrong information in any documentation or markdown file you read in this project. 

## Tech stack and project description
Read README.md and everything in the `docs/` folder to get context and knowledge about the architecture and design requirements of the project. Start with [SUMMERY.md](docs/SUMMARY.md).

## Folders to ignore
You will never need to read any folder called 'target', 'keys' or 'temp'. They do not contain useful information for you as their contents are generated. 

## Editing Rules
- Modify the smallest amount of code necessary.
- Do not make large rewrites of existing code, or do code-copy, unless explicitely instructed to do so or it is test code. Instead prefer to make as small changes as possible.
- Do not rewrite entire files unless explicitly asked.
- Preserve existing comments unless they are incorrect.
- Sanity check all existing comments related to code that you modify and edit the commetns appropriately if needed.
- When making a new public (`pub`) method, always ensure it has rust doc function documentation.
- Do not remove working features or function. Instead, notify your human about potentially dead code. 
- Always ensure backwards compatibility. That is, any data that is persisted (stored in the public, private or backup stroage/vaults) must be versioned using tfhe-rs. Read [this markdown](docs/developer/backward_compatibility.md) to ensure you understand how this should be handled.
- When making a change, or addition, to the API of the KMS service, or if you modify any data that is returned by a gRPC call, ensure that the core-client is also updated as well, and mark this as a breaking change. 

## Testing
- If tests exist, update or add tests when changing behavior.
- Never break existing tests intentionally.
- Run tests before suggesting that work is complete.
- All public methods (`pub`) must have at least a positive sunshine unit test.
- All public methods (`pub`) should have negative tests.
- Any changes to production code should not reduce test coverage.
- Prefer writing stubs and reusable scafolding rather than individual large tests with lots of setup and teardown code. 
- To make test more streamlined you are welcome to refactor existing tests to use any new scafolding or stubs.

## Architecture
- Respect the existing folder structure.
- Avoid introducing new patterns without justification.
- Reuse existing utilities instead of duplicating logic. Specifically check `util` or similarely named files for any helper functions that could be useful. 

## Safety
- Never expose secrets or API keys.
- Avoid destructive commands (e.g., deleting things).
- Ask before running migrations or large refactors.

## Branches and Commit Messages
The name of a branch for a new PR must take the following form:
```
<your name>/<type>/<issue-number>/<issue description>
```
Here `<type>` refers to the conventional commit type. The `<issue-number>` is the GitHub issue number and finally the `<issue description>` is short description of the issue. For example `tore/feat/423/zk-grpc-handles`

For commit messages use the format:
```
<type>(<component>): <short summery>
```
Furthermore you may add an exclamation mark `!` after `<type>` to draw attention to breaking change. For example `feat!: changing grpc decryptin api`.

## Review
When reviewing changes, or a whole branch, you must perform the following steps:

- Ensure the rules described in this file has been fulfilled. 
- Validate that every point on the pull request template can be checked off (https://github.com/zama-ai/kms/blob/main/.github/PULL_REQUEST_TEMPLATE.md) and if not, or if it is not something you can check, then alert your human.
- Check if there is any code that is now dead and can be removed. 
- There is no inconsistent variable names or comments when looking at the changes actually made. That is, variable names make sense and have share the name of other variables with the same semantic meaning in the files changed.  
- Look at functions with changed signatures or logic, check that there is no other similar functions that could be refactored in a similar manner. E.g. modifying a function like `purge_crs_data` likely will also require a modification of `purge_key_data`. Or a modification of a function with `threshold` in its name, will likely require a similar modification to a function with a similar name, but with `central` or `centralized` in its name. 
- Check that any refactorings and functional changes done in one place  has been done all relevant places. For example, changes to threshold code has been similarely implemented for centralized code, or changes to the S3 storage has similarly been updated in the Filesystem storage.
- If there is any changes to CLI code or configuration files, then validate that manuals (mark down files) and and deployment configurations (such as yml and toml files) have been updated consistently.
- Check there are no new security vulnerabilities, in particular cross reference OWASP AVSS (https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/OWASP_Application_Security_Verification_Standard_5.0.0_en.pdf) and the MPC pitfalls repo (https://github.com/rot256/mpc-pitfalls).

## Dependencies 
We have certain rules about dependencies and how we manage them. Mostly related to security.

- Never update a version of a dependency as part of a regular PR. Such updates must be done in a separate PR.
- Do not update a dependency unless the update is really needed because of new features, or to fix a bug we have encountered or to fix a known security issue.
- Do not add new dependencies without discussing with the the team.
- Whenever a new dependency is added, it's addition must be documented in the Cargo.toml file with an argument of why it is needed, why it addition is considered trusted.

For judgement of whether a dependency or a dependency update should be considered trusted, consider the following questions. The answer to most of these questions must be "no" for the update or addition to be considered trusted:

- Did ownership change change significantly since last update. Is the owner suspicious? I.e. is it limited to one or a few people or small companies in "dangerous territories"?
- Is the crate not particularly popular?
- Is there an unusual jump in package versions?
- Is documentation lacking?
- Is there no CI enabled on the project's GitHub?
- Do the owners not make any statements in relation security and responsible disclosure of vulnerabilities?
- Is there a significant change in size of the crate?

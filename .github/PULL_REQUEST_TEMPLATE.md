## Description of changes
<!-- Please explain the changes you made -->

## Issue ticket number and link
<!-- Add a reference to the issue fixed if available -->

## Checklist before requesting a review
- [ ] My PR title follows [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/), e.g. "chore: made key gen consistent with tfhe-rs 1.4".
- [ ] I have made sunshine tests for all new `pub` methods.
- [ ] Code comments are in place for public methods along with tricky or non-obvious code segments.
- [ ] I have performed a self-review of my code
- [ ] Any unfinished business is documented with a `TODO(#issue_number)` comment and brief description what needs to be fixed.
- [ ] I have only used `unwrap`, `expect` or `panic!` tests or in situations where it would imply that there is a bug in the code, and I have documented this.
- [ ] My PR is _not_ updating _any_ dependencies (i.e. no changes to `Cargo.lock`). Or if it is, then it _only_ contains the dependency updates and any changes needed to fix compilation and tests (see [here](#Checklist-for-dependency-updates) for details.)
- [ ] My changes do not affect the architecture of the protocol. Or if they do these steps must be taken:
    - [ ] A parallel PR or issue has been open in the [tech-spec repo](https://github.com/zama-ai/tech-spec) (add the link here).
- [ ] My PR does not contain any breaking changes to the configuration and deployment files.
      (A change is _only_ considered breaking if a deployment configuration must be changed as part of an update. E.g. adding new fields, with default values is _not_ considered breaking). Or if it does then these steps must be taken:
    - [ ] My PR is labeled with `devops`.
    - [ ] I have pinged the infra team on Slack (in the MPC channel).
    - [ ] I have put a devops person on the PR as reviewer.
- [ ] My PR does not contain breaking changes to the gRPC interface or data serialized into data in the service gRPC interface. In particular there are no changes to the `extraData` fields. Or if it does the following steps have been taken:
    - [ ] The PR is marked using `!` in accordance with conventional commits. E.g. `chore!: changed decryption format according to Q3 release`.
    - [ ] The Gateway and Connector teams have been notified about this change.
- [ ] I have not changed existing `versionized` structs, nor added new `versionized` structs. Or if I have, these steps must be taken:
    - [ ] The backwards compatibility tests have been updated and/or new tests covering the changes have been added.
- [ ] My PR does not contain changes to the critical business logic or cryptographic code. Or if it does then these steps must be taken:
    - [ ] At least two people must be assigned as reviewers (and eventually approve!) the PR.
- [ ] I have not added new structs or modified struct to contain private or key data. Or if so then these steps must be taken:
    - [ ] The `zeroize` and `ZeroizeOnDrop` traits have been implemented to clean up private data.
- [ ] I have not added data to the public storage. Or if I have, then these steps must be taken:
    - [ ] I have ensured that the data does _not_ need to be trusted. I.e. it can be validated through a signature or the existence of a digest in the private storage.

### Checklist for dependency updates
For dependency updates the following essay questions _must_ be also answered and comments where the import of the dependency happens must be updated if there is any changes in the answers since the last update.
If this is the first time a new dependency is added, then the questions must be answered in the `toml` where the new dependency is imported:
1. Did ownership change change significantly since last update. Is the owner suspicious? I.e. is it limited to one or a few people or small companies in "dangerous territories"?
2. Is the crate not particularly popular?
3. Is there an unusual jump in package versions?
4. Is documentation lacking?
5. Is there no CI enabled on the project's GitHub?
6. Do the owners not make any statements in relation to security and
responsible disclosure of vulnerabilities?
7. Is there a significant change in size of the crate?

Finally, observe that an update or addition of a dependency will cause an update to secondary imports in `Cargo.lock`. We currently consider this an acceptable risk. Hence there is no need to manually modify `Cargo.lock`.

# Contributing to the Zama KMS

This document provides guidance on how to contribute to the Zama KMS.

There are two ways to contribute:

- **Report issues:** Open issues on GitHub to report bugs, suggest improvements, or note typos.
- **Submit code**: To become an official contributor, you must sign our Contributor License Agreement (CLA). Our CLA-bot will guide you through this process when you open your first pull request.

## 1. Setting up the project

Start by [forking](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/fork-a-repo) the **KMS** repository.

{% hint style="info" %}
- **Rust version**:  Ensure that you use a Rust version >= 1.86 to compile **KMS**.
- **Other requirements**: Have a look at the [README](README.md) for more requirements.
{% endhint %}

## 2. Creating a new branch

When creating your branch, make sure to use the following format :

```
git checkout -b user-name{feat|fix|docs|chore…}/[optional issue number]/short_description
```

For example:

```
git checkout -b linus/feat/223/new_feature_X
```

## 3. Before committing

### 3.1 Linting

Each commit to **KMS** should conform to the standards of the project. In particular, every source code, Docker or workflows files should be linted to prevent programmatic and stylistic errors.

To apply automatic code formatting and lint checking, run:

```
cargo fmt && cargo clippy --all-targets -- -D warnings && cargo clippy --all-targets --all-features -- -D warnings
```


### 3.2 Testing

Your contributions must include comprehensive documentation and tests without breaking existing tests. Use `cargo test --lib` to verify your contribution locally.

## 4. Committing

**Zama KMS** follows the conventional commit specification to maintain a consistent commit history, essential for Semantic Versioning ([semver.org](https://semver.org/)).
Make sure that you follow the commit conventions detailed on [this page](https://www.conventionalcommits.org/en/v1.0.0/).

## 5. Rebasing

Before creating a pull request, make sure your branch is up to date with the `main` branch. This ensures fewer conflicts and a smoother PR review process.

## 6. PR Checklist
Before a PR is created and a PR review is requested, the PR author should go over the following checklist and make sure that all top-level points (or the respective sub-levels) are checked.

### Checklist before requesting a review
- [ ] The PR title follows [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/), e.g. "chore: did something".
- [ ] Tests exist for all new `pub` methods and I checked that test coverage is at least as good as before this PR
- [ ] Code comments are in place for public methods and non-obvious code segments.
- [ ] Any unfinished business is documented with a `TODO(#issue_number)` comment and brief description of what needs to be fixed.
- [ ] `unwrap`, `expect` or `panic!` is only used in tests or in situations where it would imply that there is a bug in the code, and I have documented this.
- [ ] The PR is _not_ updating _any_ dependencies (i.e. no changes to `Cargo.toml` or `Cargo.toml`), or if it does:
    - [ ] I confirm there are _only_ changes needed to fix compilation and tests (see [here](#Checklist-for-dependency-updates) for details.), or changes that happened due to bumping an internal version number.
- [ ] Changes in the PR do not affect the architecture of the protocol. Or if they do these steps must be taken:
    - [ ] A parallel PR or issue has been opened in the [tech-spec repo](https://github.com/zama-ai/tech-spec) (add the link here).
- [ ] The PR does not contain any breaking changes to the configuration and deployment files.
      (A change is _only_ considered breaking if a deployment configuration must be changed as part of an update. Adding new fields, with default values is _not_ considered breaking). Or if it does then these steps must be taken:
    - [ ] The PR is labeled with `devops`.
    - [ ] I have pinged the infra team on Slack (in the MPC channel).
    - [ ] I have put a devops person on the PR as reviewer.
- [ ] The PR does not contain breaking changes to the gRPC interface or data serialized in the service gRPC interface. In particular there are no changes to the `extraData` fields. Or if it does the following steps have been taken:
    - [ ] The PR is marked using `!` in accordance with conventional commits. E.g. `chore!: changed decryption format according to Q3 release`.
    - [ ] The Gateway and Connector teams have been notified about this change.
- [ ] I have not changed existing `versionized` structs, nor added new `versionized` structs. Or if I have, these steps must be taken:
    - [ ] The backwards compatibility tests have been updated and/or new tests covering the changes have been added.
- [ ] The PR does not contain changes to the critical business logic or cryptographic code. Or if it does then these steps must be taken:
    - [ ] At least two people must be assigned as reviewers and eventually approve the PR.
- [ ] I have not added new structs or modified struct to contain private or key data. Or if so then these steps must be taken:
    - [ ] The `Zeroize` and `ZeroizeOnDrop` traits have been implemented to clean up private data.
- [ ] I have not added data to the public storage. Or if I have, then these steps must be taken:
    - [ ] I have ensured that the data does _not_ need to be trusted, i.e. it can be validated through a signature or the existence of a digest in the private storage.
- [ ] No untyped/loosely-typed input crosses module/service boundaries. Strong types (e.g. enums, `Duration`, `Url`, `PathBuf`, `IpAddr`, etc.) must be used and validate/parse at the edge.
- [ ] Public errors are typed (e.g. using `thiserror`), user-facing messages are actionable, and no generic `anyhow::Error` leaks across crate boundaries.
- [ ] No `unsafe` is used, unless it’s unavoidable, minimal, documented, and covered by targeted tests/fuzzing.
- [ ] I have performed a self-review of my code

### Checklist for dependency updates
For dependency updates the following essay questions _must_ also be answered and comments where the import of the dependency happens must be updated if there are any changes in the answers since the last update.
If this is the first time a new dependency is added, then the questions must be answered in the `Cargo.toml` where the new dependency is imported:
1. Did ownership change significantly since last update. Is the owner suspicious? I.e. is it limited to one or a few people or small companies in "dangerous territories"?
2. Is the crate not particularly popular?
3. Is there an unusual jump in package versions?
4. Is documentation lacking?
5. Is there no CI enabled on the project's GitHub?
6. Do the owners not make any statements in relation to security and
responsible disclosure of vulnerabilities?
7. Is there a significant change in size of the crate?

Finally, observe that an update or addition of a dependency will cause an update to secondary imports in `Cargo.lock`
We currently consider this an acceptable risk. Hence there is no need to manually modify `Cargo.lock`.


## 7. Opening a Pull Request

Once your changes are ready, open a pull request.

For instructions on creating a PR from a fork, refer to GitHub's [official documentation](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request-from-a-fork).

## 8. Continuous integration

Before a pull request can be merged, several test suites run automatically.

{% hint style="info" %}
## Useful details:

- pipeline is triggered by humans
- review team is located in Paris timezone, pipeline launch will most likely happen during office hours
- direct changes to CI related files are not allowed for external contributors
- run `make pcc` to fix any build errors before pushing commits
{% endhint %}

## 9. Details on data versioning

Data serialized inside the KMS must remain backward compatible. This is done using the [tfhe-versionable](https://crates.io/crates/tfhe-versionable) crate.

If you modify a type that derives `Versionize` in a backward-incompatible way, an upgrade implementation must be provided.

For example, these changes are data breaking:
 * Adding a field to a struct.
 * Changing the order of the fields within a struct or the variants within an enum.
 * Renaming a field of a struct or a variant of an enum.
 * Changing the type of a field in a struct or a variant in an enum.

On the contrary, these changes are *not* data breaking:
 * Renaming a type (unless it implements the `Named` trait).
 * Adding a variant to the end of an enum.

Historical data from previous KMS versions is stored inside `backward-compatibility`. They are used to check on every PR that backward compatibility has been preserved.

## Example: adding a field

Suppose you want to add an i32 field to a type named `MyType`. The original type is defined as:
```rust
#[derive(Serialize, Deserialize, Versionize)]
#[versionize(MyTypeVersions)]
struct MyType {
  val: u64,
}
```
And you want to change it to:
```rust
#[derive(Serialize, Deserialize, Versionize)]
#[versionize(MyTypeVersions)]
struct MyType {
  val: u64,
  other_val: i32
}
```

Follow these steps:

 1. Navigate to the definition of the dispatch enum of this type. This is the type inside the `#[versionize(MyTypeVersions)]` macro attribute. In general, this type has the same name as the base type with a `Versions` suffix. You should find something like

```rust
#[derive(VersionsDispatch)]
enum MyTypeVersions {
  V0(MyTypeV0),
  V1(MyType)
}
```

 2. Add a new variant to the enum to preserve the previous version of the type. You can simply copy and paste the previous definition of the type and add a version suffix:

```rust
#[derive(Version)]
struct MyTypeV1 {
  val: u64,
}

#[derive(VersionsDispatch)]
enum MyTypeVersions {
  V0(MyTypeV0),
  V1(MyTypeV1),
  V2(MyType) // Here this points to your modified type
}
```

 3. Implement the `Upgrade` trait to define how we should go from the previous version to the current version:
```rust
impl Upgrade<MyType> for MyTypeV1 {
  type Error = Infallible;

   fn upgrade(self) -> Result<MyType, Self::Error> {
       Ok(MyType {
           val: self.val,
           other_val: 0
        })
   }
}
```

 4. Fix the upgrade target of the previous version. In this example, `impl Upgrade<MyType> for MyTypeV0 {` should simply be changed to `impl Upgrade<MyTypeV1> for MyTypeV0 {`

# Common KMS Errors & Solutions

**Comprehensive error database with immediate solutions for KMS operational and development issues.**

> **Source**: This documentation started as an export of the [Zama Notion: Encountered Issues](https://www.notion.so/zamaai/Encountered-issues-1002797be84a470ea093930bc6c971a1) document. Entries about the retired KMS blockchain, gateway and connector have since been removed; edit this file directly.

# Encountered issues

A non-exhaustive list of issues that can be faced when using/developing the KMS

## Frequent errors and how to fix them

```jsx
SetGlobalDefaultError("a global default trace dispatcher has already been set")
```

This typically occurs if you are setting a tracer multiple times, e.g. through `tracing::subscriber::set_global_default`.

---

```jsx
WARN kms_lib::engine::service::epoch_manager: No epoch data found in storage. Create an MPC epoch before using threshold operations
```

The KMS servers have not executed the `init` step, which creates the default epoch and its PRSS state. This should be done automatically by the deployment (the `kmsInit` job of the Helm chart), but can also be done manually with [`kms-init`](../../../core/service/src/bin/kms-init.rs). Be aware that this must be done for all parties at the same time, e.g. with a command like this

```jsx
kms-init --addresses http://kms-threshold-1-threshold-core_kms-threshold_svc_50100.mesh:80 http://kms-threshold-2-threshold-core_kms-threshold_svc_50100.mesh:80 http://kms-threshold-3-threshold-core_kms-threshold_svc_50100.mesh:80 http://kms-threshold-4-threshold-core_kms-threshold_svc_50100.mesh:80
```

If `init` did run, the PRSS state of the default epoch should be stored under `keys/PRIV-pX/EpochData/0800..0001` (where `pX` refers to the parties `p1`, `p2`, etc.) and is not located there or is corrupted.

---

Persistent errors in the wasm compilation and tests. E.g. this:

```jsx
error[E0432]: unresolved import `crate::sys::IoSourceState`
```

This is likely due to a missing `#[cfg(feature = "non-wasm")]` for code that is imported by the wasm code in `core/service/src/client/` (`client_wasm.rs`, `user_decryption_wasm.rs`, `js_api.rs`).

---

## TFHE-rs version mismatch

Happened once when two deployed versions didn’t use the same TFHE-rs version.
In this case one has to be extra-careful otherwise trying to load the public key might crash.

The error can look something like (but depends on the specific version/file type):

```bash
called `Result::unwrap()` on an `Err` value: reading failed on url file:///Users/dd/git/kms/core/service/keys/CLIENT/SigningKey/fe2f1a79515d96c5799df3f6fe6d848a4477d555: invalid value: integer `32`, expected variant index 0 <= i < 1
```

When running tests, a workaround can be to delete the `keys` directory in `core/service` and regenerate the test material (`make clean-test-material`, then `make generate-test-material-testing`).

## Result of decryption is incorrect

Happened once because the public key being used was not the proper pair of the private key being deployed. Do not rely on the name of the key to make sure that you have a proper pair.
In this case copy the public key from the adequate place (S3 bucket, Docker container, Kubernetes pod …)

## Ports errors

Can happen to anyone if not careful enough. This is just a simple reminder to always make sure that the proper ports are exposed to your [localhost](http://localhost) when using the kubernetes cluster or the docker containers. Some confusion can happen from similar services (similar name and basically same function) from the FHEVM and the KMS using similar but different ports.

## Install errors

- `The system library openssl required by crate openssl-sys was not found.`

    Solution:    `sudo apt-get install libssl-dev`


## Too many files error

The error `"Too many open files”` on a Mac has an easy fix. Adding the `ulimit -n 1024` statement to your bash profile using **sudo nano .bash_profile** handles it.

## Tracing logs for unit tests

The following code snippet can be called for example from a unit test to see proper tracing logs.

It does the following things and can naturally be customized accordingly:

- it shows `DEBUG` logs for `kms_lib` (core service) and `threshold_execution` (MPC protocols) and restricts tonic to `INFO` logs (the debug ones are excessive).
- It writes the logs to a file (`mylog.log`).

```rust
    use tracing_appender::rolling::{RollingFileAppender, Rotation};
    use tracing_subscriber::fmt::writer::MakeWriterExt;

    pub fn setup_logging() {
        let file_appender = RollingFileAppender::new(Rotation::DAILY, "logs", "mylog.log");
        let file_and_stdout = file_appender.and(std::io::stdout);
        let subscriber = tracing_subscriber::fmt()
            .with_writer(file_and_stdout)
            .with_ansi(false)
            .with_env_filter("kms_lib=debug,threshold_execution=debug,tonic=info")
            .finish();
        tracing::subscriber::set_global_default(subscriber).expect("Failed to set subscriber");
    }
```

## Build local core docker images

```bash
docker compose -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml build dev-kms-core-1
```

If you were using the docker files directly it would be:

```bash
make build-compose-kms-binaries
docker build -f docker/core/service/Dockerfile --target dev \
  --build-arg KMS_BINARIES_IMAGE=ghcr.io/zama-ai/kms/kms-binaries-insecure:latest-dev \
  -t ghcr.io/zama-ai/kms/core-service-insecure:latest-dev .
```

## `assertion 'left == right' failed` from tfhe-rs

When getting an issue like in https://github.com/zama-ai/kms-core/issues/1422#issuecomment-2460248552 :

```jsx
thread '<unnamed>' panicked at /var/cache/buildkit/cargo/registry/src/index.crates.io-6f17d22bba15001f/tfhe-0.9.1/src/core_crypto/algorithms/lwe_programmable_bootstrapping/fft64.rs:252:5:
assertion `left == right` failed
  left: LweSize(1281)
 right: LweSize(1025)
```

- this most likely indicates a tfhe-rs version mismatch :
    - error indicates that we are using a decompression key different from the one used for compressing the input ciphertext
    - in particular, this was using keys from tfhe-rs 0.8 or prior
- solution was to use the latest generated keys from the deployed storage

## Building docker images fail with a requirement to use `docker login`

Trying to build docker images give the following error:

```jsx
Error response from daemon: pull access denied for tfhe-core, repository does not exist or may require 'docker login'
```

Either use [this link](https://github.com/settings/tokens) or go to your GitHub, click you profile picture, select "Settings". Then  navigate to "Developer Settings" > "Personal Access Tokens" >  "Tokens (classic)" > "Generate new token (classic)". The token should have the "read:packages" permission. Afterwards, do `docker login ghcr.io` and use your github ID and the token to login. Note that this token is saved by docker locally in the clear, so it's best to only give it the  permissions you need and set the expiration time to a short period of  time.

## adding `RUST_LOG=info` (or `trace`)does not print any logs

- try to see if there is an `init_tracing` in what you run (ex: a test)
- check if there is an `await` at the end of it :
    - if not, add it
    - try again

## Core crashes with error 137

Running the servers in docker results in a crash with something like the following:

```jsx
dev-kms-core-1-1 exited with code 137
```

This is due to Docker running out of memory. By default Docker only uses 8 GB of memory, but to run tests, even for just 4 parties. Significantly more is needed. It is recommended to increase it to 24 Gb (although the tests for 4 parties will likely work with less).

Hence to fix the issue change your local Docker settings to ensure it has enough RAM

## Error loading from [ghcr.io](http://ghcr.io) during docker image generation

Running the following results in an error

```jsx
docker compose -vvv -f docker-compose-core-base.yml -f docker-compose-core-threshold.yml build
[+] Building 12.4s (8/8) FINISHED
 => [internal] load local bake definitions                                    0.0s
 => => reading from stdin 3.40kB                                              0.0s
 => [dev-kms-core-3 internal] load build definition from Dockerfile           0.0s
 => => transferring dockerfile: 4.26kB                                        0.0s
 => [dev-kms-core-certs] resolve image config for docker-image://docker.io/d  1.0s
 => CACHED [dev-kms-core-2] docker-image://docker.io/docker/dockerfile:1@sha  0.0s
 => => resolve docker.io/docker/dockerfile:1@sha256:9857836c9ee4268391bb5b09  0.0s
 => [dev-kms-core-2 internal] load metadata for docker.io/library/golang:1.2  0.7s
 => CANCELED [dev-kms-core-certs internal] load metadata for cgr.dev/chaingu  0.9s
 => ERROR [dev-kms-core-2 internal] load metadata for ghcr.io/zama-ai/kms/ru  0.9s
```

This is due to failed authentication. It can be that you have not authorized yet, or that your token is invalid, expired or do not contain the right permissions for Zama.

- First ensure you have a proper token: Go to github -> Settings → Developer Settings → Personal Access Tokens
- If there is a token then ensure that zama-ai is authorized by clicking “Configure SSO” and “Authorize” if needed.
- If no token is there, generate a new one using “Generate new token”
- On your local machine add the token for your github user

```jsx
echo '<classic PAT with Zama authorized>' | docker login ghcr.io -u <my_username> --password-stdin
```

## Error loading from cgr.dev during docker image generation

When trying to compile the docker images an error in relation to [cgr.dev](http://cgr.dev) or chainguard will be presented.

For this to work you must ensure that you have configured a valid access toke to the chainguard images.

**⚠️ NOTE:** when you use the sign-up link it is essential to use you Zama google account *not* your github account, to sign in.

**NOTE: never** use the tokens in CI or post them in the repo or other public places. The tokens are meant for local development.

Navigate to this page [https://console.chainguard.dev/org/zama.ai/settings/pull-tokens](https://console.chainguard.dev/org/zama.ai/settings/pull-tokens) and then setup a new pull token and configure this in your command line using the suggested command after token generation.

If you do not have owner rights, or access to chainguard then request access in the Working-tools slack channel.

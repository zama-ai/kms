# Architecture

This document describes the architecture of the Zama KMS: a key-management
service for fully homomorphic encryption facilitated by [TFHE-rs](https://github.com/zama-ai/tfhe-rs).
The system supports key generation, CRS generation and decryption in both a single-party centralized service or as an `n`-party threshold MPC cluster.
Input and output happen through gRPC and is designed to be triggered and consumed by [FHEVM](https://github.com/zama-ai/fhevm).

The underlying MPC protocol is maliciously secure and robust; see
[Noah's Ark (eprint 2023/815)](https://eprint.iacr.org/2023/815) for the formal
treatment.

## System context

At the top level, an FHEVM deployment is composed of three subsystems:

1. A **host chain** (EVM L1) that stores ciphertexts on-chain.
2. An **FHEVM Gateway** that coordinates user requests.
3. The **KMS** (this repository) that holds FHE key material and performs
   key generation, public/user decryption, CRS generation, and reshare
   operations.

The KMS exposes a gRPC API. In the threshold deployment the KMS is itself a
cluster of `n` independent parties (typically 13 parties, threshold `t = 4`)
that run an MPC protocol among themselves; each party runs the same binary with
its own configuration and secret share.

A single deployment mode is chosen at startup via the server configuration
(centralized vs. threshold). The gRPC surface is shared between modes; a few
RPCs (preprocessing, reshare) are only meaningful in threshold mode.

The configuration of the set of servers is handled through MPC contexts, which are also managed by the FHEVM.

The system supports automatic backup, facilitated either through AWS KMS, or through a custom threshold protocol where Custodians hold keys that can be used to help KMS nodes decrypt encrypted backups. The settings and administration for this is also managed through gRPC calls with the notion of Custodian contexts. 

## Workspace layout

The repository is a Cargo workspace. The members are declared in
[Cargo.toml](Cargo.toml).

### Core cryptography / MPC

| Crate | Path | Responsibility |
|---|---|---|
| `threshold-fhe` | [core/threshold/](core/threshold/) | Threshold FHE protocol: DKG, preprocessing, online protocols |
| `threshold-algebra` | [core/threshold-algebra/](core/threshold-algebra/) | Finite-field and group primitives used by the MPC protocols |
| `threshold-execution` | [core/threshold-execution/](core/threshold-execution/) | Execution / orchestration layer for distributed computations |
| `threshold-networking` | [core/threshold-networking/](core/threshold-networking/) | Inter-party gRPC transport and choreography |
| `threshold-hashing` | [core/threshold-hashing/](core/threshold-hashing/) | Hashing primitives used across the MPC stack |
| `threshold-types` | [core/threshold-types/](core/threshold-types/) | Shared types and constants |
| `threshold-experimental` | [core/threshold-experimental/](core/threshold-experimental/) | Experimental protocol components (e.g. homomorphic PRF keygen) |

### Service layer

| Crate | Path | Responsibility |
|---|---|---|
| `kms` | [core/service/](core/service/) | KMS service library and binaries — the packaging around the core crypto |
| `kms-grpc` | [core/grpc/](core/grpc/) | Protobuf definitions + generated types and client stubs |
| `core-client` | [core-client/](core-client/) | CLI client that drives the gRPC API |
| `observability` | [observability/](observability/) | OpenTelemetry / Prometheus wiring |
| `bc2wrap` | [bc2wrap/](bc2wrap/) | Version-pinned `bincode` wrapper used for on-disk and on-wire encoding |
| `error-utils` | [core/error-utils/](core/error-utils/) | Shared error types and helpers |
| `thread-handles` | [core/thread-handles/](core/thread-handles/) | Rayon thread-pool management |

Auxiliary tools live under [tools/](tools/): `kms-health-check` is a gRPC
health probe and `generate-test-material` produces reproducible crypto test
vectors. Shared test fixtures are in [core/test-utils/](core/test-utils/).
The [backward-compatibility/](backward-compatibility/) crate is a separate
Cargo workspace — see [Backward compatibility](#backward-compatibility).

## The service crate (`core/service`)

The service crate is the main surface area. Key subdirectories under
[core/service/src/](core/service/src/):

- [engine/](core/service/src/engine/) — RPC handlers and KMS state machines.
  Split into [centralized/](core/service/src/engine/centralized/) and
  [threshold/](core/service/src/engine/threshold/) submodules. Other notable
  files: [base.rs](core/service/src/engine/base.rs),
  [context.rs](core/service/src/engine/context.rs),
  [backup_operator.rs](core/service/src/engine/backup_operator.rs),
  [keyset_configuration.rs](core/service/src/engine/keyset_configuration.rs),
  [validation_non_wasm.rs](core/service/src/engine/validation_non_wasm.rs) and
  [validation_wasm.rs](core/service/src/engine/validation_wasm.rs) (the
  validation logic is compiled for both native and WASM so that clients can
  verify user-decryption responses in the browser).
- [vault/](core/service/src/vault/) — pluggable storage for key material.
  Backends include AWS S3, local file, AWS KMS, and AWS Nitro Enclaves. Root
  keys and key-encryption logic live in
  [vault/keychain/](core/service/src/vault/keychain/).
- [backup/](core/service/src/backup/) — custodian-based secret-sharing backup
  of long-term signing / root keys, used for disaster recovery. See
  [Backup and recovery](#backup-and-recovery) below.
- [cryptography/](core/service/src/cryptography/) — AES-GCM-SIV, signcryption,
  hybrid ML-KEM (post-quantum), and attestation (Nitro NSM + certificate
  chain verification).
- [client/](core/service/src/client/) and
  [testing/](core/service/src/testing/) — client-side helpers and
  test-only wiring.
- [bin/](core/service/src/bin/) — entry points (see below).

### Binaries

All under [core/service/src/bin/](core/service/src/bin/):

- [kms-server.rs](core/service/src/bin/kms-server.rs) — main service process.
- [kms-init.rs](core/service/src/bin/kms-init.rs) — post-deployment cluster
  initialization.
- [kms-gen-keys.rs](core/service/src/bin/kms-gen-keys.rs) — generate the server
  signing keys (and, in threshold mode, per-party self-signed CA certificates
  for mTLS). Supports `--mock-enclave` for local dev, must be compiled with the
  `insecure` feature.
- [kms-custodian.rs](core/service/src/bin/kms-custodian.rs) — custodian-side
  tool for producing and recovering backup shares.
- [kms-gen-tls-certs.rs](core/service/src/bin/kms-gen-tls-certs.rs) — TLS
  certificate generation for inter-party mTLS.

## gRPC surface

Protobuf definitions live in [core/grpc/proto/](core/grpc/proto/). The main
service definition is
[kms-service.v1.proto](core/grpc/proto/kms-service.v1.proto); shared messages
are in [kms.v1.proto](core/grpc/proto/kms.v1.proto); an insecure transport
variant is in
[kms-service-insecure.v1.proto](core/grpc/proto/kms-service-insecure.v1.proto);
metastore status types in
[metastore-status.v1.proto](core/grpc/proto/metastore-status.v1.proto).

The primary service is `CoreServiceEndpoint`. Its RPCs group into:

- **Key generation** — `KeyGenPreproc` / `KeyGenPreprocResult` (threshold
  preprocessing), `KeyGen`, and `NewEpoch` for key rotation. Multiple keyset
  configurations are supported (standard, decompression-only, compressed
  variants).
  Standard threshold keygen persists a dedicated OPRF LWE secret-key share in
  each party's private key material and includes the corresponding OPRF server
  key in the generated TFHE server key. Legacy private keysets that predate this
  field are upgraded with the OPRF share absent; `UseExisting` keygen generates
  and persists a fresh OPRF share for such legacy material before regenerating
  public keys.
- **Decryption** — `PublicDecrypt` (returns plaintext) and `UserDecrypt`
  (user-initiated, EIP-712 authenticated).
- **CRS** — `CRSGen` for ZK-proof common reference strings.
- **Reshare** — `Reshare` to rotate parties / refresh secret shares. When
  resharing legacy key material that has no dedicated OPRF secret-key share,
  the OPRF sub-protocol is skipped and the reshared private keyset keeps that
  field absent.
- **Session management** — creation, result retrieval, and cleanup for
  long-running threshold sessions.

EIP-712 signature validation on user-decryption requests is shared between
the server and in-browser verifiers via the `validation_wasm` build.

## Deployment modes

Mode is selected in the server TOML config (`[kms_mode]`); see the sample
files in `core/service/config/` (`default_centralized.toml`,
`default_1.toml`..`default_4.toml`, and the compose-specific variants).

### Centralized

A single `RealCentralizedKms` instance holds all key material. No MPC; keys
live in the configured vault backend. Preprocessing / reshare RPCs are not
applicable.

### Threshold

`n` parties each run a `ThresholdKms` server. Each party holds a secret share
of the FHE secret key and participates in the MPC protocol for every
sensitive operation. Parties reach each other over gRPC via
`threshold-networking` (typically with mTLS using certs generated by
`kms-gen-tls-certs`). Preprocessing runs asynchronously and produces material
consumed by the online phase.

## Backup and recovery

Long-term private material held by a KMS node — signing keys, FHE secret-key
shares, custodian / MPC context state — is automatically backed up so that a
node whose local storage is lost can be rebuilt without reconstructing the
whole cluster. Secrets are wrapped into versioned `BackupCiphertext`s
(tagged by `RequestId` and `PrivDataType`) and written to the configured
backup vault, typically S3.

The payload-wrapping key is protected by one of two **keychains**, selected
in server config and unified behind `KeychainProxy`
([core/service/src/vault/keychain/](core/service/src/vault/keychain/)):

- **`AwsKms`** — wrapping key is an AWS KMS CMK. Default and bootstrap path.
- **`SecretSharing`** — wrapping key is Shamir-shared across a set of
  **custodians**, offline entities who each hold a key share plus a BIP39
  seed phrase. A custodian context must already be installed before a node
  can be switched to this mode; the usual flow is to boot on the AWS KMS
  keychain, provision custodians, then restart against the secret-sharing
  keychain.

Custodian workflows are driven through the
[kms-custodian](core/service/src/bin/kms-custodian.rs) CLI and the
`NewCustodianContext` / `DestroyCustodianContext` / `CustodianRecoveryInit`
/ `CustodianBackupRecovery` RPCs defined in
[kms-service.v1.proto](core/grpc/proto/kms-service.v1.proto). A separate
`RestoreFromBackup` RPC completes restoration on the node and also covers
the no-custodian AWS-KMS path.

Implementation code lives in [core/service/src/backup/](core/service/src/backup/);
end-to-end tests live at
[core/service/src/client/tests/centralized/custodian_backup_tests.rs](core/service/src/client/tests/centralized/custodian_backup_tests.rs)
and
[core/service/src/client/tests/threshold/custodian_backup_tests.rs](core/service/src/client/tests/threshold/custodian_backup_tests.rs).

## Backward compatibility

The KMS must read material produced by earlier releases: a fresh binary
pointed at an existing vault has to load and use whatever is already there.
Compatibility is enforced at two levels.

**Versioning trait.** Every type written to disk or sent over the wire uses
[`tfhe-versionable`](https://crates.io/crates/tfhe-versionable): it derives
`Versionize` / `VersionsDispatch`, implements `Named`, and is wrapped in an
enum whose variants are its historical layouts (`V0`, `V1`, …).
`Unversionize` dispatches to the right variant by tag on read. On-disk and
on-wire encoding goes through the pinned-`bincode` wrapper
[bc2wrap](bc2wrap/) so the binary layout is deterministic. Examples of
versioned types: `BackupCiphertextVersioned`,
`InternalCustodianContextVersioned`, `AppKeyBlobVersioned`.

**Freeze-and-replay harness.** [backward-compatibility/](backward-compatibility/)
is a separate Cargo workspace (excluded from the root — see [Cargo.toml](Cargo.toml)
— because each pinned historical version drags in a conflicting dependency
graph). Per-version `generate-vX.Y.Z/` crates serialize a catalogue of types
using that release's dependencies; the artifacts land under
[backward-compatibility/data/](backward-compatibility/data/) (Git-LFS-tracked)
indexed by per-module `.ron` manifests. The loader in
[backward-compatibility/src/](backward-compatibility/src/) replays every
entry through the current-version `Unversionize` and asserts the expected
metadata.

To add support for a new release, follow
[backward-compatibility/ADDING_NEW_VERSIONS.md](backward-compatibility/ADDING_NEW_VERSIONS.md).
The top-level [Makefile](Makefile) exposes `test-backward-compatibility`
(run the loader against stored LFS vectors),
`test-backward-compatibility-local` (against locally regenerated vectors),
and `generate-backward-compatibility-*` targets to refresh vectors.

## External dependencies

The [Cargo.toml](../Cargo.toml) should be considered the ground truth.

## Testing

- **Unit tests** live alongside the source (`#[cfg(test)]`).
- **Integration tests** live in each crate's `tests/` directory, notably
  `core/service/tests/` and `core/threshold/tests/integration_redis.rs`.
- **Backward-compatibility tests** live under
  [backward-compatibility/](backward-compatibility/); per-version generator
  crates produce frozen test vectors that current-version loaders must
  accept. See [Backward compatibility](#backward-compatibility) for the full
  picture.
- **Docker-compose harness** — see [docker-compose.md](docker-compose.md) and
  the compose files at the repo root
  (`docker-compose-core-base.yml`, `docker-compose-core-threshold.yml`,
  `docker-compose-core-centralized.yml`) for a local multi-party network
  plus S3-mock, Redis, and telemetry sidecars.
- **Cargo feature flags** — `testing` enables test-only APIs; `slow_tests`
  enables the long-running suite.

See the "Building and testing" section of [README.md](README.md) for the
exact commands.

## Build and deployment

- **Toolchain** — Latest stable Rust (`rust-toolchain`) along with Protobuf (`protoc`). Docker is also required for the test harness for some integration tests.
- **Makefile** — [Makefile](Makefile) provides compose orchestration,
  backward-compat vector generation, test-material generation, and lint
  targets.
- **Container images** — [docker/core/service/Dockerfile](docker/core/service/Dockerfile)
  is a multi-stage build producing the `core-service` image (published as
  `ghcr.io/zama-ai/kms/core-service`). Its entrypoint generates signing
  keys and TLS certs on first boot, then runs `kms-server`.
- **Kubernetes** — a Helm chart is provided at
  [charts/kms-core/](charts/kms-core/) for both centralized and threshold
  deployments, including Nitro Enclaves when configured.

## Further reading

- Cryptographic specification:
  [CryptographicDocumentation.pdf](https://github.com/zama-ai/threshold-fhe/blob/main/docs/CryptographicDocumentation.pdf).
- Protocol paper: [Noah's Ark, eprint 2023/815](https://eprint.iacr.org/2023/815).
- User documentation: [docs/](docs/) and the "Using the KMS" section of
  [README.md](README.md).
- Contribution workflow: [CONTRIBUTING.md](CONTRIBUTING.md).
- Security policy: [SECURITY.md](SECURITY.md).

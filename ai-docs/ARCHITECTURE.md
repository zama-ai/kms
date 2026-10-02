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

The configuration of the set of servers is handled through MPC contexts, which are also managed by the FHEVM. Threshold KMS deployments using Nitro Enclave remote attestation reject both new and stored contexts whose PCR allowlist is empty; stored contexts that fail validation are skipped during startup. Non-enclave and mocked-enclave deployments permit an empty allowlist.

The system supports automatic backup, facilitated either through AWS KMS, or through a custom threshold protocol where Custodians hold keys that can be used to help KMS nodes decrypt encrypted backups. The settings and administration for this is also managed through gRPC calls with the notion of Custodian contexts.

## Communication interfaces and trust model

Read this section before you review code for security issues or judge a security report. The full text is in [docs/explanations/trust_model.md](../docs/explanations/trust_model.md).

A KMS core listens on two separate gRPC interfaces:

1. **Core-to-core interface** (`[threshold]` section, default port 50001, crate [threshold-networking](../core/threshold-networking/)). A peer-to-peer network between the KMS cores of one deployment. It carries the MPC protocol messages.
2. **Service interface** (`[service]` section, default port 50100, `CoreServiceEndpoint` in [kms-service.v1.proto](../core/grpc/proto/kms-service.v1.proto)). The [KMS connector](https://github.com/zama-ai/fhevm/tree/main/kms-connector) calls it to start an operation and to fetch the result. It is an orchestrator channel: the connector says which operation to run, and the cores run the MPC protocol over the core-to-core interface.

The **core-to-core interface** is guarded by mutual TLS. A node only accepts connections from the allowlisted set of peers in its peer list and MPC contexts. The receiver checks that the sender named in each message matches the Common Name of the peer certificate. In Nitro Enclave deployments (`tls.auto`), the verifier also checks the PCR values in the attestation document against `trusted_releases`, so a node only talks to peers that run an allowlisted release. PCR0 is the hash of the whole enclave image file, PCR1 the hash of the kernel and bootstrap ramdisk, and PCR2 the hash of the application root filesystem; all three must match one allowlisted entry, and when `eif_signing_cert` is configured PCR8 (hash of the image signing certificate) is checked against the certificate bundled in the peer's TLS certificate. Production deployments always run this interface with TLS enabled; a TLS-off configuration needs the `insecure` cargo feature and is used only for debugging and testing. Authenticated peers are still mutually distrusting MPC parties: up to `t` of them may be malicious, so the content of a peer message is adversarial input and the protocol code validates it.

The **service interface** has no TLS, no authentication and no authorization in the code, and it does not verify the intent of a request. It trusts and accepts every message it receives. The deployment guarantees, at the infrastructure level, that exactly one KMS connector can reach this interface. That connector is operated by the same party that runs the KMS core, so the two trust each other by definition. The interface is never publicly reachable.

Validation of a request is split across the stack. The [KMS connector](https://github.com/zama-ai/fhevm/tree/main/kms-connector) performs the ACL checks on ciphertext handles and only forwards events emitted by the gateway contracts. Input proofs, verified on smart contract level and by the coprocessor, ensure that a ciphertext is well formed before it reaches the chain. The KMS core verifies EIP-712 signatures on user decryption requests, authenticates peers, and validates protocol messages.

Request IDs work as follows. The gateway contracts assign each ID and bind it to its ciphertexts, and the connector resends the same payload on a retry, so the core assumes that a known ID carries the same ciphertexts as before. A meta store per operation type in the core tracks every accepted ID; MPC session IDs derive from the request ID, so this also stops a second MPC session under a used session ID. Key generation, preprocessing, CRS generation and context or epoch management reject a known ID with `AlreadyExists`. `PublicDecrypt` and `UserDecrypt` do the same unless the earlier attempt failed, in which case they reset the entry and decrypt again (`add_or_redo_failed_in_meta_store`). `PublicDecryptSync` and `UserDecryptSync` attach to the existing entry and return its result. A repeated decryption of the same ciphertexts is not a finding.

The meta store is in-memory only, so a reboot of the core forgets every known request and session ID. The KMS connector keeps the state of each request in its [persistent database](https://github.com/zama-ai/fhevm/tree/main/kms-connector/connector-db); its [kms-worker](https://github.com/zama-ai/fhevm/tree/main/kms-connector/crates/kms-worker) marks a request as sent and only polls for the result on a retry, so a request is not run more often than necessary across core reboots.

Consequences for agents:

- The threat model assumes that at most `t` of the `n` parties are malicious. An attack that needs more than `t` malicious parties is out of scope. Every attack that works with at most `t` malicious parties is in scope: bypassing TLS, attestation or sender binding on the core-to-core interface, or breaking the confidentiality of the key material or the correctness of a result.
- Do not report missing authentication, authorization or rate limiting on the service interface, or any finding in which the connector itself is the attacker, as a vulnerability. Such a finding describes the design.
- Values inside a request that originate from external clients and pass through the smart contracts and the connector unchanged are untrusted: ciphertexts and handles, user public encryption keys, EIP-712 signatures and domains, and parameter selectors such as the FHE parameter set or keyset configuration. The core must process them without a service outage (crash, stall, unbounded allocation) and without a confidentiality break. Such a finding is in scope even though the request arrives over the service interface.
- Do not add authentication or authorization to the service interface unless your human asks for it.
- Code that is not used in production is out of scope for security findings: the experimental BGV/BFV schemes in [core/threshold-bgv/](../core/threshold-bgv/), the benchmark and experiment harnesses in [core/experiments/](../core/experiments/), and any other code marked as experimental.
- Every security finding you report must cite the commit hash or tag you analyzed and the file path and line numbers of every code location it relies on. Verify each pointer against the checked-out tree before you report it.

## Workspace layout

The repository is a Cargo workspace. The members are declared in
[Cargo.toml](../Cargo.toml).

### Core cryptography / MPC

| Crate                  | Path                                                        | Responsibility                                                                                                       |
| ---------------------- | ----------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `threshold-algebra`    | [core/threshold-algebra/](../core/threshold-algebra/)       | Finite-field and group primitives used by the MPC protocols                                                          |
| `threshold-execution`  | [core/threshold-execution/](../core/threshold-execution/)   | Threshold FHE protocol execution: DKG, preprocessing, online protocols                                               |
| `threshold-bgv`        | [core/threshold-bgv/](../core/threshold-bgv/)               | Experimental BGV/BFV schemes with distributed keygen and threshold decryption                                        |
| `threshold-networking` | [core/threshold-networking/](../core/threshold-networking/) | Inter-party gRPC transport and choreography                                                                          |
| `threshold-hashing`    | [core/threshold-hashing/](../core/threshold-hashing/)       | Hashing primitives used across the MPC stack                                                                         |
| `threshold-types`      | [core/threshold-types/](../core/threshold-types/)           | Shared types and constants                                                                                           |
| `experiments`          | [core/experiments/](../core/experiments/)                   | Benchmark and experiment harnesses (see [docs/guides/threshold-benchmark.md](../docs/guides/threshold-benchmark.md)) |

### Service layer

| Crate            | Path                                            | Responsibility                                                                                                                                                                                                                                                                                                                                                                                           |
| ---------------- | ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `kms`            | [core/service/](../core/service/)               | KMS service library and binaries — the packaging around the core crypto                                                                                                                                                                                                                                                                                                                                  |
| `kms-grpc`       | [core/grpc/](../core/grpc/)                     | Protobuf definitions + generated types and client stubs                                                                                                                                                                                                                                                                                                                                                  |
| `core-client`    | [core-client/](../core-client/)                 | CLI client that drives the gRPC API                                                                                                                                                                                                                                                                                                                                                                      |
| `observability`  | [observability/](../observability/)             | OpenTelemetry / Prometheus wiring                                                                                                                                                                                                                                                                                                                                                                        |
| `vsocktun`       | [vsocktun/](vsocktun/)                          | Multi-queue, offload-aware TUN-to-VSOCK relay used by Nitro enclave deployment scripts to preserve end-to-end peer TCP while bridging enclave IP traffic through the parent, including raw virtio-net TUN frames when both ends support offload metadata; the parent side also bootstraps the enclave-side tunnel CIDR, MTU, shard count, and rewritten resolver config over the same VSOCK control port |
| `bc2wrap`        | [bc2wrap/](../bc2wrap/)                         | Version-pinned `bincode` wrapper used for on-disk and on-wire encoding                                                                                                                                                                                                                                                                                                                                   |
| `error-utils`    | [core/error-utils/](../core/error-utils/)       | Shared error types and helpers                                                                                                                                                                                                                                                                                                                                                                           |
| `thread-handles` | [core/thread-handles/](../core/thread-handles/) | Rayon thread-pool management                                                                                                                                                                                                                                                                                                                                                                             |

Auxiliary tools live under [tools/](../tools/): `kms-health-check` is a gRPC
health probe and `generate-test-material` produces reproducible crypto test
vectors. Shared test fixtures and generic local file helpers are in
[core/test-utils/](../core/test-utils/).
The [backward-compatibility/](../backward-compatibility/) crate is a separate
Cargo workspace — see [Backward compatibility](#backward-compatibility).

## The service crate (`core/service`)

The service crate is the main surface area. Key subdirectories under
[core/service/src/](../core/service/src/):

- [engine/](../core/service/src/engine/) — RPC handlers and KMS state machines.
  Split into [centralized/](../core/service/src/engine/centralized/) and
  [threshold/](../core/service/src/engine/threshold/) submodules. Other notable
  files: [base.rs](../core/service/src/engine/base.rs),
  [context.rs](../core/service/src/engine/context.rs),
  [backup_operator.rs](../core/service/src/engine/backup_operator.rs),
  [keyset_configuration.rs](../core/service/src/engine/keyset_configuration.rs),
  [material_integrity.rs](../core/service/src/engine/material_integrity.rs) (digest
  primitives over raw stored bytes, depended on by both the storage layer and the
  startup checks),
  [public_material_sync.rs](../core/service/src/engine/public_material_sync.rs) (the
  digest-verified peer fetcher shared with resharing, and the boot-time repair of public
  storage built on it) and
  [storage_material_verification.rs](../core/service/src/engine/storage_material_verification.rs)
  (the read-only startup checks on top of both — see
  [Boot-time storage verification](#boot-time-storage-verification)),
  [validation_non_wasm.rs](../core/service/src/engine/validation_non_wasm.rs) and
  [validation_wasm.rs](../core/service/src/engine/validation_wasm.rs) (the
  validation logic is compiled for both native and WASM so that clients can
  verify user-decryption responses in the browser).
- [vault/](../core/service/src/vault/) — pluggable storage for key material.
  Backends include AWS S3, local file, AWS KMS, and AWS Nitro Enclaves. Root
  keys and key-encryption logic live in
  [vault/keychain/](../core/service/src/vault/keychain/).
- [backup/](../core/service/src/backup/) — custodian-based secret-sharing backup
  of long-term signing / root keys, used for disaster recovery. See
  [Backup and recovery](#backup-and-recovery) below.
- [cryptography/](../core/service/src/cryptography/) — AES-GCM-SIV, signcryption,
  hybrid ML-KEM (post-quantum), MLKEM1024-P384 (a composite of post-quantum
  ML-KEM-1024 and classical P-384), and attestation (Nitro NSM + certificate
  chain verification). Custodian backup uses MLKEM1024-P384 for all three of its
  keypairs — the custodian's long-term key, the operator's ephemeral recovery key,
  and the operator's per-context backup vault key — selected in one place,
  `backup::BACKUP_PKE_SCHEME`. A new custodian context is rejected unless every
  custodian encryption key, and the operator's own backup key, uses that scheme
  (`InternalCustodianContext::new` / `validated_nodes`).
  User decryption accepts ML-KEM-512 only. Randomly generated MLKEM1024-P384
  keypairs use a 256-bit-seeded CSPRNG. The custodian key derives directly from 256-bit mnemonic entropy. Signing lives under
  [cryptography/signing/](../core/service/src/cryptography/signing/): a
  scheme-tagged `Signature` plus one backend per scheme — ECDSA/secp256k1
  (`ecdsa`, the legacy default and EIP-712 home), EdDSA/ed25519 (`eddsa`), and
  ML-DSA/FIPS-204 (`mldsa`) — behind the `SigningScheme` trait and the
  `unified_sign`/`unified_verify` entry points. The historic
  `cryptography::signatures` path is a re-export facade. A node persists two
  private objects: its ECDSA signing key (`PrivDataType::SigningKey`, the
  authoritative on-chain identity) and an independent, CSPRNG-generated
  `RootSigningSeed` (`PrivDataType::SigningSeed`), both under `SIGNING_KEY_ID`.
  The seed will eventually be the root of _every_ signing key of the node, ECDSA
  included: keys are derived on demand from the _seed_. To keep backward
  compatibility, and to avoid making nodes roll their ECDSA keys, an ECDSA key is
  also stored on its own, and the seed serves every non-ECDSA scheme. That is, if
  a stored ECDSA key exists, then the seed does _not_ derive the ECDSA material.
  The two halves come together in memory as `signing::identity::NodeSigningIdentity`,
  which `get_core_signing_identity` assembles and `BaseKmsStruct::signing_identity`
  hands out. `NodeSigningIdentity` is never persisted, and it is the only type with
  the multi-scheme `unified_sign_with` / `unified_verifying_key` methods:
  `PrivateSigKey` is the ECDSA leaf type, which client wallets and the WASM
  surface also use. An identity with no seed — a node that has not yet run
  `kms-gen-keys` — can only do ECDSA, and errors with
  `SigningError::MissingRootSeed` for anything else. On the client side,
  `Client::verify_result_signatures` checks a result's per-scheme `signatures`
  against the peers' published keys, which `Client::new_client` reads from
  `PubDataType::TypedVerfKey`, and rejects a result that omits a scheme the
  client asked for (`Client::signing_schemes`). Every scheme's public
  verification material — ECDSA's included —
  is stored under the handle `consts::signing_material_id(scheme)` gives, in the
  data types `key_setup::NON_LEGACY_VERF_MATERIAL_TYPES` names:
  `PubDataType::TypedVerfKey` holds the scheme's _own_ verification key type
  (`PublicSigKey`, `Ed25519VerfKey`, `MlDsaVerfKey<P>`), and `TypedVerfAddress` its
  `address_text()` (`0x`-prefixed hex; for ECDSA the EIP-55 address).
  ECDSA's material is _additionally_ written to the deprecated `key_setup::LEGACY_VERF_MATERIAL_TYPES`
  (`PubDataType::VerfKey`/`VerfAddress`, a bare `PublicSigKey` and the same
  address text) for existing external consumers; those two are scheduled for
  removal and nothing new should read them. Both copies are validated against the
  signing key when backfilling.
- [client/](../core/service/src/client/) and
  [testing/](../core/service/src/testing/) — client-side helpers (including
  local key-material utilities used by `core-client`) and test-only wiring.
- [bin/](../core/service/src/bin/) — entry points (see below).

### Task randomness

[`RngSource`](../core/service/src/engine/rng_source.rs) supplies task seeds from two parent
RNGs per KMS instance: a 128-bit-seeded `AesRng` and a 256-bit-seeded `ChaCha20Rng`. A fork never
carries more entropy than its parent. The wide path therefore needs its own parent, rather than a
wider fork of the narrow one. `BaseKmsStruct` instances and `SessionMaker` share the source
through `Arc`. Each task receives an owned RNG with a separate seed. Initialization seeds each
parent from an independent draw, which combines OS entropy with entropy from the configured
security module. Refresh also mixes output from the existing parents. Entropy failures return
errors and leave both parents unchanged. Refresh logs report success or failure without seed
values.

Threshold epoch creation refreshes once in `new_mpc_epoch`, before either the resharing
or PRSS session forks its RNG. This includes old-committee parties that skip PRSS initialization.
A successful refresh protects future task seeds once fresh entropy is unknown to the attacker.
Existing task RNGs remain unchanged. The source does not provide backtracking resistance
within a reseeding interval. Centralized services seed at construction; epoch refresh
applies to threshold services.

### Binaries

All under [core/service/src/bin/](../core/service/src/bin/):

- [kms-server.rs](../core/service/src/bin/kms-server.rs) — main service process.
- [kms-init.rs](../core/service/src/bin/kms-init.rs) — post-deployment cluster
  initialization.
- [kms-gen-keys.rs](../core/service/src/bin/kms-gen-keys.rs) — generate the server
  signing identity — the `RootSigningSeed` plus the ECDSA signing key, derived
  from the seed on a fresh node and left untouched on an upgraded one — and, in
  threshold mode, per-party self-signed CA certificates for mTLS. It is the
  **only** thing that ever creates a seed. Also derives and persists every
  scheme's public verification material: ECDSA's from the persisted signing key,
  every other scheme's from the seed. Reads a keygen TOML with
  `--config-file`; `[keygen] repopulate = true` backfills the per-scheme
  verification material from the signing identity already in private storage
  instead of generating keys (the same backfill runs automatically on server
  start via `migration::migrate_public_verification_material`, which warns and
  skips when the seed is absent), `[keygen] show_existing = true` prints the
  existing signing-material handles and exits, and `[keygen] overwrite = true`
  deletes the signing key and the seed together with the verification material
  derived from them, since generating an identity alongside another identity's
  derived material is rejected. Supports `mock_enclave` in config for local dev
  when compiled with the `insecure` feature.
- [kms-custodian.rs](../core/service/src/bin/kms-custodian.rs) — custodian-side
  tool for producing and recovering backup shares.
- [kms-gen-tls-certs.rs](../core/service/src/bin/kms-gen-tls-certs.rs) — TLS
  certificate generation for inter-party mTLS.

## gRPC surface

Protobuf definitions live in [core/grpc/proto/](../core/grpc/proto/). The main
service definition is
[kms-service.v1.proto](../core/grpc/proto/kms-service.v1.proto); shared messages
are in [kms.v1.proto](../core/grpc/proto/kms.v1.proto); an insecure transport
variant is in
[kms-service-insecure.v1.proto](../core/grpc/proto/kms-service-insecure.v1.proto);
metastore status types in
[metastore-status.v1.proto](../core/grpc/proto/metastore-status.v1.proto).

The primary service is `CoreServiceEndpoint`. Its RPCs group into:

- **Key generation** — `KeyGenPreproc` / `KeyGenPreprocResult` (threshold
  preprocessing), `KeyGen`, and `NewMpcEpoch` for key rotation. Multiple keyset
  configurations are supported (standard, decompression-only, compressed
  variants). Insecure key generation still requires an explicit preprocessing
  ID for both the centralized and threshold cases.
  Standard threshold keygen persists a dedicated OPRF LWE secret-key share in
  each party's private key material and includes the corresponding OPRF server
  key in the generated TFHE server key. Legacy private keysets that predate this
  field are upgraded with the OPRF share absent; `UseExisting` keygen generates
  and persists a fresh OPRF share for such legacy material before regenerating
  public keys. When the parameter set carries transciphering parameters, keygen
  additionally persists a _second_, independently sampled LWE secret-key share
  and includes the matching transciphering server key; as for the OPRF key,
  `UseExisting` keygen generates a fresh transciphering share when the existing
  keyset has none. Key generation and CRS generation write persistent material
  only after generation completes. An abort updates request state but does not
  purge storage.
- **Decryption** — `PublicDecrypt` (returns plaintext) and `UserDecrypt`
  (user-initiated, EIP-712 authenticated). `PublicDecryptSync` / `UserDecryptSync`
  start a decryption and wait for its result in the same call, so the caller does
  not need the `Get*DecryptionResult` round trip; a known `request_id` attaches to
  the running or succeeded attempt, and redoes a failed one, just like the async
  variants.
- **CRS** — `CrsGen` for ZK-proof common reference strings.
- **Resharing** — `NewMpcEpoch` with `previous_epoch` set rotates parties /
  refreshes secret shares as part of epoch creation; the outcome is fetched
  via `GetEpochResult`. The `preproc_id` supplied per key in `previous_epoch` is
  caller-controlled but ends up in the EIP-712 struct signed for the new epoch,
  so before any resharing protocol runs each party checks it against the
  preprocessing ID stored in that key's `KeyGenMetadata` and rejects a mismatch.
  What a missing keyset means depends on the party's `TwoSetsRole`: set 1 and
  both sets must hold the key material, so failing to read it rejects the
  request, whereas a pure set 2 party (a node joining the new context) never held
  the key and logs a warning instead. When resharing legacy key material that
  has no dedicated OPRF/transciphering secret-key share, the OPRF/transciphering
  sub-protocol is skipped and the reshared private keyset keeps that field
  absent. Which of these optional shares to reshare is decided from the input
  keyset, and every party must agree. A storage failure during
  resharing rolls the new epoch back on the party that fails. That party deletes
  the key shares and the CRS metadata that its own resharing wrote under the new
  epoch. The party deletes the epoch data and forgets the epoch only once
  the epoch holds no key share and no CRS metadata. Public data remains because
  an epoch change does not affect it. A failed deletion keeps the epoch
  registered so that deletion can be retried. `DestroyMpcEpoch` erases a whole
  epoch instead, and covers the material of every request.
  `DestroyMpcContext` takes a stable
  snapshot of the context's registered epochs and erases their secret shares
  before it forgets the context and removes its TLS trust-root references. A trust
  root remains if another live context uses it. This order leaves no usable key
  shares after the party set retires. Its response lists the deleted epoch IDs. In-memory
  lifecycle leases serialize creation against destruction: `NewMpcEpoch` holds
  shared leases for its target context and epoch. A reshare also holds shared
  leases for its source context and epoch through all PRSS, resharing, and persistence work.
  `DestroyMpcEpoch` and `DestroyMpcContext` require exclusive leases before
  taking snapshots or deleting data. A conflicting destruction is refused with
  `FailedPrecondition`, including while PRSS is still running and the new epoch
  has not yet been registered in the session maker; callers retry once creation
  has settled. MPC context updates serialize the existence check with storage and
  cache or session updates. A failed deletion keeps the in-memory context if its
  persistent entry remains, which permits a retry before or after restart.
- **Session management** — creation, result retrieval, and cleanup for
  long-running threshold sessions.

EIP-712 signature validation on user-decryption requests is shared between
the server and in-browser verifiers via the `validation_wasm` build.

## Deployment modes

Mode is selected in the server TOML config — a party runs in threshold mode
when the optional `[threshold]` section is present; see the sample
files in `core/service/config/` (`default_centralized.toml`,
`default_1.toml`..`default_4.toml`, and the compose-specific variants).

In both modes, when the same key or CRS ID has metadata under multiple epochs,
startup loads the metadata from the greatest epoch ID into the result meta
store. Epoch IDs are compared as big-endian integers.

### Centralized

A single `RealCentralizedKms` instance holds all key material. No MPC; keys
live in the configured vault backend. Preprocessing / reshare RPCs are not
applicable.

A centralized node keeps no epoch registry and stores no `EpochData`, so every
epoch-scoped entry it holds belongs to the default epoch. `KeyGen`, `CrsGen`,
`KeyGenPreproc`, `NewMpcEpoch`, `PublicDecrypt` and `UserDecrypt` reject any
other epoch ID with `InvalidArgument`. A request that omits the epoch ID still
falls back to the default epoch, so a caller that never sets the field is
unaffected.

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
([core/service/src/vault/keychain/](../core/service/src/vault/keychain/)):

- **`AwsKms`** — wrapping key is an AWS KMS CMK. Default and bootstrap path.
- **`SecretSharing`** — wrapping key is Shamir-shared across a set of
  **custodians**, offline entities who each hold a key share plus a BIP39
  seed phrase. `NewCustodianContext` requires the backup vault to be configured
  with this keychain already, and the keychain can only encrypt once that call
  has installed a context, so a node configured for it makes no backups until
  its first context exists. New custodian contexts are rejected unless every custodian
  encryption key and every custodian verification key is unique, and unless every
  custodian encryption key uses `BACKUP_PKE_SCHEME`.
  Every key in this path is MLKEM1024-P384 (`backup::BACKUP_PKE_SCHEME`), and the
  custodian's is derived from 256 bits of seed-phrase entropy — a 24-word mnemonic —
  so the phrase does not cap the scheme's security level. A vault written under an
  older ML-KEM-512 context is not readable by a node holding a composite key, but
  each ciphertext carries its own `pke_type`, so a vault spanning both schemes
  decrypts as long as the matching key is installed. That remains true for
  material already written; what is refused is *creating* a new context under a
  weaker scheme.

Custodian workflows are driven through the
[kms-custodian](../core/service/src/bin/kms-custodian.rs) CLI and the
`NewCustodianContext` / `DestroyCustodianContext` / `CustodianRecoveryInit`
/ `CustodianBackupRecovery` RPCs defined in
[kms-service.v1.proto](../core/grpc/proto/kms-service.v1.proto).
A separate `RestoreFromBackup` RPC completes restoration on the node for the non-custodian AWS-KMS path.

The `RecoveryValidationMaterial` describing a custodian context — the custodian-signcrypted
shares of the backup decryption key, plus the commitments and the context itself — lives in the
**backup vault**, as the one object there that the keychain does not encrypt: it is what recovery
needs in order to reconstruct that very key, so encrypting it under the key would be circular. Its
integrity comes from the operator signature it carries, checked at startup once the signing key is
available, together with a check — applied on every load — that the object is stored under the
context id its payload names. It sits outside the `<backup_id>/<PrivDataType>/`
namespace the vault's backup entries use, at `RecoveryMaterial/<context_id>`, so purging a
context's backups never touches it and vice versa; `vault/storage/mod.rs` holds the accessors.

A `CustodianContextAnchor` in **private storage** names the current context, written by
`NewCustodianContext` once the material is in the vault and by recovery once the private store is
back. At boot `adopt_custodian_context`
([vault/mod.rs](../core/service/src/vault/mod.rs)) reads the anchor and points the keychain at that
one context. Nothing is sorted or listed to make the choice, so a retired context that is still in
the vault — or was replayed into it — is inert, and a new context whose id happens to sort low is
not abandoned on the next restart. A node with no anchor makes no backups and says so; it never
guesses.

A deployment upgraded from a release that kept the material in public storage starts with no
custodian context and creates a new one. Nothing reads that folder, so its content can neither
steer the node nor stall it; the startup sweep lists it only to report leftovers.

`NewCustodianContext` points the keychain at the new context and re-encrypts the whole
vault under it _before_ persisting the recovery material, so it is rolled back if any later
step fails: the keychain is restored to its pre-setup `(context_id, backup_enc_key)` and the
vault entries written under the failed id are purged
(`rollback_failed_custodian_setup` in
[context_manager.rs](../core/service/src/engine/context_manager.rs) and
`Vault::purge_backup`). Without that, the node would keep encrypting backups under a key
whose recovery material was never written, making them unrecoverable. One failure is judged by the
anchor instead: a write that reports an error is read back, and if the anchor names the new context
the setup succeeded; if it cannot be read, the material is kept for whichever anchor wins and the
keychain is emptied, so the node makes no backups until the next boot reads the anchor. Cleanup
checks that no backup entries remain under the failed context ID. If the storage backend reports a
successful deletion but entries remain, rollback emits a `tracing::error!` and preserves the original
setup or write error. Rollback cannot repair a backend that did not apply the deletion, so these
leftover entries require operator attention. During custodian-context destruction, the same check
must pass before recovery material and lifecycle state are removed. Setup, destruction and recovery
are serialized by `custodian_context_lock`. Setup holds it until completion, including rollback on
failure, so destruction cannot remove the previous context while setup might still restore its
keychain state. The anchor is written last, after the material, so a crash anywhere before it leaves
the previous context anchored rather than a half-installed one. The setup runs on the node's task
tracker, so neither a dropped request nor a shutdown cuts it short between the keychain switch and
the anchor write, and a setup requested once a shutdown has begun is refused.
Destruction still runs on the request itself; a dropped one leaves a context that a repeated
destroy finishes.

Restoration writes the private data types back in a fixed order (`RESTORE_ORDER` in
[backup_operator.rs](../core/service/src/engine/backup_operator.rs)): contexts and `EpochData`
first, then PRSS setups, keysets and CRS metadata, and the signing key last. A restore can stop
half-way and can be run again (entries that already exist are skipped), so the order keeps every
intermediate state bootable: keysets never sit under an epoch the node does not know, which the
[boot-time checks](#boot-time-storage-verification) refuse, and a node without its signing key
stays in recovery mode, where the restore can be repeated.

Implementation code lives in [core/service/src/backup/](../core/service/src/backup/);
end-to-end tests live at
[core/service/src/client/tests/centralized/custodian_backup_tests.rs](../core/service/src/client/tests/centralized/custodian_backup_tests.rs)
and
[core/service/src/client/tests/threshold/custodian_backup_tests.rs](../core/service/src/client/tests/threshold/custodian_backup_tests.rs).

## Paired material writes

File storage writes raw bytes and versioned values into sibling temporary files, syncs them,
then atomically renames them into place. A process crash during a write cannot expose a partial
destination file. This does not make a multi-file operation atomic or guarantee rename durability
after power loss; the writers do not sync the parent directory.

Threshold calls to `CryptoMaterialStorage::write_all` use two public/private pairs:

- `PublicKey` and `FheKeyInfo` share a key ID.
- `CRS` and `CrsInfo` share a CRS ID.

The public half has no epoch. The private half has an epoch and contains one party's material.
Initial generation writes both halves through `CryptoMaterialStorage::write_all`. The method also
accepts one-sided writes. Resharing writes only the private half for the new epoch and reuses the
public half. A `ContextInfo` write stores one request-scoped private entry with no public half.

Complete FHE key writes reject any public key, server key, or compressed keyset at the key ID,
and any private entry at the requested epoch, before writing material. They cannot combine an old pair half with newly generated keys
or cache private material that storage skipped. Resharing uses a separate private-only write path.

Complete CRS writes likewise reject an existing public CRS or private `CrsInfo` at the requested
epoch. Rejection leaves storage untouched and records a failed request in the meta store.

Storage never overwrites an entry. If one requested half exists, storage keeps its bytes and writes
the missing half. The caller must ensure that the two halves belong together. If either write
fails, cleanup removes only entries created by that call. It retains each entry that existed
before the call. A backend can apply a write and then return an error, so cleanup checks the
earlier state. Callers must serialize writes to the same entries until cleanup finishes. A later
backup failure does not purge the primary material.

## Boot-time storage verification

Every node checks its storage during service construction, before it serves any request.
Four independent things happen.
Boot-time verification lets us ensure the public and private storage are
consistent, and detect any malicious behaviour and/or misconfiguration before
the KMS party boots up.

**The backup vault is repaired.** `update_backup_vault(false, OP_BOOT)` copies anything
present in private storage but missing from the backup vault, so a vault that moved or lost
entries is brought back up to date. Existing entries are not re-read or re-verified.

**Private storage is verified for internal consistency.** Private storage belongs to the node
alone, so nothing legitimate lands there by accident. `verify_private_storage_layout` lists it
and fails verification on inconsistent layouts. It deserializes contexts to verify that each
context uses its declared ID as its storage handle. A threshold node with peer configuration
writes its default context before these checks. Everything else the current layout does not
account for is logged as an error without stopping boot. On a threshold node the epoch registry
(`EpochData`) is read once before the checks, then handed to `SessionMaker::new_initialized`. In
recovery mode, the private and public checks are skipped so that the node can repair storage.

**Public storage is verified, and the verification itself never touches it.** It is the
authority on what is wrong: it names the offending entry, and it reads and hashes each
published object exactly once, which is all a node with intact storage ever pays.

**A failed verification is repaired from peers and verified again (threshold nodes only).**
Public storage can drift out of a consistent state: a misconfigured bucket or prefix can point
a node at the wrong material, and writes across multiple entries are not atomic, so a crash
mid-operation can leave material missing or stale. Private storage holds the digests and
signatures describing what should be published, so it is the reference; its own signatures are
checked before anything else consults it. Every party in an MPC context publishes the same
keysets and CRSes, so when `verify_storage_material` fails, `sync_public_material_from_peers`
([public_material_sync.rs](../core/service/src/engine/public_material_sync.rs)) compares the
digests that current private metadata records — one metadata entry per ID, the one from the
greatest epoch that holds it — against the raw bytes in public storage, and downloads any
missing or mismatched entry from the public storage of the peers in the material's epoch
context (S3 URLs from the `ContextInfo` in private storage, tried in random order; a peer
recorded with a `file://` URL or no URL at all is logged and skipped). Downloaded bytes are
accepted only when they hash to the recorded digest and are stored verbatim, and verification
then runs a second time so that whatever was written is re-checked independently. Material that
cannot be validated is never fetched: legacy metadata (no digest), decompression keys (no
private counterpart), and node-specific material (a peer publishes its own verification keys,
CA certificate, and recovery material, not this node's). A needed entry that no peer can supply
fails boot, carrying the original verification failure as its context so the log still names
what was wrong locally. Centralized nodes skip the sync — no peer publishes their material —
and recovery mode skips it along with the other checks.

The code is split by level. [material_integrity.rs](../core/service/src/engine/material_integrity.rs)
holds the digest primitives — pure functions over raw stored bytes, with no storage or
orchestration — so the vault layer can reuse them without depending on startup logic.
[storage_material_verification.rs](../core/service/src/engine/storage_material_verification.rs)
sits above it and owns the startup orchestration, entered through `verify_private_storage_layout`
and `verify_storage_material`. The checks follow three rules:

1. **Private storage is the reference.** Every integrity check takes an expected value from
   private storage and looks up its counterpart in public storage — never the reverse.
2. **Extra material in public storage is reported, never rejected.** Some of it is legitimate:
   a retired keyset, or leftovers from a previous deployment that shares the bucket. Some of it
   is not: a write that failed half-way, a corrupted store, or an entry planted by someone with
   write access. The node cannot tell these apart, so once the integrity checks pass,
   `report_unexpected_public_material` lists public storage and logs an error for every entry
   that private storage does not account for. Boot continues regardless.
3. **Read-only.** The verification writes nothing; every repair happens in the peer-sync step,
   which runs only after a verification failure, and whatever that step wrote is re-checked by
   a second verification pass from scratch.

What it verifies, and how failures are treated:

| Check | On failure |
|---|---|
| Published keysets and CRSes are present, and their raw stored bytes hash to the digests in `KeyGenMetadata` / `CrsGenMetadata` | repaired from peers and verified again when possible (threshold only); otherwise boot fails |
| Current private keygen and CRS metadata with a stored domain reconstruct a valid EIP-712 signature from the node's signing key | boot fails |
| Every non-ECDSA entry of the per-scheme `signatures` in current private keygen and CRS metadata verifies, under the key the node derives for that scheme, over the rebuilt result payload | boot fails |
| `VerfKey` and `VerfAddress` at `SIGNING_KEY_ID` match the key derived from the private `SigningKey` | boot fails |
| Every entry in a `PubDataType` folder is accounted for by private storage or by a fixed-ID convention | error logged, boot continues |
| Every top-level name in public storage is a `PubDataType` folder, and every folder can be listed | error logged, boot continues |
| The node has no foreign material (`FhePrivateKey` or legacy `PrssSetup` on a threshold node; `FheKeyInfo`, `PrssSetup`, `PrssSetupCombined`, or `EpochData` on a centralized node) | boot fails if foreign material exists |
| Every `FheKeyInfo` and `CrsInfo` epoch folder has an `EpochData` entry | boot fails |
| Every `EpochData` has a `Context` entry | boot fails |
| Every `Context` entry uses its declared context ID as its storage handle | boot fails |
| No unexpected non-epoched files exist | error logged, boot continues |
| No epoch folder exists under `Context` or `EpochData` | error logged, boot continues |
| Every top-level name in private storage is a `PrivDataType` folder, and every inspected folder can be listed | error logged, boot continues |
| `SigningKey` and `SigningSeed` each hold nothing or exactly one flat entry at `SIGNING_KEY_ID`, and at least one of them holds an entry | serving boot fails; recovery mode remains available |

The signing material lives at `SIGNING_KEY_ID` as the ECDSA `SigningKey`, the root `SigningSeed`,
or both. A node that predates the seed has only the key. Neither type is epoch-scoped, and neither
holds a second entry. The layout check accepts every combination with at least one of the two.
The current loader requires the ECDSA key and attaches the seed when one is present.

On a threshold node, a flat `PrssSetup` entry is foreign material and fails boot. The 0.15
migration leaves flat `PrssSetupCombined` entries next to their `EpochData`; those remain accepted
until the 0.16 migration removes them. A centralized node rejects both PRSS types and `EpochData`.
The 0.16 cleanup re-lists flat `PrssSetupCombined` entries after deletion and returns an error if any remain.
A successful delete response alone does not count as completed cleanup.

Custodian backup readiness is deliberately _not_ part of this. It is a property of the vault's
keychain rather than of the published material, and the backup path already reports it:
`keychain_initialized` ([backup_operator.rs](../core/service/src/engine/backup_operator.rs)) asks
the keychain directly whether a backup encryption key is set, and `inner_update_backup_vault`
skips the update when it is not — during the same boot, from
`update_backup_vault(false, OP_BOOT)`. That skip is logged as a warning, since it means no backups
are being made: the recovery material lives in the backup vault, so losing that vault also loses
the custodian context, and the node needs a new one or a recovery.

The recovery-material signature check is part of the same startup pass, but its input comes from
the backup vault rather than from public storage.

Startup verification never deserializes stored keys or CRSes. Digests are always computed over
the **raw stored bytes**, never over a serialization of a decoded value: a tfhe format change
since the material was generated would alter the bytes and report intact material as corrupt.
Legacy metadata has no digest, so its public objects receive a raw presence check only.

`external_signature` and the ECDSA entry of `signatures` sign an EIP-712 hash built from an
`Eip712Domain` that arrives from a gRPC request. At boot, current private keygen and CRS metadata
with a stored domain reconstruct their signed Solidity payload and must recover the node's
signing address. Older metadata versions upgrade with no domain and stay unverifiable. The
entries of the other schemes sign the serialized result payload (`keygen_payload_bytes`,
`crs_payload_bytes`) instead, which needs no domain, so they are checked for every current
entry. A node that cannot derive a scheme's key, because it holds no root seed, fails boot on
such an entry rather than passing it over.

`PubDataType::DecompressionKey` has no private-storage counterpart at all
(`write_decompression_key` persists no private data), so a published decompression key cannot be
verified at startup, and the sweep reports every one of them. The deprecated
`PubDataType::PublicKeyMetadata` is the opposite case: deployments upgraded from before 0.14 hold
one per keyset, so the sweep accounts for it under every keyset ID and reports only the rest.

The sweep enumerates through `StorageReader::all_data_types` (the top-level folders and objects
under the storage root) and `all_data_ids` (the entries of each `PubDataType` folder). An object
directly under the root is reported whatever its name, because a data type stores its entries
inside its folder only. The sweep is bounded by the storage root the node is configured with —
`PUB` for a centralized node, `PUB-pX` for party X — so other parties' prefixes in a shared bucket
are never listed. It does not descend into sub-folders beneath a data type: public data is never
epoched, and both `all_data_ids` implementations skip such folders. A name that does not parse as
a request ID makes the folder listing fail; that failure is logged as an error too, and boot
continues.

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
[bc2wrap](../bc2wrap/) so the binary layout is deterministic. Examples of
versioned types: `BackupCiphertextVersions`,
`InternalCustodianContextVersions`, `AppKeyBlobVersions`.

**Startup migrations.** The service moves material when a release changes its storage path. The
v0.15 migration moves legacy private `CrsInfo` into `DEFAULT_EPOCH_ID` after the other startup migrations succeed.
It accepts the copy kept by v0.14 or creates one for an older installation. It removes the non-epoched entry only after the two
copies match, and it stops startup if they differ or if the legacy entry remains after deletion. If
the copies differ, an operator must inspect them and remove the incorrect copy before restarting.
Once the migration completes, releases older than v0.14 can no longer load that CRS metadata because
they only know the removed non-epoched path.

**Freeze-and-replay harness.** [backward-compatibility/](backward-compatibility/)
is a separate Cargo workspace (excluded from the root — see [Cargo.toml](Cargo.toml)
— because each pinned historical version drags in a conflicting dependency
graph). Per-version `generate-vX.Y.Z/` crates serialize a catalogue of types
using that release's dependencies; the artifacts land under
[backward-compatibility/data/](../backward-compatibility/data/) (Git-LFS-tracked)
indexed by per-module `.ron` manifests. The loader in
[backward-compatibility/src/](../backward-compatibility/src/) replays every
entry through the current-version `Unversionize` and asserts the expected
metadata.

Custodian-backup fixtures exist for 0.15.0 only. The feature ships first in 0.15
and no deployment uses it, so adopting MLKEM1024-P384 for it broke its persisted
and wire formats, and the fixtures for 0.14.0 and earlier were dropped rather
than kept as a compatibility target.

To add support for a new release, follow
[backward-compatibility/ADDING_NEW_VERSIONS.md](../backward-compatibility/ADDING_NEW_VERSIONS.md).
The top-level [Makefile](../Makefile) exposes `test-backward-compatibility`
(run the loader against stored LFS vectors),
`test-backward-compatibility-local` (against locally regenerated vectors),
and `generate-backward-compatibility-*` targets to refresh vectors.

## External dependencies

The [Cargo.toml](../Cargo.toml) should be considered the ground truth.

## Testing

- **Unit tests** live alongside the source (`#[cfg(test)]`).
- **Integration tests** live in each crate's `tests/` directory, notably
  `core/service/tests/`.
- **Backward-compatibility tests** live under
  [backward-compatibility/](../backward-compatibility/); per-version generator
  crates produce frozen test vectors that current-version loaders must
  accept. See [Backward compatibility](#backward-compatibility) for the full
  picture.
- **Docker-compose harness** — see [docker-compose.md](../docker-compose.md) and
  the compose files at the repo root
  (`docker-compose-core-base.yml`, `docker-compose-core-threshold.yml`,
  `docker-compose-core-centralized.yml`) for a local multi-party network
  plus S3-mock, and telemetry sidecars.
- **Cargo feature flags** — `testing` exposes test helper APIs across crate boundaries;
  `slow_tests` enables the long-running suite. `kms/insecure` enables development RPCs
  and mock enclave support. It forwards `threshold-networking/insecure`, which permits
  plaintext transport and mock attestation.

The [performance suite](../ci/perf-testing/PERF_TEST_README.md) measures public and user
decryption through both sync and async endpoints. The scenario configuration selects each
operation, endpoint, and rate ladder. Client metrics identify the scenario; Slack and the
Python analyzer report the ladders separately.

See the "Building and testing" section of [README.md](../README.md) for the
exact commands.

## Build and deployment

- **Toolchain** — Rust pinned via [rust-toolchain.toml](../rust-toolchain.toml) along with Protobuf (`protoc`). Docker is also required for the test harness for some integration tests.
- **Makefile** — [Makefile](../Makefile) provides compose orchestration,
  backward-compat vector generation, test-material generation, and lint
  targets.
- **Container images** — local developer builds still use
  [docker/core/service/Dockerfile](../docker/core/service/Dockerfile) and
  [docker/core-client/Dockerfile](../docker/core-client/Dockerfile). Both package
  Dockerfiles always consume a shared `kms-binaries` image via
  `KMS_BINARIES_IMAGE`. Local scripts/compose targets build that image with
  [docker/kms-binaries/Dockerfile](../docker/kms-binaries/Dockerfile) and pass the
  desired tag explicitly; production CI builds its secure `prod` target and
  retags it as `:latest` before packaging the `prod` targets of `core-service`
  and `core-client`. Release compilation uses fat LTO, while other CI builds use
  thin LTO. The published runtime image for the service remains
  `ghcr.io/zama-ai/kms/core-service`.
- **Kubernetes** — a Helm chart is provided at
  [charts/kms-core/](../charts/kms-core/) for both centralized and threshold
  deployments, including Nitro Enclaves when configured.

## Further reading

- Cryptographic specification:
  [CryptographicDocumentation.pdf](https://github.com/zama-ai/threshold-fhe/blob/main/docs/CryptographicDocumentation.pdf).
- Protocol paper: [Noah's Ark, eprint 2023/815](https://eprint.iacr.org/2023/815).
- User documentation: [docs/](../docs/) and the "Using the KMS" section of
  [README.md](../README.md).
- Contribution workflow: [CONTRIBUTING.md](../CONTRIBUTING.md).
- Security policy: [SECURITY.md](../SECURITY.md).

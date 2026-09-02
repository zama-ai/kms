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
| `threshold-algebra` | [core/threshold-algebra/](core/threshold-algebra/) | Finite-field and group primitives used by the MPC protocols |
| `threshold-execution` | [core/threshold-execution/](core/threshold-execution/) | Threshold FHE protocol execution: DKG, preprocessing, online protocols |
| `threshold-bgv` | [core/threshold-bgv/](core/threshold-bgv/) | Experimental BGV/BFV schemes with distributed keygen and threshold decryption |
| `threshold-networking` | [core/threshold-networking/](core/threshold-networking/) | Inter-party gRPC transport and choreography |
| `threshold-hashing` | [core/threshold-hashing/](core/threshold-hashing/) | Hashing primitives used across the MPC stack |
| `threshold-types` | [core/threshold-types/](core/threshold-types/) | Shared types and constants |
| `experiments` | [core/experiments/](core/experiments/) | Benchmark and experiment harnesses (see [docs/guides/threshold-benchmark.md](docs/guides/threshold-benchmark.md)) |

### Service layer

| Crate | Path | Responsibility |
|---|---|---|
| `kms` | [core/service/](core/service/) | KMS service library and binaries — the packaging around the core crypto |
| `kms-grpc` | [core/grpc/](core/grpc/) | Protobuf definitions + generated types and client stubs |
| `core-client` | [core-client/](core-client/) | CLI client that drives the gRPC API |
| `observability` | [observability/](observability/) | OpenTelemetry / Prometheus wiring |
| `vsocktun` | [vsocktun/](vsocktun/) | Multi-queue, offload-aware TUN-to-VSOCK relay used by Nitro enclave deployment scripts to preserve end-to-end peer TCP while bridging enclave IP traffic through the parent, including raw virtio-net TUN frames when both ends support offload metadata; the parent side also bootstraps the enclave-side tunnel CIDR, MTU, shard count, and rewritten resolver config over the same VSOCK control port |
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
  [material_integrity.rs](core/service/src/engine/material_integrity.rs) (digest
  primitives over raw stored bytes, depended on by both the storage layer and the
  startup checks),
  [public_material_sync.rs](core/service/src/engine/public_material_sync.rs) (the
  digest-verified peer fetcher shared with resharing, and the boot-time repair of public
  storage built on it) and
  [storage_material_verification.rs](core/service/src/engine/storage_material_verification.rs)
  (the read-only startup checks on top of both — see
  [Boot-time storage verification](#boot-time-storage-verification)),
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
  chain verification). Signing lives under
  [cryptography/signing/](core/service/src/cryptography/signing/): a
  scheme-tagged `Signature` plus one backend per scheme — ECDSA/secp256k1
  (`ecdsa`, the legacy default and EIP-712 home), EdDSA/ed25519 (`eddsa`), and
  ML-DSA/FIPS-204 (`mldsa`) — behind the `SigningScheme` trait and the
  `unified_sign`/`unified_verify` entry points. The historic
  `cryptography::signatures` path is now a re-export facade. A node still
  persists a single ECDSA signing key; the other schemes' keys are derived from
  it on demand. Every scheme's public verification material — ECDSA's included —
  is stored under the handle `consts::signing_material_id(scheme)` gives, in the
  data types `key_setup::SCHEME_MATERIAL_TYPES` names:
  `PubDataType::TypedVerfKey` holds the scheme's *own* verification key type
  (`PublicSigKey`, `Ed25519VerfKey`, `MlDsaVerfKey<P>`), and `TypedVerfAddress` its
  `address_text()` (`0x`-prefixed hex; for ECDSA the EIP-55 address). 
  ECDSA's material is *additionally* written to the deprecated `key_setup::LEGACY_ECDSA_MATERIAL_TYPES`
  (`PubDataType::VerfKey`/`VerfAddress`, a bare `PublicSigKey` and the same
  address text) for existing external consumers; those two are scheduled for
  removal and nothing new should read them. Both copies are validated against the
  signing key when backfilling.
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
  for mTLS). Also derives and persists every non-ECDSA scheme's public
  verification material from the ECDSA key. Reads a keygen TOML with
  `--config-file`; `[keygen] repopulate = true` backfills the per-scheme
  verification material from an existing ECDSA signing key instead of
  generating keys (the same backfill runs automatically on server start via
  `migration::migrate_public_verification_material`), and `[keygen] overwrite =
  true` deletes the signing key together with the verification material derived
  from it, since generating a key alongside another key's derived material is
  rejected. Supports `mock_enclave` in config for local dev when compiled with
  the `insecure` feature.
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
  preprocessing), `KeyGen`, and `NewMpcEpoch` for key rotation. Multiple keyset
  configurations are supported (standard, decompression-only, compressed
  variants). Insecure key generation still requires an explicit preprocessing
  ID for both the centralized and threshold cases.
  Standard threshold keygen persists a dedicated OPRF LWE secret-key share in
  each party's private key material and includes the corresponding OPRF server
  key in the generated TFHE server key. Legacy private keysets that predate this
  field are upgraded with the OPRF share absent; `UseExisting` keygen generates
  and persists a fresh OPRF share for such legacy material before regenerating
  public keys.
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
  has no dedicated OPRF secret-key share, the OPRF sub-protocol is skipped and
  the reshared private keyset keeps that field absent. A storage failure during
  resharing rolls the new epoch back on the party that fails. 
  That party attempts to delete the key shares, the CRS metadata and the epoch data of the new epoch. 
  Observe that no public data is deleted as this is, and should be, unaffected by an epoch change. 
  If cleanup succeeds, it forgets the epoch; otherwise, it keeps the epoch registered so that deletion can be retried. 
  `DestroyMpcContext` carries
  the context's epoch IDs and erases their secret shares (cascading to the
  existing per-epoch deletion) before forgetting the context, so retiring a
  party set leaves no usable key shares behind; the kms-connector is the source
  of truth for which epochs belong to a context. In-memory lifecycle leases
  serialize creation against destruction: `NewMpcEpoch` holds shared leases for
  its target context and epoch through all PRSS, resharing and persistence work,
  while `DestroyMpcEpoch` and `DestroyMpcContext` require exclusive leases before
  taking snapshots or deleting data. A conflicting destruction is refused with
  `FailedPrecondition`, including while PRSS is still running and the new epoch
  has not yet been registered in the session maker; callers retry once creation
  has settled.
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
[kms-service.v1.proto](core/grpc/proto/kms-service.v1.proto).
A separate `RestoreFromBackup` RPC completes restoration on the node for the non-custodian AWS-KMS path.

`NewCustodianContext` points the keychain at the new context and re-encrypts the whole
vault under it *before* persisting the recovery material, so it is rolled back if any later
step fails: the keychain is restored to its pre-setup `(context_id, backup_enc_key)` and the
vault entries written under the failed id are purged
(`rollback_failed_custodian_setup` in
[context_manager.rs](core/service/src/engine/context_manager.rs) and
`Vault::purge_backup`). Without that, the node would keep encrypting backups under a key
whose recovery material was never written, making them unrecoverable. Setups are serialized
against each other for the same reason.

Restoration writes the private data types back in a fixed order (`RESTORE_ORDER` in
[backup_operator.rs](core/service/src/engine/backup_operator.rs)): contexts and `EpochData`
first, then PRSS setups, keysets and CRS metadata, and the signing key last. A restore can stop
half-way and can be run again (entries that already exist are skipped), so the order keeps every
intermediate state bootable: keysets never sit under an epoch the node does not know, which the
[boot-time checks](#boot-time-storage-verification) refuse, and a node without its signing key
stays in recovery mode, where the restore can be repeated.

Implementation code lives in [core/service/src/backup/](core/service/src/backup/);
end-to-end tests live at
[core/service/src/client/tests/centralized/custodian_backup_tests.rs](core/service/src/client/tests/centralized/custodian_backup_tests.rs)
and
[core/service/src/client/tests/threshold/custodian_backup_tests.rs](core/service/src/client/tests/threshold/custodian_backup_tests.rs).

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
(it deserializes nothing) and fails boot on three states: key material of the other deployment
mode (`FhePrivateKey` on a threshold node, `FheKeyInfo` on a centralized one), keysets or CRS
metadata under an epoch that has no `EpochData`, and an epoch whose context has no `Context`
entry. The last two each have a variant that only warns, because the node repairs it itself:
keysets under `DEFAULT_EPOCH_ID` before `init` created its PRSS setup (the supported
keyed-but-uninitialized state), and epochs of `DEFAULT_MPC_CONTEXT` while
`ensure_default_threshold_context_in_storage` rewrites that context from the peer list, which it
does on every boot after the checks. Everything else the current layout does not account for is a
warning; see the table below. On a threshold node the epoch registry (`EpochData`) is read once,
before the checks, and then handed to `SessionMaker::new_initialized`. In recovery mode (no
signing key) the private checks are skipped, like the public ones: that mode exists to repair
storage.

**Missing or corrupt public material is repaired from peers (threshold nodes only).** Public
storage can drift out of a consistent state: a misconfigured bucket or prefix can point a node
at the wrong material, and writes are not atomic, so a crash mid-operation can leave an entry
missing, truncated, or stale. Private storage holds the digests and signatures describing what
should be published, so it is the reference. Every party in an MPC context publishes the same
keysets and CRSes, so after private metadata validation and before the public checks run,
`sync_public_material_from_peers`
([public_material_sync.rs](core/service/src/engine/public_material_sync.rs)) compares every
digest that current private metadata records against the raw bytes in public storage and
downloads any missing or mismatched entry from the public storage of the peers in the
material's epoch context (URLs from the `ContextInfo` in private storage, tried in random
order). Downloaded bytes are accepted only when they hash to the recorded digest and are stored
verbatim, so the verification that follows re-checks them independently. Material that cannot
be validated is never fetched: legacy metadata (no digest), decompression keys (no private
counterpart), and node-specific material (a peer publishes its own verification keys, CA
certificate, and recovery material, not this node's). A needed entry that no peer can supply
fails boot. Centralized nodes skip the sync — no peer publishes their material — and recovery
mode skips it along with the other checks.

**Public storage is then verified, and the verification itself never touches it.**

The code is split by level. [material_integrity.rs](core/service/src/engine/material_integrity.rs)
holds the digest primitives — pure functions over raw stored bytes, with no storage or
orchestration — so the vault layer can reuse them without depending on startup logic.
[storage_material_verification.rs](core/service/src/engine/storage_material_verification.rs)
sits above it and owns the startup orchestration, entered through `verify_private_storage_layout`
and `verify_storage_material`. The checks follow three rules:

1. **Private storage is the reference.** Every integrity check takes an expected value from
   private storage and looks up its counterpart in public storage — never the reverse.
2. **Extra material in public storage is reported, never rejected.** Some of it is legitimate:
   a retired keyset, or leftovers from a previous deployment that shares the bucket. Some of it
   is not: a write that failed half-way, a corrupted store, or an entry planted by someone with
   write access. The node cannot tell these apart, so once the integrity checks pass,
   `report_unexpected_public_material` lists public storage and warns about every entry that
   private storage does not account for.
3. **Read-only.** The verification writes nothing; every repair happens in the peer-sync step
   above, and whatever that step wrote is re-checked here from scratch.

What it verifies, and how failures are treated:

| Check | On failure |
|---|---|
| Published keysets and CRSes are present, and their raw stored bytes hash to the digests in `KeyGenMetadata` / `CrsGenMetadata` | repaired from peers before verification when possible (threshold only); otherwise boot fails |
| Current private keygen and CRS metadata with a stored domain reconstruct a valid EIP-712 signature from the node's signing key | boot fails |
| `VerfKey` and `VerfAddress` at `SIGNING_KEY_ID` match the key derived from the private `SigningKey` | boot fails |
| Every entry in a `PubDataType` folder is accounted for by private storage or by a fixed-ID convention | warning, boot continues |
| Every top-level name in public storage is a `PubDataType`, and every folder can be listed | warning, boot continues |
| No `FhePrivateKey` entries on a threshold node, no `FheKeyInfo` entries on a centralized node | boot fails |
| Every `FheKeyInfo` and `CrsInfo` epoch folder other than `DEFAULT_EPOCH_ID` has an `EpochData` entry | boot fails |
| Every `EpochData` whose context is not `DEFAULT_MPC_CONTEXT` has a `Context` entry | boot fails |
| `FheKeyInfo` or `CrsInfo` under `DEFAULT_EPOCH_ID` with no `EpochData`; `EpochData` of `DEFAULT_MPC_CONTEXT` with no `Context` entry | warning, boot continues |
| No flat files under `FheKeyInfo`, `FhePrivateKey` or `CrsInfo` (pre-0.13 layout); no split `PrssSetup`; every `PrssSetupCombined` has an `EpochData`; no `EpochData` or PRSS setup on a centralized node | warning, boot continues |
| Every top-level name in private storage is a `PrivDataType`, and every folder can be listed | warning, boot continues |

The `SigningKey` folder is not inspected (`TODO(#3182)`); `get_core_signing_key` already
refuses anything but exactly one entry when the node starts.

Custodian backup readiness is deliberately *not* part of this. It is a property of the vault's
keychain rather than of the published material, and the backup path already reports it:
`keychain_initialized` ([backup_operator.rs](core/service/src/engine/backup_operator.rs)) asks
the keychain directly whether a backup encryption key is set, and `inner_update_backup_vault`
warns and skips the update when it is not — during the same boot, from
`update_backup_vault(false, OP_BOOT)`.

Startup verification never deserializes stored keys or CRSes. Digests are always computed over
the **raw stored bytes**, never over a serialization of a decoded value: a tfhe format change
since the material was generated would alter the bytes and report intact material as corrupt.
Legacy metadata has no digest, so its public objects receive a raw presence check only.

`external_signature` and the ECDSA entry of `signatures` sign an EIP-712 hash built from an
`Eip712Domain` that arrives from a gRPC request. At boot, current private keygen and CRS metadata
with a stored domain reconstruct their signed Solidity payload and must recover the node's
signing address. Older metadata versions upgrade with no domain and stay unverifiable.

`PubDataType::DecompressionKey` has no private-storage counterpart at all
(`write_decompression_key` persists no private data), so a published decompression key cannot be
verified at startup, and the sweep reports every one of them. The deprecated
`PubDataType::PublicKeyMetadata` is the opposite case: deployments upgraded from before 0.14 hold
one per keyset, so the sweep accounts for it under every keyset ID and reports only the rest.

The sweep enumerates through `StorageReader::all_data_types` (the top-level names under the
storage root) and `all_data_ids` (the entries of each `PubDataType` folder). It is bounded by the
storage root the node is configured with — `PUB` for a centralized node, `PUB-pX` for party X — so
other parties' prefixes in a shared bucket are never listed. It does not descend into sub-folders
beneath a data type: public data is never epoched, and both `all_data_ids` implementations skip
such folders. A name that does not parse as a request ID makes the folder listing fail; that
failure is reported as a warning too, and boot continues.

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
versioned types: `BackupCiphertextVersions`,
`InternalCustodianContextVersions`, `AppKeyBlobVersions`.

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
  `core/service/tests/`.
- **Backward-compatibility tests** live under
  [backward-compatibility/](backward-compatibility/); per-version generator
  crates produce frozen test vectors that current-version loaders must
  accept. See [Backward compatibility](#backward-compatibility) for the full
  picture.
- **Docker-compose harness** — see [docker-compose.md](docker-compose.md) and
  the compose files at the repo root
  (`docker-compose-core-base.yml`, `docker-compose-core-threshold.yml`,
  `docker-compose-core-centralized.yml`) for a local multi-party network
  plus S3-mock, and telemetry sidecars.
- **Cargo feature flags** — `testing` enables test-only APIs; `slow_tests`
  enables the long-running suite.

See the "Building and testing" section of [README.md](README.md) for the
exact commands.

## Build and deployment

- **Toolchain** — Rust pinned via [rust-toolchain.toml](rust-toolchain.toml) along with Protobuf (`protoc`). Docker is also required for the test harness for some integration tests.
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

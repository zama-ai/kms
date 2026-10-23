# Architecture

KMS provides FHE key generation, CRS generation, decryption, and resharing for FHEVM.
Startup selects centralized mode or threshold MPC (`[threshold]` in server config; samples in [core/service/config/](../core/service/config/)); both share the service API.
Production threshold deployments typically run `n = 13` parties with threshold `t = 4`.
This file records navigation and cross-module invariants. Read linked source or task-specific docs for implementation details.

## Communication interfaces and trust model

Apply this summary in every review. Read the [trust model](../docs/explanations/trust_model.md) for attestation details, report scope, and exclusions before security review or reporting a security finding.

- **Service interface**: `CoreServiceEndpoint`, default port 50100. Infrastructure lets exactly one KMS connector reach it. The same operator runs the connector and the core, so the two trust each other by definition. The interface has no application-level TLS, authentication, or authorization, and is never publicly reachable. Do not add these controls unless your human asks.
- **Core-to-core interface**: `threshold-networking`, default port 50001. Production uses mTLS, peer allowlists, and sender identity bound to the certificate CN. TLS-off requires the `insecure` feature or a `cfg(test)` build.
- Authenticated MPC peers remain adversarial: at most `t` of `n` may be malicious, so peer message content is adversarial input. Every attack that works with at most `t` malicious parties is in scope, including bypassing TLS, attestation, or sender binding.
- Connector ACL checks and upstream ciphertext proofs do not make all request fields trusted. Externally supplied ciphertexts and handles, user public keys, EIP-712 signatures and domains, and parameter selectors remain untrusted. Crashes, stalls, unbounded allocations, or confidentiality failures through them are in scope, even though the request arrives over the service interface.

## Code map

| Area | Entry point |
|---|---|
| Service handlers and state | [core/service/src/engine/](../core/service/src/engine/), split into `centralized/` and `threshold/` |
| MPC protocols | [threshold-execution](../core/threshold-execution/), [threshold-algebra](../core/threshold-algebra/) |
| Peer transport | [core/threshold-networking/](../core/threshold-networking/) |
| Storage and keychains | [core/service/src/vault/](../core/service/src/vault/) |
| Custodian recovery | [core/service/src/backup/](../core/service/src/backup/), [backup_operator.rs](../core/service/src/engine/backup_operator.rs) |
| Signing, encryption, attestation | [core/service/src/cryptography/](../core/service/src/cryptography/) |
| Client verification and helpers | [core/service/src/client/](../core/service/src/client/); `validation_non_wasm.rs` / `validation_wasm.rs` in `engine/` |
| CLI / browser API | [core-client/](../core-client/); `core/service/src/client/js_api.rs` (hidden by default `non-wasm` feature) |
| Server/admin entry points | [core/service/src/bin/](../core/service/src/bin/) |

Workspace membership and dependencies: [Cargo.toml](../Cargo.toml). Test policy: [EDITING.md](./EDITING.md#verification). Commands: [COMMANDS.md](./COMMANDS.md).

## Test fixtures

Threshold fixtures supply the default epoch and PRSS setup per party. `TestMaterialSpec::threshold_basic` includes them; `ThresholdTestEnvBuilder::with_prss()` adds them to signing-only fixtures. Servers never create epochs at boot; request fresh epochs through `new_mpc_epoch`.

## gRPC surface

Source of truth: [kms-service.v1.proto](../core/grpc/proto/kms-service.v1.proto), shared [messages](../core/grpc/proto/kms.v1.proto), [insecure service](../core/grpc/proto/kms-service-insecure.v1.proto).

- Gateway assigns request IDs and binds payloads; connector retries preserve them. Per-operation metastores track IDs; MPC session IDs derive from request IDs.
- Known IDs normally return `AlreadyExists`. Async decryption can redo failed attempts; sync decryption attaches to existing work/results and can redo failures.
- Metastores are in memory. Connector persistence coordinates retries across core restarts; do not assume durable server-side deduplication.
- Noise-flooded user decryption derives masks locally from epoch PRSS and ciphertext session IDs; it needs no network session. Public and bit-decomposition user decryption do.
- After the local session closes, each outbound peer task gives every queued message half of `max_waiting_time_for_message_queue` to deliver, then drops it. A successful session can therefore discard final messages a slow peer still needs. See [get_closed_session_delivery_timeout](../core/threshold-networking/src/grpc/config.rs).
- Centralized nodes have no epoch registry; epoch-scoped operations accept only the default epoch. Omitted epoch IDs default to it.
- Startup selects the greatest epoch's metadata per key/CRS ID; epoch ordering is big-endian integer ordering.
- Keygen/CRS persist only after generation succeeds. Abort updates request state without purging storage. Insecure keygen still requires a preprocessing ID.
- Keysets contain separate OPRF and, when configured, transciphering secret shares. Legacy upgrades leave them absent; `UseExisting` generates missing shares. Resharing preserves absence and requires parties to agree on optional shares.

## Epoch and context lifecycle

- `NewMpcEpoch(previous_epoch=...)` performs resharing. The caller-supplied preprocessing ID enters the EIP-712 struct signed for the new epoch, so validate each one against stored `KeyGenMetadata` before protocol execution.
- Reshared keys require a public-key digest and exactly one server-key/compressed-keyset digest, all nonempty.
- Match old/new parties by MPC identity, not URL; overlapping parties use the new context URL. Reject identity/signer conflicts. A changed signing key requires a new MPC identity and separate core.
- Old/overlapping parties must hold input material; new-only parties need not.
- Epoch creation holds shared lifecycle leases through protocol execution and persistence: on the target context and the target epoch, and for a reshare also on the source context and the source epoch. Destruction requires exclusive leases; conflicts return `FailedPrecondition`, including before epoch registration.
- A party serializes reshare storage and rollback with one lock. Rollback removes only that request's new epoch material. Remove epoch registration only after its private key/CRS entries are gone.
- Delete newly created public material only after private cleanup succeeds. Retain preexisting public material. Failed private deletion preserves epoch/public state for retry.
- `DestroyMpcEpoch` erases the whole epoch and rejects the node's last remaining epoch. `DestroyMpcContext` rejects the last remaining context, snapshots registered epochs, erases shares, then removes context and TLS roots. Connector owns the authoritative context/epoch mapping.
- Context updates serialize the existence check with the storage, cache, and session updates. Failed deletion retains in-memory state when the persistent context remains.

## Signing and randomness

- Persisted ECDSA `SigningKey` is the on-chain identity. Independent `SigningSeed` derives non-ECDSA keys; both use `SIGNING_KEY_ID` and are not epoched.
- `NodeSigningIdentity` combines them in memory and is never persisted. Seedless legacy nodes support ECDSA only; other schemes return `MissingRootSeed`.
- Only `kms-gen-keys` creates seeds. Its `overwrite` option deletes the signing key, the seed, and the published verification material together. Fresh identities derive ECDSA from the seed; upgraded nodes retain their ECDSA key. Startup backfills public verification material without creating a seed.
- Publish scheme-specific keys/addresses in `TypedVerfKey` / `TypedVerfAddress` under `signing_material_id(scheme)`. Legacy ECDSA `VerfKey` / `VerfAddress` remain for existing consumers; new readers use typed material.
- Clients verify every requested signing scheme against published peer keys; missing schemes fail verification.
- Custodian backup uses `BACKUP_PKE_SCHEME` (MLKEM1024-P384) and every scheme in `BACKUP_SIGNING_SCHEMES` (ECDSA + ML-DSA-87). User decryption accepts ML-KEM-512 only.
- [RngSource](../core/service/src/engine/rng_source.rs) has independent 128-bit AES and 256-bit ChaCha parents. Forking cannot increase entropy. Tasks own separately seeded RNGs; parents discard buffered output after forks.
- Threshold epoch creation refreshes before reshare/PRSS forks, including old-only parties. Refresh mixes OS/security-module entropy and existing state; failure leaves both parents unchanged. Existing task RNGs do not change; no backtracking resistance within a reseeding interval.

## Paired material writes

- Public material is not epoched; private material is. Threshold pairs, each sharing one ID: `PublicKey` / `FheKeyInfo` (key ID) and `CRS` / `CrsInfo` (CRS ID).
- Complete key or CRS generation rejects existing public material, or private material at the requested epoch. Never combine a stale half with newly generated material.
- `CryptoMaterialStorage::write_all` also permits one-sided writes, because resharing writes only the private half, and it never overwrites existing entries. Callers must ensure pair consistency and serialize conflicting writes through cleanup.
- Resharing fetches digest-verified public bytes when missing, stores them verbatim before private metadata, and checks existing bytes match. `VerifiedCrsMaterial` hashes and deserializes the same bytes.
- Cleanup removes only entries created by the failed call. A backend may apply a write then report failure; inspect prior state. Backup failure does not purge primary material.
- File writes use synced temporary files plus atomic rename. Multi-file writes are not atomic; parent directories are not synced for power-loss durability.

## Boot-time storage verification

Entry points: [storage_material_verification.rs](../core/service/src/engine/storage_material_verification.rs).
Digest primitives: [material_integrity.rs](../core/service/src/engine/material_integrity.rs).
Peer repair: [public_material_sync.rs](../core/service/src/engine/public_material_sync.rs).

- Private storage is authoritative. Verification is read-only; recovery mode skips checks to permit repair.
- Hash **raw stored bytes**, never reserialized values: a tfhe format change since generation would alter the reserialized bytes and report intact material as corrupt. Startup does not deserialize public keys/CRSes. Legacy metadata without digests permits presence checks only.
- Validate private metadata signatures before using its digests. Stored domains permit EIP-712 verification; domainless legacy metadata supports ECDSA entries only. Require canonical scheme order, no duplicates, and the required external signature matching ECDSA. Missing keys for a scheme fail boot.
- Check public signing identity against private identity. Recovery-material signatures are checked from the backup vault.
- Reject mode-inappropriate private material, unknown epochs for key/CRS metadata, missing contexts for epochs, and context IDs inconsistent with storage handles.
- Signing layout permits key, seed, or both at the fixed ID; serving still requires the ECDSA key. Unknown files/folders and extra public material log errors without blocking boot.
- Threshold nodes repair failed public verification from peers in the material's epoch context, using the greatest epoch's private metadata per ID. Accept only matching raw-byte digests; verify again after repair. Unrecoverable required material fails boot.
- No peer repair for legacy digestless objects, decompression keys without private counterparts, or node-specific material. Centralized nodes have no peer repair.
- Backup repair copies missing private entries to the vault; it does not reverify existing backups. An uninitialized custodian keychain skips backup with a warning.
- Flat legacy `PrssSetup` fails threshold boot. Flat `PrssSetupCombined` remains valid through the 0.15 migration; 0.16 removes it and verifies deletion by relisting.

## Backup and recovery

- Versioned `BackupCiphertext`, tagged by `RequestId` and `PrivDataType`, stores private material in the backup vault. `KeychainProxy` ([vault/keychain/](../core/service/src/vault/keychain/)) selects the keychain that protects the wrapping key.
- `AwsKms` keychain: the wrapping key is an AWS KMS CMK. `RestoreFromBackup` completes restoration on it. The private vault must be readable at boot, so it rejects a `SecretSharing` keychain ([conf/mod.rs](../core/service/src/conf/mod.rs)).
- `SecretSharing` keychain: the wrapping key is Shamir-shared across custodians, driven by [kms-custodian](../core/service/src/bin/kms-custodian.rs) and the `NewCustodianContext` / `DestroyCustodianContext` / `CustodianRecoveryInit` / `CustodianBackupRecovery` RPCs.
- Secret-sharing backup needs an installed custodian context. Require unique custodian encryption/verification keys and complete backup schemes. Custodian keys derive from 256-bit mnemonic entropy.
- `RecoveryValidationMaterial` lives unencrypted at `RecoveryMaterial/<context_id>` in the **backup vault**, outside encrypted backup namespaces. Encrypting it under the recovery key would be circular. Verify its composite signature and storage/payload context IDs.
- Private `CustodianContextAnchor` selects the active context. Never choose by sorting/listing vault contents. No anchor means no backups; old public recovery material is ignored.
- Setup switches keychain and re-encrypts backups, writes recovery material, then writes the anchor last, so a crash before the anchor write leaves the previous context anchored. Failure restores prior keychain and purges failed-context backups. Read back an uncertain anchor write: committed new anchor means success; unreadable anchor retains material and clears keychain until reboot.
- Setup/destruction/recovery share `custodian_context_lock`. Setup runs on the task tracker through rollback, survives request cancellation, and refuses new work during shutdown.
- Verify purge completion before deleting recovery material/lifecycle state. Failed cleanup requires operator attention. Destruction can be retried after cancellation.
- `RESTORE_ORDER` restores contexts and epochs before dependent material, and the signing key last, so every intermediate state stays bootable: keysets never sit under an unknown epoch, and a node without its signing key stays in recovery mode. Existing entries are skipped so a partial restore can resume.
- A node without its signing key serves only recovery and stays in recovery mode until restart. Embedded recovery verification keys must agree across contexts and verify their material, but are not independently trusted: operators/custodians must authenticate fingerprints out of band.
- After restore, verify recovery material against the restored identity before anchoring the context. See [backup_operator.rs](../core/service/src/engine/backup_operator.rs), [context_manager.rs](../core/service/src/engine/context_manager.rs), and [vault](../core/service/src/vault/mod.rs).

## Backward compatibility

Read the [compatibility guide](../docs/developer/backward_compatibility.md) before changing persisted types.

- Persisted versioned types use `tfhe-versionable` layouts/upgrades and `Named`; [bc2wrap](../bc2wrap/) pins binary encoding. Preserve historical variants and wire compatibility.
- [backward-compatibility/](../backward-compatibility/) is a separate workspace because historical dependencies conflict. Pinned generators produce LFS vectors and `.ron` manifests; current loaders replay them.
- Frozen generators are nondeterministic: do not regenerate their vectors. See [COMMANDS.md](./COMMANDS.md#backward-compatibility) and [adding releases](../backward-compatibility/ADDING_NEW_VERSIONS.md).
- Storage-path migrations must verify copies before deleting originals and verify deletion afterward. The 0.15 CRS migration removes the flat entry only after it matches the default-epoch copy; on a mismatch startup fails, and an operator must remove the wrong copy. As a consequence, pre-0.14 releases can no longer load that CRS metadata.
- Custodian fixtures start at 0.15. The earlier format break was a pre-deployment exception, not permission for future compatibility breaks.

## Deployment invariants

- A core and its connector upgrade together. The connector is the only service-API consumer, so the service API need not stay backward compatible.
- Upgrades roll: for a while, some cores run release i and the rest i+1. Public and user decryption must keep working throughout.
- Constructive calls (key/CRS generation, context/epoch creation) and destructive calls (context/epoch destruction) never run during a rolling upgrade, and never concurrently. Concurrent calls indicate a contract bug; the core may reject them but must leave storage consistent.
- `core-client` is a test tool, used only with cores of its own release and never during upgrades.
- WASM clients upgrade last; decryption responses must remain readable by the previous release's WASM client.
- Package Dockerfiles consume the shared `kms-binaries` image through `KMS_BINARIES_IMAGE`; see [docker/kms-binaries/Dockerfile](../docker/kms-binaries/Dockerfile).
- [HealthState](../observability/src/health.rs) drives gRPC and HTTP probes. Readiness depends on startup/shutdown, **not peers or MPC state**, because Kubernetes routes peer traffic only to ready pods. Liveness fails on faults requiring restart.
- Deployment details: [Helm chart](../charts/kms-core/), [compose guide](../docker-compose.md). Protocol background: [Noah's Ark](https://eprint.iacr.org/2023/815).

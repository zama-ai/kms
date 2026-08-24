# KMS Custodian CLI Tool

The `kms-custodian` tool is run by a custodian on an air-gapped machine to support custodian-based backup and recovery. It has two roles:

- **Setup** (`generate`): derive a custodian's key material from a BIP39 seed phrase and produce the public setup message an operator needs to create a custodian context.
- **Recovery** (`decrypt`): use that seed phrase to decrypt a custodian's share of a backup and re-encrypt it for the recovering operator.

A `verify` command is also provided to check that a seed phrase matches a given setup message.

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install). The version pinned in [rust-toolchain.toml](../../rust-toolchain.toml) is picked up automatically by `rustup` when building inside the repository.

### Custodian setup
WARNING: Setup is only meant to be used in a highly secure setting. This means that some steps must be taken to ensure security. More specifically an _air gapped_ system *must* be used, either with a freshly installed operating system, or via live booting using an USB stick. 

Run the CLI tool with the `generate` command in order to generate keys for a custodian. More specifically:
```{bash}
$ cargo run --bin kms-custodian generate --randomness <random string of chars> --custodian-role <1-index role> --custodian-name <name of the custodian as a string>
```
(If using precompiled code, replace `cargo run --bin kms-custodian` with `./bin/kms-custodian`)

Observe that the `randomness` supplied is used along with entropy of the current system to derive keys, and thus the command is *not* idempotent. 
This will generate a fresh pair of keys for the given custodian and print the base64-encoded *public* setup message to stdout (prefixed with `The custodian setup message is: `). This setup message is what the operator collects (out-of-band) to run `new-custodian-context`.
Furthermore, this will print a BIP39 seed phrase on the screen. This seed phrase must be copied _exactly_ on to a piece of paper. The paper should be stored securely as this is needed in order to perform recovery.

Observe the seed phrase and the private keys do not get logged or saved to disc; instead the seed phrase is printed _once_ to stdout. Similarly for the base64-encoded *public* setup message.

For example the command may look like this:
```{bash}
$ cargo run --bin kms-custodian generate --randomness 123 --custodian-role 3 --custodian-name homer-3
```

After execution, the following steps *must* be taken.
1. The seed phrase must be written by hand on a paper. 
2. The base64-encoded *public* setup message must be copied and shared with the operators. This is done by using a factory-fresh USB stick and copy-pasting the base64 encoding into a new .txt file that is stored on the USB stick. NOTE: Do **NOT** store the seed phrase on the USB stick! 
3. A validation of the first two steps must be done. This is done by executing the [key verification](#key-verification) steps below.
4. After these steps have been executed the base64 setup message must be shared with *all* the operators. This is done out-of-band e.g. via Slack and/or Signal. 
5. The operators will then take over and setup a new custodian context. More specifically through their [setup](./core_client.md#setup-1) phase. 
6. When the operators' setup has been confirmed to have been completed and successful, the laptop and paper with the seed phrase must be stored in a physically secure location.


### Key verification 

Run the CLI tool with the `verify` command in order to validate that a seed phrase is the one used to generate certain setup information. More specifically:
```{bash}
$ cargo run --bin kms-custodian verify --seed-phrase <the seed phrase used for generation> --setup-msg <the base64 setup message printed by generate>
```
The call will print any inconsistencies found between the public keys generated from the seed phrase and those in the data supplied.

For example:
```{bash}
$ cargo run --bin kms-custodian verify --seed-phrase "stick essence exhaust bunker meat orchard wolf timber tackle gesture video cheap" --setup-msg "<base64 setup message>"
```

### Recovery (decryption of backup)
WARNING: Recovery is only meant to be done in a secure setting. This means that some steps must be taken to ensure security. More specifically a laptop with a clean system *must* be used, i.e. either with a freshly installed operating system, or via live booting using an USB stick. Concretely this should ideally be the laptop used during [setup](#custodian-setup).

Before being able to execute the recovery steps, ensure the following has been done:
1. The operator that must be recovered has initialized the [custodian recovery phase](./core_client.md#recovery-1).
2. The desire to execute custodian recovery has been confirmed out-of-band; e.g. over Slack and/or Signal. 
3. A safe laptop and the seed phrase has been recovered. 

Run the CLI tool with the `decrypt` command in order to decrypt a backup, and then reencrypt it under a supplied operator keyset. More specifically:
```bash
$ cargo run --bin kms-custodian decrypt --seed-phrase <the seed phrase used for generation> --randomness <random string of chars> --custodian-role <1-index role> --recovery-request <the base64 recovery request from the operator's custodian-recovery-init>
```
Observe that the `randomness` supplied is used along with entropy of the current system to do re-encryption, and thus the command is *not* idempotent. 
The base64-encoded recovery output is printed to stdout (prefixed with `The custodian recovery output is: `) to be copied back to the operator out-of-band.

> **IMPORTANT — the custodian cannot validate a request's authenticity.** The tool has no way to tell whether a recovery request is legitimate. It is therefore paramount that the request is validated out-of-band before decrypting, e.g. by checking it against a digest published on a blockchain.

For example:
```{bash}
$ cargo run --bin kms-custodian decrypt --seed-phrase "stick essence exhaust bunker meat orchard wolf timber tackle gesture video cheap" --randomness 123  --custodian-role 1 --recovery-request "<base64 recovery request>"
```

WARNING: After recovery to an operator it is **crucial** to consider the previous backup burned and hence a new seed-phrase must be constructed for all backup custodians. That is, the [custodian setup](#custodian-setup) must be reexecuted once the backup recovery has been successfully completed on the operator. 

---

## Protocol details

The rest of this document is background material for readers who want to understand what the CLI commands do under the hood. It is not required to use the tool.

The custodian-based backup protocol provides disaster recovery for KMS operators by Shamir-sharing a per-context backup encryption key across `n` offline custodians, tolerating up to `t` corruptions (`t < n/2`). At recovery time, `t + 1` honest custodians cooperate with the recovering operator to reconstruct the backup decryption key, which is then used to decrypt the operator's private key material from the backup vault.

The alternative backup mode — wrapping the same key under an AWS KMS CMK — is documented in [ai-docs/ARCHITECTURE.md](../../ai-docs/ARCHITECTURE.md#backup-and-recovery).

### Parties

| Party | What it does |
|---|---|
| **Custodian `B_j`** (`j = 1..n`) | Human-held, offline party. Owns a long-term signing key `sk^{S_j}` and a post-quantum encryption key `sk^{E_j}`, both deterministically derived from a BIP39 seed phrase. Stores nothing online beyond its public-key published in the `CustodianSetupMessage`. Re-signcrypts its share of the backup key on request. |
| **Operator `P_i`** (KMS node) | Online KMS server. Holds a long-term signing key `sk^{P_i}`, a TFHE secret key, and other private material that needs backing up. Receives `NewCustodianContext` and, later, `CustodianRecoveryInit` / `CustodianBackupRecovery` gRPC calls from the core-client. |
| **core-client** | The CLI that drives every gRPC call into the KMS for custodian-based backup. It bundles the operator-bound RPCs (`NewCustodianContext`, `CustodianRecoveryInit`, `CustodianBackupRecovery`, `RestoreFromBackup`) and shuttles the resulting `RecoveryRequest` / `InternalCustodianRecoveryOutput` files between the operator and the custodians out-of-band. Documented in [docs/guides/core_client.md](core_client.md). |
| **Recovering operator `P_i'`** | A fresh operator recovers the content of the private storage of a previous operator. Reads only the public storage and the backup vault; coordinates with custodians (via the core-client) to rebuild private state. |

### Data components

All names below match the Rust/proto types so you can grep for them.

| Component | Where it lives | Carries |
|---|---|---|
| [`CustodianSetupMessage`](../../core/grpc/proto/kms.v1.proto) | gRPC + custodian's base64 setup message | `{ custodian_role, name, payload }`. `payload` is a versioned [`CustodianSetupMessagePayload`](../../core/service/src/backup/custodian.rs) `{ header, random_value, timestamp, public_enc_key = pk^{E_j}, verification_key = pk^{S_j} }`. |
| [`CustodianContext`](../../core/grpc/proto/kms.v1.proto) | Argument to `NewCustodianContext` RPC | `{ custodian_nodes: [CustodianSetupMessage], custodian_context_id, threshold }`. |
| [`InternalCustodianContext`](../../core/service/src/backup/custodian.rs) | Operator's private storage (replicated through the backup vault) | `{ threshold, context_id, custodian_nodes, backup_enc_key }`. `backup_enc_key = pk^{B}` is the per-context public key whose secret half is Shamir-shared to the custodians. |
| [`BackupMaterial`](../../core/service/src/backup/operator.rs) | Plaintext payload **inside** every operator→custodian signcryption | `{ backup_id (= custodian_context_id), mpc_context_id, custodian_pk = pk^{S_j}, custodian_role, operator_pk, shares: Vec<Share> }`. Authenticates the binding between operator, custodian, and context. |
| [`OperatorBackupOutput`](../../core/grpc/proto/kms.v1.proto) | gRPC value | A signcryption `(payload, pke_type, signing_type)`. Plaintext is `BackupMaterial`. Created with `(sk^{P_i}, pk^{E_j})` and the custodian's verf-key ID as `receiver_id`. |
| [`RecoveryValidationMaterial`](../../core/service/src/backup/operator.rs) | Operator's **public** storage at `custodian_context_id` | Operator-signed `{ cts: BTreeMap<Role, InnerOperatorBackupOutput>, commitments: BTreeMap<Role, H(BackupMaterial_j)>, custodian_context: InternalCustodianContext, mpc_context }`. Lets the recovering operator re-fetch the original signcryptions and verify them against the operator-signed commitments. |
| `BackupCiphertext` | Backup vault | Long-term private material (signing key, threshold FHE keys, custodian context, …) encrypted under `pk^{B}` (`backup_enc_key`). Tagged with `RequestId` + `PrivDataType` — see [ARCHITECTURE.md](../../ai-docs/ARCHITECTURE.md#backup-and-recovery). |
| [`RecoveryRequest`](../../core/grpc/proto/kms.v1.proto) | Result of `CustodianRecoveryInit` (operator → core-client → custodian's `--recovery-request` base64 arg) | `{ ephem_op_enc_key = pk^{e_i}, operator_verf_key = pk^{P_i}, cts: map<custodian_role, OperatorBackupOutput> }`. Carries (a) the operator's ephemeral encryption key for this recovery session, (b) the operator's long-term verification key (which the custodian must validate out-of-band), and (c) the same signcrypted shares the operator stored at backup time. |
| [`InternalCustodianRecoveryOutput`](../../core/service/src/backup/custodian.rs) | Custodian's base64 stdout output → core-client | `{ signcryption, custodian_role }`. The signcryption is the **custodian → recovering-operator** envelope, made with `(sk^{S_j}, pk^{e_i})` over the same `BackupMaterial`. |
| [`CustodianRecoveryOutput`](../../core/grpc/proto/kms.v1.proto) | gRPC payload | Wire form of `InternalCustodianRecoveryOutput`: `{ backup_output, custodian_role }`. |
| [`CustodianRecoveryRequest`](../../core/grpc/proto/kms.v1.proto) | core-client → operator gRPC | `{ custodian_context_id, custodian_recovery_outputs: [CustodianRecoveryOutput] }`. |

### Protocol overview

The diagram below shows every message that crosses a party boundary in the six phases. Internal computation (how each party builds or validates a message) is described in the prose under each phase; here we focus only on which object is sent where.

```mermaid
sequenceDiagram
    autonumber
    participant Cus as Custodian B_j (air-gapped)
    participant Cli as core-client
    participant Op as Operator P_i / P_i'
    participant Pub as Public storage
    participant Vault as Backup vault

    rect rgba(200, 230, 255, 0.25)
    Note over Cus, Vault: Phase 1 — Custodian setup
    Cus->>Cli: CustodianSetupMessage (file, out-of-band)
    end

    rect rgba(220, 240, 220, 0.25)
    Note over Cus, Vault: Phase 2 — Custodian context creation
    Cli->>Op: NewCustodianContextRequest
    Op->>Pub: RecoveryValidationMaterial
    Op->>Vault: BackupCiphertext (InternalCustodianContext)
    end

    rect rgba(245, 235, 200, 0.25)
    Note over Cus, Vault: Phase 3 — Ongoing backup
    Op->>Vault: BackupCiphertext (continuous, per PrivDataType write)
    end

    rect rgba(255, 220, 220, 0.25)
    Note over Cus, Vault: Phase 4 — Recovery init
    Cli->>Op: CustodianRecoveryInitRequest
    Pub-->>Op: RecoveryValidationMaterial
    Op-->>Cli: RecoveryRequest
    end

    rect rgba(230, 220, 245, 0.25)
    Note over Cus, Vault: Phase 5 — Custodian re-encryption
    Cli->>Cus: RecoveryRequest (+ operator verf-key, out-of-band)
    Cus-->>Cli: InternalCustodianRecoveryOutput
    end

    rect rgba(220, 245, 240, 0.25)
    Note over Cus, Vault: Phase 6 — Recovery finalization
    Cli->>Op: CustodianRecoveryRequest
    Pub-->>Op: RecoveryValidationMaterial
    Vault-->>Op: BackupCiphertext (per PrivDataType, in a loop)
    end
```

### Phase 1 — Custodian setup (offline, one-time per custodian)

Corresponds to [`kms-custodian generate`](#custodian-setup). A future custodian boots the air-gapped machine and runs the command. Keys are derived from system entropy mixed with a user-supplied `--randomness` string; the matching BIP39 seed phrase is printed to stdout **once** and must be copied onto paper.

The seed phrase is the only durable secret the custodian holds. `sk^{E_j}` and `sk^{S_j}` are re-derived from it whenever the custodian participates in a recovery.

### Phase 2 — Custodian context creation (online, one-time per context)

The core-client gathers `n` `CustodianSetupMessage`s (each custodian's base64 setup message), picks a corruption threshold `t < n/2`, and issues a `NewCustodianContext` gRPC call to every operator in the KMS cluster. Each operator, independently: generates a per-context backup keypair `(sk^{B}, pk^{B})`, Shamir-shares `sk^{B}` into `n` shares, builds and signcrypts one `BackupMaterial` per custodian role, computes a commitment over each `BackupMaterial`, packages everything into a signed `RecoveryValidationMaterial` (written to the operator's own public storage at `request_id = custodian_context_id`), and encrypts the resulting `InternalCustodianContext` into a `BackupCiphertext` for the backup vault. After secret-sharing, the operator drops `sk^{B}` and installs `pk^{B}` in its `SecretSharing` keychain.

Notes:
- The Shamir threshold encoded inside `RecoveryValidationMaterial.custodian_context.threshold` is the **recovery** threshold (`t + 1` shares needed). `Operator::new_for_sharing` enforces `t < n/2`.
- `sk^{B}` is **only** held in memory during this RPC. After secret-sharing it, the operator drops it.
- The commitment `c_j = H(BackupMaterial_j)` is what the recovering operator later checks against the decrypted material — it lets a single signature on `RecoveryValidationMaterial` authenticate every share at once, without making the encrypted plaintext public.

### Phase 3 — Ongoing backup (whenever the operator writes private material)

When the operator writes any `PrivDataType` (signing key, threshold FHE keys, custodian context itself, etc.) to private storage, the `SecretSharing` keychain encrypts the data under `pk^{B}` and stores the resulting `BackupCiphertext` in the backup vault, tagged with the originating `RequestId` and `PrivDataType`. The custodians never see this material — only `pk^{B}` matters here.

This phase is invisible to custodians and to the core-client. It runs continuously for the life of the operator.

### Phase 4 — Recovery init (operator's private storage is gone)

The recovering operator boots against the same **public** storage and backup vault but with empty private storage. It calls `CustodianRecoveryInit`, generates an ephemeral encryption keypair `(sk^{e_i}, pk^{e_i})` pinned in process memory, reads `RecoveryValidationMaterial` from public storage at `ctx_id`, verifies the operator's signature on it, and returns a `RecoveryRequest` to the core-client (which writes it to disk for later distribution to the custodians).

The recovering operator has the same long-term verification key as the original (recovered out of band from public storage), so `RecoveryValidationMaterial`'s signature still verifies.

`sk^{e_i}` lives only in process memory; restarting the server discards it. `overwrite_ephemeral_key=true` lets a stuck recovery be re-initiated.

### Phase 5 — Custodian re-encryption (offline, manual)

Corresponds to [`kms-custodian decrypt`](#recovery-decryption-of-backup). The core-client (or operator's human operator) distributes the base64 `RecoveryRequest` out-of-band to each custodian's air-gapped machine; the recovering operator's verification key is carried inside the request, so it no longer needs to be sent separately. The custodian boots, types in the seed phrase, and runs the command: re-derives `(sk^{E_j}, sk^{S_j})` from the seed phrase, unsigncrypts its share of `BackupMaterial` from `cts[j]`, sanity-checks the metadata inside and then re-signcrypts the same `BackupMaterial` to the operator's ephemeral key `pk^{e_i}`, and prints the resulting `InternalCustodianRecoveryOutput` as base64 to stdout.

The custodian's only cryptographic obligation is "decrypt your share and re-signcrypt it for the operator's ephemeral key". The custodian can't (and isn't asked to) judge whether this request is legitimate — see the warning at the top of the [Recovery](#recovery-decryption-of-backup) section. Furthermore, observe that the way the custodian receives the operator's recovery request and material, is through an out-of-band channel (e.g. Slack and/or Signal).

### Phase 6 — Recovery finalization (operator reconstructs)

For each operator that needs recovery, their core-client collects `t + 1` (or more) custodian output files and sends them, in a single `CustodianRecoveryRequest`, and sends this to the KMS core. The recovering operator re-reads `RecoveryValidationMaterial` from public storage and validates each `CustodianRecoveryOutput`, and once at least `t + 1` shares pass — Shamir-reconstructs `sk^{B}` and installs it in the `SecretSharing` keychain. Restoration then happens automatically: the operator iterates every `BackupCiphertext` in the backup vault, decrypts each with `sk^{B}`, writes the plaintext into the now-empty private storage, and finally drops the ephemeral key from memory.

After Phase 6 the recovering operator's private storage is repopulated and the node resumes normal service. The operator-side commands that drive Phases 4 and 6 are documented in [docs/guides/core_client.md](core_client.md).

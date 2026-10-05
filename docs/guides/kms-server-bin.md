# KMS Core Service Binaries

## KMS Key Generation

`kms-gen-keys` generates the server signing keys (and, in threshold mode, the per-party self-signed CA certificates used for mTLS).

To generate the signing material before the KMS server is started, pass a TOML config file:

```bash
cargo run --bin kms-gen-keys -- --config-file /path/to/kms-gen-keys.toml
```

The config must include a `[keygen]` section and the storage settings used to write the generated material:

```toml
[keygen]

[threshold]
my_id = 1
tls_subject = "kms-core-1"

[public_vault.storage.file]
path = "./keys"

[private_vault.storage.file]
path = "./keys"
```

For threshold configs, `threshold.my_id` selects the party. The TLS certificate
subject is read from `threshold.tls_subject` when present; otherwise it is
derived from the matching `[[threshold.peers]]` entry, preferring `mpc_identity`
and falling back to `address`.

Omit the `[threshold]` section to generate centralized signing material. The
centralized mode does not generate a CA certificate.

### `[threshold]` options

The `[threshold]` section accepts only the fields below. The tool rejects any
other field.
The tool needs a TLS subject on every threshold run, also when a CA certificate
exists. Still, the tool only generates a CA certificate when public storage has 
no `CACert` object, so a run on an existing party does not change its certificate,
in which case any values can be used for the `[threshold]` parameters.

The required parameters are as follows:

- `my_id`: the one-indexed party id. This field is required.
- `tls_subject`: the subject of the self-signed CA certificate. The CA
  certificate issues the mTLS certificates of the party, and the tool signs it
  with the ECDSA signing key of the party.
- `tls_wildcard`: generate a wildcard subject. Defaults to `false`.
- `peers`: a peer list with the same `[[threshold.peers]]` format as the
  `kms-server` config. The tool uses it only when `tls_subject` is not set.

Example with a peer list instead of `tls_subject`:

```toml
[threshold]
my_id = 1

[[threshold.peers]]
party_id = 1
address = "127.0.0.1"
mpc_identity = "kms-core-1"
port = 50001
```

### Local test config

To test the tool locally, in threshold mode, the configuration file `../../core/service/config/local_keygen.toml` 
can be used:

```bash
cargo run --bin kms-gen-keys -- --config-file ../../core/service/config/local_keygen.toml
```

### `[keygen]` options

All three flags default to `false` and are mutually exclusive —
pick at most one per run:

- `overwrite`: delete any existing signing material at the fixed signing-key
  handle (the private signing key, the root signing seed, and every scheme's
  verification material in public storage) before generating a fresh identity.
  Required to rotate a key.
- `show_existing`: print the existing signing-material handles and exit, without
  generating or deleting anything. Each per-scheme line names its scheme, and the
  address folders print the stored text, so this is what an operator reads to learn
  which identifiers to register for a node.
- `repopulate`: derive and store every piece of missing verification material
  — each scheme's key and digest, ECDSA's included, plus the two deprecated
  ECDSA-only objects — from the signing identity already present in private
  storage, then exit without touching that identity. Requires both the ECDSA
  signing key and the root signing seed to already exist. Material that is
  already published is validated against that identity rather than overwritten.
  Use this to restore verification material after a partial purge.

### What is written to private storage

A node's signing identity is two objects, both under the fixed `SIGNING_KEY_ID`
handle:

| Folder | Contents |
| --- | --- |
| `SigningKey` | The ECDSA/secp256k1 signing key. This is the node's authoritative identity: it is the one registered on-chain, and it is what the node signs ECDSA with. It stays authoritative for ECDSA until operators rotate onto their seed-derived ECDSA key. Unchanged from earlier releases. |
| `SigningSeed` | A 32-byte root secret drawn from the CSPRNG, which the node's signing keys are derived from eventually. |

The seed is generated independently of the ECDSA key, so recovering the secp256k1
scalar does not reveal any post-quantum key. **Losing the seed loses every
seed-derived identity of the node** — they exist nowhere else — so it is part of
the backup set, handled exactly like `SigningKey`.

The seed is meant to root *all* of a node's signing keys, ECDSA included, and on a
freshly generated node it already does: its ECDSA key is derived from the seed. An
existing operator is the exception, and only temporarily — its ECDSA key is
registered on-chain and cannot be rotated by a software upgrade, so the
`SigningKey` object above remains the authoritative ECDSA identity and the seed
serves the other schemes, until a later release rotates ECDSA onto the seed as
well.

A seed is only ever created by an explicit `kms-gen-keys` run, never silently at
boot:

- On a **fresh** node (no `SigningKey`), the seed is generated first and the ECDSA
  key is derived from it, so the whole identity descends from the seed.
- On an **upgraded** node (a `SigningKey` from an earlier release, no seed), the
  ECDSA key is left byte-for-byte untouched — operator identities are registered
  on-chain and cannot be rotated by a software upgrade — and a seed is generated
  beside it, then the non-ECDSA verification material is backfilled.
- A node started with no seed logs a warning and runs **ECDSA-only**: it boots and
  serves normally, but a request asking for a non-ECDSA scheme fails with a signing
  error until `kms-gen-keys` has been run. The boot-time migration deliberately does
  not mint a seed of its own.
- If public storage already holds non-ECDSA verification material and the seed is
  missing, `kms-gen-keys` fails instead of generating a replacement: a new seed
  would rotate every published post-quantum identity. Restore the seed from the
  backup vault, or use `overwrite` to regenerate the whole identity.

### What is written to public storage

Every scheme's public material — including ECDSA's — is written to the two `Typed*`
folders below, each under its own scheme-specific handle, so that a folder holds
exactly one kind of object and can be read whole:

| Folder | Contents |
| --- | --- |
| `TypedVerfKey` | One verification key per scheme, ECDSA's included; natively encoded. |
| `TypedVerfAddress` | The digest identifying each of those keys, as `0x`-prefixed hex text. For ECDSA it is the node's Ethereum address. |
| `VerfKey` | **Deprecated.** The node's ECDSA verification key as a bare `PublicSigKey`, under the fixed `SIGNING_KEY_ID` handle. Unchanged from earlier releases. |
| `VerfAddress` | **Deprecated.** The matching Ethereum address (checksummed, `0x`-prefixed), under the same handle. Unchanged from earlier releases. |

The two deprecated folders are still written, so consumers that read the ECDSA key
or address by handle keep working unchanged. They will be removed in a future
release: new readers should take the ECDSA entry from `TypedVerfKey` /
`TypedVerfAddress` instead.

For local test/dev runs that need pre-baked FHE keys + CRS, use `generate-test-material` instead (see the `generate-test-material-*` targets in the top-level `Makefile`).

### Upgrading an existing node

A node from a release without the root signing seed has only the ECDSA
`SigningKey`. Do these steps once per node to add the seed:

1. Run `kms-gen-keys` with the original config of the node. Do not set
   `overwrite` or `repopulate`. The run keeps the ECDSA key, generates the seed,
   and writes the missing verification material. The log shows `Signing keys
   already exist, skipping generation` for the ECDSA key, and `Generated a root
   signing seed` for the seed.
2. Run `kms-gen-keys` with `[keygen] show_existing = true`. Make sure that the
   output has a `SigningSeed` line and one `TypedVerfAddress` line per scheme.
   Make sure that the ECDSA address did not change.
3. Start the node once. Then make sure that the seed is in the backup vault.

`repopulate` does not work for this upgrade, because it requires an existing seed.
A second run of step 1 is safe, because the run uses the stored seed again.
In the `kms-core` Helm chart, a node without an enclave runs `kms-gen-keys` in
an init container at each pod start. On those nodes, step 1 runs after the
upgrade without operator action.

An enclave node does not do step 1 at boot.
[`init_enclave.sh`](../../docker/core/service/init_enclave.sh) runs
`kms-gen-keys` with the config that the parent sends. At a normal boot, this is
the `kms-server` config, which `kms-gen-keys` rejects. In enclave mode, the
chart sends the `kms-gen-keys` config in the `kmsGenCertAndKeys` job, which
runs before install, and before each upgrade while `kmsGenCertAndKeys.enabled`
is `true`. Set `kmsGenCertAndKeys.enabled` to `true` for the upgrade, so that
this job does step 1. Then set it back to `false`. From chart 1.9.6, the
job preempts the core pod and reuses its enclave slot. The party is down
until the StatefulSet starts the core again. The job reports success also when step 1 failed, so step 2
is mandatory. See
[Upgrade from v0.14 to v0.15](../operations/upgrade-0.14-to-0.15.md#check-the-result)
for the step 2 checks on an enclave node.

### Moving a cluster onto seed-rooted identities

An operator that upgraded from a release without the root signing seed keeps its
original ECDSA key, so only its non-ECDSA keys descend from the seed. The cluster
reaches the end state — every key of every node derived from one seed — at an **MPC
context switch**, with new nodes generated from scratch. No node ever rewrites the
ECDSA key it is live under, so this is an operational procedure and not a
KMS-side key rotation.

Per node, in this order:

1. **Generate the identity** with `kms-gen-keys` against empty storage. The seed is
   drawn first and the ECDSA key is derived from it, so the whole identity descends
   from one secret. Do not use `overwrite` on a live node for this: it deletes the
   seed and destroys every post-quantum identity the node already published.
2. **Start the node once**, and confirm the seed reached the backup vault. The boot
   pass copies new private objects into the vault, so a freshly generated seed is
   only protected after that start. A node whose seed is not yet backed up must not
   be registered: losing the seed loses every key derived from it.
3. **Read the identifiers to register**: run `kms-gen-keys` with
   `[keygen] show_existing = true`. Every per-scheme line names its scheme, so the
   `TypedVerfAddress` lines give the ECDSA address to register on-chain and each
   other scheme's digest to put in the new context.
4. **Register the node** in the new context's per-scheme digests, and its ECDSA
   address on-chain.

Once every node of the new context is registered, activate the context and only
then decommission the old nodes. Each old node keeps its own key until it is
retired, so there is no window in which a node signs under an identity nobody has
registered.

A further rotation follows the same route: a further context switch, with a fresh
seed per node.

## Threshold KMS TLS Certificates

If you want to run a threshold KMS, you also need TLS certificates and keys that secure the communication between the MPC cores.
These can be generated with the following commands:

```bash
cargo run --bin kms-gen-tls-certs -- --ca-prefix p --ca-count 4
```

## Running the KMS

### Locally running a centralized KMS Core

Running a centralized KMS Core with the default configuration:

```bash
cargo run --bin kms-server -- --config-file config/default_centralized.toml
```

### Locally running a threshold KMS Core

Running a threshold KMS Core with the default configuration requires running the following commands, each in a separate terminal:

```bash
cargo run --bin kms-server -- --config-file config/default_1.toml
cargo run --bin kms-server -- --config-file config/default_2.toml
cargo run --bin kms-server -- --config-file config/default_3.toml
cargo run --bin kms-server -- --config-file config/default_4.toml
```

## kms-init

The threshold nodes need to be initialized _once_ when they start for the first time, before they can run public or user decryptions.
This can be achieved by running the following stand-alone command, with the correct threshold node addresses as parameters:

```bash
cargo run --bin kms-init -- -a http://127.0.0.1:50100 http://127.0.0.1:50200 http://127.0.0.1:50300 http://127.0.0.1:50400
```

Note that this must only be done _once_ per set of threshold nodes. Calling `init` multiple times will result in an error.
Once the init material is successfully generated, it is stored to disk into the party's private storage, currently under `PRIV-pX/PrssSetup/000..001`, where `pX` denotes the party id, e.g. `p1`, etc.

When a threshold node restarts, it will automatically use init material it finds on disk. This allows failing nodes to re-join an existing set of nodes, without running `init` again.

When a different set of nodes (or a different number of nodes) should run the threshold protocols, `init` must be done again. Currently the only way is to manually delete the init material from disk in `PRIV-pX/PrssSetup/`.

## Docker and kms-core-client

To interact with a deployed version of the KMS, the recommended way is to use the [`kms-core-client`](./core_client.md).

## Mocked enclave mode

In production, the KMS server runs inside an AWS Nitro Enclave and uses the enclave's Nitro Security Module (NSM) to produce attestation documents. These attestations are required (a) by the AWS KMS key policy that guards the private-vault root key, and (b) by peers during the mTLS handshake when `[threshold.tls.auto]` is enabled.

For local development and testing outside an actual enclave, both `kms-server` and `kms-gen-keys` support a software-emulated NSM. Both binaries must be built with the `insecure` Cargo feature; without it the option is not compiled in.

On the server, set the top-level `mock_enclave` key in the TOML config:

```toml
mock_enclave = true
```

See `core/service/config/compose_*.toml` for working examples used by the docker-compose threshold setup.

On the key-generation side, set the same field in the config used with
`--config-file`:

```toml
mock_enclave = true
```

Both sides must agree: a server with `mock_enclave = true` will only accept attestations from peers and KMS keys that were also produced under the mock module, and vice versa.

When enabled, attestation documents are signed with a baked-in development key and report all-zero PCR values. Such attestations cannot satisfy a production AWS KMS key policy and provide no isolation guarantees, so this mode must never be used outside of development and test environments.

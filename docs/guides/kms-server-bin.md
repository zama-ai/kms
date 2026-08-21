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

### `[keygen]` options

All three flags default to `false` and are mutually exclusive in practice —
pick at most one per run:

- `overwrite`: delete any existing signing material at the fixed signing-key
  handle (the private signing key, the root signing seed, and every scheme's
  verification material in public storage) before generating a fresh identity.
  Required to rotate a key; without it, generation fails if storage already holds
  material for that handle. **This destroys every post-quantum identity of the
  node**, since they are derived from the seed and stored nowhere else.
- `show_existing`: print the existing signing-material handles instead of
  generating or deleting anything.
- `repopulate`: derive and store every scheme's verification material
  (ECDSA's included) from the signing identity already present in private
  storage, then exit without touching that identity. Requires both the ECDSA
  signing key and the root signing seed to already exist, and validates any
  verification material already in public storage against them. Use this to
  restore verification material after a partial purge — for example, public
  storage was restored from a snapshot that predates a signing scheme, or a
  per-scheme object was deleted by hand — without regenerating any private key.

### What is written to private storage

A node's signing identity is two objects, both under the fixed `SIGNING_KEY_ID`
handle:

| Folder | Contents |
| --- | --- |
| `SigningKey` | The ECDSA/secp256k1 signing key. This is the node's authoritative identity: it is the one registered on-chain, and it is what the node signs ECDSA with. Unchanged from earlier releases. |
| `SigningSeed` | A 32-byte root secret drawn from the CSPRNG, which every **non-ECDSA** signing key of the node is derived from. |

The seed is generated independently of the ECDSA key, so recovering the secp256k1
scalar does not reveal any post-quantum key. **Losing the seed loses every
non-ECDSA identity of the node** — they exist nowhere else — so it is part of the
backup set, handled exactly like `SigningKey`.

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

A node signs ECDSA with its persisted ECDSA signing key; the verification keys of
the other supported signature schemes are derived from its root signing seed. Every
scheme's public material — including ECDSA's — is written to the two `Scheme*`
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

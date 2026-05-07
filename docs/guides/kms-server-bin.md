# KMS Core Service Binaries

## KMS Key Generation

`kms-gen-keys` generates the server signing keys (and, in threshold mode, the per-party self-signed CA certificates used for mTLS).

To generate the signing material before the KMS server is started, run one of:

```bash
cargo run --bin kms-gen-keys -- centralized
cargo run --bin kms-gen-keys -- threshold
```

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

On the key-generation side, pass the matching CLI flag:

```bash
cargo run --bin kms-gen-keys --features insecure -- --mock-enclave ...
```

Both sides must agree: a server with `mock_enclave = true` will only accept attestations from peers and KMS keys that were also produced under the mock module, and vice versa.

When enabled, attestation documents are signed with a baked-in development key and report all-zero PCR values. Such attestations cannot satisfy a production AWS KMS key policy and provide no isolation guarantees, so this mode must never be used outside of development and test environments.

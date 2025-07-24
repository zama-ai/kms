# KMS Core Service Binaries

## KMS Key Generation

KMS keys must be generated before the KMS server can be started. To generate them you can do the following for the centralized or threshold version respectively:

```bash
cargo run --bin kms-gen-keys -F testing -- centralized
cargo run --bin kms-gen-keys -F testing -- threshold
```

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

# KMS Core Service Binaries

## kms-example-client

This binary is an example client to interact with the KMS Core Service.
It supports both a centralized and a threshold KMS Core. This binary essentially interacts with the KMS Core the same way the Blockchain Connector does, but only for testing purposes and without relaying the results further.

In the following we assume that all commands are run from the `core/service/` directory.

### Prerequisites

We're assuming that you're running the KMS Core(s) locally.

#### KMS Keys

For this, KMS keys must exist. To generate them you can do the following:

```bash
cargo run --bin kms-gen-keys -F testing -- centralized --param-path parameters/default_params.json
cargo run --bin kms-gen-keys -F testing -- threshold --param-path parameters/default_params.json
```

#### Threshold KMS TLS Certificates

If you want to run a threshold KMS, you also need TLS certificates and keys.
These can be generated with the following commands:

```bash
cargo run --bin kms-gen-tls-certs -- --ca-prefix p --ca-count 4
```

### Testing a centralized KMS Core

Running a centralized KMS Core with the default configuration:

```bash
cargo run --bin kms-server -- centralized --config-file config/default_centralized.toml
```

Running the example client (from a separate terminal):

```bash
cargo run --bin kms-example-client -F testing -- centralized
```

The default address is set to `localhost:50051`, which matches what is currently in `config/default_centralized.toml`. This can be changed by passing the `-a` flag.

### Testing a threshold KMS Core

Running a threshold KMS Core with the default configuration requires running the following commands, each in a separate terminal:

```bash
cargo run --bin kms-server -- threshold --config-file config/default_1.toml
cargo run --bin kms-server -- threshold --config-file config/default_2.toml
cargo run --bin kms-server -- threshold --config-file config/default_3.toml
cargo run --bin kms-server -- threshold --config-file config/default_4.toml
```

Running the example client (from another separate terminal):

```bash
cargo run --bin kms-example-client -F testing -- threshold
```

The default addresses are set to `localhost:50100,localhost:50200,localhost:50300,localhost:50400`, which matches what is currently in the default configs for the threshold KMS. These can be changed by passing the `-a` flag and specifying addresses separated by commas.

#### Initializing the threshold KMS Cores

If this is the first query to a set of threshold KMS cores and they have not been initialized before, it is possible to do the initialization by adding the `-i` flag to the command. Note that this initialization must only be done once per set of threshold nodes.
Alternatively you can use the `kms-init` binary to do the initialization (see [below](#kms-init)).

Note that the example client currently runs a `u8` decryption. This takes a few seconds, depending on the available hardware.
By default, the binaries are built with optimizations and debug info enabled. Performance might increase slightly by passing `--release` to the cargo run commands.

### Server Logs

The server logs might currently contain errors such as the following:

```
ERROR grpc_request{endpoint="/kms.CoreServiceEndpoint/GetReencryptResult" headers={"te": "trailers", "content-type": "application/grpc", "user-agent": "tonic/0.11.0"} trace_id="00000000000000000000000000000000"}: tower_http::trace::on_failure: response failed classification=Code: 14 latency=0 ms
```

These stem from tracing and can be safely ignored in a local deployment.


## kms-init

The threshold nodes need to be initialized _once_ when they start for the first time, before they can run decryptions or reencryptions.
This can be achieved by running the following stand-alone command, with the correct threshold node addresses as parameters:
```bash
cargo run --bin kms-init -- -a http://127.0.0.1:50100 http://127.0.0.1:50200 http://127.0.0.1:50300 http://127.0.0.1:50400
```

Alternatively, the same can be achieved by using the `kms-example-client`, by adding the `-i` flag. (see [above](#initializing-the-threshold-kms-cores)).

Note that this must only be done _once_ per set of threshold nodes. Calling `init` multiple times will result in an error.
Once the init material is successfully generated, it is stored to disk into the party's private storage, currently under `PRIV-pX/PrssSetup/000..001`, where `pX` denotes the party id, e.g. `p1`, etc.

When a threshold node restarts, it will automatically use init material it finds on disk. This allows failing nodes to re-join an existing set of nodes, without running `init` again.

When a different set of nodes (or a different number of nodes) should run the threshold protocols, `init` must be done again. Currently the only way is to manually delete the init material from disk in `PRIV-pX/PrssSetup/`.

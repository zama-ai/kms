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
Alternatively you can use the `kms-init-threshold` binary to do the initialization.

Note that the example client currently runs a `u8` decryption. This takes a few seconds, depending on the available hardware.
By default, the binaries are built with optimizations and debug info enabled. Performance might increase slightly by passing `--release` to the cargo run commands.

### Server Logs

The server logs might currently contain errors such as the following:

```
ERROR grpc_request{endpoint="/kms.CoreServiceEndpoint/GetReencryptResult" headers={"te": "trailers", "content-type": "application/grpc", "user-agent": "tonic/0.11.0"} trace_id="00000000000000000000000000000000"}: tower_http::trace::on_failure: response failed classification=Code: 14 latency=0 ms
```

These stem from tracing and can be safely ignored in a local deployment.
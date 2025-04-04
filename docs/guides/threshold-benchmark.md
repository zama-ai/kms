# Benchmarking the threshold protocols

<!--
Remove the core/threshold reference below when we copy this file to threshold-fhe
since core/threshold will be at the root.
-->
The code under `core/threshold` implements threshold multi-party computation protocols
such as threshold key generation, threshold decryption
and so on for TFHE, BFV and BGV.
The protocols are designed to be both secure and robust when a fraction
of the parties are malicious.
This page describes how to run the benchmarks in a wide range of configurations on the threshold protocols.
For the rest of this page, we assume the user is working under the `core/threshold` directory.

## Directory overview

- `benches`
  - Code needed for benchmarking the threshold protocols.
- `config`
  - Default and example configurations needed when benchmarking and testing the threshold protocols.
- `examples`
  - Some example code to get you started.
- `experiments`
  - Other configuration files for benchmarks.
- `protos`
  - Protobuf files, both for testing/benchmarking and for communication between the MPC parties.
- `src`
  - Source code for the actual server and actual MPC protocols.
- `test_scripts`
  - Bash scripts used for testing.
- `tests`
  - Integration tests.
<!--
- `TechnicalDocumentation`
  - Contains our preliminary draft NIST main submission document. 
-->

## Benchmarks with real network

Benchmarking with a real network requires to set up said network inside a docker compose orchestrator. This prevents integrating this kind of benchmarks with `Criterion` inside `cargo bench` running command.

In order to bypass this limitation we have automated this `gRPC` benchmarks using `cargo-make` utility.

### Prerequisites for running benchmarks

- [Rust](https://www.rust-lang.org/), you need version 1.85.0 or higher.
- [cargo-make](https://github.com/sagiegurari/cargo-make?tab=readme-ov-file#installation), using `cargo`.
- [docker](https://www.docker.com/), install it using your preferred method, from a package manager or using Docker Desktop.
- [protoc](https://protobuf.dev/installation/), install it using your preferred method, e.g., from a package manager.
- [redis](https://redis.io/docs/latest/get-started/): this is optional, only required for running the redis integration tests.
  Benchmarks that use redis inside a docker container do not require a local redis installation.

### Generate experiment

To create configuration files, we use a binary located in `src/bin/benches/gen-experiment.rs`.
This binary dynamically creates a new experiment setup on the fly. An experiment is composed of a `.yml` file that describes the parties (and telemetry) configuration, and a `.toml` configuration file for the choreographer (`mobygo` or `stairwayctl`) with the network topology of the parties. See `cargo run --bin gen-experiment --features="templating" -- --help`.

### Parties

The MPC parties are run by executing the mobygo binary from `src/bin/moby/mobygo.rs`.
We use the same mobygo source file for both `BGV` and `TFHE`, the difference is set via feature flags:

- For TFHE, compile mobygo with either no feature or **--features testing** (to allow for centralised key generation)
- For BGV, compile mobygo with **--features experimental,testing**.

We thus have two possible docker images which we can be build, one for `TFHE` and one for `BGV`.
Note that `BFV` is very similar to `BGV` as it is possible to convert between the two, so we do not provide a separate build.

TFHE image can be built via

```sh
cargo make tfhe-docker-image
```

BGV image can be built via

```sh
cargo make bgv-docker-image
```

### Choreographer

To interact with the MPC parties, we use a choreographer called `moby` from `src/bin/moby/moby.rs` for `TFHE`, and `stairwayctl` from `src/experimental/bin/stairwayctl.rs` for `BGV`.

In both cases, the choreographer allows to:

- Initiate the PRSSs
- Create preprocessing (for Distributed Key Generation in both cases and Distributed Decryption for `TFHE`)
- Initiate Distributed Key Generation
- Initiate Distributed Decryption
- Initiate CRS Ceremony (for `TFHE` only)
- Retrieve results for the above
- Check status of a task

For a list of the available commands, run:

```sh
./moby --help
```

And for information on a specific command, run:

```sh
./moby command --help
```

(Works also with `stairwayctl`)

### Pre-defined commands

With `cargo make` we have pre-defined commands to run experiments for both `TFHE` and `BGV`.

NOTE: Commands prefixed with `tfhe-` can be replaced by `bgv-`to execute experiment for `BGV` instead of `TFHE`.

First generate the certificates, say for 5 MPC parties:

```sh
cargo make --env NUM_PARTIES=5 gen-test-certs
```

Then create the `.yml` and `.toml` files for the experiment:

```sh
cargo make --env NUM_PARTIES=5 --env THRESHOLD=1 --env EXPERIMENT_NAME=my_experiment tfhe-gen-experiment
```

Finally, run the parties:

```sh
cargo make --env EXPERIMENT_NAME=my_experiment start-parties
```

It is now possible to interact with the cluster of parties with the `mobygo` choreographer by using the generated `.toml` file:

```sh
./mobygo -c temp/my_experiment.toml my-command
```

The CLI tool `mobygo` can be built with `cargo build  -F choreographer --bin mobygo`.
See `./mobygo -h` for available commands.

Once done, we can shut down the parties with:

```sh
cargo make --env EXPERIMENT_NAME=my_experiment stop-parties
```

We also provide one-liner benches, which can be run directly after the certificate generations.
Note that these one-liner scripts are using insecure testing parameters.
The `PARAMS` variable in `tfhe_test_script_fake_dkg.sh`
and `tfhe_test_script_real_dkg.sh` must be changed to support real parameters.

Either with a *fake* centralised key generation

```sh
cargo make tfhe-bench-fake-dkg
```

Or with a real key generation (which takes much longer)

```sh
cargo make tfhe-bench-real-dkg
```

These benchmarks run the scripts located in the `test_scripts` folder.

**NOTE**: The docker container also runs telemetry tools, therefore when running experiments, all telemetry data are exported to [jaeger](http://localhost:16686) as well as locally exported in an opentelemetry json file in `temp/telemetry`.

### Simulating Docker Network Setting

To simulate a certain network connection on all containers run the following (replace `wan.sh` with the desired network below):

```sh
# configure network on all running containers
./docker/scripts/runinallcontainers.sh ./scripts/wan.sh
# verify that ping latency has changed as desired
docker exec temp-p1-1 ping temp-p2-1
```

The following networks are simulated using `tc`:

| Network Config  | Script | Latency | Bandwidth |
| --- | --- | --- | --- |
| None  | `off.sh`  | none  | no limit  |
| WAN  | `wan.sh`  | 50 ms  | 100 Mbit/s  |
| 1 Gbps LAN  | `lan1.sh`  | 0.5 ms  | 1 Gbit/s  |
| 10 Gbps LAN  | `lan10.sh`  | 0.5 ms  | 10 Gbit/s  |

Note that ping RTT will be 2x the latency from the table, when the network config is set on all nodes.
Additionally, the docker image uses a non-root user,
for tc to work, root user must be used and this must be manually changed in the `local.dockerfile`.

## Profiling

To profile various protocols, see the `benches/` folder.

Following instructions are for Linux based systems. For individual benches one can run the following:

```sh
cargo bench --bench prep --features="testing extension_degree_8" -- --profile-time 60 triple_generation_z128/n=5_t=1_batch=1000
```

To see the flamegraph produced, fire up a terminal and open it with your favorite browser:

```sh
firefox target/criterion/triple_generation_z128/n=5_t=1_batch=1000/profile/flamegraph.svg
```

For MacOS-based users run the following:

```sh
cargo flamegraph --root --bench prep --features="testing extension_degree_8" -- triple_generation_z128/n=5_t=1_batch=1000
```

## Testing

Integration tests are located in the `tests` folder and require a `Redis` server to be running locally.
Make sure to install `Redis`and run `redis-server` in a separate terminal before running these tests.

<p align="center">
<!-- product name logo -->
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/threshold-fhe-dark.png">
  <source media="(prefers-color-scheme: light)" srcset="assets/threshold-fhe-light.png">
  <img width=600 alt="Zama TFHE-rs">
</picture>
</p>

<hr/>

<p align="center">
  <a href="https://eprint.iacr.org/2023/815"> 📃 White Paper</a> | <a href="https://zama.ai/community"> 💛 Community support</a> | <a href="https://github.com/zama-ai/awesome-zama"> 📚 FHE resources by Zama</a>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-BSD--3--Clause--Clear-%23ffb243?style=flat-square"></a>
  <a href="https://github.com/zama-ai/bounty-program"><img src="https://img.shields.io/badge/Contribute-Zama%20Bounty%20Program-%23ffd208?style=flat-square"></a>
</p>

## About

### What is it?

This repository provides threshold multi-party computation protocols
such as threshold key generation, threshold decryption
and so on for TFHE, BFV and BGV.
Our protocols are designed to be both secure and robust when a fraction
of the parties are malicious.

This repository is an early sneak peak of what we aim to be part of the submission
for the [NIST call for Multi-Party Threshold Cryptography](https://csrc.nist.gov/projects/threshold-cryptography).

### Main features

- Threshold key generation for the three FHE schemes
- Distributed decryption FHE with two techniques
  - Using noise flooding
  - Using bit decomposition
- Resharing of FHE key shares
- Distributed setup for CRS (common reference string) using in ZK proofs

### Additional resources

- Blog post *TODO link*
- The [Noah's ark](https://eprint.iacr.org/2023/815) paper contains the technical details of our protocols
- An [iniital preliminary version of our proposed NIST submission](https://github.com/zama-ai/threshold-fhe/blob/main/TechnicalDocumentation/CryptographicDocumentation.pdf), which contains the detailed specification

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
- `TechnicalDocumentation`
  - Contains our preliminary draft NIST main submission document. 

## How to use this repository

> [!Important]
> **threshold-fhe** is a snapshot of the work-in-progress code of what will eventually become a NIST submission. Use at your own risk!

The main way to use the repository is to run experiments and benchmarks on the various threshold protocols,
which we describe below.
It is also possible to use the the repository as a library (see the example in `examples/distributed_decryption.rs`),
but the public API is not document so use your own discretion.

## Benchmarks with real network

Benchmarking with a real network requires to set up said network inside a docker compose orchestrator. This prevents integrating this kind of benchmarks with `Criterion` inside `cargo bench` running command.

In order to bypass this limitation we have automated this `gRPC` benchmarks using `cargo-make` utility.

### Prerequisites for running benchmarks

- Install [Rust](https://www.rust-lang.org/), you need version 1.85.0 or higher.
- Install [cargo-make](https://github.com/sagiegurari/cargo-make?tab=readme-ov-file#installation).
- Install [docker](https://www.docker.com/) using your preferred method.

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

NOTE: Commands prefixed with `tfhe-` can be replaced by `bgv-`to execute experiment for `BGV` instead of `TFHE`

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

Once done, we can shut down the parties with:

```sh
cargo make --env EXPERIMENT_NAME=my_experiment stop-parties
```

We also provide one-liner benches, which can be run directly after the certificate generations.

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
./docker/scripts/runinallcontainers.sh ./docker/scripts/wan.sh
# verify that ping latency has changed as desired
docker exec tfhe-core-p1-1 ping tfhe-core--p2-1
```

The following networks are simulated using `tc`:

| Network Config  | Script | Latency | Bandwidth |
| --- | --- | --- | --- |
| None  | `off.sh`  | none  | no limit  |
| WAN  | `wan.sh`  | 50 ms  | 100 Mbit/s  |
| 1 Gbps LAN  | `lan1.sh`  | 0.5 ms  | 1 Gbit/s  |
| 10 Gbps LAN  | `lan10.sh`  | 0.5 ms  | 10 Gbit/s  |

Note that ping RTT will be 2x the latency from the table, when the network config is set on all nodes.

## Profiling

To profile various protocols, see the `benches/` folder.

Following instructions are for Linux based systems. For individual benches one can run the following:

```sh
cargo bench --bench prep -- --profile-time 60 triple_generation/n=5_t=1_batch=1000
```

To see the flamegraph produced, fire up a terminal and open it with your favorite browser:

```sh
firefox target/criterion/triple_generation/n=5_t=1_batch=1000/profile/flamegraph.svg
```

For MacOS based users run the following:

```sh
cargo flamegraph --root --bench prep -- triple_generation/n=5_t=1_batch=1000
```

## Testing

Integration tests are located in the `tests` folder and require a `Redis` server to be running locally.
Make sure to install `Redis`and run `redis-server` in a separate terminal before running these tests.

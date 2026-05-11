# Benchmarking the threshold protocols

<!--
Remove the core/experiments reference below when we copy this file to experiments
since core/experiments will be at the root.
-->
The threshold MPC protocols (threshold key generation, threshold decryption,
resharing, CRS ceremony, etc.) for TFHE, BFV and BGV are implemented across a
set of `core/threshold-*` crates:

- `core/threshold-execution` — the TFHE/BFV threshold protocols and the MPC
  endpoints used by `kms-server` in production.
- `core/threshold-bgv` — the (experimental) BGV/BFV algebra and protocols. This
  crate was previously called `threshold-experimental`.
- `core/threshold-networking`, `core/threshold-types` — shared networking and
  type primitives used by the crates above.

The protocols are designed to be both secure and robust when a fraction of the
parties are malicious.

The crate at `core/experiments` (previously `core/threshold`) is **not** a
production crate: it is the testing/benchmarking harness that wires the
`threshold-*` crates together, ships the MPC party and choreographer binaries
used to drive end-to-end runs, and contains the benchmark suite. This page
describes how to run those benchmarks in a wide range of configurations.
For the rest of this page, we assume the user is working under the
`core/experiments` directory.

## Directory overview

- `benches`
  - Code needed for benchmarking the threshold protocols, plus the
    non-threshold (single-machine) benchmarks under
    `benches/non-threshold/` for `tfhe-rs`, `tfhe-zk-pok` and `bgv`.
- `config`
  - Default and example configurations needed when benchmarking and testing the threshold protocols.
- `examples`
  - Some example code to get you started.
- `experiments`
  - Jinja templates (`docker-compose.yml.j2`, `conf.toml.j2`,
    `otel-collector-config.yaml`) used by `gen-experiment` to render the
    docker-compose file and the per-party config files for a run.
- `NIST_scripts`
  - One-shot scripts used to produce the NIST submission artifacts (build
    environment, threshold reproducible runs, non-threshold benches, KAT
    coverage, result parsers).
- `protos`
  - Protobuf files, for testing/benchmarking (choreographer ↔ party gRPC).
- `src`
  - Source code for the parties and the choreographers (both TFHE and BGV),
    plus the `gen-experiment` helper and the TLS cert generator.
- `test_scripts`
  - Bash scripts driving the choreographer for full benchmark/test runs.
- `tests`
  - Integration tests.
<!--
- `observability`
  - A small library for configuration and tracing functionality.
- `docs`
  - Documentation is stored here, notably it contains our preliminary draft NIST main submission document.
-->

## Benchmarks with real network

Benchmarking with a real network requires to set up said network inside a docker compose orchestrator. This prevents integrating this kind of benchmarks with `Criterion` inside `cargo bench` running command.

In order to bypass this limitation we have automated this `gRPC` benchmarks using `cargo-make` utility.

### Prerequisites for running benchmarks

- [Rust](https://www.rust-lang.org/), the workspace pins the toolchain in
  `rust-toolchain.toml` (currently `1.94.0`); the docker build uses the
  version baked into `docker/nist_testing.dockerfile`.
- [cargo-make](https://github.com/sagiegurari/cargo-make?tab=readme-ov-file#installation), using `cargo`.
- [docker](https://www.docker.com/), install it using your preferred method, from a package manager or using Docker Desktop.
- [protoc](https://protobuf.dev/installation/), install it using your preferred method, e.g., from a package manager.
- [redis](https://redis.io/docs/latest/get-started/): this is optional, only required for running the redis integration tests.
  Benchmarks that use redis inside a docker container do not require a local redis installation.

### Binaries: parties and choreographers

The `experiments` crate produces four threshold binaries (declared in
`core/experiments/Cargo.toml`):

| Binary        | Source                                       | Role                            |
| ------------- | -------------------------------------------- | ------------------------------- |
| `moby`        | `src/bin/threshold-tfhe/moby.rs`             | MPC party for TFHE              |
| `mobygo`      | `src/bin/threshold-tfhe/mobygo.rs`           | Choreographer (CLI) for TFHE    |
| `stairway`    | `src/bin/threshold-bgv/stairway.rs`          | MPC party for BGV               |
| `stairwayctl` | `src/bin/threshold-bgv/stairwayctl.rs`       | Choreographer (CLI) for BGV     |

A party is the MPC node that runs the threshold protocol; the choreographer is
the CLI client that initiates PRSS init, preprocessing, key generation,
decryption, CRS ceremony, resharing, and result retrieval against the cluster.

Two helper binaries also live next to them:

- `gen-experiment` (`src/bin/benches/gen-experiment.rs`) — renders the
  docker-compose `.yml` for the parties and the `.toml` for the
  choreographer from the Jinja templates under `experiments/`.
  See `cargo run --bin gen-experiment --features="templating" -- --help`.
- `threshold-gen-tls-certs` (`src/bin/threshold-gen-tls-certs.rs`) — generates
  the TLS material that the parties use for mTLS between themselves and with
  the choreographer.

### Feature flags

Unlike the old `threshold` crate, building `experiments` does not require
selecting between BGV and TFHE through a feature flag — both `moby` and
`stairway` are always produced. The relevant features now are:

- `extension_degree_3` … `extension_degree_8`: pick the algebraic extension
  degree used by the threshold computation. Default is `extension_degree_4`.
- `measure_memory`: enables the `peak_alloc` global allocator inside the
  parties, used by the memory benchmarks. Pair this with the
  `tfhe-docker-image-degree-N-mem` images when running memory benches.
- `templating`: only needed when running `gen-experiment` (and reused for
  `threshold-gen-tls-certs` so the binary doesn't get rebuilt with a
  different feature set).

### Docker images

The Makefile defines one image target per extension degree. The
`gen-experiment` binary then picks the right image when rendering the
docker-compose file: for `n` parties the chosen TFHE image is
`tfhe-core-degree-{floor(log2(n)) + 1}` (so n = 4 or 5 uses degree 3,
n = 6 or 7 uses degree 3, n = 8…15 uses degree 4, and so on). BGV always uses
the single `bgv-core` image.

Build a specific TFHE image with, for example:

```sh
cargo make tfhe-docker-image-degree-3
```

Build them all in one go:

```sh
cargo make tfhe-docker-images-all-degrees
```

Memory-instrumented variants (`tfhe-docker-image-degree-N-mem`) exist for each
degree and add the `measure_memory` feature.

The BGV image is built with:

```sh
cargo make bgv-docker-image
```

`BFV` is very similar to `BGV` as it is possible to convert between the two, so we do not provide a separate build.

### Choreographer

To interact with the MPC parties, use `mobygo` for `TFHE`, and `stairwayctl`
for `BGV`. Both are built from the `experiments` crate (see the table above).

In both cases, the choreographer allows you to:

- Initiate the PRSSs
- Create preprocessing (for Distributed Key Generation in both cases and Distributed Decryption for `TFHE`)
- Initiate Distributed Key Generation
- Initiate Distributed Decryption
- Initiate CRS Ceremony (for `TFHE` only)
- Initiate resharing of an existing DKG key (for `TFHE` only)
- Retrieve results for the above
- Check status of a task

For a list of the available commands, run:

```sh
./mobygo --help
```

And for information on a specific command, run:

```sh
./mobygo command --help
```

(Works also with `stairwayctl`.)

Both CLIs can be built directly with `cargo`:

```sh
cargo build --bin mobygo
cargo build --bin stairwayctl
```

### Pre-defined commands

With `cargo make` we have pre-defined targets to spin up experiments for both
`TFHE` and `BGV`. The Makefile now exposes a small, fixed set of party
clusters rather than a family of "fake DKG" / "real DKG" one-liners — the
choreographer commands that drive the actual benchmark are run from the
`test_scripts` shell scripts (see below).

First generate the TLS certificates, say for 5 MPC parties:

```sh
cargo make --env NUM_PARTIES=5 gen-test-certs
```

Then create the `.yml` (docker-compose) and `.toml` (choreographer) files for
the experiment:

```sh
cargo make --env NUM_PARTIES=5 --env THRESHOLD=1 --env MOBY_STRATEGY=secure --env EXPERIMENT_NAME=my_experiment tfhe-gen-experiment
```

`MOBY_STRATEGY` controls the behaviour of the first party. It is one of
`secure` (the default — all parties honest), `drop_all` (the first party drops
every message, modeling a crashed/silent party) or `malicious_broadcast` (the
first party deviates from the broadcast protocol). The other parties are always
`secure`. The same `cargo make` target exists for BGV (`bgv-gen-experiment`).

Finally, prepare the telemetry/session-stats files and start the parties.
Starting the parties is now done with `start-parties-healthy`, which waits for
each party's gRPC health check to pass before returning:

```sh
cargo make --env EXPERIMENT_NAME=my_experiment --env NUM_PARTIES=5 setup
cargo make --env EXPERIMENT_NAME=my_experiment start-parties-healthy
```

`setup` creates `temp/telemetry/export.json` and per-party
`temp/session_stats/session_stats_<i>.txt` files (with a `NEW_RUN:` marker
header) that the parties append timing/network metrics to during the run.
Those files are what `NIST_scripts/session-stats-parser.py` consumes after
the experiment.

For convenience, the Makefile bundles `setup → gen-test-certs →
*-gen-experiment → experiment-name → start-parties-healthy` into a few
ready-to-run cluster targets:

| Target                              | Parties | Threshold | Strategy              | Protocol |
| ----------------------------------- | ------- | --------- | --------------------- | -------- |
| `tfhe-bench-run-4p`                 | 4       | 1         | `secure`              | TFHE     |
| `tfhe-bench-run-5p`                 | 5       | 1         | `secure`              | TFHE     |
| `tfhe-bench-run-4p-malicious-drop`  | 4       | 1         | `drop_all`            | TFHE     |
| `tfhe-bench-run-4p-malicious-bcast` | 4       | 1         | `malicious_broadcast` | TFHE     |
| `bgv-bench-run`                     | 4       | 1         | n/a                   | BGV      |

Each of these only brings the cluster up — it does not run any benchmark
workload on it. Use the choreographer CLI (or one of the `test_scripts/`
scripts described below) to drive the cluster.

For example, after `cargo make tfhe-bench-run-4p` you can interact with the
cluster using the generated `.toml`:

```sh
./mobygo -c temp/tfhe-bench-run-4p.toml my-command
```

Once done, shut the cluster down. The Makefile no longer provides a generic
`stop-parties` target — use the `shutdown` task (which also archives logs and
telemetry under `temp/`):

```sh
cargo make --env EXPERIMENT_NAME=tfhe-bench-run-4p shutdown
```

Or, more aggressively, stop and remove every running docker container:

```sh
docker stop $(docker ps -a -q) && docker rm $(docker ps -a -q)
```

The reproducible test scripts use the latter form via a `cleanup_docker`
helper.

### Reproducible end-to-end runs

The `test_scripts/` folder contains the bash scripts that drive a cluster
through a full PRSS → preproc → DKG → (CRS, reshare) → decryption pipeline.
Two flavours are shipped:

- The legacy `tfhe_test_small_session.sh` / `tfhe_test_large_session.sh` and
  `bgv_test_script_{fake,real}_dkg.sh` scripts — kept around for ad-hoc use.
- The reproducible scripts that pin a fixed RNG seed and check generated keys
  / CRS against known SHA-256 hashes. These are the ones used by the NIST
  flow:

  - `tfhe_reproducible_common.sh` — shared logic, sourced by the wrappers.
  - `tfhe_reproducible_small_session.sh` (4 parties, t = 1, test parameters,
    `noise-flood-small` and `bit-dec-small` decryption modes).
  - `tfhe_reproducible_large_session.sh` (5 parties, t = 1, test parameters,
    `noise-flood-large` and `bit-dec-large` decryption modes).
  - `tfhe_reproducible_small_session_malicious.sh` (4 parties, t = 1, with a
    `malicious_broadcast` party 1, otherwise identical to the small session).
  - `bgv_reproducible.sh` (4 parties, t = 1, real BGV parameters).

Each reproducible script expects the choreographer `.toml` as its first
argument (and an optional `GEN` flag to print the new hashes when parameters
change), for example:

```sh
./test_scripts/tfhe_reproducible_small_session.sh temp/tfhe-bench-run-4p.toml
```

These reproducible scripts use the test parameter set `params-test-bk-sns`
(real parameters for BGV). To benchmark with real TFHE parameters, edit the
`PARAMS` variable inside the wrapper script.

### NIST scripts

`NIST_scripts/` packages the workflows used to produce the NIST submission
results:

- `build.sh` — provisions a clean Ubuntu 24.04 host (swap, docker, rust,
  `cargo-make`, `cargo-criterion`) and clones the repository.
- `threshold-test-params.sh` — one-shot driver that, in sequence:
  1. builds the `tfhe-core-degree-3` image,
  2. runs the small / large / small-malicious TFHE reproducible scripts
     (using `tfhe-bench-run-4p`, `tfhe-bench-run-5p` and
     `tfhe-bench-run-4p-malicious-bcast` respectively),
  3. builds the `bgv-core` image and runs the BGV reproducible script via
     `bgv-bench-run`,
  4. invokes `session-stats-parser.py` to turn the per-party
     `temp/session_stats/` files into the threshold result CSVs.

  Between each phase it tears the docker containers down via
  `cleanup_docker`, so each cluster starts from a clean slate.
- `non-threshold-tfhe-bench.sh` — runs the speed and memory non-threshold
  benchmarks for `tfhe-rs` and `bgv` (`cargo-criterion` for speed,
  `cargo bench --features=measure_memory` for memory), then parses the output
  with `non-threshold-parser.py`.
- `non-threshold-zk-pok-bench.sh` — same idea for the `tfhe-zk-pok`
  benchmarks (speed, memory, and the new size benchmark added by this
  branch).
- `non-threshold-kat.sh` — runs the `non-threshold-tfhe-kat` and
  `non-threshold-zk-pok-kat` binaries used for the NIST KAT coverage.
- `non-threshold-parser.py` / `session-stats-parser.py` — post-process the
  raw benchmark / session-stats output into the CSVs expected by the
  submission.

**NOTE**: The docker container also runs telemetry tools, therefore when
running experiments, all telemetry data are exported to
[jaeger](http://localhost:16686) as well as locally exported in an
opentelemetry json file in `temp/telemetry`.


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

Integration tests are located in the `tests` folder and require a `redis` server to be running locally.
Make sure to install `redis`and run `redis-server` in a separate terminal before running these tests.

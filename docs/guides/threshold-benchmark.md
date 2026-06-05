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
- `core/threshold-bgv` — the (experimental) BGV/BFV algebra and protocols.
- `core/threshold-networking`, `core/threshold-types` — shared networking and
  type primitives used by the crates above.

The protocols are designed to be both secure and robust when a fraction of the
parties are malicious.

The crate at `core/experiments` is **not** a production crate: it is the
testing/benchmarking harness that wires the `threshold-*` crates together, ships
the MPC party and choreographer binaries used to drive end-to-end runs, and
contains the benchmark suite. This page describes how to run those benchmarks in
a wide range of configurations.  For the rest of this page, we assume the user
is working under the `core/experiments` directory.

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

The relevant features are:

- `extension_degree_3` … `extension_degree_8`: pick the algebraic extension
  degree used by the threshold computation. Default is `extension_degree_4`.
- `measure_memory`: enables the `peak_alloc` global allocator inside the
  parties, used by the memory benchmarks.
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

`BFV` is very similar to `BGV` and it is possible to convert between the two, so we do not provide a separate build.

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
`TFHE` and `BGV`. The Makefile exposes a small, fixed set of party
clusters — the choreographer commands that drive the actual benchmark are run from the
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
`temp/session_stats/session_stats_<i>.txt` files that the parties append
timing/network metrics to during the run. The reproducible test scripts
(below) and `threshold-test-params.sh` group these flat files into per-run
folders (`temp/session_stats/<EXPERIMENT>_<TS>/`), each with its own
`BENCH_PARAMS.txt`; that's the layout `NIST_scripts/session-stats-parser.py`
consumes.

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

Once done, shut down the cluster. The Makefile provides a
`shutdown` task to stop all relevant containers
(and also archives logs and telemetry under `temp/`):

```sh
cargo make --env EXPERIMENT_NAME=tfhe-bench-run-4p shutdown
```

The reproducible test scripts use a `cleanup_docker` helper to shutdown the experiments.

### Reproducible end-to-end runs

The `test_scripts/` folder contains the bash scripts that drive a cluster
through a full PRSS (if applicable) → preproc → DKG → (CRS, reshare) → decryption pipeline.
It contains the reproducible scripts that pin a fixed RNG seed and check
generated keys / CRS against known SHA-256 hashes. These are the ones used by
the NIST flow:

  - `tfhe_reproducible_common.sh` — shared logic, sourced by the wrappers.
  - `tfhe_reproducible_small_session.sh` (4 parties, t = 1, test parameters,
    `noise-flood-small` and `bit-dec-small` decryption modes).
  - `tfhe_reproducible_large_session.sh` (5 parties, t = 1, test parameters,
    `noise-flood-large` and `bit-dec-large` decryption modes).
  - `tfhe_reproducible_small_session_malicious.sh` (4 parties, t = 1, with a
    `malicious_broadcast` party 1, otherwise identical to the small session).
  - `bgv_reproducible.sh` (4 parties, t = 1, real BGV parameters).
  - `crs_reproducible_common.sh` + `crs_reproducible_{small,large,small_malicious}_session.sh`
    — standalone CRS-generation sweep, mirroring the `tfhe_reproducible_*`
    common-plus-wrappers pattern. Each wrapper hardcodes the parameter
    sets to sweep (`CRS_PARAMS_LIST`) and the matching expected SHA-256
    hashes (`EXPECTED_CRS_HASHES`); edit both together when extending the
    sweep. The wrappers differ by cluster topology and malicious flag:
    `small` = 4 parties / honest, `large` = 5 parties / honest,
    `small_malicious` = 4 parties / party 1 misbehaves. Hashes are
    independent per wrapper because the topology can change the CRS-gen
    protocol path. The common body iterates `mobygo crs-gen` over every
    entry in one cluster lifecycle, bumping SID + seed by one per
    iteration — so the hash for a given params depends on its position
    in `CRS_PARAMS_LIST`. No PRSS init, no DKG, no Reshare, no DDEC —
    the run produces one labeled `CRS_GEN_<PARAMS_UPPER>` line per
    parameter set, which `session-stats-parser.py` turns into one row
    per param in `CRS_<suffix>.csv` (each row carrying its own `params`
    value in the metadata trailer). The `tfhe_reproducible_*` scripts no
    longer generate a CRS themselves — run the matching
    `crs_reproducible_*_session.sh` wrapper to collect CRS metrics for
    that topology.

Large and small here identifies the underlying protocols used for performing the various pre-processing phases.
When the number of parties is *small* (i.e. less than $20$ parties) we can rely on PRSS-based protocols and
which are secure for $t < n/3$, whereas when the number of parties is bigger
we have to switch to less communication-friendly protocols which are secure for $t < n/4$.


Each reproducible script expects the choreographer `.toml` as its first
argument (and an optional `GEN` flag to generate the encryptions), for example:

```sh
./test_scripts/tfhe_reproducible_small_session.sh temp/tfhe-bench-run-4p.toml GEN
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
  1. creates `temp/session_stats/campaign_<UTC_TS>/` for this campaign,
  2. builds the `tfhe-core-degree-3` image,
  3. runs the small / large / small-malicious TFHE reproducible scripts
     (using `tfhe-bench-run-4p`, `tfhe-bench-run-5p` and
     `tfhe-bench-run-4p-malicious-drop` respectively), routing each run's
     `BENCH_PARAMS.txt` + `session_stats_<i>.txt` into a per-run subfolder
     under the campaign folder via the `RUN_DEST` env var,
  4. builds the `bgv-core` image and runs the BGV reproducible script via
     `bgv-bench-run`,
  5. invokes `session-stats-parser.py` on the campaign folder; the parser
     reads each subfolder's `BENCH_PARAMS.txt` for run identity (protocol,
     session type, num parties, malicious flag, num ctxts, …) and emits the
     threshold result CSVs.

  Between each phase it tears the docker containers down via
  `cleanup_docker`, so each cluster starts from a clean slate.
- `non-threshold-tfhe-bench.sh` — runs the execution time and memory non-threshold
  benchmarks for `tfhe-rs` and `bgv` (`cargo-criterion` for execution time,
  `cargo bench --features=measure_memory` for memory), then parses the output
  with `non-threshold-parser.py`.
- `non-threshold-zk-pok-bench.sh` — same idea for the `tfhe-zk-pok`
  benchmarks (execution time, memory, and the size benchmark).
- `non-threshold-kat.sh` — runs the `non-threshold-tfhe-kat` and
  `non-threshold-zk-pok-kat` binaries used for the NIST KAT coverage.
- `non-threshold-parser.py` / `session-stats-parser.py` — post-process the
  raw benchmark / session-stats output into the CSVs expected by the
  submission.

#### What makes a run usable to `session-stats-parser.py`

A per-run subfolder is only accepted (aggregated and turned into CSV rows)
if every participating party's `session_stats_<i>.txt` carries exactly the
right number of metric lines for the run's declared schedule. Anything off
— a wrong count, a missing party file — and the run is skipped (with a
warning under `--warn`). The schedule is built from `BENCH_PARAMS.txt`'s
`PROTOCOL` + `SESSION_TYPE` + `HAS_PRSS_INIT` / `HAS_DKG` / `HAS_CRS` /
`HAS_RESHARE` flags + the modes listed in `DDEC_MODES`, in the order the
test scripts call `mobygo` / `stairwayctl`. `HAS_DKG` defaults to `1` for
backward compatibility — only the standalone `crs_reproducible.sh` script
sets it to `0`.

For TFHE runs (`PROTOCOL=tfhe`):

1. `PRSS_INIT_Z64` — only if `HAS_PRSS_INIT=1` (small sessions only)
2. `PRSS_INIT_Z128` — only if `HAS_PRSS_INIT=1` (small sessions only)
3. `DKG_PREPROC` — only if `HAS_DKG=1`
4. `DKG` — only if `HAS_DKG=1`
5. CRS gen — only if `HAS_CRS=1`. One line per entry of `CRS_PARAMS`
   labeled `CRS_GEN_<PARAMS_UPPER>` (used by the sweep script). If
   `CRS_PARAMS` is empty, a single plain `CRS_GEN` line instead (kept
   for backward compatibility with archives from before the CRS gen
   was extracted out of `tfhe_reproducible_*`).
6. `RESHARE_PREPROC` — only if `HAS_RESHARE=1`
7. `RESHARE` — only if `HAS_RESHARE=1`
8. Then, for each mode in `DDEC_MODES` (typically `noise-flood-X` then
   `bit-dec-X`), for each TFHE type in the run's `CTXT_TYPES` list
   (e.g. `bool u4 u8 u16 u32 u64`):
   - `<MODE>_<TYPE>_PREPROC`
   - `<MODE>_<TYPE>_DDEC`

That gives **30 lines** for a small-session `tfhe_reproducible_*` run
with the default 6-entry `CTXT_TYPES` (2 PRSS + 2 DKG + 2 reshare +
2×6×2 DDEC sweep — no CRS, which moved out), **28 lines** for the
large-session variant (no PRSS init), and **N lines** for a
`crs_reproducible.sh` sweep run with `CRS_PARAMS` listing N parameter
sets (no PRSS, no DKG, no Reshare, no DDEC). `CTXT_TYPES` is the
single source of truth: editing the bench script's `CTXT_TYPES_LIST`
bash array changes both the DDEC loop and the parser's expected
schedule (via the `CTXT_TYPES=` line written into `BENCH_PARAMS.txt`),
so the two stay in lock-step automatically. The parser raises if any
entry isn't a known TFHE type. Older `BENCH_PARAMS.txt` files without
a `CTXT_TYPES` line fall back to the default 6-entry sweep.

For BGV runs (`PROTOCOL=bgv`):

1. `PRSS_INIT_LEVEL_ONE` — only if `HAS_PRSS_INIT=1`
2. `PRSS_INIT_LEVEL_KSW` — only if `HAS_PRSS_INIT=1`
3. `DKG_PREPROC` — only if `HAS_DKG=1`
4. `DKG` — only if `HAS_DKG=1`
5. One `DDEC_PARALLEL_<N>` line per entry of `BGV_DDEC_PARALLEL` (the
   field is a space-separated list of positive ints, e.g. `1 2 4 8 16
   32`). Required for `PROTOCOL=bgv`. Each entry becomes one row in
   `BGV_TDec_*.csv`.

That gives **10 lines** for a default BGV run (2 PRSS + 2 DKG + 6
parallelism factors) when both kms reproducible and bench_nist set
`BGV_DDEC_PARALLEL=1 2 4 8 16 32`. Editing the bash script's
`BGV_DDEC_PARALLEL_LIST` array changes both the BGV DDEC loop and the
parser's expected schedule.

Malicious runs (`MALICIOUS=1`, currently only
`tfhe-bench-run-4p-malicious-drop`): the parser drops the party with the
fewest metric lines (the malicious party truncates early) and averages
over the remaining `NUM_PARTIES - 1` files, which must each carry the
full expected schedule.

#### Output-column semantics

The CSV columns are not raw cross-party averages — the parser applies a few
transformations driven by the per-run `BENCH_PARAMS.txt`. Reading the CSVs
without knowing these will yield wrong-looking numbers.

1. **DKG offline cells are scaled by `100 / PERCENTAGE_OFFLINE`.** When the
   DKG preproc was run on a fraction of the offline material to keep
   wall-clock manageable, `session_stats` only reflects that fraction. The
   four offline metric cells of every `DKG_PREPROC` row in
   `TFHE_KeyGen_*.csv` / `BGV_KeyGen_*.csv`
   (`offline_avg_latency_ms`, `offline_rounds`,
   `offline_avg_bytes_sent_per_party`,
   `offline_avg_bytes_received_per_party`) are therefore multiplied by
   `100 / PERCENTAGE_OFFLINE` to project to a full offline phase. Memory
   cells are NOT scaled (peak allocator usage doesn't grow with the offline
   workload count). Scaling only fires for `DKG_PREPROC` — `RESHARE_PREPROC`
   and the DDEC preproc labels always run at 100% offline.

2. **TDec throughput is in LWE-ciphertexts per second.**
   `offline_throughput_per_sec` and `online_throughput_per_sec` in
   `TFHE_TDecOne_*.csv` / `TFHE_TDecTwo_*.csv` are computed as
   `num_blocks * 1000 / per_radix_latency_ms`, where `num_blocks` is the
   number of LWE ciphertexts a single radix message decomposes into. That
   number is parameter-set dependent (see the parser's
   `PARAMS_TO_BITS_PER_BLOCK` table — mirrors
   `core/threshold-execution/src/tfhe_internals/parameters.rs::to_param`):
   - 1 bit per block (`MessageModulus = 2`): the `nist-params-p8-*` family
     (4 variants). A u64 message is 64 LWE blocks.
   - 2 bits per block (`MessageModulus = 4`): everything else
     (`nist-params-p32-*`, `bc-params-*`, `bc-params-nigel-*`,
     `params-test-bk-sns`). A u64 message is 32 LWE blocks.
   - `bool` is always exactly 1 LWE block regardless of params.

   Unknown `PARAMS` values cause the parser to raise `ValueError` rather
   than guess — add the new parameter set to `PARAMS_TO_BITS_PER_BLOCK` and
   store `log2(message_modulus)` for it.

3. **`ptxt_type` + `num_ctxt` together identify each TDec row.**
   `TFHE_TDecOne_*.csv` / `TFHE_TDecTwo_*.csv` carry a `ptxt_type` column
   (e.g. `bool`, `u4`, `u8`, …) sourced from the run's `CTXT_TYPES` line
   in `BENCH_PARAMS.txt`. The adjacent `num_ctxt` column holds the LWE
   ciphertext count derived from `(bit_width, PARAMS)` — not the message
   bit-width. Combined with item 2 above, `throughput == num_ctxt * 1000
   / avg_latency_ms` is a built-in self-check.

4. **BGV metadata trailers are non-empty.** BGV runs write
   `SESSION_TYPE=small` and `PARAMS=default` into `BENCH_PARAMS.txt` so the
   trailing metadata columns (`session_type`, `params`) on `BGV_KeyGen` and
   `BGV_TDec` rows are populated. BGV has no radix decomposition so there's nothing to scale.

**NOTE**: The docker container also runs telemetry tools, therefore when
running experiments, all telemetry data are exported to
[jaeger](http://localhost:16686) as well as locally exported in an
opentelemetry json file in `temp/telemetry`.


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

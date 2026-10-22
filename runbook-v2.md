# Controlled DKG preprocessing experiments

This procedure separates the October regression from the low average CPU utilization.
The primary result is generated bits per second. Triple throughput is a secondary result.
CPU usage, phase durations, and transport metrics explain changes in throughput.

The original worktree remains at `../kms-ddec-bench` with its uncommitted changes intact.
This worktree uses `codex/fix/773/reliable-dkg-bench`.
The local `codex/bench/773/dkg-baseline` branch identifies the instrumented decoder baseline.
The treatment branch reapplies these commits in order:

1. `372a7f9b612bfd5f5bb4c61d775c1b76cfc19a4c`
2. `638d41d9b436470d15ff6fa013585636e3fb72ce`

The treatment also has a benchmark switch, `MPC_OPTIMISTIC_RECONSTRUCTION`.
Its default is `1`. Setting it to `0` uses the decoder through the same instrumented batch code.
Use this same-binary comparison first. It controls compilation, placement, and instrumentation differences.
The decoder-baseline image provides a separate cross-check; it is not identical to the runtime-disabled treatment.

## 1. Validate the tooling before deployment

From the repository root:

```bash
bash ci/perf-testing/check-bench-tooling.sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --all-features -- -D warnings
cargo test -p observability -p thread-handles --lib
cargo test -p threshold-networking connection_selection_rotates_independently_for_twelve_peers
cargo test -p threshold-networking benchmark_goodput
cargo test -p kms bandwidth_latency_requires_successful_attempts
cargo test -p threshold-algebra optimistic
cargo test -p threshold-execution --features testing reconstruct_batch
MPC_OPTIMISTIC_RECONSTRUCTION=0 cargo test -p threshold-execution --features testing reconstruct_batch
```

Run the relevant honest, corrupt-share, and dropout protocol tests before accepting an optimization.
In particular, PRSS pipelining and hashed echo tallying remain separate experiments:

```bash
MPC_DKG_PRSS_PIPELINE=1 cargo test -p threshold-execution --features testing offline_small
MPC_BCAST_ECHO_HASH_KEYS=1 cargo test -p threshold-execution --features testing broadcast
MPC_SERIALIZE_ON_RAYON=1 cargo test -p threshold-execution --features testing broadcast
```

Use bounded build parallelism on machines with restricted process limits.
For example, `CARGO_BUILD_JOBS=2` limits concurrent compiler processes.
Never use local test CPU limits as the cluster benchmark configuration.
The validation report at the end of this file distinguishes checks executed here from cluster work.

## 2. Prepare one fixed cluster

Use one dedicated thirteen-party namespace and one reserved set of nodes.
Keep the instance type, party-to-node assignment, availability zones, enclave resources, and parent resources fixed.
Keep the client configuration, key parameters, session count, and batch sizes fixed.
Keep build profile, compiler, CPU target, tunnel image, and base-image digests fixed for an A/B pair.

Choose the placement through the deployment configuration before the first run.
Exclude unrelated workloads and automatic node replacement during the experiment window.
Do not run benchmarks concurrently in another namespace that shares the same resources.
The preview cleanup at 00:00 UTC can interrupt a run; reserve enough time before that boundary.

Build and deploy the treatment branch through the existing enclave CI workflow.
Record the deployed image digests and EIF identity from the build artifacts.
Keep the enclave PCR allowlist consistent with the selected EIF through the supported deployment workflow.
Do not substitute only the parent container image while retaining an older EIF.

The scripts require `kubectl`, `jq`, Python 3.8 or later, and Bash 4 or later on the cluster-connected machine.
Use the same client image throughout a comparison.
No cluster deployment occurs as part of the local test command.

The runner applies `TOKIO=10`, `RAYON=60`, and `PREPROC=90` unless the invocation overrides them.
It replaces the entire tuning table and restarts every party on every run.
It verifies every pod's readiness, mounted configuration, process startup values, and actual image identity.
Old images without the startup marker cannot use this strict runner; treat historical captures as exploratory evidence.

## 3. Establish repeatability

The default run lasts 1800 seconds, including a 180-second warmup.
The analyzer measures throughput and CPU over the remaining common interval.
Each party uses its first and last successful scrapes inside that interval; their exact bounds appear in the summary.
Use a longer interval if it contains too few complete production waves.
All thirteen parties must provide metrics before the workload starts.

```bash
export NS=kms-ci-titouantanguy-773
export RUNS_DIR="$HOME/Code/ai/DkgDdecBench/runs-v2"
BASE="MPC_DKG_PHASE_LOG_EVERY=100,MPC_DKG_TRACKER_LOG_PERCENTAGE=1"

TAG=baseline-off-1 TOKIO=10 RAYON=60 PREPROC=90 \
  TUNING_ENV="$BASE,MPC_OPTIMISTIC_RECONSTRUCTION=0" \
  bash ci/perf-testing/manual-run-experiment.sh

export REFERENCE_FLEET="$RUNS_DIR/baseline-off-1/start/fleet.json"
TAG=baseline-off-2 TOKIO=10 RAYON=60 PREPROC=90 \
  TUNING_ENV="$BASE,MPC_OPTIMISTIC_RECONSTRUCTION=0" \
  bash ci/perf-testing/manual-run-experiment.sh
```

`REFERENCE_FLEET` rejects changed placement, container images, runtime resource specifications, and enclave configuration.
The runner also checks that the fleet stays unchanged during each measurement.
The post-rollout facts record configuration, resources, images, and placement for manual comparison.
Investigate unstable baselines before running the optimization matrix.
Two repeats are a screening check; small claimed gains require additional paired repeats.

## 4. Measure optimistic-open with the same image

Run an off/on/on/off sequence on the fixed deployment:

```bash
PREFIX=optimistic-abba bash ci/perf-testing/manual-run-paired.sh
python3 ci/perf-testing/analyse_run.py compare "$RUNS_DIR"
```

Each row restores the full baseline configuration.
Only `MPC_OPTIMISTIC_RECONSTRUCTION` changes.
The first row supplies the reference placement when `REFERENCE_FLEET` is unset.
Repeat the block in reversed order if the difference is small or the baseline drifts.

Compare these results:

- Generated bits/s over the same measurement interval, including each party and the slowest party.
- Generated triples/s and progress totals, so different workloads remain visible.
- Process CPU-seconds per generated bit, plus Tokio/Rayon and relay CPU usage.
- Reconstruction outcomes and elapsed phase times.
- RPC latency distributions, queue depth, and network throughput during the same interval.

The process CPU-seconds/bit ratio includes concurrent triple generation and other process work.
It is a workload efficiency measure, not the isolated CPU cost of a bit.
The generated-item counters count completed producer output, not durable preprocessing material.
Counts can include batches still queued or discarded at cancellation or final rounding.
Check successful preprocessing completion separately for the winning configuration.

An improvement requires higher bit throughput across repeated pairs without protocol failures.
Lower CPU usage alone is neither a win nor a regression.
An optimistic hit rate proves path selection; it does not prove a throughput benefit.

## 5. Locate the limiting stage

Phase counters measure elapsed session time. They include scheduler waits and local processing.
Their sum across concurrent sessions is not a wall-clock critical path.
Detail timers are nested within phase timers; do not add both sets together.

| Observation | Follow-up |
|---|---|
| High Rayon queue delay with busy Rayon workers | Vary Rayon capacity while holding Tokio fixed. |
| High echo serialization or tally time | Test serialization offload and hashed tally separately. |
| Long RPCs with short local processing | Inspect each peer, flow-control state, reconnects, and relay threads. |
| Low aggregate CPU with one busy thread | Inspect that thread or connection task; aggregate CPU does not exclude a CPU bottleneck. |
| High retransmissions or interface drops | Check both tunnel endpoints and parent ENA allowance counters; localize the loss. |
| Logger near its CPU limit | Measure cgroup throttled time and log-write pressure before changing the limit. |
| Future-message drops | Inspect reason and round distance; the event is not unique to the sixteen-round limit. |

Tokio thread-name accounting can include blocking threads.
Rayon execution time includes nested parallel work and scheduling within a job; it is not CPU time.
The relay has worker threads and queues; their counts are different quantities.
The HTTP/2 estimator persists across requests on a connection. It does not restart for each echo.
PRSS prefetch can move work outside the `prss` phase timer; require a throughput improvement as evidence.

## 6. Run one-variable experiments

Keep the same duration, warmup, placement, and optimistic setting for every comparison.
Use the baseline command with an explicit complete configuration for each row.

| Experiment | Change from baseline |
|---|---|
| Tokio capacity | Increase `TOKIO`; retain the baseline `RAYON`. |
| Rayon pressure | Change `RAYON`; retain the baseline `TOKIO`. |
| Peer connections | Set `MPC_C2C_CONNECTIONS_PER_PEER=4`; verify active connections and their traffic. |
| HTTP/2 windows | Set stream/connection windows; retain the default frame size. Static windows disable adaptive mode. |
| HTTP/2 frames | Change `MPC_C2C_H2_MAX_FRAME_BYTES` in a separate run. |
| Serialization | Set `MPC_SERIALIZE_ON_RAYON=1` alone. |
| Echo tally | Set `MPC_BCAST_ECHO_HASH_KEYS=1` alone. |
| PRSS overlap | Set `MPC_DKG_PRSS_PIPELINE=1` on every party. |

For the window experiment, start with an 8 MiB stream window and a 32 MiB connection window.
Measure memory as well as throughput when increasing windows or concurrent sessions.
Test combinations only after individual effects are repeatable.
Session and batch-size sweeps come later, with the output mix and workload held constant.

## 7. Measure transport separately

Run the application bandwidth benchmark only after preprocessing stops:

```bash
RESTART_FIRST=1 bash ci/perf-testing/manual-bandwidth-bench.sh
```

One session already sends to all twelve peers from every party.
Twelve sessions mean twelve concurrent RPC streams per peer, usually on one connection.
These shapes measure application goodput under all-to-all load. They do not measure isolated TCP RTT.

Use only complete aggregate records with acknowledged payload bytes and zero errors/timeouts.
The aggregate interval covers session setup through final completion on each host.
It is conservative and has no shared start barrier across hosts.
The benchmark shares retained payload buffers, but each protobuf request still copies its payload.
Keep that cost separate from conclusions about the MPC send path.

Compare the same application workload inside and outside enclaves with matched CPU and node resources.
Use a separate two-party TCP test, TCP over the tunnel, and raw vsock to isolate further layers when available.
The current benchmark has no isolated-pair mode; do not infer one by passing fewer client endpoints.
Faster node-to-node iperf alone does not prove that vsock is the bottleneck.
Timeouts alone do not prove packet loss, and zero drops do not exclude a vsock credit stall.

## 8. Investigate historical drift only after the controls pass

Keep the environment fixed while changing one build or code factor.
Use recorded artifact digests instead of assuming that rebuilding an old SHA recreates its old image.
Record compiler, Cargo.lock, build profile, CPU target, golden image, guest kernel, and tunnel identity.
Treat an old full stack as a reproduction check, not a causal attribution to the environment.
Normalize progress by completed items and preserve the workload totals.

The uncontaminated early captures show about 2095 triples/s in August and 1455 triples/s in October.
The later October bandwidth test overlaps preprocessing, so exclude that interval from regression estimates.
If current matched controls still show a regression, bisect code under the fixed build and deployment configuration.

## 9. Validate the winner and retain evidence

Run full preprocessing with the selected configuration:

```bash
TAG=winner-complete REQUIRE_COMPLETION=1 DURATION_SECONDS=0 MAX_MINUTES=1440 \
  TOKIO=10 RAYON=60 PREPROC=90 TUNING_ENV="$BASE,MPC_OPTIMISTIC_RECONSTRUCTION=1" \
  bash ci/perf-testing/manual-run-experiment.sh
```

For a full-completion claim, require a successful client result as well as completed production counters.
A producer reaching 100% does not by itself prove that final aggregation and storage succeeded.
Retain the request ID and client result for correctness verification.

Each run keeps a manifest, start/end fleet inventories, logs, raw metrics, and per-run summaries.
Measurement closes before cleanup restarts the cores.
An interrupted run, counter reset, failed collector, or changed fleet is invalid for controlled comparison.
Historical captures without measurement boundaries remain exploratory.
`compare` reads per-run summaries; it does not depend on concurrent writers updating one shared CSV.

## Validation status

Local checks and their results are recorded in the implementation handoff.
This workspace has no cluster connection or Docker daemon.
The enclave deployment, repeatability runs, and end-to-end preprocessing validation remain cluster steps.

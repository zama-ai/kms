# DKG-preprocessing diagnostics and experimental fixes

Historical instrumentation notes. The controlled procedure is now [runbook-v2.md](../../runbook-v2.md).
It supersedes the experiment matrix and causal claims below.
Instrumentation overhead must be measured, and elapsed phase time is not CPU time.
Use identical instrumentation in both arms of a comparison.

Everything described here lives on the bench branch (`titouan/bench/ddec-and-decrypt`) and is
off by default: an unset environment gives the behaviour of `main`, plus a few extra Prometheus
series that cost nothing measurable. It implements the plan of
`~/Code/ai/proposal-dkg-preproc-bottleneck.md` (§2 measure, §3 fix); the analysis behind it is
`~/Code/ai/DkgDdecBench/ANALYSIS-nSmall-preproc-2026-09-08.md`.

## 1. What is instrumented

All series are exported on the usual `:9646` endpoint with the `kms_` prefix and the same
const-labels as the existing metrics (`observability/src/diag_metrics.rs`), so
`manual-metrics-watch.sh` reads them like the rest.

| Series | Labels | What it answers |
|---|---|---|
| `kms_dkg_phase_duration_microseconds_total`, `kms_dkg_phase_observations_total` | `phase` | How a preprocessing batch splits into `prss`, `bcast_send`, `bcast_recv`, `bcast_echo_wait`, `bcast_votes`, `recons_d`, `mult_open`, `open_v`, `solve`, `aggregator_send` (+ the `triple_batch` / `bit_batch` envelopes). `rate()` of the duration counter is "session-seconds per wall-second" in that phase; with 85 sessions the phases sum to ≈ 85, so each one's share of the wave is read directly. |
| `kms_optimistic_reconstruct_total` | `site` (`d_values`, `robust_open`), `outcome` (`hit`, `declined`, `inconsistent`, `failed`) | Whether the optimistic reconstruction is taken in production. `declined` = the eligibility check refused (share count / owner order), `inconsistent` = a real error went to the decoder. |
| `kms_c2c_send_rpc_duration_ms` (histogram) | `size_bucket` (`le_4k` … `gt_16m`) | Core-to-core `send_value` RPC time from dequeue to the peer's ack, by message size: the per-message RTT of 8 MB echoes vs 32-byte votes. |
| `kms_c2c_sender_queued_messages` (gauge) | — | Messages waiting in the per-(session, peer) sender queues: >0 for long means the sender tasks, not the protocol, are behind. |
| `kms_thread_pool_cpu_usage` (gauge), `kms_thread_pool_cpu_seconds_total` | `pool` (`tokio`, `rayon`, `other`) | CPU of this process' threads by pool (100 = one core). `tokio` near `num_tokio_threads × 100` during the network half = the transport is CPU-bound on the tokio workers. Rayon threads are now named `mpc-rayon-<i>`, tokio workers `tokio-rt-worker`. |
| `kms_named_process_cpu_usage` (gauge) | `process` | CPU of other processes in the same VM — inside an enclave, the enclave-side `vsocktun` relay, which was never measured before. List from `KMS_SYS_METRICS_PROCESSES` (default `vsocktun,socat,dnsproxy`). |
| `kms_net_iface_dropped_total` | `iface`, `dir` | `/proc/net/dev` drop counters, read from inside the enclave (the TUN's drops are the tunnel losing packets). |
| `kms_tcp_segs_total` | `kind` (`in`, `out`, `retrans`) | `/proc/net/snmp` TCP segment counters from inside the enclave: retransmissions during the network half mean the tunnel ceiling is a loss ceiling. |

Also:

- `MPC_DKG_PHASE_LOG_EVERY=N` logs, once every N batches process-wide, the phase split of the
  window since the previous log (`producers/common.rs`), for runs whose only artefact is the
  core log. `MPC_DKG_TRACKER_LOG_PERCENTAGE=1` (pre-existing) makes the progress tracker log
  every 1 %.
- The bandwidth benchmark logs session creation and every per-peer completion at info
  (`bandwidth_bench.rs`), so a run cancelled by the tool's deadline still leaves its numbers in
  the core log. Its hard caps are unchanged: the tool's deadline is
  `duration + HEALTH_CHECK__REQUEST_TIMEOUT_SECS`, the node's is `timeout_secs + 300` s, each
  per-peer send is bounded by `network_timeout` (300 s in the chart).

## 2. The knobs

All are environment variables of the `kms-server` process, read once on first use. Defaults
reproduce the behaviour of `main`.

| Variable | Default | Effect | Where |
|---|---|---|---|
| `MPC_DKG_PRSS_PIPELINE` | `0` | Draw the PRSS/PRZS values of batch k+1 on rayon while batch k waits on its broadcast and opens; the wave becomes max(compute, network) instead of their sum for the ~2 core-s of PRF work per batch. Counters are reserved at submission in the same order on every party, so the values are identical to a direct draw. | `small_execution/offline.rs` (`PrssPrefetch`), `prss.rs` (`*_deferred`) |
| `MPC_BCAST_ECHO_HASH_KEYS` | `0` | Tally the echo round by `(sender, BcastHash)` instead of by the full `BroadcastValue`: the SipHash/compare of 13 × 640 KB vectors per peer leaves the tokio worker, each value is hashed once on rayon. Same votes, same output. | `communication/broadcast.rs` (`receive_echos_from_all_hashed`) |
| `MPC_SERIALIZE_ON_RAYON` | `0` | Serialise the round-1 and echo messages of the broadcast on rayon rather than inline on the protocol task. | `communication/broadcast.rs` (`send_network_value_to_all`), `p2p.rs` (`send_bytes_to_all`) |
| `MPC_C2C_CONNECTIONS_PER_PEER` | `1` | Pool of N HTTP/2 connections (TCP + TLS each) per peer; sessions are spread over them round-robin, so a peer's bytes are no longer serialised through one connection task and one TCP flow. | `threshold-networking/src/tuning.rs`, `sending_service/service.rs` |
| `MPC_C2C_H2_STREAM_WINDOW_BYTES`, `MPC_C2C_H2_CONN_WINDOW_BYTES` | unset | Static HTTP/2 windows on both the client channels and the core-to-core server. Setting either **turns the adaptive window off automatically** — hyper's adaptive mode resets both windows to 65 535 bytes, which is why the September `NETWORKOPT` attempt never took effect. Try 8 MiB / 32 MiB. | same |
| `MPC_C2C_H2_ADAPTIVE_WINDOW` | `1` | The adaptive (BDP-driven) window, as today. `0` with no static windows gives hyper's static defaults (1 MiB server / 2–5 MiB client). | same |
| `MPC_C2C_H2_MAX_FRAME_BYTES` | unset | `SETTINGS_MAX_FRAME_SIZE` (16 KiB default). Try 1048576. | same |
| `MPC_C2C_H2_MAX_CONCURRENT_STREAMS` | unset | Streams the core-to-core server lets each peer connection open (hyper default 200; 90 sessions + a bench + retries can touch it). | same |
| `MPC_DKG_PHASE_LOG_EVERY` | `0` | See §1. | `constants.rs` |
| `KMS_SYS_METRICS_PROCESSES` | `vsocktun,socat,dnsproxy` | See §1. | `observability/src/sys_metrics.rs` |
| `MPC_DKG_CHANNEL_BUFFER_SIZE`, `MPC_DKG_BATCH_SIZE_*`, `MPC_*_PAR_MIN_CHUNK` | pre-existing | Unchanged; listed for completeness (`constants.rs`). | |

`MPC_DKG_PRSS_PIPELINE` changes the order in which the PRSS/PRZS counters are consumed, so it
must be identical on **all** parties (the chart value and `manual-set-mpc-knobs.sh` apply it to
the whole StatefulSet; never set it on a subset of pods, the d-value reconstructions would fail
and parties would land in each other's corrupt sets). It also draws one batch more than needed per
session: the last prefetch is dropped at the end of production (~2 core-s per session, logged at
debug). Every other knob is local to a party — same wire format, same values — and may differ
between parties, e.g. to A/B the transport settings on a single party.

Chart knobs that are config-file values rather than env (`kmsCore.thresholdMode.*`):
`tokioWorkerThreads` (10 in the chart; the perf values use 24), `rayonNumThreads`,
`numSessionsPreproc`. Both kinds can be changed on a live namespace with
`manual-set-mpc-knobs.sh` (§3).

## 3. Getting a knob into the process

Inside a Nitro enclave the `kms-server` process does **not** inherit the pod's environment, so
the chart carries the variables in the config file instead: `kmsCore.tuning.env` renders a
`[tuning.env]` table into `kms-server.toml`, and `kms-server` exports it into its own environment
before the tokio runtime starts (`conf::TuningConfig::apply`, `bin/kms-server.rs`). This works
in and out of the enclave; `kmsCore.extraEnv` (a plain env list on the container) is for
non-enclave convenience only.

Three ways, all ending in a kms-server restart (the knobs are read once):

```bash
# 1. In values (new deploy / helm upgrade):
kmsCore:
  tuning:
    env:
      MPC_DKG_PHASE_LOG_EVERY: "100"
      MPC_C2C_CONNECTIONS_PER_PEER: "4"

# 2. On a live namespace, without helm (patches the ConfigMaps + rolling restart; keeps PVCs,
#    keys and releases). Replaces the whole table; TUNING_ENV="" removes it:
NS=$NS TUNING_ENV="MPC_DKG_PHASE_LOG_EVERY=100,MPC_DKG_PRSS_PIPELINE=1" \
  bash ci/perf-testing/manual-set-mpc-knobs.sh
#    combinable with the config-file knobs in the same call:
NS=$NS TOKIO=24 RAYON=28 TUNING_ENV="MPC_C2C_CONNECTIONS_PER_PEER=4" bash ci/perf-testing/manual-set-mpc-knobs.sh

# 3. Non-enclave only: kubectl set env statefulset -n $NS -l app=kms-core MPC_X=... (rolls pods)
```

The rendered table is visible in the pod's start-up output (`### BEGIN - kms-server.toml ###`)
and each exported variable is logged (`tuning: exporting KEY=VALUE`) before the runtime starts —
for the enclave variant it comes out of the logger sidecar, since the enclave pipes stdout and
stderr through it:

```bash
kubectl logs -n $NS kms-core-1-core-1 -c kms-core-enclave-logger | grep 'tuning: exporting'   # enclave
kubectl logs -n $NS kms-core-1-core-1 -c kms-core | grep 'tuning: exporting'                  # plain threshold
```

The transport knobs log their resolved values too (`Core-to-core HTTP/2 settings: …`,
`Using tuning value … from env var …`) the first time a connection is built.

## 4. Run protocol

`Runbook.md` (repository root) is the ordered procedure (hypotheses, bisect, baseline, matrix) and `manual-run-experiment.sh`
does one run end to end — knobs, restart, watchers, driver, stop rule, collection and
`analyse_run.py summarize` — so the steps below are what that script automates, kept here for
running the pieces by hand:

1. `manual-set-mpc-knobs.sh` with the configuration of the run (this restarts the cores; any
   in-flight DKG is lost). Always include `MPC_DKG_PHASE_LOG_EVERY=100` and
   `MPC_DKG_TRACKER_LOG_PERCENTAGE=1`.
2. From the laptop, in two terminals:
   ```bash
   NAMESPACE=$NS PARTIES="1 2" INTERVAL=10 LOG_FILE=~/Code/ai/DkgDdecBench/metrics-$TAG.log \
     bash ci/perf-testing/manual-metrics-watch.sh
   NS=$NS bash ci/perf-testing/manual-capture-core-logs.sh      # 13 core logs
   ```
3. In the client pod, preprocessing only, no decrypt trickle:
   ```bash
   kubectl cp ci/perf-testing/manual-dkg-under-load.sh $NS/kms-core-client-0:/tmp/driver.sh
   kubectl exec -it -n $NS kms-core-client-0 -- bash -c "PREPROC_ONLY=1 RUN=$TAG nohup bash /tmp/driver.sh > /tmp/$TAG.log 2>&1 &"
   ```
4. Stop at a fixed point — TripleGen 25 % is enough to compare (20–30 min); let BitGen reach
   5 % when the bit path matters (the fixes of §2 mostly act on it).
5. Keep three numbers per run: TripleGen `%/min` from the tracker, the phase split (watch
   script or the `DKG phase timers` log lines), and the per-peer 8 MB RPC average.

Both envs run the same images: the preview `docker-build` of PR #773 produces the core image
and, for `thresholdWithEnclave`, the EIF of the same build, so every Rust change here needs a
push to the PR (and therefore a redeploy of the namespace). Chart-only or knob-only changes do
not.

### Bisecting the 1.5× regression first

Same namespace, same day, three images, PREPROC_ONLY to TripleGen 25 %:

| Image | How | Tells |
|---|---|---|
| `main` + bench charts (no optimistic open) | push the bench branch without the two cherry-picked commits (`git revert` them on a throwaway branch, or `git checkout 5ec3e4a9c -- core/` style reset of the three Rust files), label the PR | whether the drift is on `main` |
| `main` + bench + optimistic open | the branch as is | the PR's own cost/benefit on top |
| the same with `TARGET_CPU=` (generic) | `docker/kms-binaries/Dockerfile` arg, one-line change | whether `x86-64-v3` codegen hurts the hot loops |

Swapping images without a redeploy is possible through the per-party upgrade loop of
`ci/scripts/lib/kms_deployment.sh` (`helm upgrade --set kmsCore.image.tag=…`), but for the enclave
variant the EIF must be the one built with that tag, so the plain "push, wait for the preview,
run" loop is simpler and safer.

### Experiment matrix (after the bisect)

Run each as its own 25 % TripleGen + 5 % BitGen window, baseline first:

| # | Knobs | Expect in the metrics if the hypothesis holds |
|---|---|---|
| 0 | none (`MPC_DKG_PHASE_LOG_EVERY=100` only) | the phase split: how much of a wave is `bcast_echo_wait` vs `prss`/`recons_d`/`solve`; `optimistic … hit` ≈ 100 % |
| 1 | `TOKIO=24 RAYON=28` | if `kms_thread_pool_cpu_usage{pool="tokio"}` was pinned at ~1000 in run 0, `bcast_echo_wait` shrinks and the 8 MB RPC average drops |
| 2 | `MPC_C2C_CONNECTIONS_PER_PEER=4` | same signature as 1 if the single connection task / TCP flow per peer was the limit |
| 3 | `MPC_C2C_H2_STREAM_WINDOW_BYTES=8388608 MPC_C2C_H2_CONN_WINDOW_BYTES=33554432 MPC_C2C_H2_MAX_FRAME_BYTES=1048576` | 8 MB RPC average drops at the start of each wave if the cold adaptive window was costing the first seconds |
| 4 | `MPC_BCAST_ECHO_HASH_KEYS=1 MPC_SERIALIZE_ON_RAYON=1` | `tokio` CPU down, `rayon` up by the same amount; `bcast_echo_wait` slightly down |
| 5 | `MPC_DKG_PRSS_PIPELINE=1` | `prss` phase ≈ 0 (the draws are awaited after the wait), wave period down by the former `prss` share |
| 6 | best of 1–5 combined | — |

If run 0 shows `kms_tcp_segs_total{kind="retrans"}` or the `vsocktun` drop counters moving
during the network half, the tunnel is losing packets and §3.5 of the proposal (vsock credit
window, MTU) comes before 1–5.

## 5. Bandwidth benchmark

Only on an idle cluster (a DKG in flight shares the same per-peer connections and makes both
meaningless). From the client pod, with the tool's deadline raised:

```bash
kubectl exec -it -n $NS kms-core-client-0 -- bash -c '
HEALTH_CHECK__REQUEST_TIMEOUT_SECS=600 kms-health-check bandwidth-bench \
  -c 0700000000000000000000000000000000000000000000000000000000000001 \
  -d 30 -n 85 -p 8320000 \
  -e kms-core-1-core-1:50100 -e kms-core-2-core-2:50100 -e kms-core-3-core-3:50100 \
  -e kms-core-4-core-4:50100 -e kms-core-5-core-5:50100 -e kms-core-6-core-6:50100 \
  -e kms-core-7-core-7:50100 -e kms-core-8-core-8:50100 -e kms-core-9-core-9:50100 \
  -e kms-core-10-core-10:50100 -e kms-core-11-core-11:50100 -e kms-core-12-core-12:50100 \
  -e kms-core-13-core-13:50100'
```

Start with `-n 1 -p 1000000 -d 10` (per-connection rate and RTT), then `-n 12`, then the DKG
shape above. The per-session completion lines now land in the core logs even if the tool gives
up, and `kms_c2c_send_rpc_duration_ms{size_bucket="le_16m"}` carries the per-RPC latency.

## 6. Validating a knob without a cluster

The knobs are process-wide statics read once, and `cargo test` runs one process per test binary,
so the existing suites exercise a knob when the variable is set for the run. None of the fixes
changes the wire format or the values produced, so the tests must pass unchanged with them on:

```bash
# PRSS pipeline: honest run, dropouts, and the two malicious cases (check_d with the reserved
# base counters) — in one process all parties share the setting, as they must.
MPC_DKG_PRSS_PIPELINE=1 cargo test -p threshold-execution --features testing offline_small
# Hashed echo tally + offloaded serialisation: honest / dropout / malicious sender and echo /
# double vote.
MPC_BCAST_ECHO_HASH_KEYS=1 MPC_SERIALIZE_ON_RAYON=1 cargo test -p threshold-execution --features testing broadcast
# Connection pool and static windows on the real gRPC stack (restarted / frozen peer tests).
MPC_C2C_CONNECTIONS_PER_PEER=3 MPC_C2C_H2_STREAM_WINDOW_BYTES=8388608 cargo test -p threshold-networking
# Unit tests of the new code itself (tuning resolution, /proc parsers, metric registry).
cargo test -p threshold-networking tuning && cargo test -p observability
```

State of the branch when this file was written: every touched crate passes
`cargo check --tests` (`threshold-execution` with `testing`, `kms` with `testing`, bins included),
`cargo fmt --check`, and `cargo clippy --all-targets --all-features -- -D warnings`
(`observability`, `thread-handles`, `threshold-algebra`, `threshold-networking`,
`threshold-execution`, `kms`, `kms-core-client`); the `observability` and `thread-handles` unit
tests pass. The protocol suites above were **not** run — do that, or let the PR CI do it, before
trusting a knob.

## 7. Files touched

- `observability/src/diag_metrics.rs` (new), `sys_metrics.rs`, `lib.rs`
- `core/thread-handles/src/lib.rs` — named rayon threads, `spawn_compute_bound_deferred`
- `core/threshold-algebra/src/sharing/optimistic.rs` — `reconstruct_optimistic_outcome`
- `core/threshold-execution`: `constants.rs` (knobs), `config.rs`, `sharing/open.rs` (counters),
  `small_execution/offline.rs` (timers, prefetch), `small_execution/prss.rs` (deferred draws),
  `communication/broadcast.rs` (timers, hashed echoes, offloaded serialisation),
  `communication/p2p.rs`, `online/gen_bits.rs`, `online/preprocessing/orchestration/producers/*`,
  `Cargo.toml` (observability dependency)
- `core/threshold-networking/src/tuning.rs` (new), `sending_service/service.rs` (connection pool,
  RPC histogram), `sending_service/session.rs`, `lib.rs`
- `core/service`: `conf/mod.rs` (`TuningConfig`), `bin/kms-server.rs`, `engine/threshold/service/kms_impl.rs`,
  `engine/threshold/bandwidth_bench.rs`; `core-client/tests/integration/integration_test.rs`
- `charts/kms-core`: `values.yaml`, `values.schema.json`, templates (configmap, statefulset), `Chart.yaml` 1.10.8
- `ci/perf-testing`: `manual-set-mpc-knobs.sh` (`TUNING_ENV`), `manual-metrics-watch.sh` (diagnostic
  block, `RAW_DIR`), `manual-run-experiment.sh`, `manual-bandwidth-bench.sh`, `manual-cluster-facts.sh`,
  `analyse_run.py`, this file; `Runbook.md` at the repository root

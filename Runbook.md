# DKG preprocessing on 13 enclave parties — runbook and hypotheses

Historical proposal. Use [runbook-v2.md](runbook-v2.md) for the controlled procedure and current tooling.
The hypotheses and commands below are retained for context, not as established diagnoses.

Branch `titouan/bench/ddec-and-decrypt` (PR #773). What we are trying to answer, what we think
is going on, and exactly what to run, where, to find out. The tooling is in `ci/perf-testing/`
(`BENCH-DIAGNOSTICS.md` there documents the metrics and the knobs); the results go to
`~/Code/ai/DkgDdecBench/runs/`.

## 1. The questions

| # | Question | Evidence that settles it | Runs |
|---|---|---|---|
| Q1 | Today's enclave preprocessing is 1.5–1.8× slower than the Aug-17 baseline (TripleGen 25 % at 1918 s vs 1079 s). Is that the code, the build, or the environment? | TripleGen time-to-25 % and triples/s for: today's image again (noise floor), no-optimistic-open, August build flags, August stack — all on today's cluster, same day | 5, 6a, 6b, 6c |
| Q2 | Where does a wave go — compute or network, and which phase? | phase split (`bcast_echo_wait` vs `prss` / `recons_d` / `mult_open` / `open_v` / `solve`), tokio vs rayon CPU, latency of the 8 MB echo RPCs, sender-queue depth | 5 |
| Q3 | Is the enclave tunnel the ceiling, and is it a bandwidth, a CPU or a loss ceiling? | bandwidth bench (1 / 12 / 85 sessions) on the idle cluster; enclave-side `vsocktun` CPU, TUN drops and TCP retransmits during a run; node-to-node iperf3 | 4, 5 |
| Q4 | Is the optimistic open taken in production, and what does it cost or save? | `kms_optimistic_reconstruct_total` hit / declined %, `recons_d` and `open_v` phase times with and without the PR's commits | 5, 6a |
| Q5 | Which of the candidate fixes helps, and by how much? | the same three numbers per knob set | 7 |

Three numbers summarise every run (`summary.md`, `summary.csv`): TripleGen time-to-X % with
triples/s (which normalises the +12.8 % workload since August), the phase split, and the 1–16 MB
RPC average. BitGen is 85 of the 90 sessions and the real DKG cost, but it only moves 1 % every
few minutes, so it is a cross-check (bits/s), not the stop rule.

## 2. Hypotheses

Ranked by how much I would bet on them. Each one says what it predicts and which run decides it.

**H1 — The environment moved, not the code (placement).** Nothing inside the enclave changed
between the two runs (same 52 CPUs / 96 GiB, same `vsocktun` 32 queues, MTU 1500, same thread
counts and timeouts — checked in the start-up lines of both core logs), and the workload is
transport-bound. Karpenter chooses the nodes per deployment: 13 parties in one availability zone
in August and spread over three in October, or a different instance type with a 12.5 Gbps NIC,
would do 1.5× on the echo round by itself, because with hyper's adaptive window starting at
65 KB the per-flow throughput is window / RTT and cross-AZ RTT is several times intra-AZ.
*Predicts:* the August stack (6c) is slow too; `cluster-facts.txt` shows mixed ZONE values or a
different INSTANCE; the 1-session bandwidth shape (4) shows a high RTT. *If true:* pin the
placement (topology spread / node affinity in the chart) before bisecting any code.

**H2 — The build flags, not the source.** August images were built with LTO off, generic
`x86-64`, Rust 1.97.1; today's with thin LTO, `-C target-cpu=x86-64-v3`, Rust 1.99.1. Each is
"usually faster", none was measured on this workload, and u128-heavy loops (Z128 decoder) are
where codegen surprises live. *Predicts:* 6b (today's code, August flags) is faster than 5;
compute phases (`prss`, `recons_d`, `solve`) shrink in the split. *If true:* split the three
flags one rebuild at a time and fix the Dockerfile default.

**H3 — Main drift in the networking crate.** Between Aug 17 and Oct 22: #743/#802 bounded
future-round buffering with a *silent* drop of anything more than 16 rounds ahead (merged the day
after the baseline), #887 HTTP/2 keepalive pings (15 s / 30 s), #815/#834/#857 session set-up
and eviction, #893 `Bytes` bodies, #930 completed-peer detection. Each adds a little per message
or a new failure mode; on 10 saturated tokio workers "a little per message" is the budget, and a
party more than two batches behind in a session now stalls on 300 s timeouts without a log line.
*Predicts:* 6c fast, 6b still slow; `FutureMessageDropped` in the network-event counter or
"haven't heard from" warnings during 5; RPC latency up without CPU up. *If true:* bisect `main`
between `e57eceb13` (Aug 14) and `9be8698e4` with the same procedure, networking commits first.

**H4 — Main drift in the compute path.** #939 PRSS/PRZS counter batching (Oct 15), #965 erasure
handling in the decoder (Oct 22). (#925 csprng and #945 rayon offload are *not* candidates — the
PRSS PRF keeps its own AES code and #945 only touches public decryption.) *Predicts:* 6c fast,
6b slow, and the `prss` / `recons_d` shares and rayon CPU in 5 are high. *If true:* same bisect
of `main`, PRSS commits first.

**H5 — The optimistic open costs more than it saves here.** *Predicts:* 6a (same build, no
optimistic commits) faster than 5; `declined` ≫ 0 would mean the fast path is not even taken and
the PR does nothing in this deployment. *If true:* fix eligibility or drop the PR for this path.

**H6 — The new sidecar limits throttle the enclave's log pipe.** #889 (merged the day of the
run) caps `kms-core-enclave-logger` at 200m CPU; the enclave pipes stdout/stderr through it.
*Predicts:* the logger pinned at ~200m in `top-party1.log` (`summary.md` flags it). *If true:*
raise `socat.resources.limits.cpu` and rerun the baseline.

**H7 — The tunnel is the wall (Q3), and which kind.** *Predicts:* `tx Gbps` during a run flat at
the 85-session bench ceiling (bandwidth); or `retrans %` > 0.01 and TUN drops moving (loss); or
enclave-side `vsocktun` CPU near a core and the parent-side one near its queues' worth (CPU).
*If true:* the vsock credit-window / MTU / queue work of the proposal (§3.5) comes before any
knob row.

**H8 — The transport is CPU-bound on the 10 tokio workers.** TLS, h2 framing, bincode of 13 ×
640 KB echo vectors, SipHash of the echo tally all run there. *Predicts:* `tokio cores` ≈ 10 while
rayon idles and `queued` > 0 in 5; rows 7.1 (24 workers), 7.2 (4 connections per peer), 7.4
(hashed tally + serialisation on rayon) help.

**H9 — The adaptive HTTP/2 window restarts cold on every 8 MB echo.** *Predicts:* the 1–16 MB
RPC average far above size / bandwidth; row 7.3 (static 8 / 32 MB windows, 1 MB frames) helps.

**H10 — The PRSS draw is serialised with the network wait.** *Predicts:* `prss` share ≈ 5–10 %
of batch time in 5; row 7.5 removes it from the wave.

**H0 — Yesterday's number is partly an artefact.** The bandwidth bench was started inside the
DKG at 15:57, 23 min into the run, so the 15–25 % points are confounded. The 5 % and 10 % points
(377 s vs 242 s, 749 s vs 463 s) already show 1.56–1.62×, so the regression is real; run 5 and
the end-of-day repeat (7.7) give the clean number and the noise floor.

## 3. Where things run

One cluster (the kms-ci EKS cluster behind Tailscale, your usual `kubectl` context); what differs
between steps is the namespace, one per PR preview. All commands run on the laptop from
`~/Code/ai/kms-ddec-bench` unless they say "in the client pod".

| namespace | what runs there | used by |
|---|---|---|
| `kms-ci-titouantanguy-773` | PR #773: today's code + instrumentation + knobs | 4, 5, 7, 8 |
| `kms-ci-titouantanguy-<prA>` | throwaway PR A: `5ec3e4a9c` = same build, no optimistic-open commits | 6a |
| `kms-ci-titouantanguy-<prB>` | throwaway PR B: today's head with the August build flags (LTO off, generic x86-64, Rust 1.97.1) | 6b |
| `kms-ci-titouantanguy-<prD>` | throwaway PR D: the Aug-17 branch state (code, charts and flags of the baseline) | 6c |

Open the throwaway previews one at a time unless the node group can hold two 13-party enclave
clusters. All `kms-ci-*` namespaces are destroyed daily at 00:00 UTC; re-add the label to bring
one back (~45 min).

What a run does by itself, so nothing needs doing between steps: rolling-restart the cores
(through `manual-set-mpc-knobs.sh` when knobs change, on its own otherwise), wait for 13 Ready
parties + 60 s, check the knobs reached the process, start the watchers (metrics every 10 s with
raw snapshots, the 13 core logs, `kubectl top` of party 1 every 30 s), launch `PREPROC_ONLY` in
the client pod, poll the tracker, stop at the rule, kill the client, rolling-restart the cores
again (so the preprocessing does not keep running for hours), pull the client logs, write
`manifest.json`, run the analysis. The knobs are read once at process start, which is why the
restart is not optional. Ctrl-C at any point runs the same stop-and-collect sequence.

Each run is ~35–40 min with the default stop at TripleGen 25 % (≈ 32 min at today's pace,
18 min at August's); `STOP_PCT=15` cuts it to ~25 min once the noise floor is known — the rate
is stable from the first point and the instrumentation is steady a few minutes in. The tracker
logs every 1 % on the instrumented image (`MPC_DKG_TRACKER_LOG_PERCENTAGE=1` in the knob set),
every 5 % on the two throwaway images that predate `[tuning.env]`.

## 4. Preparation (laptop)

**4a. Push the instrumentation** — PR #773 rebuilds the enclave image and redeploys
`kms-ci-titouantanguy-773` (~45 min: ~25 min build with the EIF, ~15 min deploy).
```bash
cd ~/Code/ai/kms-ddec-bench
git add -A core observability charts core-client Cargo.lock ci/perf-testing Runbook.md
git commit -m "bench: DKG preprocessing diagnostics and env-toggled fixes"
git push origin titouan/bench/ddec-and-decrypt
gh pr view 773 -R zama-ai/kms --json labels --jq '.labels[].name'          # must list pr-preview-thresholdWithEnclave
gh pr edit 773 -R zama-ai/kms --add-label pr-preview-thresholdWithEnclave   # only if missing
gh run list -R zama-ai/kms --workflow build-and-test.yml --branch titouan/bench/ddec-and-decrypt --limit 3
```
Ready when `kubectl get pods -n kms-ci-titouantanguy-773` shows 13 `kms-core-<i>-core-<i>` pods
Ready and `kms-core-client-0`.

**4b. Find the August image / commit** (for 6c only). The branch was rebased on Oct 22, so the
August SHAs survive only in the PR's CI history and your reflog.
```bash
mkdir -p ~/Code/ai/DkgDdecBench/runs
gh run list -R zama-ai/kms --workflow build-and-test.yml --branch titouan/bench/ddec-and-decrypt \
  --limit 200 --json headSha,createdAt,conclusion \
  --jq '.[] | select(.createdAt < "2026-08-18") | "\(.createdAt) \(.headSha[0:7]) \(.headSha) \(.conclusion)"' \
  | tee ~/Code/ai/DkgDdecBench/runs/august-ci-runs.txt
# the run just before 2026-08-17T12:40Z is the enclave baseline; its 7-char SHA is the image tag
gh api --paginate "/orgs/zama-ai/packages/container/kms%2Fcore-service-enclave-insecure/versions" \
  --jq '.[] | select(.metadata.container.tags[]? == "<7-char-sha>") | .created_at'    # image still there?
git -C ~/Code/ai/kms cat-file -t <full-sha>                                           # commit still in the clone?
git -C ~/Code/ai/kms reflog show titouan/bench/ddec-and-decrypt | grep -i aug | head   # if not: pre-rebase heads
```
If the commit exists anywhere, 4c pushes it; CI only rebuilds the image if the tag is gone.

**4c. Open the throwaway previews.**
```bash
cd ~/Code/ai/kms-ddec-bench
# A — no optimistic open, otherwise today's build:
git push origin 5ec3e4a9c:refs/heads/titouan/bench/bisect-no-optimistic

# B — today's head with the August build flags:
git checkout -b titouan/bench/bisect-aug-flags
sed -i '' 's/^ARG TARGET_CPU=x86-64-v3/ARG TARGET_CPU=/' docker/kms-binaries/Dockerfile
sed -i '' "s/'release-lto-thin'/'release-lto-off'/g" .github/workflows/docker-build.yml
sed -i '' 's/^channel = "1.99.1"/channel = "1.97.1"/' rust-toolchain.toml
git commit -am "bench(bisect): August build flags" && git push -u origin titouan/bench/bisect-aug-flags
git checkout titouan/bench/ddec-and-decrypt

# D — the August 17 stack (only if 4b found the commit):
git -C ~/Code/ai/kms push origin <full-aug-sha>:refs/heads/titouan/bench/bisect-aug17

# for each branch (A, B, D):
gh pr create -R zama-ai/kms --draft --base main --head <branch> --title "bench bisect: <what>" \
  --body "throwaway preview for the DKG preprocessing bisect — do not merge"
gh pr edit <pr> -R zama-ai/kms --add-label pr-preview-thresholdWithEnclave
```

**4d. Check the tooling once** against the live namespace (30 s):
```bash
cd ~/Code/ai/kms-ddec-bench
NS=kms-ci-titouantanguy-773 OUT=~/Code/ai/DkgDdecBench/runs/facts-773-before.txt bash ci/perf-testing/manual-cluster-facts.sh
kubectl logs -n kms-ci-titouantanguy-773 kms-core-1-core-1 -c kms-core-enclave-logger --tail=3000 \
  | python3 ci/perf-testing/analyse_run.py progress -
```

## 5. The runs, in order — namespace and exact command

```bash
cd ~/Code/ai/kms-ddec-bench
BASE="MPC_DKG_PHASE_LOG_EVERY=100,MPC_DKG_TRACKER_LOG_PERCENTAGE=1"   # logging only, always on
```

| step | namespace (`NS=`) | command | ~time | tests |
|---|---|---|---|---|
| 4 | `kms-ci-titouantanguy-773` | `NS=kms-ci-titouantanguy-773 RESTART_FIRST=1 bash ci/perf-testing/manual-bandwidth-bench.sh` | 15 min | H1, H7 |
| 5 | `kms-ci-titouantanguy-773` | `NS=kms-ci-titouantanguy-773 TAG=r0-baseline TUNING_ENV="$BASE" bash ci/perf-testing/manual-run-experiment.sh` | 35 min | H0, H6, H7–H10, Q2–Q4 |
| 6a | `kms-ci-titouantanguy-<prA>` | `NS=kms-ci-titouantanguy-<prA> TAG=bisect-no-optimistic bash ci/perf-testing/manual-run-experiment.sh` | 35 min | H5 |
| 6b | `kms-ci-titouantanguy-<prB>` | `NS=kms-ci-titouantanguy-<prB> TAG=bisect-aug-flags TUNING_ENV="$BASE" bash ci/perf-testing/manual-run-experiment.sh` | 35 min | H2 |
| 6c | `kms-ci-titouantanguy-<prD>` | `NS=kms-ci-titouantanguy-<prD> TAG=bisect-aug17 bash ci/perf-testing/manual-run-experiment.sh` | 35 min | H1 vs H3/H4 |
| 7.1 | `kms-ci-titouantanguy-773` | `NS=kms-ci-titouantanguy-773 TAG=r1-threads TOKIO=24 RAYON=28 TUNING_ENV="$BASE" bash ci/perf-testing/manual-run-experiment.sh` | 35 min | H8 |
| 7.2 | `kms-ci-titouantanguy-773` | `NS=kms-ci-titouantanguy-773 TAG=r2-pool4 TUNING_ENV="$BASE,MPC_C2C_CONNECTIONS_PER_PEER=4" bash ci/perf-testing/manual-run-experiment.sh` | 35 min | H8 |
| 7.3 | `kms-ci-titouantanguy-773` | `NS=kms-ci-titouantanguy-773 TAG=r3-windows TUNING_ENV="$BASE,MPC_C2C_H2_STREAM_WINDOW_BYTES=8388608,MPC_C2C_H2_CONN_WINDOW_BYTES=33554432,MPC_C2C_H2_MAX_FRAME_BYTES=1048576" bash ci/perf-testing/manual-run-experiment.sh` | 35 min | H9 |
| 7.4 | `kms-ci-titouantanguy-773` | `NS=kms-ci-titouantanguy-773 TAG=r4-hash-ser TUNING_ENV="$BASE,MPC_BCAST_ECHO_HASH_KEYS=1,MPC_SERIALIZE_ON_RAYON=1" bash ci/perf-testing/manual-run-experiment.sh` | 35 min | H8 |
| 7.5 | `kms-ci-titouantanguy-773` | `NS=kms-ci-titouantanguy-773 TAG=r5-prss-pipe TUNING_ENV="$BASE,MPC_DKG_PRSS_PIPELINE=1" bash ci/perf-testing/manual-run-experiment.sh` | 35 min | H10 |
| 7.6 | `kms-ci-titouantanguy-773` | the rows that helped, together: `NS=kms-ci-titouantanguy-773 TAG=r6-combo TOKIO=.. RAYON=.. TUNING_ENV="$BASE,<knobs>" bash ci/perf-testing/manual-run-experiment.sh` | 35 min | — |
| 7.7 | `kms-ci-titouantanguy-773` | baseline again, end of day: `NS=kms-ci-titouantanguy-773 TAG=r0-baseline-2 TUNING_ENV="$BASE" bash ci/perf-testing/manual-run-experiment.sh` | 35 min | H0 (noise floor) |
| 8 | laptop | `python3 ci/perf-testing/analyse_run.py compare ~/Code/ai/DkgDdecBench/runs` | 1 s | all |

Notes:

- Steps 4, 5, 7 only make sense on #773 (the logging and the knobs exist only there). 6a–6c are
  one run each on their namespace and nothing else; 6a and 6c take no `TUNING_ENV` because their
  kms-server does not know `[tuning.env]` (the orchestrator then just restarts the cores and
  records the tracker timeline, the pre-existing metrics and the cluster facts, which is all the
  bisect needs).
- Order of value: 5, then 6c if available, 6a, 6b, then 7. Drop 6b if 6a and 6c already explain
  the gap (§6). The 6x runs are independent of each other and of #773 — one terminal per
  namespace if capacity allows.
- Chaining runs on the same namespace: `ABORT_AFTER=0` on all but the last saves the redundant
  end-of-run restart (~5 min), as long as the next run follows immediately.
- `MPC_DKG_PRSS_PIPELINE` changes the order in which PRSS counters are consumed and must be on
  for all 13 parties — it is, the `[tuning.env]` table is fleet-wide; never set it on a subset.
- If the day runs past 00:00 UTC the previews are destroyed; re-add the label and wait.

## 6. Reading the results

**The bisect (Q1)**, with `triplegen_t25_s` and `triplegen_items_per_s` from
`analyse_run.py compare`:

- `r0-baseline` ≈ 1918 s again → reproducible, small noise (H0 rejected); much faster → yesterday
  was disturbed, rerun before concluding anything.
- `bisect-aug17` ≈ 1079 s → the environment is unchanged (H1 rejected), the slowdown is in the
  code or the build; ≈ 1900 s → H1: compare `cluster-facts.txt` (ZONE, INSTANCE) of the two
  namespaces and the 1-session bench RTT, and pin the placement before touching code.
- `bisect-no-optimistic` vs `r0-baseline` → H5: the PR's own cost (expected ≈ 0 wall time in a
  network-bound regime; a large gap → look at `recons_d` / `open_v` avg ms and the hit %).
- `bisect-aug-flags` vs `r0-baseline` → H2: the thin-LTO + `x86-64-v3` + rustc 1.99 effect; if
  the August flags are faster, split them one rebuild at a time.
- what remains between `bisect-aug-flags` and `bisect-aug17` is main drift (H3/H4): bisect
  `main` between `e57eceb13` and `9be8698e4` with the same procedure — networking commits first
  if the phase split blames `bcast_echo_wait`, PRSS/decoder commits first if it blames compute.

**The instrumented baseline (Q2–Q4)**, in `r0-baseline/summary.md`:

- `bcast_echo_wait` dominant and `tokio cores` ≈ 10 → H8: rows 7.1, 7.2, 7.4.
  `bcast_echo_wait` dominant, tokio idle, `tx Gbps` flat at the bench ceiling → H7 bandwidth:
  row 7.3 and the tunnel work. `retrans %` > 0.01 or TUN drops moving → H7 loss: the tunnel work
  first. `prss` + `recons_d` + `solve` dominant → compute: row 7.5 and the H2/H4 legs.
- `opt hit %` ≈ 100 on `robust_open` and `d_values` → the fast path is taken; `declined` ≫ 0 →
  the eligibility check refuses and the PR does nothing here — fix before benchmarking it.
- `queued` persistently > 0 → the sender tasks are behind the protocol: H8.
- the logger at its 200m limit in the containers table → H6: raise the limit, rerun.
- "haven't heard from" warnings or a moving `FutureMessageDropped` → H3 directly.

**The matrix (Q5)**: a row helps when `triplegen_t25_s` drops beyond the spread between
`r0-baseline` and `r0-baseline-2` and the phase it targets shrinks (7.5 → `prss` ≈ 0; 7.1–7.3 →
the 1–16 MB RPC average and `bcast_echo_wait`).

**The transport ceiling (Q3)**, in `runs/bw-*/<shape>/summary.txt`: the 1-session MiB/s is the
single-flow ceiling of one TCP connection through the tunnel; the 12 and 85 shapes approach the
party's egress ceiling (`Gbps`). Compare with the 25 Gbps NIC and with `tx Gbps` during a run.
Timeouts/errors in the 85 shape = a loss ceiling. Optional, to separate tunnel from network:
```bash
NS=kms-ci-titouantanguy-773   # node names from cluster-facts.txt; enclave nodes may be tainted
kubectl run iperf-srv -n $NS --image=networkstatic/iperf3 --overrides='{"spec":{"nodeName":"<node of party 1>","tolerations":[{"operator":"Exists"}]}}' -- -s
kubectl run iperf-cli -n $NS --rm -it --image=networkstatic/iperf3 --overrides='{"spec":{"nodeName":"<node of party 2>","tolerations":[{"operator":"Exists"}]}}' -- -c $(kubectl get pod iperf-srv -n $NS -o jsonpath='{.status.podIP}') -P 8 -t 20 \
  | tee ~/Code/ai/DkgDdecBench/runs/iperf-node1-node2.txt
kubectl delete pod iperf-srv -n $NS
```
Node-to-node ≫ bench ceiling → the tunnel is the wall; similar → the network is. The same bench
on a non-enclave preview (`pr-preview-threshold` label on a throwaway PR) gives the
without-tunnel numbers.

## 7. What the runs leave behind

Everything is a file under `~/Code/ai/DkgDdecBench/runs/` (outside the git worktree on purpose):

```
runs/summary.csv                 one row per run (analyse_run.py compare reads it)
runs/<TAG>/manifest.json         knobs, images, times, progress at stop, why it stopped
runs/<TAG>/cluster-facts.txt     nodes (instance type, zone, kernel), pod placement, sidecar args, rendered configs
runs/<TAG>/set-knobs.log         what manual-set-mpc-knobs.sh changed
runs/<TAG>/core/core-<i>.log     the 13 core logs for the whole run
runs/<TAG>/raw/p<i>/<epoch>.prom one /metrics snapshot per 10 s for each watched party
runs/<TAG>/metrics-watch.log     the human-readable watch frames
runs/<TAG>/top-party1.log        kubectl top of party 1's containers every 30 s
runs/<TAG>/client/*.log          the kms-core-client driver logs
runs/<TAG>/summary.md            the analysis
runs/bw-<timestamp>/<shape>/     tool.log, core-<i>.bench.log, summary.txt, cluster-facts.txt
runs/august-ci-runs.txt, facts-773-before.txt, iperf-node1-node2.txt
```

About 20–30 MB per run. `analyse_run.py summarize` also accepts the old
`DkgDdecBench/dkg-under-load-*` capture folders, so the August runs can sit in the same table.

## 8. What changed since August 17 (background for H1–H6)

Enclave-side, nothing: the start-up lines of the Aug-17 and Oct-22 core logs both show 52 CPUs,
96 GiB, `vsocktun` 32 queues / 32 shards, MTU 1500, tokio 10 / rayon 60, 90 preprocessing
sessions, 300 s network timeout, 2 GiB message limit; `vsocktun` is pinned to the external tag
`v0.1.0`; the kms-server config differs only by the removed rate limiter (#949) and the
session-store intervals (#926). Everything around it moved:

- **Build flags** (H2): `release-lto-off` → `release-lto-thin` for non-release images (#837,
  Sep 8), `-C target-cpu=x86-64-v3` (bench commit `607325cd4`, Sep 8), Rust 1.97.1 → 1.99.1
  (#955), rolling golden and base images, separate prod/testing images (#609).
- **134 commits on `main`** (H3, H4): #743/#802 future-round bounds with silent drop, #887 HTTP/2
  keepalive, #815/#834/#857 session handling, #893 `Bytes` on the P2P path, #930 completed-peer
  detection, #924 removal of the per-session byte map, #939 PRSS counter batching, #965 erasure
  handling in the decoder, #949 rate limiter removed, #926 session-store intervals.
- **Chart / deploy** (H6): #889 puts `cpu: 200m` / `128Mi` limits on the socat sidecars including
  the enclave logger; #920 priority classes, #940/#827 scheduling and schema only. The tunnel
  sidecar's resources (8 CPU requested, no CPU limit) and the Karpenter tolerations are unchanged
  in the repo; the instance types and zones Karpenter handed out in August are unrecorded (H1) —
  `manual-cluster-facts.sh` records them from now on.
- **Workload**: 9.62 M → 10.85 M triples and 878 M → 924 M bits per DKG (+12.8 % / +5 %).
- **Yesterday's measurement** (H0): the bandwidth bench ran inside the DKG from 15:57.

## 9. Tools

- `ci/perf-testing/manual-run-experiment.sh` — one run end to end
- `ci/perf-testing/manual-bandwidth-bench.sh` — the three bandwidth shapes on an idle cluster
- `ci/perf-testing/manual-cluster-facts.sh` — environment record
- `ci/perf-testing/analyse_run.py` — `progress`, `summarize`, `bw`, `compare`
- `ci/perf-testing/manual-metrics-watch.sh` (`RAW_DIR`), `manual-capture-core-logs.sh`,
  `manual-set-mpc-knobs.sh` (`TUNING_ENV`), `manual-dkg-under-load.sh` — the building blocks
- `ci/perf-testing/BENCH-DIAGNOSTICS.md` — the metrics, the knobs, how they reach the enclave
- `~/Code/ai/proposal-dkg-preproc-bottleneck.md` — the proposal this implements

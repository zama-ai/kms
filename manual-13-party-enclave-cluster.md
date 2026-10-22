# Manually driving a 13-party enclave KMS cluster

Goal: spin up a **13-party threshold cluster inside Nitro enclaves** (the same
topology the `performance-testing` workflow uses) plus a **core client** that
can talk to it, but **drive the core-client commands yourself** instead of
running the fixed Argo DAG.

This is "Variant B": **deploy-and-hold** — deploy once, leave the cluster
running, and fire core-client commands by hand for as long as you need.

---

## TL;DR — can I do this directly from GitHub with existing actions?

**Partly.** Two independent questions:

- **Deploying the cluster from GitHub: yes.** The entire deploy is one script
  call (`ci/scripts/deploy.sh`) that the perf workflow already runs. But **no
  existing workflow does deploy-only** — `performance-testing.yml` always tears
  the cluster down in an `if: always()` cleanup step
  (`performance-testing.yml:596`). So a from-GitHub deploy-and-hold needs a
  **small trimmed copy** of that workflow (stop after the deploy step, drop the
  Argo-submit + cleanup steps). The cluster runs on a real EKS namespace, so it
  survives after the job finishes.

- **Interactively driving commands from GitHub: not natively.** GitHub Actions
  has **no interactive terminal**. There are only two honest ways to "drive
  manually":
  1. **Drive from your laptop** (recommended) — deploy from GitHub (or locally),
     then connect over Tailscale with `kubectl` and run commands against the
     live cluster. The *driving* is local; the *cluster* is remote.
  2. **Drive inside a GitHub job** via an added interactive-session action
     (`mxschmitt/action-tmate`), which opens a web/SSH terminal on the runner
     where the kubeconfig + Tailscale are already configured. This **is** an
     existing marketplace action, but it is **not currently used in this repo**,
     so adding it is a change — and self-hosted-runner SSH-out may be blocked by
     org policy. See the appendix.

Bottom line: the **deploy** half is trivially GitHub-driven; the **manual
command** half is cleanest from your laptop. Everything below assumes that
model, with the fully-in-GitHub alternative in the appendix.

---

## What actually gets deployed

`ci/scripts/deploy.sh --target aws-perf --deployment-type thresholdWithEnclave
--num-parties 13` installs, into namespace **`kms-ci`** on the Tailscale EKS
cluster:

- 13 core pods in Nitro enclaves, named **`kms-core-1-core-1` …
  `kms-core-13-core-13`**, each exposing gRPC on port **50100**.
- A core-client StatefulSet — pod **`kms-core-client-0`** (label
  `app=kms-core-client`), image `core-client`, CLI on `$PATH` as
  **`kms-core-client`** (real path `/app/kms-core-client/bin/kms-core-client`,
  workdir `/app/kms-core-client`).
- Per-party configmaps **`kms-enclave-ci-1` … `kms-enclave-ci-13`** holding
  `CORE_CLIENT__S3_ENDPOINT` (the public-material S3 endpoint the client needs).

Threshold parameters for n=13: **`num_majority=5`, `num_reconstruct=9`**,
decryption mode **`NoiseFloodSmall`** (from the Argo template,
`ci/perf-testing/argo-workflow/kms-perf-workflow-kms-ci.yaml:438-443`).

---

## Prerequisites

- Membership in the Tailscale tailnet with tag `tag:kms-ci`, or the
  `TS_OAUTH_CLIENT_ID` / `TS_OAUTH_SECRET` used by the workflow.
- `kubectl`, `helm`, and the Tailscale CLI locally (only if driving from your
  laptop).
- Access to the private image registry (`hub.zama.org`, Harbor) — the cluster
  pulls images via `registry-credentials`; you only need this locally if you
  also build/push images.
- Image tags for `core-service-enclave` and `core-client` that already exist in
  the registry (or build them via the `docker-build` workflow first).

> ⚠️ **Namespace collision.** `kms-ci` is the same namespace the scheduled
> `performance-testing` run uses (cron `0 0 * * 1-5`, midnight UTC Mon–Fri), and
> that run's cleanup step will `helm uninstall` everything in `kms-ci`. Hold your
> cluster **outside that window**, or accept it may be torn down under you.
> Re-homing to another namespace requires editing the values files under
> `ci/perf-testing/thresholdWithEnclave/kms-ci/`, so it is not a one-flag change.

---

## Step 1 — Deploy the cluster

### Option A (from GitHub): a deploy-only workflow

Create a `workflow_dispatch` workflow that reuses the perf setup verbatim and
**stops after the deploy step**. Copy `performance-testing.yml` and keep exactly
these steps, dropping "Run performance testing", the CPU sampler, and the
"Cleanup" step:

- Setup Runs-on → Checkout → Determine image tags → Configure deployment
  parameters (force `DEPLOYMENT_TYPE=thresholdWithEnclave`) → Harbor login →
  path suffix → validate → verify image tags → **Tailscale** → helm/argo/kubectl
  setup → **Setup kubeconfig** (`tailscale configure kubeconfig …`) → **Set
  kubeconfig context** → then the deploy call:

```bash
./ci/scripts/deploy.sh \
  --target aws-perf \
  --namespace kms-ci \
  --deployment-type thresholdWithEnclave \
  --core-tag "$KMS_CORE_IMAGE_TAG" \
  --client-tag "$KMS_CORE_CLIENT_IMAGE_TAG" \
  --num-parties 13 \
  --kms-chart-version repository \
  --tkms-infra-version 0.3.2
```

Because there is no cleanup step, the Helm releases persist on EKS after the job
ends. That **is** your deploy-and-hold. (References: setup steps
`performance-testing.yml:326-398`, deploy call `performance-testing.yml:403-424`.)

Take the image tags either from a prior `docker-build` run or from a known-good
tag, and pass them as `workflow_dispatch` inputs (mirror
`kms_core_image_tag` / `kms_core_client_image_tag`,
`performance-testing.yml:65-74`).

### Option B (from your laptop): run the script directly

With Tailscale up and kubeconfig configured (`tailscale configure kubeconfig
tailscale-operator-zws-dev.diplodocus-boa.ts.net`), run the **same** command
above from a checkout of the repo. Identical result; no workflow needed.

Wait until all 13 core pods and the threshold-init job are healthy:

```bash
kubectl get pods -n kms-ci -l app=kms-core
kubectl get job  -n kms-ci -l app=kms-threshold-init-job
kubectl get pod  -n kms-ci kms-core-client-0
```

---

## Step 2 — Connect from your laptop

```bash
# bring up Tailscale (or: tailscale up), then point kubeconfig at the cluster
tailscale configure kubeconfig tailscale-operator-zws-dev.diplodocus-boa.ts.net
kubectl config use-context tailscale-operator-zws-dev.diplodocus-boa.ts.net
kubectl get pods -n kms-ci
```

---

## Step 3 — Drive the core client

### Easiest: exec into the deployed client pod (config already there)

If you deployed via Step 1 (Option A or B), the client StatefulSet is deployed
with `kmsCoreClient.enabled: true`, and its entrypoint
(`load-core-client-config.sh`, mounted from
`charts/kms-core/templates/kms-core-client-configmap.yaml`) **renders a
ready-to-use config at startup**, then idles (`tail -f /dev/null`). So you do
**not** need to write a config — just point at the rendered one:

```bash
kubectl exec -it -n kms-ci kms-core-client-0 -- bash

# config.toml already exists with all 13 cores, the real s3_endpoint,
# num_majority=5, num_reconstruct=9, decryption_mode=NoiseFloodSmall:
kms-core-client -f /app/kms-core-client/config.toml preproc-key-gen
kms-core-client -f /app/kms-core-client/config.toml key-gen -i <preproc-request-id>
kms-core-client -f /app/kms-core-client/config.toml crs-gen --max-num-bits 2048
```

The binary is on `$PATH` (`/app/kms-core-client/bin/kms-core-client`). Each
command prints a line containing `"request_id": "<id>"` that you feed into the
matching `-result` / dependent command. (`num_majority`/`num_reconstruct` are
auto-set for `NUM_PARTIES >= 13` in `ci/scripts/lib/kms_deployment.sh`.)

Two things to know about the rendered file:
- It uses `fhe_params = "Default"`. For keygen/preproc with `Test` params (as the
  perf run does for those steps), copy it and edit that one line:
  `cp /app/kms-core-client/config.toml /tmp/config.toml && sed -i 's/fhe_params = "Default"/fhe_params = "Test"/' /tmp/config.toml`.
- Core addresses carry an `http://` prefix (`http://kms-core-N-core-N:50100`) vs
  the bare form the Argo template writes — both work.

### Alternative: spawn a throwaway client pod (must supply your own config)

A fresh `kubectl run` pod has **no** rendered config, so you write one yourself.
Grab the S3 endpoint from the party-1 configmap first:

```bash
S3_ENDPOINT=$(kubectl get cm kms-enclave-ci-1 -n kms-ci \
  -o jsonpath='{.data.CORE_CLIENT__S3_ENDPOINT}')

kubectl run kms-client-manual -n kms-ci --rm -it \
  --image=hub.zama.org/ghcr/zama-ai/kms/core-client:<client-tag> \
  --overrides='{"spec":{"imagePullSecrets":[{"name":"registry-credentials"}]}}' \
  -- bash
```

`config.toml` to write inside that pod (identical to what the Argo tasks
generate, `kms-perf-workflow-kms-ci.yaml:285-355`) — substitute `$S3_ENDPOINT`:

```toml
kms_type = "threshold"
num_majority = 5
num_reconstruct = 9
decryption_mode = "NoiseFloodSmall"
fhe_params = "Test"          # or "Default"

[[cores]]
party_id = 1
address = "kms-core-1-core-1:50100"
s3_endpoint = "<S3_ENDPOINT>"
object_folder = "PUB-p1"
# … repeat for party_id 2..13:
#   address = "kms-core-<N>-core-<N>:50100", object_folder = "PUB-p<N>"
```

(The `kms-core-<N>-core-<N>:50100` DNS names only resolve **inside** the
`kms-ci` namespace, so the client must run as a pod in that namespace.)

### Command reference (subcommands of `kms-core-client`)

From `core-client/src/lib.rs:1150-1186`:

| Command | Purpose |
|---|---|
| `preproc-key-gen` / `preproc-key-gen-result` | Threshold keygen preprocessing (+ fetch) |
| `partial-preproc-key-gen` | Offline-phase-only DKG preprocessing |
| `key-gen` / `key-gen-result` / `abort-key-gen` | Distributed key generation (+ fetch / abort) |
| `insecure-preproc-key-gen` / `insecure-key-gen` (+ `-result`) | Fast testing variants (no real MPC preprocessing) |
| `crs-gen` / `crs-gen-result` / `abort-crs-gen` | CRS generation (+ fetch / abort) |
| `insecure-crs-gen` (+ `-result`) | Fast testing CRS variant |
| `encrypt` | Encrypt a plaintext to a ciphertext |
| `public-decrypt from-args\|from-file` / `public-decrypt-result` | Public decryption |
| `user-decrypt from-args\|from-file` | User decryption |
| `new-custodian-context` / `get-operator-public-key` | Custodian backup/recovery setup |
| `custodian-recovery-init` / `custodian-backup-recovery` / `backup-restore` | Recovery flows |
| `new-epoch` / `new-mpc-context …` / `destroy-mpc-context` / `destroy-mpc-epoch` | MPC context / epoch lifecycle (resharing) |
| `new-custodian-context` / `destroy-custodian-context` | Custodian context lifecycle |

Example decrypt (mirrors the perf run,
`kms-perf-workflow-kms-ci.yaml:575`):

```bash
kms-core-client -f /tmp/config.toml \
  public-decrypt from-args -d euint64 -k <key-id> -e ffffffffffffffff \
  --batch-size 1 --rate 1100 --duration 30 --max-in-flight 10000
```

---

## Step 4 — Tear down

The cluster stays up until you remove it. Mirror the perf cleanup
(`performance-testing.yml:596-626`) — run locally or as a second one-click
`workflow_dispatch`:

```bash
helm list -n kms-ci -q | xargs -r -n1 helm uninstall -n kms-ci
kubectl delete cm  -l app=kms-core        -n kms-ci
kubectl delete cm  -l app=kms-core-client -n kms-ci
kubectl delete sts -l app=kms-core-client -n kms-ci
kubectl delete job -l app=kms-core        -n kms-ci
kubectl delete job -l app=kms-threshold-init-job -n kms-ci
kubectl delete pod kms-client-manual -n kms-ci --ignore-not-found  # if you spawned one
```

---

## Appendix — fully interactive, entirely inside GitHub

To avoid needing local Tailscale/kubectl and drive commands from a browser:

1. Build the deploy-only workflow from Step 1 Option A.
2. After the deploy step, add an interactive session on the same runner (which
   already has Tailscale + kubeconfig configured):

```yaml
   - name: Interactive session (drive core-client here)
     uses: mxschmitt/action-tmate@v3
     with:
       limit-access-to-actor: true
```

3. Open the tmate web/SSH URL printed in the job log; in that shell run the
   `kubectl exec … kms-core-client -f config.toml <cmd>` commands from Step 3.
4. Close the session (or hit the job `timeout-minutes`) to end the job, then run
   the teardown workflow.

Caveats: `action-tmate` is **not currently in this repo** (adding it is a
change); the session holds a runner for its whole duration; and outbound
SSH/tmate from self-hosted runners may be disallowed by org policy — confirm
before relying on it.

---

## Key source references

- Perf deploy call: `.github/workflows/performance-testing.yml:403-424`
- Perf setup (Tailscale/kubeconfig/tools): `.github/workflows/performance-testing.yml:326-398`
- Always-on teardown to strip for hold: `.github/workflows/performance-testing.yml:596-626`
- Deploy entrypoint: `ci/scripts/deploy.sh` (+ libs in `ci/scripts/lib/`)
- 13-core `config.toml` + commands: `ci/perf-testing/argo-workflow/kms-perf-workflow-kms-ci.yaml:285-355,438-443,575`
- Client image binary path: `docker/core-client/Dockerfile:26,63-67,96`
- Client subcommands: `core-client/src/lib.rs:1150-1186`

---

## Scenario — decryption load *while* a full DKG runs

Goal: mint a decryption key the cheap way (no full preprocessing), then run a
**sustained decrypt rate-flow concurrently with a real DKG** (`preproc-key-gen`
→ `key-gen`, i.e. the heavy MPC preprocessing) to see whether the cluster
sustains decryption while doing DKG. Keep logs of both the client processes and
all 13 core pods.

Everything uses the rendered `/app/kms-core-client/config.toml` already in the
client pod (13 cores, `num_majority=5`, `num_reconstruct=9`,
`fhe_params="Default"` — `Default` is the heavy/real param set you want for a
genuine DKG load test; `Test` is the fast CI params).

Command/flag surface verified against source: `CCCommand` enum
`core-client/src/lib.rs:1150-1171`; `-i/--preproc-id` `:831,844`; decrypt
`-k/-e/-d/-b` + `--rate/--duration/--max-in-flight` `:672-777`; CRS
`-m/--max-num-bits` `:852`.

### Step 0 — two terminals

- **Terminal A** = shell *inside* the client pod (runs the workload):
  ```bash
  kubectl exec -it -n kms-ci kms-core-client-0 -- bash
  ```
- **Terminal B** = your laptop (streams the 13 core pods' logs; there is no
  `kubectl` inside the pod).

Use a shared run tag so everything correlates (set the **same** value in both
terminals):
```bash
RUN=dkg-under-load-$(date +%Y%m%d-%H%M%S)
```

### Step 1 (Terminal A) — mint the decryption key (insecure path)

This mirrors how perf-testing mints its decrypt key (`udec-preproc-key-gen` /
`udec-key-gen` are the insecure variants), so "no full preprocessing" = the
insecure path.

```bash
cd /app/kms-core-client
CFG=/app/kms-core-client/config.toml

rid() { grep -o '"request_id": "[^"]*"' "$1" | tail -1 | sed 's/.*"\([^"]*\)"$/\1/'; }

# dummy preprocessing (fast, no real material)
kms-core-client --logs -f "$CFG" insecure-preproc-key-gen 2>&1 | tee /tmp/${RUN}-udec-preproc.log
UDEC_PREPROC_ID=$(rid /tmp/${RUN}-udec-preproc.log)

# insecure keygen consuming that preprocessing; its request_id IS the key id
kms-core-client --logs -f "$CFG" insecure-key-gen -i "$UDEC_PREPROC_ID" 2>&1 | tee /tmp/${RUN}-udec-keygen.log
KEY_ID=$(rid /tmp/${RUN}-udec-keygen.log)

echo "KEY_ID=$KEY_ID"   # keep this
```

These commands block until completion (the client polls up to `--max-iter`), so
the chaining is safe.

### Step 2 (Terminal B) — capture core-pod logs *before* the load

```bash
RUN=<same value as Terminal A>
mkdir -p "$RUN" && cd "$RUN"
for i in $(seq 1 13); do
  # enclave deployment: logs come from the enclave-logger sidecar
  kubectl logs -f -n kms-ci "kms-core-${i}-core-${i}" -c kms-core-enclave-logger \
    --timestamps > "core-${i}.log" 2>&1 &
done
echo "streaming 13 core logs into $PWD"
```
(For a non-enclave `threshold` deploy, use `-c kms-core` instead of
`-c kms-core-enclave-logger`.)

### Step 3 (Terminal A) — launch decrypt + DKG concurrently

The heaviest MPC contention is the DKG **preprocessing** phase, so decryption
must run for the whole `preproc-key-gen → key-gen` chain. This backgrounds the
DKG and keeps a decrypt rate-flow running until the DKG finishes:

```bash
# --- B: full DKG (real preprocessing + keygen) in the background ---
(
  kms-core-client --logs -f "$CFG" preproc-key-gen 2>&1 | tee /tmp/${RUN}-dkg-preproc.log
  PREPROC_ID=$(rid /tmp/${RUN}-dkg-preproc.log)
  echo "DKG preproc done, id=$PREPROC_ID; starting keygen"
  kms-core-client --logs -f "$CFG" key-gen -i "$PREPROC_ID" 2>&1 | tee /tmp/${RUN}-dkg-keygen.log
  echo "DKG COMPLETE"
) &
DKG_PID=$!

# --- A: sustained decryption, relaunched in chunks until the DKG exits ---
RATE=1100          # requests/s — start at a rate you know the cluster sustains
CHUNK=120          # seconds per decrypt run
MAXIF=10000
i=0
while kill -0 "$DKG_PID" 2>/dev/null; do
  i=$((i+1))
  kms-core-client --logs -f "$CFG" \
    public-decrypt from-args \
      -d euint64 -k "$KEY_ID" -e ffffffffffffffff \
      --batch-size 1 --rate "$RATE" --duration "$CHUNK" --max-in-flight "$MAXIF" \
    2>&1 | tee /tmp/${RUN}-decrypt-chunk-$(printf '%03d' $i).log
done

wait "$DKG_PID"
echo "all done — DKG finished, decrypt loop stopped"
```

Notes:
- Each decrypt chunk prints a `PUBLIC_DECRYPT_METRICS {...}` JSON line with
  `offered/completed/failed/shed/saturated/achieved_rate` — that's your "did
  decryption survive the DKG" signal. `failed`/`shed`/`saturated=true` rising
  when the preproc phase kicks in is exactly the interference you're testing for.
- Swap `public-decrypt` → `user-decrypt` (same flags) to test user-decrypt, or
  run both by adding a second background loop.
- `RATE=1100` mirrors the first perf rung; raise/lower to find where concurrent
  DKG starts degrading it.

### Step 4 — collect everything

From your laptop, copy the client-side logs out of the pod:
```bash
kubectl cp kms-ci/kms-core-client-0:/tmp "$RUN/client-logs"   # pulls /tmp/${RUN}-*.log
```
Then stop the core-log streamers in Terminal B:
```bash
kill $(jobs -p) 2>/dev/null
```

You end up with, under `./$RUN/`: the 13 timestamped `core-*.log`, the DKG
preproc/keygen logs, and the numbered decrypt-chunk logs with per-chunk metrics
— all correlatable by timestamp.

### Caveats

- **`--logs` skews throughput.** Client tracing is great for "what's going on"
  but the perf harness runs *without* it because it lowers achievable rate. For
  clean capacity numbers, drop `--logs` on the decrypt loop (keep it on the DKG).
- **One real DKG at a time.** `preproc-key-gen`/`key-gen` consume shared
  preprocessing capacity on the cores (that's the point here) — just make sure
  the nightly perf run isn't also active in `kms-ci`, or you can't attribute the
  load.

---

## Diagnosis so far — why is enclave DKG preprocessing slow?

The `preproc-key-gen` offline phase runs ~90 concurrent sessions (**85 BitGen +
5 TripleGen**; BitGen is the heavy load, TripleGen a small fraction). It's much
slower in the enclave than in the non-enclave NIST bench. We instrumented it
live with `ci/perf-testing/manual-metrics-watch.sh` (scrapes each party's
`:9646` Prometheus endpoint inside the enclave).

**Evidence points to latency/round-bound, NOT bandwidth or compute:**

| Signal | Reading | Rules out |
|---|---|---|
| tunnel throughput (`kms_network_rx/tx`) | 2–3 of 25 Gbps | not bandwidth-bound |
| tunnel CPU (parent, `enclave-network-tunnel`) | 1–2 of 16 cores | not tunnel-CPU-bound |
| enclave CPU util (`kms_process_cpu_usage`/`kms_total_cpus`) | ~40 % avg, idle waves | not compute-bound |
| enclave load (`kms_cpu_load`) | 0.3–0.5 | cores mostly waiting |

The `~40 % avg` is real (corroborated by loadavg), with brief peaks well above
100 % (the metric is multi-core, 100 % = 1 core; it has hit 4354 %) but never a
sustained saturation. That "cores idle while preproc crawls" signature is the
crux: **something is making the cores wait.** Two candidate explanations, tested
by the two work-streams below:

1. **Enclave/network latency** (vsock tunnel per-round round-trips) — isolate
   with the non-enclave A/B below.
2. **In-process contention** (locks/channels/thread-pools inside the core) —
   suspects catalogued two sections down.

---

## Non-enclave A/B comparison (isolating tunnel-added latency)

Run the *identical* preproc-only workload on the enclave env and on a
non-enclave `threshold` env (same 13-party topology, no vsock tunnel). If the
non-enclave cores idle *less* (utilization meaningfully higher) → the tunnel's
per-round latency was causing the idle waves → **tunnel confirmed**. If the
non-enclave env *also* idles ~40 % → the rounds are inherent to the
protocol/network and the enclave adds little → look in-process.

**Driver mode.** `ci/perf-testing/manual-dkg-under-load.sh` now takes
`PREPROC_ONLY=1`: it runs *only* `preproc-key-gen` (no key-mint/key-gen/decrypt),
timed, exporting `KMS_CLIENT_POLL_INTERVAL_MS` and logging to
`${LOG_DIR}/${RUN}-preproc-only.log`. It prints
`PREPROC-ONLY done: … duration=…s` at the end.

**Before you start — two gotchas:**
1. **Namespaces must differ** (or tear the enclave down first) — if the
   pr-preview puts both deployment types in the same namespace they collide. The
   enclave env is `kms-ci-titouantanguy-773`; the non-enclave env needs its own.
2. **Re-run the enclave with `PREPROC_ONLY` too**, so both sides are the exact
   same workload (the earlier enclave metrics log may have had other activity).

**Per-env procedure** (do once per env):

```bash
NS=<that env's namespace>
TAG=preproc-$( [ "$NS" = "kms-ci-titouantanguy-773" ] && echo enclave || echo threshold )-$(date +%H%M%S)
```

Terminal B (laptop) — metrics dashboard, logged for later review:
```bash
NAMESPACE=$NS PARTIES="1 2" INTERVAL=10 \
  LOG_FILE=~/Code/ai/DkgDdecBench/metrics-$TAG.log \
  bash ci/perf-testing/manual-metrics-watch.sh
```
Non-enclave notes: the **tunnel-CPU** column shows `n/a` (no
`enclave-network-tunnel` container) and **throughput** is now the pod's eth0 —
both expected. The `:9646` scrape still works because the per-party service
exposes it (verify once: `kubectl get svc -n $NS | grep 9646`).

Terminal A (laptop) — start the timed preproc inside the client pod:
```bash
kubectl cp ci/perf-testing/manual-dkg-under-load.sh $NS/kms-core-client-0:/tmp/driver.sh
kubectl exec -n $NS kms-core-client-0 -- \
  bash -c "PREPROC_ONLY=1 RUN=$TAG bash /tmp/driver.sh"
```
If `kms-core-client-0` doesn't exist in that ns, spawn a throwaway client pod
(see Step 3 "Alternative" above) and run
`kms-core-client -f /tmp/config.toml preproc-key-gen` directly.

Let it run ~3–5 min (enough metrics ticks), Ctrl-C both. The preproc keeps
running server-side — you only need the duration trend + the metrics window.

**Compare:** core utilization (higher on non-enclave ⇒ tunnel latency was the
idle cause), throughput, and the two `duration=…s` values.

---

## If it's NOT the enclave/network — in-process contention suspects

A code audit of the preprocessing path (gRPC `key_gen_preproc` →
`PreprocessingOrchestrator::orchestrate_dkg_processing` → per-session producer
`JoinSet` → `gen_bits_even` → `mult_list`/`robust_open` → per-session
`NetworkSession`) found the **steady-state per-session data path is genuinely
parallel**: each session owns its own `NetworkSession`, per-session round-counter
`RwLock`, per-(session,sender) receive channels, PRSS state, and RNG
(`BaseSession` is deliberately non-`Clone`, `base_session.rs:37-46`). There is
**no single global lock all 90 sessions serialize on** in the hot path. So if the
cores idle and it's not the tunnel, these structural throttles are the suspects,
ranked by plausibility:

### 1. Static tokio/rayon pool split + all DKG deserialization forced onto rayon
- One global rayon pool (`MPC_RAYON_THREAD_POOL`, `core/thread-handles/src/lib.rs:69-97`);
  every CPU task funnels through it via `spawn_compute_bound`, which pays a
  **~25 µs tokio→rayon `oneshot` round-trip per hop**.
- The pools are **statically partitioned** at startup: `num_tokio_threads =
  ceil(cpus/8)`, `num_rayon_threads = rest` (`core/service/src/conf/mod.rs:94-106`).
  Neither borrows the other's idle cores. ⚠️ Our override `rayonNumThreads=60` on
  a **52-core** enclave *oversubscribes* (60 rayon + 7 tokio > 52).
- DKG sets **every** session to `DeSerializationRunTime::Rayon`
  (`dkg_orchestrator.rs:349`), so all inbound-message deserialization hops onto
  rayon too. `gen_bits_even` does 3+ such hops per batch. Work sloshing between
  two fixed pools with a hop in between matches the "idle waves" signature.
- **Cheap test:** flip `dkg_orchestrator.rs:349` to `DeSerializationRunTime::Tokio`
  for one run; if idle waves shrink, this is real. Also try setting
  `rayonNumThreads` ≈ cores−tokio (i.e. ~45), not 60.

### 2. Producer→aggregator channels double-buffered (`CHANNEL_BUFFER_SIZE = 2`)
- Each of the 85 bit-producers can get at most **2** batches (batch = 10 000
  bits) ahead before `sender.send().await` parks it
  (`constants.rs:52-59`, producers block at `bits_producer.rs`). The consumer is
  a **single aggregator per data type** holding an `Arc<RwLock<…>>` write lock
  while draining (`dkg_orchestrator.rs`). If the single writer can't keep up, all
  85 producers stall in lock-step on a 2-slot channel → rayon compute stops →
  cores idle. Classic single-consumer throttle with almost no slack.
- **Cheap test:** `export MPC_DKG_CHANNEL_BUFFER_SIZE=16` (no rebuild — it's a
  `LazyLock` env var) and re-measure. Throughput up / idle waves down ⇒ confirmed.

### 3. Serial session creation (startup only)
- The 90 sessions are created in serial `for … .await` loops
  (`dkg_orchestrator.rs:286-303`), not concurrently — adds startup latency before
  any compute begins. Doesn't cause mid-run idle cores, but is a cheap
  `join_all` win if startup is a measurable fraction of total time.

### 4. `robust_open` per-round gather barrier (structural, expected)
- Each open can't finish until `≥ degree + 2t` shares arrive
  (`sharing/open.rs:466-472`) — a genuine per-round barrier; normally hidden by
  cross-session overlap. Watch: `try_reconstruct_from_shares` re-runs the full
  `par_iter` reconstruction on *each* newly-arrived share once over the bound
  (`open.rs:524-566`), which can repeatedly occupy rayon with partial
  reconstructions that get thrown away (compounds #1).
- **Cheap test:** count reconstruction attempts per open (`open.rs:530`); ≫1 per
  open on large batches ⇒ wasted rayon.

### Ruled out (checked, NOT serialization points)
- Per-session round-counter is a per-session `RwLock`; only `increase_round_counter`
  takes the write lock (`sending_service.rs`), never held across another
  session's `.await`.
- Sending path is `unbounded_channel` (no backpressure); receive mpsc is sized
  `MESSAGE_LIMIT = 70`, large vs per-round message count
  (`threshold-networking/constants.rs:6`).
- PRSS is precomputed per-epoch, only briefly read-locked at session creation.
- The `NETWORK_RECEIVED_MEASUREMENT` global `DashMap` is session-id-keyed
  (sharded, low contention).

### Recommended confirm-order (cheapest first)
1. `export MPC_DKG_CHANNEL_BUFFER_SIZE=16` — one env var, no rebuild (#2).
2. Set `rayonNumThreads` ≈ cores−tokio (~45, not 60) to stop oversubscription (#1).
3. Add rayon-busy vs tokio-busy gauges; look for anti-correlation during idle
   waves (#1).
4. Flip DKG deserialization to `Tokio` for one experiment (#1).

Key files: `core/thread-handles/src/lib.rs`, `core/service/src/bin/kms-server.rs:330-366`,
`core/service/src/conf/mod.rs:94-106`,
`core/threshold-execution/src/online/preprocessing/orchestration/dkg_orchestrator.rs`,
`.../orchestration/producers/bits_producer.rs`, `.../online/gen_bits.rs`,
`.../sharing/open.rs`, `core/threshold-networking/src/sending_service.rs`,
`core/threshold-execution/src/constants.rs`.

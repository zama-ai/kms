# KMS Performance Testing

This is a guide to the **Performance testing** GitHub Actions workflow (`.github/workflows/performance-testing.yml`), which you trigger manually from the Actions tab ("Run workflow").

The workflow spins up a real KMS deployment in Kubernetes, runs a suite of perf tests against it (keygen, CRS generation, public decrypt, and user decrypt), and posts a summary to Slack.
This document focuses on user/public decryption rate tests, which are the part most people come here to run.

## Decryption rate tests

The public- and user-decrypt tests offer a fixed number of requests per second for a fixed duration, then report whether the KMS kept up.
The current CI suite uses this to measure how many decryptions per second the deployment can handle.

## Managing rate scenarios

The rates to test and their pass/fail limits live in [`perf-scenarios.toml`](perf-scenarios.toml).
At submit time `generate-perf-workflow.py` expands it into the Argo workflow (filling the `# <<GENERATED:…>>` markers).
That TOML file is the source of truth for both public- and user-decrypt rate ladders.

```toml
[defaults]              # applied to every rate unless the rate overrides it
duration = 30           # measurement window, seconds
pause = 10              # cooldown after each rate and between its samples
maxfail = 0             # max failed requests, % of offered
maxshed = 0             # max shed (rate-limited) requests, % of offered
pct = 98                # min achieved/target rate, %
maxp50 = 0              # max median p50, ms (0 = do not check latency)
maxp99 = 0              # max median p99, ms (0 = do not check latency)
allowfail = false       # false → a breach fails the run; true → warns only

[scenarios.pdec]
key = "udec-key-gen"    # task providing the decryption key
after = ["crs-gen"]     # dependencies for the first rate
rates = [
  { rate = 1300, maxshed = 1, pct = 95, maxp50 = 25, maxp99 = 150 },     # gate
  { rate = 1500, maxfail = 10, maxshed = 25, pct = 70, allowfail = true },
  { rate = 1700, maxfail = 10, maxshed = 25, pct = 70, allowfail = true },
]

[scenarios.udec]
key = "udec-key-gen"
after = ["pdec"]
rates = [
  { rate = 2300, maxshed = 1, pct = 95, maxp50 = 75, maxp99 = 1500 },    # gate
  { rate = 2500, maxfail = 10, maxshed = 25, pct = 70, allowfail = true },
  { rate = 2700, maxfail = 10, maxshed = 25, pct = 70, allowfail = true },
  { rate = 2900, maxfail = 10, maxshed = 25, pct = 70, allowfail = true },
]
```

Rules, all enforced by the generator before submit:

- every `rates` entry is an inline table with a `rate` key.
- anything unspecified falls back to `[defaults]`.
- `key` names the task that supplies the key ID.
- `after` is an optional list of dependencies that must run before the first rate of a ladder.
  An entry is either an Argo DAG task, such as `crs-gen`, or a name from the `scenarios` table, such as `pdec`.
  A scenario name resolves to the last rate of that ladder.
- `maxp50` and `maxp99` come as a pair.
  Setting one alone is a half-configured gate and the generator rejects it.
- a rate cannot carry a latency limit while `allowfail = true`.
  A probe never fails, so the limit could not be enforced.

`keygen` and `crs` are one-shot setup and not configured here.

To preview the fully-expanded workflow locally:

```bash
python3 ci/perf-testing/generate-perf-workflow.py \
  --scenarios ci/perf-testing/perf-scenarios.toml \
  --template ci/perf-testing/argo-workflow/kms-perf-workflow-kms-ci.yaml -o -
```

## Quick start

To iterate on the decrypt tests, trigger the workflow with these values:

| Field | Value |
| --- | --- |
| Use workflow from | This branch |
| Build new Docker images | ✅ Checked |
| Deployment type | `threshold` |
| Enable core-client tracing logs | Unchecked (logging skews perf numbers) |
| FHE parameters for preprocessing and keygen | `Test` (faster setup) |
| TLS enabled | Unchecked (required for `threshold`) |
| KMS chart source ref | Leave empty |
| KMS chart version | `repository` |
| TKMS Infra chart version | `0.3.2` |
| KMS Core image tag | Leave empty (build fills it in) |
| KMS Core client image tag | Leave empty (build fills it in) |

Note that `FHE parameters` only affects preprocessing and keygen.
The decrypt scenarios always run with production-size `Default` parameters, so the numbers they produce are real regardless of this setting.

## Reading the results

Each rate is a **rung**.
The rates, their windows and their limits live in [`perf-scenarios.toml`](perf-scenarios.toml).
The Slack report labels each result by its target rate, for example `✅ 2300/s`.

The lowest rate of each kind is the **gate**.
A gate is the highest rate whose latency repeats, so a failure there comes from the code and not from the load the cluster carries.
Every rate above a gate is a **probe**.
A probe runs at or past the point where latency collapses, so it reports and warns but never fails the run.
A probe is the rate that carries `allowfail = true`.

The budget percentages (`maxfail`, `maxshed`) are shares of *offered* requests, not raw counts.
`maxshed=25` means "no more than 25% of offered requests were shed".
The rate percentage (`pct`) is the minimum acceptable ratio of achieved rate to target rate.

Every rung so far met its offered rate to within 0.2%, up to 2,800 req/s.
The budgets catch a collapse.
Latency degrades first, so the latency limits below are the real check.

### Latency limits

A gate must also hold its median latencies inside `maxp50` and `maxp99`, or the run fails.
A probe leaves both at 0, which turns the check off.
Without these limits, a build that meets the offered rate but takes much longer per request counts as a pass.

Each limit is about twice the worst median measured on any run so far.
A gate therefore fires on a gross regression rather than on how busy the cluster is.
That margin is deliberate and was bought the hard way.
The first limits were 2.5x the medians of a single quiet run.
Both gates then failed run 31800216785, a midday run whose medians were 1.5x to 7x that baseline at identical rate, payload and `max_in_flight`.
Nothing in the code explained the difference.
Treat a gate failure as a signal to compare against recent runs at the same time of day before you look for a regression.

The Slack line for a gate shows its limits as `gate=p50=...,p99=...`.

### When the suite stops

Each rung decides whether the next rung runs.
Any rung stops the suite when it misses its budget.
A gate also stops the suite when its median p99 passes **3000 ms**.
A gate that slow means the rates above it measure a system that already collapsed.
This limit stays above every gate `maxp99`, so a gate reports which limit it broke instead of silently stopping the run.
The suite reports every rung above a stopped rung as `⏭️ skipped`.

A probe never stops the suite on latency, however slow it gets.
Above a gate the rungs are not ordered by latency.
On 2026-08-10 udec 2700 measured a median p99 of 2302 ms.
Then udec 2750 ran clean at a p50 of 13.87 ms.
On 2026-08-13 the order was reversed.
A slow probe therefore says nothing about the rung above it, and a stop there would hide a rate that works.

The gate latency limits are not part of this decision either.
A gate that breaks its `maxp50` fails the run and still lets the higher rungs measure.
A red run therefore still shows where the ceiling was.

### Samples

The suite measures each rung three times in the same pod.
It reports the **median** achieved rate, p50 and p99 over those samples.
The budget check, the latency limits and the stop decision all run on those medians rather than on one draw.
One unlucky window no longer decides the run.
Samples settle for the same `pause` that separates rates.

Slack marks a line that carries medians with `n=3`.
The per-sample values live in the `samples` block of the rung JSON artifact.
The request counters on a line (`failed`, `shed`, `saturated`, `completed`, `offered`) belong to the sample that gave the median rate.
`samples.median_sample` names that sample.

Each median rounds against the rung, never in its favor.
The two directions are opposite:

- **Achieved rate** uses every sample and takes the *lower* median.
  An invalid sample counts as 0/s, the worst possible rate, so it can only make the rung look slower.
- **Latency** uses only the valid samples and takes the *upper* median.
  An invalid sample records 0 ms, the fastest possible value.
  It would pull the median down and let a rung pass its latency limit on a measurement that never ran.
  `samples.valid_samples` gives the count.

For p99 samples of 250 ms, invalid and 900 ms, the gate reads 900 ms and fails.
It does not read 250 ms and pass.
When all three samples are valid, both conventions return the middle value.
Slack marks a rung that has an invalid sample with `bad_samples=N`.

The first sample encrypts the ciphertext and writes it to disk.
Later samples read that file, which skips the key-set download and the switch-and-squash precompute.
A repeat costs about the measurement window, not a full setup.

To change the count, pass `-p samples=N` when you submit the Argo workflow by hand.
`samples=1` gives the old single-measurement behavior.
The GitHub Actions form does not offer this parameter.

### Outcomes

- **✅ pass** — inside budget, with no failed, shed or saturated traffic.
- **⚠️ warn** — inside budget but with some failed, shed or saturated traffic, or a probe outside budget.
  A probe never fails the run.
- **❌ fail** — a gate that misses its budget, breaks its latency limits, or reports a median p99 above 3000 ms.
  Such a rung also carries `stopped_climb=p99>3000ms`.
- **⏭️ skipped** — an earlier rung stopped the suite.

### Metric glossary

The Slack report and JSON artifacts use these fields.

The rung artifact holds two durations.
`total_duration_secs` at the top level is the wall time of every sample together.
`duration` inside `performance_metrics` is the measurement window of one sample.

**Outcome:** `offered`, `completed`, `failed`, `shed` and `saturated` come from the sample that gave the median rate.
The three percentiles are medians across samples.
A line can therefore pair `failed=0` with a p99 measured in a different window.

| Metric | Meaning |
| --- | --- |
| `offered` | Requests the rate generator scheduled. |
| `completed` | Requests that collected enough KMS responses. |
| `failed` | Requests the client sent that did not collect enough responses in time. |
| `shed` | Requests dropped before sending because `max_in_flight` was already reached. |
| `saturated` | `true` if anything was shed, or the post-run drain timed out with requests still in flight. |
| `achieved_rate` | `completed / collection_elapsed_seconds`. |
| `samples.count` | Measurements taken for this rung. |
| `samples.median_sample` | The sample (1-based) that supplied the reported counters. |
| `samples.achieved_rate` | Per-sample achieved rates, in submission order. |
| `samples.p50_ms` / `samples.p95_ms` / `samples.p99_ms` | Per-sample request latency percentiles. |
| `samples.valid` | Per-sample flag: did that measurement produce a metrics record. |
| `samples.exit_code` | Per-sample `kms-core-client` exit code. |
| `samples.valid_samples` | How many of `samples.count` were valid. This is the divisor for the latency medians. |
| `samples.median_achieved_rate` | Lower median of `samples.achieved_rate` over **all** samples. The budget check uses this value. |
| `samples.median_p50_ms` / `samples.median_p95_ms` / `samples.median_p99_ms` | Upper medians over the **valid** samples only. The report and the gate use these values. |
| `samples.records` | The full metrics record of every sample, in submission order. Each record holds its own `network` block, payload throughput and percentiles, plus `sample_number`, `start_epoch` and `end_epoch`. Use these to diagnose one bad sample, or to line a sample up against the `core-cpu-samples.log` artifact. |

**Payload throughput** (protobuf-encoded body only — excludes gRPC/TLS/header overhead):

| Metric | Meaning |
| --- | --- |
| `request_payload_bytes` | Total request bytes submitted, counted once per core target. |
| `request_payload_mib_per_sec` | Request bytes per second, in MiB/s. |
| `request_payload_avg_bytes` | Average encoded size of one request. |
| `response_payload_bytes` | Total response bytes accepted for verification/reconstruction (excludes late/abandoned responses). |
| `response_payload_mib_per_sec` | Response bytes per second, in MiB/s. |
| `response_payload_avg_bytes` | Average encoded size of one accepted response. |

The `request_payload_messages` / `response_payload_messages` counters record how many payloads went into the corresponding `_bytes` totals.

## Reusing Docker image tags

Building images is the slow part of a run.
If you just want to re-run the tests against images you already built, you can skip the rebuild.

**Find the tags from a previous run** — a run with `Build new Docker images` checked prints them in three places:

- A `KMS PERF IMAGE TAGS` block in the `performance-testing` job log, plus a matching section in the GitHub job summary.
- Earliest of all, a `KMS DOCKER IMAGE TAG` block from the `docker-build` job's first step, `KMS Docker image tag` — readable while the build is still running.
- The `Determine image tags` step logs.

Or pull them with `gh` once the run finishes:

```bash
gh run view <run-id> --repo zama-ai/kms --log \
  | rg "KMS DOCKER IMAGE TAG|KMS PERF IMAGE TAGS|KMS Core image tag|KMS Core client image tag"
```

If the logs aren't up yet, the tag is usually the first seven characters of the run's head commit SHA — but prefer the logged value when you can get it.

**Then re-run without building:**

| Field | Value |
| --- | --- |
| Build new Docker images | ⬜ Unchecked |
| KMS Core image tag | The `KMS Core image tag` from the previous run's summary |
| KMS Core client image tag | The `KMS Core client image tag` from the previous run's summary |

## Common pitfalls

- **TLS + `threshold` fails fast.** Non-enclave threshold TLS times out during deploy, so the workflow rejects it up front.
  Use `tls=false`, or switch to `thresholdWithEnclave`.
- **`kms_chart_version=repository` pulls the chart from a branch.** It uses `KMS chart source ref`, falling back to the "Use workflow from" ref when that's empty.
- **`build=true` ignores the image-tag fields.** Only fill those in when build is unchecked *and* you know the tags already exist in the registry.
- **Leave FHE params at `Test`** unless you specifically want production-size preproc/keygen.
  It doesn't touch the decrypt scenarios either way.

## Run flow

What the workflow does, end to end:

1. Optionally build the Docker images.
2. Resolve the core and core-client image tags.
3. Validate the deployment type and the TLS combination.
4. Verify the required image tags exist in the registry.
5. Deploy KMS to the `kms-ci` namespace via `ci/scripts/deploy.sh`.
6. Print a terse `before-perf` placement and network-counter snapshot.
7. Submit the Argo workflow (`ci/perf-testing/argo-workflow/kms-perf-workflow-kms-ci.yaml`).
8. Stream the Argo logs and send the Slack report.
9. Print terse `after-perf` KMS core pod network-counter deltas in the CI logs.

## Network diagnostics

Network diagnostics are printed directly in the GitHub Actions log.
The output is intentionally terse: node placement, KMS core pod placement, and after-run `eth0` rx/tx deltas for each running KMS core pod plus a total.

Each decrypt scenario also captures its own `eth0` rx/tx counters *inside* the Argo test pod, reported as `net_rx`/`net_tx` in Slack — the outer before/after diagnostics only include KMS core pods that are still running when the snapshot is taken.

Pod-level `ethtool` can't see AWS ENA allowance counters; those need a privileged node-level probe.

## Reference: workflow form fields

The full mapping from each form field to its internal effect.
Most runs only need the [Quick start](#quick-start) values above; this table is for when you need to understand or override something specific.

| Field | Effect |
| --- | --- |
| **Use workflow from** | Selects which branch/tag provides the workflow file. When `kms_chart_version=repository` and `KMS chart source ref` is empty, the KMS chart is also taken from this ref. |
| **Build new Docker images** | When checked, builds images from the selected ref and ignores the manual image-tag fields. Also builds the enclave image by default. Feeds `KMS_CORE_IMAGE_TAG` / `KMS_CORE_CLIENT_IMAGE_TAG`. |
| **Deployment type** | `threshold` → non-enclave `core-service`, path suffix `kms-ci`. `thresholdWithEnclave` → `core-service-enclave`, path suffix `kms-enclave-ci`. |
| **Enable core-client tracing logs** | Adds `--logs` to `kms-core-client`. Keep off for measurements — logging materially affects perf. |
| **FHE parameters for preprocessing and keygen** | Controls only `preproc-key-gen` and `key-gen`. Decrypt scenarios are pinned to `Default`. |
| **TLS enabled** | Only valid with `thresholdWithEnclave` here; non-enclave threshold TLS fails fast during deploy. |
| **KMS chart source ref** | Override used only when `kms_chart_version=repository`. Defaults to the "Use workflow from" ref when empty. |
| **KMS chart version** | `repository` deploys the chart from the source ref; a version like `1.4.17` deploys that OCI chart instead. |
| **TKMS Infra chart version** | Version of the TKMS infra chart that provisions S3/IAM/KMS-party resources. |
| **KMS Core image tag** | Used only when build is unchecked. Must be an existing `core-service` (or `core-service-enclave`) tag matching the deployment type. |
| **KMS Core client image tag** | Used only when build is unchecked. Must be an existing `core-client` tag. |

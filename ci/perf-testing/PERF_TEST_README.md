# KMS Performance Testing

This is a guide to the **Performance testing** GitHub Actions workflow
(`.github/workflows/performance-testing.yml`), which you trigger manually from
the Actions tab ("Run workflow").

The workflow spins up a real KMS deployment in Kubernetes, runs a suite of perf
tests against it (keygen, CRS generation, public decrypt, and user decrypt),
and posts a summary to Slack. This document focuses on user/public decryption rate tests,
which are the part most people come here to run.

## Decryption rate tests

The public- and user-decrypt tests offer a fixed number of requests per second
for a fixed duration, then report whether the KMS kept up. The current CI suite
uses this to measure how many decryptions per second the deployment can handle.

## Managing rate scenarios

The rates to test and their pass/fail limits live in [`perf-scenarios.toml`](perf-scenarios.toml). At submit time
`generate-perf-workflow.py` expands it into the Argo workflow (filling the `# <<GENERATED:…>>` markers). That TOML
file is the source of truth for both public- and user-decrypt rate ladders.

```toml
[defaults]              # applied to every rate unless the rate overrides it
duration = 60           # measurement window, seconds
pause = 10              # cooldown after each completed measurement
maxfail = 0             # max failed requests, % of offered
maxshed = 0             # max shed (rate-limited) requests, % of offered
pct = 98                # min achieved/target rate, %
allowfail = false       # false → a breach fails the run; true → warns only

[scenarios.pdec]
key = "udec-key-gen"    # task providing the decryption key
after = ["crs-gen"]     # dependencies for the first rate
rates = [
  { rate = 1100 },
  { rate = 1300, maxfail = 1, maxshed = 1, pct = 90 },
  { rate = 1500, maxfail = 10, maxshed = 25, pct = 70, allowfail = true },
]

[scenarios.udec]
key = "udec-key-gen"
after = ["pdec"]
rates = [
  { rate = 2400 },                                              # uses the defaults
  { rate = 2700, maxfail = 1, maxshed = 1, pct = 95 },          # override some limits
  { rate = 2750, maxfail = 10, maxshed = 25, pct = 70, allowfail = true },
]
```

Rules:

- every `rates` entry is an inline table with a `rate` key;
- anything unspecified falls back to `[defaults]`;
- `key` names the task that supplies the key ID; `after` is an optional list of
  dependencies that must run before the first rate of a ladder. The list can be either an Argo DAG task, e.g. `crs-gen`, or an entry from the `scenarios` table, e.g. `pdec`.

`keygen`/`crs` are one-shot setup and not configured here.

To preview the fully-expanded workflow locally:

```bash
python3 ci/perf-testing/generate-perf-workflow.py \
  --scenarios ci/perf-testing/perf-scenarios.toml \
  --template ci/perf-testing/argo-workflow/kms-perf-workflow-kms-ci.yaml -o -
```

## Quick start

To iterate on the decrypt tests, trigger the workflow with these values:

| Field                                       | Value                                  |
| ------------------------------------------- | -------------------------------------- |
| Use workflow from                           | This branch                            |
| Build new Docker images                     | ✅ Checked                             |
| Deployment type                             | `threshold`                            |
| Enable core-client tracing logs             | Unchecked (logging skews perf numbers) |
| FHE parameters for preprocessing and keygen | `Test` (faster setup)                  |
| TLS enabled                                 | Unchecked (required for `threshold`)   |
| KMS chart source ref                        | Leave empty                            |
| KMS chart version                           | `repository`                           |
| TKMS Infra chart version                    | `0.3.2`                                |
| KMS Core image tag                          | Leave empty (build fills it in)        |
| KMS Core client image tag                   | Leave empty (build fills it in)        |

Note that `FHE parameters` only affects preprocessing and keygen. The decrypt
scenarios always run with production-size `Default` parameters, so the numbers
they produce are real regardless of this setting.

Rate-tests run on a `c6in.32xlarge` instance to get as much network bandwidth as possible. Both threshold deployment
modes configure a 30,000-entry MetaStore decryption store for these tests.

## Reading the results

The public- and user-decrypt rates, their durations, and their budgets
are defined in [`perf-scenarios.toml`](perf-scenarios.toml). The Slack report
labels each result by its target rate, for example `✅ 2400/s`.

The budget percentages (`maxfail`, `maxshed`) are shares of _offered_ requests,
not raw counts — `maxshed=25` means "no more than 25% of offered requests were
shed." The rate percentage (`pct`) is the minimum acceptable ratio of achieved
rate to target rate.

Each scenario lands on one of these outcomes:

- **✅ pass** — stayed inside its budget with zero failed, shed, or saturated
  traffic.
- **⚠️ warn** — either stayed inside budget but saw _some_ failed/shed/saturated
  traffic, or has `allowfail = true` and exceeded its budget.
- **❌ fail** — a scenario without `allowfail = true` went outside its budget.
- **⏭️ skipped** — an earlier scenario failed, so this one didn't run (scenarios
  run in ascending order and stop climbing once one falls over).

### Metric glossary

The Slack report and JSON artifacts use these fields.

**Outcome:**

| Metric                        | Meaning                                                                                     |
| ----------------------------- | ------------------------------------------------------------------------------------------- |
| `offered`                     | Requests the rate generator scheduled.                                                      |
| `completed`                   | Requests that collected enough KMS responses                                                |
| `completed_in_window`         | Requests completed during the configured measurement window.                                |
| `completed_during_drain`      | Requests completed after the measurement window while draining in-flight work.              |
| `measurement_elapsed_seconds` | Duration of the measurement window.                                                         |
| `drain_elapsed_seconds`       | Time spent draining in-flight work after the measurement window.                            |
| `failed`                      | Requests that were sent but didn't collect enough responses in time.                        |
| `shed`                        | Requests dropped before sending because `max_in_flight` was already reached.                |
| `saturated`                   | `true` if anything was shed, or the post-run drain timed out with requests still in flight. |
| `achieved_rate`               | `completed_in_window / measurement_elapsed_seconds`.                                        |

**Payload throughput** (protobuf-encoded body only — excludes gRPC/TLS/header
overhead):

| Metric                             | Meaning                                                                                            |
| ---------------------------------- | -------------------------------------------------------------------------------------------------- |
| `request_payload_bytes`            | Total request bytes submitted, counted once per core target.                                       |
| `request_payload_mib_per_sec`      | Request bytes per measurement-window second, in MiB/s.                                             |
| `request_payload_avg_bytes`        | Average encoded size of one request.                                                               |
| `response_payload_bytes`           | Total response bytes accepted for verification/reconstruction (excludes late/abandoned responses). |
| `response_payload_bytes_in_window` | Response bytes accepted during the measurement window.                                             |
| `response_payload_mib_per_sec`     | Measurement-window response bytes per second, in MiB/s.                                            |
| `response_payload_avg_bytes`       | Average encoded size of one accepted response.                                                     |

The `request_payload_messages` / `response_payload_messages` counters record how
many payloads went into the corresponding `_bytes` totals;
`response_payload_messages_in_window` is the same, counting inside the measurement-window.

**RPC diagnostics:**

One aggregate `rpc_diagnostics` object is emitted at the end of each public- or
user-decrypt rate-test rung. It covers every RPC made during that rung;
diagnostics are not emitted per request or pacing tick. `submit_status` and
`result_status` count gRPC calls by status code; successful calls use `ok`, and
zero-valued statuses are omitted. The `outstanding_*` fields report work left
after the measurement window and its bounded logical-request drain; the drain
lasts up to 30 seconds but ends early when all logical requests finish. The
`*_peak_in_flight` fields show peak concurrency across the full rate test.
`result_retries` counts repeat
result calls after a not-ready response. `post_quorum_tasks` counts per-core
result tasks left after enough responses were collected, while
`post_quorum_tasks_drained` counts how many finished before metrics were emitted.
`outstanding_post_quorum_tasks` is the remainder still running after the drain.
For the synchronous endpoint, the combined call is recorded as a result RPC.
For result polling, `unavailable` normally means the KMS knows the request but
has not produced its result yet; it does not by itself indicate a network outage.

The statuses normally relevant to these tests are:

- `ok` — the RPC succeeded.
- `unavailable` — commonly an expected result poll whose result is still pending.
- `resource_exhausted` — KMS admission capacity or rate limiting was exhausted.
- `not_found` — the requested result is absent, for example after cache eviction;
  unexpected during a healthy run.
- Any other status is uncommon and should be investigated with the client and
  KMS logs.

For example, a healthy asynchronous run might report:

```json
{
	"submit_status": { "ok": 1872000 },
	"result_status": { "ok": 1872000, "unavailable": 936000 },
	"outstanding_submit_rpcs": 0,
	"submit_peak_in_flight": 742,
	"outstanding_result_rpcs": 0,
	"result_peak_in_flight": 1534,
	"result_retries": 936000,
	"post_quorum_tasks": 576000,
	"post_quorum_tasks_drained": 576000,
	"outstanding_post_quorum_tasks": 0
}
```

## Reusing Docker image tags

Building images is the slow part of a run. If you just want to re-run the tests
against images you already built, you can skip the rebuild.

**Find the tags from a previous run** — a run with `Build new Docker images`
checked prints them in three places:

- A `KMS PERF IMAGE TAGS` block in the `performance-testing` job log, plus a
  matching section in the GitHub job summary.
- Earliest of all, a `KMS DOCKER IMAGE TAG` block from the `docker-build` job's
  first step, `KMS Docker image tag` — readable while the build is still
  running.
- The `Determine image tags` step logs.

Or pull them with `gh` once the run finishes:

```bash
gh run view <run-id> --repo zama-ai/kms --log \
  | rg "KMS DOCKER IMAGE TAG|KMS PERF IMAGE TAGS|KMS Core image tag|KMS Core client image tag"
```

If the logs aren't up yet, the tag is usually the first seven characters of the
run's head commit SHA — but prefer the logged value when you can get it.

**Then re-run without building:**

| Field                     | Value                                                           |
| ------------------------- | --------------------------------------------------------------- |
| Build new Docker images   | ⬜ Unchecked                                                    |
| KMS Core image tag        | The `KMS Core image tag` from the previous run's summary        |
| KMS Core client image tag | The `KMS Core client image tag` from the previous run's summary |

## Common pitfalls

- **TLS + `threshold` fails fast.** Non-enclave threshold TLS times out during
  deploy, so the workflow rejects it up front. Use `tls=false`, or switch to
  `thresholdWithEnclave`.
- **`kms_chart_version=repository` pulls the chart from a branch.** It uses
  `KMS chart source ref`, falling back to the "Use workflow from" ref when that's
  empty.
- **`build=true` ignores the image-tag fields.** Only fill those in when build is
  unchecked _and_ you know the tags already exist in the registry.
- **Leave FHE params at `Test`** unless you specifically want production-size
  preproc/keygen. It doesn't touch the decrypt scenarios either way.

## Run flow

What the workflow does, end to end:

1. Optionally build the Docker images.
2. Resolve the core and core-client image tags.
3. Validate the deployment type and the TLS combination.
4. Verify the required image tags exist in the registry.
5. Deploy KMS to the `kms-ci` namespace via `ci/scripts/deploy.sh`.
6. Print a terse `before-perf` network snapshot and start the diagnostics.
7. Submit the Argo workflow
   (`ci/perf-testing/argo-workflow/kms-perf-workflow-kms-ci.yaml`).
8. Stream the Argo logs and send the Slack report.
9. Print terse `after-perf` KMS core pod network-counter deltas in the CI logs.
10. Upload CPU, KMS metric, ENA counter, and pod placement samples.

## Network diagnostics

Network diagnostics are printed directly in the GitHub Actions log. The output
is intentionally terse: KMS core pod placement and after-run `eth0` rx/tx
deltas for each running KMS core pod plus a total. The `perf-diagnostics`
artifact contains the full time series from the KMS metrics endpoints and ENA
interfaces, ENA probe pod states and events, plus a placement snapshot
containing the KMS cores and the first rate-test client pod.

Each decrypt scenario also captures its own `eth0` rx/tx counters inside the
Argo test pod. The core client samples them around the measurement window, and
the resulting rates are reported as `net_rx`/`net_tx` in Slack.

ENA (Elastic Network Adapter) is AWS's EC2 network interface and driver. It
exposes hardware-level throttling and allowance counters that ordinary pod
network interfaces do not. The workflow runs a host-networked DaemonSet on the
KMS and benchmark node pools to collect them.

## Analyze a completed run

Download the artifacts for one GitHub Actions run and produce a Markdown report:

```bash
python3 ci/scripts/analyze_perf_run.py --run-id 123456789 --output perf-report.md
```

The command stores the downloaded inputs in `perf-run-123456789/`. Re-run the
analysis offline, or produce machine-readable output, with:

```bash
python3 ci/scripts/analyze_perf_run.py \
  --artifacts perf-run-123456789 \
  --format json \
  --output perf-report.json
```

Run-ID mode requires an authenticated `gh` CLI. The analyzer reports missing or
partial instrumentation while retaining any rate results it can parse.

## Reference: workflow form fields

The full mapping from each form field to its internal effect. Most runs only
need the [Quick start](#quick-start) values above; this table is for when you
need to understand or override something specific.

| Field                                           | Effect                                                                                                                                                                                         |
| ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Use workflow from**                           | Selects which branch/tag provides the workflow file. When `kms_chart_version=repository` and `KMS chart source ref` is empty, the KMS chart is also taken from this ref.                       |
| **Build new Docker images**                     | When checked, builds images from the selected ref and ignores the manual image-tag fields. Also builds the enclave image by default. Feeds `KMS_CORE_IMAGE_TAG` / `KMS_CORE_CLIENT_IMAGE_TAG`. |
| **Deployment type**                             | `threshold` → non-enclave `core-service`, path suffix `kms-ci`. `thresholdWithEnclave` → `core-service-enclave`, path suffix `kms-enclave-ci`.                                                 |
| **Enable core-client tracing logs**             | Adds `--logs` to `kms-core-client`. Keep off for measurements — logging materially affects perf.                                                                                               |
| **FHE parameters for preprocessing and keygen** | Controls only `preproc-key-gen` and `key-gen`. Decrypt scenarios are pinned to `Default`.                                                                                                      |
| **TLS enabled**                                 | Only valid with `thresholdWithEnclave` here; non-enclave threshold TLS fails fast during deploy.                                                                                               |
| **KMS chart source ref**                        | Override used only when `kms_chart_version=repository`. Defaults to the "Use workflow from" ref when empty.                                                                                    |
| **KMS chart version**                           | `repository` deploys the chart from the source ref; a version like `1.4.17` deploys that OCI chart instead.                                                                                    |
| **TKMS Infra chart version**                    | Version of the TKMS infra chart that provisions S3/IAM/KMS-party resources.                                                                                                                    |
| **KMS Core image tag**                          | Used only when build is unchecked. Must be an existing `core-service` (or `core-service-enclave`) tag matching the deployment type.                                                            |
| **KMS Core client image tag**                   | Used only when build is unchecked. Must be an existing `core-client` tag.                                                                                                                      |

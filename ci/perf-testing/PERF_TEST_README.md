# KMS Performance Testing

This is a guide to the **Performance testing** GitHub Actions workflow
(`.github/workflows/performance-testing.yml`), which you trigger manually from
the Actions tab ("Run workflow").

The workflow spins up a real KMS deployment in Kubernetes, runs a suite of perf
tests against it (keygen, CRS generation, public decrypt, and user decrypt),
and posts a summary to Slack. This document focuses on the **user-decrypt**
test, which is the part most people come here to run.

## User-decrypt rate test

The user-decrypt test offers a fixed number of requests per second for a fixed
duration, then reports whether the KMS kept up. The current CI suite uses this
to measure how many user decryptions per second the deployment can handle.

## Quick start

To iterate on the user-decrypt test, trigger the workflow with these values:

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

Note that `FHE parameters` only affects preprocessing and keygen. The decrypt
scenarios always run with production-size `Default` parameters, so the numbers
they produce are real regardless of this setting.

## Reading the results

The user-decrypt test runs three scenarios, each sending `1 × euint64` for 60
seconds:

| Scenario | Rate | Budget (allowed slack) |
| --- | ---: | --- |
| stable | 2,400 req/s | no failures, no shedding, ≥98% of target rate |
| near-limit | 2,700 req/s | ≤1% failures, ≤1% shed, ≥95% of target rate |
| over-limit | 2,750 req/s | ≤10% failures, ≤25% shed, ≥70% of target rate |

The budget percentages (`maxfail`, `maxshed`) are shares of *offered* requests,
not raw counts — `maxshed=25` means "no more than 25% of offered requests were
shed." The rate percentage (`pct`) is the minimum acceptable ratio of achieved
rate to target rate.

Each scenario lands on one of these outcomes:

- **✅ pass** — stayed inside its budget with zero failed, shed, or saturated
  traffic.
- **⚠️ warn** — either stayed inside budget but saw *some* failed/shed/saturated
  traffic, **or** it's the `2,750` probe, which is expected to run hot and is
  never allowed to fail the workflow.
- **❌ fail** — a `2,400` or `2,700` scenario went outside its budget. This
  fails the whole workflow.
- **⏭️ skipped** — an earlier scenario failed, so this one didn't run (scenarios
  run in ascending order and stop climbing once one falls over).

The `2,750` scenario is deliberately just above the clean `2,700` run: it probes
where capacity starts to break down, so it warns instead of failing.

### Metric glossary

The Slack report and JSON artifacts use these fields.

**Outcome:**

| Metric | Meaning |
| --- | --- |
| `offered` | Requests the rate generator scheduled. |
| `completed` | Requests that collected enough KMS responses. |
| `failed` | Requests that were sent but didn't collect enough responses in time. |
| `shed` | Requests dropped before sending because `max_in_flight` was already reached. |
| `saturated` | `true` if anything was shed, or the post-run drain timed out with requests still in flight. |
| `achieved_rate` | `completed / collection_elapsed_seconds`. |

**Payload throughput** (protobuf-encoded body only — excludes gRPC/TLS/header
overhead):

| Metric | Meaning |
| --- | --- |
| `request_payload_bytes` | Total request bytes submitted, counted once per core target. |
| `request_payload_mib_per_sec` | Request bytes per second, in MiB/s. |
| `request_payload_avg_bytes` | Average encoded size of one request. |
| `response_payload_bytes` | Total response bytes accepted for reconstruction (excludes late/abandoned responses). |
| `response_payload_mib_per_sec` | Response bytes per second, in MiB/s. |
| `response_payload_avg_bytes` | Average encoded size of one accepted response. |

The `request_payload_messages` / `response_payload_messages` counters record how
many payloads went into the corresponding `_bytes` totals.

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

| Field | Value |
| --- | --- |
| Build new Docker images | ⬜ Unchecked |
| KMS Core image tag | The `KMS Core image tag` from the previous run's summary |
| KMS Core client image tag | The `KMS Core client image tag` from the previous run's summary |

## Common pitfalls

- **TLS + `threshold` fails fast.** Non-enclave threshold TLS times out during
  deploy, so the workflow rejects it up front. Use `tls=false`, or switch to
  `thresholdWithEnclave`.
- **`kms_chart_version=repository` pulls the chart from a branch.** It uses
  `KMS chart source ref`, falling back to the "Use workflow from" ref when that's
  empty.
- **`build=true` ignores the image-tag fields.** Only fill those in when build is
  unchecked *and* you know the tags already exist in the registry.
- **Leave FHE params at `Test`** unless you specifically want production-size
  preproc/keygen. It doesn't touch the decrypt scenarios either way.

## Run flow

What the workflow does, end to end:

1. Optionally build the Docker images.
2. Resolve the core and core-client image tags.
3. Validate the deployment type and the TLS combination.
4. Verify the required image tags exist in the registry.
5. Deploy KMS to the `kms-ci` namespace via `ci/scripts/deploy.sh`.
6. Print a terse `before-perf` placement and network-counter snapshot.
7. Submit the Argo workflow
   (`ci/perf-testing/argo-workflow/kms-perf-workflow-kms-ci.yaml`).
8. Stream the Argo logs and send the Slack report.
9. Print terse `after-perf` KMS core pod network-counter deltas in the CI logs.

## Network diagnostics

Network diagnostics are printed directly in the GitHub Actions log. The output
is intentionally terse: node placement, KMS core pod placement, and after-run
`eth0` rx/tx deltas for each running KMS core pod plus a total.

Each user-decrypt scenario also captures its own `eth0` rx/tx counters *inside* the
Argo test pod, reported as `net_rx`/`net_tx` in Slack — the outer before/after
diagnostics only include KMS core pods that are still running when the snapshot
is taken.

Pod-level `ethtool` can't see AWS ENA allowance counters; those need a
privileged node-level probe.

## Reference: workflow form fields

The full mapping from each form field to its internal effect. Most runs only
need the [Quick start](#quick-start) values above; this table is for when you
need to understand or override something specific.

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

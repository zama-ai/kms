# KMS Performance Testing Workflow

This documents the GitHub Actions manual dispatch form for
`.github/workflows/performance-testing.yml`.

## Recommended Sustained UDEC Iteration Run

Use these values when iterating on the sustained-rate user-decrypt test:

| GitHub field | Value |
| --- | --- |
| Use workflow from | This branch |
| Build new Docker images | Checked |
| Deployment type | `threshold` |
| Enable core-client tracing logs | Prefer unchecked while measuring perf |
| FHE parameters for preprocessing and keygen | `Test` for faster iteration |
| TLS enabled | Unchecked for `threshold` |
| KMS chart source ref | Empty |
| KMS chart version | `repository` |
| TKMS Infra chart version | `0.3.2` |
| KMS Core image tag | Empty when build is checked |
| KMS Core client image tag | Empty when build is checked |

The current workflow first runs baseline setup/CRS/public-decrypt checks, then
runs three sustained `user-decrypt` rate scenarios for `60s` each, payload
`1 x euint64`:

| Scenario | Rate | Parameter set percentage limits |
| --- | ---: | --- |
| `stable` | `2400 req/s` | `maxfail=0,maxshed=0,pct=98` |
| `near-limit` | `2700 req/s` | `maxfail=1,maxshed=1,pct=95` |
| `over-limit` | `2750 req/s` | `maxfail=10,maxshed=25,pct=70` |

`maxfail` and `maxshed` are percentages of `offered`, not request counts. For
example, `maxshed=5` means `shed / offered <= 5%`. `pct` is the minimum accepted
`achieved_rate / target_rate`, also as a percentage. A scenario outside its
parameter set fails the workflow. A `WARN` line means the scenario stayed inside
its parameter set but still saw failed, shed, or saturated traffic.

## Sustained UDEC Metrics

| Metric | Meaning |
| --- | --- |
| `offered` | Requests scheduled by the rate generator. |
| `completed` | Requests that collected enough KMS responses. |
| `failed` | Sent/launched requests that did not collect enough KMS responses in time. |
| `shed` | Scheduled requests not sent because `max_in_flight` was already reached. |
| `saturated` | `true` if any request was shed, or if the post-run drain timed out with requests still in flight. |
| `achieved_rate` | `completed / collection_elapsed_seconds`. |
| `request_payload_bytes` | Sum of protobuf-encoded user-decrypt request payloads submitted to KMS cores. This counts one payload per core target and excludes gRPC/TLS/header overhead. |
| `request_payload_messages` | Number of submitted core-target request payloads counted in `request_payload_bytes`. |
| `request_payload_mib_per_sec` | `request_payload_bytes / collection_elapsed_seconds`, in MiB/s. |
| `request_payload_avg_bytes` | Average protobuf-encoded size of one submitted user-decrypt request payload. |
| `response_payload_bytes` | Sum of protobuf-encoded user-decrypt response payloads accepted for quorum reconstruction. This excludes gRPC/TLS/header overhead and abandoned late responses. |
| `response_payload_messages` | Number of accepted response payloads counted in `response_payload_bytes`. |
| `response_payload_mib_per_sec` | `response_payload_bytes / collection_elapsed_seconds`, in MiB/s. |
| `response_payload_avg_bytes` | Average protobuf-encoded size of one accepted user-decrypt response payload. |

## Reusing Docker Image Tags

If a run used `Build new Docker images=true`, the `performance-testing` job
prints a `KMS PERF IMAGE TAGS` block and adds a `KMS perf image tags` section to
the GitHub job summary.

Early in the Docker build, `performance-testing/docker-build / docker-build/golden-image-tag` has a first step named
`KMS Docker image tag`. It prints a `KMS DOCKER IMAGE TAG` block, emits a GitHub notice, and adds a `KMS Docker image
tag` summary section. This is the earliest place to read the tag while the build is still running.

To rerun without rebuilding:

| GitHub field | Value |
| --- | --- |
| Build new Docker images | Unchecked |
| KMS Core image tag | The `KMS Core image tag` from the previous run summary |
| KMS Core client image tag | The `KMS Core client image tag` from the previous run summary |

The same tags are also visible in the `Determine image tags` step logs. After
registry verification, the summary lists the exact image names that were checked.

With `gh`, after the run completes:

```bash
gh run view <run-id> --repo zama-ai/kms --log \
  | rg "KMS DOCKER IMAGE TAG|KMS PERF IMAGE TAGS|KMS Core image tag|KMS Core client image tag"
```

If logs are not available yet, the non-scheduled perf image tag is usually the
first seven characters of the run head SHA. Prefer the summary/log value when
available.

## Field Mapping

| GitHub field | Workflow input | Internal env/config | Effect |
| --- | --- | --- | --- |
| Use workflow from | GitHub ref selector | `github.ref` | Selects which branch/tag provides the workflow file. If `kms_chart_version=repository` and `kms_branch` is empty, the KMS chart is also checked out from this ref. |
| Build new Docker images | `inputs.build` | `needs.docker-build.outputs.image_tag` -> `KMS_CORE_IMAGE_TAG`, `KMS_CORE_CLIENT_IMAGE_TAG` | When checked, CI builds images from the selected ref and ignores the manual image-tag fields. The reusable Docker workflow also builds the enclave image by default. |
| Deployment type | `inputs.deployment_type` | `DEPLOYMENT_TYPE`; also selects `PATH_SUFFIX` | Chooses the KMS deployment layout. `threshold` uses non-enclave `core-service` and `PATH_SUFFIX=kms-ci`; `thresholdWithEnclave` uses `core-service-enclave` and `PATH_SUFFIX=kms-enclave-ci`. |
| Enable core-client tracing logs | `inputs.client_logs` | `CLIENT_LOGS`; Argo parameter `client-logs` | Adds `--logs` to `kms-core-client` in perf tasks when enabled. Logging can materially affect local perf and should usually be off for measurements. |
| FHE parameters for preprocessing and keygen | `inputs.fhe_params` | `FHE_PARAMS`; Argo parameter `fhe-params` | Controls the baseline `preproc-key-gen` and `key-gen` tasks. The UDEC setup and sustained decrypt scenarios are fixed to `Default` so decrypt perf uses real parameters. |
| TLS enabled | `inputs.tls` | `TLS`; Argo parameter `tls`; deploy script `ENABLE_TLS` | Only supported with `deployment_type=thresholdWithEnclave` in this workflow. Non-enclave threshold TLS currently times out during deploy and fails fast. |
| KMS chart source ref | `inputs.kms_branch` | `KMS_BRANCH` | Optional override used only when `kms_chart_version=repository`. Leave empty for normal branch runs; it defaults to the ref selected in "Use workflow from". |
| KMS chart version | `inputs.kms_chart_version` | `KMS_CHART_VERSION`; deploy script `--kms-chart-version` | `repository` deploys the chart from `KMS_BRANCH`. A version such as `1.4.17` deploys the OCI chart version instead. |
| TKMS Infra chart version | `inputs.tkms_infra_chart_version` | `TKMS_INFRA_CHART_VERSION`; deploy script `--tkms-infra-version` | Selects the TKMS infra chart version used to create S3/IAM/KMS party resources. |
| KMS Core image tag | `inputs.kms_core_image_tag` | `KMS_CORE_IMAGE_TAG` | Used only when build is unchecked. Must refer to an existing `core-service` or `core-service-enclave` tag, depending on deployment type. |
| KMS Core client image tag | `inputs.kms_core_client_image_tag` | `KMS_CORE_CLIENT_IMAGE_TAG` | Used only when build is unchecked. Must refer to an existing `core-client` tag. |

## Run Flow

1. Optionally build Docker images.
2. Resolve `KMS_CORE_IMAGE_TAG` and `KMS_CORE_CLIENT_IMAGE_TAG`.
3. Validate the deployment type and supported TLS combination.
4. Verify required image tags exist in the registry.
5. Deploy KMS to the `kms-ci` namespace through `ci/scripts/deploy.sh`.
6. Capture `before-perf` Kubernetes and pod-level network diagnostics.
7. Submit `ci/perf-testing/argo-workflow/sustained-rate-kms-workflow-kms-ci.yaml`.
8. Stream Argo logs and send the Slack report.
9. Capture `after-perf` network diagnostics and upload the `network-diagnostics` artifact.

## Network Diagnostics

The `network-diagnostics` artifact contains `before-perf` and `after-perf`
snapshots. These include pod placement, node labels, recent events, pod MTU,
pod network counters, readable TCP sysctls, and opportunistic `ip`, `ss`, and
`ethtool` output from running containers. The artifact also includes
`pod-interface-counter-delta.tsv` when both snapshots are available.

Pod-level `ethtool` usually cannot see AWS ENA allowance counters. Those require
a privileged node-level probe.

## Common Pitfalls

- Leaving `tls=true` with `deployment_type=threshold` fails fast. Use `tls=false`, or choose `thresholdWithEnclave`.
- `kms_chart_version=repository` means the chart comes from `KMS chart source ref`, or from "Use workflow from" when that field is empty.
- `build=true` means the image-tag fields are ignored. Use `build=false` only when you know the exact core and client image tags already exist.
- Leave `FHE parameters for preprocessing and keygen` at `Test` unless you specifically want the baseline preproc/keygen tasks to use production-size parameters. Sustained UDEC decrypts still use `Default`.

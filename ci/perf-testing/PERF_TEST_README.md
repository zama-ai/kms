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
| Performance test suite | `sustained-rate-udec` |
| Enable core-client tracing logs | Prefer unchecked while measuring perf |
| FHE parameters for preprocessing and keygen | `Test` for faster iteration |
| TLS enabled | Unchecked for `threshold` |
| KMS branch | Empty |
| KMS chart version | `repository` |
| TKMS Infra chart version | `0.3.2` |
| KMS Core image tag | Empty when build is checked |
| KMS Core client image tag | Empty when build is checked |

The current sustained-rate workflow runs six `user-decrypt` rate scenarios:
`2700`, `2800`, `2900`, `3000`, `4000`, and `5000 req/s`, for `60s` each,
payload `1 x euint64`.

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
| Performance test suite | `inputs.test_suite` | `TEST_SUITE`; selects Argo workflow template | `sustained-rate-udec` uses `ci/perf-testing/argo-workflow/sustained-rate-kms-workflow-kms-ci.yaml` and only supports threshold deployments. `burst` is temporarily disabled on this branch while iterating on sustained UDEC. |
| Enable core-client tracing logs | `inputs.client_logs` | `CLIENT_LOGS`; Argo parameter `client-logs` | Adds `--logs` to `kms-core-client` in perf tasks when enabled. Logging can materially affect local perf and should usually be off for measurements. |
| FHE parameters for preprocessing and keygen | `inputs.fhe_params` | `FHE_PARAMS`; Argo parameter `fhe-params` | Passed into Argo. `Test` is faster and useful for iteration; `Default` is closer to production sizing. |
| TLS enabled | `inputs.tls` | `TLS`; Argo parameter `tls`; deploy script `ENABLE_TLS` | Only valid with `deployment_type=thresholdWithEnclave` in this workflow. Non-enclave deployments must use `tls=false`; the workflow fails fast otherwise. |
| KMS branch | `inputs.kms_branch` | `KMS_BRANCH` | Used only when `kms_chart_version=repository`. If empty, defaults to `github.ref` from "Use workflow from". |
| KMS chart version | `inputs.kms_chart_version` | `KMS_CHART_VERSION`; deploy script `--kms-chart-version` | `repository` deploys the chart from the checked-out repo. A version such as `1.4.17` deploys the OCI chart version. |
| TKMS Infra chart version | `inputs.tkms_infra_chart_version` | `TKMS_INFRA_CHART_VERSION`; deploy script `--tkms-infra-version` | Selects the TKMS infra chart version used to create S3/IAM/KMS party resources. |
| KMS Core image tag | `inputs.kms_core_image_tag` | `KMS_CORE_IMAGE_TAG` | Used only when build is unchecked. Must refer to an existing `core-service` or `core-service-enclave` tag, depending on deployment type. |
| KMS Core client image tag | `inputs.kms_core_client_image_tag` | `KMS_CORE_CLIENT_IMAGE_TAG` | Used only when build is unchecked. Must refer to an existing `core-client` tag. |

## Run Flow

1. Optionally build Docker images.
2. Resolve `KMS_CORE_IMAGE_TAG` and `KMS_CORE_CLIENT_IMAGE_TAG`.
3. Validate deployment/test-suite/TLS combinations.
4. Verify required image tags exist in the registry.
5. Deploy KMS to the `kms-ci` namespace through `ci/scripts/deploy.sh`.
6. Submit the selected Argo workflow.
7. Stream Argo logs and send the Slack report.

## Common Pitfalls

- Leaving `test_suite=burst` fails fast on this branch. Select `sustained-rate-udec`.
- Leaving `tls=true` with `deployment_type=threshold` fails fast. Use `tls=false`, or choose `thresholdWithEnclave`.
- `kms_chart_version=repository` means the chart comes from the selected/ref branch, not from an OCI release.
- `build=true` means the image-tag fields are ignored. Use `build=false` only when you know the exact core and client image tags already exist.
- `Default` FHE parameters are slower than `Test`. Use `Test` for iteration unless the goal is production-size perf.

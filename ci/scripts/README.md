# KMS Deployment/management Scripts

## Overview

**Quick Start:**
```bash
./deploy.sh --target kind-local
```

## File Structure

```
ci/scripts/
├── analyze_perf_run.py            # Correlate artifacts from one performance run
├── backward_snapshot.sh           # Generate and compare backward-compatibility snapshots
├── collect_network_diagnostics.py # Capture per-pod network interface counters
├── deploy.sh                      # Main deployment entry point
├── local_docs_link_check.py       # Check Markdown links to local files
├── manage_lifecycle.sh            # Lifecycle management
├── perf_common.py                 # Process helpers for runner-side perf tools
├── perf_runner.py                 # GitHub Actions performance orchestration
├── rolling_upgrade.sh             # Partially upgrade enclave KMS parties
├── sample_core_cpu.py             # Sample KMS core CPU and memory during benchmarks
├── sample_core_metrics.py         # Scrape KMS Prometheus metrics throughout a benchmark
├── sample_perf_diagnostics.py     # Orchestrate metrics, ENA, and placement collection
├── sample_pod_placement.py        # Record core/client node and AZ placement
└── lib/                           # Modular libraries
    ├── common.sh                  # Logging, parsing, utilities
    ├── context.sh                 # Kubernetes context setup
    ├── infrastructure.sh          # S3, TKMS, Crossplane
    ├── kms_deployment.sh          # KMS core deployment
    └── utils.sh                   # Port forwarding, logs
```

## Usage

### Basic Commands

```bash
# Local deployment with Kind
./deploy.sh --target kind-local

# Build and load images locally
./deploy.sh --target kind-local --build

# Clean up and redeploy
./deploy.sh --target kind-local --cleanup

# Deploy and wait indefinitely (with port forwarding)
./deploy.sh --target kind-local --block
```

### All Options

```bash
./deploy.sh \
  --target [kind-local|kind-ci|aws-ci|aws-perf] \
  --namespace <namespace> \
  --deployment-type [threshold|centralized|thresholdWithEnclave|centralizedWithEnclave] \
  --tag <image-tag> \
  --num-parties <count> \
  --kms-chart-version <version> \
  --cleanup \
  --block \
  --collect-logs \
  --build
```

### Building Images Locally

For local development with Kind:

```bash
# Build and load images into Kind cluster
./deploy.sh --target kind-local --build

# Override the Rust version (defaults to the version pinned in rust-toolchain.toml)
RUST_IMAGE_VERSION=<rust-version> ./deploy.sh --target kind-local --build
```

The build process will:
1. Build `core-service` image with Docker buildx
2. Load it into the Kind cluster
3. Build `core-client` image
4. Load it into the Kind cluster

## Module Guide

### Where to Find Things

| Need to modify... | Edit this file |
|------------------|----------------|
| **Logging or argument parsing** | `lib/common.sh` |
| **Backward-compatibility snapshots** | `backward_snapshot.sh` |
| **Benchmark network diagnostics** | `collect_network_diagnostics.py` |
| **Kind cluster setup** | `lib/context.sh` |
| **AWS/Tailscale config** | `lib/context.sh` |
| **Local documentation link checks** | `local_docs_link_check.py` |
| **LocalStack deployment** | `lib/infrastructure.sh` |
| **TKMS/Crossplane** | `lib/infrastructure.sh` |
| **Registry credentials** | `lib/infrastructure.sh` |
| **KMS Core deployment** | `lib/kms_deployment.sh` |
| **Helm overrides** | `lib/kms_deployment.sh` |
| **Docker image building** | `lib/utils.sh` |
| **Port forwarding** | `lib/utils.sh` |
| **Log collection** | `lib/utils.sh` |
| **Rolling KMS upgrades** ([docs](#rolling-upgrade-testing)) | `rolling_upgrade.sh` |
| **Core CPU/memory benchmark samples** | `sample_core_cpu.py` |
| **Perf application, ENA, and placement diagnostics** | `sample_perf_diagnostics.py` |

### Module Details

#### `deploy.sh` (Main Entry Point)
- Orchestrates the entire deployment
- Defines default configuration
- Loads library modules
- Executes main deployment flow

#### `lib/common.sh`
**Common utilities and helper functions**
- `log_info()`, `log_warn()`, `log_error()` - Logging functions
- `parse_args()` - Command-line argument parsing
- `sed_inplace()` - Cross-platform file editing
- Interactive resource configuration (local dev)
- Path suffix determination

#### `lib/context.sh`
**Kubernetes context management**
- `setup_context()` - Main context setup router
- `setup_kind_cluster()` - Kind cluster creation/management
- `create_new_kind_cluster()` - Kind cluster provisioning
- `setup_aws_context()` - AWS/Tailscale configuration

#### `lib/infrastructure.sh`
**Infrastructure provisioning and management**
- `setup_infrastructure()` - Main infrastructure setup
- `deploy_localstack()` - S3 mock deployment (Kind)
- `deploy_tkms_infra()` - Crossplane infrastructure (AWS)
- `wait_tkms_infra_ready()` - Wait for infrastructure readiness
- `wait_crossplane_resources_ready()` - Crossplane resource waiting
- `deploy_registry_credentials()` - Docker registry access
- `fetch_pcrs_from_image()` - Extract PCR values from enclave images

#### `lib/kms_deployment.sh`
**KMS Core service deployment**
- `deploy_kms()` - Main KMS deployment orchestrator
- `deploy_threshold_mode()` - Multi-party threshold deployment
- `deploy_centralized_mode()` - Single-party centralized deployment
- `generate_helm_overrides()` - Dynamic Helm values generation
- `generate_peers_config()` - Threshold peer configuration
- `deploy_init_job()` - Initialization job deployment
- `helm_upgrade_with_version()` - Helm wrapper utility

#### `lib/utils.sh`
**Utility functions for operations**
- `build_container()` - Build and load Docker images (Kind)
- `setup_port_forwarding()` - Local port forwarding (Kind)
- `wait_indefinitely()` - Keep script running
- `kms_pod_logs()` - Logs of every container in a KMS pod, TLS key excluded
- `collect_logs()` - Pod log collection for debugging

## Testing

### Performance testing

The runner tools use Python 3.11 or later and the standard library. They invoke
existing tools such as `kubectl`, `argo`, `helm`, `docker`, and `curl`.
They require no Python installation in the KMS client or core images.

`perf_runner.py` handles image selection, validation, Argo execution, reports,
and cleanup. The five diagnostic tools retain their positional arguments and
artifact formats. The network collector uses a small shell command inside core
containers to read interface counters.

`sample_perf_diagnostics.py` owns all background samplers, including CPU sampling.
It writes `core-cpu-samples.log` in the working directory and the other artifacts
in its output directory. The workflow defines deployment parameters in job-level
`env:` values.

The runner starts the diagnostics controller in a separate process group.
Its samplers share that group, so forced cleanup also stops their descendants.

The workflow copies its runner tools into `RUNNER_TEMP` before the optional chart
checkout. That checkout still supplies deployment files and Argo templates.
The runner writes the expanded workflow to `perf-workflow.generated.yaml`.

Run the tests from the repository root:

```sh
python3 -m unittest discover -s ci/scripts/tests -v
python3 ci/perf-testing/generate-perf-workflow.py --self-test
python3 ci/scripts/analyze_perf_run.py --self-test
```

The tests use fake command responses and local processes. They do not require
a cluster, registry access, or Slack credentials.

The performance-testing workflow collects network counters before and after a run,
and samples KMS Core CPU and memory while it is running. Both scripts use the
current Kubernetes context and default to the `kms-ci` namespace.

#### Network diagnostics

`collect_network_diagnostics.py` captures per-interface counters from each running `kms-core-<party>-core-<core>`
pod. Run it once before and once after a performance test to produce per-pod and
aggregate `eth0` traffic deltas:

```bash
python3 collect_network_diagnostics.py before-perf <namespace>
# Run the performance test.
python3 collect_network_diagnostics.py after-perf <namespace>
```

Results are written to `network-diagnostics/<phase>/`. The `after-perf` call also
writes `network-diagnostics/pod-interface-counter-delta.tsv` and prints the
transfer volume, average throughput, errors, and dropped packets. Set
`NETWORK_DIAGNOSTICS_DIR` to store the results elsewhere.

#### KMS Core CPU samples

`sample_core_cpu.py` continuously records CPU and memory for KMS Core pods using
`kubectl top`. Its output is one space-separated line per pod per sample:

```text
<UTC timestamp> <pod> <CPU> <memory>
```

Start it in the background for the duration of a test and stop it when the test
finishes:

```bash
python3 sample_core_cpu.py <namespace> <interval-seconds> > core-cpu-samples.log &
CPU_SAMPLER_PID=$!
# Run the performance test.
kill "${CPU_SAMPLER_PID}"
```

The namespace defaults to `kms-ci` and the interval defaults to 10 seconds. The
cluster must have metrics-server available and the current identity must be able
to run `kubectl top pod` in that namespace.

### Rolling-upgrade testing

`rolling_upgrade.sh`, driven by the `rolling-upgrade-testing.yml` GitHub Actions
workflow (`workflow_dispatch` only), deploys 13 enclave parties on an OLD version,
rolls them to a NEW version in two waves (5/13 then 9/13), and checks decryption on
the mixed-version cluster after each wave.

Dispatch inputs:

| Input | Meaning |
|-------|---------|
| `old_image_tag` / `new_image_tag` | KMS core image tags before / after the upgrade |
| `core_client_image_tag` | Core-client (test harness) tag from the new repository; defaults to `old_image_tag` from the old repository. Must be ≤ the oldest server version in the run. Required for `prss-threshold` |
| `old_kms_chart_version` / `new_kms_chart_version` | kms-core Helm chart per side (`repository` = in-tree chart) |
| `first_batch_parties` / `second_batch_parties` | Party IDs upgraded in wave 1 / wave 2 (default `1,2,3,4,5` / `6,7,8,9`) |
| `test_profile` | `decrypt` (default) or `prss-threshold` — see below |
| `client_logs` | Core-client tracing logs (default off) |
| `fhe_params` | `Test` (default) or `Default` |
| `build` / `kms_branch` | Build the new image from a branch instead of using `new_image_tag` |

**`test_profile=decrypt`** (default): plain public + user decrypt correctness on the
mixed cluster with random request-IDs. Every task must pass; the job fails on any
decrypt failure. Use this for a normal `n → n+1` upgrade.

**`test_profile=prss-threshold`** — the below-request-ID-threshold special case,
validating the legacy-PRSS-mask fix. The upgraded parties are configured with a
legacy-mask request-ID threshold of `100` (`LEGACY_PRSS_MASK_THRESHOLD`), and the
mixed stages run four probes: public and user decrypt, each pinned to a request-ID
**below** (`< 100`) and **above** (`> 100`) the threshold.

| Probe | Request-ID | Expected |
|-------|-----------|----------|
| `*-reqid-below` | `< 100` (legacy PRSS path) | PASS at every mixed state |
| `*-reqid-above` | `> 100` (new PRSS path) | FAIL where the version split exceeds the reconstruction fault budget (e.g. 5/13), PASS otherwise (e.g. 9/13) |

Because `*-reqid-above` failures are expected, the job's correctness gate excludes
`reqid-above` pods — read each probe's PASS/FAIL from the run summary, not the job
conclusion. Requires a threshold-aware new image and a request-ID-capable core-client.

#### Core-client compatibility

The Argo command strings target the **`v0.13.x` and `v0.14.x` core-client CLIs**. The baseline keygen step detects which insecure keygen form the client supports: one step (`v0.13.x`), or `insecure-preproc-key-gen` followed by `insecure-key-gen -i` (`v0.14.x`). The baseline pins the client to `old_image_tag`, so `old_image_tag` can be a `v0.13.x` or a `v0.14.x` tag.
A main (`v0.15`) client is **not** compatible as-is, because it has no `--num-requests` option. Its replacement (`--rate`/`--duration`) does not fail the command when a request gets too few responses, so it cannot replace the `-a` correctness check. If `core_client_image_tag` is empty, the mixed-state runs use the `old_image_tag` client, which is compatible when `old_image_tag` is a `v0.13.x` or `v0.14.x` tag. Do not set `core_client_image_tag` to a main or `build=true` tag.
The `prss-threshold` profile is `v0.13.x`-only by design (`v0.14` rejects the `legacy_prss_mask_*` config). Its probes pass `--request-id`, which no released core-client supports, so it also needs an explicit `core_client_image_tag`. The workflow fails at the start if either condition is not met.

### Debugging

Enable verbose mode to see all function calls:
```bash
bash -x deploy.sh --target kind-local 2>&1 | less
```

Check module loading:
```bash
bash -x deploy.sh --help 2>&1 | grep source
```

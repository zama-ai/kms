# KMS Deployment/management Scripts

## Overview

**Quick Start:**
```bash
./deploy.sh --target kind-local
```

## File Structure

```
ci/scripts/
├── backward_snapshot.sh           # Generate and compare backward-compatibility snapshots
├── collect_network_diagnostics.sh # Capture per-pod network interface counters
├── deploy.sh                      # Main deployment entry point
├── local_docs_link_check.py       # Check Markdown links to local files
├── manage_lifecycle.sh            # Lifecycle management
├── rolling_upgrade.sh             # Partially upgrade enclave KMS parties
├── sample_core_cpu.sh             # Sample KMS core CPU and memory during benchmarks
└── lib/                           # Modular libraries
    ├── common.sh                  # Logging, parsing, utilities (277 lines)
    ├── context.sh                 # Kubernetes context setup (87 lines)
    ├── infrastructure.sh          # S3, TKMS, Crossplane (316 lines)
    ├── kms_deployment.sh          # KMS core deployment (546 lines)
    └── utils.sh                   # Port forwarding, logs (165 lines)
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
| **Benchmark network diagnostics** | `collect_network_diagnostics.sh` |
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
| **Core CPU/memory benchmark samples** | `sample_core_cpu.sh` |

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
- `collect_logs()` - Pod log collection for debugging

## Testing

### Performance testing

The performance-testing workflow collects network counters before and after a run,
and samples KMS Core CPU and memory while it is running. Both scripts use the
current Kubernetes context and default to the `kms-ci` namespace.

#### Network diagnostics

`collect_network_diagnostics.sh` captures per-interface counters from each running `kms-core-<party>-core-<core>`
pod. Run it once before and once after a performance test to produce per-pod and
aggregate `eth0` traffic deltas:

```bash
bash collect_network_diagnostics.sh before-perf <namespace>
# Run the performance test.
bash collect_network_diagnostics.sh after-perf <namespace>
```

Results are written to `network-diagnostics/<phase>/`. The `after-perf` call also
writes `network-diagnostics/pod-interface-counter-delta.tsv` and prints the
transfer volume, average throughput, errors, and dropped packets. Set
`NETWORK_DIAGNOSTICS_DIR` to store the results elsewhere.

#### KMS Core CPU samples

`sample_core_cpu.sh` continuously records CPU and memory for KMS Core pods using
`kubectl top`. Its output is one space-separated line per pod per sample:

```text
<UTC timestamp> <pod> <CPU> <memory>
```

Start it in the background for the duration of a test and stop it when the test
finishes:

```bash
bash sample_core_cpu.sh <namespace> <interval-seconds> > core-cpu-samples.log &
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
| `core_client_image_tag` | Core-client (test harness) tag; defaults to `new_image_tag`. Must be ≤ the oldest server version in the run |
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

The Argo command strings target the **`v0.13.x` core-client CLI**. A main / `v0.14+` client is **not** compatible as-is.
So set `core_client_image_tag` to a `v0.13.x` tag, and **do not** use `build=true` (it would build a main-based client).
Making the `decrypt` profile main-compatible means updating those commands; the `prss-threshold` profile is
`v0.13.x`-only by design (`v0.14` rejects the `legacy_prss_mask_*` config).

### Debugging

Enable verbose mode to see all function calls:
```bash
bash -x deploy.sh --target kind-local 2>&1 | less
```

Check module loading:
```bash
bash -x deploy.sh --help 2>&1 | grep source
```

# KMS Deployment Scripts

## Overview

**Quick Start:**
```bash
./deploy.sh --target kind-local
```

## File Structure

```
ci/scripts/
├── deploy.sh                      # Main entry point (143 lines)
├── manage_lifecycle.sh            # Lifecycle management
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

# Use specific Rust version
RUST_IMAGE_VERSION=1.97 ./deploy.sh --target kind-local --build
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
| **Kind cluster setup** | `lib/context.sh` |
| **AWS/Tailscale config** | `lib/context.sh` |
| **LocalStack deployment** | `lib/infrastructure.sh` |
| **TKMS/Crossplane** | `lib/infrastructure.sh` |
| **Registry credentials** | `lib/infrastructure.sh` |
| **KMS Core deployment** | `lib/kms_deployment.sh` |
| **Helm overrides** | `lib/kms_deployment.sh` |
| **Docker image building** | `lib/utils.sh` |
| **Port forwarding** | `lib/utils.sh` |
| **Log collection** | `lib/utils.sh` |

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

### Debugging

Enable verbose mode to see all function calls:
```bash
bash -x deploy.sh --target kind-local 2>&1 | less
```

Check module loading:
```bash
bash -x deploy.sh --help 2>&1 | grep source
```

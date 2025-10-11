# KMS Testing in Kind

This directory contains scripts and configuration for testing KMS in a local Kubernetes cluster using [Kind (Kubernetes in Docker)](https://kind.sigs.k8s.io/).

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Local Usage](#local-usage)
- [CI Usage](#ci-usage)
- [Scripts](#scripts)
- [Configuration Files](#configuration-files)
- [Troubleshooting](#troubleshooting)

## Overview

The KMS testing infrastructure supports two deployment modes:
- **Threshold Mode**: Multi-party setup with 4 KMS cores (default)
- **Centralized Mode**: Single KMS core

The setup includes:
- Kind cluster with control-plane and worker nodes
- MinIO for object storage
- KMS Core services with port-forwarding
- Automated log collection in the CI

## Prerequisites

Ensure the following tools are installed:
- `kubectl` - Kubernetes CLI
- `helm` - Kubernetes package manager
- `kind` - Kubernetes in Docker
- `docker` - Container runtime

## Local Usage

### Basic Setup

Start a KMS cluster in threshold mode (default):

```bash
cd /path/to/kms
./ci/kube-testing/scripts/setup_kms_in_kind.sh
```

The script will:
1. Create a Kind cluster named `kms-test`
2. Deploy MinIO and KMS services
3. Set up port-forwarding for local access
4. Wait for user interrupt (Ctrl+C)

### Command-Line Options

```bash
./ci/kube-testing/scripts/setup_kms_in_kind.sh [OPTIONS]

Options:
  --namespace <name>          Kubernetes namespace (optionnal, default: kms-test)
  --kms-core-tag <tag>        KMS Core image tag (optionnal, default: latest)
  --kms-core-client-tag <tag> KMS Core Client image tag (optionnal, default: latest)
  --deployment-type <type>    Deployment type: threshold|centralized (optionnal, default: threshold)
  --num-parties <num>         Number of parties for threshold mode (optionnal, default: 4)
  --cleanup                   Cleanup existing deployment before setup (optionnal, default: false)
  --build                     Build and load Docker images locally (optionnal, default: false)
  --local                     Run in local mode (full cleanup on exit, optionnal, default: false)
  --help                      Show help message
```

### WARNING: For local build

If you want to build docker images locally, you need a chainguard token to pull base images. Go to https://console.chainguard.dev/, create a token and follow the instructions.

### Environment Variables

You can also configure the setup using environment variables:

```bash
# Basic configuration
export NAMESPACE="my-kms-test"
export KMS_CORE_IMAGE_TAG="v0.12.0"
export KMS_CORE_CLIENT_IMAGE_TAG="v0.12.0"
export DEPLOYMENT_TYPE="threshold"
export NUM_PARTIES="4"
```

### GitHub token for private image pulls

To pull private images and helm charts from GitHub Container Registry, you need to create a `dockerconfig.yaml` file with your Personal Access Token:

```bash
# Replace <your_username> and <your_token> with your GitHub credentials
# Token needs 'read:packages' permission
cat > ${HOME}/dockerconfig.yaml <<EOF
apiVersion: v1
data:
  .dockerconfigjson: $(cat <<JSON | base64 -w 0
{
  "auths": {
    "ghcr.io": {
      "auth": "$(echo -n "<your_username>:<your_token>" | base64 -w 0)"
    }
  }
}
JSON
)
kind: Secret
metadata:
  name: registry-credentials
type: kubernetes.io/dockerconfigjson
EOF
```

Then run the setup script with `--local` flag:

```bash
./ci/kube-testing/scripts/setup_kms_in_kind.sh --local
```

### Example: Centralized Mode

```bash
./ci/kube-testing/scripts/setup_kms_in_kind.sh \
  --deployment-type centralized \
  --namespace kms-centralized
```

### Example: Build Local Images before deployment

```bash
./ci/kube-testing/scripts/setup_kms_in_kind.sh \
  --build \
  --local
```

### Example: Custom Number of Parties if you enough resources

You can tweak the resources of kms in values:
- `ci/kube-testing/kms/values-kms-service-init-kms-test.yaml`
- `ci/kube-testing/kms/values-kms-test.yaml`

And run the setup script:

```bash
./ci/kube-testing/scripts/setup_kms_in_kind.sh \
  --deployment-type threshold \
  --num-parties 13
```

### Accessing Services

Once setup is complete, services are available at:

**Threshold Mode:**
- MinIO UI: http://localhost:9000
- KMS Core 1: http://localhost:50100
- KMS Core 2: http://localhost:50200
- KMS Core 3: http://localhost:50300
- KMS Core 4: http://localhost:50400

**Centralized Mode:**
- MinIO UI: http://localhost:9000
- KMS Core: http://localhost:50100

### Running Tests

With the cluster running, execute tests in another terminal:

```bash
# Run all Kubernetes tests
cargo nextest run --test kubernetes_test

# Run specific test
cargo nextest run --test kubernetes_test test_name
```

### Cleanup

**Graceful Cleanup (Ctrl+C):**
```bash
# Press Ctrl+C in the terminal running the setup script
# This triggers log collection and cleanup
```

**Manual Cleanup:**
```bash
# Delete the Kind cluster
kind delete cluster --name kms-test

# Remove kubeconfig
rm -f ~/.kube/kind_config
```

**Full Cleanup with --local flag:**
```bash
# Start with local mode
./ci/kube-testing/scripts/setup_kms_in_kind.sh --local

# Ctrl+C will perform full cleanup:
# - Uninstall Helm releases
# - Delete namespace
# - Delete Kind cluster
```

## CI Usage

The CI workflow uses a helper script to manage the setup lifecycle separately from test execution.

### Workflow Structure

```yaml
- name: Setup Kind Cluster
  run: ./ci/kube-testing/scripts/manage_kind_setup.sh start

- name: Run Kubernetes Tests
  run: cargo nextest run --test kubernetes_test

- name: Cleanup Kind Setup and Collect Logs
  if: always()
  run: ./ci/kube-testing/scripts/manage_kind_setup.sh stop

- name: Upload kms-core logs
  if: always()
  uses: actions/upload-artifact@v4
```

### How It Works

1. **Setup Phase** (`manage_kind_setup.sh start`):
   - Runs `setup_kms_in_kind.sh` in background
   - Saves process PIDs to `.setup_pid` and `.tail_pid`
   - Monitors log file for completion message
   - Returns when setup is ready (or fails after timeout)

2. **Test Phase**:
   - Tests run directly in CI (not through script)
   - Test exit code saved to `$GITHUB_ENV`

3. **Cleanup Phase** (`manage_kind_setup.sh stop`):
   - Terminates setup script and port-forwards
   - Collects logs from all KMS pods to `/tmp/`
   - Verifies log collection succeeded
   - Cleans up PID files

4. **Upload Phase**:
   - Uploads collected logs as GitHub artifacts
   - Logs retained for 7 days

5. **Result Check**:
   - Fails workflow if tests failed
   - Always runs after log upload

### Log Collection

Logs are collected to `/tmp/` with the following naming:

**Threshold Mode:**
```
/tmp/kms-service-threshold-1-kms-test-core-1.log
/tmp/kms-service-threshold-2-kms-test-core-2.log
/tmp/kms-service-threshold-3-kms-test-core-3.log
/tmp/kms-service-threshold-4-kms-test-core-4.log
```

**Centralized Mode:**
```
/tmp/kms-core-kms-test.log
```

### Environment Variables in CI

The CI workflow sets these environment variables at the job level:

```yaml
env:
  NAMESPACE: kms-test
  KMS_CORE_IMAGE_TAG: ${{ needs.docker-build.outputs.image_tag }}
  KMS_CORE_CLIENT_IMAGE_TAG: ${{ needs.docker-build.outputs.image_tag }}
  DEPLOYMENT_TYPE: threshold  # Can be changed to 'centralized'
  NUM_PARTIES: 4              # Can be changed to 13 or other values
  GITHUB_TOKEN: ${{ secrets.ZWS_BOT_TOKEN }}
```

**To customize the deployment in CI:**

1. Edit `.github/workflows/kind-testing.yml`
2. Modify the `env` section of the `Setup Kind Cluster` step:
   ```yaml
   DEPLOYMENT_TYPE: threshold  # Change deployment mode
   NUM_PARTIES: 4              # Change number of parties (threshold only)
   ```
3. The `manage_kind_setup.sh` script will automatically use these values

## Scripts

### `setup_kms_in_kind.sh`

**Purpose**: Main setup script that creates and configures the Kind cluster.

**Key Functions**:
- `setup_kind_cluster()` - Creates Kind cluster
- `setup_namespace()` - Creates Kubernetes namespace
- `deploy_minio()` - Deploys MinIO object storage
- `deploy_threshold_mode()` - Deploys multi-party KMS
- `deploy_centralized_mode()` - Deploys single-party KMS
- `setup_port_forwarding()` - Configures port-forwards
- `cleanup()` - Triggered by SIGINT/SIGTERM (Ctrl+C)

**Behavior**:
- Runs in foreground with infinite loop
- Responds to SIGINT (Ctrl+C) for graceful shutdown
- In local mode (`--local`): performs full cleanup on exit
- In CI mode (default): lightweight cleanup, CI handles cluster deletion

### `manage_kind_setup.sh`

**Purpose**: CI helper script to manage setup lifecycle.

**Commands**:

```bash
# Start setup and wait for completion
./manage_kind_setup.sh start

# Stop setup and collect logs
./manage_kind_setup.sh stop [SETUP_PID] [TAIL_PID]
```

**Key Features**:
- Runs setup in background
- Monitors setup completion via log file
- Handles timeouts (10 minutes)
- Collects logs via kubectl
- Auto-detects deployment type
- Fallback log collection if primary method fails

## Configuration Files

### Helm Values

Located in `kms/` directory:

- `values-kms-test.yaml` - Base configuration
- `values-kms-service-init-kms-test.yaml` - Initialization job configuration
- `values-kms-service-gen-keys-kms-test.yaml` - Configuration for gen keys mode

### Infrastructure

Located in `infra/` directory:

- `minio-values.yaml` - MinIO configuration

## Troubleshooting

### Cluster Already Exists

```bash
# Delete existing cluster
kind delete cluster --name kms-test

# Or use --cleanup flag
./ci/kube-testing/scripts/setup_kms_in_kind.sh --cleanup
```

### Port Already in Use

```bash
# Find and kill processes using the ports
lsof -ti:9000 | xargs kill -9
lsof -ti:50100 | xargs kill -9

# Or kill all kubectl port-forwards
pkill -f "kubectl port-forward"
```

### Image Pull Errors

```bash
# Set GitHub token for private images
export GITHUB_TOKEN="ghp_xxxxxxxxxxxxx"

# Or build images locally
./ci/kube-testing/scripts/setup_kms_in_kind.sh --build
```

### Pods Not Starting

```bash
# Check pod status
kubectl get pods -n kms-test

# View pod logs
kubectl logs <pod-name> -n kms-test

# Describe pod for events
kubectl describe pod <pod-name> -n kms-test
```

### Setup Timeout

```bash
# Increase timeout in manage_kind_setup.sh (line 48)
TIMEOUT=1200  # 20 minutes

# Or check logs for errors
tail -f setup_kms.log
```

### Logs Not Collected

Logs are collected in two ways:

1. **Primary**: Via cleanup function when Ctrl+C is pressed
2. **Fallback**: Via `manage_kind_setup.sh` using kubectl directly

Check logs manually:
```bash
# Threshold mode
kubectl logs kms-service-threshold-1-kms-test-core-1 -n kms-test

# Centralized mode
kubectl logs kms-core -n kms-test
```

### Kind Cluster Issues

```bash
# View Kind logs
kind export logs --name kms-test

# Recreate cluster
kind delete cluster --name kms-test
./ci/kube-testing/scripts/setup_kms_in_kind.sh
```

## Advanced Usage

### Custom Kubeconfig Location

```bash
# Set custom kubeconfig path
export KUBE_CONFIG="/path/to/custom/kubeconfig"
./ci/kube-testing/scripts/setup_kms_in_kind.sh
```

### Debug Mode

```bash
# Enable bash debug mode
bash -x ./ci/kube-testing/scripts/setup_kms_in_kind.sh
```

### Multiple Clusters

```bash
# Use different namespaces for isolation
./ci/kube-testing/scripts/setup_kms_in_kind.sh --namespace kms-test-1
./ci/kube-testing/scripts/setup_kms_in_kind.sh --namespace kms-test-2
```

### Port Forwarding Customization

Edit `setup_port_forwarding()` function in `setup_kms_in_kind.sh`:

```bash
# Threshold mode ports: 50100, 50200, 50300, 50400
local port=$((50000 + i * 100))
```

## Contributing

When modifying the scripts:

1. **Test locally first**: Use `--local` flag for full cleanup
2. **Check both modes**: Test threshold and centralized deployments
3. **Verify log collection**: Ensure logs are saved to `/tmp/`
4. **Update this README**: Document any new options or behavior
5. **Test in CI**: Verify the changes work in the GitHub Actions workflow

## References

- [Kind Documentation](https://kind.sigs.k8s.io/)
- [Helm Documentation](https://helm.sh/docs/)
- [Kubernetes Documentation](https://kubernetes.io/docs/)
- [GitHub Actions Workflow](../../.github/workflows/kind-testing.yml)

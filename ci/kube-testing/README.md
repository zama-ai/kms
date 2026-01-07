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

### Required Tools

Ensure the following tools are installed:
- `aws` - AWS CLI
- `kubectl` - Kubernetes CLI
- `helm v3` - Package manager to deploy application
- `kind` - Kubernetes in Docker
- `docker` - Container runtime

### Supported Platforms

The scripts support both **macOS** and **Linux**:
- ✅ **macOS** (Darwin) - Tested on macOS
- ✅ **Linux** - Tested on Ubuntu/Debian

Platform-specific commands (like `base64`) are automatically detected and adjusted.

### Token for private image pulls

To pull private images and helm charts from GitHub Container Registry, you need to create a `dockerconfig.yaml` file with your Personal Access Token from github:

**Note**: The script automatically handles platform differences (macOS uses `base64`, Linux uses `base64 -w 0`), but for manual creation:

**macOS:**
```bash
# Replace <your_username> and <your_token> with your GitHub credentials
# Token needs 'read:packages' permission
cat > ${HOME}/dockerconfig.yaml <<EOF
apiVersion: v1
data:
  .dockerconfigjson: $(cat <<JSON | base64
{
  "auths": {
    "ghcr.io": {
      "auth": "$(echo -n "<your_username>:<your_token>" | base64)"
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

**Linux:**
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

## Local Usage

### Quick Start

For a quick test with minimal resources:

```bash
cd /path/to/kms
./ci/kube-testing/scripts/setup_kms_in_kind.sh --local
# Choose option 2 when prompted to adjust resources
# Enter: 4Gi memory, 2 CPU per core
```

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
  --namespace <name>          Kubernetes namespace (optional, default: kms-test)
  --kms-core-tag <tag>        KMS Core image tag (optional, default: latest)
  --kms-core-client-tag <tag> KMS Core Client image tag (optional, default: latest)
  --deployment-type <type>    Deployment type: threshold|centralized (optional, default: threshold)
  --num-parties <num>         Number of parties for threshold mode (optional, default: 4)
  --cleanup                   Cleanup existing deployment before setup (optional, default: false)
  --build                     Build and load Docker images locally (optional, default: false)
  --local                     Run in local mode (full cleanup on exit, optional, default: false)
  --gen-keys                  Generate keys using gen-keys job (optional, only with --local and threshold mode)
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

Then run the setup script with `--local` flag:

```bash
./ci/kube-testing/scripts/setup_kms_in_kind.sh --local
```

### Interactive Resource Adjustment (Local Mode)

When running with the `--local` flag, the script will analyze resource requirements and offer an interactive prompt to adjust them based on your system capabilities.

**Resource Warning Example:**
```
=========================================
Running in LOCAL mode
=========================================
The default Helm values require significant resources:

KMS Core Client (1 instance):
  - Memory: 24Gi
  - CPU: 12 cores

KMS Core (4 parties):
  - Memory per core: 24Gi
  - CPU per core: 12 cores
  - Total: 96Gi RAM, 48 CPU cores

KMS Core num_sessions_preproc:
  - num_sessions_preproc: 12

TOTAL RESOURCES REQUIRED:
  - Memory: 120Gi
  - CPU: 60 cores
=========================================
```

**Interactive Options:**
```
Choose an option:
  1) Continue with current values
  2) Adjust resources interactively
  3) Cancel and edit files manually
Enter your choice (1/2/3):
```

**Option 1: Continue** - Proceeds with existing values (requires sufficient system resources)

**Option 2: Interactive Adjustment** - Prompts for custom values:
```
Adjusting KMS Core resources...
KMS Core Memory per party (current: 24Gi, recommended: 4Gi): 6
KMS Core CPU per party (current: 12, recommended: 2): 4
KMS Core num_sessions_preproc (current: 12, recommended: 4): 4

Adjusting KMS Core Client resources...
KMS Core Client Memory (current: 24Gi, recommended: 4Gi): 4
KMS Core Client CPU (current: 12, recommended: 2): 2
```

The script will:
- Remove any existing local values files (if present)
- Create fresh local values files with your custom settings
- **Automatically replace `<namespace>` placeholders** with the actual namespace
- Use these files for deployment
- Show the new total resource requirements
- Apply FHE parameter settings to all files

**Local Values Files Created:**
- `ci/kube-testing/kms/local-values-kms-test.yaml`
- `ci/kube-testing/kms/local-values-kms-service-init-kms-test.yaml`
- `ci/kube-testing/kms/local-values-kms-service-gen-keys-kms-test.yaml` (only if using `--gen-keys`)

These files are:
- ✅ **Automatically created** from the interactive prompt
- ✅ **Git-ignored** (won't be committed to the repository)
- ✅ **Used only for local development** (CI uses default values)
- ✅ **Safe to delete** (will be recreated on next interactive run)
- ✅ **Include FHE parameter customization** (e.g., Test, Default)
- ✅ **Namespace placeholders automatically replaced** (`<namespace>` → actual namespace)
- ✅ **Automatically cleaned up** when choosing option 2 again (old files removed before creating new ones)

**Option 3: Cancel** - Exits the script so you can manually edit values files

**Recommended Minimum Resources for Local Testing:**

With `FHE_PARAMS=Test` parameter:
- **KMS Core Client:** 4Gi RAM, 2 CPU cores
- **KMS Core (per party):** 4Gi RAM, 2 CPU cores
- **Total for 4 parties:** 20Gi RAM, 10 CPU cores
- **Total for 13 parties:** 56Gi RAM, 28 CPU cores

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

### Example: Generate Keys (Threshold Mode Only)

The `--gen-keys` flag enables automatic key generation using a Kubernetes job. This is useful for testing threshold mode deployments with pre-generated keys.

**Requirements:**
- Must be used with `--local` flag
- Only works with `--deployment-type threshold`
- Automatically creates `local-values-kms-service-gen-keys-kms-test.yaml` if using interactive adjustment

**Basic usage:**
```bash
./ci/kube-testing/scripts/setup_kms_in_kind.sh \
  --local \
  --gen-keys
```

**With interactive resource adjustment:**
```bash
./ci/kube-testing/scripts/setup_kms_in_kind.sh \
  --local \
  --gen-keys \
  --deployment-type threshold \
  --num-parties 4
```

When prompted with the interactive menu (option 2), the script will:
1. Create local values files for KMS Core and KMS Core Client
2. Create `local-values-kms-service-gen-keys-kms-test.yaml` for the key generation job
3. Apply your custom resource settings and FHE parameters to all files
4. Deploy the key generation job after KMS Core initialization

**What happens:**
1. KMS Core pods are deployed (threshold mode)
2. KMS Core Client initialization job runs
3. **Key generation job runs** (generates keys for all parties)
4. Keys are stored in MinIO
5. Setup completes and waits for user interrupt

**Configuration file:**
- Default: `ci/kube-testing/kms/values-kms-service-gen-keys-kms-test.yaml`
- Local: `ci/kube-testing/kms/local-values-kms-service-gen-keys-kms-test.yaml` (auto-generated)

### Common Workflows

**Workflow 1: First-time Local Setup with Resource Adjustment**
```bash
# Start with local mode
./ci/kube-testing/scripts/setup_kms_in_kind.sh --local

# When prompted:
# 1. Review resource requirements
# 2. Choose option 2 (Interactive Adjustment)
# 3. Enter lower values (e.g., 4Gi memory, 2 CPU)
# 4. Script creates local files and deploys
```

**Workflow 2: Re-adjust Resources After Initial Setup**
```bash
# If you need to change resources again
./ci/kube-testing/scripts/setup_kms_in_kind.sh --local

# Choose option 2 again - old local files are automatically removed
# Enter new values, script recreates files with your settings
```

**Workflow 3: Quick Test with Pre-configured Resources**
```bash
# If local files already exist from previous run
./ci/kube-testing/scripts/setup_kms_in_kind.sh --local

# Choose option 1 (Continue) - uses existing local files
# No prompts, faster startup
```

**Workflow 4: Development with Key Generation**
```bash
# For testing threshold mode with pre-generated keys
./ci/kube-testing/scripts/setup_kms_in_kind.sh \
  --local \
  --gen-keys \
  --deployment-type threshold \
  --num-parties 4

# Choose option 2 to adjust resources
# Script creates all three local files (core, init, gen-keys)
```

### Example: Custom Number of Parties

**Option 1: Use Interactive Adjustment (Recommended for Local)**

Run with `--local` flag and choose option 2 to interactively adjust resources:

```bash
./ci/kube-testing/scripts/setup_kms_in_kind.sh \
  --deployment-type threshold \
  --num-parties 13 \
  --local
```

**Option 2: Manual Configuration (For CI)**

Manually edit the values files:
- `ci/kube-testing/kms/values-kms-service-init-kms-test.yaml`
- `ci/kube-testing/kms/values-kms-test.yaml`

Look for sections marked with:
```yaml
#==========RESOURCES TO ADJUST BASED ON ENVIRONMENT==========
resources:
  requests:
    memory: 24Gi  # Adjust based on your system
    cpu: 12       # Adjust based on your system
```

Then run the setup script:

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
- `detect_platform` - Detects the platform (macOS or Linux) and adjusts commands accordingly
- `validate_config` - Validates configuration parameters
- `check_local_resources` - Interactive resource adjustment for local development
- `replace_namespace_in_files` - Replaces `<namespace>` placeholders in values files
- `setup_kind_cluster` - Creates Kind cluster with control-plane and worker nodes
- `setup_namespace` - Creates Kubernetes namespace
- `setup_registry_credentials` - Configures Docker registry authentication
- `deploy_localstack` - Deploys Localstack for S3 object storage
- `deploy_threshold_mode` - Deploys multi-party KMS with configurable number of parties
- `deploy_centralized_mode` - Deploys single-party KMS
- `setup_port_forwarding` - Configures port-forwards for local access
- `collect_logs` - Collects logs from all KMS pods
- `cleanup` - Triggered by SIGINT/SIGTERM (Ctrl+C) for graceful shutdown

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

**Default Values (Used by CI):**
- `values-kms-test.yaml` - Base configuration for KMS Core
- `values-kms-service-init-kms-test.yaml` - Initialization job and KMS Core Client configuration
- `values-kms-service-gen-keys-kms-test.yaml` - Key generation job configuration (used with `--gen-keys`)

**Local Values (Auto-generated, Git-ignored):**
- `local-values-kms-test.yaml` - Local overrides for KMS Core (created by interactive prompt)
- `local-values-kms-service-init-kms-test.yaml` - Local overrides for KMS Core Client (created by interactive prompt)
- `local-values-kms-service-gen-keys-kms-test.yaml` - Local overrides for key generation job (created when using `--gen-keys`)

These local files are:
- Created automatically when using `--local` flag with interactive adjustment (option 2)
- Used instead of default values when running in local mode
- Ignored by git (listed in `.gitignore`)
- Safe to delete (will be recreated on next interactive run)
- The gen-keys local file is only created when using `--gen-keys` flag
- **Namespace placeholders automatically replaced** during creation
- **Automatically removed and recreated** when choosing interactive adjustment again (option 2)

**Important Notes:**
- Local files are created by copying base files and then applying your customizations
- The `<namespace>` placeholder in base files is automatically replaced with the actual namespace
- If you manually edit local files, they won't be overwritten unless you choose option 2 again

**Resource Configuration Sections:**

Look for these marked sections in values files to adjust resources:
```yaml
#=============================================================
#==========RESOURCES TO ADJUST BASED ON ENVIRONMENT==========
# If you launch the deployment locally, adjust these resources
# according to your system and available resources
resources:
  requests:
    memory: 24Gi  # Default for CI/production
    cpu: 12       # Adjust for local development
  limits:
    memory: 24Gi
    cpu: 12
#=============================================================
```

### Infrastructure

Located in `infra/` directory:

- `localstack-s3-values.yaml` - Localstack S3 configuration (replaces MinIO)

**Note**: The setup uses Localstack for S3-compatible object storage, accessible at `http://localstack:4566` within the cluster and `http://localhost:9000` via port-forwarding.

## Troubleshooting

### Cluster Already Exists

`Error from server (AlreadyExists): namespaces “kms-test” already exists`

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

### Namespace Placeholder Not Replaced

If you see `<namespace>` in pod names or service URLs instead of the actual namespace:

**Symptoms:**
- Pod names contain literal `<namespace>` text
- Service URLs show `kms-service-threshold-1-<namespace>-core-1`
- Connection errors when accessing services

**Solution:**
The script automatically replaces `<namespace>` placeholders in values files. If you see this issue:

1. **Check if local files exist and have correct namespace:**
   ```bash
   grep -r "<namespace>" ci/kube-testing/kms/local-values-*.yaml
   ```

2. **Recreate local files with interactive adjustment:**
   ```bash
   ./ci/kube-testing/scripts/setup_kms_in_kind.sh --local
   # Choose option 2 to recreate files with namespace replacement
   ```

3. **Manually replace if needed:**
   ```bash
   # Replace in all local files
   sed -i '' "s|<namespace>|kms-test|g" ci/kube-testing/kms/local-values-*.yaml
   # On Linux, use: sed -i "s|<namespace>|kms-test|g" ci/kube-testing/kms/local-values-*.yaml
   ```

### Insufficient Resources (OOMKilled, Pending Pods)

If pods are failing due to insufficient resources:

**Symptoms:**
- Pods stuck in `Pending` state
- Pods showing `OOMKilled` status
- Error: `Insufficient memory` or `Insufficient cpu`

**Solution 1: Use Interactive Adjustment (Recommended)**
```bash
# Run with --local flag and choose option 2
./ci/kube-testing/scripts/setup_kms_in_kind.sh --local

# When prompted, choose option 2 and enter lower values
# Example: 4Gi memory and 2 CPU per core instead of 24Gi and 12 CPU
```

**Solution 2: Manually Edit Local Values**
```bash
# Create local values files
cp ci/kube-testing/kms/values-kms-test.yaml \
   ci/kube-testing/kms/local-values-kms-test.yaml

cp ci/kube-testing/kms/values-kms-service-init-kms-test.yaml \
   ci/kube-testing/kms/local-values-kms-service-init-kms-test.yaml

# Edit the files and reduce resource requests
# Then run with --local flag
./ci/kube-testing/scripts/setup_kms_in_kind.sh --local
```

**Solution 3: Reduce Number of Parties**
```bash
# Use centralized mode (1 party) instead of threshold (4 parties)
./ci/kube-testing/scripts/setup_kms_in_kind.sh \
  --deployment-type centralized \
  --local
```

**Check Available Resources:**
```bash
# Check Docker resources (macOS)
docker info | grep -E 'CPUs|Total Memory'

# Check system resources (Linux)
free -h
nproc
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

## Understanding the Setup Process

### Execution Flow

When you run the setup script, it follows this sequence:

1. **Validation Phase**
   - Checks prerequisites (kubectl, helm, kind, docker)
   - Validates configuration parameters
   - Detects platform (macOS/Linux) for command compatibility

2. **Resource Check Phase** (Local mode only)
   - Analyzes resource requirements from values files
   - Prompts for interactive adjustment if needed
   - Creates/updates local values files with customizations
   - **Replaces namespace placeholders** in local files

3. **Cluster Setup Phase**
   - Creates Kind cluster
   - Sets up Kubernetes namespace
   - Configures registry credentials (if GITHUB_TOKEN provided)

4. **Infrastructure Deployment Phase**
   - Deploys Localstack for S3 storage
   - Waits for infrastructure to be ready

5. **Image Build Phase** (if `--build` flag used)
   - Builds Docker images locally
   - Loads images into Kind cluster

6. **KMS Deployment Phase**
   - Deploys KMS Core services (threshold or centralized)
   - Replaces namespace placeholders in values files (if not already done)
   - Waits for pods to be ready
   - Deploys initialization job
   - Deploys key generation job (if `--gen-keys` used)

7. **Port Forwarding Phase**
   - Sets up port-forwards for local access
   - Keeps script running until interrupted

8. **Cleanup Phase** (on Ctrl+C)
   - Collects logs from all pods
   - Stops port-forwards
   - In local mode: deletes cluster and cleans up
   - In CI mode: lightweight cleanup (CI handles cluster deletion)

### Namespace Replacement

The script automatically replaces `<namespace>` placeholders in values files with the actual namespace value. This happens:

- **During interactive adjustment** (option 2): Immediately after creating local files
- **During deployment**: Before deploying Helm charts (as a safety measure)

The replacement uses the pattern `s|<namespace>|${NAMESPACE}|g` with `|` as delimiter to avoid conflicts with file paths.

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

#!/usr/bin/env bash

#=============================================================================
# KMS Setup Script for Kind (Kubernetes in Docker)
#
# This script sets up KMS in a local Kind cluster for testing purposes.
# It supports different deployment modes:
#   - threshold: Standard threshold mode (4 parties)
#   - centralized: Single party mode
#
# Usage:
#   ./setup_kms_in_kind.sh [OPTIONS]
#
# Options:
#   --namespace <name>          Kubernetes namespace (default: kms-test)
#   --kms-core-tag <tag>        KMS Core image tag (default: latest-dev)
#   --kms-core-client-tag <tag> KMS Core Client image tag (default: latest-dev)
#   --deployment-type <type>    Deployment type: threshold|centralized (default: threshold)
#   --num-parties <num>         Number of parties for threshold mode (default: 4)
#   --cleanup                   Cleanup existing deployment before setup
#   --build                     Build and load Docker images locally
#   --local                     Run in local mode (full cleanup on exit)
#   --help                      Show this help message
#
#=============================================================================

# Exit on error, undefined variables, and pipe failures
set -euo pipefail

#=============================================================================
# Configuration Variables
#=============================================================================
NAMESPACE="${NAMESPACE:-kms-test}"
KMS_CORE_IMAGE_TAG="${KMS_CORE_IMAGE_TAG:-latest}"
KMS_CORE_CLIENT_IMAGE_TAG="${KMS_CORE_CLIENT_IMAGE_TAG:-latest}"
DEPLOYMENT_TYPE="${DEPLOYMENT_TYPE:-threshold}"
NUM_PARTIES="${NUM_PARTIES:-$([ "${DEPLOYMENT_TYPE}" = "centralized" ] && echo "1" || echo "4")}"
KUBE_CONFIG="${HOME}/.kube/kind_config"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUST_IMAGE_VERSION="$(cat ${REPO_ROOT}/toolchain.txt)"
CLEANUP=false
BUILD=false
LOCAL=false

#=============================================================================
# Platform Detection
#=============================================================================

# Detect OS and set platform-specific commands
detect_platform() {
    case "$(uname -s)" in
        Darwin*)
            OS="macos"
            BASE64_CMD="base64"
            ;;
        Linux*)
            OS="linux"
            BASE64_CMD="base64 -w 0"
            ;;
        *)
            log_error "Unsupported OS: $(uname -s)"
            exit 1
            ;;
    esac
}

#=============================================================================
# Color Codes for Output
#=============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

#=============================================================================
# Logging Functions
#=============================================================================
log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

#=============================================================================
# Argument Parsing
#=============================================================================

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --namespace)
                NAMESPACE="$2"
                shift 2
                ;;
            --kms-core-tag)
                KMS_CORE_IMAGE_TAG="$2"
                shift 2
                ;;
            --kms-core-client-tag)
                KMS_CORE_CLIENT_IMAGE_TAG="$2"
                shift 2
                ;;
            --deployment-type)
                DEPLOYMENT_TYPE="$2"
                shift 2
                ;;
            --num-parties)
                NUM_PARTIES="$2"
                shift 2
                ;;
            --cleanup)
                CLEANUP=true
                shift
                ;;
            --build)
                BUILD=true
                shift
                ;;
            --local)
                LOCAL=true
                shift
                ;;
            --help)
                grep "^#" "$0" | grep -v "^#!/" | sed 's/^# //'
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

#=============================================================================
# Configuration Validation
#=============================================================================

# Validate and adjust configuration based on deployment type
validate_config() {
    # Validate deployment type
    if [[ "${DEPLOYMENT_TYPE}" != "centralized" ]] && [[ "${DEPLOYMENT_TYPE}" != "threshold" ]]; then
        log_error "Invalid DEPLOYMENT_TYPE: ${DEPLOYMENT_TYPE}. Must be 'threshold' or 'centralized'"
        exit 1
    fi

    # Override NUM_PARTIES for centralized mode if explicitly set to something else
    if [[ "${DEPLOYMENT_TYPE}" == "centralized" ]] && [[ "${NUM_PARTIES}" != "1" ]]; then
        log_warn "NUM_PARTIES=${NUM_PARTIES} ignored for centralized deployment, using 1"
        NUM_PARTIES=1
    fi

    # Check if image tags are provided or build flag is set
    if [[ "${KMS_CORE_IMAGE_TAG}" == "latest" ]] || [[ "${KMS_CORE_CLIENT_IMAGE_TAG}" == "latest" ]]; then
        if [[ "${BUILD}" != "true" ]]; then
            log_error "Image tags are set to 'latest' but --build flag is not set"
            log_error "Either provide specific image tags (--kms-core-tag, --kms-core-client-tag) or use --build to build locally"
            exit 1
        fi
    fi
}

check_local_resources() {
    # Check resource requirements for local development
    if [[ "${LOCAL}" == "true" ]]; then
        # Extract resource values from values files
        local KMS_CORE_VALUES="${SCRIPT_DIR}/../kms/values-kms-test.yaml"
        local KMS_CORE_CLIENT_VALUES="${SCRIPT_DIR}/../kms/values-kms-service-init-kms-test.yaml"

        # Parse memory and CPU from kms-core values (values-kms-test.yaml)
        local KMS_CORE_MEMORY=$(grep -A 10 "resources:" "${KMS_CORE_VALUES}" | grep "memory:" | head -1 | awk '{print $2}' | sed 's/Gi//')
        local KMS_CORE_CPU=$(grep -A 10 "resources:" "${KMS_CORE_VALUES}" | grep "cpu:" | head -1 | awk '{print $2}')

        # Parse memory and CPU from kms-core-client values (values-kms-service-init-kms-test.yaml)
        local KMS_CORE_CLIENT_MEMORY=$(grep -A 10 "resources:" "${KMS_CORE_CLIENT_VALUES}" | grep "memory:" | head -1 | awk '{print $2}' | sed 's/Gi//')
        local KMS_CORE_CLIENT_CPU=$(grep -A 10 "resources:" "${KMS_CORE_CLIENT_VALUES}" | grep "cpu:" | head -1 | awk '{print $2}')

        # Calculate total resources
        local TOTAL_KMS_CORE_MEMORY=$((KMS_CORE_MEMORY * NUM_PARTIES))
        local TOTAL_KMS_CORE_CPU=$((KMS_CORE_CPU * NUM_PARTIES))
        local TOTAL_MEMORY=$((TOTAL_KMS_CORE_MEMORY + KMS_CORE_CLIENT_MEMORY))
        local TOTAL_CPU=$((TOTAL_KMS_CORE_CPU + KMS_CORE_CLIENT_CPU))

        # Retrieve num_seccion_preproc
        local NUM_SESSIN_PREPROC=$(grep "numSessionsPreproc:" "${KMS_CORE_VALUES}" | head -1 | awk '{print $2}')

        log_warn "========================================="
        log_warn "Running in LOCAL mode"
        log_warn "========================================="
        log_warn "The default Helm values require significant resources:"
        log_warn ""
        log_warn "KMS Core Client (1 instance):"
        log_warn "  - Memory: ${KMS_CORE_CLIENT_MEMORY}Gi"
        log_warn "  - CPU: ${KMS_CORE_CLIENT_CPU} cores"
        log_warn ""
        log_warn "KMS Core (${NUM_PARTIES} parties):"
        log_warn "  - Memory per core: ${KMS_CORE_MEMORY}Gi"
        log_warn "  - CPU per core: ${KMS_CORE_CPU} cores"
        log_warn "  - Total: ${TOTAL_KMS_CORE_MEMORY}Gi RAM, ${TOTAL_KMS_CORE_CPU} CPU cores"
        log_warn ""
        log_warn "KMS Core num_sessions_preproc:"
        log_warn "  - num_sessions_preproc: ${NUM_SESSIN_PREPROC}"
        log_warn ""
        log_warn "TOTAL RESOURCES REQUIRED:"
        log_warn "  - Memory: ${TOTAL_MEMORY}Gi"
        log_warn "  - CPU: ${TOTAL_CPU} cores"
        log_warn "========================================="
        log_warn ""
        log_warn "If your system doesn't have these resources, you MUST adjust the values files:"
        log_warn "  - ${KMS_CORE_VALUES}"
        log_warn "  - ${KMS_CORE_CLIENT_VALUES}"
        log_warn ""
        log_warn "Look for sections marked with:"
        log_warn "  #==========RESOURCES TO ADJUST BASED ON ENVIRONMENT=========="
        log_warn ""
        log_warn "Recommended minimum for local testing with FHE_PARAMS=Test :"
        log_warn "  - KMS Core Client: 4Gi RAM, 2 CPU cores"
        log_warn "  - KMS Core (per party): 4Gi RAM, 2 CPU cores"
        log_warn "  - Total for ${NUM_PARTIES} parties: $((4 + 4 * NUM_PARTIES))Gi RAM, $((2 + 2 * NUM_PARTIES)) CPU cores"
        log_warn "========================================="
        echo ""

        # Prompt user for action
        echo "Choose an option:"
        echo "  1) Continue with current values"
        echo "  2) Adjust resources interactively"
        echo "  3) Cancel and edit files manually"
        read -p "Enter your choice (1/2/3): " -r CHOICE
        echo ""

        case "${CHOICE}" in
            1)
                log_info "Continuing with current resource values..."
                ;;
            2)
                log_info "Interactive resource adjustment..."
                echo ""
                # Create local values files
                log_info "Creating local values files..."
                cp "${KMS_CORE_VALUES}" "${SCRIPT_DIR}"/../kms/local-values-kms-test.yaml
                cp "${KMS_CORE_CLIENT_VALUES}" "${SCRIPT_DIR}"/../kms/local-values-kms-service-init-kms-test.yaml
                local KMS_CORE_VALUES="${SCRIPT_DIR}/../kms/local-values-kms-test.yaml"
                local KMS_CORE_CLIENT_VALUES="${SCRIPT_DIR}/../kms/local-values-kms-service-init-kms-test.yaml"

                # Adjust KMS Core resources
                echo ""
                echo "Adjusting KMS Core resources..."
                read -p "KMS Core Memory per party (current: ${KMS_CORE_MEMORY}Gi, recommended: 4Gi): " -r NEW_CORE_MEM
                NEW_CORE_MEM="${NEW_CORE_MEM:-${KMS_CORE_MEMORY}}"
                read -p "KMS Core CPU per party (current: ${KMS_CORE_CPU}, recommended: 2): " -r NEW_CORE_CPU
                NEW_CORE_CPU="${NEW_CORE_CPU:-${KMS_CORE_CPU}}"
                read -p "KMS Core num_sessions_preproc (current: ${NUM_SESSIN_PREPROC}, recommended: ${NEW_CORE_CPU}): " -r NEW_NUM_SESSIN_PREPROC
                NEW_NUM_SESSIN_PREPROC="${NEW_NUM_SESSIN_PREPROC:-${NUM_SESSIN_PREPROC}}"

                # Adjust KMS Core Client resources
                echo ""
                echo "Adjusting KMS Core Client resources..."
                read -p "KMS Core Client Memory (current: ${KMS_CORE_CLIENT_MEMORY}Gi, recommended: 4Gi): " -r NEW_CLIENT_MEM
                NEW_CLIENT_MEM="${NEW_CLIENT_MEM:-${KMS_CORE_CLIENT_MEMORY}}"
                read -p "KMS Core Client CPU (current: ${KMS_CORE_CLIENT_CPU}, recommended: 2): " -r NEW_CLIENT_CPU
                NEW_CLIENT_CPU="${NEW_CLIENT_CPU:-${KMS_CORE_CLIENT_CPU}}"


                # Update the values files with sed (platform-aware)
                log_info "Updating values files..."

                # Update KMS Core Client values
                if [[ "${OS}" == "macos" ]]; then
                    sed -i '' "s/memory: ${KMS_CORE_MEMORY}Gi/memory: ${NEW_CORE_MEM}Gi/g" "${KMS_CORE_VALUES}"
                    sed -i '' "s/cpu: ${KMS_CORE_CPU}/cpu: ${NEW_CORE_CPU}/g" "${KMS_CORE_VALUES}"
                    sed -i '' "s/numSessionsPreproc: ${NUM_SESSIN_PREPROC}/numSessionsPreproc: ${NEW_NUM_SESSIN_PREPROC}/g" "${KMS_CORE_VALUES}"
                    sed -i '' "s/memory: ${KMS_CORE_CLIENT_MEMORY}Gi/memory: ${NEW_CLIENT_MEM}Gi/g" "${KMS_CORE_CLIENT_VALUES}"
                    sed -i '' "s/cpu: ${KMS_CORE_CLIENT_CPU}/cpu: ${NEW_CLIENT_CPU}/g" "${KMS_CORE_CLIENT_VALUES}"
                else
                    sed -i "s/memory: ${KMS_CORE_MEMORY}Gi/memory: ${NEW_CORE_MEM}Gi/g" "${KMS_CORE_VALUES}"
                    sed -i "s/cpu: ${KMS_CORE_CPU}/cpu: ${NEW_CORE_CPU}/g" "${KMS_CORE_VALUES}"
                    sed -i "s/numSessionsPreproc: ${NUM_SESSIN_PREPROC}/numSessionsPreproc: ${NEW_NUM_SESSIN_PREPROC}/g" "${KMS_CORE_VALUES}"
                    sed -i "s/memory: ${KMS_CORE_CLIENT_MEMORY}Gi/memory: ${NEW_CLIENT_MEM}Gi/g" "${KMS_CORE_CLIENT_VALUES}"
                    sed -i "s/cpu: ${KMS_CORE_CLIENT_CPU}/cpu: ${NEW_CLIENT_CPU}/g" "${KMS_CORE_CLIENT_VALUES}"
                fi

                log_info "New local values files created successfully:"
                log_info "- ${SCRIPT_DIR}/../kms/local-values-kms-test.yaml"
                log_info "- ${SCRIPT_DIR}/../kms/local-values-kms-service-init-kms-test.yaml"

                # Calculate new totals
                local NEW_TOTAL_MEM=$((NEW_CORE_MEM * NUM_PARTIES + NEW_CLIENT_MEM))
                local NEW_TOTAL_CPU=$((NEW_CORE_CPU * NUM_PARTIES + NEW_CLIENT_CPU))
                local NEW_TOTAL_NUM_SESSIN_PREPROC=${NEW_NUM_SESSIN_PREPROC}

                log_info ""
                log_info "======================NEW RESOURCES ADJUSTMENT========================="
                log_info "New total resources: ${NEW_TOTAL_MEM}Gi RAM, ${NEW_TOTAL_CPU} CPU cores"
                log_info "New total num_sessions_preproc: ${NEW_TOTAL_NUM_SESSIN_PREPROC}"
                log_info "======================================================================="
                log_info ""
                ;;
            3)
                log_info "Setup cancelled. Please edit the values files manually and run again."
                exit 0
                ;;
            *)
                log_error "Invalid choice. Setup cancelled."
                exit 1
                ;;
        esac
    fi
}

#=============================================================================
# Prerequisite Checks
#=============================================================================

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    local missing_tools=()

    for tool in kubectl helm kind docker; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_error "Please install them before running this script"
        exit 1
    fi

    log_info "All prerequisites met"
}

#=============================================================================
# Kind Cluster Setup
#=============================================================================

# Setup Kind cluster
setup_kind_cluster() {
    log_info "Setting up Kind cluster..."

    if kind get clusters | grep -q "^kms-test$"; then
        log_warn "Kind cluster 'kms-test' already exists"
        if [[ "$CLEANUP" == "true" ]]; then
            log_info "Deleting existing cluster..."
            kind delete cluster --name kms-test --kubeconfig "${KUBE_CONFIG}"
        else
            log_info "Using existing cluster"
            return 0
        fi
    fi

    log_info "Creating Kind cluster..."
    kind create cluster --name "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}" --config - <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
EOF

    log_info "Kind cluster created successfully"
}

#=============================================================================
# Kubernetes Configuration
#=============================================================================

# Setup Kubernetes context
setup_kube_context() {
    log_info "Setting up Kubernetes context..."

    log_info "Available contexts:"
    kubectl config get-contexts --kubeconfig "${KUBE_CONFIG}"

    log_info "Using kind-"${NAMESPACE}" context..."
    kubectl config use-context kind-"${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}"

    log_info "Checking cluster nodes..."
    kubectl get nodes --kubeconfig "${KUBE_CONFIG}"

    log_info "Kubernetes context configured"
}

# Setup namespace
setup_namespace() {
    log_info "Setting up namespace: ${NAMESPACE}"

    if kubectl get namespace "${NAMESPACE}" &> /dev/null; then
        if [[ "$CLEANUP" == "true" ]]; then
            log_info "Deleting existing namespace..."
            kubectl delete namespace "${NAMESPACE}" --wait=true --kubeconfig "${KUBE_CONFIG}" || true
        else
            log_warn "Namespace already exists, skipping creation"
            return 0
        fi
    fi

    kubectl create namespace "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}"
    kubectl get namespace --kubeconfig "${KUBE_CONFIG}"
    log_info "Namespace created"
}

# Setup registry credentials for pulling private images
setup_registry_credentials() {
    log_info "Setting up registry credentials..."

    if [[ "$LOCAL" == "true" ]]; then
        log_info "Skipping registry credentials setup for local deployment"
        kubectl apply -f ${HOME}/dockerconfig.yaml -n ${NAMESPACE} --kubeconfig ${KUBE_CONFIG}
        return 0
    fi

    # Check if GITHUB_TOKEN is set
    if [[ -z "${GITHUB_TOKEN:-}" ]]; then
        log_warn "GITHUB_TOKEN not set, skipping registry credentials setup"
        log_warn "Set GITHUB_TOKEN environment variable to enable private image pulls"
        return 0
    fi

    # Create dockerconfigjson for ghcr.io authentication
    local DOCKER_CONFIG_JSON
    DOCKER_CONFIG_JSON=$(cat <<JSON | ${BASE64_CMD}
{
  "auths": {
    "ghcr.io": {
      "auth": "$(echo -n "zws-bot:${GITHUB_TOKEN}" | ${BASE64_CMD})"
    }
  }
}
JSON
)

    # Apply the secret to Kubernetes
    cat <<EOF | kubectl apply -f - --namespace "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}"
apiVersion: v1
data:
  .dockerconfigjson: ${DOCKER_CONFIG_JSON}
kind: Secret
metadata:
  name: registry-credentials
type: kubernetes.io/dockerconfigjson
EOF

    # Verify secret exists without printing its contents
    if kubectl get secret registry-credentials -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}" &> /dev/null; then
        log_info "Registry credentials configured successfully"
    else
        log_error "Failed to create registry credentials"
        return 1
    fi
}

#=============================================================================
# Helm Configuration
#=============================================================================

# Setup Helm repositories
setup_helm_repos() {
    log_info "Setting up Helm repositories..."

    helm repo add minio https://charts.min.io/ || true
    helm repo update

    log_info "Helm repositories configured"
}

#=============================================================================
# Container Build and Load
#=============================================================================

# Build and load Docker images into Kind cluster
build_container() {
  log_info "Building container for core-service ..."
  docker buildx build -t "ghcr.io/zama-ai/kms/core-service:latest-dev" \
    -f "${REPO_ROOT}/docker/core/service/Dockerfile" \
    --build-arg RUST_IMAGE_VERSION=${RUST_IMAGE_VERSION} \
    "${REPO_ROOT}/" \
    --load

  log_info "Loading container for core-service in kind ..."
  kind load docker-image "ghcr.io/zama-ai/kms/core-service:latest-dev" \
    -n "${NAMESPACE}" \
    --kubeconfig "${KUBE_CONFIG}" \
    --nodes "${NAMESPACE}"-worker

  log_info "Building container for core-client ..."
  docker buildx build -t "ghcr.io/zama-ai/kms/core-client:latest-dev" \
    -f "${REPO_ROOT}/docker/core/client/Dockerfile" \
    --build-arg RUST_IMAGE_VERSION=${RUST_IMAGE_VERSION} \
    "${REPO_ROOT}/" \
    --load

  log_info "Loading container for core-client in kind ..."
  kind load docker-image "ghcr.io/zama-ai/kms/core-client:latest-dev" \
    -n "${NAMESPACE}" \
    --kubeconfig "${KUBE_CONFIG}" \
    --nodes "${NAMESPACE}"-worker
}

#=============================================================================
# MinIO Deployment
#=============================================================================

# Deploy MinIO object storage
deploy_minio() {
    log_info "Deploying MinIO..."

    helm upgrade --install minio minio/minio \
        --namespace "${NAMESPACE}" \
        --kubeconfig "${KUBE_CONFIG}" \
        --create-namespace \
        --wait \
        --timeout 5m \
        -f "${REPO_ROOT}/ci/kube-testing/infra/minio-values.yaml"

    log_info "MinIO deployed successfully"
}

#=============================================================================
# KMS Core Deployment
#=============================================================================

# Deploy KMS Core based on deployment type
deploy_kms_core() {
    log_info "Deploying KMS Core (${DEPLOYMENT_TYPE} mode with ${NUM_PARTIES} parties)..."

    case "${DEPLOYMENT_TYPE}" in
        threshold)
            deploy_threshold_mode
            ;;
        centralized)
            deploy_centralized_mode
            ;;
        *)
            log_error "Unknown deployment type: ${DEPLOYMENT_TYPE}"
            exit 1
            ;;
    esac
}

# Deploy threshold mode with multiple parties
deploy_threshold_mode() {
    log_info "Deploying KMS Core in threshold mode with ${NUM_PARTIES} parties..."

    if [[ "${LOCAL}" == "true" ]]; then
      VALUES_FILE_KMS_CORE="${REPO_ROOT}/ci/kube-testing/kms/local-values-kms-test.yaml"
      VALUES_FILE_KMS_CORE_INIT="${REPO_ROOT}/ci/kube-testing/kms/local-values-kms-service-init-kms-test.yaml"
    else
      VALUES_FILE_KMS_CORE="${REPO_ROOT}/ci/kube-testing/kms/values-kms-test.yaml"
      VALUES_FILE_KMS_CORE_INIT="${REPO_ROOT}/ci/kube-testing/kms/values-kms-service-init-kms-test.yaml"
    fi

    for i in $(seq 1 "${NUM_PARTIES}"); do
        log_info "Deploying KMS Core party ${i}/${NUM_PARTIES}..."
        helm upgrade --install "kms-service-threshold-${i}-${NAMESPACE}" \
            "${REPO_ROOT}/charts/kms-core" \
            --namespace "${NAMESPACE}" \
            --kubeconfig "${KUBE_CONFIG}" \
            -f "${VALUES_FILE_KMS_CORE}" \
            --set kmsCore.image.tag="${KMS_CORE_IMAGE_TAG}" \
            --set kmsCoreClient.image.tag="${KMS_CORE_CLIENT_IMAGE_TAG}" \
            --set kmsPeers.id="${i}" \
            --wait \
            --timeout 10m &
    done
    wait

    log_info "Waiting for KMS Core pods to be ready..."
    for i in $(seq 1 "${NUM_PARTIES}"); do
        kubectl wait --for=condition=ready pod -l app=kms-core \
            -n "${NAMESPACE}" --timeout=10m --kubeconfig "${KUBE_CONFIG}"
        kubectl logs kms-service-threshold-${i}-${NAMESPACE}-core-${i} -n ${NAMESPACE} --kubeconfig ${KUBE_CONFIG}
    done

    # Deploy initialization job
    log_info "Deploying KMS Core initialization job..."
    helm upgrade --install kms-core-init \
        "${REPO_ROOT}/charts/kms-core" \
        --namespace "${NAMESPACE}" \
        --kubeconfig "${KUBE_CONFIG}" \
        -f "${VALUES_FILE_KMS_CORE_INIT}" \
        --set kmsCore.image.tag="${KMS_CORE_IMAGE_TAG}" \
        --set kmsCoreClient.image.tag="${KMS_CORE_CLIENT_IMAGE_TAG}" \
        --wait \
        --wait-for-jobs \
        --timeout 20m

    log_info "Waiting for initialization to complete..."
    kubectl wait --for=condition=complete job -l app=kms-threshold-init-job \
        -n "${NAMESPACE}" --timeout=10m --kubeconfig "${KUBE_CONFIG}"

    # Deploy key generation job
    # log_info "Deploying KMS Core key generation job..."
    # helm upgrade --install kms-core-gen-keys \
    #     "${REPO_ROOT}/charts/kms-core" \
    #     --namespace "${NAMESPACE}" \
    #     --kubeconfig "${KUBE_CONFIG}" \
    #     -f "${REPO_ROOT}/ci/kube-testing/kms/values-kms-service-gen-keys-kms-test.yaml" \
    #     --set kmsCore.image.tag="${KMS_CORE_IMAGE_TAG}" \
    #     --set kmsCoreClient.image.tag="${KMS_CORE_CLIENT_IMAGE_TAG}" \
    #     --wait \
    #     --wait-for-jobs \
    #     --timeout 40m

    # log_info "Waiting for key generation to complete..."
    # kubectl wait --for=condition=complete job -l app=kms-core-client-gen-keys \
    #     -n "${NAMESPACE}" --timeout=10m --kubeconfig "${KUBE_CONFIG}"

    log_info "Threshold mode deployment completed"
}

# Deploy centralized mode with single party
deploy_centralized_mode() {
    log_info "Deploying KMS Core in centralized mode..."

    if [[ "${LOCAL}" == "true" ]]; then
      VALUES_FILE_KMS_CORE="${REPO_ROOT}/ci/kube-testing/kms/local-values-kms-test.yaml"
    else
      VALUES_FILE_KMS_CORE="${REPO_ROOT}/ci/kube-testing/kms/values-kms-test.yaml"
    fi

    helm upgrade --install kms-core \
        "${REPO_ROOT}/charts/kms-core" \
        --namespace "${NAMESPACE}" \
        --kubeconfig "${KUBE_CONFIG}" \
        -f "${VALUES_FILE_KMS_CORE}" \
        --set kmsCore.image.tag="${KMS_CORE_IMAGE_TAG}" \
        --set kmsCoreClient.image.tag="${KMS_CORE_CLIENT_IMAGE_TAG}" \
        --wait \
        --timeout 10m

    log_info "Waiting for KMS Core pod to be ready..."
    kubectl wait --for=condition=ready pod -l app=kms-core \
        -n "${NAMESPACE}" --timeout=10m

    log_info "Centralized mode deployment completed"
}

#=============================================================================
# Port Forwarding Setup
#=============================================================================

# Setup port forwarding for local access to services
setup_port_forwarding() {
    log_info "Setting up port forwarding..."

    # Port forward MinIO
    log_info "Port forwarding MinIO (9000:9000)..."
    kubectl port-forward \
        -n "${NAMESPACE}" \
        svc/minio \
        9000:9000 \
        --kubeconfig "${KUBE_CONFIG}" \
        > /dev/null 2>&1 \
        &

    # Port forward KMS Core services
    case "${DEPLOYMENT_TYPE}" in
        threshold)
            for i in $(seq 1 "${NUM_PARTIES}"); do
                local port=$((50000 + i * 100))
                log_info "Port forwarding kms-core-${i} (${port}:50100)..."
                kubectl port-forward \
                    -n "${NAMESPACE}" \
                    "svc/kms-service-threshold-${i}-${NAMESPACE}-core-${i}" \
                    "${port}:50100" \
                    --kubeconfig "${KUBE_CONFIG}" \
                    > /dev/null 2>&1 \
                    &
            done
            ;;
        centralized)
            log_info "Port forwarding kms-core (50100:50100)..."
            kubectl port-forward \
                -n "${NAMESPACE}" \
                svc/kms-core \
                50100:50100 \
                --kubeconfig "${KUBE_CONFIG}" \
                > /dev/null 2>&1 \
                &
            ;;
    esac

    log_info "Port forwarding setup complete"
}

#=============================================================================
# Cleanup Function
#=============================================================================

# Cleanup resources on script termination (triggered by SIGINT/SIGTERM)
cleanup() {
    log_info "========================================="
    log_info "Cleanup function triggered by signal"
    log_info "========================================="
    log_info "Cleaning up KMS resources..."

    # Stop all port forwarding processes
    log_info "Stopping port-forward processes..."
    pkill -f "kubectl port-forward" || true

    # Conditional cleanup based on execution mode
    if [[ "$LOCAL" == "true" ]]; then
        # Full cleanup for local development
        log_info "Running full cleanup (local mode)..."
        # Uninstall Helm releases
        case "${DEPLOYMENT_TYPE}" in
            threshold)
                for i in $(seq 1 "${NUM_PARTIES}"); do
                  POD_NAME="kms-service-threshold-${i}-${NAMESPACE}-core-${i}"
                  if kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}" &>/dev/null; then
                    kubectl logs "${POD_NAME}" -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}" \
                        > "/tmp/kms-service-threshold-${i}-${NAMESPACE}-core-${i}.log" 2>/dev/null && \
                    echo "  Collected logs from ${POD_NAME}" || \
                    echo "  Failed to collect logs from ${POD_NAME}"
                  fi
                  helm uninstall -n "${NAMESPACE}" "kms-core-${i}" 2>/dev/null || true
                done
                ;;
            centralized)
                kubectl logs kms-core -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}" \
                > "/tmp/kms-core-${NAMESPACE}.log" 2>/dev/null && \
                echo "  Collected logs from kms-core" || \
                echo "  Failed to collect logs from kms-core"
                helm uninstall -n "${NAMESPACE}" kms-core 2>/dev/null || true
                ;;
        esac
        helm uninstall -n "${NAMESPACE}" kms-core-gen-keys 2>/dev/null || true
        helm uninstall -n "${NAMESPACE}" kms-core-init 2>/dev/null || true
        helm uninstall -n "${NAMESPACE}" minio 2>/dev/null || true
        kubectl delete namespace "${NAMESPACE}" --wait=true 2>/dev/null || true
        kind delete cluster --name ${NAMESPACE} --kubeconfig ${KUBE_CONFIG}
        rm -f "${KUBE_CONFIG}"
    else
        # Lightweight cleanup for CI
        # The CI workflow will handle full cluster cleanup
        log_info "Running lightweight cleanup (CI mode)..."
        log_info "Logs collected and port-forwards stopped. CI will handle cluster cleanup."
    fi

    log_info "Cleanup completed"
    exit 0
}

#=============================================================================
# Main Function
#=============================================================================

# Main execution function
main() {
    parse_args "$@"
    # Initializing platform detection
    detect_platform
    # Validating configuration
    validate_config
    if [[ "${LOCAL}" == "true" ]]; then
      # Adjusting resources
      check_local_resources
    fi

    log_info "Starting KMS setup in Kind..."
    log_info "========================================="
    log_info "Configuration:"
    log_info "  Namespace:                ${NAMESPACE}"
    log_info "  Deployment Type:          ${DEPLOYMENT_TYPE}"
    log_info "  Number of Parties:        ${NUM_PARTIES}"
    log_info "  KMS Core Image Tag:       ${KMS_CORE_IMAGE_TAG}"
    log_info "  KMS CoreClient Image Tag: ${KMS_CORE_CLIENT_IMAGE_TAG}"
    log_info "  Cleanup Mode:             ${CLEANUP}"
    log_info "  Build Locally:            ${BUILD}"
    log_info "  Local Mode:               ${LOCAL}"
    log_info "========================================="

    # Execute setup steps
    check_prerequisites
    setup_kind_cluster
    setup_kube_context
    setup_namespace
    setup_registry_credentials
    setup_helm_repos
    deploy_minio

    # Optionally build and load images
    if [[ "$BUILD" == "true" ]]; then
        build_container
    fi

    deploy_kms_core
    setup_port_forwarding

    # Display success message and access information
    log_info ""
    log_info "========================================="
    log_info "KMS setup completed successfully!"
    log_info "========================================="
    log_info ""
    log_info "Service Access URLs:"
    log_info "  MinIO UI: http://localhost:9000"
    case "${DEPLOYMENT_TYPE}" in
        threshold)
            for i in $(seq 1 "${NUM_PARTIES}"); do
                local port=$((50000 + i * 100))
                log_info "  KMS Core ${i}: http://localhost:${port}"
            done
            ;;
        centralized)
            log_info "  KMS Core: http://localhost:50100"
            ;;
    esac
    log_info ""
    log_info "Cleanup Instructions:"
    log_info "  Script cleanup:  $0 --cleanup"
    log_info "  Manual cleanup:  kind delete cluster --name kms-test"
    log_info ""
    log_info "Port forwarding is running in the background."
    log_info "Press Ctrl+C to stop port forwarding and exit."
    log_info "========================================="

    # Wait for user interrupt to keep port-forwards alive
    # Start a background sleep and wait for it - this makes the script properly interruptible
    while true; do
        sleep 3600 &
        wait $! || true
    done
}

#=============================================================================
# Script Execution
#=============================================================================

# Trap cleanup on interrupt and termination signals (not on normal exit)
trap cleanup INT TERM

# Execute main function with all arguments
main "$@"

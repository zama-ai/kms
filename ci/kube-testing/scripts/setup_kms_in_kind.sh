#!/usr/bin/env bash

##############################################################################
# KMS Setup Script for Kind (Kubernetes in Docker)
#
# This script sets up KMS in a local Kind cluster for testing purposes.
# It supports different deployment modes:
# - threshold: Standard threshold mode (4 parties)
# - centralized: Single party mode
#
# Usage:
#   ./setup_kms_in_kind.sh [OPTIONS]
#
# Options:
#   --namespace <name>           Kubernetes namespace (default: kms-test)
#   --kms-core-tag <tag>        KMS Core image tag (default: latest)
#   --kms-client-tag <tag>      KMS Core Client image tag (default: latest)
#   --deployment-type <type>    Deployment type: threshold|centralized (default: threshold)
#   --num-parties <num>         Number of parties for threshold mode (default: 4)
#   --cleanup                   Cleanup existing deployment before setup
#   --help                      Show this help message
#
##############################################################################

set -euo pipefail

# Default configuration
NAMESPACE="${NAMESPACE:-kms-test}"
KMS_CORE_IMAGE_TAG="${KMS_CORE_IMAGE_TAG:-latest}"
KMS_CORE_CLIENT_IMAGE_TAG="${KMS_CORE_CLIENT_IMAGE_TAG:-latest}"
DEPLOYMENT_TYPE="${DEPLOYMENT_TYPE:-threshold}"
NUM_PARTIES="${NUM_PARTIES:-4}"
CLEANUP=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

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

# Setup Kind cluster
setup_kind_cluster() {
    log_info "Setting up Kind cluster..."

    if kind get clusters | grep -q "^kms-test$"; then
        log_warn "Kind cluster 'kms-test' already exists"
        if [[ "$CLEANUP" == "true" ]]; then
            log_info "Deleting existing cluster..."
            kind delete cluster --name kms-test
        else
            log_info "Using existing cluster"
            return 0
        fi
    fi

    log_info "Creating Kind cluster..."
    kind create cluster --name "${NAMESPACE}" --config - <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
EOF

    log_info "Kind cluster created successfully"
}

# Setup Kubernetes context
setup_kube_context() {
    log_info "Setting up Kubernetes context..."

    log_info "Available contexts:"
    kubectl config get-contexts --kubeconfig "${KUBECONFIG}"

    log_info "Using kind-"${NAMESPACE}" context..."
    kubectl config use-context kind-"${NAMESPACE}" --kubeconfig "${KUBECONFIG}"

    log_info "Checking cluster nodes..."
    kubectl get nodes

    log_info "Kubernetes context configured"
}

# Setup namespace
setup_namespace() {
    log_info "Setting up namespace: ${NAMESPACE}"

    if kubectl get namespace "${NAMESPACE}" &> /dev/null; then
        if [[ "$CLEANUP" == "true" ]]; then
            log_info "Deleting existing namespace..."
            kubectl delete namespace "${NAMESPACE}" --wait=true || true
        else
            log_warn "Namespace already exists, skipping creation"
            return 0
        fi
    fi

    kubectl create namespace "${NAMESPACE}"
    kubectl get namespace
    log_info "Namespace created"
}

# Setup registry credentials
setup_registry_credentials() {
    log_info "Setting up registry credentials..."

    # Check if GITHUB_TOKEN is set
    if [[ -z "${GITHUB_TOKEN:-}" ]]; then
        log_warn "GITHUB_TOKEN not set, skipping registry credentials setup"
        log_warn "Set GITHUB_TOKEN environment variable to enable private image pulls"
        return 0
    fi

    # Create dockerconfigjson for ghcr.io authentication
    local DOCKER_CONFIG_JSON
    DOCKER_CONFIG_JSON=$(cat <<JSON | base64 -w 0
{
  "auths": {
    "ghcr.io": {
      "auth": "$(echo -n "zws-bot:${GITHUB_TOKEN}" | base64 -w 0)"
    }
  }
}
JSON
)

    # Apply the secret to Kubernetes
    cat <<EOF | kubectl apply -f - --namespace "${NAMESPACE}"
apiVersion: v1
data:
  .dockerconfigjson: ${DOCKER_CONFIG_JSON}
kind: Secret
metadata:
  name: registry-credentials
type: kubernetes.io/dockerconfigjson
EOF

    kubectl get secrets registry-credentials -n "${NAMESPACE}" -o yaml
    log_info "Registry credentials configured"
}

# Setup Helm repositories
setup_helm_repos() {
    log_info "Setting up Helm repositories..."

    helm repo add minio https://charts.min.io/ || true
    helm repo update

    log_info "Helm repositories configured"
}

# Deploy MinIO
deploy_minio() {
    log_info "Deploying MinIO..."

    helm upgrade --install minio minio/minio \
        --namespace "${NAMESPACE}" \
        --create-namespace \
        --wait \
        --timeout 5m \
        -f "${REPO_ROOT}/ci/kube-testing/minio/values-minio-kms-test.yaml"

    log_info "MinIO deployed successfully"
}

# Deploy KMS Core
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

# Deploy threshold mode
deploy_threshold_mode() {
    log_info "Deploying KMS Core in threshold mode with ${NUM_PARTIES} parties..."

    for i in $(seq 1 "${NUM_PARTIES}"); do
        log_info "Deploying KMS Core party ${i}/${NUM_PARTIES}..."
        helm upgrade --install "kms-core-${i}" \
            "${REPO_ROOT}/charts/kms-core" \
            --namespace "${NAMESPACE}" \
            -f "${REPO_ROOT}/ci/kube-testing/kms/values-kms-test.yaml" \
            -f "${REPO_ROOT}/ci/kube-testing/kms/values-kms-service-threshold-${i}-kms-test.yaml" \
            --set kmsCore.image.tag="${KMS_CORE_IMAGE_TAG}" \
            --set kmsCoreClient.image.tag="${KMS_CORE_CLIENT_IMAGE_TAG}" \
            --wait \
            --timeout 10m
    done

    log_info "Waiting for KMS Core pods to be ready..."
    for i in $(seq 1 "${NUM_PARTIES}"); do
        kubectl wait --for=condition=ready pod "kms-core-${i}" \
            -n "${NAMESPACE}" --timeout=10m
    done

    # Deploy initialization job
    log_info "Deploying KMS Core initialization job..."
    helm upgrade --install kms-core-init \
        "${REPO_ROOT}/charts/kms-core" \
        --namespace "${NAMESPACE}" \
        -f "${REPO_ROOT}/ci/kube-testing/kms/values-kms-service-init-kms-test.yaml" \
        --set kmsCore.image.tag="${KMS_CORE_IMAGE_TAG}" \
        --set kmsCoreClient.image.tag="${KMS_CORE_CLIENT_IMAGE_TAG}" \
        --wait \
        --wait-for-jobs \
        --timeout 20m

    log_info "Waiting for initialization to complete..."
    kubectl wait --for=condition=complete job -l app=kms-threshold-init-job \
        -n "${NAMESPACE}" --timeout=10m

    # Deploy key generation job
    log_info "Deploying KMS Core key generation job..."
    helm upgrade --install kms-core-gen-keys \
        "${REPO_ROOT}/charts/kms-core" \
        --namespace "${NAMESPACE}" \
        -f "${REPO_ROOT}/ci/kube-testing/kms/values-kms-service-gen-keys-kms-test.yaml" \
        --set kmsCore.image.tag="${KMS_CORE_IMAGE_TAG}" \
        --set kmsCoreClient.image.tag="${KMS_CORE_CLIENT_IMAGE_TAG}" \
        --wait \
        --wait-for-jobs \
        --timeout 40m

    log_info "Waiting for key generation to complete..."
    kubectl wait --for=condition=complete job -l app=kms-core-client-gen-keys \
        -n "${NAMESPACE}" --timeout=10m

    log_info "Threshold mode deployment completed"
}

# Deploy centralized mode
deploy_centralized_mode() {
    log_info "Deploying KMS Core in centralized mode..."

    helm upgrade --install kms-core \
        "${REPO_ROOT}/charts/kms-core" \
        --namespace "${NAMESPACE}" \
        -f "${REPO_ROOT}/ci/kube-testing/kms/values-kms-centralized-test.yaml" \
        --set kmsCore.image.tag="${KMS_CORE_IMAGE_TAG}" \
        --set kmsCoreClient.image.tag="${KMS_CORE_CLIENT_IMAGE_TAG}" \
        --wait \
        --timeout 10m

    log_info "Waiting for KMS Core pod to be ready..."
    kubectl wait --for=condition=ready pod -l app=kms-core \
        -n "${NAMESPACE}" --timeout=10m

    log_info "Centralized mode deployment completed"
}

# Setup port forwarding
setup_port_forwarding() {
    log_info "Setting up port forwarding..."

    # Port forward MinIO
    log_info "Port forwarding MinIO (9000:9000)..."
    kubectl port-forward -n "${NAMESPACE}" svc/minio 9000:9000 &

    # Port forward KMS Core services
    case "${DEPLOYMENT_TYPE}" in
        threshold)
            for i in $(seq 1 "${NUM_PARTIES}"); do
                local port=$((50000 + i * 100))
                log_info "Port forwarding kms-core-${i} (${port}:50100)..."
                kubectl port-forward -n "${NAMESPACE}" "svc/kms-core-${i}" "${port}:50100" &
            done
            ;;
        centralized)
            log_info "Port forwarding kms-core (50100:50100)..."
            kubectl port-forward -n "${NAMESPACE}" svc/kms-core 50100:50100 &
            ;;
    esac

    log_info "Port forwarding setup complete"
    log_info "MinIO UI: http://localhost:9000"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up KMS resources..."

    # Uninstall Helm releases
    helm uninstall -n "${NAMESPACE}" kms-core-gen-keys 2>/dev/null || true
    helm uninstall -n "${NAMESPACE}" kms-core-init 2>/dev/null || true

    case "${DEPLOYMENT_TYPE}" in
        threshold)
            for i in $(seq 1 "${NUM_PARTIES}"); do
                helm uninstall -n "${NAMESPACE}" "kms-core-${i}" 2>/dev/null || true
            done
            ;;
        centralized)
            helm uninstall -n "${NAMESPACE}" kms-core 2>/dev/null || true
            ;;
    esac

    helm uninstall -n "${NAMESPACE}" minio 2>/dev/null || true

    # Delete namespace
    kubectl delete namespace "${NAMESPACE}" --wait=true 2>/dev/null || true

    # Kill port forwarding processes
    pkill -f "kubectl port-forward" || true

    log_info "Cleanup completed"
}

# Main function
main() {
    parse_args "$@"

    log_info "Starting KMS setup in Kind..."
    log_info "Configuration:"
    log_info "  Namespace: ${NAMESPACE}"
    log_info "  Deployment Type: ${DEPLOYMENT_TYPE}"
    log_info "  Number of Parties: ${NUM_PARTIES}"
    log_info "  KMS Core Image Tag: ${KMS_CORE_IMAGE_TAG}"
    log_info "  KMS Client Image Tag: ${KMS_CORE_CLIENT_IMAGE_TAG}"
    log_info "  Cleanup: ${CLEANUP}"

    check_prerequisites
    setup_kind_cluster
    setup_kube_context
    setup_namespace
    setup_registry_credentials
    setup_helm_repos
    deploy_minio
    deploy_kms_core
    setup_port_forwarding

    log_info "========================================="
    log_info "KMS setup completed successfully!"
    log_info "========================================="
    log_info ""
    log_info "To access the services:"
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
    log_info "To cleanup, run:"
    log_info "  $0 --cleanup"
    log_info "Or delete the Kind cluster:"
    log_info "  kind delete cluster --name kms-test"
}

# Trap cleanup on exit
trap cleanup EXIT INT TERM

# Run main function
main "$@"

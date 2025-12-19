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
#   --gen-keys                  Generate keys using gen-keys job (only with --local and threshold)
#   --enable-tls                Enable TLS for threshold mode peer communication
#   --collect-logs              Collect logs from pods and exit (for CI use)
#   --help                      Show this help message
#
#=============================================================================

# Exit on error, undefined variables, and pipe failures
set -euo pipefail

#=============================================================================
# Configuration Variables
#=============================================================================
NAMESPACE="${NAMESPACE:-kms-test}"
KMS_CORE_IMAGE_TAG="${KMS_CORE_IMAGE_TAG:-latest-dev}"
KMS_CORE_CLIENT_IMAGE_TAG="${KMS_CORE_CLIENT_IMAGE_TAG:-latest-dev}"
DEPLOYMENT_TYPE="${DEPLOYMENT_TYPE:-threshold}"
NUM_PARTIES="${NUM_PARTIES:-$([ "${DEPLOYMENT_TYPE}" = "centralized" ] && echo "1" || echo "4")}"
KUBE_CONFIG="${HOME}/.kube/kind_config_${DEPLOYMENT_TYPE}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
RUST_IMAGE_VERSION="$(cat ${REPO_ROOT}/toolchain.txt)"
CLEANUP=false
BUILD=false
LOCAL=false
GEN_KEYS=false
ENABLE_TLS=false
COLLECT_LOGS_ONLY=false

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
# Platform-aware sed in-place function
#=============================================================================
sed_inplace() {
    local pattern="$1"
    local file="$2"
    if [[ "${OS}" == "macos" ]]; then
        sed -i '' "${pattern}" "${file}"
    else
        sed -i "${pattern}" "${file}"
    fi
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
# Log Collection Function
#=============================================================================
# Collects logs from all KMS pods and saves them to /tmp for artifact upload
collect_pod_logs() {
    log_info "Collecting pod logs to /tmp for artifact upload..."
    for i in $(seq 1 "${NUM_PARTIES}"); do
        local POD_NAME="kms-service-threshold-${i}-${NAMESPACE}-core-${i}"
        local LOG_FILE="/tmp/kms-core-party-${i}.log"
        log_info "=== Collecting logs for party ${i} (${POD_NAME}) ==="
        {
            echo "=== Init container logs (kms-core-init-load-env) ==="
            kubectl logs "${POD_NAME}" -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}" -c kms-core-init-load-env 2>&1 || \
            echo "No init container logs available"
            echo ""
            echo "=== Main container logs (kms-core) - previous ==="
            kubectl logs "${POD_NAME}" -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}" -c kms-core --previous 2>&1 || \
            echo "No previous main container logs available"
            echo ""
            echo "=== Main container logs (kms-core) - current ==="
            kubectl logs "${POD_NAME}" -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}" -c kms-core 2>&1 || \
            echo "No current main container logs available"
            echo ""
            echo "=== Pod describe ==="
            kubectl describe pod "${POD_NAME}" -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}" 2>&1 || true
        } | tee "${LOG_FILE}"
        log_info "Saved logs to ${LOG_FILE}"
    done
    log_info "Log files saved to /tmp/kms-core-party-*.log"
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
            --gen-keys)
                GEN_KEYS=true
                shift
                ;;
            --enable-tls)
                ENABLE_TLS=true
                shift
                ;;
            --collect-logs)
                COLLECT_LOGS_ONLY=true
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
    if [[ "${KMS_CORE_IMAGE_TAG}" == "latest-dev" ]] || [[ "${KMS_CORE_CLIENT_IMAGE_TAG}" == "latest-dev" ]]; then
        if [[ "${LOCAL}" == "true" ]] && [[ "${BUILD}" != "true" ]]; then
            log_warn "Image tags are set to 'latest-dev' but --build flag is not set"
            log_warn "We're checking if latest-dev image is available locally"
            if $(docker image inspect "ghcr.io/zama-ai/kms/core-service:latest-dev" > /dev/null 2>&1); then
                log_info "core-service:latest-dev image is available locally"
            else
                log_error "core-service:latest-dev image is not available locally"
                log_error "You can build it locally with --build flag"
            fi
            if $(docker image inspect "ghcr.io/zama-ai/kms/core-client:latest-dev" > /dev/null 2>&1); then
                log_info "core-client:latest-dev image is available locally"
            else
                log_error "core-client:latest-dev image is not available locally"
                log_error "You can build it locally with --build flag"
            fi
            read -p "Do you want to use existing images locally? (y/n): " -r EXISTING_IMAGES
            if [[ "${EXISTING_IMAGES}" != "y" ]]; then
                log_error "If you want to build the images locally next time, you need to use --build flag"
                exit 1
            else
                log_info "Using existing images locally"
            fi
        fi
    fi
}

#=============================================================================
# Helper Functions for Local Resource Management
#=============================================================================

# Get file paths (local or base) - sets variables via reference
get_values_file_paths() {
    local use_local="${1:-false}"
    local base_dir="${REPO_ROOT}/ci/kube-testing/kms"

    if [[ "${use_local}" == "true" ]]; then
        echo "${base_dir}/local-values-kms-test.yaml"
        echo "${base_dir}/local-values-kms-service-init-kms-test.yaml"
        if [[ "${GEN_KEYS}" == "true" ]]; then
            echo "${base_dir}/local-values-kms-service-gen-keys-kms-test.yaml"
        fi
    else
        echo "${base_dir}/values-kms-test.yaml"
        echo "${base_dir}/values-kms-service-init-kms-test.yaml"
        if [[ "${GEN_KEYS}" == "true" ]]; then
            echo "${base_dir}/values-kms-service-gen-keys-kms-test.yaml"
        fi
    fi
}

# Check if all required values files exist and are non-empty
check_values_files_exist() {
    local core_file="$1"
    local client_init_file="$2"
    local client_gen_keys_file="${3:-}"

    local files_missing=false
    if [[ ! -s "${core_file}" ]] || [[ ! -s "${client_init_file}" ]]; then
        files_missing=true
    fi
    if [[ -n "${client_gen_keys_file}" ]] && [[ ! -s "${client_gen_keys_file}" ]]; then
        files_missing=true
    fi

    echo "${files_missing}"
}

# Remove local values files if they exist
remove_local_values_files() {
    local base_dir="${REPO_ROOT}/ci/kube-testing/kms"
    local files_to_remove=(
        "${base_dir}/local-values-kms-test.yaml"
        "${base_dir}/local-values-kms-service-init-kms-test.yaml"
    )

    if [[ "${GEN_KEYS}" == "true" ]]; then
        files_to_remove+=("${base_dir}/local-values-kms-service-gen-keys-kms-test.yaml")
    fi

    local any_exist=false
    for file in "${files_to_remove[@]}"; do
        if [[ -f "${file}" ]]; then
            any_exist=true
            break
        fi
    done

    if [[ "${any_exist}" == "true" ]]; then
        log_info "Removing existing local values files..."
        for file in "${files_to_remove[@]}"; do
            rm -f "${file}"
        done
    fi
}

# Copy base values files to local values files
copy_to_local_values_files() {
    local core_base="$1"
    local client_init_base="$2"
    local client_gen_keys_base="${3:-}"

    local base_dir="${REPO_ROOT}/ci/kube-testing/kms"

    log_info "Creating local values files..."
    cp "${core_base}" "${base_dir}/local-values-kms-test.yaml"
    cp "${client_init_base}" "${base_dir}/local-values-kms-service-init-kms-test.yaml"

    if [[ -n "${client_gen_keys_base}" ]]; then
        cp "${client_gen_keys_base}" "${base_dir}/local-values-kms-service-gen-keys-kms-test.yaml"
    fi
}

# Replace namespace placeholder in values files
replace_namespace_in_files() {
    local core_file="$1"
    local client_init_file="$2"
    local client_gen_keys_file="${3:-}"

    # Use '|' as delimiter to avoid conflicts with paths that might contain '/'
    if [[ -f "${core_file}" ]]; then
        if grep -q "<namespace>" "${core_file}" 2>/dev/null; then
            sed_inplace "s|<namespace>|${NAMESPACE}|g" "${core_file}"
            log_info "Replaced <namespace> with ${NAMESPACE} in ${core_file}"
        fi
    fi
    if [[ -f "${client_init_file}" ]]; then
        if grep -q "<namespace>" "${client_init_file}" 2>/dev/null; then
            sed_inplace "s|<namespace>|${NAMESPACE}|g" "${client_init_file}"
            log_info "Replaced <namespace> with ${NAMESPACE} in ${client_init_file}"
        fi
    fi
    if [[ -n "${client_gen_keys_file}" ]] && [[ -f "${client_gen_keys_file}" ]]; then
        if grep -q "<namespace>" "${client_gen_keys_file}" 2>/dev/null; then
            sed_inplace "s|<namespace>|${NAMESPACE}|g" "${client_gen_keys_file}"
            log_info "Replaced <namespace> with ${NAMESPACE} in ${client_gen_keys_file}"
        fi
    fi
}

check_local_resources() {
    # Check resource requirements for local development
    if [[ "${LOCAL}" != "true" ]]; then
        return 0
    fi

    local base_dir="${REPO_ROOT}/ci/kube-testing/kms"

    # Try local files first, fallback to base files
    local KMS_CORE_VALUES="${base_dir}/local-values-kms-test.yaml"
    local KMS_CORE_CLIENT_INIT_VALUES="${base_dir}/local-values-kms-service-init-kms-test.yaml"
    local KMS_CORE_CLIENT_GEN_KEYS_VALUES=""
    if [[ "${GEN_KEYS}" == "true" ]]; then
        KMS_CORE_CLIENT_GEN_KEYS_VALUES="${base_dir}/local-values-kms-service-gen-keys-kms-test.yaml"
    fi

    # Check if files exist
    local files_missing=$(check_values_files_exist "${KMS_CORE_VALUES}" "${KMS_CORE_CLIENT_INIT_VALUES}" "${KMS_CORE_CLIENT_GEN_KEYS_VALUES}")

    if [[ "${files_missing}" == "true" ]]; then
        log_error "One or more local values files are missing or empty:"
        log_error "KMS Core values: ${KMS_CORE_VALUES}"
        log_error "KMS Core Client init values: ${KMS_CORE_CLIENT_INIT_VALUES}"
        if [[ -n "${KMS_CORE_CLIENT_GEN_KEYS_VALUES}" ]]; then
            log_error "KMS Core Client gen keys values: ${KMS_CORE_CLIENT_GEN_KEYS_VALUES}"
        fi
        # Fallback to base files
        KMS_CORE_VALUES="${base_dir}/values-kms-test.yaml"
        KMS_CORE_CLIENT_INIT_VALUES="${base_dir}/values-kms-service-init-kms-test.yaml"
        if [[ "${GEN_KEYS}" == "true" ]]; then
            KMS_CORE_CLIENT_GEN_KEYS_VALUES="${base_dir}/values-kms-service-gen-keys-kms-test.yaml"
        fi
    else
        log_info "Values files found:"
        log_info "KMS Core values: ${KMS_CORE_VALUES}"
        log_info "KMS Core Client init values: ${KMS_CORE_CLIENT_INIT_VALUES}"
        if [[ -n "${KMS_CORE_CLIENT_GEN_KEYS_VALUES}" ]]; then
            log_info "KMS Core Client gen keys values: ${KMS_CORE_CLIENT_GEN_KEYS_VALUES}"
        fi
        log_info "You're are going to use the existing local values files for resource adjustment"
    fi

    # Parse memory and CPU from kms-core values (matching original inline code)
    local KMS_CORE_MEMORY=$(grep -A 10 "resources:" "${KMS_CORE_VALUES}" | grep "memory:" | head -1 | awk '{print $2}' | sed 's/Gi//')
    local KMS_CORE_CPU=$(grep -A 10 "resources:" "${KMS_CORE_VALUES}" | grep "cpu:" | head -1 | awk '{print $2}')

    # Parse memory and CPU from kms-core-client values (matching original inline code)
    local KMS_CORE_CLIENT_MEMORY=$(grep -A 10 "resources:" "${KMS_CORE_CLIENT_INIT_VALUES}" | grep "memory:" | head -1 | awk '{print $2}' | sed 's/Gi//')
    local KMS_CORE_CLIENT_CPU=$(grep -A 10 "resources:" "${KMS_CORE_CLIENT_INIT_VALUES}" | grep "cpu:" | head -1 | awk '{print $2}')

    # Calculate total resources (using bc for floating-point arithmetic)
    local TOTAL_KMS_CORE_MEMORY=$(echo "${KMS_CORE_MEMORY} * ${NUM_PARTIES}" | bc)
    local TOTAL_KMS_CORE_CPU=$((KMS_CORE_CPU * NUM_PARTIES))
    local TOTAL_MEMORY=$(echo "${TOTAL_KMS_CORE_MEMORY} + ${KMS_CORE_CLIENT_MEMORY}" | bc)
    local TOTAL_CPU=$((TOTAL_KMS_CORE_CPU + KMS_CORE_CLIENT_CPU))

    # Retrieve num_sessions_preproc and FHE_PARAMS (matching original inline code)
    local NUM_SESSIN_PREPROC=$(grep "numSessionsPreproc:" "${KMS_CORE_VALUES}" | head -1 | awk '{print $2}')
    local FHE_PARAMS=$(grep "fhe_parameter:" "${KMS_CORE_CLIENT_INIT_VALUES}" | head -1 | awk '{print $2}')

        log_warn "========================================="
        log_warn "Running in LOCAL mode"
        log_warn "========================================="
        log_warn "The default Helm values require significant resources:"
        log_warn ""
        log_warn "KMS Core (${NUM_PARTIES} parties):"
        log_warn "  - Memory per core: ${KMS_CORE_MEMORY}Gi"
        log_warn "  - CPU per core: ${KMS_CORE_CPU} cores"
        log_warn "  - Total: ${TOTAL_KMS_CORE_MEMORY}Gi RAM, ${TOTAL_KMS_CORE_CPU} CPU cores"
        log_warn ""
        log_warn "KMS Core num_sessions_preproc:"
        log_warn "  - num_sessions_preproc: ${NUM_SESSIN_PREPROC}"
        log_warn ""
        log_warn "KMS Core Client (1 instance):"
        log_warn "  - Memory: ${KMS_CORE_CLIENT_MEMORY}Gi"
        log_warn "  - CPU: ${KMS_CORE_CLIENT_CPU} cores"
        log_warn ""
        log_warn "KMS Core Client fhe_parameter:"
        log_warn "  - fhe_parameter: ${FHE_PARAMS}"
        log_warn ""
        log_warn "TOTAL RESOURCES REQUIRED:"
        log_warn "  - Memory: ${TOTAL_MEMORY}Gi"
        log_warn "  - CPU: ${TOTAL_CPU} cores"
        log_warn "========================================="
        log_warn ""
        log_warn "If your system doesn't have these resources, you MUST adjust the values files:"
        log_warn "  - ${KMS_CORE_VALUES}"
        log_warn "  - ${KMS_CORE_CLIENT_INIT_VALUES}"
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
                # Get base file paths for copying
                local base_dir="${REPO_ROOT}/ci/kube-testing/kms"
                local BASE_CORE_VALUES="${base_dir}/values-kms-test.yaml"
                local BASE_CLIENT_INIT_VALUES="${base_dir}/values-kms-service-init-kms-test.yaml"
                local BASE_CLIENT_GEN_KEYS_VALUES=""
                if [[ "${GEN_KEYS}" == "true" ]]; then
                    BASE_CLIENT_GEN_KEYS_VALUES="${base_dir}/values-kms-service-gen-keys-kms-test.yaml"
                fi

                # Remove existing local values files if they exist
                remove_local_values_files

                # Copy base files to local files
                copy_to_local_values_files "${BASE_CORE_VALUES}" "${BASE_CLIENT_INIT_VALUES}" "${BASE_CLIENT_GEN_KEYS_VALUES}"

                # Update variables to point to local files
                KMS_CORE_VALUES="${base_dir}/local-values-kms-test.yaml"
                KMS_CORE_CLIENT_INIT_VALUES="${base_dir}/local-values-kms-service-init-kms-test.yaml"
                if [[ "${GEN_KEYS}" == "true" ]]; then
                    KMS_CORE_CLIENT_GEN_KEYS_VALUES="${base_dir}/local-values-kms-service-gen-keys-kms-test.yaml"
                fi

                # Replace namespace placeholder in the newly created local files
                replace_namespace_in_files "${KMS_CORE_VALUES}" "${KMS_CORE_CLIENT_INIT_VALUES}" "${KMS_CORE_CLIENT_GEN_KEYS_VALUES}"

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
                read -p "KMS Core Client fhe_parameter (current: ${FHE_PARAMS}, recommended: Test): " -r NEW_FHE_PARAMS
                NEW_FHE_PARAMS="${NEW_FHE_PARAMS:-${FHE_PARAMS}}"


                # Update the values files with sed (platform-aware)
                log_info "Updating values files..."

                # Update KMS Core values
                sed_inplace "s/memory: ${KMS_CORE_MEMORY}Gi/memory: ${NEW_CORE_MEM}Gi/g" "${KMS_CORE_VALUES}"
                sed_inplace "s/cpu: ${KMS_CORE_CPU}/cpu: ${NEW_CORE_CPU}/g" "${KMS_CORE_VALUES}"
                sed_inplace "s/numSessionsPreproc: ${NUM_SESSIN_PREPROC}/numSessionsPreproc: ${NEW_NUM_SESSIN_PREPROC}/g" "${KMS_CORE_VALUES}"

                # Update KMS Core Client values
                sed_inplace "s/memory: ${KMS_CORE_CLIENT_MEMORY}Gi/memory: ${NEW_CLIENT_MEM}Gi/g" "${KMS_CORE_CLIENT_INIT_VALUES}"
                sed_inplace "s/cpu: ${KMS_CORE_CLIENT_CPU}/cpu: ${NEW_CLIENT_CPU}/g" "${KMS_CORE_CLIENT_INIT_VALUES}"
                sed_inplace "s/fhe_parameter: ${FHE_PARAMS}/fhe_parameter: ${NEW_FHE_PARAMS}/g" "${KMS_CORE_CLIENT_INIT_VALUES}"
                if [[ "${GEN_KEYS}" == "true" ]]; then
                    sed_inplace "s/fhe_parameter: ${FHE_PARAMS}/fhe_parameter: ${NEW_FHE_PARAMS}/g" "${KMS_CORE_CLIENT_GEN_KEYS_VALUES}"
                fi

                log_info "New local values files created successfully:"
                log_info "- ${REPO_ROOT}/ci/kube-testing/kms/local-values-kms-test.yaml"
                log_info "- ${REPO_ROOT}/ci/kube-testing/kms/local-values-kms-service-init-kms-test.yaml"
                if [[ "${GEN_KEYS}" == "true" ]]; then
                    log_info "- ${REPO_ROOT}/ci/kube-testing/kms/local-values-kms-service-gen-keys-kms-test.yaml"
                fi

                # Calculate new totals (using bc for floating-point arithmetic)
                local NEW_TOTAL_MEM=$(echo "${NEW_CORE_MEM} * ${NUM_PARTIES} + ${NEW_CLIENT_MEM}" | bc)
                local NEW_TOTAL_CPU=$((NEW_CORE_CPU * NUM_PARTIES + NEW_CLIENT_CPU))
                local NEW_TOTAL_NUM_SESSIN_PREPROC=${NEW_NUM_SESSIN_PREPROC}
                local NEW_TOTAL_FHE_PARAMS=${NEW_FHE_PARAMS}

                log_info ""
                log_info "======================NEW RESOURCES ADJUSTMENT========================="
                log_info "New total resources: ${NEW_TOTAL_MEM}Gi RAM, ${NEW_TOTAL_CPU} CPU cores"
                log_info "New total num_sessions_preproc: ${NEW_TOTAL_NUM_SESSIN_PREPROC}"
                log_info "New total fhe_parameter: ${NEW_TOTAL_FHE_PARAMS}"
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

    helm repo add localstack-charts https://localstack.github.io/helm-charts || true
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
    --nodes "${NAMESPACE}"-worker

  log_info "Building container for core-client ..."
  docker buildx build -t "ghcr.io/zama-ai/kms/core-client:latest-dev" \
    -f "${REPO_ROOT}/docker/core-client/Dockerfile" \
    --build-arg RUST_IMAGE_VERSION=${RUST_IMAGE_VERSION} \
    "${REPO_ROOT}/" \
    --load

  log_info "Loading container for core-client in kind ..."
  kind load docker-image "ghcr.io/zama-ai/kms/core-client:latest-dev" \
    -n "${NAMESPACE}" \
    --nodes "${NAMESPACE}"-worker
}

#=============================================================================
# Localstack Deployment
#=============================================================================

# Deploy Localstack object storage
deploy_localstack() {
    log_info "Deploying Localstack..."

    helm upgrade --install localstack localstack-charts/localstack \
        --namespace "${NAMESPACE}" \
        --kubeconfig "${KUBE_CONFIG}" \
        --create-namespace \
        -f "${REPO_ROOT}/ci/kube-testing/infra/localstack-s3-values.yaml"

    sleep 30
    log_info "Localstack deployed successfully"
}

#=============================================================================
# TLS Certificate Generation
#=============================================================================

# Generate TLS certificates for threshold mode and upload to S3
generate_and_upload_tls_certs() {
    log_info "Generating TLS certificates for ${NUM_PARTIES} parties..."

    local CERTS_DIR="${REPO_ROOT}/ci/kube-testing/certs"
    mkdir -p "${CERTS_DIR}"

    # Generate CA names for each party (e.g., party1, party2, ...)
    local CA_NAMES=""
    for i in $(seq 1 "${NUM_PARTIES}"); do
        if [[ -n "${CA_NAMES}" ]]; then
            CA_NAMES="${CA_NAMES} "
        fi
        CA_NAMES="${CA_NAMES}kms-service-threshold-${i}-${NAMESPACE}-core-${i}"
    done

    log_info "Generating certificates for: ${CA_NAMES}"

    # Build and run the certificate generator
    # The kms-gen-tls-certs binary generates self-signed CA certificates
    cargo run --release --bin kms-gen-tls-certs -- \
        --ca-names ${CA_NAMES} \
        --output-dir "${CERTS_DIR}" \
        --wildcard

    # Wait for localstack to be ready
    log_info "Waiting for localstack to be ready..."
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=localstack \
        -n "${NAMESPACE}" --timeout=5m --kubeconfig "${KUBE_CONFIG}"

    # Port forward localstack for S3 access
    log_info "Setting up port forward to localstack..."
    kubectl port-forward -n "${NAMESPACE}" svc/localstack 4566:4566 \
        --kubeconfig "${KUBE_CONFIG}" > /dev/null 2>&1 &
    local PF_PID=$!
    sleep 5

    # Upload certificates and private keys to S3 for each party
    log_info "Uploading certificates and keys to S3..."
    for i in $(seq 1 "${NUM_PARTIES}"); do
        local PARTY_NAME="kms-service-threshold-${i}-${NAMESPACE}-core-${i}"
        local CERT_FILE="${CERTS_DIR}/cert_${PARTY_NAME}.pem"
        local KEY_FILE="${CERTS_DIR}/key_${PARTY_NAME}.pem"

        if [[ -f "${CERT_FILE}" ]]; then
            # Upload certificate to public bucket under PUB-p{i}/CACert/
            aws --endpoint-url=http://localhost:4566 s3 cp \
                "${CERT_FILE}" \
                "s3://kms-public/PUB-p${i}/CACert/cert.pem" \
                --no-sign-request 2>/dev/null || true
            log_info "Uploaded certificate for party ${i}"
        else
            log_warn "Certificate file not found: ${CERT_FILE}"
        fi

        if [[ -f "${KEY_FILE}" ]]; then
            # Upload private key to public bucket under PUB-p{i}/PrivateKey/
            aws --endpoint-url=http://localhost:4566 s3 cp \
                "${KEY_FILE}" \
                "s3://kms-public/PUB-p${i}/PrivateKey/key.pem" \
                --no-sign-request 2>/dev/null || true
            log_info "Uploaded private key for party ${i}"
        else
            log_warn "Private key file not found: ${KEY_FILE}"
        fi
    done

    # Also upload the combined certificate
    if [[ -f "${CERTS_DIR}/cert_combined.pem" ]]; then
        aws --endpoint-url=http://localhost:4566 s3 cp \
            "${CERTS_DIR}/cert_combined.pem" \
            "s3://kms-public/certs/cert_combined.pem" \
            --no-sign-request 2>/dev/null || true
        log_info "Uploaded combined certificate"
    fi

    # Stop port forward
    kill ${PF_PID} 2>/dev/null || true

    log_info "TLS certificates generated and uploaded successfully"
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

    local KMS_CORE_CLIENT_GEN_KEYS_VALUES=""
    if [[ "${LOCAL}" == "true" ]]; then
        local KMS_CORE_VALUES="${REPO_ROOT}/ci/kube-testing/kms/local-values-kms-test.yaml"
        local KMS_CORE_CLIENT_INIT_VALUES="${REPO_ROOT}/ci/kube-testing/kms/local-values-kms-service-init-kms-test.yaml"
        if [[ "${GEN_KEYS}" == "true" ]]; then
            KMS_CORE_CLIENT_GEN_KEYS_VALUES="${REPO_ROOT}/ci/kube-testing/kms/local-values-kms-service-gen-keys-kms-test.yaml"
        fi
    else
        local KMS_CORE_VALUES="${REPO_ROOT}/ci/kube-testing/kms/values-kms-test.yaml"
        local KMS_CORE_CLIENT_INIT_VALUES="${REPO_ROOT}/ci/kube-testing/kms/values-kms-service-init-kms-test.yaml"
        if [[ "${GEN_KEYS}" == "true" ]]; then
            KMS_CORE_CLIENT_GEN_KEYS_VALUES="${REPO_ROOT}/ci/kube-testing/kms/values-kms-service-gen-keys-kms-test.yaml"
        fi
    fi

    # Replace namespace placeholder with actual namespace
    replace_namespace_in_files "${KMS_CORE_VALUES}" "${KMS_CORE_CLIENT_INIT_VALUES}" "${KMS_CORE_CLIENT_GEN_KEYS_VALUES}"

    # Generate and upload TLS certificates if TLS is enabled
    if [[ "${ENABLE_TLS}" == "true" ]]; then
        generate_and_upload_tls_certs
    fi

    # Calculate threshold value based on number of parties
    # Formula: n = 3t + 1, so t = (n - 1) / 3
    # Valid party counts: 4 (t=1), 7 (t=2), 10 (t=3), 13 (t=4)
    local THRESHOLD_VALUE=$(( (NUM_PARTIES - 1) / 3 ))
    if [[ $(( 3 * THRESHOLD_VALUE + 1 )) -ne ${NUM_PARTIES} ]]; then
        log_error "Invalid number of parties: ${NUM_PARTIES}. Must satisfy n = 3t + 1 (valid: 4, 7, 10, 13, ...)"
        exit 1
    fi
    log_info "Calculated threshold value: ${THRESHOLD_VALUE} for ${NUM_PARTIES} parties"

    # Generate peersList dynamically based on NUM_PARTIES
    # Each peer entry needs: id, host, port
    # Host format: kms-service-threshold-{id}-{namespace}-core-{id}
    local PEERS_JSON="["
    for j in $(seq 1 "${NUM_PARTIES}"); do
        if [[ $j -gt 1 ]]; then
            PEERS_JSON+=","
        fi
        PEERS_JSON+="{\"id\":${j},\"host\":\"kms-service-threshold-${j}-${NAMESPACE}-core-${j}\",\"port\":50001}"
    done
    PEERS_JSON+="]"
    log_info "Generated peersList: ${PEERS_JSON}"

    # Build TLS Helm flags if TLS is enabled
    # The Helm chart template requires tls.certificate and tls.privateKey objects to exist
    # even if we're using environment variables for the actual cert/key content.
    # Use an array to properly handle the arguments with special characters.
    local TLS_FLAGS=()
    if [[ "${ENABLE_TLS}" == "true" ]]; then
        TLS_FLAGS=(
            --set kmsCore.thresholdMode.tls.enabled=true
            --set "kmsCore.thresholdMode.tls.certificate.path="
            --set "kmsCore.thresholdMode.tls.privateKey.path="
            --set "kmsCore.thresholdMode.tls.ca_certificate.path="
        )
        log_info "TLS enabled for threshold mode"
    fi

    # Deploy all parties in parallel WITHOUT --wait flag
    # In threshold mode, pods need to connect to each other for health checks,
    # so we must deploy all releases first, then wait for pods to become ready together
    local HELM_PIDS=()
    for i in $(seq 1 "${NUM_PARTIES}"); do
        log_info "Deploying KMS Core party ${i}/${NUM_PARTIES}..."
        helm upgrade --install "kms-service-threshold-${i}-${NAMESPACE}" \
            "${REPO_ROOT}/charts/kms-core" \
            --namespace "${NAMESPACE}" \
            --kubeconfig "${KUBE_CONFIG}" \
            -f "${KMS_CORE_VALUES}" \
            --set kmsCore.image.tag="${KMS_CORE_IMAGE_TAG}" \
            --set kmsCoreClient.image.tag="${KMS_CORE_CLIENT_IMAGE_TAG}" \
            --set kmsPeers.id="${i}" \
            --set kmsCore.thresholdMode.thresholdValue="${THRESHOLD_VALUE}" \
            --set-json "kmsCore.thresholdMode.peersList=${PEERS_JSON}" \
            "${TLS_FLAGS[@]}" \
            --timeout 10m &
        HELM_PIDS+=($!)
    done
    
    # Wait for all Helm deployments and check for failures
    local HELM_FAILED=false
    for pid in "${HELM_PIDS[@]}"; do
        if ! wait "$pid"; then
            HELM_FAILED=true
            log_error "Helm deployment failed (PID: $pid)"
        fi
    done
    
    if [[ "${HELM_FAILED}" == "true" ]]; then
        log_error "One or more Helm deployments failed. Check the errors above."
        exit 1
    fi
    
    log_info "All Helm releases deployed successfully, waiting for pods to become ready..."

    # Show pod status for debugging
    log_info "Current pod status:"
    kubectl get pods -l app=kms-core -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}" -o wide

    # Wait for all pods to become ready together (they need each other for health checks)
    # Use a loop with status checks for better debugging
    local MAX_WAIT=900  # 15 minutes
    local WAIT_INTERVAL=30
    local ELAPSED=0
    
    while [ $ELAPSED -lt $MAX_WAIT ]; do
        # Get ready count - trim whitespace to avoid integer comparison issues
        local READY_COUNT
        READY_COUNT=$(kubectl get pods -l app=kms-core -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}" \
            -o jsonpath='{range .items[*]}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' 2>/dev/null | grep -c "True" || echo "0")
        READY_COUNT=$(echo "${READY_COUNT}" | tr -d '[:space:]')
        
        local TOTAL_COUNT
        TOTAL_COUNT=$(kubectl get pods -l app=kms-core -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}" \
            -o jsonpath='{.items[*].metadata.name}' 2>/dev/null | wc -w | tr -d '[:space:]')
        
        # Default to 0 if empty
        READY_COUNT=${READY_COUNT:-0}
        TOTAL_COUNT=${TOTAL_COUNT:-0}
        
        log_info "Pod readiness: ${READY_COUNT}/${TOTAL_COUNT} ready (elapsed: ${ELAPSED}s)"
        
        if [ "$READY_COUNT" -eq "$TOTAL_COUNT" ] && [ "$TOTAL_COUNT" -gt 0 ]; then
            log_info "All ${TOTAL_COUNT} pods are ready!"
            break
        fi
        
        # Check for CrashLoopBackOff - if all pods are crashing, collect logs early and fail fast
        local CRASH_COUNT
        CRASH_COUNT=$(kubectl get pods -l app=kms-core -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}" \
            -o jsonpath='{range .items[*]}{.status.containerStatuses[*].state.waiting.reason}{"\n"}{end}' 2>/dev/null | grep -c "CrashLoopBackOff" || echo "0")
        CRASH_COUNT=$(echo "${CRASH_COUNT}" | tr -d '[:space:]')
        
        if [ "${CRASH_COUNT:-0}" -ge "${TOTAL_COUNT:-0}" ] && [ "${TOTAL_COUNT:-0}" -gt 0 ] && [ "${ELAPSED}" -ge 90 ]; then
            log_error "All pods are in CrashLoopBackOff - collecting logs and failing early"
            collect_pod_logs
            exit 1
        fi
        
        # Show detailed status every 60 seconds
        if [ $((ELAPSED % 60)) -eq 0 ]; then
            log_info "Detailed pod status:"
            kubectl get pods -l app=kms-core -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}"
            log_info "Pod events:"
            kubectl get events -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}" --sort-by='.lastTimestamp' | tail -20
        fi
        
        sleep $WAIT_INTERVAL
        ELAPSED=$((ELAPSED + WAIT_INTERVAL))
    done
    
    if [ $ELAPSED -ge $MAX_WAIT ]; then
        log_error "Timeout waiting for pods to become ready"
        log_info "Final pod status:"
        kubectl get pods -l app=kms-core -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}" -o wide
        log_info "Pod descriptions:"
        kubectl describe pods -l app=kms-core -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}"
        collect_pod_logs
        exit 1
    fi

    log_info "All KMS Core pods are ready, collecting logs..."
    for i in $(seq 1 "${NUM_PARTIES}"); do
        kubectl logs "kms-service-threshold-${i}-${NAMESPACE}-core-${i}" -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}" || true
    done

    # Deploy initialization job
    log_info "Deploying KMS Core initialization job..."
    helm upgrade --install kms-core-init \
        "${REPO_ROOT}/charts/kms-core" \
        --namespace "${NAMESPACE}" \
        --kubeconfig "${KUBE_CONFIG}" \
        -f "${KMS_CORE_CLIENT_INIT_VALUES}" \
        --set kmsCore.image.tag="${KMS_CORE_IMAGE_TAG}" \
        --set kmsCoreClient.image.tag="${KMS_CORE_CLIENT_IMAGE_TAG}" \
        --set-json "kmsCore.thresholdMode.peersList=${PEERS_JSON}" \
        --wait \
        --wait-for-jobs \
        --timeout 20m

    log_info "Waiting for initialization to complete..."
    kubectl wait --for=condition=complete job -l app=kms-threshold-init-job \
        -n "${NAMESPACE}" --timeout=10m --kubeconfig "${KUBE_CONFIG}"

    # Deploy key generation job
    if [[ "${LOCAL}" == "true" && "${GEN_KEYS}" == "true" && "${DEPLOYMENT_TYPE}" == "threshold" ]]; then
      log_info "Deploying KMS Core key generation job..."
      helm upgrade --install kms-core-gen-keys \
          "${REPO_ROOT}/charts/kms-core" \
          --namespace "${NAMESPACE}" \
          --kubeconfig "${KUBE_CONFIG}" \
          -f "${KMS_CORE_CLIENT_GEN_KEYS_VALUES}" \
          --set kmsCore.image.tag="${KMS_CORE_IMAGE_TAG}" \
          --set kmsCoreClient.image.tag="${KMS_CORE_CLIENT_IMAGE_TAG}" \
          --set-json "kmsCore.thresholdMode.peersList=${PEERS_JSON}" \
          --wait \
          --wait-for-jobs \
          --timeout 40m

      log_info "Waiting for key generation to complete..."
      kubectl wait --for=condition=complete job -l app=kms-core-client-gen-keys \
          -n "${NAMESPACE}" --timeout=10m --kubeconfig "${KUBE_CONFIG}"
    fi
    log_info "Threshold mode deployment completed"
}

# Deploy centralized mode with single party
deploy_centralized_mode() {
    log_info "Deploying KMS Core in centralized mode..."

    if [[ "${LOCAL}" == "true" ]]; then
      local KMS_CORE_VALUES="${REPO_ROOT}/ci/kube-testing/kms/local-values-kms-test.yaml"
      local KMS_CORE_CLIENT_INIT_VALUES="${REPO_ROOT}/ci/kube-testing/kms/local-values-kms-service-init-kms-test.yaml"
    else
      local KMS_CORE_VALUES="${REPO_ROOT}/ci/kube-testing/kms/values-kms-test.yaml"
      local KMS_CORE_CLIENT_INIT_VALUES="${REPO_ROOT}/ci/kube-testing/kms/values-kms-service-init-kms-test.yaml"
    fi

    # Replace namespace placeholder with actual namespace
    replace_namespace_in_files "${KMS_CORE_VALUES}" "${KMS_CORE_CLIENT_INIT_VALUES}"

    helm upgrade --install kms \
        "${REPO_ROOT}/charts/kms-core" \
        --namespace "${NAMESPACE}" \
        --kubeconfig "${KUBE_CONFIG}" \
        -f "${KMS_CORE_VALUES}" \
        --set kmsCore.thresholdMode.enabled=false \
        --set kmsCore.image.tag="${KMS_CORE_IMAGE_TAG}" \
        --set kmsCoreClient.image.tag="${KMS_CORE_CLIENT_IMAGE_TAG}" \
        --set kmsCore.publicVault.s3.prefix=PUB \
        --set kmsCore.privateVault.s3.prefix=PRIV \
        --set kmsCore.backupVault.s3.prefix=BACKUP \
        --wait \
        --timeout 10m

    log_info "Waiting for KMS Core pod to be ready..."
    kubectl wait --for=condition=ready pod -l app=kms-core \
        -n "${NAMESPACE}" --timeout=10m --kubeconfig "${KUBE_CONFIG}"

    log_info "Centralized mode deployment completed"
}

#=============================================================================
# Port Forwarding Setup
#=============================================================================

# Setup port forwarding for local access to services
setup_port_forwarding() {
    log_info "Setting up port forwarding..."

    # Port forward Localstack s3
    log_info "Port forwarding Localstack s3 (9000:4566)..."
    kubectl port-forward \
        -n "${NAMESPACE}" \
        svc/localstack \
        9000:4566 \
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
            log_info "Port forwarding kms-core-1 (50100:50100)..."
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
# Log Collection Function
# Collects logs from KMS Core pods based on deployment type
# Can be called from cleanup or directly from CI
#=============================================================================
collect_logs() {
    log_info "Collecting logs for ${DEPLOYMENT_TYPE} deployment..."

    case "${DEPLOYMENT_TYPE}" in
        threshold)
            if [ -z "${NUM_PARTIES:-}" ]; then
                log_error "NUM_PARTIES not set for threshold deployment"
                return 1
            fi

            log_info "Collecting logs from ${NUM_PARTIES} KMS Core pods..."
            for i in $(seq 1 "${NUM_PARTIES}"); do
                POD_NAME="kms-service-threshold-${i}-${NAMESPACE}-core-${i}"
                LOG_FILE="/tmp/kms-service-threshold-${i}-${NAMESPACE}-core-${i}.log"
                log_info "  Checking pod: ${POD_NAME}"

                if kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}" &>/dev/null; then
                    log_info "  Pod ${POD_NAME} exists, collecting logs..."
                    {
                        echo "=== Init container logs (kms-core-init-load-env) ==="
                        kubectl logs "${POD_NAME}" -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}" -c kms-core-init-load-env --previous 2>&1 || \
                        kubectl logs "${POD_NAME}" -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}" -c kms-core-init-load-env 2>&1 || \
                        echo "No init container logs available"
                        echo ""
                        echo "=== Main container logs (kms-core) ==="
                        kubectl logs "${POD_NAME}" -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}" -c kms-core --previous 2>&1 || \
                        kubectl logs "${POD_NAME}" -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}" -c kms-core 2>&1 || \
                        echo "No main container logs available"
                    } > "${LOG_FILE}" 2>&1
                    log_info "  ✓ Collected logs to ${LOG_FILE}"
                else
                    log_error "  ✗ Pod ${POD_NAME} not found"
                fi
            done
            ;;
        centralized)
            log_info "Collecting logs from centralized KMS Core pod..."
            if kubectl get pod kms-core-1 -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}" &>/dev/null; then
                if kubectl logs kms-core-1 -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}" \
                    > "/tmp/kms-core-${NAMESPACE}.log" 2>&1; then
                    log_info "  ✓ Collected logs from kms-core-1"
                else
                    log_error "  ✗ Failed to collect logs from kms-core-1"
                fi
            else
                log_error "  ✗ Pod kms-core-1 not found"
            fi
            ;;
        *)
            log_error "Unknown deployment type: ${DEPLOYMENT_TYPE}"
            return 1
            ;;
    esac

    log_info "Log collection completed"
    return 0
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

        # Collect logs before destroying cluster
        collect_logs || log_error "Failed to collect logs"

        # Delete cluster and kubeconfig
        kind delete cluster --name ${NAMESPACE} --kubeconfig ${KUBE_CONFIG}
        rm -f "${KUBE_CONFIG}"
    else
        # Lightweight cleanup for CI
        # The CI workflow will handle full cluster cleanup
        log_info "Running lightweight cleanup (CI mode)..."
        
        # Collect pod logs before CI destroys the cluster
        collect_logs || log_error "Failed to collect logs"
        
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

    # If only collecting logs, do that and exit
    if [[ "${COLLECT_LOGS_ONLY}" == "true" ]]; then
        log_info "Collecting logs only (CI mode)..."
        collect_logs
        exit $?
    fi

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
    log_info "  Generate Keys:            ${GEN_KEYS}"
    log_info "  Enable TLS:               ${ENABLE_TLS}"
    log_info "========================================="

    # Execute setup steps
    check_prerequisites
    setup_kind_cluster
    setup_kube_context
    setup_namespace
    setup_registry_credentials
    setup_helm_repos
    deploy_localstack

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
    log_info "  Localstack S3: http://localhost:9000"
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
    log_info "  Manual cleanup:  kind delete cluster --name ${NAMESPACE}"
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

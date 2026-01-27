#!/usr/bin/env bash

#=============================================================================
# Common Functions and Utilities
# Helper functions, logging, argument parsing, and basic utilities
#=============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

#=============================================================================
# Logging Functions
#=============================================================================
log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

#=============================================================================
# Usage
#=============================================================================
usage() {
    cat <<EOF
Usage: $0 --target [kind-local|kind-ci|aws-ci|aws-perf] [OPTIONS]

Options:
  --namespace <name>       K8s namespace (default: kms-test)
  --deployment-type <type> threshold|centralized|thresholdWithEnclave... (default: threshold)
  --tag <tag>              Image tag (default: latest-dev)
  --core-tag <tag>         KMS core image tag (overrides --tag)
  --client-tag <tag>       KMS client image tag (overrides --tag)
  --num-parties <n>        Number of parties (default: 4 for threshold)
  --kms-chart-version <v>  KMS chart version (perf testing)
  --tkms-infra-version <v> TKMS infra chart version (perf testing)
  --cleanup                Cleanup before deploy
  --build                  Build images locally (kind targets only)
  --block                  Keep script running (for port-forwarding)
  --pcr0 <val>             PCR0 value for Enclave (optional)
  --pcr1 <val>             PCR1 value for Enclave (optional)
  --pcr2 <val>             PCR2 value for Enclave (optional)
  --collect-logs           Only collect logs from pods and exit
  --enable-tls             Explicitly enable TLS (default for threshold mode)
  --disable-tls            Explicitly disable TLS (overrides default for threshold mode)
  --help                   Show this help
EOF
}

#=============================================================================
# Parse arguments
#=============================================================================
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --target) TARGET="$2"; shift 2 ;;
            --namespace) NAMESPACE="$2"; shift 2 ;;
            --deployment-type) DEPLOYMENT_TYPE="$2"; shift 2 ;;
            --tag) KMS_CORE_TAG="$2"; KMS_CLIENT_TAG="$2"; shift 2 ;; # Simplified for now
            --core-tag) KMS_CORE_TAG="$2"; shift 2 ;;
            --client-tag) KMS_CLIENT_TAG="$2"; shift 2 ;;
            --num-parties) NUM_PARTIES="$2"; shift 2 ;;
            --kms-chart-version) KMS_CHART_VERSION="$2"; shift 2 ;;
            --tkms-infra-version) TKMS_INFRA_VERSION="$2"; shift 2 ;;
            --cleanup) CLEANUP="true"; shift ;;
            --build) BUILD_IMAGES="true"; shift ;;
            --block) BLOCK="true"; shift ;;
            --pcr0) PCR0="$2"; shift 2 ;;
            --pcr1) PCR1="$2"; shift 2 ;;
            --pcr2) PCR2="$2"; shift 2 ;;
            --collect-logs) COLLECT_LOGS="true"; shift ;;
            --enable-tls) ENABLE_TLS="true"; shift ;;
            --disable-tls) ENABLE_TLS="false"; shift ;;
            --help) usage; exit 0 ;;
            *) log_error "Unknown argument: $1"; usage; exit 1 ;;
        esac
    done

    # Adjust NUM_PARTIES based on deployment type
    if [[ "${DEPLOYMENT_TYPE}" == *"centralized"* ]]; then
        NUM_PARTIES=1
    fi
}

#=============================================================================
# File Utilities
#=============================================================================
sed_inplace() {
    local pattern="$1"
    local file="$2"
    if [[ "$(uname -s)" == "Darwin" ]]; then
        sed -i '' "${pattern}" "${file}"
    else
        sed -i "${pattern}" "${file}"
    fi
}

#=============================================================================
# Local Values File Management
#=============================================================================
remove_local_values_files() {
    local base_dir="${REPO_ROOT}/ci/kube-testing/kms"
    local files_to_remove=(
        "${base_dir}/local-values-kms-test.yaml"
        "${base_dir}/local-values-kms-service-init-kms-test.yaml"
    )

    local any_exist="false"
    for file in "${files_to_remove[@]}"; do
        if [[ -f "${file}" ]]; then
            any_exist="true"
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

copy_to_local_values_files() {
    local core_base="$1"
    local client_init_base="$2"
    local base_dir="${REPO_ROOT}/ci/kube-testing/kms"

    log_info "Creating local values files..."
    cp "${core_base}" "${base_dir}/local-values-kms-test.yaml"
    cp "${client_init_base}" "${base_dir}/local-values-kms-service-init-kms-test.yaml"
}

replace_namespace_in_files() {
    local core_file="$1"
    local client_init_file="$2"

    if [[ -f "${core_file}" ]] && grep -q "<namespace>" "${core_file}" 2>/dev/null; then
        sed_inplace "s|<namespace>|${NAMESPACE}|g" "${core_file}"
        log_info "Replaced <namespace> with ${NAMESPACE} in ${core_file}"
    fi
    if [[ -f "${client_init_file}" ]] && grep -q "<namespace>" "${client_init_file}" 2>/dev/null; then
        sed_inplace "s|<namespace>|${NAMESPACE}|g" "${client_init_file}"
        log_info "Replaced <namespace> with ${NAMESPACE} in ${client_init_file}"
    fi
}

#=============================================================================
# Interactive Resource Configuration (Local Dev Only)
#=============================================================================
check_local_resources() {
    local base_dir="${REPO_ROOT}/ci/kube-testing/kms"
    local core_base="${base_dir}/values-kms-test.yaml"
    local init_base="${base_dir}/values-kms-service-init-kms-test.yaml"
    local core_local="${base_dir}/local-values-kms-test.yaml"
    local init_local="${base_dir}/local-values-kms-service-init-kms-test.yaml"

    local core_values="${core_base}"
    local init_values="${init_base}"
    if [[ -s "${core_local}" && -s "${init_local}" ]]; then
        core_values="${core_local}"
        init_values="${init_local}"
        log_info "Using existing local values files for resource adjustment"
    fi

    local kms_core_memory
    local kms_core_cpu
    local kms_core_client_memory
    local kms_core_client_cpu
    local num_sessions_preproc
    local fhe_params

    kms_core_memory=$(grep -A 10 "resources:" "${core_values}" | grep "memory:" | head -1 | awk '{print $2}' | sed 's/Gi//')
    kms_core_cpu=$(grep -A 10 "resources:" "${core_values}" | grep "cpu:" | head -1 | awk '{print $2}')
    kms_core_client_memory=$(grep -A 10 "resources:" "${init_values}" | grep "memory:" | head -1 | awk '{print $2}' | sed 's/Gi//')
    kms_core_client_cpu=$(grep -A 10 "resources:" "${init_values}" | grep "cpu:" | head -1 | awk '{print $2}')
    num_sessions_preproc=$(grep "numSessionsPreproc:" "${core_values}" | head -1 | awk '{print $2}')
    fhe_params=$(grep "fhe_parameter:" "${init_values}" | head -1 | awk '{print $2}')

    local total_core_memory
    local total_core_cpu
    local total_memory
    local total_cpu
    total_core_memory=$(echo "${kms_core_memory} * ${NUM_PARTIES}" | bc)
    total_core_cpu=$((kms_core_cpu * NUM_PARTIES))
    total_memory=$(echo "${total_core_memory} + ${kms_core_client_memory}" | bc)
    total_cpu=$((total_core_cpu + kms_core_client_cpu))

    log_warn "========================================="
    log_warn "Running in kind-local mode"
    log_warn "========================================="
    log_warn "KMS Core (${NUM_PARTIES} parties):"
    log_warn "  - Memory per core: ${kms_core_memory}Gi"
    log_warn "  - CPU per core: ${kms_core_cpu} cores"
    log_warn "  - Total: ${total_core_memory}Gi RAM, ${total_core_cpu} CPU cores"
    log_warn ""
    log_warn "KMS Core num_sessions_preproc: ${num_sessions_preproc}"
    log_warn ""
    log_warn "KMS Core Client (1 instance):"
    log_warn "  - Memory: ${kms_core_client_memory}Gi"
    log_warn "  - CPU: ${kms_core_client_cpu} cores"
    log_warn "  - fhe_parameter: ${fhe_params}"
    log_warn ""
    log_warn "TOTAL RESOURCES REQUIRED:"
    log_warn "  - Memory: ${total_memory}Gi"
    log_warn "  - CPU: ${total_cpu} cores"
    log_warn "========================================="
    echo ""

    echo "Choose an option:"
    echo "  1) Continue with current values"
    echo "  2) Adjust resources interactively"
    echo "  3) Cancel and edit files manually"
    read -r -p "Enter your choice (1/2/3): " choice
    echo ""

    case "${choice}" in
        1)
            log_info "Continuing with current resource values..."
            ;;
        2)
            log_info "Interactive resource adjustment..."
            remove_local_values_files
            copy_to_local_values_files "${core_base}" "${init_base}"

            core_values="${core_local}"
            init_values="${init_local}"
            replace_namespace_in_files "${core_values}" "${init_values}"

            echo ""
            echo "Adjusting KMS Core resources..."
            read -r -p "KMS Core Memory per party (current: ${kms_core_memory}Gi, recommended: 4Gi): " new_core_mem
            new_core_mem="${new_core_mem:-${kms_core_memory}}"
            read -r -p "KMS Core CPU per party (current: ${kms_core_cpu}, recommended: 2): " new_core_cpu
            new_core_cpu="${new_core_cpu:-${kms_core_cpu}}"
            read -r -p "KMS Core num_sessions_preproc (current: ${num_sessions_preproc}, recommended: ${new_core_cpu}): " new_num_sessions_preproc
            new_num_sessions_preproc="${new_num_sessions_preproc:-${num_sessions_preproc}}"

            echo ""
            echo "Adjusting KMS Core Client resources..."
            read -r -p "KMS Core Client Memory (current: ${kms_core_client_memory}Gi, recommended: 4Gi): " new_client_mem
            new_client_mem="${new_client_mem:-${kms_core_client_memory}}"
            read -r -p "KMS Core Client CPU (current: ${kms_core_client_cpu}, recommended: 2): " new_client_cpu
            new_client_cpu="${new_client_cpu:-${kms_core_client_cpu}}"
            read -r -p "KMS Core Client fhe_parameter (current: ${fhe_params}, recommended: Test): " new_fhe_params
            new_fhe_params="${new_fhe_params:-${fhe_params}}"

            log_info "Updating values files..."
            sed_inplace "s/memory: ${kms_core_memory}Gi/memory: ${new_core_mem}Gi/g" "${core_values}"
            sed_inplace "s/cpu: ${kms_core_cpu}/cpu: ${new_core_cpu}/g" "${core_values}"
            sed_inplace "s/numSessionsPreproc: ${num_sessions_preproc}/numSessionsPreproc: ${new_num_sessions_preproc}/g" "${core_values}"
            sed_inplace "s/memory: ${kms_core_client_memory}Gi/memory: ${new_client_mem}Gi/g" "${init_values}"
            sed_inplace "s/cpu: ${kms_core_client_cpu}/cpu: ${new_client_cpu}/g" "${init_values}"
            sed_inplace "s/fhe_parameter: ${fhe_params}/fhe_parameter: ${new_fhe_params}/g" "${init_values}"

            log_info "New local values files created:"
            log_info "- ${core_local}"
            log_info "- ${init_local}"
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
# Path Suffix Determination
#=============================================================================
set_path_suffix() {
    if [[ "${DEPLOYMENT_TYPE}" == *"Enclave"* ]]; then
        PATH_SUFFIX="kms-enclave-ci"
    else
        PATH_SUFFIX="kms-ci"
    fi
}

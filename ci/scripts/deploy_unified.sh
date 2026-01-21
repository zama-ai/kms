#!/usr/bin/env bash

#=============================================================================
# Unified KMS Deployment Script
#
# Handles deployment to:
#   1. Local Kind Cluster (local development)
#   2. CI Kind Cluster (CI testing)
#   3. AWS Cluster via Tailscale (PR Previews / Staging)
#
# Usage:
#   ./deploy_unified.sh --target [kind-local|kind-ci|aws-ci] [OPTIONS]
#=============================================================================

set -euo pipefail

#=============================================================================
# Default Configuration
#=============================================================================
TARGET="kind-local"
NAMESPACE="kms-test"
DEPLOYMENT_TYPE="threshold"
NUM_PARTIES="4"
KMS_CORE_TAG="latest-dev"
KMS_CLIENT_TAG="latest-dev"
KMS_CORE_IMAGE_NAME="${KMS_CORE_IMAGE_NAME:-ghcr.io/zama-ai/kms/core-service}"
KMS_CORE_CLIENT_IMAGE_NAME="${KMS_CORE_CLIENT_IMAGE_NAME:-ghcr.io/zama-ai/kms/core-client}"
CLEANUP="false"
BUILD_IMAGES="false"
# Perf-testing defaults (can be overridden by env/args)
KMS_CHART_VERSION="${KMS_CHART_VERSION:-repository}"
TKMS_INFRA_VERSION="${TKMS_INFRA_CHART_VERSION:-0.3.2}"
SYNC_SECRETS_VERSION="0.2.1"
PATH_SUFFIX="${PATH_SUFFIX:-kms-ci}"
TLS="${TLS:-false}"
# Default Repo Root (assuming script is in ci/scripts/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# AWS/Tailscale Defaults
TAILSCALE_HOSTNAME="tailscale-operator-zws-dev.diplodocus-boa.ts.net"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

#=============================================================================
# Helper Functions
#=============================================================================
log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

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
  --help                   Show this help
EOF
}

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
            --help) usage; exit 0 ;;
            *) log_error "Unknown argument: $1"; usage; exit 1 ;;
        esac
    done

    # Adjust NUM_PARTIES based on deployment type
    if [[ "${DEPLOYMENT_TYPE}" == *"centralized"* ]]; then
        NUM_PARTIES=1
    fi
}

sed_inplace() {
    local pattern="$1"
    local file="$2"
    if [[ "$(uname -s)" == "Darwin" ]]; then
        sed -i '' "${pattern}" "${file}"
    else
        sed -i "${pattern}" "${file}"
    fi
}

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
# Context Setup
#=============================================================================
setup_context() {
    log_info "Setting up context for target: ${TARGET}"

    case "${TARGET}" in
        kind-local|kind-ci)
            setup_kind_cluster
            ;;
        aws-ci|aws-perf)
            setup_aws_context
            ;;
        *)
            log_error "Invalid target: ${TARGET}"
            exit 1
            ;;
    esac
}

setup_kind_cluster() {
    local cluster_name="${NAMESPACE}"
    # Use a fixed name for local dev to avoid spamming clusters? Or strictly follow namespace.
    # Existing script uses namespace as cluster name.

    if kind get clusters | grep -q "^${cluster_name}$"; then
        log_info "Kind cluster '${cluster_name}' already exists"
        if [[ "${CLEANUP}" == "true" ]]; then
            log_info "Deleting existing cluster..."
            kind delete cluster --name "${cluster_name}"
            create_new_kind_cluster "${cluster_name}"
        fi
    else
        create_new_kind_cluster "${cluster_name}"
    fi

    kubectl config use-context "kind-${cluster_name}"
}

create_new_kind_cluster() {
    local name="$1"
    log_info "Creating Kind cluster: ${name}"
    kind create cluster --name "${name}" --config - <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
EOF
}

setup_aws_context() {
    # Assumes tailscale is available in environment
    log_info "Configuring kubeconfig via Tailscale..."
    tailscale configure kubeconfig "${TAILSCALE_HOSTNAME}"

    # Check/Create Namespace
    if kubectl get namespace "${NAMESPACE}" > /dev/null 2>&1; then
        if [[ "${CLEANUP}" == "true" ]]; then
             log_info "Destroying namespace ${NAMESPACE}..."
             # Simplified cleanup for brevity
             kubectl delete namespace "${NAMESPACE}" --wait=true
             kubectl create namespace "${NAMESPACE}"
        else
            log_info "Namespace ${NAMESPACE} exists."
        fi
    else
        kubectl create namespace "${NAMESPACE}"
    fi
}

#=============================================================================
# Infrastructure Setup
#=============================================================================
setup_infrastructure() {
    log_info "Setting up infrastructure..."

    if [[ "${TARGET}" == *"kind"* ]]; then
        deploy_localstack
        deploy_registry_credentials
    elif [[ "${TARGET}" == "aws-ci" || "${TARGET}" == "aws-perf" ]]; then
        # Check if we need to fetch PCRs from image if not provided
        if [[ "${DEPLOYMENT_TYPE}" == *"Enclave"* ]] && [[ -z "${PCR0:-}" ]]; then
             fetch_pcrs_from_image
        fi

        deploy_tkms_infra
        deploy_registry_credentials
    fi
}

fetch_pcrs_from_image() {
    log_info "Fetching PCRs from image: ${KMS_CORE_TAG}"
    # Requires docker and jq
    if ! command -v docker &> /dev/null; then
        log_warn "Docker not found, skipping PCR fetch. Ensure PCR0 env var is set if needed."
        return
    fi

    # We might need to pull first if not present
    # Assuming full image name is constructed like in the original script
    local IMAGE_REPO="ghcr.io/zama-ai/kms"
    local FULL_IMAGE="${IMAGE_REPO}/core-service-enclave:${KMS_CORE_TAG}"

    log_info "Pulling ${FULL_IMAGE}..."
    docker pull "${FULL_IMAGE}" > /dev/null 2>&1 || log_warn "Failed to pull image to check PCRs"

    PCR0=$(docker inspect "${FULL_IMAGE}" | jq -r '.[0].Config.Labels["zama.kms.eif_pcr0"]' || echo "")
    PCR1=$(docker inspect "${FULL_IMAGE}" | jq -r '.[0].Config.Labels["zama.kms.eif_pcr1"]' || echo "")
    PCR2=$(docker inspect "${FULL_IMAGE}" | jq -r '.[0].Config.Labels["zama.kms.eif_pcr2"]' || echo "")

    log_info "Detected PCR0: ${PCR0}"
}

deploy_localstack() {
    log_info "Deploying Localstack (S3 Mock)..."
    helm repo add localstack-charts https://localstack.github.io/helm-charts || true
    helm repo update
    helm upgrade --install localstack localstack-charts/localstack \
        --namespace "${NAMESPACE}" \
        --create-namespace \
        -f "${REPO_ROOT}/ci/kube-testing/infra/localstack-s3-values.yaml" \
        --wait
}

set_path_suffix() {
    if [[ "${DEPLOYMENT_TYPE}" == *"Enclave"* ]]; then
        PATH_SUFFIX="kms-enclave-ci"
    else
        PATH_SUFFIX="kms-ci"
    fi
}

wait_tkms_infra_ready() {
    local party_prefix="kms-party-${NAMESPACE}"
    if [[ "${TARGET}" == "aws-perf" ]]; then
        set_path_suffix
        party_prefix="kms-party-${PATH_SUFFIX}"
    fi

    log_info "Waiting for KMS parties to be ready..."
    if [[ "${DEPLOYMENT_TYPE}" == *"centralized"* ]]; then
        kubectl wait --for=condition=ready Kmsparties "${party_prefix}-1" \
            -n "${NAMESPACE}" --timeout=120s
    elif [[ "${DEPLOYMENT_TYPE}" == *"threshold"* ]]; then
        for i in $(seq 1 "${NUM_PARTIES}"); do
            kubectl wait --for=condition=ready Kmsparties "${party_prefix}-${i}" \
                -n "${NAMESPACE}" --timeout=120s
        done
    fi

    if [[ "${DEPLOYMENT_TYPE}" == *"Enclave"* ]]; then
        log_info "Waiting for enclave nodegroups to be ready..."
        kubectl wait --for=condition=ready enclavenodegroup \
            "${party_prefix}" \
            -n "${NAMESPACE}" --timeout=1200s
    fi
}

deploy_tkms_infra() {
    if [[ "${TARGET}" == "aws-perf" ]]; then
        log_info "Deploying TKMS Infra (Performance Testing)..."
        set_path_suffix
        local VALUES_FILE="${REPO_ROOT}/ci/perf-testing/${DEPLOYMENT_TYPE}/kms-ci/tkms-infra/values-${PATH_SUFFIX}.yaml"
        local EXTRA_ARGS=""
        if [[ "${DEPLOYMENT_TYPE}" == *"Enclave"* ]]; then
            EXTRA_ARGS="--set kmsParties.awsKms.recipientAttestationImageSHA384=${PCR0:-}"
        fi

        helm upgrade --install tkms-infra \
            oci://ghcr.io/zama-zws/crossplane/tkms-infra \
            --namespace "${NAMESPACE}" \
            --version "${TKMS_INFRA_VERSION}" \
            --values "${VALUES_FILE}" \
            ${EXTRA_ARGS} \
            --wait
        wait_tkms_infra_ready
        return 0
    fi

    log_info "Deploying TKMS Infra (AWS Resources)..."
    # Logic adapted from pr-preview-deploy.yml

    # Determine PCR values if Enclave (Env vars expected to be set in CI)
    # This part assumes environment variables are present or passed

    local VALUES_FILE="${REPO_ROOT}/ci/pr-preview/${DEPLOYMENT_TYPE}/tkms-infra/values-kms-ci.yaml"

    local EXTRA_ARGS=""
    if [[ "${DEPLOYMENT_TYPE}" == *"Enclave"* ]]; then
        EXTRA_ARGS="--set kmsParties.awsKms.recipientAttestationImageSHA384=${PCR0:-}"
        # Add taint logic if needed
        EXTRA_ARGS="${EXTRA_ARGS} --set kmsParties.enclaveNodeGroup.taint[0].value=${NAMESPACE}"
    fi

    helm upgrade --install tkms-infra \
        oci://ghcr.io/zama-zws/crossplane/tkms-infra \
        --namespace "${NAMESPACE}" \
        --version "${TKMS_INFRA_VERSION}" \
        --values "${VALUES_FILE}" \
        --set kmsParties.replicas="${NUM_PARTIES}" \
        --set fullnameOverride="kms-party-${NAMESPACE}" \
        --set publicBucketVault.labels.environment="${NAMESPACE}" \
        --set kmsParties.serviceAccountPrefixName="${NAMESPACE}" \
        --set kmsParties.publishConnectionDetailsTo.prefixName="${NAMESPACE}" \
        --set kmsParties.publicBucketVaultRef.matchLabels.environment="${NAMESPACE}" \
        ${EXTRA_ARGS} \
        --wait
    wait_tkms_infra_ready
}

deploy_registry_credentials() {
    log_info "Setting up registry credentials..."

    if [[ "${TARGET}" == *"kind"* ]]; then
        if [[ "${TARGET}" == "kind-local" ]]; then
            log_info "Skipping registry credentials setup for local deployment"
            if [[ -f "${HOME}/dockerconfig.yaml" ]]; then
                kubectl apply -f "${HOME}/dockerconfig.yaml" -n "${NAMESPACE}"
            else
                log_warn "Missing ${HOME}/dockerconfig.yaml; skipping local registry credentials"
            fi
            return 0
        fi

        # kind-ci: build a dockerconfigjson secret for ghcr.io
        if [[ -z "${GITHUB_TOKEN:-}" ]]; then
            log_warn "GITHUB_TOKEN not set, skipping registry credentials setup"
            log_warn "Set GITHUB_TOKEN to enable private image pulls"
            return 0
        fi

        local base64_cmd="base64"
        if base64 --help 2>&1 | grep -q '\-w'; then
            base64_cmd="base64 -w 0"
        fi

        local docker_config_json
        docker_config_json=$(cat <<JSON | ${base64_cmd}
{
  "auths": {
    "ghcr.io": {
      "auth": "$(echo -n "zws-bot:${GITHUB_TOKEN}" | ${base64_cmd})"
    }
  }
}
JSON
)

        cat <<EOF | kubectl apply -f - --namespace "${NAMESPACE}"
apiVersion: v1
data:
  .dockerconfigjson: ${docker_config_json}
kind: Secret
metadata:
  name: registry-credentials
type: kubernetes.io/dockerconfigjson
EOF

        if kubectl get secret registry-credentials -n "${NAMESPACE}" &> /dev/null; then
            log_info "Registry credentials configured successfully"
        else
            log_error "Failed to create registry credentials"
            return 1
        fi

        return 0
    fi

    log_info "Deploying Sync Secrets..."
    local registry_values_path="${REPO_ROOT}/ci/pr-preview/registry-credential/values-kms-ci.yaml"
    if [[ "${TARGET}" == "aws-perf" ]]; then
        registry_values_path="${REPO_ROOT}/ci/perf-testing/registry-credential/values-kms-ci.yaml"
    fi

    helm upgrade --install sync-secrets \
        oci://ghcr.io/zama-zws/helm-charts/sync-secrets \
        --namespace "${NAMESPACE}" \
        --version "${SYNC_SECRETS_VERSION}" \
        --values "${registry_values_path}" \
        --create-namespace \
        --wait
}

#=============================================================================
# KMS Deployment
#=============================================================================
deploy_kms() {
    log_info "Deploying KMS Core..."
    local is_perf=false
    if [[ "${TARGET}" == "aws-perf" ]]; then
        is_perf=true
        set_path_suffix
    fi

    # 1. Determine base values file
    local BASE_VALUES=""
    local LOCAL_VALUES_USED="false"
    if [[ "${TARGET}" == *"kind"* ]]; then
        local base_dir="${REPO_ROOT}/ci/kube-testing/kms"
        local kind_values="${base_dir}/values-kms-test.yaml"
        local kind_local_values="${base_dir}/local-values-kms-test.yaml"
        if [[ "${TARGET}" == "kind-local" && -f "${kind_local_values}" ]]; then
            BASE_VALUES="${kind_local_values}"
            LOCAL_VALUES_USED="true"
        else
            BASE_VALUES="${kind_values}"
        fi
    else
        # For AWS/CI, we use the values from pr-preview
        BASE_VALUES="${REPO_ROOT}/ci/pr-preview/${DEPLOYMENT_TYPE}/kms-service/values-kms-ci.yaml"
    fi

    local helm_chart_location="${REPO_ROOT}/charts/kms-core"
    local helm_version_args=()
    local perf_values_dir=""
    if [[ "${is_perf}" == "true" ]]; then
        perf_values_dir="${REPO_ROOT}/ci/perf-testing/${DEPLOYMENT_TYPE}/kms-ci/kms-service"
        if [[ "${KMS_CHART_VERSION}" != "repository" ]]; then
            helm_chart_location="oci://ghcr.io/zama-ai/kms/charts/kms-core"
            helm_version_args=(--version "${KMS_CHART_VERSION}")
        fi
    fi

    # 2. Generate Peers List (if threshold)
    local PEERS_VALUES="/tmp/kms-peers-values-${NAMESPACE}.yaml"
    if [[ "${DEPLOYMENT_TYPE}" == *"threshold"* ]]; then
        generate_peers_config "${PEERS_VALUES}"
    else
        echo "kmsPeers: { count: 1 }" > "${PEERS_VALUES}"
    fi

    # 3. Generate Dynamic Overrides (Image names, Tolerations, Enclave settings)
    local OVERRIDE_VALUES="/tmp/kms-values-override-${NAMESPACE}.yaml"
    generate_helm_overrides "${OVERRIDE_VALUES}"

    # 4. Deploy
    if [[ "${DEPLOYMENT_TYPE}" == *"threshold"* ]]; then
        local threshold_value="1"
        if [[ "${NUM_PARTIES}" -ge 13 ]]; then
            threshold_value="4"
        fi

        local wait_args=(--wait --wait-for-jobs --timeout=1200s)

        for i in $(seq 1 "${NUM_PARTIES}"); do
            log_info "Deploying Party ${i}..."

            # Common Helm Args
            local HELM_ARGS=(
                --namespace "${NAMESPACE}"
                --values "${BASE_VALUES}"
                --values "${PEERS_VALUES}"
                --values "${OVERRIDE_VALUES}"
                --set kmsPeers.id="${i}"
                --set kmsCoreClient.image.tag="${KMS_CLIENT_TAG}"
                --set kmsCore.publicVault.s3.prefix="PUB-p${i}"
                --set kmsCore.privateVault.s3.prefix="PRIV-p${i}"
                --set kmsCore.backupVault.s3.prefix="BACKUP-p${i}"
            )

            if [[ "${is_perf}" == "true" ]]; then
                HELM_ARGS+=(
                    --values "${perf_values_dir}/values-${PATH_SUFFIX}.yaml"
                    --set kmsCore.serviceAccountName="${NAMESPACE}-${i}"
                    --set kmsCore.envFrom.configmap.name="${NAMESPACE}-${i}"
                    --set kmsCore.image.tag="${KMS_CORE_TAG}"
                )
                if [[ "${DEPLOYMENT_TYPE}" == "thresholdWithEnclave" ]]; then
                    HELM_ARGS+=(
                        --set kmsCore.thresholdMode.tls.enabled="${TLS}"
                        --set kmsCore.thresholdMode.tls.trustedReleases[0].pcr0="${PCR0:-}"
                        --set kmsCore.thresholdMode.tls.trustedReleases[0].pcr1="${PCR1:-}"
                        --set kmsCore.thresholdMode.tls.trustedReleases[0].pcr2="${PCR2:-}"
                    )
                fi
            fi

            if [[ "${DEPLOYMENT_TYPE}" == *"threshold"* ]]; then
                HELM_ARGS+=(
                    --set kmsCore.thresholdMode.thresholdValue="${threshold_value}"
                )
            fi

            if [[ "${TARGET}" == "aws-ci" ]]; then
                # Kind specific overrides (Localstack S3)
                HELM_ARGS+=(
                    --set kmsCore.serviceAccountName="${NAMESPACE}-${i}"
                    --set kmsCore.envFrom.configmap.name="${NAMESPACE}-${i}"
                )
            fi

            # Local Dev Overrides (Low Resources)
            if [[ "${TARGET}" == "kind-local" ]]; then
                if [[ "${LOCAL_VALUES_USED}" != "true" ]]; then
                    HELM_ARGS+=("--values" "${REPO_ROOT}/ci/values/overrides/dev-minimal.yaml")
                fi

                # Check for user-specific overrides (gitignored)
                if [[ -f "${REPO_ROOT}/ci/values/overrides/user.yaml" ]]; then
                    log_info "Applying user overrides from user.yaml"
                    HELM_ARGS+=("--values" "${REPO_ROOT}/ci/values/overrides/user.yaml")
                fi
            fi

            helm upgrade --install "kms-core-${i}" \
                "${helm_chart_location}" \
                "${helm_version_args[@]}" \
                "${HELM_ARGS[@]}" \
                "${wait_args[@]}" &
        done
        wait

        if [[ "${TARGET}" == "aws-ci" ]]; then
            log_info "Waiting for KMS Core pods to be ready..."
            sleep 60
            for i in $(seq 1 "${NUM_PARTIES}"); do
                kubectl wait --for=condition=ready pod "kms-core-${i}-core-${i}" \
                    -n "${NAMESPACE}" --timeout=600s
            done
        fi

        # Init Job
        if [[ "${is_perf}" == "true" ]]; then
            log_info "Deploying KMS Core initialization job..."
            helm upgrade --install kms-core-init \
                "${helm_chart_location}" \
                "${helm_version_args[@]}" \
                --namespace "${NAMESPACE}" \
                --values "${perf_values_dir}/values-kms-service-init-${PATH_SUFFIX}.yaml" \
                --set kmsCoreClient.image.tag="${KMS_CLIENT_TAG}" \
                --set kmsCore.image.tag="${KMS_CORE_TAG}" \
                --wait \
                --wait-for-jobs \
                --timeout=1200s
        else
            deploy_init_job "${BASE_VALUES}" "${PEERS_VALUES}" "${OVERRIDE_VALUES}"
        fi

    else
        # Centralized
        log_info "Deploying Centralized..."
        local wait_args=()
        if [[ "${TARGET}" != "aws-ci" ]]; then
            wait_args=(--wait)
        fi

        local HELM_ARGS=(
            --namespace "${NAMESPACE}"
            --values "${BASE_VALUES}"
            --values "${PEERS_VALUES}"
            --values "${OVERRIDE_VALUES}"
            --set kmsCore.thresholdMode.enabled=false
            --set kmsCoreClient.image.tag="${KMS_CLIENT_TAG}"
        )

        if [[ "${is_perf}" == "true" ]]; then
            HELM_ARGS+=(
                --values "${perf_values_dir}/values-${PATH_SUFFIX}.yaml"
                --set kmsCore.image.tag="${KMS_CORE_TAG}"
            )
        fi

        helm upgrade --install kms-core \
            "${helm_chart_location}" \
            "${helm_version_args[@]}" \
            "${HELM_ARGS[@]}" \
            "${wait_args[@]}"

        if [[ "${TARGET}" == "aws-ci" ]]; then
            log_info "Waiting for KMS Core pods to be ready..."
            sleep 60
            kubectl wait --for=condition=ready pod kms-core-core-1 \
                -n "${NAMESPACE}" --timeout=600s
        fi
    fi
}

generate_helm_overrides() {
    local output_file="$1"
    log_info "Generating Helm overrides to ${output_file}"

    local IS_ENCLAVE="false"
    local KMS_IMAGE_NAME="${KMS_CORE_IMAGE_NAME}"
    local KMS_CLIENT_IMAGE_NAME_LOCAL="${KMS_CORE_CLIENT_IMAGE_NAME}"
    local GEN_KEYS="false"
    local TOLERATION_KEY="karpenter.sh/nodepool"
    local TOLERATION_VALUE="kms-bench-spot-64" # Default for Standard
    local INCLUDE_TOLERATIONS="false"
    local TLS_ENABLED="false"
    local NUM_MAJORITY="1"
    local NUM_RECONSTRUCT="1"

    # Logic ported from pr-preview-deploy.yml
    if [[ "${DEPLOYMENT_TYPE}" == *"Enclave"* ]]; then
         IS_ENCLAVE="true"
         KMS_IMAGE_NAME="ghcr.io/zama-ai/kms/core-service-enclave"
         GEN_KEYS="true"
         TOLERATION_KEY="app"
         TOLERATION_VALUE="${NAMESPACE}"
         TLS_ENABLED="true"
    fi

    if [[ "${TARGET}" == "aws-ci" ]]; then
        INCLUDE_TOLERATIONS="true"
    fi

    # Set Threshold params
    if [[ "${DEPLOYMENT_TYPE}" == *"threshold"* ]]; then
        # Default for 4 parties as per original workflow
        if [[ "${NUM_PARTIES}" -ge 13 ]]; then
            NUM_MAJORITY="5"
            NUM_RECONSTRUCT="9"
        else
            NUM_MAJORITY="2"
            NUM_RECONSTRUCT="3"
        fi
    fi

    cat <<EOF > "${output_file}"
kmsCore:
  image:
    name: "${KMS_IMAGE_NAME}"
    tag: "${KMS_CORE_TAG}"
EOF

    if [[ "${TARGET}" == "aws-ci" ]]; then
        cat <<EOF >> "${output_file}"
  serviceAccountName: "${NAMESPACE}-1"
  envFrom:
    configmap:
      name: "${NAMESPACE}-1"
EOF
    fi

    if [[ "${INCLUDE_TOLERATIONS}" == "true" ]]; then
        cat <<EOF >> "${output_file}"
  tolerations:
    - key: "${TOLERATION_KEY}"
      effect: "NoSchedule"
      operator: "Equal"
      value: "${TOLERATION_VALUE}"
EOF
    fi

    # Append Enclave specific settings
    if [[ "${IS_ENCLAVE}" == "true" && "${DEPLOYMENT_TYPE}" == *"threshold"* ]]; then
        cat <<EOF >> "${output_file}"
  thresholdMode:
    tls:
      enabled: ${TLS_ENABLED}
      trustedReleases:
        - pcr0: "${PCR0:-}"
          pcr1: "${PCR1:-}"
          pcr2: "${PCR2:-}"
EOF
    fi

    # Append Common Client/GenKey settings
    cat <<EOF >> "${output_file}"

kmsCoreClient:
  image:
    name: "${KMS_CLIENT_IMAGE_NAME_LOCAL}"
    tag: "${KMS_CLIENT_TAG}"
EOF

    if [[ "${TARGET}" == "aws-ci" ]]; then
        cat <<EOF >> "${output_file}"
  envFrom:
    configmap:
      name: "${NAMESPACE}-1"
EOF
    fi

    if [[ "${INCLUDE_TOLERATIONS}" == "true" ]]; then
        cat <<EOF >> "${output_file}"
  tolerations:
    - key: "karpenter.sh/nodepool"
      effect: "NoSchedule"
      operator: "Equal"
      value: "zws-pool"
EOF
    fi

    cat <<EOF >> "${output_file}"
  num_majority: ${NUM_MAJORITY}
  num_reconstruct: ${NUM_RECONSTRUCT}

kmsGenCertAndKeys:
  enabled: ${GEN_KEYS}
EOF

    log_info "Generated overrides content:"
    cat "${output_file}"
}

generate_peers_config() {
    local output_file="$1"
    log_info "Generating peers config to ${output_file}"

    echo "kmsCore:" > "${output_file}"
    echo "  thresholdMode:" >> "${output_file}"
    echo "    peersList:" >> "${output_file}"

    for i in $(seq 1 "${NUM_PARTIES}"); do
        local host
        if [[ "${TARGET}" == *"kind"* ]]; then
            # Format used in setup_kms_in_kind.sh
            # host: kms-service-threshold-1-<namespace>-core-1
            # Note: The existing script used different release names.
            # Let's standardize on: kms-core-${i}-core-${i} (assuming chart naming conventions)
            # BUT setup_kms_in_kind uses: kms-service-threshold-${i}-${NAMESPACE}-core-${i}
            # We are changing the release name in this script to 'kms-core-${i}'
            # So the service will likely be 'kms-core-${i}-core-${i}' depending on chart helpers.
            host="kms-core-${i}-core-${i}"
        else
            # AWS/CI format
            host="kms-core-${i}-core-${i}"
        fi

        echo "      - id: ${i}" >> "${output_file}"
        echo "        host: ${host}" >> "${output_file}"
        echo "        port: 50001" >> "${output_file}"
    done
}

deploy_init_job() {
    local base_values="$1"
    local peers_values="$2"
    local override_values="$3"
    local threshold_value="1"
    if [[ "${NUM_PARTIES}" -ge 13 ]]; then
        threshold_value="4"
    fi

    # Determine init values file
    local INIT_VALUES=""
    local LOCAL_VALUES_USED="false"
    if [[ "${TARGET}" == *"kind"* ]]; then
        local base_dir="${REPO_ROOT}/ci/kube-testing/kms"
        local init_values="${base_dir}/values-kms-service-init-kms-test.yaml"
        local init_local_values="${base_dir}/local-values-kms-service-init-kms-test.yaml"
        if [[ "${TARGET}" == "kind-local" && -f "${init_local_values}" ]]; then
            INIT_VALUES="${init_local_values}"
            LOCAL_VALUES_USED="true"
        else
            INIT_VALUES="${init_values}"
        fi
    else
        INIT_VALUES="${REPO_ROOT}/ci/pr-preview/${DEPLOYMENT_TYPE}/kms-service/values-kms-service-init-kms-ci.yaml"
    fi

    log_info "Deploying Init Job..."

    local HELM_ARGS=(
        --namespace "${NAMESPACE}"
        --values "${INIT_VALUES}"
        --values "${peers_values}"
        --values "${override_values}"
        --wait \
        --wait-for-jobs \
        --timeout=1200s
    )

    if [[ "${TARGET}" == "kind-local" ]]; then
        if [[ "${LOCAL_VALUES_USED}" != "true" ]]; then
            HELM_ARGS+=("--values" "${REPO_ROOT}/ci/values/overrides/dev-minimal.yaml")
        fi
        if [[ -f "${REPO_ROOT}/ci/values/overrides/user.yaml" ]]; then
             HELM_ARGS+=("--values" "${REPO_ROOT}/ci/values/overrides/user.yaml")
        fi
    fi

    log_info "Helm init command: helm upgrade --install kms-core-init \"${REPO_ROOT}/charts/kms-core\" ${HELM_ARGS[*]}"
    helm upgrade --install kms-core-init \
        "${REPO_ROOT}/charts/kms-core" \
        "${HELM_ARGS[@]}"

    log_info "Waiting for KMS Core initialization to complete..."
    sleep 30
    kubectl wait --for=condition=complete job -l app=kms-threshold-init-job \
        -n "${NAMESPACE}" --timeout=600s || {
            log_error "KMS init job did not complete in time"
            kubectl get jobs -n "${NAMESPACE}" -l app=kms-threshold-init-job || true
            exit 1
        }
}

#=============================================================================
# Port Forwarding (Local/Kind only)
#=============================================================================
setup_port_forwarding() {
    if [[ "${TARGET}" != *"kind"* ]]; then
        return 0
    fi

    log_info "Setting up port forwarding..."

    # Localstack
    log_info "  - Localstack (9000:4566)"
    kubectl port-forward -n "${NAMESPACE}" svc/localstack 9000:4566 > /dev/null 2>&1 &

    # KMS Core
    if [[ "${DEPLOYMENT_TYPE}" == *"threshold"* ]]; then
        for i in $(seq 1 "${NUM_PARTIES}"); do
            local port=$((50000 + i * 100))
            # Service name depends on chart logic.
            # In deploy_kms, we named release "kms-core-${i}"
            # Standard chart usually appends "-core-${i}" or similar.
            # We assume "kms-core-${i}-core-${i}" based on previous pattern analysis.
            local svc_name="kms-core-${i}-core-${i}"

            log_info "  - Party ${i} (${port}:50100 -> ${svc_name})"
            kubectl port-forward -n "${NAMESPACE}" \
                "svc/${svc_name}" \
                "${port}:50100" > /dev/null 2>&1 &
        done
    else
        # Centralized
        # Release "kms-core" -> Service "kms-core-core" or "kms-core" depending on chart
        # Standard chart with centralized usually just "kms-core-core" or nameOverride
        log_info "  - Centralized (50100:50100 -> kms-core-core)"
        kubectl port-forward -n "${NAMESPACE}" \
            "svc/kms-core-core" \
            "50100:50100" > /dev/null 2>&1 &
    fi
}

wait_indefinitely() {
    log_info "Deployment ready. Port forwarding active."
    log_info "Press Ctrl+C to stop port forwarding and exit."

    # Handle cleanup on exit
    trap 'pkill -P $$; exit' INT TERM

    while true; do
        sleep 3600 &
        wait $!
    done
}

#=============================================================================
# Main
#=============================================================================
main() {
    parse_args "$@"

    # Special mode: Collect logs and exit
    if [[ "${COLLECT_LOGS:-false}" == "true" ]]; then
        # Minimal context setup if needed
        if [[ "${TARGET}" == *"kind"* ]]; then
             kubectl config use-context "kind-${NAMESPACE}" || true
        fi
        collect_logs
        exit 0
    fi

    if [[ "${TARGET}" == "kind-local" ]]; then
        check_local_resources
    fi

    log_info "Starting Deployment"
    log_info "Target: ${TARGET}"
    log_info "Namespace: ${NAMESPACE}"

    setup_context
    setup_infrastructure

    if [[ "${BUILD_IMAGES}" == "true" ]] && [[ "${TARGET}" == *"kind"* ]]; then
        # Call build function (omitted for brevity, can import from other script or copy)
        log_warn "Build requested but logic not fully ported yet in this draft."
    fi

    deploy_kms
    setup_port_forwarding

    log_info "Deployment Complete!"

    if [[ "${BLOCK:-false}" == "true" ]]; then
        wait_indefinitely
    fi
}

collect_logs() {
    log_info "Collecting logs for ${DEPLOYMENT_TYPE} deployment..."

    # Ensure context is set (we might need to infer or pass it if just collecting logs)
    # Assuming the caller has set up kubeconfig or is in the right context environment

    if [[ "${DEPLOYMENT_TYPE}" == *"threshold"* ]]; then
        log_info "Collecting logs from ${NUM_PARTIES} KMS Core parties..."
        for i in $(seq 1 "${NUM_PARTIES}"); do
            # Note: We need to match the Pod names.
            # Helm Release: kms-core-${i}
            # StatefulSet Pod: kms-core-${i}-core-${i}-0 (if replicas=1)
            # OR if using chart name override...
            # Based on previous analysis: kms-core-${i}-core-${i} was the service,
            # so the pod is likely: kms-core-${i}-core-${i}-0

            # Let's try to find pods by label to be safer
            # Label: app.kubernetes.io/instance=kms-core-${i}

            local POD_NAME=$(kubectl get pods -n "${NAMESPACE}" -l "app.kubernetes.io/instance=kms-core-${i},app.kubernetes.io/name=kms-core-service" -o jsonpath="{.items[0].metadata.name}" 2>/dev/null)

            if [[ -n "${POD_NAME}" ]]; then
                log_info "  Dumping logs for ${POD_NAME}..."
                mkdir -p logs
                kubectl logs "${POD_NAME}" -n "${NAMESPACE}" > "logs/${POD_NAME}.log" 2>&1 || true
            else
                log_warn "  No pod found for party ${i}"
            fi
        done
    else
        # Centralized
        local POD_NAME=$(kubectl get pods -n "${NAMESPACE}" -l "app.kubernetes.io/instance=kms-core" -o jsonpath="{.items[0].metadata.name}" 2>/dev/null)
        if [[ -n "${POD_NAME}" ]]; then
             log_info "  Dumping logs for ${POD_NAME}..."
             mkdir -p logs
             kubectl logs "${POD_NAME}" -n "${NAMESPACE}" > "logs/${POD_NAME}.log" 2>&1 || true
        else
             log_warn "  No centralized pod found"
        fi
    fi
}

main "$@"

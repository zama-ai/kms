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
CLEANUP="false"
BUILD_IMAGES="false"
# Default Repo Root (assuming script is in ci/scripts/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# AWS/Tailscale Defaults
TAILSCALE_HOSTNAME="tailscale-operator-zws-dev.diplodocus-boa.ts.net"
TKMS_INFRA_VERSION="0.3.2"
SYNC_SECRETS_VERSION="0.2.1"

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

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --target) TARGET="$2"; shift 2 ;;
            --namespace) NAMESPACE="$2"; shift 2 ;;
            --deployment-type) DEPLOYMENT_TYPE="$2"; shift 2 ;;
            --tag) KMS_CORE_TAG="$2"; KMS_CLIENT_TAG="$2"; shift 2 ;; # Simplified for now
            --num-parties) NUM_PARTIES="$2"; shift 2 ;;
            --cleanup) CLEANUP="true"; shift ;;
            --build) BUILD_IMAGES="true"; shift ;;
            --block) BLOCK="true"; shift ;;
            --pcr0) PCR0="$2"; shift 2 ;;
            --pcr1) PCR1="$2"; shift 2 ;;
            --pcr2) PCR2="$2"; shift 2 ;;
            --collect-logs) COLLECT_LOGS="true"; shift ;;
            --help) show_help; exit 0 ;;
            *) log_error "Unknown argument: $1"; exit 1 ;;
        esac
    done

    # Adjust NUM_PARTIES based on deployment type
    if [[ "${DEPLOYMENT_TYPE}" == *"centralized"* ]]; then
        NUM_PARTIES=1
    fi
}

show_help() {
    echo "Usage: $0 --target [kind-local|kind-ci|aws-ci] [OPTIONS]"
    echo "Options:"
    echo "  --namespace <name>       K8s namespace (default: kms-test)"
    echo "  --deployment-type <type> threshold|centralized|thresholdWithEnclave... (default: threshold)"
    echo "  --tag <tag>              Image tag (default: latest-dev)"
    echo "  --num-parties <n>        Number of parties (default: 4 for threshold)"
    echo "  --cleanup                Cleanup before deploy"
    echo "  --build                  Build images locally (kind targets only)"
    echo "  --block                  Keep script running (for port-forwarding)"
    echo "  --pcr0 <val>             PCR0 value for Enclave (optional)"
    echo "  --collect-logs           Only collect logs from pods and exit"
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
        aws-ci)
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
    elif [[ "${TARGET}" == "aws-ci" ]]; then
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

deploy_tkms_infra() {
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
}

deploy_registry_credentials() {
    log_info "Deploying Sync Secrets..."
    helm upgrade --install sync-secrets \
        oci://ghcr.io/zama-zws/helm-charts/sync-secrets \
        --namespace "${NAMESPACE}" \
        --version "${SYNC_SECRETS_VERSION}" \
        --values "${REPO_ROOT}/ci/pr-preview/registry-credential/values-kms-ci.yaml" \
        --create-namespace \
        --wait
}

#=============================================================================
# KMS Deployment
#=============================================================================
deploy_kms() {
    log_info "Deploying KMS Core..."

    # 1. Determine base values file
    local BASE_VALUES=""
    if [[ "${TARGET}" == *"kind"* ]]; then
        BASE_VALUES="${REPO_ROOT}/ci/kube-testing/kms/values-kms-test.yaml"
    else
        # For AWS/CI, we use the values from pr-preview
        BASE_VALUES="${REPO_ROOT}/ci/pr-preview/${DEPLOYMENT_TYPE}/kms-service/values-kms-ci.yaml"
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
            )

            if [[ "${TARGET}" == *"kind"* ]]; then
                # Kind specific overrides (Localstack S3)
                HELM_ARGS+=(
                    --set kmsCore.publicVault.s3.prefix="PUB-p${i}"
                    --set kmsCore.privateVault.s3.prefix="PRIV-p${i}"
                    --set kmsCore.backupVault.s3.prefix="BACKUP-p${i}"
                )
            else
                # AWS Specific overrides (Service Accounts, etc.)
                HELM_ARGS+=(
                    --set kmsCore.serviceAccountName="${NAMESPACE}-${i}"
                    --set kmsCore.envFrom.configmap.name="${NAMESPACE}-${i}"
                    --set kmsCore.thresholdMode.thresholdValue="1" # TODO: Make variable
                    --set kmsCore.publicVault.s3.prefix="PUB-p${i}"
                    --set kmsCore.privateVault.s3.prefix="PRIV-p${i}"
                )
            fi

            # Local Dev Overrides (Low Resources)
            if [[ "${TARGET}" == "kind-local" ]]; then
                HELM_ARGS+=("--values" "${REPO_ROOT}/ci/values/overrides/dev-minimal.yaml")

                # Check for user-specific overrides (gitignored)
                if [[ -f "${REPO_ROOT}/ci/values/overrides/user.yaml" ]]; then
                    log_info "Applying user overrides from user.yaml"
                    HELM_ARGS+=("--values" "${REPO_ROOT}/ci/values/overrides/user.yaml")
                fi
            fi

            helm upgrade --install "kms-core-${i}" \
                "${REPO_ROOT}/charts/kms-core" \
                "${HELM_ARGS[@]}" \
                --wait &
        done
        wait

        # Init Job
        deploy_init_job "${BASE_VALUES}" "${PEERS_VALUES}" "${OVERRIDE_VALUES}"

    else
        # Centralized
        log_info "Deploying Centralized..."
        helm upgrade --install kms-core \
            "${REPO_ROOT}/charts/kms-core" \
            --namespace "${NAMESPACE}" \
            --values "${BASE_VALUES}" \
            --values "${PEERS_VALUES}" \
            --values "${OVERRIDE_VALUES}" \
            --set kmsCoreClient.image.tag="${KMS_CLIENT_TAG}" \
            --wait
    fi
}

generate_helm_overrides() {
    local output_file="$1"
    log_info "Generating Helm overrides to ${output_file}"

    local IS_ENCLAVE="false"
    local KMS_IMAGE_NAME="ghcr.io/zama-ai/kms/core-service"
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
        NUM_MAJORITY="2"
        NUM_RECONSTRUCT="3"
    fi

    cat <<EOF > "${output_file}"
kmsCore:
  image:
    name: "${KMS_IMAGE_NAME}"
    tag: "${KMS_CORE_TAG}"
EOF

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
EOF

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

    # Determine init values file
    local INIT_VALUES=""
    if [[ "${TARGET}" == *"kind"* ]]; then
        INIT_VALUES="${REPO_ROOT}/ci/kube-testing/kms/values-kms-service-init-kms-test.yaml"
    else
        INIT_VALUES="${REPO_ROOT}/ci/pr-preview/${DEPLOYMENT_TYPE}/kms-service/values-kms-service-init-kms-ci.yaml"
    fi

    log_info "Deploying Init Job..."

    local HELM_ARGS=(
        --namespace "${NAMESPACE}"
        --values "${INIT_VALUES}"
        --values "${peers_values}"
        --values "${override_values}"
        --set kmsCoreClient.image.tag="${KMS_CLIENT_TAG}" \
        --wait \
        --wait-for-jobs
    )

    if [[ "${TARGET}" == "kind-local" ]]; then
        HELM_ARGS+=("--values" "${REPO_ROOT}/ci/values/overrides/dev-minimal.yaml")
        if [[ -f "${REPO_ROOT}/ci/values/overrides/user.yaml" ]]; then
             HELM_ARGS+=("--values" "${REPO_ROOT}/ci/values/overrides/user.yaml")
        fi
    fi

    helm upgrade --install kms-core-init \
        "${REPO_ROOT}/charts/kms-core" \
        "${HELM_ARGS[@]}"
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

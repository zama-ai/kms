#!/usr/bin/env bash

#=============================================================================
# Infrastructure Setup
# Functions for deploying and configuring infrastructure components
#=============================================================================

#=============================================================================
# Setup Infrastructure
# Deploy required infrastructure components
# - Kind: LocalStack (S3 mock) + registry credentials
# - AWS: TKMS infrastructure (S3, IAM via Crossplane) + registry credentials
#=============================================================================
setup_infrastructure() {
    log_info "Setting up infrastructure..."

    if [[ "${TARGET}" == *"kind"* ]]; then
        #---------------------------------------------------------------------
        # Kind deployments: Mock AWS services locally
        #---------------------------------------------------------------------
        deploy_localstack           # S3-compatible storage
        deploy_registry_credentials # GHCR access

    elif [[ "${TARGET}" == "aws-ci" || "${TARGET}" == "aws-perf" ]]; then
        #---------------------------------------------------------------------
        # AWS deployments: Real infrastructure via Crossplane
        #---------------------------------------------------------------------

        # Fetch PCR values from enclave image if not provided
        if [[ "${DEPLOYMENT_TYPE}" == *"Enclave"* ]] && [[ -z "${PCR0:-}" ]]; then
             fetch_pcrs_from_image
        fi

        deploy_tkms_infra           # S3 buckets, IAM roles, service accounts
        deploy_registry_credentials # GHCR access via sync-secrets
    fi
}

#=============================================================================
# Fetch PCRs from Image
#=============================================================================
fetch_pcrs_from_image() {
    log_info "Fetching PCRs from image: ${KMS_CORE_TAG}"

    if ! command -v docker &> /dev/null; then
        log_warn "Docker not found, skipping PCR fetch. Ensure PCR0 env var is set if needed."
        return
    fi

    local IMAGE_REPO="ghcr.io/zama-ai/kms"
    local FULL_IMAGE="${IMAGE_REPO}/core-service-enclave:${KMS_CORE_TAG}"

    log_info "Pulling ${FULL_IMAGE}..."
    docker pull "${FULL_IMAGE}" > /dev/null 2>&1 || log_warn "Failed to pull image to check PCRs"

    export PCR0=$(docker inspect "${FULL_IMAGE}" | jq -r '.[0].Config.Labels["zama.kms.eif_pcr0"]' || echo "")
    export PCR1=$(docker inspect "${FULL_IMAGE}" | jq -r '.[0].Config.Labels["zama.kms.eif_pcr1"]' || echo "")
    export PCR2=$(docker inspect "${FULL_IMAGE}" | jq -r '.[0].Config.Labels["zama.kms.eif_pcr2"]' || echo "")

    log_info "Detected PCR0: ${PCR0}"
    log_info "Detected PCR1: ${PCR1}"
    log_info "Detected PCR2: ${PCR2}"
}

#=============================================================================
# Deploy Localstack (S3 Mock)
#=============================================================================
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

#=============================================================================
# Wait for Crossplane Resources
# Wait for Crossplane-managed AWS resources to be provisioned
# Includes: S3 buckets, IAM roles, and other composite resources
#=============================================================================
wait_crossplane_resources_ready() {
    local party_prefix="kms-party-${NAMESPACE}"
    if [[ "${TARGET}" == "aws-perf" ]]; then
        set_path_suffix
        party_prefix="kms-party-${PATH_SUFFIX}"
    fi

    log_info "Waiting for Crossplane resources (S3 buckets, IAM roles) to be ready..."

    local max_wait=300      # 5 minutes timeout
    local elapsed=0
    local check_interval=10  # Check every 10 seconds

    while [[ $elapsed -lt $max_wait ]]; do
        # Check if S3 bucket resources have reached Ready status
        if kubectl get s3 -n "${NAMESPACE}" -o jsonpath='{.items[*].status.conditions[?(@.type=="Ready")].status}' 2>/dev/null | grep -q "True"; then
            log_info "S3 bucket resources are ready"
            break
        fi

        log_info "Waiting for S3 bucket resources... ($elapsed/$max_wait seconds)"
        sleep $check_interval
        elapsed=$((elapsed + check_interval))
    done

    # Timeout handling: Show current state for debugging
    if [[ $elapsed -ge $max_wait ]]; then
        log_warn "Timeout waiting for S3 resources. Checking current state..."
        kubectl get s3 -n "${NAMESPACE}" -o wide || true
        kubectl get composite -n "${NAMESPACE}" -o wide || true
    fi
}

#=============================================================================
# Wait for TKMS Infrastructure
# Wait for TKMS infrastructure components to be ready
# This includes: S3 buckets, IAM roles, Kmsparties, and enclave nodegroups
#=============================================================================
wait_tkms_infra_ready() {
    # Determine party prefix based on target
    local party_prefix="kms-party-${NAMESPACE}"
    if [[ "${TARGET}" == "aws-perf" ]]; then
        set_path_suffix
        party_prefix="kms-party-${PATH_SUFFIX}"
    fi

    #-------------------------------------------------------------------------
    # Phase 1: Wait for Crossplane resources (S3, IAM)
    #-------------------------------------------------------------------------
    wait_crossplane_resources_ready

    #-------------------------------------------------------------------------
    # Phase 2: Wait for Kmsparties resources to be created
    #-------------------------------------------------------------------------
    log_info "Waiting for Kmsparties resources to be created..."

    local max_wait=120
    local elapsed=0
    local check_interval=5

    while [[ $elapsed -lt $max_wait ]]; do
        if kubectl get Kmsparties -n "${NAMESPACE}" 2>/dev/null | grep -qF "${party_prefix}"; then
            log_info "Kmsparties resources found"
            break
        fi
        log_info "Waiting for Kmsparties to be created... ($elapsed/$max_wait seconds)"
        sleep $check_interval
        elapsed=$((elapsed + check_interval))
    done

    #-------------------------------------------------------------------------
    # Phase 3: Wait for Kmsparties to become ready
    #-------------------------------------------------------------------------
    log_info "Waiting for Kmsparties to be ready..."

    if [[ "${DEPLOYMENT_TYPE}" == "centralizedWithEnclave" ]]; then
        # Centralized: Try both possible naming patterns
        if kubectl get Kmsparties "${party_prefix}-1" -n "${NAMESPACE}" >/dev/null 2>&1; then
            kubectl wait --for=condition=ready Kmsparties "${party_prefix}-1" \
                -n "${NAMESPACE}" --timeout=120s
        elif kubectl get Kmsparties "${party_prefix}" -n "${NAMESPACE}" >/dev/null 2>&1; then
            kubectl wait --for=condition=ready Kmsparties "${party_prefix}" \
                -n "${NAMESPACE}" --timeout=120s
        else
            log_warn "No KMS party found with name ${party_prefix} or ${party_prefix}-1"
            kubectl get Kmsparties -n "${NAMESPACE}" -o name || true
            return 1
        fi
    elif [[ "${DEPLOYMENT_TYPE}" == *"threshold"* ]]; then
        # Threshold: Wait for all parties
        for i in $(seq 1 "${NUM_PARTIES}"); do
            kubectl wait --for=condition=ready Kmsparties "${party_prefix}-${i}" \
                -n "${NAMESPACE}" --timeout=120s
        done
    fi

    #-------------------------------------------------------------------------
    # Phase 4: Wait for enclave nodegroups (if applicable)
    #-------------------------------------------------------------------------
    if [[ "${DEPLOYMENT_TYPE}" == *"Enclave"* ]]; then
        log_info "Waiting for enclave nodegroups to be ready..."
        kubectl wait --for=condition=ready enclavenodegroup \
            "${party_prefix}" \
            -n "${NAMESPACE}" --timeout=1200s
    fi
}

#=============================================================================
# Deploy TKMS Infrastructure
#=============================================================================
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
    local VALUES_FILE="${REPO_ROOT}/ci/pr-preview/${DEPLOYMENT_TYPE}/tkms-infra/values-kms-ci.yaml"

    local EXTRA_ARGS=""
    if [[ "${DEPLOYMENT_TYPE}" == *"Enclave"* ]]; then
        EXTRA_ARGS="--set kmsParties.awsKms.recipientAttestationImageSHA384=${PCR0:-}"
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
        ${EXTRA_ARGS}

    wait_tkms_infra_ready
}

#=============================================================================
# Deploy Registry Credentials
# Deploy registry credentials for private image access
# - Kind: Create dockerconfigjson secret locally
# - AWS: Use sync-secrets Helm chart for remote registry access
#=============================================================================
deploy_registry_credentials() {
    log_info "Setting up registry credentials for target: ${TARGET}"

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

    # Check if sync-secrets release exists (even in failed state)
    if helm list -n "${NAMESPACE}" -a | grep -q "^sync-secrets"; then
        log_info "Found existing sync-secrets release, uninstalling first..."
        helm uninstall sync-secrets -n "${NAMESPACE}" --wait || true
        sleep 3  # Give Kubernetes time to clean up resources
    fi

    # Also check for orphaned Helm secrets (release metadata)
    if kubectl get secret -n "${NAMESPACE}" -l owner=helm,name=sync-secrets 2>/dev/null | grep -q "sync-secrets"; then
        log_info "Found orphaned sync-secrets Helm metadata, cleaning up..."
        kubectl delete secret -n "${NAMESPACE}" -l owner=helm,name=sync-secrets || true
        sleep 2
    fi

    log_info "Installing sync-secrets Helm chart..."
    helm upgrade --install sync-secrets \
        oci://ghcr.io/zama-zws/helm-charts/sync-secrets \
        --namespace "${NAMESPACE}" \
        --version "${SYNC_SECRETS_VERSION}" \
        --values "${registry_values_path}" \
        --create-namespace \
        --wait
}

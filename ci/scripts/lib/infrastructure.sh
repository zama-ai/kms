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

        # Optional: install kube-prometheus-stack (Prometheus Operator) so the
        # KMS ServiceMonitor is scraped and metrics are remote-written to
        # Grafana Cloud. Must run BEFORE deploy_kms so the ServiceMonitor CRD
        # exists when the kms-core chart renders it.
        if [[ "${ENABLE_METRICS:-false}" == "true" ]]; then
            deploy_kube_prometheus_stack
        fi

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

        # Metrics are kind-only: without the kube-prometheus-stack installed above
        # there is no ServiceMonitor CRD and deploy_kms would fail rendering one.
        if [[ "${ENABLE_METRICS:-false}" == "true" ]]; then
            log_warn "--enable-metrics is only supported on kind targets; disabling for TARGET=${TARGET}."
            export ENABLE_METRICS="false"
        fi
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

    local IMAGE_REPO="hub.zama.org/ghcr/zama-ai/kms"
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
# Deploy kube-prometheus-stack (Prometheus Operator)
#
# Installs a lean, operator-only kube-prometheus-stack in the `monitoring`
# namespace and configures Prometheus to remote-write to Grafana Cloud.
# The `ci_` metric-name prefix is applied at scrape time by the KMS
# ServiceMonitor (see charts/kms-core), so remote-write stays plain here.
#
# Credentials are read from the environment (never echoed):
#   - GRAFANA_CLOUD_PROM_URL       remote-write endpoint
#   - GRAFANA_CLOUD_PROM_USERNAME  Prometheus instance / user id
#   - GRAFANA_CLOUD_PROM_PASSWORD  Cloud Access Policy token (metrics:write)
#=============================================================================
# Pin the chart version for reproducible CI runs.
KUBE_PROMETHEUS_STACK_VERSION="${KUBE_PROMETHEUS_STACK_VERSION:-77.6.2}"

deploy_kube_prometheus_stack() {
    log_info "Deploying kube-prometheus-stack (metrics enabled)..."

    # Require the full credential set; a partial one would only fail later, at
    # remote-write time.
    if [[ -z "${GRAFANA_CLOUD_PROM_URL:-}" || -z "${GRAFANA_CLOUD_PROM_USERNAME:-}" || -z "${GRAFANA_CLOUD_PROM_PASSWORD:-}" ]]; then
        log_warn "GRAFANA_CLOUD_PROM_URL/USERNAME/PASSWORD not all set; skipping kube-prometheus-stack install."
        log_warn "Metrics will not be remote-written. Set all GRAFANA_CLOUD_PROM_* secrets to enable."
        # Force metrics off for the rest of the deploy so deploy_kms (same shell, runs after)
        # does not enable the kms-core ServiceMonitor — its CRD ships with the
        # kube-prometheus-stack we just skipped, so the Helm deploy would fail without it.
        export ENABLE_METRICS="false"
        return 0
    fi

    # Dedicated namespace for the monitoring stack.
    kubectl create namespace monitoring \
        --dry-run=client -o yaml | kubectl apply -f -

    # Basic-auth secret referenced by Prometheus remoteWrite[].basicAuth. Feed the
    # credentials via stdin (env-file) instead of --from-literal so they never appear
    # in argv (/proc/<pid>/cmdline is world-readable and shows up in `ps`).
    printf 'username=%s\npassword=%s\n' \
        "${GRAFANA_CLOUD_PROM_USERNAME:-}" "${GRAFANA_CLOUD_PROM_PASSWORD:-}" |
        kubectl create secret generic grafana-cloud-prom-auth \
            --namespace monitoring \
            --from-env-file=/dev/stdin \
            --dry-run=client -o yaml | kubectl apply -f -

    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts || true
    helm repo update prometheus-community

    # --set-file keeps the URL (a secret, like the credentials above) out of
    # helm's argv. It still lands in the in-cluster release values, which is
    # fine for ephemeral kind.
    local REMOTE_WRITE_URL_FILE
    REMOTE_WRITE_URL_FILE="$(mktemp)"
    chmod 600 "${REMOTE_WRITE_URL_FILE}"
    printf '%s' "${GRAFANA_CLOUD_PROM_URL}" > "${REMOTE_WRITE_URL_FILE}"

    # Capture helm's status so the URL file is removed on failure too. No RETURN
    # trap here: it would re-fire on the caller's return, where the local var is
    # gone — fatal under set -u.
    local HELM_STATUS=0
    helm upgrade --install kube-prometheus-stack prometheus-community/kube-prometheus-stack \
        --version "${KUBE_PROMETHEUS_STACK_VERSION}" \
        --namespace monitoring \
        --create-namespace \
        -f "${REPO_ROOT}/ci/kube-testing/infra/kube-prometheus-stack-values.yaml" \
        --set-file "prometheus.prometheusSpec.remoteWrite[0].url=${REMOTE_WRITE_URL_FILE}" \
        --set-string "prometheus.prometheusSpec.externalLabels.ci_run_id=${GITHUB_RUN_ID:-local}" \
        --wait --timeout 5m || HELM_STATUS=$?
    rm -f "${REMOTE_WRITE_URL_FILE}"
    return "${HELM_STATUS}"
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
dump_tkms_infra_status() {
    local resource_name="${1:-}"

    log_warn "Dumping TKMS infrastructure status for namespace ${NAMESPACE}"
    kubectl get s3 -n "${NAMESPACE}" -o wide || true
    kubectl get Kmsparties -n "${NAMESPACE}" -o wide || true
    kubectl get enclavenodegroup -n "${NAMESPACE}" -o wide || true
    kubectl describe enclavenodegroup -n "${NAMESPACE}" || true

    if [[ -n "${resource_name}" ]]; then
        kubectl describe Kmsparties "${resource_name}" -n "${NAMESPACE}" || true
        kubectl get Kmsparties "${resource_name}" -n "${NAMESPACE}" -o yaml || true
    fi
}

wait_kmsparty_ready() {
    local resource_name="$1"
    local wait_output
    local ready_status

    log_info "Waiting for Kmsparties/${resource_name} to become ready..."
    if ! wait_output=$(kubectl wait --for=condition=ready Kmsparties "${resource_name}" \
        -n "${NAMESPACE}" --timeout=120s 2>&1); then
        echo "${wait_output}"
        log_error "Timed out waiting for Kmsparties/${resource_name}"
        dump_tkms_infra_status "${resource_name}"
        return 1
    fi
    echo "${wait_output}"

    ready_status=$(kubectl get Kmsparties "${resource_name}" -n "${NAMESPACE}" \
        -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
    if [[ "${ready_status}" != *"True"* ]]; then
        log_error "Kmsparties/${resource_name} is not Ready after kubectl wait; status=${ready_status:-missing}"
        dump_tkms_infra_status "${resource_name}"
        return 1
    fi
}

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
    local kmsparties_found="false"

    while [[ $elapsed -lt $max_wait ]]; do
        if kubectl get Kmsparties -n "${NAMESPACE}" 2>/dev/null | grep -qF "${party_prefix}"; then
            log_info "Kmsparties resources found"
            kmsparties_found="true"
            break
        fi
        log_info "Waiting for Kmsparties to be created... ($elapsed/$max_wait seconds)"
        sleep $check_interval
        elapsed=$((elapsed + check_interval))
    done

    if [[ "${kmsparties_found}" != "true" ]]; then
        log_error "Timed out waiting for Kmsparties resources matching ${party_prefix}"
        dump_tkms_infra_status
        return 1
    fi

    #-------------------------------------------------------------------------
    # Phase 3: Wait for Kmsparties to become ready
    #-------------------------------------------------------------------------
    log_info "Waiting for Kmsparties to be ready..."

    if [[ "${DEPLOYMENT_TYPE}" == *"centralized"* ]]; then
        # Centralized: Try both possible naming patterns
        if kubectl get Kmsparties "${party_prefix}-1" -n "${NAMESPACE}" >/dev/null 2>&1; then
            wait_kmsparty_ready "${party_prefix}-1" || return 1
        elif kubectl get Kmsparties "${party_prefix}" -n "${NAMESPACE}" >/dev/null 2>&1; then
            wait_kmsparty_ready "${party_prefix}" || return 1
        else
            log_warn "No KMS party found with name ${party_prefix} or ${party_prefix}-1"
            dump_tkms_infra_status
            return 1
        fi
    elif [[ "${DEPLOYMENT_TYPE}" == *"threshold"* ]]; then
        # Threshold: Wait for all parties
        for i in $(seq 1 "${NUM_PARTIES}"); do
            local resource_name="${party_prefix}-${i}"
            wait_kmsparty_ready "${resource_name}" || return 1
        done
    fi

    #-------------------------------------------------------------------------
    # Phase 4: Wait for enclave nodegroups (if applicable)
    #-------------------------------------------------------------------------
    if [[ "${DEPLOYMENT_TYPE}" == *"Enclave"* ]]; then
        log_info "Waiting for enclave nodegroups to be ready..."
        if ! kubectl wait --for=condition=ready enclavenodegroup \
            "${party_prefix}" \
            -n "${NAMESPACE}" --timeout=1200s; then
            log_error "Timed out waiting for enclavenodegroup/${party_prefix}"
            dump_tkms_infra_status
            return 1
        fi
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
            oci://hub.zama.org/ghcr/zama-zws/crossplane/tkms-infra \
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
        oci://hub.zama.org/ghcr/zama-zws/crossplane/tkms-infra \
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
# Update TKMS Infrastructure for Rolling Upgrade
# Updates per-party recipientAttestationImageSHA384 via partyOverrides
# so that upgraded parties use the new PCR0 in their AWS KMS key policy
# while non-upgraded parties keep the old one.
#
# Required env vars: NAMESPACE, TARGET, DEPLOYMENT_TYPE, TKMS_INFRA_VERSION,
#                    NUM_PARTIES
# Arguments:
#   $1 - old PCR0 value (for non-upgraded parties)
#   $2 - new PCR0 value (for upgraded parties)
#   $3 - comma-separated list of party IDs that have been upgraded
#=============================================================================
update_tkms_infra_for_upgrade() {
    local old_pcr0="$1"
    local new_pcr0="$2"
    local upgraded_parties_csv="$3"

    log_info "Updating TKMS infra with per-party recipientAttestationImageSHA384..."
    log_info "  Old PCR0 (default): ${old_pcr0:0:16}..."
    log_info "  New PCR0 (upgraded): ${new_pcr0:0:16}..."
    log_info "  Upgraded parties: ${upgraded_parties_csv}"

    set_path_suffix
    local VALUES_FILE="${REPO_ROOT}/ci/perf-testing/${DEPLOYMENT_TYPE}/kms-ci/tkms-infra/values-${PATH_SUFFIX}.yaml"

    # Build partyOverrides --set args for each upgraded party
    local OVERRIDE_ARGS=()
    OVERRIDE_ARGS+=(--set "kmsParties.awsKms.recipientAttestationImageSHA384=${old_pcr0}")

    IFS=',' read -ra UPGRADED_IDS <<< "${upgraded_parties_csv}"
    local override_idx=0
    for party_id in "${UPGRADED_IDS[@]}"; do
        party_id=$(echo "${party_id}" | tr -d ' ')
        OVERRIDE_ARGS+=(
            --set "kmsParties.partyOverrides[${override_idx}].partyIndex=${party_id}"
            --set "kmsParties.partyOverrides[${override_idx}].awsKms.recipientAttestationImageSHA384=${new_pcr0}"
        )
        override_idx=$((override_idx + 1))
    done

    log_info "Running helm upgrade for tkms-infra with ${#UPGRADED_IDS[@]} party overrides..."
    helm upgrade --install tkms-infra \
        oci://hub.zama.org/ghcr/zama-zws/crossplane/tkms-infra \
        --namespace "${NAMESPACE}" \
        --version "${TKMS_INFRA_VERSION}" \
        --values "${VALUES_FILE}" \
        "${OVERRIDE_ARGS[@]}" \
        --wait

    # Wait for Crossplane to reconcile the key policy changes
    log_info "Waiting for Crossplane to reconcile KMS key policy changes..."
    wait_kms_key_policy_ready "${upgraded_parties_csv}"
}

#=============================================================================
# Wait for KMS Key Policy Updates
# After updating recipientAttestationImageSHA384, Crossplane needs to
# reconcile and update the actual AWS KMS key policy.
#=============================================================================
wait_kms_key_policy_ready() {
    local upgraded_parties_csv="$1"

    local party_prefix="kms-party-${NAMESPACE}"
    if [[ "${TARGET}" == "aws-perf" ]]; then
        set_path_suffix
        party_prefix="kms-party-${PATH_SUFFIX}"
    fi

    IFS=',' read -ra UPGRADED_IDS <<< "${upgraded_parties_csv}"
    log_info "Waiting for ${#UPGRADED_IDS[@]} KMS party resources to reconcile..."

    for party_id in "${UPGRADED_IDS[@]}"; do
        party_id=$(echo "${party_id}" | tr -d ' ')
        local resource_name="${party_prefix}-${party_id}"
        log_info "Waiting for Kmsparties/${resource_name} to become ready..."
        kubectl wait --for=condition=ready Kmsparties "${resource_name}" \
            -n "${NAMESPACE}" --timeout=300s || {
                log_warn "Timeout waiting for ${resource_name}, checking status..."
                kubectl get Kmsparties "${resource_name}" -n "${NAMESPACE}" -o yaml || true
            }
    done

    log_info "KMS key policy reconciliation complete"
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

        # kind-ci: build a dockerconfigjson secret for hub.zama.org.
        # Both vars are needed; guarding only the token would let an unset
        # HARBOR_READ_LOGIN abort the script under `set -u` a few lines down.
        if [[ -z "${HARBOR_READ_LOGIN:-}" || -z "${HARBOR_READ_TOKEN:-}" ]]; then
            log_warn "HARBOR_READ_LOGIN/HARBOR_READ_TOKEN not both set, skipping registry credentials setup"
            log_warn "Set HARBOR_READ_LOGIN and HARBOR_READ_TOKEN to enable private image pulls"
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
    "hub.zama.org": {
      "auth": "$(echo -n "${HARBOR_READ_LOGIN}:${HARBOR_READ_TOKEN}" | ${base64_cmd})"
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
        oci://hub.zama.org/ghcr/zama-zws/helm-charts/sync-secrets \
        --namespace "${NAMESPACE}" \
        --version "${SYNC_SECRETS_VERSION}" \
        --values "${registry_values_path}" \
        --create-namespace \
        --wait
}

#!/usr/bin/env bash

#=============================================================================
# KMS Deployment
# Functions for deploying KMS Core services
#=============================================================================

#=============================================================================
# Helm Upgrade with Version
# Helper function to conditionally include version args
#=============================================================================
helm_upgrade_with_version() {
    local release_name="$1"
    local chart_location="$2"
    shift 2

    # Remaining args are passed to helm
    local remaining_args=("$@")

    if [[ "${#helm_version_args[@]}" -gt 0 ]]; then
        helm upgrade --install "${release_name}" \
            "${chart_location}" \
            "${helm_version_args[@]}" \
            "${remaining_args[@]}"
    else
        helm upgrade --install "${release_name}" \
            "${chart_location}" \
            "${remaining_args[@]}"
    fi
}

#=============================================================================
# Deploy KMS
# Main deployment function for KMS Core services
#=============================================================================
deploy_kms() {
    log_info "Deploying KMS Core..."

    # Determine if this is a performance testing deployment
    local is_performance_testing=false
    if [[ "${TARGET}" == "aws-perf" ]]; then
        is_performance_testing=true
        set_path_suffix
    fi

    #=========================================================================
    # STEP 1: Determine base values file
    #=========================================================================
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
        BASE_VALUES="${REPO_ROOT}/ci/pr-preview/${DEPLOYMENT_TYPE}/kms-service/values-kms-ci.yaml"
    fi

    #=========================================================================
    # STEP 2: Configure Helm chart location and version
    #=========================================================================
    local helm_chart_location="${REPO_ROOT}/charts/kms-core"
    local helm_version_args=()
    local performance_values_dir=""

    if [[ "${is_performance_testing}" == "true" ]]; then
        performance_values_dir="${REPO_ROOT}/ci/perf-testing/${DEPLOYMENT_TYPE}/kms-ci/kms-service"
        # Use OCI chart if a specific version is requested
        if [[ "${KMS_CHART_VERSION}" != "repository" ]]; then
            helm_chart_location="oci://ghcr.io/zama-ai/kms/charts/kms-core"
            helm_version_args=(--version "${KMS_CHART_VERSION}")
        fi
    fi

    #=========================================================================
    # STEP 3: Generate Peers Configuration
    #=========================================================================
    local PEERS_VALUES="/tmp/kms-peers-values-${NAMESPACE}.yaml"
    if [[ "${DEPLOYMENT_TYPE}" == *"threshold"* ]]; then
        generate_peers_config "${PEERS_VALUES}"
    else
        # Centralized mode: single party
        echo "kmsPeers: { count: 1 }" > "${PEERS_VALUES}"
    fi

    #=========================================================================
    # STEP 4: Generate Dynamic Overrides
    # (Image names, tolerations, enclave settings, etc.)
    #=========================================================================
    local OVERRIDE_VALUES="/tmp/kms-values-override-${NAMESPACE}.yaml"
    generate_helm_overrides "${OVERRIDE_VALUES}"

    #=========================================================================
    # STEP 5: Deploy KMS Core Services
    #=========================================================================
    if [[ "${DEPLOYMENT_TYPE}" == *"threshold"* ]]; then
        deploy_threshold_mode "${BASE_VALUES}" "${PEERS_VALUES}" "${OVERRIDE_VALUES}" \
            "${helm_chart_location}" "${LOCAL_VALUES_USED}" "${is_performance_testing}" \
            "${performance_values_dir}"
    else
        deploy_centralized_mode "${BASE_VALUES}" "${OVERRIDE_VALUES}" \
            "${helm_chart_location}" "${is_performance_testing}" "${performance_values_dir}"
    fi
}

#=============================================================================
# Deploy Threshold Mode
#=============================================================================
deploy_threshold_mode() {
    local BASE_VALUES="$1"
    local PEERS_VALUES="$2"
    local OVERRIDE_VALUES="$3"
    local helm_chart_location="$4"
    local LOCAL_VALUES_USED="$5"
    local is_performance_testing="$6"
    local performance_values_dir="$7"

    log_info "Deploying KMS Core in threshold mode with ${NUM_PARTIES} parties..."

    # Set threshold value based on party count
    local threshold_value="1"
    if [[ "${NUM_PARTIES}" -ge 13 ]]; then
        threshold_value="4"
    fi

    local wait_args=(--wait --wait-for-jobs --timeout=1200s)

    # Deploy each party in parallel
    for i in $(seq 1 "${NUM_PARTIES}"); do
        log_info "Deploying Party ${i}/${NUM_PARTIES}..."

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
            --set kmsCore.thresholdMode.thresholdValue="${threshold_value}"
        )

        # Performance testing specific overrides
        if [[ "${is_performance_testing}" == "true" ]]; then
            HELM_ARGS+=(
                --values "${performance_values_dir}/values-${PATH_SUFFIX}.yaml"
                --set kmsCore.serviceAccountName="${NAMESPACE}-${i}"
                --set kmsCore.envFrom.configmap.name="${NAMESPACE}-${i}"
                --set kmsCore.image.tag="${KMS_CORE_TAG}"
            )
            # Add TLS/PCR settings for enclave deployments
            if [[ "${DEPLOYMENT_TYPE}" == "thresholdWithEnclave" ]]; then
                HELM_ARGS+=(
                    --set kmsCore.thresholdMode.tls.enabled="${TLS}"
                    --set kmsCore.thresholdMode.tls.trustedReleases[0].pcr0="${PCR0:-}"
                    --set kmsCore.thresholdMode.tls.trustedReleases[0].pcr1="${PCR1:-}"
                    --set kmsCore.thresholdMode.tls.trustedReleases[0].pcr2="${PCR2:-}"
                )
            fi
        fi

        # AWS-CI specific: Service account and configmap references
        if [[ "${TARGET}" == "aws-ci" ]]; then
            HELM_ARGS+=(
                --set kmsCore.serviceAccountName="${NAMESPACE}-${i}"
                --set kmsCore.envFrom.configmap.name="${NAMESPACE}-${i}"
            )
        fi

        # Local development: Resource optimization
        if [[ "${TARGET}" == "kind-local" ]]; then
            if [[ "${LOCAL_VALUES_USED}" != "true" ]]; then
                HELM_ARGS+=("--values" "${REPO_ROOT}/ci/values/overrides/dev-minimal.yaml")
            fi

            # Apply user-specific overrides if available
            if [[ -f "${REPO_ROOT}/ci/values/overrides/user.yaml" ]]; then
                log_info "Applying user overrides from user.yaml"
                HELM_ARGS+=("--values" "${REPO_ROOT}/ci/values/overrides/user.yaml")
            fi
        fi

        # Deploy party in background for parallel execution
        helm_upgrade_with_version "kms-core-${i}" "${helm_chart_location}" \
            "${HELM_ARGS[@]}" \
            "${wait_args[@]}" &
    done

    # Wait for all party deployments to complete
    log_info "Waiting for all ${NUM_PARTIES} party deployments to complete..."
    wait

    # AWS-CI: Explicitly wait for pod readiness
    if [[ "${TARGET}" == "aws-ci" ]]; then
        log_info "Waiting for all KMS Core pods to be ready..."
        sleep 60  # Allow time for pods to start
        for i in $(seq 1 "${NUM_PARTIES}"); do
            log_info "Waiting for party ${i} pod..."
            kubectl wait --for=condition=ready pod "kms-core-${i}-core-${i}" \
                -n "${NAMESPACE}" --timeout=600s
        done
    fi

    #=========================================================================
    # STEP 6: Deploy Initialization Job
    #=========================================================================
    if [[ "${is_performance_testing}" == "true" ]]; then
        log_info "Deploying KMS Core initialization job (performance testing)..."
        helm_upgrade_with_version kms-core-init "${helm_chart_location}" \
            --namespace "${NAMESPACE}" \
            --values "${performance_values_dir}/values-kms-service-init-${PATH_SUFFIX}.yaml" \
            --set kmsCoreClient.image.tag="${KMS_CLIENT_TAG}" \
            --set kmsCore.image.tag="${KMS_CORE_TAG}" \
            --wait \
            --wait-for-jobs \
            --timeout=1200s
    else
        deploy_init_job "${BASE_VALUES}" "${PEERS_VALUES}" "${OVERRIDE_VALUES}"
    fi
}

#=============================================================================
# Deploy Centralized Mode
#=============================================================================
deploy_centralized_mode() {
    local BASE_VALUES="$1"
    local OVERRIDE_VALUES="$2"
    local helm_chart_location="$3"
    local is_performance_testing="$4"
    local performance_values_dir="$5"

    log_info "Deploying KMS Core in centralized mode..."

    # Configure wait behavior based on target
    local wait_args=()
    if [[ "${TARGET}" != "aws-ci" ]]; then
        wait_args=(--wait)
    fi

    local HELM_ARGS=(
        --namespace "${NAMESPACE}"
        --values "${BASE_VALUES}"
        --values "${OVERRIDE_VALUES}"
        --set kmsPeers.id="1"
        --set kmsCore.thresholdMode.enabled=false
        --set kmsCoreClient.image.tag="${KMS_CLIENT_TAG}"
        --set kmsCoreClient.nameOverride="kms-core-client"
    )

    # Performance testing specific overrides
    if [[ "${is_performance_testing}" == "true" ]]; then
        HELM_ARGS+=(
            --values "${performance_values_dir}/values-${PATH_SUFFIX}.yaml"
            --set kmsCore.image.tag="${KMS_CORE_TAG}"
        )
    fi

    # AWS-specific: Configure service account and configmap references
    if [[ "${TARGET}" == "aws-ci" ]]; then
        HELM_ARGS+=(
            --set kmsCore.serviceAccountName="${NAMESPACE}-1"
            --set kmsCore.envFrom.configmap.name="${NAMESPACE}-1"
        )
    fi

    helm_upgrade_with_version kms-core "${helm_chart_location}" \
        "${HELM_ARGS[@]}" \
        "${wait_args[@]}"

    # Wait for centralized pod readiness (AWS only)
    if [[ "${TARGET}" == "aws-ci" ]]; then
        log_info "Waiting for KMS Core pod to be ready..."
        sleep 60
        kubectl wait --for=condition=ready pod kms-core-core-1 \
            -n "${NAMESPACE}" --timeout=600s
    fi
}

#=============================================================================
# Generate Helm Overrides
#=============================================================================
generate_helm_overrides() {
    local output_file="$1"
    log_info "Generating Helm overrides to ${output_file}"

    #=========================================================================
    # Initialize default values
    #=========================================================================
    local IS_ENCLAVE="false"
    local KMS_IMAGE_NAME="${KMS_CORE_IMAGE_NAME}"
    local KMS_CLIENT_IMAGE_NAME_LOCAL="${KMS_CORE_CLIENT_IMAGE_NAME}"
    local GEN_KEYS="false"
    local TOLERATION_KEY="karpenter.sh/nodepool"
    local TOLERATION_VALUE="kms-bench-spot-64"
    local INCLUDE_TOLERATIONS="false"
    local TLS_ENABLED="false"
    local NUM_MAJORITY="1"
    local NUM_RECONSTRUCT="1"

    #=========================================================================
    # Configure enclave-specific settings
    #=========================================================================
    if [[ "${DEPLOYMENT_TYPE}" == *"Enclave"* ]]; then
         IS_ENCLAVE="true"
         KMS_IMAGE_NAME="ghcr.io/zama-ai/kms/core-service-enclave"
         GEN_KEYS="true"              # Enable key generation for enclave
         TOLERATION_KEY="app"         # Enclave uses app-based taints
         TOLERATION_VALUE="${NAMESPACE}"
         TLS_ENABLED="true"           # TLS required for enclave communication
    fi

    #=========================================================================
    # Configure target-specific settings
    #=========================================================================
    if [[ "${TARGET}" == "aws-ci" ]]; then
        INCLUDE_TOLERATIONS="true"
    fi

    #=========================================================================
    # Set threshold parameters based on party count
    #=========================================================================
    if [[ "${DEPLOYMENT_TYPE}" == *"threshold"* ]]; then
        if [[ "${NUM_PARTIES}" -ge 13 ]]; then
            # Large deployment (13+ parties): Higher thresholds
            NUM_MAJORITY="5"
            NUM_RECONSTRUCT="9"
        else
            # Standard deployment (4 parties): Default thresholds
            NUM_MAJORITY="2"
            NUM_RECONSTRUCT="3"
        fi
    fi

    #=========================================================================
    # Generate values file
    #=========================================================================

    # Core service configuration
    cat <<EOF > "${output_file}"
# Auto-generated Helm overrides for ${DEPLOYMENT_TYPE} deployment
# Generated by: deploy_unified.sh
# Target: ${TARGET}
# Namespace: ${NAMESPACE}

kmsCore:
  image:
    name: "${KMS_IMAGE_NAME}"
    tag: "${KMS_CORE_TAG}"
EOF

    # AWS-CI: Add service account and configmap references
    if [[ "${TARGET}" == "aws-ci" ]]; then
        cat <<EOF >> "${output_file}"
  serviceAccountName: "${NAMESPACE}-1"
  envFrom:
    configmap:
      name: "${NAMESPACE}-1"
EOF
    fi

    # Add pod tolerations for AWS deployments
    if [[ "${INCLUDE_TOLERATIONS}" == "true" ]]; then
        cat <<EOF >> "${output_file}"
  tolerations:
    - key: "${TOLERATION_KEY}"
      effect: "NoSchedule"
      operator: "Equal"
      value: "${TOLERATION_VALUE}"
EOF
    fi

    # Enclave-specific TLS configuration (threshold mode only)
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

    # Client configuration
    cat <<EOF >> "${output_file}"

kmsCoreClient:
  image:
    name: "${KMS_CLIENT_IMAGE_NAME_LOCAL}"
    tag: "${KMS_CLIENT_TAG}"
EOF

    # AWS-CI: Client configmap reference
    if [[ "${TARGET}" == "aws-ci" ]]; then
        cat <<EOF >> "${output_file}"
  envFrom:
    configmap:
      name: "${NAMESPACE}-1"
EOF
    fi

    # Client tolerations for AWS
    if [[ "${INCLUDE_TOLERATIONS}" == "true" ]]; then
        cat <<EOF >> "${output_file}"
  tolerations:
    - key: "karpenter.sh/nodepool"
      effect: "NoSchedule"
      operator: "Equal"
      value: "zws-pool"
EOF
    fi

    # Threshold reconstruction parameters and key generation
    cat <<EOF >> "${output_file}"
  num_majority: ${NUM_MAJORITY}
  num_reconstruct: ${NUM_RECONSTRUCT}

kmsGenCertAndKeys:
  enabled: ${GEN_KEYS}
EOF

    log_info "Generated overrides content:"
    cat "${output_file}"
}

#=============================================================================
# Generate Peers Configuration
# Creates a YAML file listing all KMS parties for peer-to-peer communication
#=============================================================================
generate_peers_config() {
    local output_file="$1"
    log_info "Generating peers config for ${NUM_PARTIES} parties to ${output_file}"

    cat <<EOF > "${output_file}"
kmsCore:
  thresholdMode:
    peersList:
EOF

    # Generate peer entry for each party
    # Service naming: kms-core-${i}-core-${i} (based on Helm release name)
    for i in $(seq 1 "${NUM_PARTIES}"); do
        cat <<EOF >> "${output_file}"
      - id: ${i}
        host: kms-core-${i}-core-${i}
        port: 50001
EOF
    done

    log_info "Generated peers configuration for ${NUM_PARTIES} parties"
}

#=============================================================================
# Deploy Initialization Job
# This job performs initial key generation and configuration
#=============================================================================
deploy_init_job() {
    local base_values="$1"
    local peers_values="$2"
    local override_values="$3"

    # Set threshold value based on party count
    local threshold_value="1"
    if [[ "${NUM_PARTIES}" -ge 13 ]]; then
        threshold_value="4"
    fi

    #-------------------------------------------------------------------------
    # Determine init values file location
    #-------------------------------------------------------------------------
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

    #-------------------------------------------------------------------------
    # Build Helm arguments
    #-------------------------------------------------------------------------
    log_info "Deploying initialization job..."

    local HELM_ARGS=(
        --namespace "${NAMESPACE}"
        --values "${INIT_VALUES}"
        --values "${peers_values}"
        --values "${override_values}"
        --wait
        --wait-for-jobs
        --timeout=1200s
    )

    # Local development: Apply resource optimizations
    if [[ "${TARGET}" == "kind-local" ]]; then
        if [[ "${LOCAL_VALUES_USED}" != "true" ]]; then
            HELM_ARGS+=("--values" "${REPO_ROOT}/ci/values/overrides/dev-minimal.yaml")
        fi
        if [[ -f "${REPO_ROOT}/ci/values/overrides/user.yaml" ]]; then
             log_info "Applying user-specific overrides"
             HELM_ARGS+=("--values" "${REPO_ROOT}/ci/values/overrides/user.yaml")
        fi
    fi

    #-------------------------------------------------------------------------
    # Deploy and wait for completion
    #-------------------------------------------------------------------------
    log_info "Installing kms-core-init job..."
    helm upgrade --install kms-core-init \
        "${REPO_ROOT}/charts/kms-core" \
        "${HELM_ARGS[@]}"

    log_info "Waiting for initialization job to complete (may take several minutes)..."
    sleep 30  # Allow time for job to be created

    kubectl wait --for=condition=complete job -l app=kms-threshold-init-job \
        -n "${NAMESPACE}" --timeout=600s || {
            log_error "KMS initialization job did not complete within 10 minutes"
            log_error "Checking job status..."
            kubectl get jobs -n "${NAMESPACE}" -l app=kms-threshold-init-job || true
            kubectl describe jobs -n "${NAMESPACE}" -l app=kms-threshold-init-job || true
            exit 1
        }

    log_info "Initialization job completed successfully"
}

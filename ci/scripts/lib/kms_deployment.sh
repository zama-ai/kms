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
#
# Naming Convention:
# ------------------
# For threshold mode, each party is deployed as a separate Helm release:
#   - Release name:     kms-core-${party_id}
#   - StatefulSet name: kms-core-${party_id}-core (via kmsCoreName helper)
#   - Pod name:         kms-core-${party_id}-core-${party_id}
#
# The pod name pattern is used for TLS certificate generation and must match
# the actual pod names created by Kubernetes. The pattern can be customized
# by setting HELM_RELEASE_PREFIX (defaults to "kms-core").
#=============================================================================
deploy_kms() {
    log_info "Deploying KMS Core..."

    # Determine if this is a performance testing deployment
    local is_performance_testing=false
    if [[ "${TARGET}" == "aws-perf" ]]; then
        is_performance_testing=true
        set_path_suffix
    fi

    # Set Helm release prefix (can be overridden via environment variable)
    export HELM_RELEASE_PREFIX="${HELM_RELEASE_PREFIX:-kms-core}"

    #=========================================================================
    # STEP 1: Determine base values file
    #=========================================================================
    local BASE_VALUES=""
    local LOCAL_VALUES_USED="false"
    local USE_BASE_VALUES="true"

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
    elif [[ "${TARGET}" == "aws-perf" ]]; then
        # For performance testing, skip BASE_VALUES - performance values are comprehensive
        USE_BASE_VALUES="false"
    else
        # For aws-ci (PR previews), use pr-preview values
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
    # STEP 3: Enable TLS by Default for Threshold Mode
    #=========================================================================
    # For threshold deployments (with or without enclave), enable TLS by default
    # TLS can be explicitly disabled with --disable-tls if needed
    # For centralized deployments, TLS is disabled by default
    # Also respect TLS env var from GitHub workflow (for backward compatibility)
    log_info "DEBUG: TLS env var='${TLS:-<unset>}', ENABLE_TLS='${ENABLE_TLS:-<unset>}', DEPLOYMENT_TYPE='${DEPLOYMENT_TYPE}'"
    if [[ -n "${TLS:-}" ]]; then
        export ENABLE_TLS="${TLS}"
        log_info "TLS for ${DEPLOYMENT_TYPE} mode: ${ENABLE_TLS} (from TLS env var)"
    elif [[ "${DEPLOYMENT_TYPE}" == *"threshold"* ]]; then
        export ENABLE_TLS="${ENABLE_TLS:-true}"
        log_info "TLS for ${DEPLOYMENT_TYPE} mode: ${ENABLE_TLS} (default: enabled)"
    else
        export ENABLE_TLS="${ENABLE_TLS:-false}"
        log_info "TLS for ${DEPLOYMENT_TYPE} mode: ${ENABLE_TLS} (default: disabled)"
    fi
    log_info "DEBUG: Final ENABLE_TLS='${ENABLE_TLS}' (checking if == 'true': $([[ '${ENABLE_TLS}' == 'true' ]] && echo YES || echo NO))"

    #=========================================================================
    # STEP 4: Generate Peers Configuration
    #=========================================================================
    local PEERS_VALUES="/tmp/kms-peers-values-${NAMESPACE}.yaml"
    if [[ "${DEPLOYMENT_TYPE}" == *"threshold"* ]]; then
        generate_peers_config "${PEERS_VALUES}"
        # Generate and upload TLS certificates for Kind deployments with TLS enabled
        # For AWS deployments, the kms-gen-cert-and-keys Helm job handles this automatically
        if [[ "${ENABLE_TLS}" == "true" && "${TARGET}" == *"kind"* ]]; then
            generate_and_upload_tls_certs
        fi
    else
        # Centralized mode: single party
        echo "kmsPeers: { count: 1 }" > "${PEERS_VALUES}"
    fi

    #=========================================================================
    # STEP 5: Generate Dynamic Overrides
    # (Image names, tolerations, enclave settings, etc.)
    #=========================================================================
    local OVERRIDE_VALUES="/tmp/kms-values-override-${NAMESPACE}.yaml"
    generate_helm_overrides "${OVERRIDE_VALUES}"

    #=========================================================================
    # STEP 6: Deploy KMS Core Services
    #=========================================================================
    if [[ "${DEPLOYMENT_TYPE}" == *"threshold"* ]]; then
        deploy_threshold_mode "${BASE_VALUES}" "${PEERS_VALUES}" "${OVERRIDE_VALUES}" \
            "${helm_chart_location}" "${LOCAL_VALUES_USED}" "${is_performance_testing}" \
            "${performance_values_dir}" "${USE_BASE_VALUES}"
    else
        deploy_centralized_mode "${BASE_VALUES}" "${OVERRIDE_VALUES}" \
            "${helm_chart_location}" "${is_performance_testing}" "${performance_values_dir}" \
            "${USE_BASE_VALUES}"
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
    local USE_BASE_VALUES="${8:-true}"

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
        )

        # Add BASE_VALUES if it should be used
        if [[ "${USE_BASE_VALUES}" == "true" ]]; then
            HELM_ARGS+=(--values "${BASE_VALUES}")
        fi

        HELM_ARGS+=(
            --values "${PEERS_VALUES}"
            --values "${OVERRIDE_VALUES}"
            --set kmsPeers.id="${i}"
            --set kmsCoreClient.image.tag="${KMS_CLIENT_TAG}"
            --set kmsCore.publicVault.s3.prefix="PUB-p${i}"
            --set kmsCore.privateVault.s3.prefix="PRIV-p${i}"
            --set kmsCore.backupVault.s3.prefix="BACKUP-p${i}"
            --set kmsCore.thresholdMode.thresholdValue="${threshold_value}"
        )

        # Enable TLS Helm flag for non-enclave deployments when TLS is enabled
        # Enclave deployments handle TLS separately (see performance testing overrides below)
        if [[ "${ENABLE_TLS}" == "true" && "${DEPLOYMENT_TYPE}" != *"Enclave"* ]]; then
            HELM_ARGS+=(
                --set kmsCore.thresholdMode.tls.enabled=true
            )
            log_info "TLS enabled for threshold mode (target: ${TARGET})"
        fi

        # Performance testing specific overrides
        if [[ "${is_performance_testing}" == "true" ]]; then
            log_info "Performance testing mode - ENABLE_TLS=${ENABLE_TLS}, DEPLOYMENT_TYPE=${DEPLOYMENT_TYPE}"
            HELM_ARGS+=(
                --values "${performance_values_dir}/values-${PATH_SUFFIX}.yaml"
                --set kmsCore.serviceAccountName="${PATH_SUFFIX}-${i}"
                --set kmsCore.envFrom.configmap.name="${PATH_SUFFIX}-${i}"
                --set kmsCore.image.tag="${KMS_CORE_TAG}"
            )
            # Add TLS/PCR settings for threshold deployments with TLS enabled
            if [[ "${DEPLOYMENT_TYPE}" == *"threshold"* && "${ENABLE_TLS}" == "true" ]]; then
                log_info "Adding TLS and kmsGenCertAndKeys settings for party ${i}"
                HELM_ARGS+=(
                    --set kmsCore.thresholdMode.tls.enabled=true
                    --set kmsGenCertAndKeys.enabled=true
                )
                # For enclave deployments, also set PCR values for attestation (if available)
                if [[ "${DEPLOYMENT_TYPE}" == "thresholdWithEnclave" ]]; then
                    # Only override PCR values if they're explicitly set (non-empty)
                    # Otherwise let the values file's hardcoded PCRs be used
                    if [[ -n "${PCR0:-}" && -n "${PCR1:-}" && -n "${PCR2:-}" ]]; then
                        log_info "Using PCR values from environment/image: PCR0=${PCR0:0:16}..."
                        HELM_ARGS+=(
                            --set kmsCore.thresholdMode.tls.trustedReleases[0].pcr0="${PCR0}"
                            --set kmsCore.thresholdMode.tls.trustedReleases[0].pcr1="${PCR1}"
                            --set kmsCore.thresholdMode.tls.trustedReleases[0].pcr2="${PCR2}"
                        )
                    else
                        log_info "PCR values not set - using hardcoded values from values file"
                    fi
                fi
            else
                log_info "TLS condition not met - DEPLOYMENT_TYPE=${DEPLOYMENT_TYPE}, ENABLE_TLS=${ENABLE_TLS}"
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
        local release_name="${HELM_RELEASE_PREFIX}-${i}"
        log_info "=== Deploying Party ${i} - Debug Info ==="
        log_info "Release: ${release_name}"
        log_info "Expected pod name: $(get_party_pod_name "${i}")"
        log_info "Chart: ${helm_chart_location}"
        log_info "Version args: ${helm_version_args[*]:-none}"
        log_info "Wait args: ${wait_args[*]}"
        log_info "Values files used:"
        for arg_idx in "${!HELM_ARGS[@]}"; do
            if [[ "${HELM_ARGS[$arg_idx]}" == "--values" ]]; then
                local values_file="${HELM_ARGS[$((arg_idx + 1))]}"
                log_info "  - ${values_file}"
            fi
        done
        log_info ""
        log_info "Contents of values files:"
        for arg_idx in "${!HELM_ARGS[@]}"; do
            if [[ "${HELM_ARGS[$arg_idx]}" == "--values" ]]; then
                local values_file="${HELM_ARGS[$((arg_idx + 1))]}"
                log_info "--- BEGIN: ${values_file} ---"
                cat "${values_file}"
                log_info "--- END: ${values_file} ---"
                log_info ""
            fi
        done
        log_info "Full helm command:"
        log_info "  helm upgrade --install ${release_name} ${helm_chart_location} ${helm_version_args[*]:-} ${HELM_ARGS[*]} ${wait_args[*]}"
        log_info "========================================="

        helm_upgrade_with_version "${release_name}" "${helm_chart_location}" \
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
            local pod_name="$(get_party_pod_name "${i}")"
            log_info "Waiting for party ${i} pod: ${pod_name}"
            kubectl wait --for=condition=ready pod "${pod_name}" \
                -n "${NAMESPACE}" --timeout=600s
        done
    fi

    #=========================================================================
    # STEP 7: Deploy Initialization Job
    #=========================================================================
    deploy_init_job "${BASE_VALUES}" "${PEERS_VALUES}" "${OVERRIDE_VALUES}" \
        "${helm_chart_location}" "${is_performance_testing}" "${performance_values_dir}"
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
    local USE_BASE_VALUES="${6:-true}"

    log_info "Deploying KMS Core in centralized mode..."

    # Configure wait behavior based on target
    local wait_args=()
    if [[ "${TARGET}" != "aws-ci" ]]; then
        wait_args=(--wait)
    fi

    local HELM_ARGS=(
        --namespace "${NAMESPACE}"
    )

    # Add BASE_VALUES if it should be used
    if [[ "${USE_BASE_VALUES}" == "true" ]]; then
        HELM_ARGS+=(--values "${BASE_VALUES}")
    fi

    HELM_ARGS+=(
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
            --set kmsCore.serviceAccountName="${PATH_SUFFIX}-1"
            --set kmsCore.envFrom.configmap.name="${PATH_SUFFIX}-1"
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
         TOLERATION_KEY="app"         # Enclave uses app-based taints
         # For aws-perf, use PATH_SUFFIX for toleration value; otherwise use NAMESPACE
         if [[ "${TARGET}" == "aws-perf" ]]; then
             TOLERATION_VALUE="${PATH_SUFFIX}"
         else
             TOLERATION_VALUE="${NAMESPACE}"
         fi
         TLS_ENABLED="true"           # TLS required for enclave communication
    fi

    #=========================================================================
    # Enable certificate & key generation for AWS threshold deployments with TLS
    # This applies to both enclave and non-enclave threshold deployments
    # For Kind deployments, certificates are generated locally via scripts
    # For AWS deployments, the kms-gen-cert-and-keys Helm job handles it
    #=========================================================================
    if [[ "${DEPLOYMENT_TYPE}" == *"threshold"* && "${ENABLE_TLS}" == "true" && "${TARGET}" != *"kind"* ]]; then
        GEN_KEYS="true"
        TLS_ENABLED="true"
    fi

    #=========================================================================
    # Configure target-specific settings
    #=========================================================================
    if [[ "${TARGET}" == "aws-ci" || "${TARGET}" == "aws-perf" ]]; then
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
    elif [[ "${TARGET}" == "aws-perf" ]]; then
        cat <<EOF >> "${output_file}"
  serviceAccountName: "${PATH_SUFFIX}-1"
  envFrom:
    configmap:
      name: "${PATH_SUFFIX}-1"
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
    elif [[ "${TARGET}" == "aws-perf" ]]; then
        cat <<EOF >> "${output_file}"
  envFrom:
    configmap:
      name: "${PATH_SUFFIX}-1"
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
    # Service naming: ${RELEASE_NAME}-core-${i} (based on Helm release name)
    for i in $(seq 1 "${NUM_PARTIES}"); do
        local pod_name="$(get_party_pod_name "${i}")"

        cat <<EOF >> "${output_file}"
      - id: ${i}
        host: ${pod_name}
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
    local helm_chart_location="$4"
    local is_performance_testing="${5:-false}"
    local performance_values_dir="$6"

    log_info "Deploying KMS Core initialization job..."

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
    elif [[ "${TARGET}" == "aws-ci" ]]; then
        INIT_VALUES="${REPO_ROOT}/ci/pr-preview/${DEPLOYMENT_TYPE}/kms-service/values-kms-service-init-kms-ci.yaml"
    elif [[ "${TARGET}" == "aws-perf" ]]; then
        INIT_VALUES="${REPO_ROOT}/ci/perf-testing/${DEPLOYMENT_TYPE}/kms-ci/kms-service/values-kms-service-init-${PATH_SUFFIX}-ci.yaml"
    fi

    #-------------------------------------------------------------------------
    # Build Helm arguments
    #-------------------------------------------------------------------------
    log_info "Deploying initialization job for ${TARGET} ..."

    local HELM_ARGS=(
        --namespace "${NAMESPACE}"
        --values "${INIT_VALUES}"
        --values "${peers_values}"
        --values "${override_values}"
        --set kmsGenCertAndKeys.enabled=false # This is set to false to avoid generating cert for init job.
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
    if [[ "${TARGET}" == "aws-perf" ]]; then  # For performance testing, use the helm chart location
        helm upgrade --install kms-core-init "${helm_chart_location}" \
            "${HELM_ARGS[@]}"
    else
        helm upgrade --install kms-core-init \
            "${REPO_ROOT}/charts/kms-core" \
            "${HELM_ARGS[@]}"
    fi

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

#=============================================================================
# Generate Party Name
# Generates the pod name for a given party ID based on Helm naming conventions
# Pattern: ${HELM_RELEASE_PREFIX}-${party_id}-core-${party_id}
# Where HELM_RELEASE_PREFIX defaults to "kms-core"
#=============================================================================
get_party_pod_name() {
    local party_id="$1"
    local release_prefix="${HELM_RELEASE_PREFIX:-kms-core}"
    echo "${release_prefix}-${party_id}-core-${party_id}"
}

#=============================================================================
# TLS Certificate Generation for threshold mode and upload to S3
#=============================================================================
# Generate TLS Certificates
# Generates self-signed CA certificates for each KMS party
#=============================================================================
generate_tls_certs() {
    log_info "Generating TLS certificates for ${NUM_PARTIES} parties..."

    local CERTS_DIR="${REPO_ROOT}/ci/kube-testing/certs"
    mkdir -p "${CERTS_DIR}"

    # Generate CA names for each party
    # These names must match the pod names that will be created by Helm
    local CA_NAMES=""
    for i in $(seq 1 "${NUM_PARTIES}"); do
        if [[ -n "${CA_NAMES}" ]]; then
            CA_NAMES="${CA_NAMES} "
        fi
        CA_NAMES="${CA_NAMES}$(get_party_pod_name "${i}")"
    done

    log_info "Generating certificates for: ${CA_NAMES}"

    # Build and run the certificate generator
    # The kms-gen-tls-certs binary generates self-signed CA certificates
    cargo run --release --bin kms-gen-tls-certs -- \
        --ca-names ${CA_NAMES} \
        --output-dir "${CERTS_DIR}" \
        --wildcard

    ls -al "${CERTS_DIR}/"
    log_info "TLS certificates generated successfully in ${CERTS_DIR}"
}

#=============================================================================
# Upload TLS Certificates to Localstack
# Uploads certificates and keys to localstack S3 (Kind deployments)
#=============================================================================
upload_tls_certs_to_localstack() {
    local CERTS_DIR="${REPO_ROOT}/ci/kube-testing/certs"

    # Wait for localstack to be ready
    log_info "Waiting for localstack to be ready..."
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=localstack \
        -n "${NAMESPACE}" --timeout=5m

    # Get localstack pod name for kubectl exec commands
    local LOCALSTACK_POD
    LOCALSTACK_POD=$(kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/name=localstack \
        -o jsonpath='{.items[0].metadata.name}')
    log_info "Using localstack pod: ${LOCALSTACK_POD}"

    # Helper function to run awslocal commands in localstack pod
    run_awslocal() {
        kubectl exec -n "${NAMESPACE}" "${LOCALSTACK_POD}" -- \
            awslocal "$@"
    }

    # Ensure buckets exist (localstack startup script should create them, but verify)
    log_info "Ensuring S3 buckets exist..."
    run_awslocal s3 mb s3://kms-public 2>/dev/null || true
    run_awslocal s3 mb s3://kms-private 2>/dev/null || true

    # List buckets to verify
    log_info "Available S3 buckets:"
    run_awslocal s3 ls

    # Upload certificates and private keys to S3 for each party
    log_info "Uploading certificates and keys to localstack S3..."
    for i in $(seq 1 "${NUM_PARTIES}"); do
        local PARTY_NAME="$(get_party_pod_name "${i}")"
        local CERT_FILE="${CERTS_DIR}/cert_${PARTY_NAME}.pem"
        local KEY_FILE="${CERTS_DIR}/key_${PARTY_NAME}.pem"

        if [[ -f "${CERT_FILE}" ]]; then
            # Copy cert to localstack pod, then upload to S3
            log_info "Uploading certificate for party ${i} to s3://kms-public/PUB-p${i}/CACert/cert.pem"
            kubectl cp "${CERT_FILE}" "${NAMESPACE}/${LOCALSTACK_POD}:/tmp/cert_p${i}.pem"
            if run_awslocal s3 cp /tmp/cert_p${i}.pem "s3://kms-public/PUB-p${i}/CACert/cert.pem"; then
                log_info "Successfully uploaded certificate for party ${i}"
            else
                log_error "Failed to upload certificate for party ${i}"
            fi
        else
            log_error "Certificate file not found: ${CERT_FILE}"
        fi

        if [[ -f "${KEY_FILE}" ]]; then
            # Copy key to localstack pod, then upload to S3
            log_info "Uploading private key for party ${i} to s3://kms-public/PUB-p${i}/PrivateKey/key.pem"
            kubectl cp "${KEY_FILE}" "${NAMESPACE}/${LOCALSTACK_POD}:/tmp/key_p${i}.pem"
            if run_awslocal s3 cp /tmp/key_p${i}.pem "s3://kms-public/PUB-p${i}/PrivateKey/key.pem"; then
                log_info "Successfully uploaded private key for party ${i}"
            else
                log_error "Failed to upload private key for party ${i}"
            fi
        else
            log_error "Private key file not found: ${KEY_FILE}"
        fi
    done

    # Also upload the combined certificate
    if [[ -f "${CERTS_DIR}/cert_combined.pem" ]]; then
        kubectl cp "${CERTS_DIR}/cert_combined.pem" "${NAMESPACE}/${LOCALSTACK_POD}:/tmp/cert_combined.pem"
        if run_awslocal s3 cp /tmp/cert_combined.pem "s3://kms-public/certs/cert_combined.pem"; then
            log_info "Successfully uploaded combined certificate"
        else
            log_error "Failed to upload combined certificate"
        fi
    fi

    # Verify uploads by listing the bucket contents
    log_info "Verifying uploaded certificates in localstack S3:"
    run_awslocal s3 ls s3://kms-public/ --recursive

    log_info "TLS certificates uploaded to localstack successfully"
}

#=============================================================================
# Upload TLS Certificates to AWS S3
# Uploads certificates and keys to real AWS S3 buckets (AWS deployments)
#=============================================================================
upload_tls_certs_to_aws_s3() {
    local CERTS_DIR="${REPO_ROOT}/ci/kube-testing/certs"

    # Check if AWS CLI is available
    if ! command -v aws &> /dev/null; then
        log_error "AWS CLI not found. Please install it to upload certificates to S3."
        return 1
    fi

    log_info "Uploading certificates and keys to AWS S3..."

    # Upload certificates and private keys to S3 for each party
    for i in $(seq 1 "${NUM_PARTIES}"); do
        local PARTY_NAME="$(get_party_pod_name "${i}")"
        local CERT_FILE="${CERTS_DIR}/cert_${PARTY_NAME}.pem"
        local KEY_FILE="${CERTS_DIR}/key_${PARTY_NAME}.pem"

        # Get the bucket name from the configmap for this party
        local CONFIGMAP_NAME="${NAMESPACE}-${i}"
        log_info "Reading S3 bucket name from configmap: ${CONFIGMAP_NAME}"

        local PUBLIC_BUCKET
        PUBLIC_BUCKET=$(kubectl get configmap "${CONFIGMAP_NAME}" -n "${NAMESPACE}" \
            -o jsonpath='{.data.KMS_CORE__PUBLIC_VAULT__STORAGE__S3__BUCKET}' 2>/dev/null || echo "")

        if [[ -z "${PUBLIC_BUCKET}" ]]; then
            log_error "Failed to get public bucket name from configmap ${CONFIGMAP_NAME}"
            log_info "Available configmaps in namespace:"
            kubectl get configmap -n "${NAMESPACE}" || true
            continue
        fi

        log_info "Using S3 bucket for party ${i}: ${PUBLIC_BUCKET}"

        # Upload certificate
        if [[ -f "${CERT_FILE}" ]]; then
            log_info "Uploading certificate for party ${i} to s3://${PUBLIC_BUCKET}/PUB-p${i}/CACert/cert.pem"
            if aws s3 cp "${CERT_FILE}" "s3://${PUBLIC_BUCKET}/PUB-p${i}/CACert/cert.pem"; then
                log_info "Successfully uploaded certificate for party ${i}"
            else
                log_error "Failed to upload certificate for party ${i}"
            fi
        else
            log_error "Certificate file not found: ${CERT_FILE}"
        fi

        # Upload private key
        if [[ -f "${KEY_FILE}" ]]; then
            log_info "Uploading private key for party ${i} to s3://${PUBLIC_BUCKET}/PUB-p${i}/PrivateKey/key.pem"
            if aws s3 cp "${KEY_FILE}" "s3://${PUBLIC_BUCKET}/PUB-p${i}/PrivateKey/key.pem"; then
                log_info "Successfully uploaded private key for party ${i}"
            else
                log_error "Failed to upload private key for party ${i}"
            fi
        else
            log_error "Private key file not found: ${KEY_FILE}"
        fi
    done

    # Upload the combined certificate to the first party's bucket
    if [[ -f "${CERTS_DIR}/cert_combined.pem" ]]; then
        local CONFIGMAP_NAME="${NAMESPACE}-1"
        local PUBLIC_BUCKET
        PUBLIC_BUCKET=$(kubectl get configmap "${CONFIGMAP_NAME}" -n "${NAMESPACE}" \
            -o jsonpath='{.data.KMS_CORE__PUBLIC_VAULT__STORAGE__S3__BUCKET}' 2>/dev/null || echo "")

        if [[ -n "${PUBLIC_BUCKET}" ]]; then
            log_info "Uploading combined certificate to s3://${PUBLIC_BUCKET}/certs/cert_combined.pem"
            if aws s3 cp "${CERTS_DIR}/cert_combined.pem" "s3://${PUBLIC_BUCKET}/certs/cert_combined.pem"; then
                log_info "Successfully uploaded combined certificate"
            else
                log_error "Failed to upload combined certificate"
            fi
        fi
    fi

    log_info "TLS certificates uploaded to AWS S3 successfully"
}

#=============================================================================
# Generate and Upload TLS Certificates
# Main function that generates certs and uploads to appropriate storage
#=============================================================================
generate_and_upload_tls_certs() {
    # Step 1: Generate certificates (common for all targets)
    generate_tls_certs

    # Step 2: Upload to appropriate storage based on target
    if [[ "${TARGET}" == *"kind"* ]]; then
        upload_tls_certs_to_localstack
    elif [[ "${TARGET}" == "aws-ci" || "${TARGET}" == "aws-perf" ]]; then
        upload_tls_certs_to_aws_s3
    else
        log_warn "Unknown target ${TARGET}, skipping certificate upload"
    fi
}
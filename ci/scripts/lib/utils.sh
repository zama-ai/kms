#!/usr/bin/env bash

#=============================================================================
# Utility Functions
# Port forwarding, log collection, container building, and other helper functions
#=============================================================================

#=============================================================================
# Container Build and Load
# Build Docker images locally and load them into Kind cluster
#=============================================================================
build_container() {
    log_info "========================================="
    log_info "Building and Loading Docker Images"
    log_info "========================================="

    # Use RUST_IMAGE_VERSION from environment or default
    local RUST_IMAGE_VERSION="${RUST_IMAGE_VERSION:-1.92}"

    #-------------------------------------------------------------------------
    # Build and load core-service
    #-------------------------------------------------------------------------
    log_info "Building container for core-service..."
    docker buildx build -t "ghcr.io/zama-ai/kms/core-service:latest-dev" \
        -f "${REPO_ROOT}/docker/core/service/Dockerfile" \
        --build-arg RUST_IMAGE_VERSION="${RUST_IMAGE_VERSION}" \
        "${REPO_ROOT}/" \
        --load

    log_info "Loading core-service container into Kind cluster '${NAMESPACE}'..."
    kind load docker-image "ghcr.io/zama-ai/kms/core-service:latest-dev" \
        -n "${NAMESPACE}" \
        --nodes "${NAMESPACE}-worker"

    #-------------------------------------------------------------------------
    # Build and load core-client
    #-------------------------------------------------------------------------
    log_info "Building container for core-client..."
    docker buildx build -t "ghcr.io/zama-ai/kms/core-client:latest-dev" \
        -f "${REPO_ROOT}/docker/core-client/Dockerfile" \
        --build-arg RUST_IMAGE_VERSION="${RUST_IMAGE_VERSION}" \
        "${REPO_ROOT}/" \
        --load

    log_info "Loading core-client container into Kind cluster '${NAMESPACE}'..."
    kind load docker-image "ghcr.io/zama-ai/kms/core-client:latest-dev" \
        -n "${NAMESPACE}" \
        --nodes "${NAMESPACE}-worker"

    log_info "========================================="
    log_info "Docker images built and loaded successfully"
    log_info "========================================="
}

#=============================================================================
# Setup Port Forwarding
# Setup local port forwarding for development access
# Only applies to Kind deployments (kind-local, kind-ci)
#=============================================================================
setup_port_forwarding() {
    if [[ "${TARGET}" != *"kind"* ]]; then
        return 0
    fi

    log_info "Setting up port forwarding for local access..."

    # Determine output destination based on DEBUG flag
    local log_dir=""
    local output_redirect="/dev/null 2>&1"
    if [[ "${DEBUG:-false}" == "true" ]]; then
        log_dir="logs/port-forward"
        mkdir -p "${log_dir}"
        log_debug "Port-forward logs will be saved to ${log_dir}/"
        output_redirect=""
    fi

    #-------------------------------------------------------------------------
    # Forward Localstack S3 endpoint
    #-------------------------------------------------------------------------
    log_info "  - Localstack S3: localhost:9000 -> localstack:4566"
    if [[ "${DEBUG:-false}" == "true" ]]; then
        kubectl port-forward -n "${NAMESPACE}" svc/localstack 9000:4566 \
            > "${log_dir}/localstack.log" 2>&1 &
    else
        kubectl port-forward -n "${NAMESPACE}" svc/localstack 9000:4566 \
            > /dev/null 2>&1 &
    fi

    #-------------------------------------------------------------------------
    # Forward KMS Core services
    #-------------------------------------------------------------------------
    if [[ "${DEPLOYMENT_TYPE}" == *"threshold"* ]]; then
        # Threshold: Forward each party on separate ports
        log_info "  Threshold parties:"
        for i in $(seq 1 "${NUM_PARTIES}"); do
            local port=$((50000 + i * 100))
            local svc_name="kms-core-${i}-core-${i}"

            log_info "    - Party ${i}: localhost:${port} -> ${svc_name}:50100"
            if [[ "${DEBUG:-false}" == "true" ]]; then
                kubectl port-forward -n "${NAMESPACE}" \
                    "svc/${svc_name}" \
                    "${port}:50100" > "${log_dir}/kms-core-party-${i}.log" 2>&1 &
            else
                kubectl port-forward -n "${NAMESPACE}" \
                    "svc/${svc_name}" \
                    "${port}:50100" > /dev/null 2>&1 &
            fi
        done
    else
        # Centralized: Single service on standard port
        log_info "  - Centralized: localhost:50100 -> kms-core-core:50100"
        if [[ "${DEBUG:-false}" == "true" ]]; then
            kubectl port-forward -n "${NAMESPACE}" \
                "svc/kms-core-core" \
                "50100:50100" > "${log_dir}/kms-core-centralized.log" 2>&1 &
        else
            kubectl port-forward -n "${NAMESPACE}" \
                "svc/kms-core-core" \
                "50100:50100" > /dev/null 2>&1 &
        fi
    fi

    log_info "Port forwarding established (running in background)"
    if [[ "${DEBUG:-false}" == "true" ]]; then
        log_debug "Monitor port-forward status with: tail -f ${log_dir}/*.log"
    fi
}

#=============================================================================
# Wait Indefinitely
# Keep script running for port forwarding
#=============================================================================
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
# Log Collection
# Collect logs from KMS Core pods for debugging and analysis
# Saves logs to ./logs directory in current working directory
#=============================================================================
collect_logs() {
    log_info "Collecting logs for ${DEPLOYMENT_TYPE} deployment..."
    mkdir -p logs

    if [[ "${DEPLOYMENT_TYPE}" == *"threshold"* ]]; then
        #---------------------------------------------------------------------
        # Threshold mode: Collect logs from all parties
        #---------------------------------------------------------------------
        log_info "Collecting logs from ${NUM_PARTIES} KMS Core parties..."

        for i in $(seq 1 "${NUM_PARTIES}"); do
            # Find pod by label (more reliable than hardcoded names)
            local POD_NAME=$(kubectl get pods -n "${NAMESPACE}" \
                -l "app.kubernetes.io/instance=kms-core-${i},app.kubernetes.io/name=kms-core-service" \
                -o jsonpath="{.items[0].metadata.name}" 2>/dev/null)

            if [[ -n "${POD_NAME}" ]]; then
                log_info "  Collecting logs from party ${i}: ${POD_NAME}"
                kubectl logs "${POD_NAME}" -n "${NAMESPACE}" > "logs/${POD_NAME}.log" 2>&1 || true
            else
                log_warn "  No pod found for party ${i}"
            fi
        done

        log_info "Logs saved to ./logs/"
    else
        #---------------------------------------------------------------------
        # Centralized mode: Single pod
        #---------------------------------------------------------------------
        log_info "Collecting logs from centralized KMS Core..."

        local POD_NAME=$(kubectl get pods -n "${NAMESPACE}" \
            -l "app.kubernetes.io/instance=kms-core" \
            -o jsonpath="{.items[0].metadata.name}" 2>/dev/null)

        if [[ -n "${POD_NAME}" ]]; then
             log_info "  Collecting logs: ${POD_NAME}"
             kubectl logs "${POD_NAME}" -n "${NAMESPACE}" > "logs/${POD_NAME}.log" 2>&1 || true
             log_info "Log saved to ./logs/${POD_NAME}.log"
        else
             log_warn "  No centralized pod found"
        fi
    fi
}

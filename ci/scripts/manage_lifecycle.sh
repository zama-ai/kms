#!/usr/bin/env bash

#=============================================================================
# Manage KMS Kind Setup Lifecycle
#
# This script manages the lifecycle of the KMS setup script:
#   - start: Launch setup in background and wait for completion
#   - stop:  Gracefully stop setup and cleanup resources
#
# Usage:
#   ./manage_lifecycle.sh start
#   ./manage_lifecycle.sh stop <SETUP_PID> <TAIL_PID> [DEPLOYMENT_TYPE] [NUM_PARTIES]
#
#=============================================================================

set -euo pipefail

COMMAND="${1:-}"
SETUP_LOG="setup_kms.log"
# Need to source or infer correct namespace/config if not set
NAMESPACE="${NAMESPACE:-kms-test}"
KUBE_CONFIG="${HOME}/.kube/kind_config_${DEPLOYMENT_TYPE:-threshold}"

#=============================================================================
# Dump Cluster State
# When a pod never becomes Ready, the setup log stops at "helm --wait" and does
# not say why. The cluster does.
#=============================================================================
dump_cluster_state() {
    echo "### Pods in ${NAMESPACE}"
    kubectl get pods --request-timeout=30s -n "${NAMESPACE}" -o wide 2>&1 || true
    echo "### Recent events"
    kubectl get events --request-timeout=30s -n "${NAMESPACE}" --sort-by=.lastTimestamp 2>&1 | tail -n 60 || true
    echo "### Pod descriptions"
    kubectl describe pods --request-timeout=30s -n "${NAMESPACE}" 2>&1 || true
    echo "### Container logs, previous instance first where one exists"
    # kms-core-init-load-env is skipped: it prints the rendered config, TLS private key included.
    for pod in $(kubectl get pods --request-timeout=30s -n "${NAMESPACE}" -o name 2>/dev/null); do
        for container in $(kubectl get "${pod}" --request-timeout=30s -n "${NAMESPACE}" \
            -o jsonpath='{.spec.initContainers[*].name} {.spec.containers[*].name}' 2>/dev/null); do
            [[ "${container}" == "kms-core-init-load-env" ]] && continue
            echo "### ${pod} ${container}"
            kubectl logs "${pod}" --request-timeout=30s -n "${NAMESPACE}" -c "${container}" --previous --tail=100 2>/dev/null || true
            kubectl logs "${pod}" --request-timeout=30s -n "${NAMESPACE}" -c "${container}" --tail=200 2>&1 || true
        done
    done
}

#=============================================================================
# Start Setup
#=============================================================================
start_setup() {
    echo "Starting KMS setup in background..."

    # Build TLS flag if enabled
    local TLS_FLAG=""
    if [[ "${ENABLE_TLS:-false}" == "true" ]]; then
        TLS_FLAG="--enable-tls"
    fi

    # Build metrics flag if enabled (installs kube-prometheus-stack and remote-writes
    # KMS metrics to Grafana Cloud). Grafana Cloud credentials are passed through the
    # environment (GRAFANA_CLOUD_PROM_*) and consumed by deploy.sh, so no extra args.
    local METRICS_FLAG=""
    if [[ "${ENABLE_KIND_METRICS:-false}" == "true" ]]; then
        METRICS_FLAG="--enable-metrics"
    fi

    # Use the new Unified Deploy Script
    # Note: We use --block to ensure it keeps running (for port forwards)
    # We map old args to new args
    ./ci/scripts/deploy.sh \
        --target "kind-ci" \
        --namespace "${NAMESPACE}" \
        --tag "${KMS_CORE_IMAGE_TAG:-latest-dev}" \
        --deployment-type "${DEPLOYMENT_TYPE:-threshold}" \
        --num-parties "${NUM_PARTIES:-4}" \
        --block \
        ${TLS_FLAG} ${METRICS_FLAG} > "${SETUP_LOG}" 2>&1 &

    SETUP_PID=$!

    # Tail the log file in background for real-time output
    tail -f "${SETUP_LOG}" &
    TAIL_PID=$!

    # Save PIDs to files for later retrieval
    echo "${SETUP_PID}" > .setup_pid
    echo "${TAIL_PID}" > .tail_pid

    echo "Setup PID: ${SETUP_PID}"
    echo "Tail PID: ${TAIL_PID}"

    # Wait for setup to complete
    echo "Waiting for KMS setup to complete..."
    # Base 10 min budget; allow extra time when metrics are enabled because the
    # kube-prometheus-stack install runs on the critical path before deploy_kms.
    TIMEOUT=600  # 10 minutes timeout
    if [[ "${ENABLE_KIND_METRICS:-false}" == "true" ]]; then
        TIMEOUT=900  # 15 minutes when kube-prometheus-stack is installed
    fi
    ELAPSED=0

    while [ $ELAPSED -lt $TIMEOUT ]; do
        # deploy.sh prints this when ready in block mode
        if grep -q "Press Ctrl+C to stop port forwarding and exit" "${SETUP_LOG}" 2>/dev/null; then
            echo "KMS setup completed successfully!"
            return 0
        fi

        if ! kill -0 ${SETUP_PID} 2>/dev/null; then
            echo "Setup script terminated unexpectedly!"
            cat "${SETUP_LOG}"
            dump_cluster_state
            return 1
        fi

        sleep 5
        ELAPSED=$((ELAPSED + 5))
    done

    # Timeout reached
    echo "Timeout waiting for KMS setup to complete"
    cat "${SETUP_LOG}"
    dump_cluster_state
    kill -TERM ${SETUP_PID} 2>/dev/null || true
    return 1
}

#=============================================================================
# Stop Setup
#=============================================================================
stop_setup() {
    local SETUP_PID="${2:-}"
    local TAIL_PID="${3:-}"

    # Read PIDs from files if not provided
    if [ -z "${SETUP_PID}" ] && [ -f .setup_pid ]; then
        SETUP_PID=$(cat .setup_pid)
    fi
    if [ -z "${TAIL_PID}" ] && [ -f .tail_pid ]; then
        TAIL_PID=$(cat .tail_pid)
    fi

    echo "Stopping setup script and port-forwards (PID: ${SETUP_PID})..."

    # Stop the tail process first
    if [ -n "${TAIL_PID}" ]; then
        kill ${TAIL_PID} 2>/dev/null || true
    fi

    # Check if setup process still exists
    if [ -z "${SETUP_PID}" ]; then
        echo "No setup PID provided or found"
        return 0
    fi

    echo "Terminating setup process (PID: ${SETUP_PID})..."
    kill -9 ${SETUP_PID} 2>/dev/null || true
    # Also kill any remaining port-forward processes
    echo "Terminating any remaining port-forward processes..."
    pkill -9 -f "kubectl port-forward" || true
    sleep 2

    # Delete cluster (if it was Kind)
    # The config name depends on how deploy sets it up.
    # deploy uses: kind-${NAMESPACE} as context name, and ${NAMESPACE} as cluster name.
    if kind get clusters | grep -q "^${NAMESPACE}$"; then
        echo "Deleting Kind cluster ${NAMESPACE}..."
        kind delete cluster --name "${NAMESPACE}"
    fi

    echo "Setup process terminated"

    # Cleanup PID files
    rm -f .setup_pid .tail_pid
}

#=============================================================================
# Main
#=============================================================================

case "${COMMAND}" in
    start)
        start_setup
        ;;
    stop)
        stop_setup "$@"
        ;;
    *)
        echo "Usage: $0 {start|stop [SETUP_PID] [TAIL_PID]}"
        exit 1
        ;;
esac

#!/usr/bin/env bash

#=============================================================================
# Manage KMS Kind Setup Lifecycle
#
# This script manages the lifecycle of the KMS setup script:
#   - start: Launch setup in background and wait for completion
#   - stop:  Gracefully stop setup and cleanup resources
#
# Usage:
#   ./manage_kind_setup.sh start
#   ./manage_kind_setup.sh stop <SETUP_PID> <TAIL_PID> [DEPLOYMENT_TYPE] [NUM_PARTIES]
#
#=============================================================================

set -euo pipefail

COMMAND="${1:-}"
SETUP_LOG="setup_kms.log"
# Need to source or infer correct namespace/config if not set
NAMESPACE="${NAMESPACE:-kms-test}"
KUBE_CONFIG="${HOME}/.kube/kind_config_${DEPLOYMENT_TYPE:-threshold}"

#=============================================================================
# Start Setup
#=============================================================================
start_setup() {
    echo "Starting KMS setup in background..."

    # Use the new Unified Deploy Script
    # Note: We use --block to ensure it keeps running (for port forwards)
    # We map old args to new args
    ./ci/scripts/deploy_unified.sh \
        --target "kind-ci" \
        --namespace "${NAMESPACE}" \
        --tag "${KMS_CORE_IMAGE_TAG:-latest-dev}" \
        --deployment-type "${DEPLOYMENT_TYPE:-threshold}" \
        --num-parties "${NUM_PARTIES:-4}" \
        --block > "${SETUP_LOG}" 2>&1 &

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
    TIMEOUT=600  # 10 minutes timeout
    ELAPSED=0

    while [ $ELAPSED -lt $TIMEOUT ]; do
        # deploy_unified.sh prints this when ready in block mode
        if grep -q "Press Ctrl+C to stop port forwarding and exit" "${SETUP_LOG}" 2>/dev/null; then
            echo "KMS setup completed successfully!"
            return 0
        fi

        if ! kill -0 ${SETUP_PID} 2>/dev/null; then
            echo "Setup script terminated unexpectedly!"
            cat "${SETUP_LOG}"
            return 1
        fi

        sleep 5
        ELAPSED=$((ELAPSED + 5))
    done

    # Timeout reached
    echo "Timeout waiting for KMS setup to complete"
    cat "${SETUP_LOG}"
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
    # The config name depends on how deploy_unified sets it up.
    # deploy_unified uses: kind-${NAMESPACE} as context name, and ${NAMESPACE} as cluster name.
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

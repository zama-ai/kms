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

#=============================================================================
# Start Setup
#=============================================================================
start_setup() {
    echo "Starting KMS setup in background..."

    # Run setup script in background and capture its PID
    ./ci/kube-testing/scripts/setup_kms_in_kind.sh \
        --namespace "${NAMESPACE}" \
        --kms-core-tag "${KMS_CORE_IMAGE_TAG}" \
        --kms-core-client-tag "${KMS_CORE_CLIENT_IMAGE_TAG}" \
        --deployment-type "${DEPLOYMENT_TYPE}" \
        --num-parties "${NUM_PARTIES}" > "${SETUP_LOG}" 2>&1 &
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

    # Debug: Print environment variables
    echo "Environment variables for log collection:"
    echo "  DEPLOYMENT_TYPE: ${DEPLOYMENT_TYPE:-not set}"
    echo "  NUM_PARTIES: ${NUM_PARTIES:-not set}"
    echo "  NAMESPACE: ${NAMESPACE:-not set}"
    echo "  KUBE_CONFIG: ${KUBE_CONFIG:-not set}"

    # Collect logs based on deployment type
    echo "Collecting logs for ${DEPLOYMENT_TYPE:-unknown} deployment before stopping..."

    # Check if required variables are set
    if [ -z "${DEPLOYMENT_TYPE:-}" ] || [ -z "${NAMESPACE:-}" ] || [ -z "${KUBE_CONFIG:-}" ]; then
        echo "ERROR: Required environment variables not set for log collection"
        echo "Skipping log collection..."
        return 0
    fi

    case "${DEPLOYMENT_TYPE}" in
        threshold)
            if [ -z "${NUM_PARTIES:-}" ]; then
                echo "ERROR: Required environment variable NUM_PARTIES not set for threshold deployment cleanup"
                return 0
            fi

            echo "Collecting logs from ${NUM_PARTIES} KMS Core pods..."
            for i in $(seq 1 "${NUM_PARTIES}"); do
                POD_NAME="kms-service-threshold-${i}-${NAMESPACE}-core-${i}"
                echo "  Checking pod: ${POD_NAME}"

                if kubectl get pod "${POD_NAME}" -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}" &>/dev/null; then
                    echo "  Pod ${POD_NAME} exists, collecting logs..."
                    if kubectl logs "${POD_NAME}" -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}" \
                        > "/tmp/kms-service-threshold-${i}-${NAMESPACE}-core-${i}.log" 2>&1; then
                        echo "  ✓ Collected logs from ${POD_NAME}"
                    else
                        echo "  ✗ Failed to collect logs from ${POD_NAME}"
                    fi
                else
                    echo "  ✗ Pod ${POD_NAME} not found"
                fi
            done
            ;;
        centralized)
            echo "Collecting logs from centralized KMS Core pod..."
            if kubectl get pod kms-core -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}" &>/dev/null; then
                if kubectl logs kms-core -n "${NAMESPACE}" --kubeconfig "${KUBE_CONFIG}" \
                    > "/tmp/kms-core-${NAMESPACE}.log" 2>&1; then
                    echo "  ✓ Collected logs from kms-core"
                else
                    echo "  ✗ Failed to collect logs from kms-core"
                fi
            else
                echo "  ✗ Pod kms-core not found"
            fi
            ;;
        *)
            echo "ERROR: Unknown deployment type: ${DEPLOYMENT_TYPE}"
            ;;
    esac

    echo "Log collection completed"

    echo "Stopping setup script and port-forwards (PID: ${SETUP_PID})..."
    echo "Deployment type: ${DEPLOYMENT_TYPE}, Number of parties: ${NUM_PARTIES}"

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

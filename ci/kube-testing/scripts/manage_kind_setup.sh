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
#   ./manage_kind_setup.sh stop <PID> <TAIL_PID>
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
        --namespace "${NAMESPACE:-kms-test}" \
        --kms-core-tag "${KMS_CORE_IMAGE_TAG:-v0.12.0}" \
        --kms-core-client-tag "${KMS_CORE_CLIENT_IMAGE_TAG:-v0.12.0}" \
        --deployment-type "${DEPLOYMENT_TYPE:-threshold}" \
        --num-parties "${NUM_PARTIES:-4}" > "${SETUP_LOG}" 2>&1 &
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
    
    if kill -0 ${SETUP_PID} 2>/dev/null; then
        echo "Process ${SETUP_PID} is running, sending SIGINT..."
        
        # Send SIGINT to the process
        if kill -INT ${SETUP_PID} 2>/dev/null; then
            echo "Sent SIGINT to process ${SETUP_PID}"
        else
            echo "Failed to send SIGINT, process may have already terminated"
        fi
        
        # Wait for graceful shutdown with timeout
        CLEANUP_TIMEOUT=10
        CLEANUP_ELAPSED=0
        echo "Waiting for cleanup to complete (timeout: ${CLEANUP_TIMEOUT}s)..."
        
        while kill -0 ${SETUP_PID} 2>/dev/null && [ $CLEANUP_ELAPSED -lt $CLEANUP_TIMEOUT ]; do
            sleep 1
            CLEANUP_ELAPSED=$((CLEANUP_ELAPSED + 1))
            if [ $((CLEANUP_ELAPSED % 2)) -eq 0 ]; then
                echo "  Still waiting... (${CLEANUP_ELAPSED}s elapsed)"
            fi
        done
        
        # Force kill if still running
        if kill -0 ${SETUP_PID} 2>/dev/null; then
            echo "Process didn't terminate after ${CLEANUP_TIMEOUT}s, sending SIGKILL..."
            kill -9 ${SETUP_PID} 2>/dev/null || true
            # Also kill any remaining port-forward processes
            pkill -9 -f "kubectl port-forward" || true
            sleep 2
        else
            echo "Process terminated successfully after ${CLEANUP_ELAPSED}s"
        fi
    else
        echo "Setup process already terminated"
    fi
    
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

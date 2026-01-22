#!/usr/bin/env bash

#=============================================================================
# Unified KMS Deployment Script (Modular Version)
#
# Handles deployment to:
#   1. Local Kind Cluster (local development)
#   2. CI Kind Cluster (CI testing)
#   3. AWS Cluster via Tailscale (PR Previews / Staging)
#
# Usage:
#   ./deploy.sh --target [kind-local|kind-ci|aws-ci] [OPTIONS]
#
# This modular version splits functionality across multiple library files
# for better maintainability and organization.
#=============================================================================

set -euo pipefail

#=============================================================================
# Script Location and Library Path
#=============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/lib"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

#=============================================================================
# Default Configuration
#=============================================================================
TARGET="kind-local"
NAMESPACE="kms-test"
DEPLOYMENT_TYPE="threshold"
NUM_PARTIES="4"
KMS_CORE_TAG="latest-dev"
KMS_CLIENT_TAG="latest-dev"
KMS_CORE_IMAGE_NAME="${KMS_CORE_IMAGE_NAME:-ghcr.io/zama-ai/kms/core-service}"
KMS_CORE_CLIENT_IMAGE_NAME="${KMS_CORE_CLIENT_IMAGE_NAME:-ghcr.io/zama-ai/kms/core-client}"
CLEANUP="false"
BUILD_IMAGES="false"

# Perf-testing defaults (can be overridden by env/args)
KMS_CHART_VERSION="${KMS_CHART_VERSION:-repository}"
TKMS_INFRA_VERSION="${TKMS_INFRA_CHART_VERSION:-0.3.2}"
SYNC_SECRETS_VERSION="0.2.1"
PATH_SUFFIX="${PATH_SUFFIX:-kms-ci}"
TLS="${TLS:-false}"

# AWS/Tailscale Defaults
TAILSCALE_HOSTNAME="tailscale-operator-zws-dev.diplodocus-boa.ts.net"

#=============================================================================
# Load Library Modules
#=============================================================================
# shellcheck source=lib/common.sh
source "${LIB_DIR}/common.sh"

# shellcheck source=lib/context.sh
source "${LIB_DIR}/context.sh"

# shellcheck source=lib/infrastructure.sh
source "${LIB_DIR}/infrastructure.sh"

# shellcheck source=lib/kms_deployment.sh
source "${LIB_DIR}/kms_deployment.sh"

# shellcheck source=lib/utils.sh
source "${LIB_DIR}/utils.sh"

#=============================================================================
# Main Execution Flow
#=============================================================================
main() {
    #=========================================================================
    # Parse command line arguments
    #=========================================================================
    parse_args "$@"

    #=========================================================================
    # Special Mode: Log Collection Only
    #=========================================================================
    if [[ "${COLLECT_LOGS:-false}" == "true" ]]; then
        log_info "Running in log collection mode..."
        # Setup minimal context for log collection
        if [[ "${TARGET}" == *"kind"* ]]; then
             kubectl config use-context "kind-${NAMESPACE}" || true
        fi
        collect_logs
        exit 0
    fi

    #=========================================================================
    # Local Development: Interactive Resource Configuration
    #=========================================================================
    if [[ "${TARGET}" == "kind-local" ]]; then
        check_local_resources
    fi

    #=========================================================================
    # Display Deployment Configuration
    #=========================================================================
    log_info "========================================="
    log_info "KMS Deployment Starting"
    log_info "========================================="
    log_info "Target:          ${TARGET}"
    log_info "Namespace:       ${NAMESPACE}"
    log_info "Deployment Type: ${DEPLOYMENT_TYPE}"
    log_info "Parties:         ${NUM_PARTIES}"
    log_info "Core Tag:        ${KMS_CORE_TAG}"
    log_info "Client Tag:      ${KMS_CLIENT_TAG}"
    log_info "========================================="

    #=========================================================================
    # Deployment Phases
    #=========================================================================
    setup_context          # Phase 1: Setup Kubernetes context
    setup_infrastructure   # Phase 2: Deploy infrastructure (LocalStack/TKMS)

    # Phase 3: Build images if requested (Kind only)
    if [[ "${BUILD_IMAGES}" == "true" ]] && [[ "${TARGET}" == *"kind"* ]]; then
        log_warn "Image building requested but not yet implemented in unified script"
        log_warn "Please build images separately before running deployment"
    fi

    deploy_kms              # Phase 4: Deploy KMS core services
    setup_port_forwarding   # Phase 5: Setup local port forwarding (Kind only)

    #=========================================================================
    # Deployment Complete
    #=========================================================================
    log_info "========================================="
    log_info "Deployment Complete!"
    log_info "========================================="

    # Optional: Block and maintain port forwarding
    if [[ "${BLOCK:-false}" == "true" ]]; then
        wait_indefinitely
    fi
}

#=============================================================================
# Execute Main
#=============================================================================
main "$@"

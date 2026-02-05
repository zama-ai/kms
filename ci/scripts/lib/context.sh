#!/usr/bin/env bash

#=============================================================================
# Kubernetes Context Management
# Functions for setting up and configuring Kubernetes contexts
#=============================================================================

#=============================================================================
# Setup Kubernetes Context
# Configure Kubernetes context based on deployment target
# - Kind: Create/use local cluster
# - AWS: Configure Tailscale access to remote cluster
#=============================================================================
setup_context() {
    log_info "Setting up Kubernetes context for target: ${TARGET}"

    case "${TARGET}" in
        kind-local|kind-ci)
            setup_kind_cluster
            ;;
        aws-ci|aws-perf)
            setup_aws_context
            ;;
        *)
            log_error "Invalid target: ${TARGET}. Must be one of: kind-local, kind-ci, aws-ci, aws-perf"
            exit 1
            ;;
    esac
}

#=============================================================================
# Setup Kind Cluster
#=============================================================================
setup_kind_cluster() {
    local cluster_name="${NAMESPACE}"

    if kind get clusters | grep -q "^${cluster_name}$"; then
        log_info "Kind cluster '${cluster_name}' already exists"
        if [[ "${CLEANUP}" == "true" ]]; then
            log_info "Deleting existing cluster..."
            kind delete cluster --name "${cluster_name}"
            create_new_kind_cluster "${cluster_name}"
        fi
    else
        create_new_kind_cluster "${cluster_name}"
    fi

    kubectl config use-context "kind-${cluster_name}"
}

#=============================================================================
# Create New Kind Cluster
#=============================================================================
create_new_kind_cluster() {
    local name="$1"
    log_info "Creating Kind cluster: ${name}"
    kind create cluster --name "${name}" --config - <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
EOF
}

#=============================================================================
# Setup AWS Context
#=============================================================================
setup_aws_context() {
    # Assumes tailscale is available in environment
    log_info "Configuring kubeconfig via Tailscale..."
    tailscale configure kubeconfig "${TAILSCALE_HOSTNAME}"

    # Check/Create Namespace
    if kubectl get namespace "${NAMESPACE}" > /dev/null 2>&1; then
        if [[ "${CLEANUP}" == "true" ]]; then
             log_info "Destroying namespace ${NAMESPACE}..."
             kubectl delete namespace "${NAMESPACE}" --wait=true

             # Wait for namespace to be fully deleted
             log_info "Waiting for namespace deletion to complete..."
             local max_wait=120  # 2 minutes timeout
             local elapsed=0
             while kubectl get namespace "${NAMESPACE}" > /dev/null 2>&1; do
                 if [[ $elapsed -ge $max_wait ]]; then
                     log_error "Timeout waiting for namespace deletion after ${max_wait}s"
                     log_info "Namespace may be stuck in Terminating state. Check for finalizers:"
                     kubectl get namespace "${NAMESPACE}" -o yaml | grep -A5 finalizers || true
                     return 1
                 fi
                 sleep 2
                 elapsed=$((elapsed + 2))
             done

             log_info "Namespace deleted. Creating fresh namespace ${NAMESPACE}..."
             kubectl create namespace "${NAMESPACE}"

             # Verify namespace is ready (not terminating)
             local status
             status=$(kubectl get namespace "${NAMESPACE}" -o jsonpath='{.status.phase}')
             if [[ "${status}" != "Active" ]]; then
                 log_warn "Namespace created but status is: ${status}"
             else
                 log_info "Namespace ${NAMESPACE} is active and ready"
             fi
        else
            log_info "Namespace ${NAMESPACE} exists."
        fi
    else
        log_info "Creating namespace ${NAMESPACE}..."
        kubectl create namespace "${NAMESPACE}"

        # Give namespace a moment to initialize
        sleep 10

        # Verify namespace is ready
        local status
        status=$(kubectl get namespace "${NAMESPACE}" -o jsonpath='{.status.phase}')
        if [[ "${status}" != "Active" ]]; then
            log_warn "Namespace created but status is: ${status}"
        else
            log_info "Namespace ${NAMESPACE} is active and ready"
        fi
    fi
}

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
             while kubectl get namespace "${NAMESPACE}" > /dev/null 2>&1; do
                 sleep 2
             done

             log_info "Creating fresh namespace ${NAMESPACE}..."
             kubectl create namespace "${NAMESPACE}"

             # Wait for namespace to be fully active
             kubectl wait --for=condition=Active namespace/"${NAMESPACE}" --timeout=60s
        else
            log_info "Namespace ${NAMESPACE} exists."
        fi
    else
        log_info "Creating namespace ${NAMESPACE}..."
        kubectl create namespace "${NAMESPACE}"
        kubectl wait --for=condition=Active namespace/"${NAMESPACE}" --timeout=60s
    fi
}

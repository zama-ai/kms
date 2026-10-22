#!/usr/bin/env bash
#=============================================================================
# manual-cluster-facts.sh
#
# Snapshot of everything about the deployment that can change a measurement
# but is NOT in the code: node instance types / zones / kernels, which node
# each party runs on, image tags, the tunnel sidecar's arguments and resources,
# the enclave size, the rendered kms-server.toml (incl. [tuning.env]) and the
# client config. Keep one per run so two runs can be compared for environment
# drift (the August baseline had no such record).
#
# Usage (laptop, kubectl + jq):
#   NS=<namespace> bash manual-cluster-facts.sh                 # to stdout
#   NS=<namespace> OUT=facts.txt bash manual-cluster-facts.sh   # to a file
#=============================================================================

set -uo pipefail
NS="${NS:?set NS=<namespace>}"
OUT="${OUT:-/dev/stdout}"
CLIENT_POD="${CLIENT_POD:-kms-core-client-0}"
PARTY1_STS="${PARTY1_STS:-kms-core-1-core-1}"

command -v kubectl >/dev/null || { echo "kubectl not found" >&2; exit 1; }
command -v jq      >/dev/null || { echo "jq not found" >&2; exit 1; }

section() { printf '\n==== %s ====\n' "$*"; }

{
  echo "cluster facts for ${NS} at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "kubectl context: $(kubectl config current-context 2>/dev/null)"

  section "pods -> nodes"
  kubectl get pods -n "${NS}" -o wide 2>&1

  section "nodes hosting the namespace (instance type, zone, kernel, kubelet)"
  nodes="$(kubectl get pods -n "${NS}" -o jsonpath='{range .items[*]}{.spec.nodeName}{"\n"}{end}' 2>/dev/null | sort -u | grep -v '^$' | tr '\n' ' ')"
  if [ -n "${nodes}" ]; then
    # shellcheck disable=SC2086
    kubectl get nodes ${nodes} -o custom-columns='NAME:.metadata.name,INSTANCE:.metadata.labels.node\.kubernetes\.io/instance-type,ZONE:.metadata.labels.topology\.kubernetes\.io/zone,KERNEL:.status.nodeInfo.kernelVersion,KUBELET:.status.nodeInfo.kubeletVersion,CPU:.status.allocatable.cpu,MEM:.status.allocatable.memory' 2>&1
    section "node load right now (kubectl top, needs metrics-server)"
    # shellcheck disable=SC2086
    kubectl top nodes ${nodes} 2>&1 | head -n 20
  fi

  section "images per statefulset (first = main container)"
  kubectl get sts -n "${NS}" -o jsonpath='{range .items[*]}{.metadata.name}{"  chart="}{.metadata.labels.helm\.sh/chart}{"\n   "}{range .spec.template.spec.containers[*]}{.image}{" "}{end}{"\n   init: "}{range .spec.template.spec.initContainers[*]}{.image}{" "}{end}{"\n"}{end}' 2>&1

  section "tunnel sidecar of ${PARTY1_STS} (args, env, resources)"
  kubectl get sts -n "${NS}" "${PARTY1_STS}" -o json 2>/dev/null \
    | jq '.spec.template.spec | (.initContainers + .containers)[] | select(.name=="enclave-network-tunnel") | {args, env, resources}' 2>&1

  section "main container resources / env of ${PARTY1_STS}"
  kubectl get sts -n "${NS}" "${PARTY1_STS}" -o json 2>/dev/null \
    | jq '.spec.template.spec.containers[0] | {name, resources, env: [.env[]? | select(.value != null) | "\(.name)=\(.value)"]}' 2>&1

  section "rendered config of party 1 (ConfigMap with kms-server.toml)"
  cm=""
  for c in $(kubectl get cm -n "${NS}" -o name 2>/dev/null); do
    if kubectl get "${c}" -n "${NS}" -o jsonpath='{.data.kms-server\.toml}' 2>/dev/null | grep -q num_rayon_threads; then
      cm="${c}"; break
    fi
  done
  if [ -n "${cm}" ]; then
    echo "(${cm})"
    kubectl get "${cm}" -n "${NS}" -o jsonpath='{.data.kms-server\.toml}' 2>&1
    echo
    echo "-- enclave.json --"
    kubectl get "${cm}" -n "${NS}" -o jsonpath='{.data.enclave\.json}' 2>&1
    echo
  else
    echo "no ConfigMap with kms-server.toml found"
  fi

  section "client config (${CLIENT_POD})"
  kubectl exec -n "${NS}" "${CLIENT_POD}" -- cat /app/kms-core-client/config.toml 2>&1 | grep -v '^\s*$' | head -n 80

  section "helm releases"
  if command -v helm >/dev/null; then helm list -n "${NS}" 2>&1; else echo "(helm not installed on this machine)"; fi

  section "recent restarts"
  kubectl get pods -n "${NS}" -o custom-columns='NAME:.metadata.name,RESTARTS:.status.containerStatuses[*].restartCount,STARTED:.status.startTime' 2>&1
} > "${OUT}" 2>&1

[ "${OUT}" != "/dev/stdout" ] && echo "cluster facts written to ${OUT}"
exit 0

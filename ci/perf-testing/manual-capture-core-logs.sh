#!/usr/bin/env bash
#=============================================================================
# manual-capture-core-logs.sh
#
# Companion to manual-dkg-under-load.sh. Streams the logs of all 13 core pods
# into per-party files so you can correlate them (by timestamp) with the DKG /
# decrypt activity driven from inside the client pod.
#
# WHERE TO RUN THIS: on your laptop / a machine with kubectl + Tailscale access
# to the kms-ci cluster (the core-client pod does NOT have kubectl). Start it
# BEFORE launching the load, and stop it (Ctrl-C) when the run is done.
#
#   RUN=<same tag you use for the load> bash manual-capture-core-logs.sh
#
# See ../../manual-13-party-enclave-cluster.md for the full walkthrough.
#=============================================================================

set -euo pipefail

NAMESPACE="${NAMESPACE:-kms-ci-titouantanguy-773}"
NUM_PARTIES="${NUM_PARTIES:-13}"
RUN="${RUN:-dkg-under-load-$(date +%Y%m%d-%H%M%S)}"
# Enclave deploy -> logs come from the enclave-logger sidecar.
# Non-enclave 'threshold' deploy -> use CONTAINER=kms-core.
CONTAINER="${CONTAINER:-kms-core-enclave-logger}"
CLEANUP_TIMEOUT_SECONDS="${CLEANUP_TIMEOUT_SECONDS:-5}"
[[ "${NUM_PARTIES}" =~ ^[1-9][0-9]*$ ]] || { echo "invalid NUM_PARTIES" >&2; exit 1; }
[[ "${CLEANUP_TIMEOUT_SECONDS}" =~ ^[1-9][0-9]*$ ]] || { echo "invalid CLEANUP_TIMEOUT_SECONDS" >&2; exit 1; }
[ "${CLEANUP_TIMEOUT_SECONDS}" -le 10 ] || { echo "cleanup timeout must not exceed 10 seconds" >&2; exit 1; }

say() { echo "[$(date -u +%H:%M:%S)] $*"; }

mkdir -p "${RUN}"
say "streaming ${NUM_PARTIES} core logs (ns=${NAMESPACE}, container=${CONTAINER}) into ./${RUN}/"

pids=()
cleanup() {
  trap - INT TERM EXIT
  [ "${#pids[@]}" -gt 0 ] || return 0
  say "stopping ${#pids[@]} log streamers ..."
  kill -TERM "${pids[@]}" 2>/dev/null || true
  local deadline=$((SECONDS + CLEANUP_TIMEOUT_SECONDS)) alive pid
  while :; do
    alive=0
    for pid in "${pids[@]}"; do
      kill -0 "$pid" 2>/dev/null && alive=1
    done
    [ "$alive" = 1 ] || break
    [ "$SECONDS" -lt "$deadline" ] || break
    sleep 0.1
  done
  for pid in "${pids[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then kill -KILL "$pid" 2>/dev/null || true; fi
    wait "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT
trap 'exit 0' TERM
trap 'exit 130' INT

for i in $(seq 1 "${NUM_PARTIES}"); do
  pod="kms-core-${i}-core-${i}"
  out="${RUN}/core-${i}.log"
  say "  -> ${pod} -> ${out}"
  kubectl logs -f -n "${NAMESPACE}" "${pod}" -c "${CONTAINER}" --timestamps > "${out}" 2>&1 &
  pids+=("$!")
done

say "capturing... press Ctrl-C when the load run is finished."
while :; do
  for index in "${!pids[@]}"; do
    if ! kill -0 "${pids[$index]}" 2>/dev/null; then
      child_status=0
      wait "${pids[$index]}" || child_status=$?
      unset 'pids[index]'
      echo "ERROR: party $((index + 1)) log streamer exited unexpectedly (status $child_status)" >&2
      exit 1
    fi
  done
  sleep 0.2
done

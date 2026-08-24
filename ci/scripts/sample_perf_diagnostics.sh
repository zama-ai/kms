#!/usr/bin/env bash
# Coordinate application-metric, ENA-interface, and pod-placement collection.
# The performance-testing workflow runs this alongside the Argo performance test.
# Output is a directory containing core-metrics.log, pod-placement.tsv, and ENA probe samples
# and lifecycle diagnostics.
set -uo pipefail

namespace="${1:-kms-ci}"
output_dir="${2:-perf-diagnostics}"
mkdir -p "${output_dir}"

child_pids=()
finish() {
  trap - EXIT INT TERM
  for pid in "${child_pids[@]}"; do
    kill "${pid}" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  kubectl logs --request-timeout=30s -n "${namespace}" -l app=ena-probe \
    --prefix --all-containers \
    > "${output_dir}/ena-samples.log" 2>&1 || true
  kubectl logs --request-timeout=30s -n "${namespace}" -l app=ena-probe \
    --prefix --all-containers --previous \
    > "${output_dir}/ena-previous.log" 2>&1 || true
  {
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) final ENA probe descriptions"
    kubectl describe --request-timeout=30s -n "${namespace}" daemonset/ena-probe
    kubectl describe --request-timeout=30s -n "${namespace}" pods -l app=ena-probe
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) final ENA probe events"
    kubectl events --request-timeout=30s -n "${namespace}" \
      --for daemonset/ena-probe --types=Warning,Normal
    kubectl get events --request-timeout=30s -n "${namespace}" \
      --field-selector involvedObject.kind=Pod -o json |
      jq -r '.items[] | select(.involvedObject.name | startswith("ena-probe-")) |
        [.eventTime // .lastTimestamp // .metadata.creationTimestamp,
         .involvedObject.name, .type, .reason, .message] | @tsv'
  } >> "${output_dir}/ena-lifecycle.log" 2>&1 || true
}
trap finish EXIT
trap 'exit 0' INT TERM

{
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) applying ENA probe"
  if kubectl apply --request-timeout=30s -f ci/perf-testing/ena-probe.yml; then
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) ENA probe applied"
  else
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) warning: ENA probe could not be started; continuing"
  fi
} > "${output_dir}/ena-start.log" 2>&1

sample_ena_lifecycle() {
  while true; do
    timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    kubectl get --request-timeout=30s -n "${namespace}" daemonset/ena-probe -o json |
      jq -r --arg timestamp "${timestamp}" '
        [$timestamp, "daemonset", .metadata.creationTimestamp,
         (.status.desiredNumberScheduled // 0), (.status.currentNumberScheduled // 0),
         (.status.numberReady // 0), (.status.numberUnavailable // 0)] | @tsv' || true
    kubectl get --request-timeout=30s -n "${namespace}" pods -l app=ena-probe -o json |
      jq -r --arg timestamp "${timestamp}" '
        .items[] |
        .status.containerStatuses[0] as $container |
        [$timestamp, "pod", .metadata.name, .metadata.creationTimestamp,
         .status.startTime, .spec.nodeName, .status.phase,
         ($container.ready // false), ($container.restartCount // 0),
         ($container.state.running.startedAt // ""),
         ($container.state.waiting.reason // ""),
         ($container.state.terminated.reason // "")] | @tsv' || true
    sleep 10
  done
}

{
  echo "# daemonset: timestamp kind created desired current ready unavailable"
  echo "# pod: timestamp kind pod created started node phase ready restarts container_started waiting_reason terminated_reason"
  sample_ena_lifecycle
} > "${output_dir}/ena-lifecycle.log" 2>&1 &
child_pids+=("$!")

bash ci/scripts/sample_core_metrics.sh "${namespace}" \
  > "${output_dir}/core-metrics.log" 2>&1 &
child_pids+=("$!")
bash ci/scripts/sample_pod_placement.sh "${namespace}" \
  > "${output_dir}/pod-placement.tsv" 2>&1 &
child_pids+=("$!")

wait

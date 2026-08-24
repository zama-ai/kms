#!/usr/bin/env bash
# Coordinate application-metric, ENA-interface, and pod-placement collection.
# The performance-testing workflow runs this alongside the Argo performance test.
# Output is a directory containing core-metrics.log, pod-placement.tsv, ena-start.log, and
# ena-samples.log.
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
}
trap finish EXIT
trap 'exit 0' INT TERM

kubectl apply --request-timeout=30s -f ci/perf-testing/ena-probe.yml \
  > "${output_dir}/ena-start.log" 2>&1 ||
  echo "warning: ENA probe could not be started; continuing" >> "${output_dir}/ena-start.log"

bash ci/scripts/sample_core_metrics.sh "${namespace}" \
  > "${output_dir}/core-metrics.log" 2>&1 &
child_pids+=("$!")
bash ci/scripts/sample_pod_placement.sh "${namespace}" \
  > "${output_dir}/pod-placement.tsv" 2>&1 &
child_pids+=("$!")

wait

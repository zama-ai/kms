#!/usr/bin/env bash
# Scrape selected Prometheus metrics from every KMS core at a fixed interval.
# sample_perf_diagnostics.sh starts this during the performance-testing workflow.
# Output is written to stdout as timestamped sampler status and one metric per line; the
# diagnostics controller stores it in core-metrics.log.
set -uo pipefail

namespace="${1:-kms-ci}"
interval="${2:-5}"
metrics_port="${3:-9646}"
scrape_timeout="${SCRAPE_TIMEOUT:-4}"
tmp_root="$(mktemp -d)"
expected_diagnostics=(
  kms_completed_sessions
  kms_network_debug_events_total
  kms_network_sender_tasks
  kms_tokio_alive_tasks
  kms_tokio_global_queue_depth
  kms_user_decrypt_background_tasks
  kms_user_decrypt_stage_duration_microseconds_total
  kms_user_decrypt_stage_observations_total
)

cleanup() {
  trap - EXIT INT TERM
  jobs -pr | xargs -r kill 2>/dev/null || true
  wait 2>/dev/null || true
  rm -rf "${tmp_root}"
}
trap cleanup EXIT
trap 'exit 0' INT TERM

extract_metrics() {
  local timestamp="$1" pod="$2"
  awk -v ts="${timestamp}" -v pod="${pod}" '
    /^kms_network_debug_events_total([[:space:]]|\{|$)/ ||
    /^kms_(active_sessions|inactive_sessions|completed_sessions|rate_limiter_usage|fhe_key_cache_size|meta_storage_user_decryptions|meta_storage_pub_decryptions|meta_storage_user_decryptions_in_store|meta_storage_pub_decryptions_in_store|network_rx_bytes_total|network_tx_bytes_total|tasks|cpu_load|process_cpu_usage|process_memory_usage|total_cpus|tokio_alive_tasks|tokio_global_queue_depth|user_decrypt_background_tasks|user_decrypt_stage_duration_microseconds_total|user_decrypt_stage_observations_total|network_sender_tasks|network_sender_tasks_spawned_total|network_sender_tasks_completed_total)([[:space:]]|\{|$)/ ||
    /^process_(cpu_seconds_total|threads)([[:space:]]|\{|$)/ ||
    (/^kms_operation_duration_ms_(bucket|sum|count)\{/ && /operation_type="user_decrypt_/) ||
    (/^kms_operations_total\{/ && /operation="user_decrypt_(request|result)"/) ||
    (/^kms_operation_errors_total\{/ && /operation="user_decrypt_(request|result)"/) {
      print ts, pod, $1, $2
    }
  '
}

scrape_pod() {
  local timestamp="$1" pod="$2" pod_ip="$3" output="$4"
  local metrics="" method="" error_file="${output}.error"
  if [[ -n "${pod_ip}" ]]; then
    metrics="$(curl --fail --silent --show-error --connect-timeout "${scrape_timeout}" \
      --max-time "${scrape_timeout}" "http://${pod_ip}:${metrics_port}/metrics" \
      2> "${error_file}")" || metrics=""
    [[ -z "${metrics}" ]] || method="pod-ip"
  fi
  if [[ -z "${metrics}" ]]; then
    metrics="$(kubectl get --request-timeout="${scrape_timeout}s" --raw \
      "/api/v1/namespaces/${namespace}/pods/${pod}:${metrics_port}/proxy/metrics" \
      2> "${error_file}")" || metrics=""
    [[ -z "${metrics}" ]] || method="pod-proxy"
  fi
  if [[ -z "${metrics}" ]]; then
    printf '%s %s scrape_error error="%s"\n' "${timestamp}" "${pod}" \
      "$(tr '\n' ' ' < "${error_file}")" > "${output}"
    return
  fi
  local selected found_names expected missing=""
  selected="$(extract_metrics "${timestamp}" "${pod}" <<< "${metrics}")"
  found_names="$(awk '{ name=$3; sub(/\{.*/, "", name); print name }' <<< "${selected}" | sort -u)"
  for expected in "${expected_diagnostics[@]}"; do
    if ! grep -Fxq "${expected}" <<< "${found_names}"; then
      missing="${missing}${missing:+,}${expected}"
    fi
  done
  {
    printf '%s %s scrape_ok method=%s\n' "${timestamp}" "${pod}" "${method}"
    if [[ -n "${missing}" ]]; then
      printf '%s %s scrape_partial missing=%s\n' "${timestamp}" "${pod}" "${missing}"
    fi
    printf '%s\n' "${selected}"
  } > "${output}"
}

scrape_once() {
  local timestamp pod_output round_dir i
  timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  pod_output="$(kubectl get --request-timeout=10s pods -n "${namespace}" -l app=kms-core \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.podIP}{"\n"}{end}' 2>&1)" || {
      printf '%s sampler_error pod_discovery="%s"\n' "${timestamp}" "${pod_output}"
      return
    }
  local -a pods=() ips=() pids=() outputs=()
  while IFS=$'\t' read -r pod pod_ip; do
    [[ -z "${pod}" ]] || { pods+=("${pod}"); ips+=("${pod_ip}"); }
  done <<< "${pod_output}"
  printf '%s sampler_discovery namespace=%s pods=%d expected=13\n' \
    "${timestamp}" "${namespace}" "${#pods[@]}"
  round_dir="$(mktemp -d "${tmp_root}/round.XXXXXX")"
  for i in "${!pods[@]}"; do
    outputs[i]="${round_dir}/${i}.log"
    scrape_pod "${timestamp}" "${pods[i]}" "${ips[i]}" "${outputs[i]}" &
    pids[i]="$!"
  done
  for i in "${!pids[@]}"; do
    wait "${pids[i]}" || true
    cat "${outputs[i]}"
  done
  rm -rf "${round_dir}"
}

printf '%s sampler_start namespace=%s interval=%ss port=%s\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${namespace}" "${interval}" "${metrics_port}"
while true; do
  scrape_once
  sleep "${interval}"
done

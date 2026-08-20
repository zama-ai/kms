#!/usr/bin/env bash
# Sample KMS application gauges used to diagnose decryption backpressure.
# Scrapes run concurrently so one unhealthy core cannot delay every other core.
set -uo pipefail

NS="${1:-kms-ci}"
INTERVAL="${2:-5}"
METRICS_PORT="${3:-9646}"
MODE="${4:-continuous}"
EXPECTED_PODS="${EXPECTED_PODS:-13}"
SCRAPE_TIMEOUT="${SCRAPE_TIMEOUT:-4}"
KUBECTL_BIN="${KUBECTL_BIN:-kubectl}"
CURL_BIN="${CURL_BIN:-curl}"
EXPECTED_METRICS=9

if [[ "${MODE}" != "continuous" && "${MODE}" != "--once" ]]; then
  echo "usage: $0 [namespace] [interval] [metrics-port] [--once]" >&2
  exit 2
fi

tmp_root="$(mktemp -d)"
cleanup() {
  rm -rf "${tmp_root}"
}
trap cleanup EXIT

single_line() {
  tr '\n' ' ' < "$1" | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//'
}

extract_metrics() {
  local ts="$1"
  local pod="$2"
  awk -v ts="${ts}" -v pod="${pod}" '
    /^kms_(active_sessions|inactive_sessions|rate_limiter_usage|fhe_key_cache_size|meta_storage_user_decryptions|meta_storage_public_decryptions|meta_storage_user_decryptions_in_store|meta_storage_public_decryptions_in_store|tasks)([[:space:]]|\{|$)/ {
      print ts, pod, $1, $2
    }
  '
}

scrape_pod() {
  local ts="$1"
  local pod="$2"
  local pod_ip="$3"
  local output="$4"
  local metrics=""
  local method=""
  local direct_error="${output}.direct-error"
  local proxy_error="${output}.proxy-error"

  if [[ -n "${pod_ip}" ]]; then
    metrics="$(
      "${CURL_BIN}" --fail --silent --show-error \
        --connect-timeout "${SCRAPE_TIMEOUT}" \
        --max-time "${SCRAPE_TIMEOUT}" \
        "http://${pod_ip}:${METRICS_PORT}/metrics" \
        2> "${direct_error}"
    )" || metrics=""
    if [[ -n "${metrics}" ]]; then
      method="pod-ip"
    fi
  fi

  if [[ -z "${metrics}" ]]; then
    metrics="$(
      "${KUBECTL_BIN}" get --request-timeout="${SCRAPE_TIMEOUT}s" --raw \
        "/api/v1/namespaces/${NS}/pods/${pod}:${METRICS_PORT}/proxy/metrics" \
        2> "${proxy_error}"
    )" || metrics=""
    if [[ -n "${metrics}" ]]; then
      method="pod-proxy"
    fi
  fi

  if [[ -z "${metrics}" ]]; then
    printf '%s %s scrape_error direct="%s" proxy="%s"\n' \
      "${ts}" \
      "${pod}" \
      "$(single_line "${direct_error}")" \
      "$(single_line "${proxy_error}")" \
      > "${output}"
    return 1
  fi

  local selected
  selected="$(extract_metrics "${ts}" "${pod}" <<< "${metrics}")"
  local metric_count=0
  if [[ -n "${selected}" ]]; then
    metric_count="$(wc -l <<< "${selected}" | tr -d ' ')"
  fi

  if [[ "${metric_count}" -ne "${EXPECTED_METRICS}" ]]; then
    printf '%s %s scrape_error method=%s expected_metrics=%d found_metrics=%d\n' \
      "${ts}" "${pod}" "${method}" "${EXPECTED_METRICS}" "${metric_count}" \
      > "${output}"
    return 1
  fi

  {
    printf '%s %s scrape_ok method=%s metrics=%d\n' \
      "${ts}" "${pod}" "${method}" "${metric_count}"
    printf '%s\n' "${selected}"
  } > "${output}"
}

scrape_once() {
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  local discovery_error="${tmp_root}/discovery-error"
  local pod_output
  pod_output="$(
    "${KUBECTL_BIN}" get pods -n "${NS}" -l app=kms-core \
      -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.podIP}{"\n"}{end}' \
      2> "${discovery_error}"
  )" || {
    printf '%s sampler_error pod_discovery="%s"\n' \
      "${ts}" "$(single_line "${discovery_error}")"
    return 1
  }

  local -a pods=()
  local -a pod_ips=()
  local pod pod_ip
  while IFS=$'\t' read -r pod pod_ip; do
    if [[ -n "${pod}" ]]; then
      pods+=("${pod}")
      pod_ips+=("${pod_ip}")
    fi
  done <<< "${pod_output}"

  printf '%s sampler_discovery namespace=%s pods=%d expected=%d\n' \
    "${ts}" "${NS}" "${#pods[@]}" "${EXPECTED_PODS}"
  if [[ "${#pods[@]}" -ne "${EXPECTED_PODS}" ]]; then
    return 1
  fi

  local round_dir
  round_dir="$(mktemp -d "${tmp_root}/round.XXXXXX")"
  local -a pids=()
  local -a outputs=()
  local i
  for i in "${!pods[@]}"; do
    outputs[i]="${round_dir}/${i}.log"
    scrape_pod "${ts}" "${pods[i]}" "${pod_ips[i]}" "${outputs[i]}" &
    pids[i]="$!"
  done

  local failed=0
  for i in "${!pids[@]}"; do
    if ! wait "${pids[i]}"; then
      failed=$((failed + 1))
    fi
    cat "${outputs[i]}"
  done

  if [[ "${failed}" -ne 0 ]]; then
    printf '%s sampler_error failed_pods=%d expected_pods=%d\n' \
      "${ts}" "${failed}" "${EXPECTED_PODS}"
    return 1
  fi
  printf '%s sampler_ok pods=%d metrics_per_pod=%d\n' \
    "${ts}" "${#pods[@]}" "${EXPECTED_METRICS}"
}

echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) sampler_start namespace=${NS} interval=${INTERVAL}s port=${METRICS_PORT} mode=${MODE}"
if [[ "${MODE}" == "--once" ]]; then
  scrape_once
  exit $?
fi

while true; do
  scrape_once || true
  sleep "${INTERVAL}"
done

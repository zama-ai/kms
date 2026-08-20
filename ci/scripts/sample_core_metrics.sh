#!/usr/bin/env bash
# Sample the KMS application gauges that are most useful when diagnosing
# decryption backpressure. The pod proxy keeps this independent of tools in the
# KMS containers and produces one timestamped value per pod and metric.
set -uo pipefail

NS="${1:-kms-ci}"
INTERVAL="${2:-5}"
METRICS_PORT="${3:-9646}"

while true; do
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  mapfile -t pods < <(
    kubectl get pods -n "${NS}" -l app=kms-core \
      -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null
  )

  for pod in "${pods[@]}"; do
    metrics="$(
      kubectl get --raw \
        "/api/v1/namespaces/${NS}/pods/${pod}:${METRICS_PORT}/proxy/metrics" \
        2>/dev/null
    )" || {
      echo "${ts} ${pod} scrape_error"
      continue
    }

    awk -v ts="${ts}" -v pod="${pod}" '
      /^kms_(active_sessions|inactive_sessions|rate_limiter_usage|meta_storage_user_decryptions|meta_storage_public_decryptions|tasks)($|\{)/ {
        print ts, pod, $1, $2
      }
    ' <<< "${metrics}"
  done

  sleep "${INTERVAL}"
done

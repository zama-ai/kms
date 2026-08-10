#!/usr/bin/env bash
# Basic bash script to sample CPUs on the core side during benchmarking so we can get an idea of how much pressure our
# benchmarks are putting on the KMS cluster.
# Samples per-party CPU + memory every INTERVAL seconds until killed. Used by performance-testing.yml to correlate core
# CPU against performance tests in a similar way to the eth0 diagnostics (collect_network_diagnostics.sh).
#
# Kubernetes's metrics-server resolution is ~15s and `kubectl top` reports CPU as a rate over that window, so sampling
# faster just re-reads the same value; ~10s is plenty.
#
# Each line: "<utc-ts> <pod> <cpu> <mem>", e.g. "2026-07-12T10:25:00Z kms-core-1-core-1 47800m 20480Mi".
set -uo pipefail

NS="${1:-kms-ci}"
INTERVAL="${2:-10}"

while true; do
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  kubectl top pod -n "${NS}" -l app=kms-core --no-headers 2>/dev/null \
    | awk -v ts="${ts}" '{ print ts, $1, $2, $3 }' || true
  sleep "${INTERVAL}"
done

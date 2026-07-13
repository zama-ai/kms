#!/usr/bin/env bash
# Sample per-party (kms-core pod) CPU + memory via metrics-server, timestamped,
# every INTERVAL seconds until killed. Used by performance-testing.yml to
# correlate core CPU against the decrypt rate rungs — pairs with the eth0
# diagnostics (collect_network_diagnostics.sh) to show whether the cores are
# CPU-bound or network-bound at the top rungs.
#
# metrics-server resolution is ~15s and `kubectl top` reports CPU as a rate over
# that window, so sampling faster just re-reads the same value; ~10s is plenty.
# Namespace-scoped pod metrics only (no cluster node-metrics RBAC needed).
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

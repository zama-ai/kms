#!/usr/bin/env bash
# Checks the local benchmark tooling without Kubernetes or cloud credentials.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for script in manual-run-experiment.sh manual-run-paired.sh manual-set-mpc-knobs.sh \
  manual-bandwidth-bench.sh manual-metrics-watch.sh manual-capture-core-logs.sh \
  manual-cluster-facts.sh manual-dkg-under-load.sh; do
  bash -n "$SCRIPT_DIR/$script"
done
python3 -B -m unittest discover -s "$SCRIPT_DIR" -p 'test_*.py' -v

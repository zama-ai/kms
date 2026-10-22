#!/usr/bin/env bash
# Compares optimistic reconstruction with its decoder control on one deployed image.
set -euo pipefail
NS="${NS:?set NS=<dedicated-namespace>}"
PREFIX="${PREFIX:?set PREFIX=<unique-block-name>}"
RUNS_DIR="${RUNS_DIR:-$HOME/Code/ai/DkgDdecBench/runs-v2}"
REFERENCE_FLEET="${REFERENCE_FLEET:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="MPC_DKG_PHASE_LOG_EVERY=100,MPC_DKG_TRACKER_LOG_PERCENTAGE=1"
row=0
for enabled in 0 1 1 0; do
  row=$((row + 1))
  tag="$PREFIX-$row-opt$enabled"
  NS="$NS" TAG="$tag" RUNS_DIR="$RUNS_DIR" REFERENCE_FLEET="$REFERENCE_FLEET" \
    TOKIO=10 RAYON=60 PREPROC=90 \
    TUNING_ENV="$BASE,MPC_OPTIMISTIC_RECONSTRUCTION=$enabled" \
    bash "$SCRIPT_DIR/manual-run-experiment.sh"
  if [ -z "$REFERENCE_FLEET" ]; then REFERENCE_FLEET="$RUNS_DIR/$tag/start/fleet.json"; fi
done
python3 "$SCRIPT_DIR/analyse_run.py" compare "$RUNS_DIR"

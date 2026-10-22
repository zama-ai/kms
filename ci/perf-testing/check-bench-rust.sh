#!/usr/bin/env bash
# Focused Rust checks for the benchmark measurement and reconstruction controls.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/../.."
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_PROFILE_DEV_CODEGEN_UNITS="${CARGO_PROFILE_DEV_CODEGEN_UNITS:-1}"
export CARGO_PROFILE_TEST_CODEGEN_UNITS="${CARGO_PROFILE_TEST_CODEGEN_UNITS:-1}"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
export MPC_DKG_PRSS_PIPELINE=0 MPC_BCAST_ECHO_HASH_KEYS=0 MPC_SERIALIZE_ON_RAYON=0
export MPC_OPTIMISTIC_RECONSTRUCTION=1
if [ -n "${PROTOC:-}" ]; then
  "$PROTOC" --version
else
  command -v protoc >/dev/null || { echo 'Install protoc or set PROTOC to its executable.' >&2; exit 1; }
fi
cargo fmt --all --check
cargo test --locked -p observability -p thread-handles --lib -- --test-threads=2
cargo test --locked -p threshold-networking --lib -- --test-threads=2
cargo test --locked -p threshold-algebra --lib optimistic -- --test-threads=2
cargo test --locked -p threshold-execution --features testing --lib reconstruct_batch -- --test-threads=2
MPC_OPTIMISTIC_RECONSTRUCTION=0 cargo test --locked -p threshold-execution --features testing --lib reconstruct_batch -- --test-threads=2
cargo test --locked -p threshold-execution --features testing --lib reconstruct_mode -- --test-threads=2
cargo test --locked -p threshold-execution --features testing --lib offline_small -- --test-threads=2
MPC_DKG_PRSS_PIPELINE=1 cargo test --locked -p threshold-execution --features testing --lib offline_small -- --test-threads=2
cargo test --locked -p threshold-execution --features testing --lib broadcast -- --test-threads=2
MPC_BCAST_ECHO_HASH_KEYS=1 cargo test --locked -p threshold-execution --features testing --lib broadcast -- --test-threads=2
MPC_SERIALIZE_ON_RAYON=1 cargo test --locked -p threshold-execution --features testing --lib broadcast -- --test-threads=2
cargo test --locked -p kms --lib bandwidth_latency_requires_successful_attempts -- --test-threads=2

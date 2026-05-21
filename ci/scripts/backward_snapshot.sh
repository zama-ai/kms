#!/usr/bin/env bash

#=============================================================================
# Backward Compatibility Snapshot Script
#
# Generates `VersionsDispatch` snapshots via the tfhe-rs `tfhe-lints/snapshot`
# Dylint library and compares them between two revisions of this workspace.
#
# Subcommands:
#   check
#     Main CI/local gate. Generates one snapshot from --base-ref and one from
#     the current checkout, then runs `tfhe-backward-compat-checker check`.
#   report
#     Same snapshot generation as `check`, but writes a markdown report instead
#     of failing only on errors. Useful when reviewing warnings locally.
#
# Usage:
#   ./backward_snapshot.sh check --base-ref <ref>
#   ./backward_snapshot.sh report --base-ref <ref> --output <file>
#
# `check` and `report` are the user-facing entry points and the Makefile shims
# call those.
#
# Tool installation runs by default before any snapshot-producing subcommand.
# Set SKIP_TFHE_SNAPSHOT_TOOL_INSTALL=1 to suppress it during local iteration.
#
# Configuration env vars (defaults shown):
#   TFHE_LINTS_GIT=https://github.com/zama-ai/tfhe-rs
#   TFHE_LINTS_TAG=tfhe-rs-1.6.1
#   TFHE_LINTS_TOOLCHAIN=nightly-2026-01-22
#   TFHE_SNAPSHOT_PATTERN=utils/tfhe-lints/snapshot
#   SNAPSHOT_PACKAGES="kms kms-grpc threshold-execution threshold-algebra threshold-networking threshold-types"
#=============================================================================

set -euo pipefail

#=============================================================================
# Script Location
#=============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

#=============================================================================
# Configuration (env-var-overridable)
#=============================================================================
TFHE_LINTS_GIT="${TFHE_LINTS_GIT:-https://github.com/zama-ai/tfhe-rs}"
TFHE_LINTS_TAG="${TFHE_LINTS_TAG:-tfhe-rs-1.6.1}"
TFHE_LINTS_TOOLCHAIN="${TFHE_LINTS_TOOLCHAIN:-nightly-2026-01-22}"
TFHE_SNAPSHOT_PATTERN="${TFHE_SNAPSHOT_PATTERN:-utils/tfhe-lints/snapshot}"
SNAPSHOT_PACKAGES="${SNAPSHOT_PACKAGES:-kms kms-grpc threshold-execution threshold-algebra threshold-networking threshold-types}"

#=============================================================================
# Logging
#=============================================================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

#=============================================================================
# Usage
#=============================================================================
usage() {
    cat <<EOF
Usage: $0 <subcommand> [options]

Subcommands:
  check  --base-ref <ref>
      Main gate used by \`make backward-snapshot-check\`.
      Creates two temporary snapshot directories:
        - base: generated from a detached git worktree at <ref>
        - head: generated from the current checkout
      Then runs \`tfhe-backward-compat-checker check\`.
      Exits non-zero for backward-compatibility errors such as removed
      version variants.

  report --base-ref <ref> --output <file>
      Main review aid used by \`make backward-snapshot-report\`.
      Generates the same base/head snapshots as \`check\`, then runs
      \`tfhe-backward-compat-checker diff-report\` and writes markdown to
      <file>. Use this when you want the warnings and neutral changes in a
      shareable format.

Examples:
  $0 check --base-ref origin/main
  $0 report --base-ref origin/main --output /tmp/kms-backward-snapshot-report.md
  SKIP_TFHE_SNAPSHOT_TOOL_INSTALL=1 SNAPSHOT_PACKAGES=threshold-types \\
      $0 check --base-ref origin/main

Environment:
  SKIP_TFHE_SNAPSHOT_TOOL_INSTALL=1   Skip the implicit install-tools step.
  TFHE_LINTS_GIT, TFHE_LINTS_TAG, TFHE_LINTS_TOOLCHAIN,
  TFHE_SNAPSHOT_PATTERN                Override the pinned snapshot lint source.
  SNAPSHOT_PACKAGES                    Space-separated package list to snapshot.
EOF
}

die() {
    log_error "$@"
    exit 1
}

#=============================================================================
# Tool installation
#=============================================================================
install_tools() {
    if [[ "${SKIP_TFHE_SNAPSHOT_TOOL_INSTALL:-0}" == "1" ]]; then
        log_info "SKIP_TFHE_SNAPSHOT_TOOL_INSTALL=1, skipping tool install"
        return
    fi
    log_info "Installing cargo-dylint, dylint-link"
    cargo install cargo-dylint dylint-link --locked
    log_info "Installing Rust toolchain ${TFHE_LINTS_TOOLCHAIN}"
    rustup toolchain install "${TFHE_LINTS_TOOLCHAIN}" --component llvm-tools-preview,rustc-dev
    log_info "Installing tfhe-backward-compat-checker from ${TFHE_LINTS_GIT}@${TFHE_LINTS_TAG}"
    cargo install --force --git "${TFHE_LINTS_GIT}" --tag "${TFHE_LINTS_TAG}" tfhe-backward-compat-checker --locked
}

#=============================================================================
# Snapshot generation
#
# Runs `cargo dylint` with the tfhe-lints snapshot pattern over each package
# in $SNAPSHOT_PACKAGES, writing lint_enum_snapshots_*.json into $1.
# The cwd at call time determines which checkout is snapshotted.
#=============================================================================
generate_in_cwd() {
    local output_dir="$1"
    local target_dir="${output_dir}/cargo-target"

    rm -f "${output_dir}"/lint_enum_snapshots_*.json

    for package in ${SNAPSHOT_PACKAGES}; do
        log_info "Generating snapshot for ${package} in $(pwd)"
        CARGO_TARGET_DIR="${target_dir}" \
            cargo clean -p "${package}" --profile dev
        CARGO_TARGET_DIR="${target_dir}" \
        TFHE_BACKWARD_COMPAT_DATA_DIR="${output_dir}" \
            cargo dylint \
                --git "${TFHE_LINTS_GIT}" \
                --tag "${TFHE_LINTS_TAG}" \
                --pattern "${TFHE_SNAPSHOT_PATTERN}" \
                --all \
                --no-deps \
                -p "${package}" -- --all-features
    done
}

# generate_snapshot <abs-output-dir> [<base-ref>]
generate_snapshot() {
    local output_dir="$1"
    local base_ref="${2:-}"

    mkdir -p "${output_dir}"

    if [[ -z "${base_ref}" ]]; then
        ( cd "${REPO_ROOT}" && generate_in_cwd "${output_dir}" )
        return
    fi

    local tmp_parent worktree_dir
    tmp_parent="$(mktemp -d)"
    worktree_dir="${tmp_parent}/worktree"
    # shellcheck disable=SC2064
    trap "git -C '${REPO_ROOT}' worktree remove --force '${worktree_dir}' >/dev/null 2>&1 || true; rm -rf '${tmp_parent}'" RETURN

    log_info "Creating worktree for ${base_ref} at ${worktree_dir}"
    git -C "${REPO_ROOT}" worktree add --detach "${worktree_dir}" "${base_ref}"
    ( cd "${worktree_dir}" && generate_in_cwd "${output_dir}" )
}

#=============================================================================
# Subcommand: check
#=============================================================================
cmd_check() {
    local base_ref=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --base-ref) base_ref="$2"; shift 2 ;;
            -h|--help)  usage; exit 0 ;;
            *) die "Unknown flag for check: $1" ;;
        esac
    done
    [[ -n "${base_ref}" ]] || die "check requires --base-ref <ref>"

    install_tools

    local base_dir head_dir
    base_dir="$(mktemp -d)"
    head_dir="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '${base_dir}' '${head_dir}'" EXIT

    generate_snapshot "${base_dir}" "${base_ref}"
    generate_snapshot "${head_dir}"

    log_info "Running tfhe-backward-compat-checker check"
    tfhe-backward-compat-checker check --base-dir "${base_dir}" --head-dir "${head_dir}"
}

#=============================================================================
# Subcommand: report
#=============================================================================
cmd_report() {
    local base_ref="" output_file=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --base-ref) base_ref="$2";    shift 2 ;;
            --output)   output_file="$2"; shift 2 ;;
            -h|--help)  usage; exit 0 ;;
            *) die "Unknown flag for report: $1" ;;
        esac
    done
    [[ -n "${base_ref}" ]]    || die "report requires --base-ref <ref>"
    [[ -n "${output_file}" ]] || die "report requires --output <file>"

    # Resolve to absolute path before any cwd hops.
    local output_dir
    output_dir="$(dirname "${output_file}")"
    mkdir -p "${output_dir}"
    output_file="$(cd "${output_dir}" && pwd)/$(basename "${output_file}")"

    install_tools

    local base_dir head_dir
    base_dir="$(mktemp -d)"
    head_dir="$(mktemp -d)"
    # shellcheck disable=SC2064
    trap "rm -rf '${base_dir}' '${head_dir}'" EXIT

    generate_snapshot "${base_dir}" "${base_ref}"
    generate_snapshot "${head_dir}"

    log_info "Writing diff report to ${output_file}"
    tfhe-backward-compat-checker diff-report \
        --base-dir "${base_dir}" --head-dir "${head_dir}" --output "${output_file}"
}

#=============================================================================
# Dispatch
#=============================================================================
main() {
    if [[ $# -eq 0 ]]; then
        usage
        exit 1
    fi

    local subcommand="$1"
    shift
    case "${subcommand}" in
        check)         cmd_check "$@" ;;
        report)        cmd_report "$@" ;;
        -h|--help)     usage ;;
        *) die "Unknown subcommand: ${subcommand}" ;;
    esac
}

main "$@"

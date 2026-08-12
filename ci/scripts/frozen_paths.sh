#!/usr/bin/env bash
#
# Byte-freeze gate for frozen reference assets, complementing the digest test
# core/service/tests/evm_path_byte_frozen.rs.
#
# The hard-failing paths below are pure frozen assets — anything that changes there changes a
# reference, not an implementation.
#
# The EVM path's own tests live in inline `#[cfg(test)]` modules inside production files, so a
# path deny-list cannot separate "edited the production code" from "edited the EVM test next to
# it". Those files are therefore *reported* for the reviewer instead of failed, and the byte-level
# guarantee for them comes from the frozen-digest test, not from this script.
#
# Usage: ci/scripts/frozen_paths.sh [base-ref]
#   base-ref defaults to $GITHUB_BASE_REF, then to main.

set -euo pipefail

BASE_REF="${1:-${GITHUB_BASE_REF:-main}}"

if ! git rev-parse --verify --quiet "${BASE_REF}" >/dev/null; then
    if git rev-parse --verify --quiet "origin/${BASE_REF}" >/dev/null; then
        BASE_REF="origin/${BASE_REF}"
    else
        echo "error: base ref '${BASE_REF}' not found; fetch it before running this check" >&2
        exit 2
    fi
fi

MERGE_BASE="$(git merge-base "${BASE_REF}" HEAD)"

# Modified or deleted only. Adding a reference (a new backward-compatibility snapshot for a new
# release) is ordinary work; changing or removing one that already exists is what breaks
# byte-compatibility, and that is what this gate refuses. Rename detection is disabled so a
# renamed-and-edited frozen asset still shows up as a deletion at the frozen path instead of an
# `R` entry that the `MD` filter would miss.
CHANGED="$(git diff --no-renames --name-only --diff-filter=MD "${MERGE_BASE}" HEAD)"

# Frozen assets: references, not implementations. Modifying one is the failure this gate exists
# for. core/grpc/proto is deliberately absent: proto changes must be additive in field numbers,
# and that rule is checked in Rust, where the wire rule actually lives.
#
# The EVM entries freeze the shipped EVM references; the Solana entries freeze the published
# linker vectors, their set digest, and the constants snapshot, which other repositories
# reproduce. Modifying any of the latter is a version bump in the linker's scheme tag — a protocol
# decision that needs its own reviewed change.
FROZEN_GLOBS=(
    'backward-compatibility/data/*'
    'backward-compatibility/generate-*/*'
    'core/service/tests/evm_path_byte_frozen.rs'
    'core/grpc/test-vectors/solana_linker_v1.json'
    'core/grpc/test-vectors/solana_linker_v1.sha256'
    'core/grpc/tests/solana_frozen_constants.rs'
)

violations=()
while IFS= read -r file; do
    [ -n "${file}" ] || continue
    for glob in "${FROZEN_GLOBS[@]}"; do
        # shellcheck disable=SC2053 # glob matching is the point
        if [[ ${file} == ${glob} ]]; then
            violations+=("${file}")
        fi
    done
done <<<"${CHANGED}"

if [ ${#violations[@]} -ne 0 ]; then
    echo "Byte-freeze gate FAILED — frozen assets modified against ${BASE_REF}:" >&2
    printf '  %s\n' "${violations[@]}" >&2
    echo >&2
    echo "These paths hold frozen references. If a reference genuinely must move, that is a" >&2
    echo "protocol decision and needs its own reviewed change, not a line in this series." >&2
    exit 1
fi

echo "Byte-freeze gate: no frozen asset modified against ${BASE_REF}."

# Report-only half: files that mix production code with inline tests.
mixed=()
while IFS= read -r file; do
    [ -n "${file}" ] || continue
    case "${file}" in
    *.rs) ;;
    *) continue ;;
    esac
    [ -f "${file}" ] || continue
    if grep -q '#\[cfg(test)\]' "${file}"; then
        mixed+=("${file}")
    fi
done <<<"${CHANGED}"

if [ ${#mixed[@]} -ne 0 ]; then
    echo
    echo "Reviewer note — these changed files carry inline tests. Confirm that no pre-existing"
    echo "EVM test was edited to accommodate new behaviour (added Solana tests are expected):"
    printf '  %s\n' "${mixed[@]}"
fi

#!/usr/bin/env bash
# Resolve the compat-matrix config + workflow_dispatch overrides into matrix JSON.
#
# Reads ci/compat-matrix.json. Optional environment overrides (from
# workflow_dispatch inputs):
#   INPUT_VERSIONS     comma-separated list of versions (replaces "versions")
#   INPUT_SKIP_CELLS   JSON array (replaces "skip_cells")
#
# Writes to $GITHUB_OUTPUT (when set, else stdout):
#   producers     JSON array of versions (Y-axis)
#   consumers     JSON array of versions (X-axis, same set as producers)
#   pairs         JSON array of {a, b} for the off-diagonal, non-skipped cells
#   pairs_count   integer

set -euo pipefail

CONFIG_PATH="${1:-ci/compat-matrix.json}"

if [[ ! -f "${CONFIG_PATH}" ]]; then
    echo "compat-matrix config not found at ${CONFIG_PATH}" >&2
    exit 1
fi

raw_versions="$(jq -r '.versions | @json' "${CONFIG_PATH}")"
raw_skip="$(jq -r '.skip_cells // [] | @json' "${CONFIG_PATH}")"

if [[ -n "${INPUT_VERSIONS:-}" ]]; then
    raw_versions="$(printf '%s' "${INPUT_VERSIONS}" | jq -Rrc 'split(",") | map(gsub("^\\s+|\\s+$"; "")) | map(select(length > 0))')"
fi

if [[ -n "${INPUT_SKIP_CELLS:-}" ]]; then
    raw_skip="${INPUT_SKIP_CELLS}"
fi

pairs="$(jq -nc \
    --argjson versions "${raw_versions}" \
    --argjson skip "${raw_skip}" \
    '
    ($skip | map({key: (.producer + "|" + .consumer), value: true}) | from_entries) as $skipmap
    | [
        $versions[] as $a
        | $versions[] as $b
        | select($a != $b)
        | select($skipmap[$a + "|" + $b] != true)
        | {a: $a, b: $b}
      ]
    ')"

pairs_count="$(jq 'length' <<<"${pairs}")"

emit() {
    local name="$1" value="$2"
    if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
        printf '%s=%s\n' "${name}" "${value}" >> "${GITHUB_OUTPUT}"
    else
        printf '%s=%s\n' "${name}" "${value}"
    fi
}

emit producers "${raw_versions}"
emit consumers "${raw_versions}"
emit pairs "${pairs}"
emit pairs_count "${pairs_count}"

echo "compat-matrix setup: $(jq 'length' <<<"${raw_versions}") versions, ${pairs_count} off-diagonal pairs" >&2

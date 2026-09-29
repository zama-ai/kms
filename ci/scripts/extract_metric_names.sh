#!/usr/bin/env bash

#=============================================================================
# Metric Names Extraction Script
#
# Prints a sorted, stable text snapshot of the externally-observable KMS metric
# names and label-value constants (operation/tag/error strings) that Prometheus
# rules and Grafana dashboards, living OUTSIDE this repo, match literally.
#
# The snapshot has two kinds of lines:
#   metric: kms_<name>          one per registered Prometheus metric family
#   const:  <NAME> = "<value>"  one per OP_/OP_TYPE_/TAG_/ERR_/CENTRAL_TAG const
#
# Sources (relative to the repo root passed as $1):
#   observability/src/metrics.rs        metric family registrations
#   observability/src/metrics_names.rs  operation/tag/error label constants
#
# Usage:
#   ./extract_metric_names.sh [repo-root]   # defaults to the repo root
#
# The output is deterministic (sorted) so two snapshots can be diffed directly.
# This is a read-only extractor: it never fails the build, it only reports.
#=============================================================================

set -euo pipefail

#=============================================================================
# Script Location
#=============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

REPO_ROOT="${1:-${DEFAULT_REPO_ROOT}}"

METRICS_RS="${REPO_ROOT}/observability/src/metrics.rs"
METRICS_NAMES_RS="${REPO_ROOT}/observability/src/metrics_names.rs"

die() {
    echo "[ERROR] $*" >&2
    exit 1
}

[[ -f "${METRICS_RS}" ]]       || die "metrics.rs not found at ${METRICS_RS}"
[[ -f "${METRICS_NAMES_RS}" ]] || die "metrics_names.rs not found at ${METRICS_NAMES_RS}"

#=============================================================================
# Metric family names
#
# Names are registered either as `format!("{prefix}_<suffix>", ...)` (default
# prefix "kms") or, for the build-info gauge, as the literal "kms_version".
# We normalise every `{prefix}_<suffix>` to `kms_<suffix>` so the snapshot
# reflects the default-prefix names dashboards actually query.
#
# sed pipeline (-nE): match any `{prefix}_<suffix>` token inside the file and
# print `kms_<suffix>`; the literal kms_version is captured by the second
# expression.
#=============================================================================
extract_metric_families() {
    {
        sed -nE 's/.*\{prefix\}_([a-zA-Z0-9_]+).*/kms_\1/p' "${METRICS_RS}"
        sed -nE 's/.*"(kms_version)".*/\1/p' "${METRICS_RS}"
    } | sort -u | sed 's/^/metric: /'
}

#=============================================================================
# Label-value / tag constants
#
# Every `pub const <NAME>: &str = "<value>";` whose name starts with one of the
# label prefixes (OP_, TAG_, ERR_, CENTRAL_TAG). OP_TYPE_* is covered by the
# OP_ prefix. These are the label values/keys (operation=..., error=..., etc.)
# that dashboards query, so a rename here silently breaks them.
#=============================================================================
extract_constants() {
    sed -nE 's/^pub const (OP_[A-Z0-9_]+|TAG_[A-Z0-9_]+|ERR_[A-Z0-9_]+|CENTRAL_TAG)[[:space:]]*:[[:space:]]*&str[[:space:]]*=[[:space:]]*"([^"]*)".*/const: \1 = "\2"/p' "${METRICS_NAMES_RS}" \
        | sort -u
}

extract_metric_families
extract_constants

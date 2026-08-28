#!/usr/bin/env bash

#=============================================================================
# Rolling Upgrade Script
#
# Orchestrates a partial upgrade of KMS enclave parties. Handles the
# three-layer update required for a mixed-version cluster:
#   1. AWS KMS key policy (recipientAttestationImageSHA384 per party)
#   2. TLS peer attestation (trustedReleases with both old + new PCRs)
#   3. Container image tag (selective helm upgrade)
#
# Usage:
#   ./rolling_upgrade.sh \
#     --old-tag <old_image_tag> \
#     --new-tag <new_image_tag> \
#     --parties-to-upgrade 1,2,3,4,5 \
#     --all-upgraded-parties 1,2,3,4,5 \
#     --namespace <namespace> \
#     --num-parties <n> \
#     --deployment-type thresholdWithEnclave \
#     [--kms-chart-version <version>] \
#     [--tkms-infra-version <version>]
#
# The --all-upgraded-parties flag is the cumulative list of all parties
# that should be on the new version after this upgrade step. For the
# first upgrade (5/13), this equals --parties-to-upgrade. For the second
# upgrade (9/13), this should be "1,2,3,4,5,6,7,8,9".
#=============================================================================

set -euo pipefail

#=============================================================================
# Script Location and Library Path
#=============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="${SCRIPT_DIR}/lib"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

#=============================================================================
# Default Configuration
#=============================================================================
TARGET="aws-perf"
NAMESPACE="${NAMESPACE:-kms-ci}"
DEPLOYMENT_TYPE="${DEPLOYMENT_TYPE:-thresholdWithEnclave}"
NUM_PARTIES="${NUM_PARTIES:-13}"
OLD_KMS_CHART_VERSION="${OLD_KMS_CHART_VERSION:-repository}"
NEW_KMS_CHART_VERSION="${NEW_KMS_CHART_VERSION:-repository}"
TKMS_INFRA_VERSION="${TKMS_INFRA_CHART_VERSION:-0.3.2}"
SYNC_SECRETS_VERSION="0.2.3"
PATH_SUFFIX="${PATH_SUFFIX:-kms-enclave-ci}"
KMS_CORE_IMAGE_NAME="${KMS_CORE_IMAGE_NAME:-hub.zama.org/ghcr/zama-ai/kms/core-service}"
KMS_CORE_CLIENT_IMAGE_NAME="${KMS_CORE_CLIENT_IMAGE_NAME:-hub.zama.org/ghcr/zama-ai/kms/core-client}"
HELM_RELEASE_PREFIX="${HELM_RELEASE_PREFIX:-kms-core}"
ENABLE_TLS="true"
TLS="true"

OLD_TAG=""
NEW_TAG=""
PARTIES_TO_UPGRADE=""
ALL_UPGRADED_PARTIES=""

#=============================================================================
# Load Library Modules
#=============================================================================
# shellcheck source=lib/common.sh
source "${LIB_DIR}/common.sh"

# shellcheck source=lib/infrastructure.sh
source "${LIB_DIR}/infrastructure.sh"

# shellcheck source=lib/kms_deployment.sh
source "${LIB_DIR}/kms_deployment.sh"

#=============================================================================
# Parse Arguments
#=============================================================================
parse_rolling_upgrade_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --old-tag) OLD_TAG="$2"; shift 2 ;;
            --new-tag) NEW_TAG="$2"; shift 2 ;;
            --parties-to-upgrade) PARTIES_TO_UPGRADE="$2"; shift 2 ;;
            --all-upgraded-parties) ALL_UPGRADED_PARTIES="$2"; shift 2 ;;
            --namespace) NAMESPACE="$2"; shift 2 ;;
            --num-parties) NUM_PARTIES="$2"; shift 2 ;;
            --deployment-type) DEPLOYMENT_TYPE="$2"; shift 2 ;;
            --old-kms-chart-version) OLD_KMS_CHART_VERSION="$2"; shift 2 ;;
            --new-kms-chart-version) NEW_KMS_CHART_VERSION="$2"; shift 2 ;;
            --tkms-infra-version) TKMS_INFRA_VERSION="$2"; shift 2 ;;
            --help)
                echo "Usage: $0 --old-tag <tag> --new-tag <tag> --parties-to-upgrade <ids> --all-upgraded-parties <ids> [OPTIONS]"
                exit 0
                ;;
            *) log_error "Unknown argument: $1"; exit 1 ;;
        esac
    done

    # Validate required arguments
    if [[ -z "${OLD_TAG}" ]]; then
        log_error "--old-tag is required"
        exit 1
    fi
    if [[ -z "${NEW_TAG}" ]]; then
        log_error "--new-tag is required"
        exit 1
    fi
    if [[ -z "${PARTIES_TO_UPGRADE}" ]]; then
        log_error "--parties-to-upgrade is required (comma-separated party IDs)"
        exit 1
    fi
    if [[ -z "${ALL_UPGRADED_PARTIES}" ]]; then
        ALL_UPGRADED_PARTIES="${PARTIES_TO_UPGRADE}"
    fi
}

#=============================================================================
# Fetch PCR Values from an Enclave Image Tag
# Sets the output into the provided variable name prefixes.
#=============================================================================
fetch_pcrs_for_tag() {
    local tag="$1"
    local prefix="$2"

    log_info "Fetching PCR values for tag: ${tag}"

    if ! command -v docker &> /dev/null; then
        log_error "Docker is required to fetch PCR values from images"
        exit 1
    fi

    local IMAGE_REPO="hub.zama.org/ghcr/zama-ai/kms"
    local FULL_IMAGE="${IMAGE_REPO}/core-service-enclave:${tag}"

    log_info "Pulling ${FULL_IMAGE}..."
    docker pull "${FULL_IMAGE}" > /dev/null 2>&1 || {
        log_error "Failed to pull image: ${FULL_IMAGE}"
        exit 1
    }

    local pcr0 pcr1 pcr2
    pcr0=$(docker inspect "${FULL_IMAGE}" | jq -r '.[0].Config.Labels["zama.kms.eif_pcr0"]' || echo "")
    pcr1=$(docker inspect "${FULL_IMAGE}" | jq -r '.[0].Config.Labels["zama.kms.eif_pcr1"]' || echo "")
    pcr2=$(docker inspect "${FULL_IMAGE}" | jq -r '.[0].Config.Labels["zama.kms.eif_pcr2"]' || echo "")

    if [[ -z "${pcr0}" || "${pcr0}" == "null" ]]; then
        log_error "Failed to extract PCR0 from image ${FULL_IMAGE}"
        exit 1
    fi

    eval "export ${prefix}_PCR0='${pcr0}'"
    eval "export ${prefix}_PCR1='${pcr1}'"
    eval "export ${prefix}_PCR2='${pcr2}'"

    log_info "  ${prefix}_PCR0: ${pcr0:0:16}..."
    log_info "  ${prefix}_PCR1: ${pcr1:0:16}..."
    log_info "  ${prefix}_PCR2: ${pcr2:0:16}..."
}

#=============================================================================
# Main
#=============================================================================
main() {
    parse_rolling_upgrade_args "$@"

    log_info "========================================="
    log_info "Rolling Upgrade Starting"
    log_info "========================================="
    log_info "Old tag:               ${OLD_TAG}"
    log_info "New tag:               ${NEW_TAG}"
    log_info "Parties to upgrade:    ${PARTIES_TO_UPGRADE}"
    log_info "All upgraded parties:  ${ALL_UPGRADED_PARTIES}"
    log_info "Namespace:             ${NAMESPACE}"
    log_info "Deployment type:       ${DEPLOYMENT_TYPE}"
    log_info "Num parties:           ${NUM_PARTIES}"
    log_info "========================================="

    #=========================================================================
    # Step 1: Fetch PCR values from both old and new enclave images
    #=========================================================================
    log_info "Step 1: Fetching PCR values from old and new images..."

    if [[ -n "${OLD_PCR0:-}" && -n "${OLD_PCR1:-}" && -n "${OLD_PCR2:-}" ]]; then
        log_info "Using pre-set OLD PCR values from environment"
    else
        fetch_pcrs_for_tag "${OLD_TAG}" "OLD"
    fi

    if [[ -n "${NEW_PCR0:-}" && -n "${NEW_PCR1:-}" && -n "${NEW_PCR2:-}" ]]; then
        log_info "Using pre-set NEW PCR values from environment"
    else
        fetch_pcrs_for_tag "${NEW_TAG}" "NEW"
    fi

    #=========================================================================
    # Step 2: Update TKMS infra (AWS KMS key policies) for upgraded parties
    #=========================================================================
    log_info "Step 2: Updating AWS KMS key policies via tkms-infra..."
    update_tkms_infra_for_upgrade "${OLD_PCR0}" "${NEW_PCR0}" "${ALL_UPGRADED_PARTIES}"

    #=========================================================================
    # Step 3: Upgrade selected parties' images and update trustedReleases
    #=========================================================================
    log_info "Step 3: Upgrading parties and updating trustedReleases on all nodes..."

    export HELM_RELEASE_PREFIX="${HELM_RELEASE_PREFIX}"
    export ENABLE_TLS="true"

    upgrade_parties \
        "${NEW_TAG}" \
        "${OLD_TAG}" \
        "${ALL_UPGRADED_PARTIES}" \
        "${OLD_PCR0}" "${OLD_PCR1}" "${OLD_PCR2}" \
        "${NEW_PCR0}" "${NEW_PCR1}" "${NEW_PCR2}" \
        "${OLD_KMS_CHART_VERSION}" \
        "${NEW_KMS_CHART_VERSION}"

    #=========================================================================
    # Step 4 (phase 2): Enable the PRSS-Mask legacy-schedule threshold on the
    # upgraded parties, AFTER their new binary is running.
    #
    # The threshold lives in the core-service config (TOML over vsock — pod env
    # does not reach the enclave). Pre-#663 binaries reject the unknown field
    # (`deny_unknown_fields`, config read fresh at start), so it must be absent
    # until every upgraded party runs the new binary — which Step 3 guarantees
    # by deploying them with the field off (chart value empty). We now set it via
    # a second helm upgrade on the upgraded parties only; the configmap change
    # bumps `checksum/config`, restarting the (already-new) pod to pick it up.
    # Non-upgraded (old) parties are never touched, so no old binary ever sees it.
    #=========================================================================
    # The server parses the threshold as a U256 and logs it back in canonical decimal, and the
    # confirmation below gates the wave on that log line. An input that differs from its own
    # canonical form could never match it, so restrict this script to decimal and strip leading
    # zeros. 0x-prefixed hex remains valid for the chart value and the server config; only this
    # script's automated comparison requires decimal.
    local threshold="${LEGACY_PRSS_MASK_THRESHOLD:-100}"
    if [[ ! "${threshold}" =~ ^[0-9]+$ ]]; then
        log_error "LEGACY_PRSS_MASK_THRESHOLD must be a decimal integer, got '${threshold}'."
        log_error "0x-prefixed hex is accepted by the chart value but not by this script; convert it to decimal."
        exit 1
    fi
    threshold="$(echo "${threshold}" | sed 's/^0*//')"
    threshold="${threshold:-0}"

    log_info "Step 4: Enabling PRSS-Mask threshold=${threshold} on upgraded parties [${ALL_UPGRADED_PARTIES}]..."

    local new_chart_loc="${REPO_ROOT}/charts/kms-core"
    local new_version_args=()
    if [[ "${NEW_KMS_CHART_VERSION}" != "repository" ]]; then
        new_chart_loc="oci://hub.zama.org/ghcr/zama-ai/kms/charts/kms-core"
        new_version_args=(--version "${NEW_KMS_CHART_VERSION}")
    fi

    # Run the upgrades in parallel but track each PID → party, and fail the step if ANY of them
    # fails (a bare `wait` only returns the exit status of the last backgrounded job).
    IFS=',' read -ra _prss_ids <<< "${ALL_UPGRADED_PARTIES}"
    local -a _prss_pids=()
    local -a _prss_parties=()
    for _id in "${_prss_ids[@]}"; do
        local i; i="$(echo "${_id}" | tr -d ' ')"
        [[ -z "${i}" ]] && continue
        log_info "  Party ${i}: helm upgrade (reuse-values) + PRSS threshold..."
        helm upgrade --install "${HELM_RELEASE_PREFIX}-${i}" "${new_chart_loc}" \
            "${new_version_args[@]}" \
            --namespace "${NAMESPACE}" \
            --reuse-values \
            --set kmsGenCertAndKeys.enabled=false \
            --set "kmsCore.thresholdMode.legacyPrssMask.beforePublicDecryptId=${threshold}" \
            --set "kmsCore.thresholdMode.legacyPrssMask.beforeUserDecryptId=${threshold}" \
            --wait --wait-for-jobs --timeout=1200s &
        _prss_pids+=("$!")
        _prss_parties+=("${i}")
    done

    local _prss_failed=()
    for _idx in "${!_prss_pids[@]}"; do
        if ! wait "${_prss_pids[$_idx]}"; then
            _prss_failed+=("${_prss_parties[$_idx]}")
        fi
    done
    if [[ "${#_prss_failed[@]}" -gt 0 ]]; then
        log_error "PRSS-Mask threshold rollout failed for parties: ${_prss_failed[*]}"
        exit 1
    fi

    # A successful helm upgrade only proves Helm accepted the values, not that the threshold
    # reached the core config: a misplaced value is dropped without error and the server then
    # defaults to "0" (fixed schedule). The startup line below is the only signal that the value
    # took effect, so gate the wave on it per party rather than trusting the upgrade exit status.
    #
    # A threshold of 0 is the one value that cannot be confirmed this way: it means "no legacy
    # window" (no request ID is strictly below 0), which is already the default, so the server
    # emits no line at all. Skip the gate rather than fail it, and say so loudly — running this
    # step with 0 configures nothing.
    if [[ "${threshold}" == "0" ]]; then
        log_warn "PRSS-Mask threshold is 0: no legacy-schedule window is configured and the server"
        log_warn "logs no activation line, so there is nothing to confirm. Skipping the startup check."
        log_warn "If you meant to enable a legacy window, set LEGACY_PRSS_MASK_THRESHOLD to a non-zero value."
    else
        local _prss_unconfirmed=()
        local _expected="PRSS-Mask legacy schedule activation thresholds configured: requests with ID strictly below public=${threshold} / user=${threshold}"
        local _max_attempts=6
        for _id in "${_prss_ids[@]}"; do
            local i; i="$(echo "${_id}" | tr -d ' ')"
            [[ -z "${i}" ]] && continue
            local _pod; _pod="$(get_party_pod_name "${i}")"
            local _confirmed="false"
            local _logs _attempt
            for ((_attempt = 1; _attempt <= _max_attempts; _attempt++)); do
                # Read the whole stream into a variable and match in-shell. Piping into `grep -q`
                # would let grep exit on the first match and SIGPIPE `kubectl logs`, which under
                # this script's `set -o pipefail` makes the pipeline fail — turning a successful
                # match into a reported failure.
                _logs="$(kubectl logs "${_pod}" -n "${NAMESPACE}" --all-containers=true 2>/dev/null || true)"
                if [[ "${_logs}" == *"${_expected}"* ]]; then
                    _confirmed="true"
                    break
                fi
                if [[ "${_attempt}" -lt "${_max_attempts}" ]]; then
                    log_info "  Party ${i}: threshold startup line not present yet (attempt ${_attempt}/${_max_attempts})..."
                    sleep 10
                fi
            done
            if [[ "${_confirmed}" == "true" ]]; then
                log_info "  Party ${i}: PRSS-Mask threshold=${threshold} confirmed in startup log."
            else
                _prss_unconfirmed+=("${i}")
            fi
        done
        if [[ "${#_prss_unconfirmed[@]}" -gt 0 ]]; then
            log_error "PRSS-Mask threshold=${threshold} never appeared in the startup log of parties: ${_prss_unconfirmed[*]}"
            log_error "Those parties are running the fixed schedule while unpatched peers run the legacy one."
            log_error "Check that the value is set at kmsCore.thresholdMode.legacyPrssMask (not kmsCore.legacyPrssMask)."
            exit 1
        fi
        log_info "PRSS-Mask threshold enabled and confirmed on all upgraded parties."
    fi

    log_info "========================================="
    log_info "Rolling Upgrade Complete!"
    log_info "========================================="
}

main "$@"

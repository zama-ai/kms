#!/usr/bin/env bash

set -uo pipefail

PHASE="${1:-snapshot}"
NAMESPACE="${2:-${NAMESPACE:-kms-ci}}"
BASE_DIR="${NETWORK_DIAGNOSTICS_DIR:-network-diagnostics}"
OUT_DIR="${BASE_DIR}/${PHASE}"
COUNTERS_FILE="${OUT_DIR}/pod-interface-counters.tsv"
SUMMARY_FILE="${OUT_DIR}/summary.txt"

mkdir -p "${OUT_DIR}"

kubectl_exec() {
    if command -v timeout >/dev/null 2>&1; then
        timeout 20s kubectl exec "$@"
    else
        kubectl exec "$@"
    fi
}

epoch_from_iso() {
    date -d "$1" +%s 2>/dev/null \
        || date -j -u -f "%Y-%m-%dT%H:%M:%SZ" "$1" +%s 2>/dev/null
}

print_table() {
    local title="$1"
    shift
    echo "[network] ${title}"
    "$@" 2>/dev/null || true
}

capture_pod_counters() {
    printf 'pod\tcontainer\tiface\tmtu\trx_bytes\ttx_bytes\trx_packets\ttx_packets\trx_errors\ttx_errors\trx_dropped\ttx_dropped\n' \
        > "${COUNTERS_FILE}"

    mapfile -t pods < <(
        kubectl get pods -n "${NAMESPACE}" \
            -o jsonpath='{range .items[?(@.status.phase=="Running")]}{.metadata.name}{"\n"}{end}' \
            2>/dev/null | grep -E '^kms-core-[0-9]+-core-[0-9]+$' || true
    )

    for pod in "${pods[@]}"; do
        container="$(
            kubectl get pod "${pod}" -n "${NAMESPACE}" \
                -o jsonpath='{.spec.containers[0].name}' 2>/dev/null || true
        )"
        [[ -n "${container}" ]] || continue

        kubectl_exec -n "${NAMESPACE}" "${pod}" -c "${container}" -- sh -c '
            for iface_path in /sys/class/net/*; do
                iface="${iface_path##*/}"
                printf "%s\t%s\t%s\t" "$1" "$2" "${iface}"
                cat "${iface_path}/mtu" 2>/dev/null | tr "\n" "\t" || printf "\t"
                for stat in rx_bytes tx_bytes rx_packets tx_packets rx_errors tx_errors rx_dropped tx_dropped; do
                    cat "${iface_path}/statistics/${stat}" 2>/dev/null | tr "\n" "\t" || printf "\t"
                done
                printf "\n"
            done
        ' _ "${pod}" "${container}" >> "${COUNTERS_FILE}" 2>/dev/null || true
    done

    awk -F '\t' 'NR > 1 && $3 == "eth0" { n++ } END { print n + 0 }' "${COUNTERS_FILE}"
}

write_delta() {
    local before="${BASE_DIR}/before-perf/pod-interface-counters.tsv"
    local delta="${BASE_DIR}/pod-interface-counter-delta.tsv"
    [[ -f "${before}" && -f "${COUNTERS_FILE}" ]] || return 0

    awk -F '\t' '
        BEGIN {
            OFS = "\t"
            print "pod", "container", "iface", "mtu", "rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_errors", "tx_errors", "rx_dropped", "tx_dropped"
        }
        NR == FNR {
            if (FNR > 1) {
                key = $1 OFS $2 OFS $3
                for (i = 5; i <= 12; i++) {
                    before[key, i] = $i + 0
                }
            }
            next
        }
        FNR > 1 {
            key = $1 OFS $2 OFS $3
            print $1, $2, $3, $4, ($5 + 0) - before[key, 5], ($6 + 0) - before[key, 6], ($7 + 0) - before[key, 7], ($8 + 0) - before[key, 8], ($9 + 0) - before[key, 9], ($10 + 0) - before[key, 10], ($11 + 0) - before[key, 11], ($12 + 0) - before[key, 12]
        }
    ' "${before}" "${COUNTERS_FILE}" > "${delta}" 2>/dev/null || true
}

print_delta_summary() {
    local delta="${BASE_DIR}/pod-interface-counter-delta.tsv"
    local before_ts=""
    local after_ts=""
    local window_secs=0

    [[ -f "${delta}" ]] || return 0

    before_ts="$(sed -n 's/^captured_at=//p' "${BASE_DIR}/before-perf/summary.txt" 2>/dev/null | head -n 1)"
    after_ts="$(sed -n 's/^captured_at=//p' "${SUMMARY_FILE}" 2>/dev/null | head -n 1)"
    if [[ -n "${before_ts}" && -n "${after_ts}" ]]; then
        if before_epoch="$(epoch_from_iso "${before_ts}")" \
            && after_epoch="$(epoch_from_iso "${after_ts}")"; then
            window_secs=$((after_epoch - before_epoch))
        fi
    fi

    echo "[network] kms-core eth0 deltas since before-perf (window=${window_secs}s)"
    awk -F '\t' -v window_secs="${window_secs}" '
        function gib(bytes) { return bytes / 1024 / 1024 / 1024 }
        function gbps(bytes) {
            if (window_secs <= 0) {
                return 0
            }
            return bytes * 8 / window_secs / 1000000000
        }
        NR > 1 && $3 == "eth0" {
            pods++
            rx += $5
            tx += $6
            rx_packets += $7
            tx_packets += $8
            rx_errors += $9
            tx_errors += $10
            rx_dropped += $11
            tx_dropped += $12
            printf "[network] %-24s mtu=%s rx=%.2fGiB tx=%.2fGiB avg_rx=%.2fGbps avg_tx=%.2fGbps err=%s/%s drop=%s/%s\n", $1, $4, gib($5), gib($6), gbps($5), gbps($6), $9, $10, $11, $12
        }
        END {
            printf "[network] TOTAL kms-core eth0 pods=%d rx=%.2fGiB tx=%.2fGiB avg_rx=%.2fGbps avg_tx=%.2fGbps packets=%.0f/%.0f err=%.0f/%.0f drop=%.0f/%.0f\n", pods, gib(rx), gib(tx), gbps(rx), gbps(tx), rx_packets, tx_packets, rx_errors, tx_errors, rx_dropped, tx_dropped
        }
    ' "${delta}"
    echo "[network] note: this is pod-level KMS core traffic only. Per-rate core-client rx/tx is measured inside Argo and shown in the Slack report."
}

captured_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
{
    echo "phase=${PHASE}"
    echo "namespace=${NAMESPACE}"
    echo "captured_at=${captured_at}"
} > "${SUMMARY_FILE}"

echo "[network] ${PHASE}: namespace=${NAMESPACE} captured_at=${captured_at}"
print_table "nodes" kubectl get nodes \
    -o 'custom-columns=NAME:.metadata.name,INSTANCE:.metadata.labels.node\.kubernetes\.io/instance-type,NODEPOOL:.metadata.labels.karpenter\.sh/nodepool,ZONE:.metadata.labels.topology\.kubernetes\.io/zone'
print_table "kms-core pods" kubectl get pods -n "${NAMESPACE}" \
    -l app=kms-core \
    -o custom-columns=NAME:.metadata.name,PHASE:.status.phase,NODE:.spec.nodeName,IP:.status.podIP

pod_count="$(capture_pod_counters)"
echo "[network] captured eth counters for ${pod_count} running kms-core pods"

if [[ "${PHASE}" == "after-perf" ]]; then
    write_delta
    print_delta_summary
fi

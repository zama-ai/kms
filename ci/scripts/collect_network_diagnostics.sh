#!/usr/bin/env bash

set -uo pipefail

PHASE="${1:-snapshot}"
NAMESPACE="${2:-${NAMESPACE:-kms-ci}}"
BASE_DIR="${NETWORK_DIAGNOSTICS_DIR:-network-diagnostics}"
OUT_DIR="${BASE_DIR}/${PHASE}"
POD_NET_DIR="${OUT_DIR}/pod-network"

mkdir -p "${POD_NET_DIR}"

capture() {
    local file="$1"
    shift
    {
        echo "\$ $*"
        "$@"
    } > "${OUT_DIR}/${file}" 2>&1 || true
}

capture_shell() {
    local file="$1"
    shift
    {
        echo "\$ $*"
        bash -o pipefail -c "$*"
    } > "${OUT_DIR}/${file}" 2>&1 || true
}

safe_name() {
    printf '%s' "$1" | tr '/: ' '___'
}

kubectl_exec() {
    if command -v timeout >/dev/null 2>&1; then
        timeout 20s kubectl exec "$@"
    else
        kubectl exec "$@"
    fi
}

{
    echo "phase=${PHASE}"
    echo "namespace=${NAMESPACE}"
    echo "captured_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "deployment_type=${DEPLOYMENT_TYPE:-}"
    echo "tls=${TLS:-}"
    echo "core_tag=${KMS_CORE_IMAGE_TAG:-}"
    echo "client_tag=${KMS_CORE_CLIENT_IMAGE_TAG:-}"
    echo "github_run_id=${GITHUB_RUN_ID:-}"
    echo
    echo "Note: pod-level ethtool output does not expose host ENA allowance counters."
    echo "Host ENA allowance counters require a privileged node-level probe."
} > "${OUT_DIR}/summary.txt"

capture kubectl-contexts.txt kubectl config get-contexts
capture pods-wide.txt kubectl get pods -n "${NAMESPACE}" -o wide
capture jobs-wide.txt kubectl get jobs -n "${NAMESPACE}" -o wide
capture nodes-wide.txt kubectl get nodes -o wide
capture nodes-labels.txt kubectl get nodes --show-labels
capture_shell events-tail.txt "kubectl get events -n '${NAMESPACE}' --sort-by=.lastTimestamp | tail -200"
capture top-nodes.txt kubectl top nodes
capture top-pods.txt kubectl top pods -n "${NAMESPACE}"
capture pod-placement.tsv kubectl get pods -n "${NAMESPACE}" -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.phase}{"\t"}{.spec.nodeName}{"\t"}{range .spec.containers[*]}{.name}{","}{end}{"\n"}{end}'
capture node-placement.tsv kubectl get pods -n "${NAMESPACE}" -o custom-columns=NAME:.metadata.name,PHASE:.status.phase,NODE:.spec.nodeName,IP:.status.podIP
capture node-summary.tsv kubectl get nodes -o custom-columns=NAME:.metadata.name,INSTANCE:.metadata.labels.node\.kubernetes\.io/instance-type,NODEPOOL:.metadata.labels.karpenter\.sh/nodepool,ZONE:.metadata.labels.topology\.kubernetes\.io/zone

printf 'pod\tcontainer\tiface\tmtu\trx_bytes\ttx_bytes\trx_packets\ttx_packets\trx_errors\ttx_errors\trx_dropped\ttx_dropped\n' \
    > "${OUT_DIR}/pod-interface-counters.tsv"

mapfile -t running_pods < <(
    kubectl get pods -n "${NAMESPACE}" \
        -o jsonpath='{range .items[?(@.status.phase=="Running")]}{.metadata.name}{"\n"}{end}' \
        2>/dev/null || true
)

for pod in "${running_pods[@]}"; do
    mapfile -t containers < <(
        kubectl get pod "${pod}" -n "${NAMESPACE}" \
            -o jsonpath='{range .spec.containers[*]}{.name}{"\n"}{end}' \
            2>/dev/null || true
    )

    for container in "${containers[@]}"; do
        file_name="$(safe_name "${pod}_${container}").txt"
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
        ' _ "${pod}" "${container}" >> "${OUT_DIR}/pod-interface-counters.tsv" 2>/dev/null || true

        {
            echo "pod=${pod}"
            echo "container=${container}"
            echo "captured_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
            echo
            kubectl_exec -n "${NAMESPACE}" "${pod}" -c "${container}" -- sh -c '
                set +e
                echo "--- identity ---"
                hostname || true
                date -u +%Y-%m-%dT%H:%M:%SZ || true

                echo "--- interfaces ---"
                ls -l /sys/class/net || true
                for iface_path in /sys/class/net/*; do
                    iface="${iface_path##*/}"
                    echo "--- iface ${iface} ---"
                    printf "mtu="; cat "${iface_path}/mtu" 2>/dev/null || true
                    printf "speed="; cat "${iface_path}/speed" 2>/dev/null || true
                    for stat in rx_bytes tx_bytes rx_packets tx_packets rx_errors tx_errors rx_dropped tx_dropped; do
                        printf "%s=" "${stat}"
                        cat "${iface_path}/statistics/${stat}" 2>/dev/null || true
                    done
                done

                echo "--- /proc/net/dev ---"
                cat /proc/net/dev 2>/dev/null || true

                echo "--- sysctl ---"
                for key in \
                    /proc/sys/net/ipv4/tcp_congestion_control \
                    /proc/sys/net/ipv4/tcp_rmem \
                    /proc/sys/net/ipv4/tcp_wmem \
                    /proc/sys/net/core/rmem_max \
                    /proc/sys/net/core/wmem_max \
                    /proc/sys/net/core/somaxconn \
                    /proc/sys/net/ipv4/ip_local_port_range; do
                    printf "%s=" "${key}"
                    cat "${key}" 2>/dev/null || true
                done

                echo "--- ip ---"
                if command -v ip >/dev/null 2>&1; then
                    ip addr show || true
                    ip -s link || true
                    ip route || true
                else
                    echo "ip not found"
                fi

                echo "--- ss ---"
                if command -v ss >/dev/null 2>&1; then
                    ss -s || true
                else
                    echo "ss not found"
                fi

                echo "--- ethtool allowance counters if available ---"
                if command -v ethtool >/dev/null 2>&1; then
                    for iface_path in /sys/class/net/*; do
                        iface="${iface_path##*/}"
                        echo "--- ethtool -S ${iface} | grep -i allowance ---"
                        ethtool -S "${iface}" 2>/dev/null | grep -i allowance || true
                    done
                else
                    echo "ethtool not found"
                fi
            '
        } > "${POD_NET_DIR}/${file_name}" 2>&1 || true
    done
done

if [[ "${PHASE}" == "after-perf" && -f "${BASE_DIR}/before-perf/pod-interface-counters.tsv" ]]; then
    awk -F '\t' '
        BEGIN {
            OFS = "\t"
            print "pod", "container", "iface", "rx_bytes_delta", "tx_bytes_delta", "rx_packets_delta", "tx_packets_delta", "rx_errors_delta", "tx_errors_delta", "rx_dropped_delta", "tx_dropped_delta"
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
            print $1, $2, $3, ($5 + 0) - before[key, 5], ($6 + 0) - before[key, 6], ($7 + 0) - before[key, 7], ($8 + 0) - before[key, 8], ($9 + 0) - before[key, 9], ($10 + 0) - before[key, 10], ($11 + 0) - before[key, 11], ($12 + 0) - before[key, 12]
        }
    ' "${BASE_DIR}/before-perf/pod-interface-counters.tsv" \
      "${OUT_DIR}/pod-interface-counters.tsv" \
      > "${BASE_DIR}/pod-interface-counter-delta.tsv" 2>/dev/null || true
fi

echo "Network diagnostics written to ${OUT_DIR}"

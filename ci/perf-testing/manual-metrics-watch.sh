#!/usr/bin/env bash
#=============================================================================
# manual-metrics-watch.sh
#
# Live observations for the DKG preprocessing investigation.
#
# It shows, per party, refreshed every INTERVAL seconds:
#   - enclave CPU utilization  (kms_process_cpu_usage vs kms_total_cpus*100,
#                               measured INSIDE the enclave via :9646)
#   - 1-min load average       (kms_cpu_load)
#   - enclave memory           (kms_memory_usage / kms_total_memory)
#   - tunnel throughput        (kms_network_rx/tx_bytes_total deltas -> Gbps;
#                               inside the enclave the only iface is vsocktun,
#                               so this IS the tunnel traffic)
#   - tunnel CPU (parent side) (kubectl top: enclave-network-tunnel container)
#   - active MPC sessions      (kms_active_sessions)
# CPU utilization alone does not identify a bottleneck. A saturated worker pool
# can consume only a fraction of the enclave CPUs. Compare pools, queues and peers.
# READY_FILE appears after a successful scrape of every requested party in one round.
# STOP_FILE requests exit after the current complete round. A failed final scrape
# returns status 1. Neither marker file is necessary for interactive use.
#
# WHERE TO RUN: your laptop (needs kubectl + Tailscale to the cluster; metrics-
# server for the tunnel-CPU column). It scrapes each party's :9646 via a single
# in-cluster helper pod (`kubectl exec ... curl`) rather than `kubectl
# port-forward`, because port-forward's streaming is unreliable through the
# Tailscale API-server proxy ("lost connection to pod"). exec/attach works.
# The per-party ClusterIP service `kms-core-<i>-core-<i>` exposes :9646.
#
# Usage:
#   PARTIES="1 2" INTERVAL=5 bash manual-metrics-watch.sh
#   PARTIES="1 2 7" INTERVAL=10 LOG_FILE=run.log RAW_DIR=raw bash manual-metrics-watch.sh
#   (RAW_DIR keeps the raw /metrics pages per tick; `analyse_run.py summarize` turns them into
#    run averages — manual-run-experiment.sh sets both for you)
#=============================================================================

set -uo pipefail

NAMESPACE="${NAMESPACE:-kms-ci-titouantanguy-773}"
PARTIES="${PARTIES:-1 2 3 4 5 6 7 8 9 10 11 12 13}"
INTERVAL="${INTERVAL:-5}"               # refresh seconds
POD_TMPL="${POD_TMPL:-kms-core-%s-core-%s}"   # pod AND service name template (party id x2)
TUNNEL_CONTAINER="${TUNNEL_CONTAINER:-enclave-network-tunnel}"
METRICS_PORT="${METRICS_PORT:-9646}"
NIC_GBPS="${NIC_GBPS:-25}"              # c7a.16xlarge nominal NIC ceiling, for context
HELPER_IMAGE="${HELPER_IMAGE:-curlimages/curl}"
HELPER="${HELPER:-metrics-watch-$$}"    # in-cluster scrape pod (unique per run)
LOG_FILE="${LOG_FILE:-}"                # if set, append each tick (plain text, no screen-clear) here for later review
RAW_DIR="${RAW_DIR:-}"                  # if set, keep every scraped /metrics page as RAW_DIR/p<i>/<epoch>.prom (analyse_run.py reads these)
READY_FILE="${READY_FILE:-}"
STOP_FILE="${STOP_FILE:-}"

command -v python3 >/dev/null || { echo "python3 not found" >&2; exit 1; }

STATE_DIR="$(mktemp -d)"

cleanup() {
  trap - INT TERM EXIT   # disarm so this can't re-enter / double-run
  echo; echo "removing helper pod ${HELPER}..."
  kubectl --request-timeout=15s delete pod "${HELPER}" -n "${NAMESPACE}" --now --wait=false --ignore-not-found >/dev/null 2>&1
  rm -rf "${STATE_DIR}" 2>/dev/null
}
# On Ctrl-C/TERM: clean up AND exit (without the explicit exit the INT trap
# returns into the `while true` loop and the terminal never comes back).
trap 'cleanup; exit 130' INT TERM
trap cleanup EXIT

pod_of() { printf "${POD_TMPL}" "$1" "$1"; }

# --- launch the in-cluster scrape helper -----------------------------------
echo "launching in-cluster scrape helper (${HELPER_IMAGE}) as pod/${HELPER} in ${NAMESPACE}..."
kubectl --request-timeout=15s run "${HELPER}" -n "${NAMESPACE}" --image="${HELPER_IMAGE}" --restart=Never \
  --command -- sleep 100000000 >/dev/null 2>&1 || true
if ! kubectl --request-timeout=65s wait --for=condition=Ready "pod/${HELPER}" -n "${NAMESPACE}" --timeout=60s >/dev/null 2>&1; then
  echo "ERROR: helper pod ${HELPER} did not become Ready. Recent status:"
  kubectl --request-timeout=10s get pod "${HELPER}" -n "${NAMESPACE}" 2>&1 | sed 's/^/    /'
  exit 1
fi
echo "helper ready; scraping parties: ${PARTIES}"

# --- helpers ---------------------------------------------------------------
# value of a prometheus metric (handles optional {labels}); prints the last field
mval() { grep "^$2[ {]" "$1" 2>/dev/null | grep -v '^#' | head -1 | awk '{print $NF}'; }
# value of a labelled prometheus metric: mlv <file> <name> <label-fragment>, e.g. 'pool="tokio"'
mlv() { grep "^$2{" "$1" 2>/dev/null | grep -F -- "$3" | head -1 | awk '{print $NF}'; }
# sum of a labelled metric over all series whose labels contain the fragment
msum() { grep "^$2{" "$1" 2>/dev/null | grep -F -- "$3" | awk '{s+=$NF} END{printf "%d", s}'; }

# Per-party counter deltas for the diagnostic block (bench instrumentation):
# `dstate` holds the previous tick's values as "key value" lines.
declare -A PREV
load_prev()  { PREV=(); [ -f "$1" ] && while read -r k v; do PREV["$k"]="$v"; done < "$1"; }
# delta <key> <current-value>: prints current - previous (or "n/a" on the first tick) and records
# the current value in $NEXT_FILE (a file, since this runs inside command substitutions).
delta() {
  local key="$1" cur="${2:-}" prev
  [ -z "$cur" ] && { echo "n/a"; return; }
  prev="${PREV[$key]:-}"
  echo "$key $cur" >> "$NEXT_FILE"
  if [ -z "$prev" ]; then echo "n/a"; else awk -v a="$cur" -v b="$prev" 'BEGIN{ if(a<b) print "n/a"; else printf "%.6f", a-b }'; fi
}
# phase_rate <file> <phase> <window-secs>: session-seconds of that phase per wall-second over the window
phase_rate() {
  local d
  d="$(delta "phase_$2" "$(mlv "$1" kms_dkg_phase_duration_microseconds_total "phase=\"$2\"")")"
  [ "$d" = "n/a" ] && { echo "n/a"; return; }
  awk -v us="$d" -v dt="$3" 'BEGIN{ if(dt>0) printf "%.1f", us/1e6/dt; else print "n/a" }'
}

fmt_gib() { awk -v b="${1:-0}" 'BEGIN{ if(b=="")b=0; printf "%.1f", b/1024/1024/1024 }'; }

# --- main loop -------------------------------------------------------------
while true; do
  frame="${STATE_DIR}/frame.txt"
  round_failed=0
  {   # render the whole tick into a frame, so we can both display AND log it
  echo "================================================================================"
  echo " KMS enclave metrics — $(date -u '+%Y-%m-%d %H:%M:%SZ')   (refresh ${INTERVAL}s, Ctrl-C to stop)"
  echo " CPU, queues and network are observations; aggregate CPU does not identify the bottleneck."
  echo "================================================================================"

  for i in ${PARTIES}; do
    pod="$(pod_of "$i")"   # pod name == ClusterIP service name (exposes :9646)
    m="${STATE_DIR}/metrics-p${i}.txt"
    err="${STATE_DIR}/err-p${i}.log"

    if ! kubectl --request-timeout=10s exec -n "${NAMESPACE}" "${HELPER}" -- \
           curl -fsS -m 5 "http://${pod}:${METRICS_PORT}/metrics" > "$m" 2>"$err" \
       || ! grep -q '^kms_total_cpus[ {]' "$m"; then
      round_failed=1
      echo
      echo "party ${i}  (${pod})   metrics UNAVAILABLE — exec/curl says:"
      echo "    $(tail -1 "$err" 2>/dev/null || echo '(no error output)')"
      continue
    fi
    scrape_epoch="$(python3 -c 'import time; print(f"{time.time():.6f}")')"
    if [ -n "${RAW_DIR}" ]; then
      mkdir -p "${RAW_DIR}/p${i}" && cp "$m" "${RAW_DIR}/p${i}/${scrape_epoch}.prom.part" \
        && mv "${RAW_DIR}/p${i}/${scrape_epoch}.prom.part" "${RAW_DIR}/p${i}/${scrape_epoch}.prom" \
        || round_failed=1
    fi

    total_cpus="$(mval "$m" kms_total_cpus)"
    proc_cpu="$(mval "$m" kms_process_cpu_usage)"
    load="$(mval "$m" kms_cpu_load)"
    mem_used="$(mval "$m" kms_memory_usage)"
    mem_total="$(mval "$m" kms_total_memory)"
    rx="$(mval "$m" kms_network_rx_bytes_total)"
    tx="$(mval "$m" kms_network_tx_bytes_total)"
    sess="$(mval "$m" kms_active_sessions)"
    : "${total_cpus:=0}" "${proc_cpu:=0}" "${load:=0}" "${rx:=0}" "${tx:=0}" "${sess:=0}"

    # utilization = process cpu% / (cores * 100)
    util="$(awk -v p="$proc_cpu" -v c="$total_cpus" 'BEGIN{ if(c>0) printf "%.0f", (p/(c*100))*100; else print "0" }')"

    # network throughput from counter deltas
    sf="${STATE_DIR}/net-p${i}"
    now="${scrape_epoch%.*}"
    rxg="n/a"; txg="n/a"
    if [ -f "$sf" ]; then
      read -r p_ts p_rx p_tx < "$sf"
      rxg="$(awk -v a="$rx" -v b="$p_rx" -v dt=$((now - p_ts)) 'BEGIN{ if(dt>0 && a>=b) printf "%.2f", (a-b)*8/dt/1e9; else print "n/a" }')"
      txg="$(awk -v a="$tx" -v b="$p_tx" -v dt=$((now - p_ts)) 'BEGIN{ if(dt>0 && a>=b) printf "%.2f", (a-b)*8/dt/1e9; else print "n/a" }')"
    fi
    echo "$now $rx $tx" > "$sf"

    # tunnel CPU (parent side) via kubectl top; best-effort
    tcpu="$(kubectl --request-timeout=10s top pod "$pod" -n "${NAMESPACE}" --containers --no-headers 2>/dev/null \
            | awk -v c="${TUNNEL_CONTAINER}" '$2==c{print $3}')"
    : "${tcpu:=n/a}"

    # --- bench diagnostics (kms_* series added by the instrumentation; "n/a" on older images) ---
    dstate="${STATE_DIR}/diag-p${i}"
    load_prev "$dstate"
    NEXT_FILE="${dstate}.next"; : > "$NEXT_FILE"
    dt=$(( now - ${PREV[ts]:-now} ))
    echo "ts $now" >> "$NEXT_FILE"
    tokio_c="$(awk -v v="$(mlv "$m" kms_thread_pool_cpu_usage 'pool="tokio"')" 'BEGIN{ if(v=="")print "n/a"; else printf "%.1f", v/100 }')"
    rayon_c="$(awk -v v="$(mlv "$m" kms_thread_pool_cpu_usage 'pool="rayon"')" 'BEGIN{ if(v=="")print "n/a"; else printf "%.1f", v/100 }')"
    vsock_c="$(awk -v v="$(mlv "$m" kms_named_process_cpu_usage 'process="vsocktun"')" 'BEGIN{ if(v=="")print "n/a"; else printf "%.1f", v/100 }')"
    queued="$(mval "$m" kms_c2c_sender_queued_messages)"; : "${queued:=n/a}"
    rpc_n="$(delta rpc16_count "$(mlv "$m" kms_c2c_send_rpc_duration_ms_count 'size_bucket="le_16m"')")"
    rpc_s="$(delta rpc16_sum "$(mlv "$m" kms_c2c_send_rpc_duration_ms_sum 'size_bucket="le_16m"')")"
    rpc_avg="$(awk -v n="$rpc_n" -v s="$rpc_s" 'BEGIN{ if(n=="n/a"||n+0==0) print "n/a"; else printf "%.0f", s/n }')"
    opt_hit="$(delta opt_hit "$(msum "$m" kms_optimistic_reconstruct_total 'outcome="hit"')")"
    opt_dec="$(delta opt_declined "$(msum "$m" kms_optimistic_reconstruct_total 'outcome="declined"')")"
    opt_inc="$(delta opt_inconsistent "$(msum "$m" kms_optimistic_reconstruct_total 'outcome="inconsistent"')")"
    opt_fail="$(delta opt_failed "$(msum "$m" kms_optimistic_reconstruct_total 'outcome="failed"')")"
    opt_pct="$(awk -v h="$opt_hit" -v d="$opt_dec" -v i="$opt_inc" 'BEGIN{ t=h+d+i; if(h=="n/a"||t==0) print "n/a"; else printf "%.1f%% hit / %.1f%% declined / %.1f%% inconsistent", 100*h/t, 100*d/t, 100*i/t }')"
    drop_rx="$(delta drop_rx "$(msum "$m" kms_net_iface_dropped_total 'dir="rx"')")"
    drop_tx="$(delta drop_tx "$(msum "$m" kms_net_iface_dropped_total 'dir="tx"')")"
    tcp_re="$(delta tcp_retrans "$(mlv "$m" kms_tcp_segs_total 'kind="retrans"')")"
    tcp_out="$(delta tcp_out "$(mlv "$m" kms_tcp_segs_total 'kind="out"')")"
    ph_prss="$(phase_rate "$m" prss "$dt")"
    ph_recv="$(phase_rate "$m" bcast_recv "$dt")"
    ph_echo="$(phase_rate "$m" bcast_echo_wait "$dt")"
    ph_votes="$(phase_rate "$m" bcast_votes "$dt")"
    ph_recons="$(phase_rate "$m" recons_d "$dt")"
    ph_mult="$(phase_rate "$m" mult_open "$dt")"
    ph_openv="$(phase_rate "$m" open_v "$dt")"
    ph_solve="$(phase_rate "$m" solve "$dt")"
    ph_agg="$(phase_rate "$m" aggregator_send "$dt")"
    mv -f "$NEXT_FILE" "$dstate"

    echo
    echo "party ${i}  (${pod})  scrape epoch ${scrape_epoch}"
    printf "  enclave cores        : %s\n" "${total_cpus}"
    printf "  enclave CPU          : %s%%   => utilization %s%% of %s%%\n" \
      "${proc_cpu}" "${util}" "$(awk -v c="$total_cpus" 'BEGIN{print c*100}')"
    printf "  load (1m / cores)    : %s\n" "${load}"
    printf "  enclave memory       : %s / %s GiB\n" "$(fmt_gib "$mem_used")" "$(fmt_gib "$mem_total")"
    printf "  tunnel throughput    : rx %s  tx %s  Gbps   (NIC ~%s Gbps)\n" "${rxg}" "${txg}" "${NIC_GBPS}"
    printf "  tunnel CPU (parent)  : %s   [container %s]\n" "${tcpu}" "${TUNNEL_CONTAINER}"
    printf "  active MPC sessions  : %s\n" "${sess}"
    printf "  thread pools (cores) : tokio %s   rayon %s   | enclave-side vsocktun %s cores\n" "${tokio_c}" "${rayon_c}" "${vsock_c}"
    printf "  c2c sender           : %s msgs queued | 1-16 MB RPCs this tick: %s, avg %s ms\n" "${queued}" "${rpc_n}" "${rpc_avg}"
    printf "  phases (session-s/s) : prss %s | bcast_recv %s | echo_wait %s | votes %s | recons_d %s | mult_open %s | open_v %s | solve %s | agg_send %s\n" \
      "${ph_prss}" "${ph_recv}" "${ph_echo}" "${ph_votes}" "${ph_recons}" "${ph_mult}" "${ph_openv}" "${ph_solve}" "${ph_agg}"
    printf "  optimistic recons    : %s (failed %s)\n" "${opt_pct}" "${opt_fail}"
    printf "  packets this tick    : iface drops rx %s tx %s | tcp retrans %s of %s out segs\n" "${drop_rx}" "${drop_tx}" "${tcp_re}" "${tcp_out}"
  done
  } > "${frame}"

  printf '\033[2J\033[H'                               # clear the terminal only (not the log)
  cat "${frame}"
  [ -n "${LOG_FILE}" ] && cat "${frame}" >> "${LOG_FILE}"

  if [ "${round_failed}" = "0" ] && [ -n "${READY_FILE}" ] && [ ! -e "${READY_FILE}" ]; then
    printf '%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "${READY_FILE}"
  fi
  if [ -n "${STOP_FILE}" ] && [ -e "${STOP_FILE}" ]; then
    [ "${round_failed}" = "0" ] || echo "ERROR: final scrape round incomplete" >&2
    exit "${round_failed}"
  fi

  sleep "${INTERVAL}"
done

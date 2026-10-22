#!/usr/bin/env python3
"""Offline analysis of a diagnostic run (stdlib only, Python 3.8+).

A run directory is what manual-run-experiment.sh leaves behind:

    <RUN_DIR>/manifest.json          knobs, images, times (written by the orchestrator)
    <RUN_DIR>/core/core-<i>.log      the 13 core logs (manual-capture-core-logs.sh)
    <RUN_DIR>/raw/p<i>/<epoch>.prom  one /metrics snapshot per tick and party (manual-metrics-watch.sh RAW_DIR)
    <RUN_DIR>/client/*.log           the kms-core-client logs of the driver

Subcommands:

    progress <core.log|->  [--tracker NAME]
        Latest "Progress <tracker>" of the log (stdin with "-"). With --tracker prints
        "<pct> <elapsed_s>" (or "0 0" when absent) for scripts; otherwise one line per tracker.
    summarize <RUN_DIR> [--stop-pct N]
        Writes summary.md and summary.json within the run directory.
    bw <core-*.log ...>
        Per-party throughput from the "Bandwidth benchmark session" lines (manual-bandwidth-bench.sh).
    compare <RUNS_DIR | summary.csv> [--csv FILE]
        Reads per-run summaries and optionally exports one aggregate CSV.

Everything degrades gracefully: a run on an image without the instrumentation only has the
tracker timeline and the pre-existing metrics (CPU, network, sessions).
"""

import csv
import glob
import json
import math
import os
import re
import statistics
import sys
import tempfile
from collections import defaultdict
from datetime import datetime

ANSI = re.compile(r"\x1b\[[0-9;]*m")
KUBE_TS = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z)\s")
PROGRESS = re.compile(r"Progress (\w+):")
FINISHED = re.compile(r"Finished (\w+):")
PCT = re.compile(r"Percentage done:\s*([0-9.]+)")
ELAPSED = re.compile(r"Time elapsed \(s\):\s*(\d+)")
TOTAL = re.compile(r"Total:\s*(\d+)")
PHASE_LINE = re.compile(r"DKG phase timers over the last (\d+) batches \(([0-9.]+) s\): (.*)$")
PHASE_ITEM = re.compile(
    r"(\w+): ([0-9.]+) s total over (\d+) obs \(([0-9.]+) ms avg, ([0-9.]+) session-s per wall-s\)"
)
TUNING = re.compile(r"tuning: exporting (\S+=\S*)")
H2 = re.compile(r"Core-to-core HTTP/2 settings: (.*)$")
BENCH = re.compile(r"Bandwidth benchmark session (\d+)/(\d+) finished after ([0-9.]+) s: (.*)$")
BENCH_PEER = re.compile(
    r"(\d+): ([0-9.]+) MiB in ([0-9.]+) s \(([0-9.]+) MiB/s, (\d+) sends, (\d+) timeouts, (\d+) errors\)"
)
BENCH_CREATED = re.compile(r"Bandwidth benchmark: (\d+) sessions created after ([0-9.]+) s, sending (\d+)-byte")
BENCH_AGGREGATE = re.compile(
    r"Bandwidth benchmark aggregate: status=([\w-]+) sessions=(\d+)/(\d+) acknowledged_bytes=(\d+) "
    r"attempts=(\d+) successes=(\d+) timeouts=(\d+) errors=(\d+) elapsed_s=([0-9.]+)"
)
LEVEL = re.compile(r"\b(WARN|ERROR)\b")

# Phases of a preprocessing batch (the two envelopes overlap the others and are reported apart).
PHASES = ["prss", "bcast_send", "bcast_recv", "bcast_echo_wait", "bcast_votes", "recons_d",
          "mult_open", "open_v", "solve", "aggregator_send"]
ENVELOPES = ["triple_batch", "bit_batch"]
RPC_BUCKETS = ["le_4k", "le_64k", "le_1m", "le_16m", "gt_16m"]


# --------------------------------------------------------------------------- core logs
def clean(line):
    line = ANSI.sub("", line.rstrip("\n"))
    ts = None
    m = KUBE_TS.match(line)
    if m:
        ts = m.group(1)
        line = line[m.end():]
    return ts, line


def parse_core_log(path, start_epoch=None, end_epoch=None):
    """Everything useful in one core log, in one pass."""
    out = {
        "progress": defaultdict(list),   # tracker -> [(ts, pct, elapsed)]
        "totals": {},                    # tracker -> total items (triples, bits, ...)
        "finished": {},                  # tracker -> elapsed
        "phase_lines": [],               # [{"ts", "every", "window_s", "phases": {label: (total_s, obs, avg_ms, sps)}}]
        "tuning": [],
        "h2": None,
        "bench": [],                     # [(idx, n, t, [(peer, mib, s, mibps, sends, timeouts, errors)])]
        "bench_created": None,
        "bench_aggregate": None,
        "warn": 0, "error": 0, "unheard": 0,
        "errors_by_kind": defaultdict(int),
        "first_ts": None, "last_ts": None,
    }
    stream = sys.stdin if path == "-" else open(path, errors="replace")
    lines = stream.read().splitlines()
    if path != "-":
        stream.close()
    pending = None  # (kind, tracker, ts) waiting for its Percentage/Time lines
    for raw in lines:
        ts, line = clean(raw)
        if ts and (start_epoch is not None or end_epoch is not None):
            epoch = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
            if (start_epoch is not None and epoch < start_epoch) or (end_epoch is not None and epoch > end_epoch):
                pending = None
                continue
        if ts:
            out["first_ts"] = out["first_ts"] or ts
            out["last_ts"] = ts
        m = PROGRESS.search(line)
        if m:
            pending = ["progress", m.group(1), ts, None, None]
            continue
        m = FINISHED.search(line)
        if m:
            pending = ["finished", m.group(1), ts, 100.0, None]
            continue
        if pending is not None:
            m = TOTAL.search(line)
            if m:
                out["totals"][pending[1]] = int(m.group(1))
            m = PCT.search(line)
            if m:
                pending[3] = float(m.group(1))
            m = ELAPSED.search(line)
            if m:
                pending[4] = int(m.group(1))
            if pending[3] is not None and pending[4] is not None:
                kind, tracker, pts, pct, elapsed = pending
                if kind == "progress":
                    out["progress"][tracker].append((pts, pct, elapsed))
                else:
                    out["finished"][tracker] = elapsed
                    out["progress"][tracker].append((pts, 100.0, elapsed))
                pending = None
            elif "Expected time remaining" in line or "Progress" in line:
                pending = None
        m = PHASE_LINE.search(line)
        if m:
            phases = {}
            for item in m.group(3).split(" | "):
                pm = PHASE_ITEM.search(item)
                if pm:
                    phases[pm.group(1)] = (float(pm.group(2)), int(pm.group(3)), float(pm.group(4)), float(pm.group(5)))
            out["phase_lines"].append({"ts": ts, "every": int(m.group(1)), "window_s": float(m.group(2)), "phases": phases})
            continue
        m = TUNING.search(line)
        if m:
            out["tuning"].append(m.group(1))
            continue
        m = H2.search(line)
        if m:
            out["h2"] = m.group(1).strip()
            continue
        m = BENCH.search(line)
        if m:
            peers = [(int(p[0]), float(p[1]), float(p[2]), float(p[3]), int(p[4]), int(p[5]), int(p[6]))
                     for p in BENCH_PEER.findall(m.group(4))]
            out["bench"].append((int(m.group(1)), int(m.group(2)), float(m.group(3)), peers))
            continue
        m = BENCH_CREATED.search(line)
        if m:
            out["bench_created"] = (int(m.group(1)), float(m.group(2)), int(m.group(3)))
            continue
        m = BENCH_AGGREGATE.search(line)
        if m:
            names = ("completed_sessions", "requested_sessions", "acknowledged_bytes", "attempts", "successes", "timeouts", "errors")
            out["bench_aggregate"] = dict(zip(names, (int(v) for v in m.groups()[1:8])),
                                          status=m.group(1), elapsed_s=float(m.group(9)))
            continue
        m = LEVEL.search(line)
        if m:
            if m.group(1) == "WARN":
                out["warn"] += 1
            else:
                out["error"] += 1
                # kind = the message after "<file>.rs:<line>: ", with ids/numbers blanked, first 90 chars
                tail = line[m.end():]
                fm = re.search(r"\S+\.rs:\d+:\s*", tail)
                if fm:
                    tail = tail[fm.end():]
                tail = re.sub(r"\b[0-9a-f]{32,}\b", "<id>", tail)
                tail = re.sub(r"\d+", "N", tail)
                out["errors_by_kind"][tail.strip()[:90]] += 1
            if "haven't heard from" in line:
                out["unheard"] += 1
    return out


def latest_progress(parsed):
    """tracker -> (pct, elapsed, ts) of its last line."""
    res = {}
    for tracker, points in parsed["progress"].items():
        if points:
            ts, pct, elapsed = points[-1]
            res[tracker] = (pct, elapsed, ts)
    return res


def time_to_pct(points, target):
    """Elapsed seconds at which the tracker crossed `target` %, linearly interpolated; None if not reached."""
    prev = (0.0, 0)
    for _, pct, elapsed in points:
        if pct >= target:
            p0, e0 = prev
            if pct == p0:
                return elapsed
            return e0 + (target - p0) * (elapsed - e0) / (pct - p0)
        prev = (pct, elapsed)
    return None


# --------------------------------------------------------------------------- prometheus snapshots
SAMPLE = re.compile(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})?\s+(\S+)')
LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"')


def parse_prom(path):
    series = defaultdict(list)  # name -> [(labels, value)]
    with open(path, errors="replace") as f:
        for line in f:
            if not line or line[0] == "#":
                continue
            m = SAMPLE.match(line)
            if not m:
                continue
            labels = dict(LABEL.findall(m.group(2) or ""))
            try:
                value = float(m.group(3))
            except ValueError:
                continue
            if not math.isfinite(value):
                continue
            series[m.group(1)].append((labels, value))
    return series


def pick(snap, name, **want):
    """Sum of the series `name` whose labels contain `want` (None when absent)."""
    found = False
    total = 0.0
    for labels, value in snap.get(name, []):
        if all(labels.get(k) == v for k, v in want.items()):
            total += value
            found = True
    return total if found else None


def mean(xs):
    xs = [x for x in xs if x is not None]
    return statistics.fmean(xs) if xs else None


def fmt(x, nd=1, unit=""):
    if x is None:
        return "n/a"
    if isinstance(x, float):
        return f"{x:.{nd}f}{unit}"
    return f"{x}{unit}"


def weighted_mean(samples):
    """Returns the mean of (value, seconds) pairs with available values."""
    samples = [(value, seconds) for value, seconds in samples if value is not None and seconds > 0]
    duration = sum(seconds for _, seconds in samples)
    return sum(value * seconds for value, seconds in samples) / duration if duration else None


def weighted_p95(samples):
    """Returns the duration-weighted 95th percentile of sampled values."""
    samples = sorted((value, seconds) for value, seconds in samples if value is not None and seconds > 0)
    threshold = 0.95 * sum(seconds for _, seconds in samples)
    elapsed = 0.0
    for value, seconds in samples:
        elapsed += seconds
        if elapsed >= threshold:
            return value
    return None


def summarise_party_metrics(raw_dir, start_epoch=None, end_epoch=None, scrape_interval_seconds=None):
    """All the per-party numbers from the snapshot series under raw/p<i>/."""
    files = sorted(glob.glob(os.path.join(raw_dir, "*.prom")), key=lambda p: float(os.path.basename(p)[:-5]))
    snaps = [(float(os.path.basename(p)[:-5]), parse_prom(p)) for p in files]
    snaps = [(t, s) for t, s in snaps if (start_epoch is None or t >= start_epoch)
             and (end_epoch is None or t <= end_epoch)]
    if len(snaps) < 2:
        return None
    t0, first = snaps[0]
    t1, last = snaps[-1]
    window = t1 - t0
    if window <= 0:
        return None
    res = {"ticks": len(snaps), "window_s": window, "first_epoch": t0, "last_epoch": t1,
           "status": "valid", "invalid_reasons": [], "warnings": []}
    res["max_scrape_gap_s"] = max(right[0] - left[0] for left, right in zip(snaps, snaps[1:]))
    if scrape_interval_seconds is not None:
        allowance = max(3 * scrape_interval_seconds, 30)
        res["coverage"] = {"requested_start_epoch": start_epoch, "requested_end_epoch": end_epoch,
                           "max_allowed_gap_s": allowance, "start_lag_s": t0 - start_epoch,
                           "end_lag_s": end_epoch - t1}
        if t0 > start_epoch + allowance:
            res["invalid_reasons"].append(f"first scrape is {t0 - start_epoch:.3f}s after window start; maximum {allowance:g}s")
        if t1 < end_epoch - allowance:
            res["invalid_reasons"].append(f"last scrape is {end_epoch - t1:.3f}s before window end; maximum {allowance:g}s")
        if res["max_scrape_gap_s"] > allowance:
            res["invalid_reasons"].append(f"scrape gap is {res['max_scrape_gap_s']:.3f}s; maximum {allowance:g}s")
    identities = [pick(s, "kms_process_start_time_seconds") or pick(s, "process_start_time_seconds")
                  for _, s in snaps]
    stable_identity = all(identity is not None for identity in identities) and len(set(identities)) == 1
    if len({identity for identity in identities if identity is not None}) > 1:
        res["invalid_reasons"].append("process identity changed within the measurement window")
    elif not stable_identity:
        res["warnings"].append("process identity unavailable for part of the measurement window")

    # A reset can occur between the endpoints even when their net delta stays positive.
    counter_names = {
        "kms_network_tx_bytes_total", "kms_network_rx_bytes_total",
        "kms_dkg_phase_duration_microseconds_total", "kms_dkg_phase_observations_total",
        "kms_optimistic_reconstruct_total", "kms_c2c_send_rpc_duration_ms_count",
        "kms_c2c_send_rpc_duration_ms_sum", "kms_c2c_send_rpc_duration_ms_bucket", "kms_tcp_segs_total", "kms_net_iface_dropped_total",
        "kms_thread_pool_cpu_seconds_total", "kms_dkg_generated_items_total", "kms_process_cpu_seconds_total",
        "kms_dkg_detail_duration_seconds_total", "kms_dkg_detail_observations_total",
        "kms_network_debug_events_total",
    }
    previous = {}
    for _, snap in snaps:
        current = {(name, tuple(sorted(labels.items()))): value
                   for name in counter_names for labels, value in snap.get(name, [])}
        for key, old in previous.items():
            if key not in current:
                res["invalid_reasons"].append(f"counter disappeared: {key}")
            elif current[key] < old:
                res["invalid_reasons"].append(f"counter decreased: {key}")
        previous = current
    res["invalid_reasons"] = sorted(set(res["invalid_reasons"]))
    if res["invalid_reasons"]:
        res["status"] = "invalid"
        return res
    if not stable_identity:
        res["status"] = "exploratory"

    # gauges over the run
    utils, tokio, rayon, other, vsock, sess, queued, mem = [], [], [], [], [], [], [], []
    tx_rates, rx_rates = [], []
    prev = None
    for index, (t, s) in enumerate(snaps):
        weight = snaps[index + 1][0] - t if index + 1 < len(snaps) else 0
        cpus = pick(s, "kms_total_cpus")
        proc = pick(s, "kms_process_cpu_usage")
        if cpus and proc is not None:
            utils.append((proc / cpus, weight))
        tokio.append((pick(s, "kms_thread_pool_cpu_usage", pool="tokio"), weight))
        rayon.append((pick(s, "kms_thread_pool_cpu_usage", pool="rayon"), weight))
        other.append((pick(s, "kms_thread_pool_cpu_usage", pool="other"), weight))
        vsock.append((pick(s, "kms_named_process_cpu_usage", process="vsocktun"), weight))
        sess.append((pick(s, "kms_active_sessions"), weight))
        queued.append((pick(s, "kms_c2c_sender_queued_messages"), weight))
        mem.append((pick(s, "kms_memory_usage"), weight))
        if prev is not None:
            pt, ps = prev
            dt = t - pt
            if dt > 0:
                for name, acc in (("kms_network_tx_bytes_total", tx_rates), ("kms_network_rx_bytes_total", rx_rates)):
                    a, b = pick(s, name), pick(ps, name)
                    if a is not None and b is not None:
                        acc.append(((a - b) * 8 / dt / 1e9, dt))
        prev = (t, s)
    res["cpus"] = pick(last, "kms_total_cpus")
    res["util_pct"] = weighted_mean(utils)
    res["util_p95"] = weighted_p95(utils)
    for key, acc in (("tokio", tokio), ("rayon", rayon), ("other", other), ("vsocktun", vsock)):
        res[f"{key}_cores"] = None if weighted_mean(acc) is None else weighted_mean(acc) / 100
        res[f"{key}_cores_p95"] = None if weighted_p95(acc) is None else weighted_p95(acc) / 100
    res["sessions"] = weighted_mean(sess)
    res["queued_mean"] = weighted_mean(queued)
    res["queued_max"] = max((q for q, _ in queued if q is not None), default=None)
    res["mem_gib"] = None if weighted_mean(mem) is None else weighted_mean(mem) / 2**30
    res["tx_gbps"] = weighted_mean(tx_rates)
    res["tx_gbps_p95"] = weighted_p95(tx_rates)
    res["rx_gbps"] = weighted_mean(rx_rates)
    res["rx_gbps_p95"] = weighted_p95(rx_rates)

    def delta(name, **labels):
        a, b = pick(last, name, **labels), pick(first, name, **labels)
        if a is None:
            return None
        if b is None and not stable_identity:
            res["warnings"].append(f"initial zero assumed for {name} {labels}; process identity unavailable")
        return a - (b or 0)

    # phases
    phases = {}
    total_us = 0.0
    for ph in PHASES + ENVELOPES:
        dus = delta("kms_dkg_phase_duration_microseconds_total", phase=ph)
        dobs = delta("kms_dkg_phase_observations_total", phase=ph)
        if dus is None:
            continue
        phases[ph] = {"us": dus, "obs": dobs or 0, "sps": dus / 1e6 / window,
                      "avg_ms": (dus / 1e3 / dobs) if dobs else None}
        if ph in PHASES:
            total_us += dus
    for ph, d in phases.items():
        d["share"] = (d["us"] / total_us * 100) if (total_us and ph in PHASES) else None
    res["phases"] = phases
    res["phase_total_sps"] = total_us / 1e6 / window if total_us else None

    # optimistic reconstruction
    opt = {}
    for site in ("robust_open", "d_values", "unspecified"):
        counts = {o: delta("kms_optimistic_reconstruct_total", site=site, outcome=o)
                  for o in ("hit", "declined", "inconsistent", "failed", "disabled")}
        if all(v is None for v in counts.values()):
            continue
        counts = {k: (v or 0) for k, v in counts.items()}
        tried = counts["hit"] + counts["declined"] + counts["inconsistent"]
        opt[site] = dict(counts, tried=tried, hit_pct=(100 * counts["hit"] / tried) if tried else None)
    res["optimistic"] = opt

    # RPC latency by size bucket
    rpc = {}
    for b in RPC_BUCKETS:
        n = delta("kms_c2c_send_rpc_duration_ms_count", size_bucket=b)
        s = delta("kms_c2c_send_rpc_duration_ms_sum", size_bucket=b)
        if n:
            rpc[b] = {"n": n, "avg_ms": s / n}
            buckets = sorted({float(labels["le"]) for labels, _ in last.get("kms_c2c_send_rpc_duration_ms_bucket", [])
                              if labels.get("size_bucket") == b and "le" in labels})
            for quantile in (50, 95, 99):
                bound = None
                for upper in buckets:
                    label = "+Inf" if math.isinf(upper) else format(upper, "g")
                    count = delta("kms_c2c_send_rpc_duration_ms_bucket", size_bucket=b, le=label)
                    if count is not None and count >= n * quantile / 100:
                        bound = upper if math.isfinite(upper) else None
                        break
                rpc[b][f"p{quantile}_ms_upper_bound"] = bound
    res["rpc"] = rpc

    # loss signals inside the enclave
    res["retrans"] = delta("kms_tcp_segs_total", kind="retrans")
    res["out_segs"] = delta("kms_tcp_segs_total", kind="out")
    res["retrans_pct"] = (100 * res["retrans"] / res["out_segs"]) if res["retrans"] is not None and res["out_segs"] else None
    res["drops_rx"] = delta("kms_net_iface_dropped_total", dir="rx")
    res["drops_tx"] = delta("kms_net_iface_dropped_total", dir="tx")
    res["future_messages_dropped"] = delta("kms_network_debug_events_total", event="future_message_dropped")
    res["pool_cpu_seconds"] = {pool: delta("kms_thread_pool_cpu_seconds_total", pool=pool)
                               for pool in ("tokio", "rayon", "main", "other")}
    cpu_values = list(res["pool_cpu_seconds"].values())
    cpu_seconds = sum(value for value in cpu_values if value is not None) if any(value is not None for value in cpu_values) else None
    process_cpu_seconds = delta("kms_process_cpu_seconds_total")
    cpu_seconds = process_cpu_seconds if process_cpu_seconds is not None else cpu_seconds
    res["process_cpu_seconds"] = cpu_seconds
    res["details"] = {}
    for operation in ("rayon_queue", "rayon_execute", "broadcast_serialize", "echo_serialize", "echo_receive_wait", "echo_tally", "echo_hash"):
        seconds = delta("kms_dkg_detail_duration_seconds_total", operation=operation)
        count = delta("kms_dkg_detail_observations_total", operation=operation)
        if seconds is not None:
            res["details"][operation] = {"seconds": seconds, "observations": count,
                                         "avg_ms": seconds * 1000 / count if count else None}
    res["generated"] = {}
    for kind in ("bits", "triples"):
        count = delta("kms_dkg_generated_items_total", kind=kind)
        res["generated"][kind] = {
            "items": count, "items_per_s": count / window if count is not None else None,
            "workload_cpu_seconds_per_item": cpu_seconds / count if cpu_seconds is not None and count else None,
        }
    missing_kinds = [kind for kind, value in res["generated"].items() if value["items"] is None]
    if missing_kinds:
        res["status"] = "exploratory"
        res["warnings"].append(f"completed-item counters unavailable for {', '.join(missing_kinds)}; both kinds are required for a valid run")
    return res


# --------------------------------------------------------------------------- kubectl top samples
TOP_LINE = re.compile(r"^(\S+)\s+(\S+)\s+(\d+)m\s+(\d+)Mi")


def parse_top_log(path, start_epoch=None, end_epoch=None):
    """container -> {"samples", "cpu_m_mean", "cpu_m_max", "mem_mi_max"} from top-party1.log."""
    per = defaultdict(list)
    epoch = None
    try:
        with open(path, errors="replace") as f:
            for line in f:
                timestamp = line[3:].strip() if line.startswith("## ") else line.strip()
                if re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z", timestamp):
                    try:
                        epoch = datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
                    except ValueError:
                        epoch = None
                    continue
                if start_epoch is not None and (epoch is None or epoch < start_epoch):
                    continue
                if end_epoch is not None and (epoch is None or epoch > end_epoch):
                    continue
                m = TOP_LINE.match(line.strip())
                if m:
                    per[m.group(2)].append((int(m.group(3)), int(m.group(4))))
    except OSError:
        return {}
    return {c: {"samples": len(v), "cpu_m_mean": statistics.fmean(x for x, _ in v),
                "cpu_m_max": max(x for x, _ in v), "mem_mi_max": max(y for _, y in v)}
            for c, v in per.items() if v}


# --------------------------------------------------------------------------- summarize
def load_manifest(run_dir):
    try:
        with open(os.path.join(run_dir, "manifest.json")) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def party_index(path):
    m = re.search(r"(?:core-|p)(\d+)", os.path.basename(path.rstrip("/")))
    return int(m.group(1)) if m else 0


def summarize(run_dir, stop_pct, csv_path):
    manifest = load_manifest(run_dir)
    tag = manifest.get("tag") or os.path.basename(os.path.abspath(run_dir))
    start = manifest.get("measurement_start_epoch")
    end = manifest.get("measurement_end_epoch")
    start = float(start) if start is not None else None
    end = float(end) if end is not None else None
    warmup = float(manifest.get("warmup_seconds", 0))
    steady_start = start + warmup if start is not None else None
    scrape_interval = None
    reasons = []
    status = manifest.get("status", "exploratory")
    if status not in ("valid", "invalid", "exploratory"):
        status = "exploratory"
    if manifest.get("invalid_reason"):
        reasons.append(str(manifest["invalid_reason"]))
        status = "invalid"
    if start is None or end is None:
        if status != "invalid":
            status = "exploratory"
        reasons.append("measurement boundaries unavailable; historical capture is exploratory")
    elif end <= start or warmup < 0 or steady_start >= end:
        status = "invalid"
        reasons.append("measurement boundaries or warmup are invalid")
    if manifest.get("schema_version") == 2:
        try:
            scrape_interval = float(manifest["scrape_interval_seconds"])
            if not math.isfinite(scrape_interval) or scrape_interval <= 0:
                raise ValueError("nonpositive interval")
        except (KeyError, TypeError, ValueError):
            status = "invalid"
            reasons.append("schema 2 requires a positive scrape_interval_seconds")
            scrape_interval = None
        if steady_start is None or end is None:
            scrape_interval = None
    core_files = sorted(glob.glob(os.path.join(run_dir, "core", "core-*.log")))
    if not core_files:  # an old-style capture dir (dkg-under-load-*/core-<i>.log) works too
        core_files = sorted(glob.glob(os.path.join(run_dir, "core-*.log")))
    logs = {party_index(p): parse_core_log(p, start, end) for p in core_files}
    metrics = {}
    rejected_metrics = {}
    for d in sorted(glob.glob(os.path.join(run_dir, "raw", "p*"))):
        m = summarise_party_metrics(d, steady_start, end, scrape_interval)
        if m:
            party = party_index(d)
            if m["status"] == "invalid":
                rejected_metrics[party] = m
                status = "invalid"
                reasons.extend(f"party {party}: {reason}" for reason in m["invalid_reasons"])
            else:
                metrics[party] = m
                if m["status"] == "exploratory" and status != "invalid":
                    status = "exploratory"
                reasons.extend(f"party {party}: {warning}" for warning in m["warnings"])
    expected = manifest.get("watched_parties")
    if expected is None and manifest.get("num_parties"):
        expected = list(range(1, int(manifest["num_parties"]) + 1))
    if expected is not None:
        if isinstance(expected, str):
            expected = expected.split()
        missing = sorted({int(p) for p in expected} - set(metrics) - set(rejected_metrics))
        if missing:
            status = "invalid"
            reasons.append(f"fewer than two measurement snapshots for parties {missing}")
    elif status == "valid":
        status = "exploratory"
        reasons.append("expected party coverage unavailable")

    lines = [f"# Run `{tag}`", ""]
    lines.append(f"Status: **{status}**.")
    lines.append("")
    for reason in sorted(set(reasons)):
        lines.append(f"- {reason}")
    lines.append("")
    if metrics or rejected_metrics:
        lines.append("| party | first scrape epoch | last scrape epoch | maximum scrape gap s | allowed gap s |")
        lines.append("|---|---|---|---|---|")
        for party, measured in sorted({**metrics, **rejected_metrics}.items()):
            lines.append(f"| {party} | {measured['first_epoch']:.3f} | {measured['last_epoch']:.3f} | "
                         f"{measured['max_scrape_gap_s']:.3f} | {fmt(measured.get('coverage', {}).get('max_allowed_gap_s'))} |")
        lines.append("")
    if steady_start is not None and end is not None:
        lines.append(f"Steady measurement window: {steady_start:.3f} to {end:.3f} Unix seconds; warmup {warmup:g} s.")
        lines.append("Each party uses its first and last successful scrapes within this window.")
        lines.append("")
    if manifest:
        knobs = manifest.get("knobs", {})
        lines.append(f"- namespace `{manifest.get('namespace', '?')}`, {manifest.get('start', '?')} → {manifest.get('end', '?')}")
        lines.append(f"- knobs: `{json.dumps(knobs, sort_keys=True)}`")
        lines.append(f"- images: `{manifest.get('images', '?')}`; branch head `{manifest.get('git_head', '?')}`")
        lines.append(f"- stop rule: {manifest.get('stop_rule', '?')}; stopped because: {manifest.get('stopped_because', '?')}")
        lines.append("")

    # --- progress (party 1, or the first log) -------------------------------------------------
    ref = logs.get(1) or (next(iter(logs.values())) if logs else None)
    headline = {}
    if ref:
        lines.append("## Progress (party 1)")
        lines.append("")
        lines.append("| tracker | total items | last % | at s | overall %/min | last-interval %/min | items/s overall | time to {0}% s |".format(stop_pct))
        lines.append("|---|---|---|---|---|---|---|---|")
        for tracker in ("TripleGen", "BitGen", "RandomGen"):
            pts = ref["progress"].get(tracker, [])
            if not pts:
                continue
            _, pct, elapsed = pts[-1]
            overall = pct / (elapsed / 60) if elapsed else None
            last_rate = None
            if len(pts) >= 2:
                _, p0, e0 = pts[-2]
                if elapsed > e0:
                    last_rate = (pct - p0) / ((elapsed - e0) / 60)
            tts = time_to_pct(pts, stop_pct)
            total = ref["totals"].get(tracker)
            items_s = (pct / 100 * total / elapsed) if (total and elapsed) else None
            lines.append(f"| {tracker} | {total or '?'} | {fmt(pct)} | {elapsed} | {fmt(overall, 2)} | {fmt(last_rate, 2)} | {fmt(items_s, 0)} | {fmt(tts, 0)} |")
            headline[f"{tracker.lower()}_total"] = total
            headline[f"{tracker.lower()}_items_per_s"] = items_s
            headline[f"{tracker.lower()}_pct"] = pct
            headline[f"{tracker.lower()}_elapsed_s"] = elapsed
            headline[f"{tracker.lower()}_pct_per_min"] = overall
            for target in sorted({5, 10, 15, 20, 25, 50, 100, stop_pct}):
                headline[f"{tracker.lower()}_t{target:g}_s"] = time_to_pct(pts, target)
        lines.append("")
        if ref["tuning"]:
            lines.append(f"- tuning exported: `{' '.join(sorted(set(ref['tuning'])))}`")
        if ref["h2"]:
            lines.append(f"- HTTP/2 settings: `{ref['h2']}`")
        lines.append(f"- log window {ref['first_ts']} → {ref['last_ts']}: {ref['warn']} WARN, {ref['error']} ERROR, "
                     f"{ref['unheard']} \"haven't heard from\"")
        if ref["errors_by_kind"]:
            top = sorted(ref["errors_by_kind"].items(), key=lambda kv: -kv[1])[:5]
            for kind, n in top:
                lines.append(f"    - {n} × `{kind}`")
        lines.append("")

    # --- phase split from the log lines (all parties) -------------------------------------------
    phase_lines = [(party, pl) for party, lg in logs.items() for pl in lg["phase_lines"]
                   if steady_start is None or (pl["ts"] and datetime.fromisoformat(
                       pl["ts"].replace("Z", "+00:00")).timestamp() - pl["window_s"] >= steady_start)]
    if phase_lines:
        lines.append("## Phase split from complete log windows inside the steady measurement window")
        lines.append("")
        agg = defaultdict(lambda: [0.0, 0])
        for _, pl in phase_lines:
            for label, (total_s, obs, _, _) in pl["phases"].items():
                agg[label][0] += total_s
                agg[label][1] += obs
        core_total = sum(v[0] for k, v in agg.items() if k in PHASES)
        lines.append("| phase | share of batch time | avg ms / observation | observations |")
        lines.append("|---|---|---|---|")
        for label in PHASES + ENVELOPES:
            if label not in agg:
                continue
            total_s, obs = agg[label]
            share = f"{100 * total_s / core_total:.1f}%" if (core_total and label in PHASES) else "(envelope)"
            lines.append(f"| {label} | {share} | {fmt(1000 * total_s / obs if obs else None, 0)} | {obs} |")
        lines.append("")
        lines.append(f"({len(phase_lines)} windows over {len({p for p, _ in phase_lines})} parties)")
        lines.append("")

    # --- metrics per party ----------------------------------------------------------------------
    if metrics:
        lines.append("## Metrics (per watched party, duration-weighted steady window)")
        lines.append("")
        lines.append("| party | actual window s | completed bits/s | completed triples/s | workload CPU s/bit | workload CPU s/triple | future messages dropped |")
        lines.append("|---|---|---|---|---|---|---|")
        for party, m in sorted(metrics.items()):
            bits, triples = m["generated"]["bits"], m["generated"]["triples"]
            lines.append(f"| {party} | {m['window_s']:.1f} | {fmt(bits['items_per_s'], 0)} | "
                         f"{fmt(triples['items_per_s'], 0)} | {fmt(bits['workload_cpu_seconds_per_item'], 6)} | "
                         f"{fmt(triples['workload_cpu_seconds_per_item'], 6)} | {fmt(m['future_messages_dropped'], 0)} |")
        lines.append("")
        lines.append("CPU per item uses all KMS process CPU during the shared workload; it does not attribute CPU to one producer.")
        lines.append("Counters describe completed phases and items. In-flight work at the cutoff is excluded.")
        lines.append("")
        lines.append("| party | ticks | util % | tokio cores | rayon cores | vsocktun cores | sessions | tx Gbps (p95) | rx Gbps (p95) | queued mean/max | RPC ≤16 MB avg ms | opt hit % (robust / d) | retrans % | drops rx/tx |")
        lines.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
        for party, m in sorted(metrics.items()):
            opt = m["optimistic"]
            opt_s = f"{fmt(opt.get('robust_open', {}).get('hit_pct'))} / {fmt(opt.get('d_values', {}).get('hit_pct'))}"
            rpc16 = m["rpc"].get("le_16m", {}).get("avg_ms")
            lines.append(
                f"| {party} | {m['ticks']} | {fmt(m['util_pct'], 0)} | {fmt(m['tokio_cores'])} ({fmt(m['tokio_cores_p95'])}) | "
                f"{fmt(m['rayon_cores'])} ({fmt(m['rayon_cores_p95'])}) | {fmt(m['vsocktun_cores'])} | {fmt(m['sessions'], 0)} | "
                f"{fmt(m['tx_gbps'], 2)} ({fmt(m['tx_gbps_p95'], 2)}) | {fmt(m['rx_gbps'], 2)} ({fmt(m['rx_gbps_p95'], 2)}) | "
                f"{fmt(m['queued_mean'], 0)}/{fmt(m['queued_max'], 0)} | {fmt(rpc16, 0)} | {opt_s} | {fmt(m['retrans_pct'], 3)} | "
                f"{fmt(m['drops_rx'], 0)}/{fmt(m['drops_tx'], 0)} |")
        lines.append("")
        for party, m in sorted(metrics.items()):
            disabled = {site: counts["disabled"] for site, counts in m["optimistic"].items() if counts["disabled"]}
            if disabled:
                lines.append(f"Party {party}: optimistic reconstruction disabled counts: {disabled}. Disabled calls do not enter the hit-rate denominator.")
                lines.append("")
        # phases from counters, first watched party with data
        for party, m in sorted(metrics.items()):
            if m["phases"]:
                lines.append(f"### Phase split from the counters (party {party}, {m['window_s']} s window)")
                lines.append("")
                lines.append("| phase | share | session-s per wall-s | avg ms / obs | obs |")
                lines.append("|---|---|---|---|---|")
                for ph in PHASES + ENVELOPES:
                    d = m["phases"].get(ph)
                    if not d:
                        continue
                    share = f"{d['share']:.1f}%" if d["share"] is not None else "(envelope)"
                    lines.append(f"| {ph} | {share} | {fmt(d['sps'])} | {fmt(d['avg_ms'], 0)} | {d['obs']:.0f} |")
                lines.append("")
                lines.append(f"Sum over the batch phases: {fmt(m['phase_total_sps'])} session-s per wall-s "
                             f"(≈ the number of sessions busy in those phases; compare with `sessions`).")
                lines.append("")
                if m["rpc"]:
                    lines.append("RPC latency by size: " + ", ".join(
                        f"{b} average {fmt(d['avg_ms'], 1)} ms, p95 bucket upper bound {fmt(d['p95_ms_upper_bound'], 1)} ms (n={d['n']:.0f})"
                        for b, d in m["rpc"].items()))
                    lines.append("")
                if m["details"]:
                    lines.append("Nested operation timers (these overlap phases and do not enter the phase denominator):")
                    lines.append("")
                    lines.append("| operation | total seconds | observations | average ms |")
                    lines.append("|---|---|---|---|")
                    for operation, detail in m["details"].items():
                        lines.append(f"| {operation} | {fmt(detail['seconds'])} | {fmt(detail['observations'], 0)} | {fmt(detail['avg_ms'])} |")
                    lines.append("")
                break

    # --- sidecar / tunnel CPU from kubectl top ---------------------------------------------------
    top = parse_top_log(os.path.join(run_dir, "top-party1.log"), steady_start, end)
    if top:
        lines.append("## Party 1 containers (`kubectl top`, parent side)")
        lines.append("")
        lines.append("| container | samples | CPU m mean | CPU m max | mem Mi max |")
        lines.append("|---|---|---|---|---|")
        for c, d in sorted(top.items(), key=lambda kv: -kv[1]["cpu_m_max"]):
            lines.append(f"| {c} | {d['samples']} | {d['cpu_m_mean']:.0f} | {d['cpu_m_max']} | {d['mem_mi_max']} |")
        logger = top.get("kms-core-enclave-logger")
        if logger and logger["cpu_m_max"] >= 180:
            lines.append("")
            lines.append("Logger CPU reaches at least 180m. Check its configured limit and cgroup throttling counters before attributing delay.")
        lines.append("")

    # --- bandwidth bench lines, if the run contains any ----------------------------------------
    bench_logs = {p: lg for p, lg in logs.items() if lg["bench"]}
    if bench_logs:
        lines.append("## Bandwidth benchmark lines found in the core logs")
        lines.append("")
        lines.extend(bw_table(bench_logs))
        lines.append("")

    text = "\n".join(lines) + "\n"
    with open(os.path.join(run_dir, "summary.md"), "w") as f:
        f.write(text)
    print(text)

    # --- CSV row ---------------------------------------------------------------------------------
    row = {"tag": tag, "status": status, "invalid_reason": "; ".join(sorted(set(reasons))),
           "stop_pct": stop_pct, "knobs": json.dumps(manifest.get("knobs", {}), sort_keys=True),
           "images": manifest.get("images", ""), "start": manifest.get("start", "")}
    row.update({k: (f"{v:.2f}" if isinstance(v, float) else v) for k, v in headline.items()})
    if metrics:
        def avg(key, sub=None):
            vals = []
            for m in metrics.values():
                v = m.get(key) if sub is None else (m.get(key) or {}).get(sub)
                if isinstance(v, dict):
                    v = v.get("avg_ms") if "avg_ms" in v else v.get("hit_pct")
                if v is not None:
                    vals.append(v)
            return f"{statistics.fmean(vals):.2f}" if vals else ""
        row.update({
            "util_pct": avg("util_pct"), "tokio_cores": avg("tokio_cores"), "rayon_cores": avg("rayon_cores"),
            "vsocktun_cores": avg("vsocktun_cores"), "tx_gbps": avg("tx_gbps"), "tx_gbps_p95": avg("tx_gbps_p95"),
            "queued_mean": avg("queued_mean"), "rpc_le16m_ms": avg("rpc", "le_16m"),
            "opt_hit_robust_pct": avg("optimistic", "robust_open"), "opt_hit_d_pct": avg("optimistic", "d_values"),
            "retrans_pct": avg("retrans_pct"),
        })
        for kind in ("bits", "triples"):
            rates = [m["generated"][kind]["items_per_s"] for m in metrics.values()
                     if m["generated"][kind]["items_per_s"] is not None]
            costs = [m["generated"][kind]["workload_cpu_seconds_per_item"] for m in metrics.values()
                     if m["generated"][kind]["workload_cpu_seconds_per_item"] is not None]
            row[f"{kind}_per_s"] = mean(rates)
            row[f"{kind}_per_s_min"] = min(rates) if rates else None
            row[f"workload_cpu_s_per_{kind[:-1]}"] = mean(costs)
        for ph in PHASES:
            vals = [m["phases"][ph]["share"] for m in metrics.values() if ph in m["phases"] and m["phases"][ph]["share"] is not None]
            row[f"share_{ph}"] = f"{statistics.fmean(vals):.1f}" if vals else ""
    if top:
        tun = top.get("enclave-network-tunnel", {})
        lgr = top.get("kms-core-enclave-logger", {})
        row["tunnel_parent_cpu_m_mean"] = f"{tun['cpu_m_mean']:.0f}" if tun else ""
        row["logger_cpu_m_max"] = str(lgr.get("cpu_m_max", "")) if lgr else ""
    result = {"schema_version": 2, "row": row, "metrics": metrics, "rejected_metrics": rejected_metrics,
              "measurement_start_epoch": start, "measurement_end_epoch": end, "warmup_seconds": warmup}
    with tempfile.NamedTemporaryFile(mode="w", dir=run_dir, prefix=".summary-", delete=False) as f:
        json.dump(result, f, indent=2, sort_keys=True)
        temporary = f.name
    os.replace(temporary, os.path.join(run_dir, "summary.json"))
    if csv_path:
        print("[summarize does not mutate shared CSV files; use compare RUNS_DIR --csv FILE]", file=sys.stderr)
    print(f"[summary written to {os.path.join(run_dir, 'summary.md')} and summary.json]")
    return result


# --------------------------------------------------------------------------- bandwidth bench
def bandwidth_result(log):
    """Returns acknowledged goodput only for a complete aggregate record."""
    aggregate = log.get("bench_aggregate")
    if aggregate:
        complete = (aggregate["status"] == "complete"
                    and aggregate["completed_sessions"] == aggregate["requested_sessions"]
                    and aggregate["requested_sessions"] > 0
                    and aggregate["timeouts"] == 0 and aggregate["errors"] == 0
                    and aggregate["successes"] > 0
                    and aggregate["attempts"] == aggregate["successes"]
                    and aggregate["elapsed_s"] > 0)
        return dict(aggregate, status="valid" if complete else "invalid",
                    gbps=aggregate["acknowledged_bytes"] * 8 / aggregate["elapsed_s"] / 1e9 if complete else None)
    sessions = log.get("bench", [])
    timeouts = sum(peer[5] for _, _, _, peers in sessions for peer in peers)
    errors = sum(peer[6] for _, _, _, peers in sessions for peer in peers)
    requested = sessions[-1][1] if sessions else 0
    complete = bool(sessions) and len({index for index, _, _, peers in sessions if peers}) == requested
    return {"status": "exploratory" if complete and not timeouts and not errors else "invalid",
            "completed_sessions": len(sessions), "requested_sessions": requested,
            "elapsed_s": None, "acknowledged_bytes": None, "gbps": None,
            "timeouts": timeouts, "errors": errors}


def bw_table(bench_logs):
    """Returns per-party status and goodput over the common benchmark interval."""
    rows = ["| party | status | sessions | common duration s | acknowledged bytes | goodput Gbps | timeouts | errors |",
            "|---|---|---|---|---|---|---|---|"]
    for party, log in sorted(bench_logs.items()):
        result = bandwidth_result(log)
        rows.append(f"| {party} | {result['status']} | {result['completed_sessions']}/{result['requested_sessions']} | "
                    f"{fmt(result['elapsed_s'])} | {fmt(result['acknowledged_bytes'], 0)} | {fmt(result['gbps'], 3)} | "
                    f"{result['timeouts']} | {result['errors']} |")
    return rows


def bw(paths, expected_parties=None, json_path=None):
    logs = {party_index(p): parse_core_log(p) for p in paths}
    if not logs:
        print("invalid: no bandwidth logs")
        return 1
    results = {party: bandwidth_result(log) for party, log in logs.items()}
    missing = sorted(set(range(1, expected_parties + 1)) - set(logs)) if expected_parties else []
    valid = not missing and all(result["status"] == "valid" for result in results.values())
    created = next((lg["bench_created"] for lg in logs.values() if lg["bench_created"]), None)
    if created:
        print(f"{created[0]} sessions, {created[2]}-byte payloads, sessions created after {created[1]:.1f} s")
    print("\n".join(bw_table(logs)))
    print("\nGoodput uses acknowledged bytes over the common session interval, including setup.")
    print("Legacy captures are exploratory. Errors, timeouts, missing parties, and partial results do not establish a transport ceiling.")
    if missing:
        print(f"Missing parties: {missing}")
    print(f"Benchmark status: {'valid' if valid else 'invalid or exploratory'}")
    if json_path:
        with open(json_path, "w") as f:
            json.dump({"status": "valid" if valid else "invalid", "missing_parties": missing, "parties": results}, f, indent=2)
    return 0 if valid else 1


# --------------------------------------------------------------------------- compare
def compare(target, csv_path=None):
    if target.endswith(".csv"):
        with open(target, newline="") as f:
            rows = list(csv.DictReader(f))
        for row in rows:
            row.setdefault("status", "exploratory")
    else:
        rows = []
        for path in sorted(glob.glob(os.path.join(target, "*", "summary.json"))):
            with open(path) as f:
                rows.append(json.load(f)["row"])
    if not rows:
        print("No per-run summaries found. Run summarize on each capture first.")
        return []
    target_columns = sorted({key for row in rows for key in row if re.fullmatch(r"triplegen_t[0-9.]+_s", key)},
                            key=lambda key: float(key[len("triplegen_t"):-2]))
    comparable = [row for row in rows if row.get("status") == "valid"] or rows
    target_columns = [key for key in target_columns if all(row.get(key) not in (None, "") for row in comparable)]
    cols = ["tag", "status"] + target_columns + ["bits_per_s_min", "triples_per_s_min", "workload_cpu_s_per_bit",
            "triplegen_items_per_s", "bitgen_items_per_s", "util_pct", "tokio_cores",
            "rayon_cores", "tx_gbps", "rpc_le16m_ms", "opt_hit_robust_pct", "retrans_pct",
            "share_bcast_echo_wait", "share_prss", "share_recons_d", "share_mult_open", "share_open_v", "share_solve"]
    cols = [c for c in cols if any(r.get(c) for r in rows)]
    def cell(row, col):
        value = row.get(col)
        return "" if value is None else (f"{value:.6g}" if isinstance(value, float) else str(value))
    widths = {c: max(len(c), *(len(cell(r, c)) for r in rows)) for c in cols}
    print("  ".join(c.ljust(widths[c]) for c in cols))
    for r in rows:
        print("  ".join(cell(r, c).ljust(widths[c]) for c in cols))
    print("\nknobs per run:")
    for r in rows:
        print(f"  {r['tag']}: {r.get('knobs', '')}")
    if csv_path:
        fieldnames = list(dict.fromkeys(key for row in rows for key in row))
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
    return rows


# --------------------------------------------------------------------------- main
def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print(__doc__)
        return 0
    cmd, args = argv[1], argv[2:]
    if cmd == "progress":
        path = args[0] if args else "-"
        tracker = args[args.index("--tracker") + 1] if "--tracker" in args else None
        latest = latest_progress(parse_core_log(path))
        if tracker:
            pct, elapsed, _ = latest.get(tracker, (0.0, 0, None))
            print(f"{pct:.2f} {elapsed}")
        else:
            for t, (pct, elapsed, ts) in sorted(latest.items()):
                print(f"{t}: {pct:.1f}% at {elapsed}s ({ts})")
            if not latest:
                print("no progress lines")
        return 0
    if cmd == "summarize":
        run_dir = args[0]
        stop_pct = float(args[args.index("--stop-pct") + 1]) if "--stop-pct" in args else 25.0
        csv_path = args[args.index("--csv") + 1] if "--csv" in args else None
        result = summarize(run_dir, stop_pct, csv_path)
        return 1 if result["row"]["status"] == "invalid" else 0
    if cmd == "bw":
        expected = None
        json_path = None
        for flag in ("--expected-parties", "--json"):
            if flag in args:
                index = args.index(flag)
                value = args[index + 1]
                if flag == "--expected-parties":
                    expected = int(value)
                else:
                    json_path = value
                del args[index:index + 2]
        return bw(args, expected, json_path)
    if cmd == "compare":
        csv_path = args[args.index("--csv") + 1] if "--csv" in args else None
        compare(args[0] if args else ".", csv_path)
        return 0
    print(f"unknown command {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))

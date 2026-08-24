#!/usr/bin/env python3
"""Correlate one performance run's rate results with its diagnostic artifacts.

The analyzer downloads a GitHub Actions run or reads an existing artifact directory. It emits
either a Markdown report or the complete machine-readable analysis as JSON.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import unittest
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable


ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
TIME_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z")
RATE_RE = re.compile(r"\b(PUBLIC|USER)_DECRYPT_METRICS\s+(\{.*\})")
METRIC_RE = re.compile(r'^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(?P<labels>.*)\})?$')
KEY_VALUE_RE = re.compile(r"([a-z_]+)=([^ ]+)")

GAUGES = (
    "kms_active_sessions",
    "kms_inactive_sessions",
    "kms_completed_sessions",
    "kms_meta_storage_user_decryptions",
    "kms_meta_storage_user_decryptions_in_store",
    "kms_meta_storage_pub_decryptions",
    "kms_meta_storage_pub_decryptions_in_store",
    "kms_network_sender_tasks",
    "kms_rate_limiter_usage",
    "kms_tasks",
    "kms_tokio_alive_tasks",
    "kms_tokio_global_queue_depth",
    "kms_user_decrypt_background_tasks",
)
NETWORK_COUNTERS = ("kms_network_rx_bytes_total", "kms_network_tx_bytes_total")
STAGE_DURATION = "kms_user_decrypt_stage_duration_microseconds_total"
STAGE_COUNT = "kms_user_decrypt_stage_observations_total"
NETWORK_EVENTS = "kms_network_debug_events_total"
SERVICE_OPERATION_COUNT = "kms_operations_total"
SERVICE_OPERATION_ERRORS = "kms_operation_errors_total"
SERVICE_DURATION_SUM = "kms_operation_duration_ms_sum"
SERVICE_DURATION_COUNT = "kms_operation_duration_ms_count"
ENA_ALLOWANCES = ("bw_in", "bw_out", "pps", "conntrack", "linklocal")
PERF_ARTIFACTS = (
    "argo-workflow-logs.txt",
    "core-cpu-samples.log",
    "perf-diagnostics",
)


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def iso(value: datetime | None) -> str | None:
    return value.isoformat().replace("+00:00", "Z") if value else None


def run_command(*args: str) -> str:
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"{' '.join(args)} failed: {detail}")
    return result.stdout


def find_file(root: Path, names: Iterable[str]) -> Path | None:
    matches = [path for path in root.rglob("*") if path.is_file() and path.name in names]
    return min(matches, key=lambda path: (len(path.parts), str(path))) if matches else None


def read_file(root: Path, *names: str) -> str:
    path = find_file(root, names)
    return path.read_text(encoding="utf-8", errors="replace") if path else ""


def read_files(root: Path, *names: str) -> str:
    paths = sorted(
        path for path in root.rglob("*") if path.is_file() and path.name in names
    )
    return "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in paths)


def parse_labels(raw: str | None) -> dict[str, str]:
    if not raw:
        return {}
    return {
        match.group(1): match.group(2)
        for match in re.finditer(r'(\w+)="((?:\\.|[^"])*)"', raw)
    }


def parse_rate_metrics(text: str) -> list[dict[str, Any]]:
    rates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_line in text.splitlines():
        line = ANSI_RE.sub("", raw_line)
        match = RATE_RE.search(line)
        if not match or match.group(2) in seen:
            continue
        try:
            metrics = json.loads(match.group(2))
        except json.JSONDecodeError:
            continue
        seen.add(match.group(2))
        timestamps = TIME_RE.findall(line[: match.start()])
        emitted = parse_time(timestamps[-1]) if timestamps else None
        measurement = float(
            metrics.get("measurement_elapsed_seconds", metrics.get("duration", 0))
        )
        drain = float(metrics.get("drain_elapsed_seconds", 0))
        post_process = metrics.get("verification_ms") or metrics.get("reconstruction_ms") or {}
        post_process_seconds = float(post_process.get("wall", 0)) / 1000
        end = emitted - timedelta(seconds=drain + post_process_seconds) if emitted else None
        start = end - timedelta(seconds=measurement) if end else None
        rates.append(
            {
                "kind": "pdec" if match.group(1) == "PUBLIC" else "udec",
                "metrics": metrics,
                "emitted_at": iso(emitted),
                "window_start": iso(start),
                "window_end": iso(end),
            }
        )
    return rates


def has_sequential_windows(rates: list[dict[str, Any]]) -> bool:
    """Reject timestamps added while replaying several completed Argo pod logs."""
    windows = [
        (parse_time(rate["window_start"]), parse_time(rate["window_end"])) for rate in rates
    ]
    if not windows or any(start is None or end is None for start, end in windows):
        return False
    ordered = sorted(windows)
    return all(current[0] >= previous[1] for previous, current in zip(ordered, ordered[1:]))


def parse_cpu(text: str) -> list[dict[str, Any]]:
    samples = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 4 or not TIME_RE.fullmatch(fields[0]):
            continue
        cpu = fields[2]
        try:
            if cpu.endswith("n"):
                cores = float(cpu[:-1]) / 1_000_000_000
            elif cpu.endswith("u"):
                cores = float(cpu[:-1]) / 1_000_000
            elif cpu.endswith("m"):
                cores = float(cpu[:-1]) / 1_000
            else:
                cores = float(cpu)
        except ValueError:
            continue
        samples.append({"time": fields[0], "pod": fields[1], "cores": cores})
    return samples


def parse_core_metrics(text: str) -> list[dict[str, Any]]:
    samples = []
    for line in text.splitlines():
        fields = line.split(maxsplit=3)
        if len(fields) != 4 or not TIME_RE.fullmatch(fields[0]):
            continue
        metric_match = METRIC_RE.fullmatch(fields[2])
        if not metric_match:
            continue
        try:
            value = float(fields[3])
        except ValueError:
            continue
        samples.append(
            {
                "time": fields[0],
                "pod": fields[1],
                "name": metric_match.group("name"),
                "labels": parse_labels(metric_match.group("labels")),
                "value": value,
            }
        )
    return samples


def parse_ena(text: str) -> list[dict[str, Any]]:
    samples = []
    for line in text.splitlines():
        time_match = TIME_RE.search(line)
        values = dict(KEY_VALUE_RE.findall(line))
        if not time_match or "node" not in values or "iface" not in values:
            continue
        try:
            numeric = {
                key: int(values.get(key, "0"))
                for key in ("rx_bytes", "tx_bytes", *ENA_ALLOWANCES)
            }
        except ValueError:
            continue
        samples.append({
            "time": time_match.group(0),
            "node": values["node"],
            "iface": values["iface"],
            **numeric,
        })
    return samples


def parse_placement(text: str) -> list[dict[str, str]]:
    rows = []
    fields = ("time", "pod", "workflow_node", "node", "zone", "instance_type", "nodepool")
    for line in text.splitlines():
        values = line.split("\t")
        if len(values) == len(fields) and values[0] != "timestamp":
            rows.append(dict(zip(fields, values)))
    return rows


def parse_ena_lifecycle(text: str) -> dict[str, Any]:
    daemonset_samples = []
    pod_states: dict[str, dict[str, Any]] = {}
    warning_events = []
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) == 7 and fields[1] == "daemonset":
            try:
                desired, current, ready, unavailable = map(int, fields[3:7])
            except ValueError:
                continue
            daemonset_samples.append(
                {
                    "time": fields[0],
                    "created_at": fields[2],
                    "desired": desired,
                    "current": current,
                    "ready": ready,
                    "unavailable": unavailable,
                }
            )
        elif len(fields) == 12 and fields[1] == "pod":
            try:
                restarts = int(fields[8])
            except ValueError:
                continue
            pod = fields[2]
            state = pod_states.setdefault(
                pod,
                {
                    "created_at": fields[3],
                    "started_at": fields[4],
                    "node": fields[5],
                    "first_seen_at": fields[0],
                    "first_ready_at": None,
                    "max_restarts": 0,
                    "waiting_reasons": set(),
                    "terminated_reasons": set(),
                },
            )
            if fields[7] == "true" and state["first_ready_at"] is None:
                state["first_ready_at"] = fields[0]
            state["max_restarts"] = max(state["max_restarts"], restarts)
            if fields[10]:
                state["waiting_reasons"].add(fields[10])
            if fields[11]:
                state["terminated_reasons"].add(fields[11])
        elif len(fields) >= 5 and fields[2] == "Warning" and fields[1].startswith("ena-probe-"):
            warning_events.append(
                {"time": fields[0], "pod": fields[1], "reason": fields[3], "message": fields[4]}
            )

    first_all_ready = next(
        (
            sample["time"]
            for sample in daemonset_samples
            if sample["desired"] > 0 and sample["ready"] >= sample["desired"]
        ),
        None,
    )
    serializable_pods = {
        pod: {
            **state,
            "waiting_reasons": sorted(state["waiting_reasons"]),
            "terminated_reasons": sorted(state["terminated_reasons"]),
        }
        for pod, state in sorted(pod_states.items())
    }
    return {
        "samples": len(daemonset_samples),
        "max_desired": max((sample["desired"] for sample in daemonset_samples), default=0),
        "max_ready": max((sample["ready"] for sample in daemonset_samples), default=0),
        "max_unavailable": max(
            (sample["unavailable"] for sample in daemonset_samples), default=0
        ),
        "first_all_ready_at": first_all_ready,
        "pods": serializable_pods,
        "warning_events": warning_events,
    }


def within(sample: dict[str, Any], start: datetime, end: datetime) -> bool:
    timestamp = parse_time(sample["time"])
    return bool(timestamp and start <= timestamp <= end)


def counter_deltas(
    samples: list[dict[str, Any]], start: datetime, end: datetime, names: Iterable[str]
) -> dict[tuple[str, str, tuple[tuple[str, str], ...]], tuple[float, float]]:
    grouped: dict[
        tuple[str, str, tuple[tuple[str, str], ...]], list[dict[str, Any]]
    ] = defaultdict(list)
    wanted = set(names)
    for sample in samples:
        if sample["name"] in wanted and within(sample, start, end):
            labels = tuple(sorted(sample["labels"].items()))
            grouped[(sample["pod"], sample["name"], labels)].append(sample)
    totals: dict[tuple[str, str, tuple[tuple[str, str], ...]], tuple[float, float]] = {}
    for key, values in grouped.items():
        values.sort(key=lambda sample: sample["time"])
        first = parse_time(values[0]["time"])
        last = parse_time(values[-1]["time"])
        sample_seconds = (last - first).total_seconds() if first and last else 0.0
        totals[key] = (
            cumulative_increase([sample["value"] for sample in values]),
            sample_seconds,
        )
    return totals


def range_summary(values: list[float]) -> dict[str, float] | None:
    if not values:
        return None
    return {"min": min(values), "avg": sum(values) / len(values), "max": max(values)}


def cumulative_increase(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    total = 0.0
    previous = values[0]
    for value in values[1:]:
        total += value - previous if value >= previous else value
        previous = value
    return total


def ranges_by_pod(samples: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
    grouped: dict[str, list[float]] = defaultdict(list)
    for sample in samples:
        grouped[sample["pod"]].append(sample["value"])
    return {
        pod: summary
        for pod, values in sorted(grouped.items())
        if (summary := range_summary(values)) is not None
    }


def summarize_window(
    rate: dict[str, Any],
    cpu: list[dict[str, Any]],
    core: list[dict[str, Any]],
    ena: list[dict[str, Any]],
) -> dict[str, Any]:
    start = parse_time(rate["window_start"])
    end = parse_time(rate["window_end"])
    if not start or not end:
        return {"available": False, "reason": "rate log has no timestamp"}
    selected_cpu = [
        {"pod": sample["pod"], "value": sample["cores"]}
        for sample in cpu
        if within(sample, start, end)
    ]
    gauge_ranges = {}
    for name in GAUGES:
        selected = [
            sample
            for sample in core
            if sample["name"] == name and within(sample, start, end)
        ]
        by_pod = ranges_by_pod(selected)
        if by_pod:
            gauge_ranges[name] = {
                "all_samples": range_summary([sample["value"] for sample in selected]),
                "by_pod": by_pod,
            }

    deltas = counter_deltas(
        core,
        start,
        end,
        (
            *NETWORK_COUNTERS,
            NETWORK_EVENTS,
            STAGE_DURATION,
            STAGE_COUNT,
            SERVICE_OPERATION_COUNT,
            SERVICE_OPERATION_ERRORS,
            SERVICE_DURATION_SUM,
            SERVICE_DURATION_COUNT,
        ),
    )
    network_by_pod: dict[str, dict[str, float]] = defaultdict(
        lambda: {"rx_gbps": 0.0, "tx_gbps": 0.0}
    )
    for (pod, name, labels), (value, sample_seconds) in deltas.items():
        if labels or name not in NETWORK_COUNTERS:
            continue
        direction = "rx_gbps" if name == NETWORK_COUNTERS[0] else "tx_gbps"
        if sample_seconds > 0:
            network_by_pod[pod][direction] += value * 8 / sample_seconds / 1_000_000_000
            network_by_pod[pod]["sample_seconds"] = max(
                network_by_pod[pod].get("sample_seconds", 0.0), sample_seconds
            )
    network = {
        "total": {
            direction: sum(values[direction] for values in network_by_pod.values())
            for direction in ("rx_gbps", "tx_gbps")
        },
        "by_pod": dict(sorted(network_by_pod.items())),
    }

    events: dict[str, float] = defaultdict(float)
    events_by_pod: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    for (pod, name, labels), (value, _sample_seconds) in deltas.items():
        label_map = dict(labels)
        if name == NETWORK_EVENTS and value:
            event = label_map.get("event", "unknown")
            events[event] += value
            events_by_pod[pod][event] += value

    stage_duration: dict[tuple[str, str], float] = defaultdict(float)
    stage_count: dict[tuple[str, str], float] = defaultdict(float)
    for (pod, name, labels), (value, _sample_seconds) in deltas.items():
        stage = dict(labels).get("stage")
        if name == STAGE_DURATION and stage:
            stage_duration[(pod, stage)] += value
        elif name == STAGE_COUNT and stage:
            stage_count[(pod, stage)] += value
    stages_by_pod = {
        pod: {
            stage: {
                "observations": stage_count[(pod, stage)],
                "mean_microseconds": duration / stage_count[(pod, stage)],
            }
            for (duration_pod, stage), duration in stage_duration.items()
            if duration_pod == pod and stage_count[(pod, stage)]
        }
        for pod in sorted({pod for pod, _stage in stage_duration})
    }
    stage_names = sorted({stage for _pod, stage in stage_duration})
    stages = {}
    for stage in stage_names:
        duration = sum(
            value for (pod, sample_stage), value in stage_duration.items() if sample_stage == stage
        )
        observations = sum(
            value for (pod, sample_stage), value in stage_count.items() if sample_stage == stage
        )
        if observations:
            stages[stage] = {
                "observations": observations,
                "mean_microseconds": duration / observations,
            }

    operation_counts: dict[tuple[str, str], float] = defaultdict(float)
    operation_count_spans: dict[tuple[str, str], float] = defaultdict(float)
    operation_errors: dict[tuple[str, str, str], float] = defaultdict(float)
    operation_duration_sums: dict[tuple[str, str], float] = defaultdict(float)
    operation_duration_counts: dict[tuple[str, str], float] = defaultdict(float)
    for (pod, name, labels), (value, sample_seconds) in deltas.items():
        label_map = dict(labels)
        if name == SERVICE_OPERATION_COUNT and label_map.get("operation"):
            key = (pod, label_map["operation"])
            operation_counts[key] += value
            operation_count_spans[key] = max(operation_count_spans[key], sample_seconds)
        elif name == SERVICE_OPERATION_ERRORS and label_map.get("operation"):
            operation_errors[
                (pod, label_map["operation"], label_map.get("error", "unknown"))
            ] += value
        elif name == SERVICE_DURATION_SUM and label_map.get("operation_type"):
            operation_duration_sums[(pod, label_map["operation_type"])] += value
        elif name == SERVICE_DURATION_COUNT and label_map.get("operation_type"):
            operation_duration_counts[(pod, label_map["operation_type"])] += value

    service_by_pod = {}
    service_pods = sorted(
        {pod for pod, _operation in operation_counts}
        | {pod for pod, _operation, _error in operation_errors}
        | {pod for pod, _operation in operation_duration_sums}
    )
    for pod in service_pods:
        calls = {
            operation: {
                "count": count,
                "rate": count / operation_count_spans[(pod, operation)]
                if operation_count_spans[(pod, operation)] > 0
                else None,
                "sample_seconds": operation_count_spans[(pod, operation)],
            }
            for (sample_pod, operation), count in operation_counts.items()
            if sample_pod == pod
        }
        errors = {
            f"{operation}/{error}": count
            for (sample_pod, operation, error), count in operation_errors.items()
            if sample_pod == pod and count
        }
        durations = {}
        for (sample_pod, operation), duration_sum in operation_duration_sums.items():
            count = operation_duration_counts.get((sample_pod, operation), 0)
            if sample_pod == pod and count:
                durations[operation] = {
                    "observations": count,
                    "mean_milliseconds": duration_sum / count,
                }
        service_by_pod[pod] = {
            "calls": dict(sorted(calls.items())),
            "errors": dict(sorted(errors.items())),
            "durations": dict(sorted(durations.items())),
        }

    total_calls: dict[str, float] = defaultdict(float)
    total_errors: dict[str, float] = defaultdict(float)
    total_duration_sums: dict[str, float] = defaultdict(float)
    total_duration_counts: dict[str, float] = defaultdict(float)
    for (_pod, operation), count in operation_counts.items():
        total_calls[operation] += count
    for (_pod, operation, error), count in operation_errors.items():
        total_errors[f"{operation}/{error}"] += count
    for (_pod, operation), duration_sum in operation_duration_sums.items():
        total_duration_sums[operation] += duration_sum
    for (_pod, operation), count in operation_duration_counts.items():
        total_duration_counts[operation] += count
    service_total = {
        "calls": {
            operation: {
                "count": count,
                "rate": sum(
                    pod_service["calls"].get(operation, {}).get("rate") or 0.0
                    for pod_service in service_by_pod.values()
                ),
            }
            for operation, count in sorted(total_calls.items())
        },
        "errors": dict(sorted((key, value) for key, value in total_errors.items() if value)),
        "durations": {
            operation: {
                "observations": total_duration_counts[operation],
                "mean_milliseconds": duration_sum / total_duration_counts[operation],
            }
            for operation, duration_sum in sorted(total_duration_sums.items())
            if total_duration_counts[operation]
        },
    }

    ena_grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for sample in ena:
        if within(sample, start, end):
            ena_grouped[(sample["node"], sample["iface"])].append(sample)
    ena_totals = {"rx_bytes": 0, "tx_bytes": 0, **{key: 0 for key in ENA_ALLOWANCES}}
    for values in ena_grouped.values():
        values.sort(key=lambda sample: sample["time"])
        for key in ena_totals:
            ena_totals[key] += cumulative_increase([sample[key] for sample in values])
    ena_by_interface = {}
    for (node, iface), values in sorted(ena_grouped.items()):
        values.sort(key=lambda sample: sample["time"])
        deltas_for_interface = {
            key: cumulative_increase([sample[key] for sample in values])
            for key in ena_totals
        }
        first = parse_time(values[0]["time"])
        last = parse_time(values[-1]["time"])
        sample_seconds = (last - first).total_seconds() if first and last else 0.0
        ena_by_interface[f"{node}/{iface}"] = {
            "rx_gbps": deltas_for_interface["rx_bytes"] * 8 / sample_seconds / 1_000_000_000
            if sample_seconds > 0
            else 0.0,
            "tx_gbps": deltas_for_interface["tx_bytes"] * 8 / sample_seconds / 1_000_000_000
            if sample_seconds > 0
            else 0.0,
            "sample_seconds": sample_seconds,
            "allowance_deltas": {
                key: deltas_for_interface[key] for key in ENA_ALLOWANCES
            },
        }
    ena_summary = {
        "interfaces": len(ena_grouped),
        "rx_gbps": sum(values["rx_gbps"] for values in ena_by_interface.values()),
        "tx_gbps": sum(values["tx_gbps"] for values in ena_by_interface.values()),
        "allowance_deltas": {key: ena_totals[key] for key in ENA_ALLOWANCES},
        "by_interface": ena_by_interface,
    }
    missing = []
    if not selected_cpu:
        missing.append("core CPU")
    if not any(within(sample, start, end) for sample in core):
        missing.append("core metrics")
    if not ena_grouped:
        missing.append("ENA")
    return {
        "available": True,
        "missing": missing,
        "core_pod_cpu": {
            "all_samples": range_summary([sample["value"] for sample in selected_cpu]),
            "by_pod": ranges_by_pod(selected_cpu),
        },
        "core_gauges": gauge_ranges,
        "core_network": network,
        "network_events": {
            "total": dict(sorted(events.items())),
            "by_pod": {
                pod: dict(sorted(values.items()))
                for pod, values in sorted(events_by_pod.items())
            },
        },
        "user_decrypt_stages": {"total": stages, "by_pod": stages_by_pod},
        "service_operations": {"total": service_total, "by_pod": service_by_pod},
        "ena": ena_summary,
    }


def analyze_directory(root: Path, run_id: int | None = None) -> dict[str, Any]:
    argo_log = read_file(root, "argo-workflow-logs.txt")
    github_log = read_file(root, "github-run.log")
    argo_rates = parse_rate_metrics(argo_log)
    github_rates = parse_rate_metrics(github_log)
    if has_sequential_windows(argo_rates):
        rates = argo_rates
    elif has_sequential_windows(github_rates):
        rates = github_rates
    elif argo_rates:
        rates = argo_rates
    else:
        rates = github_rates
        for rate in rates:
            rate.update(emitted_at=None, window_start=None, window_end=None)
    cpu_text = read_file(root, "core-cpu-samples.log")
    core_text = read_file(root, "core-metrics.log", "core-metrics-samples.log")
    ena_text = read_file(root, "ena-samples.log")
    if not ena_text:
        ena_files = [path for path in root.rglob("*.log") if "ena-probe" in str(path)]
        ena_text = "\n".join(
            path.read_text(encoding="utf-8", errors="replace") for path in ena_files
        )
    placement_text = read_file(root, "pod-placement.tsv")
    ena_lifecycle_text = read_file(root, "ena-lifecycle.log")
    diagnostic_text = read_files(
        root,
        "perf-diagnostics-controller.log",
        "ena-start.log",
        "ena-lifecycle.log",
        "ena-previous.log",
        "pod-placement.tsv",
    )
    cpu = parse_cpu(cpu_text)
    core = parse_core_metrics(core_text)
    ena = parse_ena(ena_text)
    placement = parse_placement(placement_text)
    ena_lifecycle = parse_ena_lifecycle(ena_lifecycle_text)
    download_warnings = read_file(root, "download-warnings.log").splitlines()
    for rate in rates:
        rate["correlation"] = summarize_window(rate, cpu, core, ena)

    metadata_text = read_file(root, "run.json")
    try:
        metadata = json.loads(metadata_text) if metadata_text else {}
    except json.JSONDecodeError:
        metadata = {}
    combined_log = f"{github_log}\n{argo_log}"
    phases = re.findall(r"Argo workflow phase:\s*(\w+)", combined_log)
    failed_conclusions = {
        "action_required",
        "cancelled",
        "failure",
        "startup_failure",
        "timed_out",
    }
    failed_jobs = [
        job.get("name")
        for job in metadata.get("jobs", [])
        if job.get("conclusion") in failed_conclusions and job.get("name")
    ]
    failed_steps = [
        {
            "job": job.get("name"),
            "step": step.get("name"),
            "conclusion": step.get("conclusion"),
        }
        for job in metadata.get("jobs", [])
        for step in job.get("steps", [])
        if step.get("conclusion") in failed_conclusions and step.get("name")
    ]
    missing = []
    for label, present in (
        ("rate metrics", bool(rates)),
        ("timestamped rate windows", any(rate["window_start"] for rate in rates)),
        ("core CPU samples", bool(cpu)),
        ("core application metrics", bool(core)),
        ("ENA samples", bool(ena)),
        ("pod placement", bool(placement)),
    ):
        if not present:
            missing.append(label)
    degraded_lines = [
        line.strip()
        for line in f"{core_text}\n{diagnostic_text}".splitlines()
        if any(
            marker in line
            for marker in (
                "sampler_error",
                "sampler_warning",
                "scrape_error",
                "scrape_partial",
                "warning:",
                "OOMKilled",
                "CrashLoopBackOff",
                "ImagePullBackOff",
                "ErrImagePull",
            )
        )
    ]
    degraded_lines.extend(
        line.strip()
        for line in ena_text.splitlines()
        if "no-ena-interface-found" in line
    )
    return {
        "run": {
            "id": run_id or metadata.get("databaseId") or metadata.get("id"),
            "url": metadata.get("url") or metadata.get("html_url"),
            "github_conclusion": metadata.get("conclusion"),
            "argo_phase": phases[-1] if phases else None,
            "head_branch": metadata.get("headBranch"),
            "head_sha": metadata.get("headSha"),
            "failed_jobs": failed_jobs,
            "failed_steps": failed_steps,
        },
        "rates": rates,
        "placement": placement,
        "instrumentation": {
            "cpu_samples": len(cpu),
            "core_metric_samples": len(core),
            "ena_samples": len(ena),
            "placement_rows": len(placement),
            "ena_lifecycle": ena_lifecycle,
            "missing": missing,
            "degraded_samples": degraded_lines,
            "download_warnings": download_warnings,
        },
    }


def number(value: Any, digits: int = 1) -> str:
    return "-" if value is None else f"{float(value):.{digits}f}"


def markdown_report(report: dict[str, Any]) -> str:
    run = report["run"]
    output = [f"# Performance run {run.get('id') or 'analysis'}", ""]
    output.append(
        f"GitHub conclusion: **{run.get('github_conclusion') or 'unknown'}**; "
        f"Argo phase: **{run.get('argo_phase') or 'unknown'}**."
    )
    if run.get("failed_steps"):
        failures = ", ".join(
            f"{failure.get('job') or '?'} / {failure['step']} ({failure['conclusion']})"
            for failure in run["failed_steps"]
        )
        output.append(f"Failed GitHub steps: {failures}.")
    output.extend(
        [
            "",
            "| Rung | Offered | Achieved | Window done | Drain done | Total done | Failed | Shed | "
            "Saturated | p50 | p99 | RPC submit peak | RPC result peak |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for rate in report["rates"]:
        metrics = rate["metrics"]
        latency = metrics.get("latency_ms", {})
        rpc = metrics.get("rpc_diagnostics", {})
        output.append(
            f"| {rate['kind']}-{metrics.get('target_rate', '?')} | "
            f"{metrics.get('offered', '-')} | {number(metrics.get('achieved_rate'))}/s | "
            f"{metrics.get('completed_in_window', metrics.get('completed', '-'))} | "
            f"{metrics.get('completed_during_drain', '-')} | {metrics.get('completed', '-')} | "
            f"{metrics.get('failed', '-')} | {metrics.get('shed', '-')} | "
            f"{str(metrics.get('saturated', '-')).lower()} | "
            f"{number(latency.get('p50'))} ms | {number(latency.get('p99'))} ms | "
            f"{rpc.get('submit_peak_in_flight', '-')} | {rpc.get('result_peak_in_flight', '-')} |"
        )

    for rate in report["rates"]:
        metrics = rate["metrics"]
        correlation = rate["correlation"]
        output.extend(["", f"## {rate['kind']}-{metrics.get('target_rate', '?')}", ""])
        output.append(
            f"Window: `{rate.get('window_start') or '?'} .. "
            f"{rate.get('window_end') or '?'}`"
        )
        rpc = metrics.get("rpc_diagnostics")
        if rpc:
            output.append(
                f"RPC statuses: submit={json.dumps(rpc.get('submit_status', {}), sort_keys=True)}; "
                f"result={json.dumps(rpc.get('result_status', {}), sort_keys=True)}; "
                f"retries={rpc.get('result_retries', 0)}."
            )
            output.append(
                "RPC concurrency: submit peak/outstanding "
                f"{rpc.get('submit_peak_in_flight', '-')}/"
                f"{rpc.get('outstanding_submit_rpcs', '-')}; result peak/outstanding "
                f"{rpc.get('result_peak_in_flight', '-')}/"
                f"{rpc.get('outstanding_result_rpcs', '-')}; post-quorum "
                f"total/drained/outstanding {rpc.get('post_quorum_tasks', '-')}/"
                f"{rpc.get('post_quorum_tasks_drained', '-')}/"
                f"{rpc.get('outstanding_post_quorum_tasks', '-')}."
            )
        client_network = metrics.get("network")
        if client_network:
            output.append(
                f"Client pod network: rx {number(client_network.get('rx_gbps'), 2)} Gbps, "
                f"tx {number(client_network.get('tx_gbps'), 2)} Gbps; "
                f"errors {client_network.get('rx_errors', 0)}/"
                f"{client_network.get('tx_errors', 0)}, drops "
                f"{client_network.get('rx_dropped', 0)}/"
                f"{client_network.get('tx_dropped', 0)}."
            )
        if not correlation.get("available"):
            output.append(f"Correlation unavailable: {correlation.get('reason')}.")
            continue
        cpu = correlation.get("core_pod_cpu", {}).get("all_samples")
        output.append(
            "KMS core pod CPU: "
            + (
                f"avg {number(cpu['avg'], 2)}, max {number(cpu['max'], 2)} cores per pod sample."
                if cpu
                else "no samples."
            )
        )
        core_network = correlation["core_network"]["total"]
        ena = correlation["ena"]
        output.append(
            f"KMS threshold-network metrics: rx {number(core_network['rx_gbps'], 2)} Gbps, "
            f"tx {number(core_network['tx_gbps'], 2)} Gbps."
        )
        if ena["interfaces"]:
            output.append(
                f"ENA: rx {number(ena['rx_gbps'], 2)} Gbps, tx {number(ena['tx_gbps'], 2)} "
                f"Gbps across {ena['interfaces']} interfaces; allowance deltas "
                f"`{json.dumps(ena['allowance_deltas'], sort_keys=True)}`."
            )
        else:
            output.append("ENA: no samples overlap this measurement window.")
        if correlation["network_events"]["total"]:
            output.append(
                "Nonzero network-event deltas: "
                f"`{json.dumps(correlation['network_events']['total'], sort_keys=True)}`."
            )
        decrypt_metric = "user" if rate["kind"] == "udec" else "pub"
        pending_metric = f"kms_meta_storage_{decrypt_metric}_decryptions"
        stored_metric = f"{pending_metric}_in_store"
        pending = correlation["core_gauges"].get(pending_metric, {}).get("all_samples")
        stored = correlation["core_gauges"].get(stored_metric, {}).get("all_samples")
        if pending or stored:
            output.append(
                f"Per-core {rate['kind'].upper()} meta-store sample maxima: pending "
                f"{number(pending['max'] if pending else None, 0)}; total stored "
                f"{number(stored['max'] if stored else None, 0)}."
            )
        queue = correlation["core_gauges"].get(
            "kms_tokio_global_queue_depth", {}
        ).get("all_samples")
        alive = correlation["core_gauges"].get("kms_tokio_alive_tasks", {}).get(
            "all_samples"
        )
        background = correlation["core_gauges"].get(
            "kms_user_decrypt_background_tasks", {}
        ).get("all_samples")
        output.append(
            f"Tokio queue max: {number(queue['max'] if queue else None, 0)}; "
            f"alive tasks max: {number(alive['max'] if alive else None, 0)}; "
            f"UDEC background tasks max: {number(background['max'] if background else None, 0)}."
        )
        stages = correlation["user_decrypt_stages"]["total"]
        if stages:
            stage_means = {
                stage: round(values["mean_microseconds"], 1)
                for stage, values in stages.items()
                if values["mean_microseconds"] is not None
            }
            output.append(
                f"Mean UDEC stage times (µs): `{json.dumps(stage_means, sort_keys=True)}`."
            )
        service = correlation["service_operations"]
        service_total = service["total"]
        if service_total["calls"]:
            call_rates = {
                operation: round(values["rate"], 1)
                for operation, values in service_total["calls"].items()
            }
            output.append(
                "Aggregate KMS service call rates (/s): "
                f"`{json.dumps(call_rates, sort_keys=True)}`."
            )
        if service_total["errors"]:
            output.append(
                "Aggregate KMS service error deltas: "
                f"`{json.dumps(service_total['errors'], sort_keys=True)}`."
            )
        if service_total["durations"]:
            duration_means = {
                operation: round(values["mean_milliseconds"], 3)
                for operation, values in service_total["durations"].items()
            }
            output.append(
                "Mean KMS service durations (ms): "
                f"`{json.dumps(duration_means, sort_keys=True)}`."
            )
        if correlation["missing"]:
            output.append("Missing in this window: " + ", ".join(correlation["missing"]) + ".")

        cpu_by_pod = correlation["core_pod_cpu"]["by_pod"]
        network_by_pod = correlation["core_network"]["by_pod"]
        gauges = correlation["core_gauges"]
        pods = sorted(
            set(cpu_by_pod)
            | set(network_by_pod)
            | {
                pod
                for gauge in gauges.values()
                for pod in gauge.get("by_pod", {})
            }
        )
        if pods:
            output.extend(
                [
                    "",
                    "| KMS core pod | CPU avg | CPU max | Net rx | Net tx | "
                    f"{rate['kind'].upper()} pending max | {rate['kind'].upper()} stored max | "
                    "Tokio queue max | Alive tasks max |",
                    "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
                ]
            )

            def gauge_max(name: str, pod: str) -> Any:
                return gauges.get(name, {}).get("by_pod", {}).get(pod, {}).get("max")

            for pod in pods:
                pod_cpu = cpu_by_pod.get(pod, {})
                pod_network = network_by_pod.get(pod, {})
                output.append(
                    f"| {pod} | {number(pod_cpu.get('avg'), 2)} | "
                    f"{number(pod_cpu.get('max'), 2)} | "
                    f"{number(pod_network.get('rx_gbps'), 3)} Gbps | "
                    f"{number(pod_network.get('tx_gbps'), 3)} Gbps | "
                    f"{number(gauge_max(pending_metric, pod), 0)} | "
                    f"{number(gauge_max(stored_metric, pod), 0)} | "
                    f"{number(gauge_max('kms_tokio_global_queue_depth', pod), 0)} | "
                    f"{number(gauge_max('kms_tokio_alive_tasks', pod), 0)} |"
                )

        if service["by_pod"]:
            output.extend(
                [
                    "",
                    "| KMS core pod | Submit calls/s | Result calls/s | Service errors | "
                    "Request mean | Inner mean |",
                    "|---|---:|---:|---:|---:|---:|",
                ]
            )
            for pod, pod_service in service["by_pod"].items():
                calls = pod_service["calls"]
                durations = pod_service["durations"]
                request_mean = durations.get("user_decrypt_request", {}).get(
                    "mean_milliseconds"
                )
                inner_mean = durations.get("user_decrypt_inner", {}).get(
                    "mean_milliseconds"
                )
                output.append(
                    f"| {pod} | "
                    f"{number(calls.get('user_decrypt_request', {}).get('rate'), 1)} | "
                    f"{number(calls.get('user_decrypt_result', {}).get('rate'), 1)} | "
                    f"{number(sum(pod_service['errors'].values()), 0)} | "
                    f"{number(request_mean, 3)} ms | {number(inner_mean, 3)} ms |"
                )

    instrumentation = report["instrumentation"]
    output.extend(
        [
            "",
            "## Instrumentation",
            "",
            f"CPU samples: {instrumentation['cpu_samples']}; core metric samples: "
            f"{instrumentation['core_metric_samples']}; ENA samples: "
            f"{instrumentation['ena_samples']}; "
            f"placement rows: {instrumentation['placement_rows']}.",
        ]
    )
    if instrumentation["missing"]:
        output.append("Missing or unusable: " + ", ".join(instrumentation["missing"]) + ".")
    if instrumentation["degraded_samples"]:
        output.append(
            f"Sampler warnings/errors: {len(instrumentation['degraded_samples'])} "
            "(see JSON output or the original artifact for details)."
        )
    if instrumentation["download_warnings"]:
        output.append(
            f"Artifact download warnings: {len(instrumentation['download_warnings'])} "
            "(see JSON output or download-warnings.log for details)."
        )
    lifecycle = instrumentation["ena_lifecycle"]
    if lifecycle["samples"]:
        restarts = sum(
            int(pod["max_restarts"]) for pod in lifecycle["pods"].values()
        )
        output.append(
            f"ENA probe lifecycle: peak ready {lifecycle['max_ready']}/"
            f"{lifecycle['max_desired']}; first all-ready sample "
            f"{lifecycle['first_all_ready_at'] or '-'}; total container restarts {restarts}; "
            f"warning events {len(lifecycle['warning_events'])}."
        )
    if report["placement"]:
        output.extend(
            [
                "",
                "| Pod | Node | AZ | Instance | Node pool |",
                "|---|---|---|---|---|",
            ]
        )
        for row in report["placement"]:
            output.append(
                f"| {row['pod']} | {row['node']} | {row['zone']} | "
                f"{row['instance_type']} | {row['nodepool']} |"
            )
    return "\n".join(output) + "\n"


def download_run(repo: str, run_id: int, destination: Path) -> list[str]:
    destination.mkdir(parents=True, exist_ok=True)
    warnings = []
    artifact_payload = json.loads(
        run_command(
            "gh", "api", f"repos/{repo}/actions/runs/{run_id}/artifacts?per_page=100"
        )
    )
    available = {artifact["name"] for artifact in artifact_payload.get("artifacts", [])}
    for name in PERF_ARTIFACTS:
        artifact_dir = destination / name
        if name not in available:
            continue
        if artifact_dir.exists() and any(artifact_dir.iterdir()):
            continue
        artifact_dir.mkdir(exist_ok=True)
        try:
            run_command(
                "gh", "run", "download", str(run_id), "--repo", repo,
                "--name", name, "--dir", str(artifact_dir),
            )
        except RuntimeError as error:
            warnings.append(str(error))
    run_json = destination / "run.json"
    if not run_json.exists():
        try:
            run_json.write_text(
                run_command(
                    "gh", "run", "view", str(run_id), "--repo", repo, "--json",
                    "databaseId,url,conclusion,headBranch,headSha,createdAt,updatedAt,jobs",
                ),
                encoding="utf-8",
            )
        except RuntimeError as error:
            warnings.append(str(error))
    github_log = destination / "github-run.log"
    if not github_log.exists():
        try:
            github_log.write_text(
                run_command("gh", "run", "view", str(run_id), "--repo", repo, "--log"),
                encoding="utf-8",
            )
        except RuntimeError as error:
            warnings.append(str(error))
    if warnings:
        (destination / "download-warnings.log").write_text(
            "\n".join(warnings) + "\n", encoding="utf-8"
        )
    return warnings


class AnalyzerTests(unittest.TestCase):
    def test_parses_clean_and_collapsed_rungs(self) -> None:
        log = "\n".join(
            [
                'job\tstep\t2026-08-24T10:01:02Z pod: USER_DECRYPT_METRICS '
                '{"target_rate":2400,"duration":60,"measurement_elapsed_seconds":60,'
                '"drain_elapsed_seconds":2,"completed":144000,"completed_in_window":143900,'
                '"completed_during_drain":100,"failed":0,"shed":0,"achieved_rate":2400,'
                '"latency_ms":{"p50":7,"p99":10},"rpc_diagnostics":'
                '{"submit_status":{"ok":1872000},"result_status":{"ok":1296000},'
                '"submit_peak_in_flight":100,"result_peak_in_flight":200}}',
                'job\tstep\t2026-08-24T10:03:02Z pod: USER_DECRYPT_METRICS '
                '{"target_rate":2800,"duration":60,"completed":60000,"failed":10,"shed":90000,'
                '"achieved_rate":1000,"latency_ms":{"p50":9000,"p99":12000}}',
            ]
        )
        rates = parse_rate_metrics(log)
        self.assertEqual([rate["metrics"]["achieved_rate"] for rate in rates], [2400, 1000])
        self.assertEqual(rates[1]["metrics"]["shed"], 90000)
        self.assertEqual(rates[0]["window_start"], "2026-08-24T10:00:00Z")
        self.assertEqual(rates[0]["window_end"], "2026-08-24T10:01:00Z")
        self.assertEqual(rates[0]["metrics"]["completed_during_drain"], 100)
        self.assertTrue(has_sequential_windows(rates))

        replayed = parse_rate_metrics(log.replace("10:03:02Z", "10:01:03Z"))
        self.assertFalse(has_sequential_windows(replayed))

    def test_partial_artifacts_and_wrapper_result_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "run.json").write_text(
                json.dumps(
                    {
                        "databaseId": 42,
                        "conclusion": "cancelled",
                        "jobs": [
                            {
                                "name": "performance-testing",
                                "conclusion": "failure",
                                "steps": [
                                    {
                                        "name": "Deploy KMS using unified script",
                                        "conclusion": "failure",
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (root / "github-run.log").write_text(
                "Argo workflow phase: Succeeded\n", encoding="utf-8"
            )
            report = analyze_directory(root)
        self.assertEqual(report["run"]["github_conclusion"], "cancelled")
        self.assertEqual(report["run"]["argo_phase"], "Succeeded")
        self.assertEqual(
            report["run"]["failed_steps"][0]["step"], "Deploy KMS using unified script"
        )
        self.assertIn("rate metrics", report["instrumentation"]["missing"])

    def test_counter_and_cpu_accounting(self) -> None:
        start = parse_time("2026-08-24T10:00:00Z")
        end = parse_time("2026-08-24T10:01:00Z")
        assert start and end
        samples = parse_core_metrics(
            "2026-08-24T10:00:00Z p1 kms_network_rx_bytes_total 100\n"
            "2026-08-24T10:01:00Z p1 kms_network_rx_bytes_total 250\n"
            "2026-08-24T10:00:00Z p2 kms_network_rx_bytes_total 50\n"
            "2026-08-24T10:01:00Z p2 kms_network_rx_bytes_total 90\n"
        )
        deltas = counter_deltas(samples, start, end, ["kms_network_rx_bytes_total"])
        self.assertEqual(deltas[("p1", "kms_network_rx_bytes_total", ())], (150, 60))
        self.assertEqual(deltas[("p2", "kms_network_rx_bytes_total", ())], (40, 60))
        self.assertEqual(parse_cpu("2026-08-24T10:00:00Z p1 1250m 1Gi")[0]["cores"], 1.25)
        self.assertEqual(cumulative_increase([100, 150, 5, 10]), 60)

    def test_window_correlation_preserves_per_core_outliers(self) -> None:
        rate = {
            "window_start": "2026-08-24T10:00:00Z",
            "window_end": "2026-08-24T10:01:00Z",
        }
        cpu = parse_cpu(
            "2026-08-24T10:00:00Z p1 1000m 1Gi\n"
            "2026-08-24T10:01:00Z p1 2000m 1Gi\n"
            "2026-08-24T10:00:00Z p13 8000m 1Gi\n"
            "2026-08-24T10:01:00Z p13 10000m 1Gi\n"
        )
        core = parse_core_metrics(
            "2026-08-24T10:00:00Z p1 kms_tokio_global_queue_depth 1\n"
            "2026-08-24T10:01:00Z p1 kms_tokio_global_queue_depth 2\n"
            "2026-08-24T10:00:00Z p13 kms_tokio_global_queue_depth 100\n"
            "2026-08-24T10:01:00Z p13 kms_tokio_global_queue_depth 200\n"
            "2026-08-24T10:00:00Z p1 kms_network_rx_bytes_total 0\n"
            "2026-08-24T10:01:00Z p1 kms_network_rx_bytes_total 1000\n"
            "2026-08-24T10:00:00Z p13 kms_network_rx_bytes_total 0\n"
            "2026-08-24T10:01:00Z p13 kms_network_rx_bytes_total 9000\n"
            '2026-08-24T10:00:00Z p1 kms_operations_total{operation="user_decrypt_request"} 10\n'
            '2026-08-24T10:01:00Z p1 kms_operations_total{operation="user_decrypt_request"} 70\n'
            '2026-08-24T10:00:00Z p13 kms_operations_total{operation="user_decrypt_request"} 10\n'
            '2026-08-24T10:01:00Z p13 kms_operations_total{operation="user_decrypt_request"} 130\n'
        )
        summary = summarize_window(rate, cpu, core, [])
        self.assertEqual(summary["core_pod_cpu"]["by_pod"]["p13"]["max"], 10)
        self.assertEqual(
            summary["core_gauges"]["kms_tokio_global_queue_depth"]["by_pod"]["p13"][
                "max"
            ],
            200,
        )
        self.assertGreater(
            summary["core_network"]["by_pod"]["p13"]["rx_gbps"],
            summary["core_network"]["by_pod"]["p1"]["rx_gbps"],
        )
        p13_calls = summary["service_operations"]["by_pod"]["p13"]["calls"]
        self.assertEqual(p13_calls["user_decrypt_request"]["rate"], 2)

    def test_ena_lifecycle_reports_readiness_and_restarts(self) -> None:
        lifecycle = parse_ena_lifecycle(
            "2026-08-24T10:00:00Z\tdaemonset\t2026-08-24T09:59:00Z\t2\t2\t1\t1\n"
            "2026-08-24T10:00:00Z\tpod\tena-probe-a\tcreated\tstarted\tnode-a\tRunning\t"
            "false\t1\t\tCrashLoopBackOff\tOOMKilled\n"
            "2026-08-24T10:00:10Z\tdaemonset\t2026-08-24T09:59:00Z\t2\t2\t2\t0\n"
            "2026-08-24T10:00:10Z\tpod\tena-probe-a\tcreated\tstarted\tnode-a\tRunning\t"
            "true\t1\t2026-08-24T10:00:05Z\t\t\n"
            "2026-08-24T10:00:11Z\tena-probe-a\tWarning\tBackOff\trestarting container\n"
        )
        self.assertEqual(lifecycle["first_all_ready_at"], "2026-08-24T10:00:10Z")
        self.assertEqual(lifecycle["pods"]["ena-probe-a"]["max_restarts"], 1)
        self.assertEqual(
            lifecycle["pods"]["ena-probe-a"]["waiting_reasons"], ["CrashLoopBackOff"]
        )
        self.assertEqual(len(lifecycle["warning_events"]), 1)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--run-id", type=int, help="GitHub Actions run to download and analyze")
    source.add_argument("--artifacts", type=Path, help="Already-downloaded artifact directory")
    parser.add_argument("--repo", default="zama-ai/kms", help="GitHub OWNER/REPO")
    parser.add_argument("--download-dir", type=Path, help="Directory used with --run-id")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(AnalyzerTests)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
    if args.run_id is None and args.artifacts is None:
        raise SystemExit("provide --run-id, --artifacts, or --self-test")
    if args.run_id is not None and args.run_id <= 0:
        raise SystemExit("--run-id must be positive")
    if args.download_dir is not None and args.run_id is None:
        raise SystemExit("--download-dir requires --run-id")
    if args.artifacts is not None and not args.artifacts.is_dir():
        raise SystemExit(f"artifact directory does not exist: {args.artifacts}")
    if args.run_id is not None:
        root = args.download_dir or Path(f"perf-run-{args.run_id}")
        warnings = download_run(args.repo, args.run_id, root)
        for warning in warnings:
            print(f"warning: {warning}", file=sys.stderr)
    else:
        root = args.artifacts
    assert root is not None
    report = analyze_directory(root, args.run_id)
    rendered = (
        json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.format == "json"
        else markdown_report(report)
    )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

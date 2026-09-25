"""Scrapes selected Prometheus metrics with pod-proxy fallback."""

import argparse
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from perf_common import best_effort, cli, timestamp

EXPECTED = {
    "kms_completed_sessions",
    "kms_network_debug_events_total",
    "kms_network_sender_tasks",
    "kms_tokio_alive_tasks",
    "kms_tokio_global_queue_depth",
    "kms_user_decrypt_background_tasks",
    "kms_user_decrypt_stage_duration_microseconds_total",
    "kms_user_decrypt_stage_observations_total",
}
METRICS = EXPECTED | frozenset(
    {
        "kms_active_sessions",
        "kms_inactive_sessions",
        "kms_rate_limiter_usage",
        "kms_fhe_key_cache_size",
        "kms_meta_storage_user_decryptions",
        "kms_meta_storage_pub_decryptions",
        "kms_meta_storage_user_decryptions_in_store",
        "kms_meta_storage_pub_decryptions_in_store",
        "kms_network_rx_bytes_total",
        "kms_network_tx_bytes_total",
        "kms_tasks",
        "kms_cpu_load",
        "kms_process_cpu_usage",
        "kms_process_memory_usage",
        "kms_total_cpus",
        "kms_network_sender_tasks_spawned_total",
        "kms_network_sender_tasks_completed_total",
        "process_cpu_seconds_total",
        "process_threads",
    }
)


def extract_metrics(text, stamp, pod):
    selected, names = [], set()
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 2 or line.startswith("#"):
            continue
        name = fields[0].split("{", 1)[0]
        duration = name in {
            "kms_operation_duration_ms_bucket",
            "kms_operation_duration_ms_sum",
            "kms_operation_duration_ms_count",
        } and re.search(r'operation_type="(user|public)_decrypt_', line)
        operation = name in {"kms_operations_total", "kms_operation_errors_total"} and re.search(
            r'operation="(user|public)_decrypt_(request|result)"', line
        )
        if name in METRICS or duration or operation:
            selected.append(f"{stamp} {pod} {fields[0]} {fields[1]}")
            names.add(name)
    return selected, sorted(EXPECTED - names)


def scrape_pod(namespace, stamp, pod, ip, port, timeout):
    result = None
    method = "pod-ip"
    if ip:
        host = f"[{ip}]" if ":" in ip else ip
        result = best_effort(
            [
                "curl",
                "--fail",
                "--silent",
                "--show-error",
                "--connect-timeout",
                str(timeout),
                "--max-time",
                str(timeout),
                f"http://{host}:{port}/metrics",
            ],
            timeout=timeout + 1,
        )
    if result is None or result.returncode or not result.stdout:
        method = "pod-proxy"
        result = best_effort(
            [
                "kubectl",
                "get",
                f"--request-timeout={timeout}s",
                "--raw",
                f"/api/v1/namespaces/{namespace}/pods/{pod}:{port}/proxy/metrics",
            ],
            timeout=timeout + 1,
        )
    if result.returncode or not result.stdout:
        error = result.stderr.replace("\n", " ")
        return [f'{stamp} {pod} scrape_error error="{error}"']
    selected, missing = extract_metrics(result.stdout, stamp, pod)
    lines = [f"{stamp} {pod} scrape_ok method={method}"]
    if missing:
        lines.append(f"{stamp} {pod} scrape_partial missing={','.join(missing)}")
    return lines + selected


def scrape_once(namespace, port, timeout):
    stamp = timestamp()
    result = best_effort(
        [
            "kubectl",
            "get",
            "--request-timeout=10s",
            "pods",
            "-n",
            namespace,
            "-l",
            "app=kms-core",
            "-o",
            'jsonpath={range .items[*]}{.metadata.name}{"\\t"}{.status.podIP}{"\\n"}{end}',
        ],
        timeout=11,
    )
    if result.returncode:
        print(f'{stamp} sampler_error pod_discovery="{result.stderr.strip()}"', flush=True)
        return
    pods = []
    for line in result.stdout.splitlines():
        if line:
            name, _, ip = line.partition("\t")
            pods.append((name, ip))
    print(
        f"{stamp} sampler_discovery namespace={namespace} pods={len(pods)} expected=13", flush=True
    )
    with ThreadPoolExecutor(max_workers=13) as pool:
        futures = [
            pool.submit(scrape_pod, namespace, stamp, pod, ip, port, timeout) for pod, ip in pods
        ]
        for future in futures:
            print("\n".join(future.result()), flush=True)


NETWORK_EVENT = re.compile(r'^kms_network_debug_events_total[{].*event="([a-z_]+)"')
# A non-zero change of these events means that parties failed to talk to each other.
WARN_EVENTS = ("send_failed", "send_retry", "receive_wait_timeout")


def network_event_counts(lines):
    """Maps (pod, event) to the value of kms_network_debug_events_total in a snapshot."""
    counts = {}
    for line in lines:
        fields = line.split()
        if len(fields) == 4 and (match := NETWORK_EVENT.match(fields[2])):
            counts[(fields[1], match.group(1))] = float(fields[3])
    return counts


def network_event_deltas(before, after):
    """Returns the non-zero change per (pod, event) between two snapshots.

    A pod or event missing from `before` counts from zero. A negative change means that the
    pod restarted between the snapshots.
    """
    old, new = network_event_counts(before), network_event_counts(after)
    deltas = {key: value - old.get(key, 0) for key, value in new.items()}
    return {key: delta for key, delta in deltas.items() if delta}


def pod_order(pod):
    return [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", pod)]


def summarize_network_events(before_path, after_path, label):
    """Prints the network event changes between two snapshot files, plus scrape problems.

    Emits one GitHub warning annotation per event in WARN_EVENTS that grew on any pod.
    """
    before = before_path.read_text().splitlines()
    after = after_path.read_text().splitlines()
    for line in before + after:
        if " scrape_error " in line or " scrape_partial " in line:
            print(line)
    deltas = network_event_deltas(before, after)
    print(f"Network debug events during the {label} tests (non-zero changes only):")
    for (pod, event), delta in sorted(deltas.items(), key=lambda i: (pod_order(i[0][0]), i[0][1])):
        print(f"{pod:<22} {event:<30} {delta:g}")
    for event in WARN_EVENTS:
        pods = [
            f"{pod} (+{delta:g})"
            for (pod, name), delta in sorted(deltas.items(), key=lambda i: pod_order(i[0][0]))
            if name == event and delta > 0
        ]
        if pods:
            print(f"::warning title=Network events ({label})::{event} on {', '.join(pods)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("namespace", nargs="?", default="kms-ci")
    parser.add_argument("interval", nargs="?", type=float, default=5)
    parser.add_argument("port", nargs="?", type=int, default=9646)
    parser.add_argument("--once", action="store_true", help="take one snapshot and exit")
    parser.add_argument(
        "--network-delta",
        nargs=2,
        type=Path,
        metavar=("BEFORE", "AFTER"),
        help="summarize the network events between two --once snapshots and exit",
    )
    parser.add_argument("--label", default="", help="test label for --network-delta output")
    args = parser.parse_args()
    if args.network_delta:
        summarize_network_events(*args.network_delta, args.label)
        return
    timeout = float(os.environ.get("SCRAPE_TIMEOUT", "4"))
    if args.interval <= 0 or timeout <= 0 or not 0 < args.port < 65536:
        parser.error("interval and timeout must be positive; port must be 1..65535")
    if args.once:
        scrape_once(args.namespace, args.port, timeout)
        return
    print(
        f"{timestamp()} sampler_start namespace={args.namespace} "
        f"interval={args.interval:g}s port={args.port}",
        flush=True,
    )
    while True:
        scrape_once(args.namespace, args.port, timeout)
        time.sleep(args.interval)


if __name__ == "__main__":
    cli(main)

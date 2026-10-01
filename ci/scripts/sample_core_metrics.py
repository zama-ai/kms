"""Scrapes selected Prometheus metrics with pod-proxy fallback."""

import argparse
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor

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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("namespace", nargs="?", default="kms-ci")
    parser.add_argument("interval", nargs="?", type=float, default=5)
    parser.add_argument("port", nargs="?", type=int, default=9646)
    args = parser.parse_args()
    timeout = float(os.environ.get("SCRAPE_TIMEOUT", "4"))
    if args.interval <= 0 or timeout <= 0 or not 0 < args.port < 65536:
        parser.error("interval and timeout must be positive; port must be 1..65535")
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

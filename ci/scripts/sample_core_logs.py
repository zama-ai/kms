"""Streams kms-core container logs for the whole run.

Collecting logs once at the end loses everything that container log rotation has already
discarded, and everything a restarted container printed before it died. Following each
container from the start keeps both.
"""

import argparse
import gzip
import os
import subprocess
import threading
from pathlib import Path

from perf_common import cli, kube_json, timestamp

REATTACH_DELAY_SECS = 5
POD_DISCOVERY_INTERVAL_SECS = 30


def containers():
    # In enclave mode kms-server runs inside the enclave and its output reaches the pod through
    # the logger container; the kms-core container runs the enclave and the liveness probe.
    if os.environ.get("DEPLOYMENT_TYPE") == "thresholdWithEnclave":
        return ["kms-core-enclave-logger", "kms-core"]
    return ["kms-core"]


def follow(namespace, pod, container, path, stop, processes):
    """Follows one container, reattaching after restarts from the last timestamp seen."""
    since = None
    with gzip.open(path, "at") as out:
        while not stop.is_set():
            origin = f"--since-time={since}" if since else "--tail=-1"
            out.write(f"### {timestamp()} following {pod}/{container} ({origin})\n")
            process = subprocess.Popen(
                ["kubectl", "-n", namespace, "logs", "-f", "--timestamps", origin, pod, "-c", container],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            processes.append(process)
            for count, line in enumerate(process.stdout, 1):
                out.write(line)
                stamp = line.split(" ", 1)[0]
                if stamp[:4].isdigit():
                    since = stamp
                if count % 1000 == 0:
                    out.flush()
            process.wait()
            out.write(f"### {timestamp()} stream ended with status {process.returncode}\n")
            out.flush()
            stop.wait(REATTACH_DELAY_SECS)


def stream(namespace, output):
    output.mkdir(parents=True, exist_ok=True)
    stop = threading.Event()
    processes, threads, followed = [], [], set()
    try:
        while True:
            pods = kube_json(namespace, "get", "pods", "-l", "app=kms-core").get("items", [])
            for pod in pods:
                name = pod.get("metadata", {}).get("name")
                for container in containers():
                    if not name or (name, container) in followed:
                        continue
                    followed.add((name, container))
                    thread = threading.Thread(
                        target=follow,
                        args=(
                            namespace,
                            name,
                            container,
                            output / f"{name}-{container}.log.gz",
                            stop,
                            processes,
                        ),
                        daemon=True,
                    )
                    thread.start()
                    threads.append(thread)
            if stop.wait(POD_DISCOVERY_INTERVAL_SECS):
                break
    finally:
        stop.set()
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for thread in threads:
            thread.join(timeout=30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("namespace", nargs="?", default="kms-ci")
    parser.add_argument("output", nargs="?", type=Path, default=Path("perf-diagnostics/core-logs"))
    args = parser.parse_args()
    stream(args.namespace, args.output)


if __name__ == "__main__":
    cli(main)

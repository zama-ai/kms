"""Samples core CPU and memory through Kubernetes metrics-server."""

import argparse
import time

from perf_common import best_effort, cli, timestamp


def sample(namespace):
    stamp = timestamp()
    result = best_effort(
        ["kubectl", "top", "pod", "-n", namespace, "-l", "app=kms-core", "--no-headers"]
    )
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 3:
            print(stamp, *fields[:3], flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("namespace", nargs="?", default="kms-ci")
    parser.add_argument("interval", nargs="?", type=float, default=10)
    args = parser.parse_args()
    if args.interval <= 0:
        parser.error("interval must be positive")
    while True:
        sample(args.namespace)
        time.sleep(args.interval)


if __name__ == "__main__":
    cli(main)

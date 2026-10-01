"""Captures pod interface counters and reports before/after traffic deltas."""

import argparse
import csv
import datetime
import os
import re
from pathlib import Path

from perf_common import best_effort, cli, kube_json, timestamp

HEADER = [
    "pod",
    "container",
    "iface",
    "mtu",
    "rx_bytes",
    "tx_bytes",
    "rx_packets",
    "tx_packets",
    "rx_errors",
    "tx_errors",
    "rx_dropped",
    "tx_dropped",
]
# This command runs in existing core containers, which do not require Python.
REMOTE_COUNTERS = r"""
for iface_path in /sys/class/net/*; do
    iface="${iface_path##*/}"
    printf "%s\t%s\t%s\t" "$1" "$2" "${iface}"
    cat "${iface_path}/mtu" 2>/dev/null | tr "\n" "\t" || printf "\t"
    for stat in rx_bytes tx_bytes rx_packets tx_packets \
        rx_errors tx_errors rx_dropped tx_dropped; do
        cat "${iface_path}/statistics/${stat}" 2>/dev/null | tr "\n" "\t" || printf "\t"
    done
    printf "\n"
done
"""


def read_rows(path):
    with path.open() as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def number(value):
    try:
        return int(value or 0)
    except ValueError:
        return 0


def counter_deltas(before, after):
    indexed = {tuple(row[key] for key in HEADER[:3]): row for row in before}
    rows = []
    for row in after:
        previous = indexed.get(tuple(row[key] for key in HEADER[:3]), {})
        delta = {key: row.get(key, "") for key in HEADER[:4]}
        delta.update({key: number(row.get(key)) - number(previous.get(key)) for key in HEADER[4:]})
        rows.append(delta)
    return rows


def elapsed(before, after):
    def captured(path):
        for line in path.read_text().splitlines():
            if line.startswith("captured_at="):
                return datetime.datetime.fromisoformat(line.split("=", 1)[1].replace("Z", "+00:00"))
        raise ValueError("missing captured_at")

    try:
        return int((captured(after) - captured(before)).total_seconds())
    except (OSError, ValueError):
        return 0


def print_summary(rows, seconds):
    def rate(value):
        return value * 8 / seconds / 1e9 if seconds > 0 else 0

    def metrics(row):
        rx, tx = (number(row.get(key)) for key in ("rx_bytes", "tx_bytes"))
        return (
            f"rx={rx / 1024**3:.2f}GiB tx={tx / 1024**3:.2f}GiB "
            f"avg_rx={rate(rx):.2f}Gbps avg_tx={rate(tx):.2f}Gbps"
        )

    rows = [row for row in rows if row["iface"] == "eth0"]
    print(f"[network] kms-core eth0 deltas since before-perf (window={seconds}s)")
    for row in rows:
        print(
            f"[network] {row['pod']:<24} mtu={row['mtu']} {metrics(row)} "
            f"err={row['rx_errors']}/{row['tx_errors']} "
            f"drop={row['rx_dropped']}/{row['tx_dropped']}"
        )
    total = {key: sum(number(row[key]) for row in rows) for key in HEADER[4:]}
    print(
        f"[network] TOTAL kms-core eth0 pods={len(rows)} {metrics(total)} "
        f"packets={total['rx_packets']}/{total['tx_packets']} "
        f"err={total['rx_errors']}/{total['tx_errors']} "
        f"drop={total['rx_dropped']}/{total['tx_dropped']}"
    )
    print(
        "[network] note: this is pod-level KMS core traffic only. "
        "Per-rate core-client rx/tx is measured inside Argo and shown in the Slack report."
    )


def collect(phase, namespace, base):
    output = base / phase
    output.mkdir(parents=True, exist_ok=True)
    stamp = timestamp()
    summary = output / "summary.txt"
    summary.write_text(f"phase={phase}\nnamespace={namespace}\ncaptured_at={stamp}\n")
    print(f"[network] {phase}: namespace={namespace} captured_at={stamp}")
    for title, args in [
        (
            "nodes",
            [
                "nodes",
                "-o",
                (
                    r"custom-columns=NAME:.metadata.name,"
                    r"INSTANCE:.metadata.labels.node\.kubernetes\.io/instance-type,"
                    r"NODEPOOL:.metadata.labels.karpenter\.sh/nodepool,"
                    r"ZONE:.metadata.labels.topology\.kubernetes\.io/zone"
                ),
            ],
        ),
        (
            "kms-core pods",
            [
                "pods",
                "-n",
                namespace,
                "-l",
                "app=kms-core",
                "-o",
                (
                    "custom-columns=NAME:.metadata.name,PHASE:.status.phase,"
                    "NODE:.spec.nodeName,IP:.status.podIP"
                ),
            ],
        ),
    ]:
        print(f"[network] {title}")
        print(best_effort(["kubectl", "get", *args]).stdout, end="")
    counters = output / "pod-interface-counters.tsv"
    with counters.open("w") as stream:
        stream.write("\t".join(HEADER) + "\n")
        for pod in kube_json(namespace, "get", "pods").get("items", []):
            name = pod.get("metadata", {}).get("name", "")
            containers = pod.get("spec", {}).get("containers", [])
            if (
                pod.get("status", {}).get("phase") != "Running"
                or not re.fullmatch(r"kms-core-\d+-core-\d+", name)
                or not containers
            ):
                continue
            container = containers[0]["name"]
            result = best_effort(
                [
                    "kubectl",
                    "exec",
                    "-n",
                    namespace,
                    name,
                    "-c",
                    container,
                    "--",
                    "sh",
                    "-c",
                    REMOTE_COUNTERS,
                    "_",
                    name,
                    container,
                ],
                timeout=20,
            )
            stream.write(result.stdout)
    rows = read_rows(counters)
    print(
        f"[network] captured eth counters for {sum(row['iface'] == 'eth0' for row in rows)} "
        "running kms-core pods"
    )
    before = base / "before-perf" / counters.name
    if phase == "after-perf" and before.exists():
        deltas = counter_deltas(read_rows(before), rows)
        with (base / "pod-interface-counter-delta.tsv").open("w") as stream:
            writer = csv.DictWriter(stream, fieldnames=HEADER, delimiter="\t", lineterminator="\n")
            writer.writeheader()
            writer.writerows(deltas)
        print_summary(deltas, elapsed(before.parent / "summary.txt", summary))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", nargs="?", default="snapshot")
    parser.add_argument("namespace", nargs="?", default=os.environ.get("NAMESPACE", "kms-ci"))
    args = parser.parse_args()
    if not args.phase or Path(args.phase).name != args.phase or args.phase in {".", ".."}:
        parser.error("phase must be a directory name")
    collect(
        args.phase,
        args.namespace,
        Path(os.environ.get("NETWORK_DIAGNOSTICS_DIR", "network-diagnostics")),
    )


if __name__ == "__main__":
    cli(main)

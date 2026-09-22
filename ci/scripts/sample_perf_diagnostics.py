"""Coordinates CPU, application metrics, ENA lifecycle, and pod placement samples."""

import argparse
import time
from pathlib import Path

from perf_common import (
    ROOT,
    best_effort,
    cli,
    kube_json,
    start_sampler,
    stop_samplers,
    timestamp,
    tsv,
)


def lifecycle_rows(daemonset, pods, stamp):
    rows = []
    if daemonset:
        status = daemonset.get("status", {})
        rows.append(
            [
                stamp,
                "daemonset",
                daemonset.get("metadata", {}).get("creationTimestamp"),
                *[
                    status.get(key, 0)
                    for key in (
                        "desiredNumberScheduled",
                        "currentNumberScheduled",
                        "numberReady",
                        "numberUnavailable",
                    )
                ],
            ]
        )
    for pod in pods.get("items", []):
        meta, status = pod.get("metadata", {}), pod.get("status", {})
        container = (status.get("containerStatuses") or [{}])[0]
        state = container.get("state") or {}
        rows.append(
            [
                stamp,
                "pod",
                meta.get("name"),
                meta.get("creationTimestamp"),
                status.get("startTime"),
                pod.get("spec", {}).get("nodeName"),
                status.get("phase"),
                container.get("ready", False),
                container.get("restartCount", 0),
                state.get("running", {}).get("startedAt", ""),
                state.get("waiting", {}).get("reason", ""),
                state.get("terminated", {}).get("reason", ""),
            ]
        )
    return rows


def finish(namespace, output):
    def capture(args, stream):
        result = best_effort(
            ["kubectl", "--request-timeout=30s", "-n", namespace, *args], timeout=35
        )
        stream.write(result.stdout + result.stderr)

    for name, extra in [("ena-samples.log", []), ("ena-previous.log", ["--previous"])]:
        with (output / name).open("w") as stream:
            capture(
                [
                    "logs",
                    "-l",
                    "app=ena-probe",
                    "--prefix",
                    "--all-containers",
                    *extra,
                    "--tail=-1",
                ],
                stream,
            )
    with (output / "ena-lifecycle.log").open("a") as stream:
        stream.write(f"{timestamp()} final ENA probe descriptions\n")
        capture(["describe", "daemonset/ena-probe"], stream)
        capture(["describe", "pods", "-l", "app=ena-probe"], stream)
        stream.write(f"{timestamp()} final ENA probe events\n")
        capture(["events", "--for", "daemonset/ena-probe", "--types=Warning,Normal"], stream)
        for event in kube_json(
            namespace, "get", "events", "--field-selector", "involvedObject.kind=Pod"
        ).get("items", []):
            name = event.get("involvedObject", {}).get("name", "")
            if name.startswith("ena-probe-"):
                stream.write(
                    tsv(
                        [
                            event.get("eventTime")
                            or event.get("lastTimestamp")
                            or event.get("metadata", {}).get("creationTimestamp"),
                            name,
                            event.get("type"),
                            event.get("reason"),
                            event.get("message"),
                        ]
                    )
                    + "\n"
                )


def sample(namespace, output):
    output.mkdir(parents=True, exist_ok=True)
    children = []
    try:
        # The CPU artifact and analyzer expect this file at the workspace root.
        children.append(start_sampler("sample_core_cpu.py", [namespace], "core-cpu-samples.log"))
        with (output / "ena-start.log").open("w") as stream:
            stream.write(f"{timestamp()} applying ENA probe\n")
            result = best_effort(
                [
                    "kubectl",
                    "apply",
                    "--request-timeout=30s",
                    "-f",
                    str(ROOT / "ci/perf-testing/ena-probe.yml"),
                ],
                timeout=35,
            )
            stream.write(result.stdout + result.stderr)
            message = (
                "ENA probe applied"
                if result.returncode == 0
                else "warning: ENA probe could not be started; continuing"
            )
            stream.write(f"{timestamp()} {message}\n")
        for script, name in [
            ("sample_core_metrics.py", "core-metrics.log"),
            ("sample_pod_placement.py", "pod-placement.tsv"),
        ]:
            children.append(start_sampler(script, [namespace], output / name))
        with (output / "ena-lifecycle.log").open("w") as stream:
            stream.write("# daemonset: timestamp kind created desired current ready unavailable\n")
            stream.write(
                "# pod: timestamp kind pod created started node phase ready restarts "
                "container_started waiting_reason terminated_reason\n"
            )
            while True:
                stamp = timestamp()
                rows = lifecycle_rows(
                    kube_json(namespace, "get", "daemonset/ena-probe"),
                    kube_json(namespace, "get", "pods", "-l", "app=ena-probe"),
                    stamp,
                )
                for row in rows:
                    stream.write(tsv(row) + "\n")
                stream.flush()
                time.sleep(10)
    finally:
        stop_samplers(children)
        finish(namespace, output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("namespace", nargs="?", default="kms-ci")
    parser.add_argument("output", nargs="?", type=Path, default=Path("perf-diagnostics"))
    args = parser.parse_args()
    sample(args.namespace, args.output)


if __name__ == "__main__":
    cli(main)

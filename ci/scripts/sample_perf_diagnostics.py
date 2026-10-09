"""Coordinates CPU, application metrics, ENA lifecycle, pod placement, and kms-core restarts."""

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

FINALIZATION_TIMEOUT = 270  # The runner kills the process group after 300 seconds.
ENA_FINALIZATION_RESERVE = 90  # Preserve time for the existing ENA artifacts.


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


def core_lifecycle_rows(pods, stamp):
    """One row per kms-core container: readiness, restarts, and why it last terminated."""
    rows = []
    for pod in pods.get("items", []):
        name = pod.get("metadata", {}).get("name")
        for container in pod.get("status", {}).get("containerStatuses") or []:
            state = container.get("state") or {}
            last = (
                state.get("terminated")
                or (container.get("lastState") or {}).get("terminated")
                or {}
            )
            rows.append(
                [
                    stamp,
                    name,
                    container.get("name"),
                    container.get("ready", False),
                    container.get("restartCount", 0),
                    state.get("running", {}).get("startedAt", ""),
                    state.get("waiting", {}).get("reason", ""),
                    last.get("reason", ""),
                    last.get("exitCode", ""),
                    last.get("startedAt", ""),
                    last.get("finishedAt", ""),
                ]
            )
    return rows


def capture_before_deadline(namespace, args, deadline, timeout=30):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    timeout = min(timeout, remaining)
    result = best_effort(
        ["kubectl", f"--request-timeout={timeout:.3f}s", "-n", namespace, *args],
        timeout=timeout,
    )
    return result.stdout + result.stderr


def finish_core(namespace, output, deadline):
    """Records kms-core termination details and previous logs while the pods exist."""
    output.mkdir(parents=True, exist_ok=True)

    if deadline - time.monotonic() < 35:
        return
    pods = kube_json(namespace, "get", "pods", "-l", "app=kms-core")
    for pod in pods.get("items", []):
        name = pod.get("metadata", {}).get("name")
        for container in pod.get("status", {}).get("containerStatuses") or []:
            if container.get("restartCount", 0):
                text = capture_before_deadline(
                    namespace,
                    ["logs", "--previous", "--timestamps", name, "-c", container.get("name")],
                    deadline,
                    timeout=120,
                )
                if text is not None:
                    (output / f"{name}-{container.get('name')}-previous.log").write_text(text)
        if any(
            c.get("name") == "kms-core-enclave-logger"
            for c in pod.get("status", {}).get("containerStatuses") or []
        ):
            text = capture_before_deadline(
                namespace,
                [
                    "exec",
                    name,
                    "-c",
                    "kms-core-enclave",
                    "--",
                    "sh",
                    "-c",
                    "nitro-cli describe-enclaves; cat /var/log/nitro_enclaves/*.log",
                ],
                deadline,
                timeout=120,
            )
            if text is not None:
                (output / f"{name}-nitro.log").write_text(text)

    description = capture_before_deadline(
        namespace, ["describe", "pods", "-l", "app=kms-core"], deadline, timeout=120
    )
    if description is not None:
        (output / "describe-pods.txt").write_text(description)
    events = capture_before_deadline(
        namespace, ["get", "events", "--sort-by=.lastTimestamp", "-o", "wide"], deadline,
        timeout=120,
    )
    if events is not None:
        (output / "events.txt").write_text(events)


def finish(namespace, output, deadline):
    def capture(args, stream):
        stream.write(capture_before_deadline(namespace, args, deadline) or "")

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
        events = (
            kube_json(namespace, "get", "events", "--field-selector", "involvedObject.kind=Pod")
            if deadline - time.monotonic() >= 35
            else {}
        )
        for event in events.get("items", []):
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
        with (
            (output / "ena-lifecycle.log").open("w") as stream,
            (output / "core-lifecycle.tsv").open("w") as core_lifecycle,
        ):
            stream.write("# daemonset: timestamp kind created desired current ready unavailable\n")
            stream.write(
                "# pod: timestamp kind pod created started node phase ready restarts "
                "container_started waiting_reason terminated_reason\n"
            )
            core_lifecycle.write(
                "# timestamp pod container ready restarts started waiting_reason "
                "last_terminated_reason last_exit_code last_started last_finished\n"
            )
            while True:
                stamp = timestamp()
                for row in core_lifecycle_rows(
                    kube_json(namespace, "get", "pods", "-l", "app=kms-core"), stamp
                ):
                    core_lifecycle.write(tsv(row) + "\n")
                core_lifecycle.flush()
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
        deadline = time.monotonic() + FINALIZATION_TIMEOUT
        stop_samplers(children, timeout=10)
        finish_core(namespace, output / "core-restarts", deadline - ENA_FINALIZATION_RESERVE)
        finish(namespace, output, deadline)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("namespace", nargs="?", default="kms-ci")
    parser.add_argument("output", nargs="?", type=Path, default=Path("perf-diagnostics"))
    args = parser.parse_args()
    sample(args.namespace, args.output)


if __name__ == "__main__":
    cli(main)

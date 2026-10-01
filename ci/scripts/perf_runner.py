"""Runs performance workflow orchestration on the GitHub Actions runner."""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import deque
from pathlib import Path

from perf_common import (
    ROOT,
    SCRIPTS,
    best_effort,
    cli,
    run,
    start_sampler,
    stop_samplers,
)


def stage_tools():
    """Preserves the workflow's runner tools across the optional chart checkout.

    The workspace checkout supplies scenarios, Argo templates, and the ENA manifest.
    """
    destination = Path(os.environ["RUNNER_TEMP"]) / "kms-perf-tools"
    destination.mkdir(parents=True, exist_ok=True)
    for pattern in ("perf_*.py", "sample_*.py", "collect_*.py"):
        for script in sorted(SCRIPTS.glob(pattern)):
            shutil.copyfile(script, destination / script.name)
    github_env({"PERF_TOOLS_DIR": str(destination)})


def github_env(values):
    for key, value in values.items():
        if "\n" in value or "\r" in value:
            raise ValueError(f"{key} must be a single line")
    with open(os.environ["GITHUB_ENV"], "a") as stream:
        for key, value in values.items():
            stream.write(f"{key}={value}\n")


def summary(text):
    print(text, flush=True)
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as stream:
        stream.write(text + "\n")


def determine_tags():
    build = os.environ.get("DOCKER_BUILD_TAG", "")
    core = build or os.environ.get("INPUT_CORE_TAG", "")
    client = build or os.environ.get("INPUT_CLIENT_TAG", "")
    if not core or not client:
        raise ValueError(
            "Either build images or provide both kms_core_image_tag and kms_core_client_image_tag"
        )
    source = "docker-build" if build else "workflow-inputs"
    github_env({"KMS_CORE_IMAGE_TAG": core, "KMS_CORE_CLIENT_IMAGE_TAG": client})
    summary(
        "## KMS perf image tags\n\n| Field | Value |\n| --- | --- |\n"
        f"| Source | `{source}` |\n| KMS Core image tag | `{core}` |\n"
        f"| KMS Core client image tag | `{client}` |\n\n"
        "For a rerun without rebuilding, uncheck `Build new Docker images` "
        "and use the tags above."
    )


def validate():
    deployment, tls = os.environ["DEPLOYMENT_TYPE"], os.environ["TLS"]
    if deployment not in {"threshold", "thresholdWithEnclave"}:
        raise ValueError(f"performance-testing does not support deployment_type={deployment}")
    if tls == "true" and deployment != "thresholdWithEnclave":
        raise ValueError("TLS requires deployment_type=thresholdWithEnclave")
    github_env(
        {"PATH_SUFFIX": "kms-enclave-ci" if deployment == "thresholdWithEnclave" else "kms-ci"}
    )


def verify_images():
    repo = os.environ["IMAGE_REPO"]
    core = (
        "core-service-enclave-insecure"
        if "Enclave" in os.environ["DEPLOYMENT_TYPE"]
        else "core-service-insecure"
    )
    images = [
        f"{repo}/{core}:{os.environ['KMS_CORE_IMAGE_TAG']}",
        f"{repo}/core-client-insecure:{os.environ['KMS_CORE_CLIENT_IMAGE_TAG']}",
    ]
    missing = []
    for image in images:
        print(f"Checking {image}...", flush=True)
        for attempt in range(12):
            if best_effort(["docker", "manifest", "inspect", image]).returncode == 0:
                break
            if attempt < 11:
                time.sleep(5)
        else:
            missing.append(image)
    if missing:
        raise ValueError(
            f"Images not found after 12 attempts: {', '.join(missing)}. "
            "Check the tags or rerun with build=true."
        )
    summary(
        "## Verified perf images\n\n| Image |\n| --- |\n"
        + "\n".join(f"| `{image}` |" for image in images)
    )


def job_link():
    env = os.environ
    url = f"{env['SERVER_URL']}/{env['REPOSITORY']}/actions/runs/{env['RUN_ID']}"
    label = f"run {env['RUN_ID']}"
    if shutil.which("gh"):
        result = best_effort(
            ["gh", "api", f"repos/{env['REPOSITORY']}/actions/runs/{env['RUN_ID']}/jobs"]
        )
        try:
            if result.returncode == 0:
                for job in json.loads(result.stdout).get("jobs", []):
                    if job.get("name") == "performance-testing":
                        return job["html_url"], f"job {job['id']}"
        except (ValueError, KeyError, TypeError):
            pass
    return url, label


def execute_workflow(namespace):
    env = os.environ
    directory = ROOT / "ci/perf-testing"
    template = directory / "argo-workflow/kms-perf-workflow-kms-ci.yaml"
    # Keep the source template intact for diagnostics and repeated local invocations.
    generated = Path("perf-workflow.generated.yaml")
    run(
        [
            sys.executable,
            str(directory / "generate-perf-workflow.py"),
            "--scenarios",
            str(directory / "perf-scenarios.toml"),
            "--template",
            str(template),
            "-o",
            str(generated),
        ]
    )
    generated.write_text(
        generated.read_text()
        .replace("<client-version>", env["KMS_CORE_CLIENT_IMAGE_TAG"])
        .replace("<version>", env["KMS_CORE_IMAGE_TAG"])
    )
    url, label = job_link()
    params = {
        "tls": "enabled" if env["TLS"] == "true" else "disabled",
        "client-logs": "enabled" if env["CLIENT_LOGS"] == "true" else "disabled",
        "fhe-params": env["FHE_PARAMS"],
        "s3-config-map-name": "kms-enclave-ci-1"
        if env["DEPLOYMENT_TYPE"] == "thresholdWithEnclave"
        else "kms-ci-1",
        "run_url": f"{env['SERVER_URL']}/{env['REPOSITORY']}/actions/runs/{env['RUN_ID']}",
        "job_url": url,
        "job_label": label,
    }
    args = ["argo", "submit", "-n", namespace, str(generated)]
    for key, value in params.items():
        args.extend(["-p", f"{key}={value}"])
    result = run([*args, "-o", "json"], timeout=300)
    workflow = json.loads(result.stdout).get("metadata", {}).get("name")
    if not isinstance(workflow, str) or not workflow:
        raise ValueError("argo submit returned no workflow name")
    github_env({"PERF_WORKFLOW_NAME": workflow})
    print(f"Submitted Argo workflow: {workflow}", flush=True)
    try:
        waited = run(
            ["argo", "wait", workflow, "-n", namespace], timeout=3600, check=False, stdout=None
        )
        wait_exit = waited.returncode
    except subprocess.TimeoutExpired:
        wait_exit = 124
    with open("argo-workflow-logs.txt", "w") as stream:
        try:
            logs = run(
                ["argo", "logs", workflow, "-n", namespace, "--timestamps"],
                timeout=600,
                check=False,
                stdout=stream,
            )
            if logs.returncode:
                print(f"::warning::Could not fetch complete logs for {workflow}")
        except (OSError, subprocess.TimeoutExpired):
            print(f"::warning::Could not fetch complete logs for {workflow}")
    with open("argo-workflow-logs.txt") as stream:
        for line in stream:
            print(line, end="")
    result = run(
        ["argo", "get", workflow, "-n", namespace, "--request-timeout", "1m", "-o", "json"],
        timeout=65,
    )
    phase = json.loads(result.stdout).get("status", {}).get("phase")
    print(f"Argo workflow phase: {phase}")
    if wait_exit == 124:
        raise ValueError(f"Timed out waiting for {workflow}")
    if wait_exit:
        print(f"::warning::argo wait exited with status {wait_exit}")
    if phase != "Succeeded":
        raise ValueError(f"Workflow {workflow} ended in phase {phase}")


def performance():
    namespace = os.environ["NAMESPACE"]
    children = []
    try:
        # One session contains the controller, its samplers, and their commands.
        children.append(
            start_sampler(
                "sample_perf_diagnostics.py",
                [namespace, "perf-diagnostics"],
                "perf-diagnostics-controller.log",
                new_session=True,
            )
        )
        execute_workflow(namespace)
    finally:
        stop_samplers(children, process_groups=True)


def report_cpu():
    path = Path("core-cpu-samples.log")
    if not path.exists() or path.stat().st_size == 0:
        print(
            "[cpu] no samples captured — check metrics-server pod-metrics RBAC "
            f"for the CI identity in {os.environ['NAMESPACE']}"
        )
        return
    tail = deque(maxlen=500)
    count = 0
    with path.open() as stream:
        for line in stream:
            count += 1
            tail.append(line)
    print(
        "[cpu] per-core CPU via metrics-server (~15s resolution); cores request 48 vCPU (=48000m)."
    )
    print(
        "[cpu] full timeseries is in the core-cpu-samples artifact; "
        "correlate its timestamps with the rung timestamps in the Argo log."
    )
    print(f"[cpu] {count} sample lines captured; last 500 below:")
    print("".join(tail), end="")


def report_diagnostics():
    for title, name, pattern in [
        ("Placement snapshot", "pod-placement.tsv", None),
        (
            "Application-metrics sampler status",
            "core-metrics.log",
            r"sampler_(start|discovery|error)|scrape_(error|partial)",
        ),
        ("ENA probe status", "ena-start.log", None),
    ]:
        print(f"{title}:")
        try:
            with (Path("perf-diagnostics") / name).open() as stream:
                if pattern:
                    print(
                        "".join(
                            deque((line for line in stream if re.search(pattern, line)), maxlen=100)
                        ),
                        end="",
                    )
                else:
                    for line in stream:
                        print(line, end="")
        except FileNotFoundError:
            print(f"warning: {name} unavailable")


def core_logs():
    namespace = os.environ["NAMESPACE"]
    container = (
        "kms-core-enclave-logger"
        if os.environ["DEPLOYMENT_TYPE"] == "thresholdWithEnclave"
        else "kms-core"
    )
    for party in range(1, 14):
        pod = f"{os.environ.get('HELM_RELEASE_PREFIX', 'kms-core')}-{party}-core-{party}"
        path = Path(f"kms-core-{party}-logs.txt")
        if best_effort(["kubectl", "get", "pod", pod, "-n", namespace]).returncode:
            print(f"Pod {pod} not found, skipping log collection")
            path.touch()
        else:
            with path.open("w") as stream:
                run(
                    ["kubectl", "logs", pod, "-c", container, "-n", namespace],
                    stdout=stream,
                    timeout=300,
                )


def cleanup():
    namespace = os.environ["NAMESPACE"]

    def attempt(args):
        result = best_effort(args, timeout=360)
        print(result.stdout, end="")
        if result.returncode:
            print(f"::warning::Cleanup command failed: {' '.join(args)}: {result.stderr}")
        return result

    releases = attempt(["helm", "list", "-n", namespace, "-q"])
    if releases.returncode == 0:
        for release in releases.stdout.splitlines():
            attempt(["helm", "uninstall", "-n", namespace, release])
    for resource, label in [
        ("cm", "kms-core"),
        ("cm", "kms-core-client"),
        ("sts", "kms-core-client"),
    ]:
        attempt(["kubectl", "delete", resource, "-l", f"app={label}", "-n", namespace])
    attempt(
        [
            "kubectl",
            "delete",
            "-f",
            str(ROOT / "ci/perf-testing/ena-probe.yml"),
            "--ignore-not-found",
        ]
    )
    for label in ("kms-core", "kms-threshold-init-job"):
        attempt(["kubectl", "delete", "job", "-l", f"app={label}", "-n", namespace])
    if os.environ.get("PERF_WORKFLOW_NAME"):
        attempt(["argo", "delete", os.environ["PERF_WORKFLOW_NAME"], "-n", namespace])


COMMANDS = {
    "stage-tools": stage_tools,
    "determine-tags": determine_tags,
    "validate": validate,
    "verify-images": verify_images,
    "run": performance,
    "report-cpu": report_cpu,
    "report-diagnostics": report_diagnostics,
    "core-logs": core_logs,
    "cleanup": cleanup,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=COMMANDS)
    args = parser.parse_args()
    COMMANDS[args.command]()


if __name__ == "__main__":
    cli(main)

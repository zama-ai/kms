"""Process and output helpers for runner-side performance tools."""

import contextlib
import datetime
import json
import os
import signal
import subprocess
import sys
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("GITHUB_WORKSPACE", SCRIPTS.parent.parent))
SAMPLER_STOP_TIMEOUT = 300


def timestamp():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run(args, *, timeout=60, check=True, stdout=subprocess.PIPE):
    """Runs a command with a deadline and terminates it on cancellation."""
    with subprocess.Popen(args, text=True, stdout=stdout, stderr=subprocess.PIPE) as process:
        try:
            output, error = process.communicate(timeout=timeout)
        except (KeyboardInterrupt, SystemExit, subprocess.TimeoutExpired):
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
            raise
        result = subprocess.CompletedProcess(args, process.returncode, output or "", error or "")
        if check:
            result.check_returncode()
        return result


def best_effort(args, *, timeout=60):
    try:
        return run(args, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        return subprocess.CompletedProcess(args, 1, "", str(error))


def kube_json(namespace, *args):
    result = best_effort(
        ["kubectl", "--request-timeout=30s", "-n", namespace, *args, "-o", "json"], timeout=35
    )
    try:
        if result.returncode:
            raise ValueError(result.stderr)
        return json.loads(result.stdout)
    except (ValueError, TypeError) as error:
        print(f"kubectl {' '.join(args)} failed: {error}", file=sys.stderr)
        return {}


def tsv(values):
    # Match jq's @tsv escaping, including lowercase JSON booleans.
    def field(value):
        if value is None:
            return ""
        value = str(value).lower() if isinstance(value, bool) else str(value)
        return (
            value.replace("\\", "\\\\")
            .replace("\t", "\\t")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
        )

    return "\t".join(field(value) for value in values)


def start_sampler(script, args, output, *, new_session=False):
    """Starts a sampler in its controller's group unless it owns a new session."""
    with Path(output).open("w") as stream:
        return subprocess.Popen(
            [sys.executable, "-u", str(SCRIPTS / script), *args],
            stdout=stream,
            stderr=subprocess.STDOUT,
            start_new_session=new_session,
        )


def stop_samplers(processes, *, process_groups=False):
    """Stops controllers first so each can reap its own children and save diagnostics.

    Set process_groups only for controllers started with new_session=True.
    """
    for process in processes:
        if process.poll() is None:
            process.terminate()
    for process in processes:
        try:
            process.wait(timeout=SAMPLER_STOP_TIMEOUT)
        except subprocess.TimeoutExpired:
            if process_groups:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            process.wait()
        finally:
            # A failed controller can leave descendants after its own exit.
            if process_groups:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)


def cli(main):
    def cancel(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, cancel)
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except KeyError as error:
        print(f"::error::Missing required value: {error}", file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"::error::{error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr, file=sys.stderr)
        sys.exit(1)

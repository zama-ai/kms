#!/usr/bin/env python3
"""Post one Slack message that summarizes all job results of a nightly run."""

import argparse
import json
import os
import urllib.request

FAILED = {"failure", "timed_out", "startup_failure"}
EMOJI = {
    "success": ":white_check_mark:",
    "cancelled": ":no_entry_sign:",
    "in_progress": ":hourglass_flowing_sand:",
    "queued": ":hourglass_flowing_sand:",
}


def short_name(name: str) -> str:
    """Returns a readable label for a job name from the GitHub jobs API.

    Reusable workflows produce names such as
    `main/rust-testing / rust-testing/core-grpc-p1 / common-testing/compile-rust-unit-tests`.
    The label is the last segment that is not a `common-testing/` job, without
    the `main/` prefix. An implicit matrix suffix `(a, b, c)` becomes `(a)`.
    """
    parts = [
        part for part in name.split(" / ") if not part.startswith("common-testing/")
    ]
    label = (parts[-1] if parts else name).removeprefix("main/")
    head, sep, matrix = label.partition(" (")
    if not sep:
        return label
    return f"{head} ({matrix.split(', ', 1)[0].removesuffix(')')})"


def outcome(job: dict) -> str:
    """Returns the conclusion of `job`, or its status while it has no conclusion."""
    return job.get("conclusion") or job["status"]


def rank(result: str) -> int:
    """Returns the sort rank of a job outcome, so failed jobs come first."""
    if result in FAILED:
        return 0
    if result == "success":
        return 2
    return 1


def escape(text: str) -> str:
    """Returns `text` with the characters that Slack mrkdwn reserves escaped."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_payload(jobs: list[dict], run_url: str, own_runner: str) -> dict:
    """Returns the Slack attachment for the non-skipped jobs in `jobs`.

    The unfinished job on `own_runner` is the job that posts the summary, so
    it is left out. Other unfinished jobs are reported as not succeeded.
    """
    reported = [
        job
        for job in jobs
        if job.get("conclusion") != "skipped"
        and not (job.get("conclusion") is None and job.get("runner_name") == own_runner)
    ]
    reported.sort(key=lambda job: (rank(outcome(job)), short_name(job["name"])))
    failed = sum(1 for job in reported if outcome(job) != "success")
    if failed:
        header = f"<{run_url}|Nightly run>: {failed} of {len(reported)} jobs did not succeed."
    else:
        header = f"<{run_url}|Nightly run>: all {len(reported)} jobs succeeded."
    lines = [header, ""]
    for job in reported:
        result = outcome(job)
        emoji = EMOJI.get(result, ":x:" if result in FAILED else ":grey_question:")
        line = f"{emoji} <{job['html_url']}|{escape(short_name(job['name']))}>"
        if result != "success":
            line += f" ({result})"
        lines.append(line)
    return {
        "color": "danger" if failed or not reported else "good",
        "title": "Nightly Tests Result",
        "text": "\n".join(lines),
        "mrkdwn_in": ["text"],
    }


def main() -> None:
    """Reads the jobs of a run and posts the summary to the Slack webhook."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "jobs_file",
        help="output of `gh api --paginate --slurp .../actions/runs/<id>/jobs`",
    )
    parser.add_argument("run_url", help="URL of the workflow run")
    args = parser.parse_args()

    with open(args.jobs_file, encoding="utf-8") as handle:
        pages = json.load(handle)
    jobs = [job for page in pages for job in page["jobs"]]
    message = {
        "channel": os.environ["SLACK_CHANNEL"],
        "username": os.environ["SLACK_USERNAME"],
        "icon_emoji": ":github-octocat:",
        "attachments": [build_payload(jobs, args.run_url, os.environ["RUNNER_NAME"])],
    }
    print(message["attachments"][0]["text"])
    request = urllib.request.Request(
        os.environ["SLACK_WEBHOOK"],
        data=json.dumps(message).encode(),
        headers={"Content-Type": "application/json"},
    )
    # `urlopen` raises on a non-2xx status, which fails the step.
    with urllib.request.urlopen(request, timeout=30):
        pass


if __name__ == "__main__":
    main()

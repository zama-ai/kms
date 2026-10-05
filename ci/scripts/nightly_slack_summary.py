#!/usr/bin/env python3
"""Post one Slack message that summarizes all job results of a nightly run."""

import argparse
import json
import os
import urllib.request

FAILED = {"failure", "timed_out", "startup_failure"}
NOT_REPORTED = {None, "skipped"}
EMOJI = {"success": ":white_check_mark:", "cancelled": ":no_entry_sign:"}


def short_name(name: str) -> str:
    """Returns a readable label for a job name from the GitHub jobs API.

    Reusable workflows produce names such as
    `main/rust-testing / rust-testing/core-grpc-p1 / common-testing/compile-rust-unit-tests`.
    The label keeps the innermost segment that identifies the caller, and
    reduces an implicit matrix suffix `(a, b, c)` to its first value `(a)`.
    """
    parts = [
        part for part in name.split(" / ") if not part.startswith("common-testing/")
    ]
    label = parts[-1] if parts else name
    head, sep, matrix = label.partition(" (")
    if not sep:
        return label
    return f"{head} ({matrix.split(', ', 1)[0].removesuffix(')')})"


def rank(conclusion: str) -> int:
    """Returns the sort rank of a job conclusion, so failed jobs come first."""
    if conclusion in FAILED:
        return 0
    if conclusion == "success":
        return 2
    return 1


def build_payload(jobs: list[dict], run_url: str) -> dict:
    """Returns the Slack attachment for the finished, non-skipped jobs in `jobs`."""
    finished = [job for job in jobs if job.get("conclusion") not in NOT_REPORTED]
    finished.sort(key=lambda job: (rank(job["conclusion"]), short_name(job["name"])))
    failed = sum(1 for job in finished if job["conclusion"] != "success")
    if failed:
        header = f"<{run_url}|Nightly run>: {failed} of {len(finished)} jobs did not succeed."
    else:
        header = f"<{run_url}|Nightly run>: all {len(finished)} jobs succeeded."
    lines = [header, ""]
    for job in finished:
        conclusion = job["conclusion"]
        emoji = EMOJI.get(
            conclusion, ":x:" if conclusion in FAILED else ":grey_question:"
        )
        line = f"{emoji} <{job['html_url']}|{short_name(job['name'])}>"
        if conclusion != "success":
            line += f" ({conclusion})"
        lines.append(line)
    return {
        "color": "danger" if failed or not finished else "good",
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
        "attachments": [build_payload(jobs, args.run_url)],
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

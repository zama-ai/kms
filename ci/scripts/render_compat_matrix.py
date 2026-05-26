#!/usr/bin/env python3
"""Render the cross-version compatibility matrix as Markdown.

Reads:
  results_dir   directory containing result-<A>-<B>.json (and optionally a
                nested result-<A>-<B>/result.json laid out by upload-artifact).
                Each file is the shape emitted by compat_matrix_emit_result.sh.
  config_path   ci/compat-matrix.json (for the canonical version list, the
                explicit skip_cells list, and ordering).

Writes Markdown to stdout. Exits 0 if every cell is pass / fail / skip,
exits 1 if any cell is `error` (workflow-level problem that needs operator
attention).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PASS = "✅"
FAIL = "❌"
ERROR = "⚠️"
SKIP = "⊘"
MISSING = "⚠️ missing"


def find_results(results_dir: Path) -> dict[tuple[str, str], dict]:
    """Find result-*.json files. upload-artifact may nest them in subdirs."""
    out: dict[tuple[str, str], dict] = {}
    for path in results_dir.rglob("result.json"):
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            print(f"warning: could not read {path}: {exc}", file=sys.stderr)
            continue
        a = data.get("producer")
        b = data.get("consumer")
        if not a or not b:
            print(f"warning: {path} missing producer/consumer", file=sys.stderr)
            continue
        out[(a, b)] = data
    return out


def cell_markdown(status: str, run_url: str) -> str:
    if status == "pass":
        emoji = PASS
    elif status == "fail":
        emoji = FAIL
    elif status == "error":
        emoji = ERROR
    else:
        return f"`{status}`"
    if run_url:
        return f"[{emoji}]({run_url})"
    return emoji


def render(results_dir: Path, config_path: Path) -> tuple[str, bool]:
    cfg = json.loads(config_path.read_text())
    versions: list[str] = cfg["versions"]
    skips = {
        (s["producer"], s["consumer"]): s.get("reason", "")
        for s in cfg.get("skip_cells", [])
    }
    results = find_results(results_dir)

    any_error = False
    lines: list[str] = []
    lines.append("# node-tkms ↔ kms compatibility matrix")
    lines.append("")
    lines.append(
        "Rows: kms producer (server) version. "
        "Columns: node-tkms consumer (client) version. "
        "Same-version cells are run as a sanity check. "
        f"Legend: {PASS} pass, {FAIL} incompatible, "
        f"{ERROR} workflow error, {SKIP} explicitly skipped."
    )
    lines.append("")

    header = "| Producer ↓ / Consumer → | " + " | ".join(f"`{v}`" for v in versions) + " |"
    sep = "|---|" + "|".join(["---"] * len(versions)) + "|"
    lines.append(header)
    lines.append(sep)

    for a in versions:
        row = [f"**`{a}`**"]
        for b in versions:
            if (a, b) in skips:
                row.append(SKIP)
                continue
            cell = results.get((a, b))
            if cell is None:
                row.append(MISSING)
                any_error = True
                continue
            status = cell.get("status", "error")
            if status == "error":
                any_error = True
            row.append(cell_markdown(status, cell.get("run_url", "")))
        lines.append("| " + " | ".join(row) + " |")

    failed_cells = sorted(
        (k for k, v in results.items() if v.get("status") in {"fail", "error"})
    )
    if failed_cells:
        lines.append("")
        lines.append("## Failure details")
        lines.append("")
        for (a, b) in failed_cells:
            data = results[(a, b)]
            status = data.get("status", "?")
            excerpt = (data.get("log_excerpt") or "").strip()
            lines.append(f"### `{a}` → `{b}` ({status})")
            if data.get("run_url"):
                lines.append(f"Run: {data['run_url']}")
            lines.append("")
            if excerpt:
                lines.append("```")
                lines.append(excerpt)
                lines.append("```")
            lines.append("")

    if skips:
        lines.append("")
        lines.append("## Skipped cells")
        lines.append("")
        for (a, b), reason in sorted(skips.items()):
            lines.append(f"- `{a}` → `{b}`: {reason or '(no reason given)'}")
        lines.append("")

    return "\n".join(lines) + "\n", any_error


def main() -> int:
    if len(sys.argv) != 3:
        print(
            f"usage: {sys.argv[0]} <results_dir> <compat-matrix.json>",
            file=sys.stderr,
        )
        return 64
    results_dir = Path(sys.argv[1])
    config_path = Path(sys.argv[2])
    if not results_dir.is_dir():
        print(f"results dir not found: {results_dir}", file=sys.stderr)
        return 1
    if not config_path.is_file():
        print(f"config not found: {config_path}", file=sys.stderr)
        return 1

    markdown, any_error = render(results_dir, config_path)
    sys.stdout.write(markdown)
    return 1 if any_error else 0


if __name__ == "__main__":
    sys.exit(main())

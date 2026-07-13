#!/usr/bin/env python3
"""Expand perf-scenarios.toml into the concrete Argo perf workflow.

Reads a workflow *template* containing `# <<GENERATED:NAME>>` marker lines and
replaces each with a block generated from the rate scenarios in the scenarios file.
Run at submit time (see the "Run performance testing" step), before the image-tag
`sed`. Fails loudly on any invalid scenario so a bad edit never reaches a run.

  generate-perf-workflow.py --scenarios perf-scenarios.toml \
      --template argo-workflow/kms-perf-workflow-kms-ci.yaml -o <out>

Reads TOML via the stdlib `tomllib` (Python >= 3.11) — no third-party deps.

Markers (indentation is taken from the marker line, so blocks land correctly):
  dag-tasks       the rate DAG tasks (chained, previous-ok gated)
  summary-args    the summary task's test-result arguments
  summary-inputs  the summary template's test-result input params
  summary-echo    the summary's "write each result JSON" lines
  rate-vars       `<kind>_rates="…"` shell vars for the per-kind summary loops
"""
import argparse
import sys
import tomllib

RATE_KEYS = {"rate", "duration", "pause", "maxfail", "maxshed", "pct", "allowfail"}
DEFAULT_KEYS = {"duration", "pause", "maxfail", "maxshed", "pct", "allowfail"}


def die(msg):
    sys.exit(f"generate-perf-workflow: {msg}")


def load_scenarios(path):
    with open(path, "rb") as f:
        doc = tomllib.load(f)
    if not isinstance(doc, dict) or "defaults" not in doc or "scenarios" not in doc:
        die(f"{path}: expected top-level [defaults] and [scenarios] tables")
    defaults = doc["defaults"]
    missing = DEFAULT_KEYS - set(defaults)
    if missing:
        die(f"defaults is missing required keys: {sorted(missing)}")
    scenarios = doc["scenarios"]
    if not isinstance(scenarios, dict) or not scenarios:
        die("'scenarios' must be a non-empty mapping of kind -> config")

    resolved = {}
    for kind, scen in scenarios.items():
        if "key" not in scen or "rates" not in scen:
            die(f"scenario '{kind}' needs 'key' and 'rates'")
        rates = []
        for i, entry in enumerate(scen["rates"]):
            if not isinstance(entry, dict):
                die(f"{kind}.rates[{i}] must be an inline table with a 'rate' key, got {entry!r}")
            if "rate" not in entry:
                die(f"{kind}.rates[{i}] is missing required key 'rate'")
            unknown = set(entry) - RATE_KEYS
            if unknown:
                die(f"{kind}.rates[{i}] (rate {entry['rate']}) has unknown keys: {sorted(unknown)}")
            rates.append({**defaults, **entry})
        resolved[kind] = {"key": scen["key"], "after": scen.get("after", []), "rates": rates}
    return resolved


def dag_tasks(kind, scen):
    key, after, rates = scen["key"], scen["after"], scen["rates"]
    out = []
    prev = None
    for r in rates:
        name = f"{kind}-rate-{r['rate']}"
        if prev is None:
            deps = [key] + after
            prevok = "true"
        else:
            deps = [prev]
            prevok = f"{{{{tasks.{prev}.outputs.parameters.capacity-ok}}}}"
        deps_str = ", ".join(f'"{d}"' for d in deps)
        allowfail = "true" if r["allowfail"] else "false"
        out += [
            f"- name: {name}",
            f"  dependencies: [{deps_str}]",
            f"  template: run-{kind}-rate",
            "  arguments:",
            "    parameters:",
            f'    - {{name: rate, value: "{r["rate"]}"}}',
            f'    - {{name: key_id, value: "{{{{tasks.{key}.outputs.parameters.request-id}}}}"}}',
            f'    - {{name: previous-ok, value: "{prevok}"}}',
            f'    - {{name: duration, value: "{r["duration"]}"}}',
            f'    - {{name: pause, value: "{r["pause"]}"}}',
            f'    - {{name: maxfail, value: "{r["maxfail"]}"}}',
            f'    - {{name: maxshed, value: "{r["maxshed"]}"}}',
            f'    - {{name: pct, value: "{r["pct"]}"}}',
            f'    - {{name: allowfail, value: "{allowfail}"}}',
            "",
        ]
        prev = name
    return out[:-1]  # drop trailing blank


def summary_deps(kind, scen):
    return [f'- "{kind}-rate-{r["rate"]}"' for r in scen["rates"]]


def summary_args(kind, scen):
    out = []
    for r in scen["rates"]:
        name = f"{kind}-rate-{r['rate']}"
        out += [
            f"- name: test-result-{name}",
            f'  value: "{{{{tasks.{name}.outputs.parameters.test-result}}}}"',
        ]
    return out


def summary_inputs(kind, scen):
    return [f"- name: test-result-{kind}-rate-{r['rate']}" for r in scen["rates"]]


def summary_echo(kind, scen):
    out = []
    for r in scen["rates"]:
        name = f"{kind}-rate-{r['rate']}"
        out.append(f"echo '{{{{inputs.parameters.test-result-{name}}}}}' > /mnt/results/{name}.json")
    return out


def rate_vars(kind, scen):
    rates = " ".join(str(r["rate"]) for r in scen["rates"])
    return [f'{kind}_rates="{rates}"']


BUILDERS = {
    "dag-tasks": dag_tasks,
    "summary-deps": summary_deps,
    "summary-args": summary_args,
    "summary-inputs": summary_inputs,
    "summary-echo": summary_echo,
    "rate-vars": rate_vars,
}


def render(template_text, scenarios):
    out = []
    seen = set()
    for line in template_text.split("\n"):
        stripped = line.strip()
        if stripped.startswith("# <<GENERATED:") and stripped.endswith(">>"):
            name = stripped[len("# <<GENERATED:"):-len(">>")]
            if name not in BUILDERS:
                die(f"unknown marker '<<GENERATED:{name}>>' in template")
            seen.add(name)
            indent = line[: len(line) - len(line.lstrip())]
            block = []
            for kind, scen in scenarios.items():
                block += BUILDERS[name](kind, scen)
            out += [indent + b if b else "" for b in block]
        else:
            out.append(line)
    unused = set(BUILDERS) - seen
    if unused:
        die(f"template is missing markers for: {sorted(unused)}")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", required=True)
    ap.add_argument("--template", required=True)
    ap.add_argument("-o", "--out", default="-")
    args = ap.parse_args()

    scenarios = load_scenarios(args.scenarios)
    with open(args.template) as f:
        rendered = render(f.read(), scenarios)

    if args.out == "-":
        sys.stdout.write(rendered)
    else:
        with open(args.out, "w") as f:
            f.write(rendered)
    n = sum(len(s["rates"]) for s in scenarios.values())
    sys.stderr.write(f"generate-perf-workflow: expanded {n} rates across {len(scenarios)} scenario(s)\n")


if __name__ == "__main__":
    main()

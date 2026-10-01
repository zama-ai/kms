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
  summary-deps    the summary task's dependencies for generated rate tasks
  summary-args    the summary task's test-result arguments
  summary-inputs  the summary template's test-result input params
  summary-echo    the summary's "write each result JSON" lines
  summary-calls   per-scenario calls to the decrypt-rate summary function
"""

import argparse
import json
import re
import shlex
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

import tomllib

RATE_KEYS = {"rate", "duration", "pause", "maxfail", "maxshed", "pct", "allowfail"}
DEFAULT_KEYS = {"duration", "pause", "maxfail", "maxshed", "pct", "allowfail"}
SCENARIOS = {"pdec-async", "pdec-sync", "udec-async", "udec-sync"}
NAME_PATTERN = r"[a-z][a-z0-9_-]*"


def die(msg):
    sys.exit(f"generate-perf-workflow: {msg}")


def validate_name(name, field):
    if re.fullmatch(NAME_PATTERN, name) is None:
        die(
            f"{field} {name!r} must start with a lowercase letter and contain only "
            "lowercase letters, digits, hyphens, or underscores"
        )


def load_scenarios(path):
    with open(path, "rb") as f:
        doc = tomllib.load(f)
    if not isinstance(doc, dict) or "defaults" not in doc or "scenarios" not in doc:
        die(f"{path}: expected top-level [defaults] and [scenarios] tables")

    defaults = doc["defaults"]
    if not isinstance(defaults, dict):
        die(f"{path}: [defaults] must be a table")
    unknown_defaults = set(defaults) - DEFAULT_KEYS
    if unknown_defaults:
        die(f"defaults has unknown keys: {sorted(unknown_defaults)}")
    missing = DEFAULT_KEYS - set(defaults)
    if missing:
        die(f"defaults is missing required keys: {sorted(missing)}")

    scenarios = doc["scenarios"]
    if not isinstance(scenarios, dict) or not scenarios:
        die("'scenarios' must be a non-empty mapping of scenario -> config")

    resolved = {}
    for scenario, scen in scenarios.items():
        validate_name(scenario, "scenario name")
        if scenario not in SCENARIOS:
            die(
                f"unsupported scenario {scenario!r}; expected one of {sorted(SCENARIOS)}"
            )
        if not isinstance(scen, dict):
            die(f"scenario '{scenario}' must be a table")
        unknown_scen = set(scen) - {"key", "after", "rates"}
        if unknown_scen:
            die(f"scenario '{scenario}' has unknown keys: {sorted(unknown_scen)}")
        if "key" not in scen or "rates" not in scen:
            die(f"scenario '{scenario}' needs 'key' and 'rates'")
        if not isinstance(scen["key"], str) or not scen["key"]:
            die(f"scenario '{scenario}'.key must be a non-empty string")
        validate_name(scen["key"], f"scenario '{scenario}'.key")

        after = scen.get("after", [])
        if not isinstance(after, list) or not all(isinstance(x, str) for x in after):
            die(f"scenario '{scenario}'.after must be a list of strings")
        for i, dependency in enumerate(after):
            validate_name(dependency, f"scenario '{scenario}'.after[{i}]")

        if not isinstance(scen["rates"], list) or not scen["rates"]:
            die(
                f"scenario '{scenario}'.rates must be a non-empty array of inline tables"
            )

        rates = []
        for i, entry in enumerate(scen["rates"]):
            if not isinstance(entry, dict):
                die(
                    f"{scenario}.rates[{i}] must be an inline table with a 'rate' key, got {entry!r}"
                )
            if "rate" not in entry:
                die(f"{scenario}.rates[{i}] is missing required key 'rate'")
            unknown = set(entry) - RATE_KEYS
            if unknown:
                die(
                    f"{scenario}.rates[{i}] (rate {entry['rate']}) has unknown keys: {sorted(unknown)}"
                )

            merged = {**defaults, **entry}
            if not isinstance(merged["rate"], int):
                die(
                    f"{scenario}.rates[{i}].rate must be an int, got {merged['rate']!r}"
                )
            for k in ("duration", "pause", "maxfail", "maxshed", "pct"):
                v = merged[k]
                if not isinstance(v, int) or v < 0:
                    die(
                        f"{scenario}.rates[{i}].{k} must be a non-negative int, got {v!r}"
                    )
            if not isinstance(merged["allowfail"], bool):
                die(
                    f"{scenario}.rates[{i}].allowfail must be a bool, got {merged['allowfail']!r}"
                )

            rates.append(merged)
        resolved[scenario] = {
            "key": scen["key"],
            "after": after,
            "rates": rates,
        }

    # A scenario dependency means "after its entire rate ladder", so point it
    # at the ladder's terminal task. Other names refer to concrete DAG tasks.
    for scen in resolved.values():
        scen["after"] = [
            f"{dep}-rate-{resolved[dep]['rates'][-1]['rate']}"
            if dep in resolved
            else dep
            for dep in scen["after"]
        ]
    return resolved


def dag_tasks(scenario, scen):
    key, after, rates = scen["key"], scen["after"], scen["rates"]
    out = []
    prev = None
    for r in rates:
        name = f"{scenario}-rate-{r['rate']}"
        if prev is None:
            deps = [key] + after
            prevok = "true"
        else:
            deps = [prev]
            prevok = f"{{{{tasks.{prev}.outputs.parameters.capacity-ok}}}}"
        deps_str = ", ".join(f'"{d}"' for d in deps)
        allowfail = "true" if r["allowfail"] else "false"
        pause = r["pause"]
        out += [
            f"- name: {name}",
            f"  dependencies: [{deps_str}]",
            "  template: run-decrypt-rate",
            "  arguments:",
            "    parameters:",
            f'    - {{name: scenario, value: "{scenario}"}}',
            f'    - {{name: rate, value: "{r["rate"]}"}}',
            f'    - {{name: key_id, value: "{{{{tasks.{key}.outputs.parameters.request-id}}}}"}}',
            f'    - {{name: previous-ok, value: "{prevok}"}}',
            f'    - {{name: duration, value: "{r["duration"]}"}}',
            f'    - {{name: pause, value: "{pause}"}}',
            f'    - {{name: maxfail, value: "{r["maxfail"]}"}}',
            f'    - {{name: maxshed, value: "{r["maxshed"]}"}}',
            f'    - {{name: pct, value: "{r["pct"]}"}}',
            f'    - {{name: allowfail, value: "{allowfail}"}}',
            "",
        ]
        prev = name
    return out[:-1]  # drop trailing blank


def summary_deps(scenario, scen):
    return [f'- "{scenario}-rate-{r["rate"]}"' for r in scen["rates"]]


def summary_args(scenario, scen):
    out = []
    for r in scen["rates"]:
        name = f"{scenario}-rate-{r['rate']}"
        out += [
            f"- name: test-result-{name}",
            f'  value: "{{{{tasks.{name}.outputs.parameters.test-result}}}}"',
        ]
    return out


def summary_inputs(scenario, scen):
    return [f"- name: test-result-{scenario}-rate-{r['rate']}" for r in scen["rates"]]


def summary_echo(scenario, scen):
    out = []
    for r in scen["rates"]:
        name = f"{scenario}-rate-{r['rate']}"
        out.append(
            f"echo '{{{{inputs.parameters.test-result-{name}}}}}' > /mnt/results/{name}.json"
        )
    return out


def summary_calls(scenario, scen):
    rates = " ".join(str(r["rate"]) for r in scen["rates"])
    return [f"summarize_decrypt_rates {shlex.quote(scenario)} {rates}"]


BUILDERS = {
    "dag-tasks": dag_tasks,
    "summary-deps": summary_deps,
    "summary-args": summary_args,
    "summary-inputs": summary_inputs,
    "summary-echo": summary_echo,
    "summary-calls": summary_calls,
}


def render(template_text, scenarios):
    out = []
    seen = set()
    for line in template_text.split("\n"):
        stripped = line.strip()
        if stripped.startswith("# <<GENERATED:") and stripped.endswith(">>"):
            name = stripped[len("# <<GENERATED:") : -len(">>")]
            if name not in BUILDERS:
                die(f"unknown marker '<<GENERATED:{name}>>' in template")
            seen.add(name)
            indent = line[: len(line) - len(line.lstrip())]
            block = []
            for scenario, scen in scenarios.items():
                block += BUILDERS[name](scenario, scen)
            out += [indent + b if b else "" for b in block]
        else:
            out.append(line)
    unused = set(BUILDERS) - seen
    if unused:
        die(f"template is missing markers for: {sorted(unused)}")
    return "\n".join(out)


class LoadScenariosTest(unittest.TestCase):
    def load(self, scenarios):
        contents = textwrap.dedent(
            f"""
            [defaults]
            duration = 60
            pause = 10
            maxfail = 0
            maxshed = 0
            pct = 98
            allowfail = false

            {scenarios}
            """
        )
        with tempfile.NamedTemporaryFile(
            "w", suffix=".toml", encoding="utf-8"
        ) as config:
            config.write(contents)
            config.flush()
            return load_scenarios(config.name)

    def test_scenario_dependency_resolves_to_its_terminal_rate(self):
        scenarios = self.load(
            """
            [scenarios.udec-async]
            key = "udec-key-gen"
            after = ["pdec-async"]
            rates = [{ rate = 2400 }]

            [scenarios.pdec-async]
            key = "udec-key-gen"
            after = ["crs-gen"]
            rates = [{ rate = 1100 }, { rate = 1500 }]
            """
        )

        self.assertEqual(scenarios["udec-async"]["after"], ["pdec-async-rate-1500"])

    def test_concrete_task_dependency_is_unchanged(self):
        scenarios = self.load(
            """
            [scenarios.pdec-async]
            key = "udec-key-gen"
            after = ["crs-gen"]
            rates = [{ rate = 1100 }]
            """
        )

        self.assertEqual(scenarios["pdec-async"]["after"], ["crs-gen"])

    def test_unsupported_scenarios_are_rejected(self):
        for name in ("pdec", "udec", "udec-sunc", "my-perf"):
            with self.subTest(name=name), self.assertRaises(SystemExit):
                self.load(
                    f'[scenarios.{name}]\nkey = "udec-key-gen"\nrates = [{{ rate = 1100 }}]'
                )

    def test_scenario_name_rejects_shell_syntax(self):
        with self.assertRaises(SystemExit) as error:
            self.load(
                """
                [scenarios."bad; touch injected"]
                key = "udec-key-gen"
                rates = [{ rate = 1100 }]
                """
            )

        self.assertIn("must start with a lowercase letter", str(error.exception))

    def test_redundant_scenario_fields_are_rejected(self):
        base = (
            '[scenarios.pdec-async]\nkey = "udec-key-gen"\nrates = [{ rate = 1100 }]\n'
        )
        for field in ("operation", "endpoint", "kind"):
            with self.subTest(field=field), self.assertRaises(SystemExit):
                self.load(base + f'{field} = "pdec"\n')

    def test_sync_ladder_has_independent_gate_and_shared_summary_identity(self):
        scenarios = self.load("""
            [scenarios.pdec-async]
            key = "udec-key-gen"
            rates = [{ rate = 1100 }]

            [scenarios.pdec-sync]
            key = "udec-key-gen"
            after = ["pdec-async"]
            rates = [{ rate = 1100 }, { rate = 1300 }]
        """)
        scenario = scenarios["pdec-sync"]
        tasks = "\n".join(dag_tasks("pdec-sync", scenario))
        self.assertIn('dependencies: ["udec-key-gen", "pdec-async-rate-1100"]', tasks)
        self.assertIn('{name: previous-ok, value: "true"}', tasks)
        self.assertIn("tasks.pdec-sync-rate-1100.outputs.parameters.capacity-ok", tasks)
        self.assertNotIn(
            "tasks.pdec-async-rate-1100.outputs.parameters.capacity-ok", tasks
        )
        self.assertIn('{name: scenario, value: "pdec-sync"}', tasks)
        self.assertEqual(
            summary_calls("pdec-sync", scenario),
            ["summarize_decrypt_rates pdec-sync 1100 1300"],
        )
        for builder in (summary_deps, summary_args, summary_inputs, summary_echo):
            self.assertIn(
                "pdec-sync-rate-1100", "\n".join(builder("pdec-sync", scenario))
            )

    def test_repository_workflow_covers_both_endpoints(self):
        root = Path(__file__).resolve().parent
        scenarios = load_scenarios(root / "perf-scenarios.toml")
        self.assertEqual(
            set(scenarios),
            SCENARIOS,
        )
        workflow = render(
            (root / "argo-workflow/kms-perf-workflow-kms-ci.yaml").read_text(),
            scenarios,
        )
        self.assertNotIn("<<GENERATED:", workflow)
        for name, scenario in scenarios.items():
            for rate in scenario["rates"]:
                self.assertEqual(
                    workflow.count(f"- name: {name}-rate-{rate['rate']}\n"), 1
                )

    def test_workflow_dispatches_each_operation_and_endpoint(self):
        root = Path(__file__).resolve().parent
        template = (root / "argo-workflow/kms-perf-workflow-kms-ci.yaml").read_text()
        script = template[
            template.index('          scenario="{{inputs.parameters.scenario}}"') :
        ]
        script = script.split("          mkdir -p /tmp/artifacts", 1)[0]
        for operation in ("pdec", "udec"):
            for endpoint in ("async", "sync"):
                with self.subTest(operation=operation, endpoint=endpoint):
                    expanded = script.replace(
                        "{{inputs.parameters.scenario}}", f"{operation}-{endpoint}"
                    )
                    expanded = re.sub(r"\{\{[^}]+\}\}", "1", expanded)
                    command_script = expanded + '\necho "$test_command"'
                    result = subprocess.run(
                        ["bash", "-eu", "-c", command_script],
                        capture_output=True,
                        text=True,
                        check=True,
                    )
                    command = shlex.split(result.stdout)
                    self.assertEqual(
                        command[0],
                        "public-decrypt" if operation == "pdec" else "user-decrypt",
                    )
                    self.assertEqual("--sync" in command, endpoint == "sync")

    def test_slack_summary_keeps_endpoint_results_and_counts(self):
        root = Path(__file__).resolve().parent
        template = (root / "argo-workflow/kms-perf-workflow-kms-ci.yaml").read_text()
        script = template[
            template.index("          keygen_total=0") : template.index(
                '          echo "Keygen and CRS perf tests:"'
            )
        ]
        with tempfile.TemporaryDirectory() as directory:
            script = script.replace("/mnt/results", directory)
            cases = [
                ("pdec-async", "pdec", "async", "passed", True, False),
                ("pdec-sync", "pdec", "sync", "passed", False, True),
                ("udec-async", "udec", "async", "failed", False, False),
                ("udec-sync", "udec", "sync", "skipped", False, True),
            ]
            for name, operation, endpoint, status, within, allow in cases:
                metrics_key = (
                    "public_decrypt" if operation == "pdec" else "user_decrypt"
                )
                result = {
                    "status": status,
                    "performance_metrics": {
                        metrics_key: {
                            "target_rate": 1100,
                            "within_parameter_set": within,
                            "allowed_failure": allow,
                        }
                    },
                }
                (Path(directory) / f"{name}-rate-1100.json").write_text(
                    json.dumps(result)
                )
                script += f"\nsummarize_decrypt_rates {name} 1100\n"
            script += '\ntest "$pdec_passed:$pdec_warned:$udec_failed:$udec_skipped" = "1:1:1:1"\n'
            script += (
                '\nprintf "REPORT=%s\\n" "$(printf %s "$decrypt_blocks" | jq -c .)"\n'
            )
            result = subprocess.run(
                ["bash", "-eu", "-c", script],
                capture_output=True,
                text=True,
                check=True,
            )
        blocks = json.loads(result.stdout.split("REPORT=", 1)[1])
        self.assertEqual(len(blocks), 8)
        for index, (_, operation, endpoint, _, _, _) in enumerate(cases):
            text = blocks[index * 2]["text"]["text"]
            self.assertIn(f"({endpoint})", text)
            self.assertIn("1100/s", text)
            self.assertIn("Public" if operation == "pdec" else "User", text)
        self.assertTrue(all(len(block["text"]["text"]) <= 3000 for block in blocks))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--scenarios")
    ap.add_argument("--template")
    ap.add_argument("-o", "--out", default="-")
    args = ap.parse_args()

    if args.self_test:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(LoadScenariosTest)
        result = unittest.TextTestRunner().run(suite)
        return 0 if result.wasSuccessful() else 1
    if not args.scenarios or not args.template:
        ap.error("--scenarios and --template are required unless --self-test is used")

    scenarios = load_scenarios(args.scenarios)
    with open(args.template, encoding="utf-8") as f:
        rendered = render(f.read(), scenarios)

    if args.out == "-":
        sys.stdout.write(rendered)
    else:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(rendered)
    n = sum(len(s["rates"]) for s in scenarios.values())
    sys.stderr.write(
        f"generate-perf-workflow: expanded {n} rates across {len(scenarios)} scenario(s)\n"
    )


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Independent grader simulation derived from files/challenge_brief.md only."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

SANDBOX = re.compile(r"^sbx-[a-z0-9]{8,}$")
RUN_ID = re.compile(r"^run-[a-z0-9]{12,32}$")
ALLOWED_CAPABILITIES = {
    "persistence", "snapshots", "celestofs", "browser", "published_ports",
    "network_policy", "safety_hooks", "host_mounts", "coding_agent_preset",
    "agentor_durable",
}
REQUIRED_ENV = {
    "CELESTO_PROVIDER", "CELESTO_API_KEY", "LLM_API_KEY", "LLM_MODEL",
    "DATABASE_URL", "API_PORT",
}
PLACEHOLDER_MARKERS = {"replace-me", "replace-with-a-model-name", "example-llm-host"}
SECRET_ENV_KEYS = {"CELESTO_API_KEY", "LLM_API_KEY", "OPERATOR_TOKEN"}


class Grader:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.failures: list[str] = []
        self.passes: list[str] = []

    def check(self, name: str, condition: bool, detail: str = "") -> None:
        if condition:
            self.passes.append(name)
            print(f"PASS {name}{(': ' + detail) if detail else ''}")
        else:
            message = f"FAIL {name}{(': ' + detail) if detail else ''}"
            self.failures.append(message)
            print(message)

    def path(self, relative: str) -> Path:
        return self.root / relative

    def read_json(self, relative: str) -> Any | None:
        path = self.path(relative)
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            self.check(f"file:{relative}", False, "missing")
        except json.JSONDecodeError as exc:
            self.check(f"file:{relative}", False, f"invalid JSON: {exc.msg}")
        return None

    def run(self) -> int:
        self.core_01_compose()
        self.core_02_env()
        self.core_03_problem()
        commands = self.core_04_commands()
        self.core_05_capabilities()
        reliability = self.core_07_reliability()
        self.core_06_lifecycle(commands, reliability)
        self.core_08_containment()
        self.core_09_failure()
        self.core_10_concurrency()
        self.core_11_api_static()
        self.core_12_readme()
        self.extra_architecture_and_demo()
        print(f"\nsummary pass={len(self.passes)} fail={len(self.failures)}")
        return 1 if self.failures else 0

    def core_01_compose(self) -> None:
        path = self.path("docker-compose.yml")
        if yaml is None:
            self.check("CR-01 compose parse", False, "PyYAML unavailable")
            return
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001 - grader reports parser failures.
            self.check("CR-01 compose parse", False, repr(exc))
            return
        services = data.get("services", {}) if isinstance(data, dict) else {}
        self.check("CR-01 services", all(name in services for name in ("api", "ledger")))
        ledger = services.get("ledger", {})
        api = services.get("api", {})
        self.check("CR-01 ledger healthcheck", self._healthcheck_complete(ledger.get("healthcheck")))
        self.check("CR-01 api healthcheck", self._healthcheck_complete(api.get("healthcheck")))
        mounts = ledger.get("volumes", [])
        self.check("CR-01 seed mount", any("./seeds" in str(item) or "seeds:" in str(item) for item in mounts))
        depends = api.get("depends_on", {})
        self.check("CR-01 api depends on healthy ledger", depends.get("ledger", {}).get("condition") == "service_healthy")
        ports = [str(item) for item in api.get("ports", [])]
        self.check("CR-01 api publishes 8080", any("8080" in item for item in ports))

    @staticmethod
    def _healthcheck_complete(value: Any) -> bool:
        return isinstance(value, dict) and all(key in value for key in ("interval", "timeout", "retries", "start_period"))

    def core_02_env(self) -> None:
        path = self.path(".env.example")
        values: dict[str, str] = {}
        if path.is_file():
            for line in path.read_text(encoding="utf-8").splitlines():
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    values[key.strip()] = value.strip()
        self.check("CR-02 required env keys", REQUIRED_ENV.issubset(values), str(sorted(REQUIRED_ENV - values.keys())))
        placeholders = all(
            not values.get(key)
            or any(marker in values[key] for marker in PLACEHOLDER_MARKERS)
            for key in SECRET_ENV_KEYS
        )
        self.check("CR-02 env placeholders", placeholders)
        self.check("CR-02 no root .env", not self.path(".env").exists())

    def core_03_problem(self) -> None:
        data = self.read_json("reports/problem.json")
        if not isinstance(data, dict):
            return
        self.check("CR-03 problem who", isinstance(data.get("who"), str) and len(data["who"]) >= 40)
        self.check("CR-03 problem agent_work", isinstance(data.get("agent_work"), str) and len(data["agent_work"]) >= 40)
        self.check("CR-03 problem proof_output", isinstance(data.get("proof_output"), str) and len(data["proof_output"]) >= 20)
        self.check("CR-03 problem idea_source", data.get("idea_source") in {"idea_bank", "original"})

    def core_04_commands(self) -> set[str]:
        path = self.path("logs/commands.jsonl")
        names: set[str] = set()
        lines = path.read_text(encoding="utf-8").splitlines() if path.is_file() else []
        self.check("CR-04 command log exists", bool(lines))
        has_block = False
        for index, line in enumerate(lines, 1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                self.check(f"CR-04 line {index} JSON", False)
                continue
            timestamp = row.get("ts")
            if timestamp is None:
                timestamp = row.get("timestamp")
            try:
                if timestamp:
                    dt.datetime.fromisoformat(str(timestamp))
            except ValueError:
                timestamp = None
            command = row.get("command") or row.get("command_summary")
            decision = row.get("decision")
            self.check(f"CR-04 line {index} fields", bool(timestamp) and isinstance(row.get("sandbox_name"), str) and bool(command) and decision in {"allow", "block"} and row.get("execution_target") == "celesto_sandbox")
            if decision == "block":
                has_block = True
            if isinstance(row.get("sandbox_name"), str):
                names.add(row["sandbox_name"])
        self.check("CR-04 block line", has_block)
        return names

    def core_05_capabilities(self) -> None:
        data = self.read_json("reports/capabilities.json")
        caps = data.get("capabilities", []) if isinstance(data, dict) else []
        ids = [item.get("id") for item in caps if isinstance(item, dict)]
        self.check("CR-05 capability count", len(caps) >= 2)
        self.check("CR-05 capability ids", len(ids) == len(set(ids)) and set(ids).issubset(ALLOWED_CAPABILITIES))
        for index, item in enumerate(caps):
            why = item.get("why") if isinstance(item, dict) else None
            evidence = item.get("evidence_path") if isinstance(item, dict) else None
            self.check(f"CR-05 capability {index}", isinstance(why, str) and len(why) >= 80 and isinstance(evidence, str) and self.path(evidence).is_file())

    def core_06_lifecycle(self, command_names: set[str], reliability: Any) -> None:
        data = self.read_json("reports/lifecycle.json")
        if not isinstance(data, dict):
            return
        self.check("CR-06 cleanup flags", all(data.get(key) is True for key in ("cleanup_on_success", "cleanup_on_failure", "cleanup_on_interrupt")))
        names = data.get("sandbox_names", [])
        reliability_names = {row.get("sandbox_name") for row in (reliability or {}).get("runs", []) if isinstance(row, dict)}
        self.check("CR-06 sandbox names", isinstance(names, list) and bool(names) and len(names) == len(set(names)) and all(isinstance(name, str) and SANDBOX.fullmatch(name) and (name in command_names or name in reliability_names) for name in names))

    def core_07_reliability(self) -> Any:
        data = self.read_json("reports/reliability.json")
        if not isinstance(data, dict):
            return None
        runs = data.get("runs")
        self.check("CR-07 run count", isinstance(runs, list) and len(runs) >= 20 and data.get("run_count") == len(runs))
        if not isinstance(runs, list) or not runs:
            return data
        names = [row.get("sandbox_name") for row in runs if isinstance(row, dict)]
        self.check("CR-07 row fields", len(names) == len(runs) and len(names) == len(set(names)) and all(SANDBOX.fullmatch(str(name)) for name in names))
        self.check("CR-07 numeric fields", all(isinstance(row.get("success"), bool) and row.get("fresh") is True and isinstance(row.get("wall_clock_s"), (int, float)) and row.get("wall_clock_s") >= 0 and isinstance(row.get("boot_to_ready_s"), (int, float)) and row.get("boot_to_ready_s") >= 0 and isinstance(row.get("cost_usd"), (int, float)) and row.get("cost_usd") >= 0 for row in runs if isinstance(row, dict)))
        ordered = sorted(runs, key=lambda row: float(row["wall_clock_s"]))
        wall = [float(row["wall_clock_s"]) for row in ordered]
        boot = [float(row["boot_to_ready_s"]) for row in ordered]
        def median(values: list[float]) -> float:
            n = len(values); m = n // 2
            return values[m] if n % 2 else (values[m - 1] + values[m]) / 2
        p90 = wall[max(0, int(__import__("math").ceil(0.9 * len(wall))) - 1)]
        self.check("CR-07 sorted runs", wall == [float(row["wall_clock_s"]) for row in runs])
        self.check("CR-07 arithmetic", abs(float(data.get("success_rate", -1)) - sum(row["success"] for row in runs) / len(runs)) <= .001 and abs(float(data.get("median_wall_clock_s", -1)) - median(wall)) <= .001 and abs(float(data.get("p90_wall_clock_s", -1)) - p90) <= .001 and abs(float(data.get("median_boot_to_ready_s", -1)) - median(boot)) <= .001 and abs(float(data.get("total_cost_usd", -1)) - sum(float(row["cost_usd"]) for row in runs)) <= .01)
        self.check("CR-07 postmortem", data.get("postmortem_path") == "reports/postmortem.md" and self.path("reports/postmortem.md").is_file() and len(self.path("reports/postmortem.md").read_text(encoding="utf-8")) >= 200)
        return data

    def core_08_containment(self) -> None:
        data = self.read_json("reports/containment.json")
        if not isinstance(data, dict): return
        self.check("CR-08 containment", data.get("attack") in {"prompt_injection_exfil", "destructive_command", "suspicious_package"} and data.get("blocked") is True and data.get("host_untouched") is True and isinstance(data.get("evidence_paths"), list) and bool(data["evidence_paths"]) and all(self.path(item).is_file() for item in data["evidence_paths"]))

    def core_09_failure(self) -> None:
        data = self.read_json("reports/failure_policy.json")
        trace_path = self.path("reports/failure_trace.jsonl")
        self.check("CR-09 policy", isinstance(data, dict) and data.get("failed_step") == 7 and data.get("total_steps") == 10 and data.get("policy") in {"resume", "rollback", "fresh"} and isinstance(data.get("rationale"), str) and len(data["rationale"]) >= 200 and data.get("trace_path") == "reports/failure_trace.jsonl")
        matches = False
        if trace_path.is_file() and isinstance(data, dict):
            for line in trace_path.read_text(encoding="utf-8").splitlines():
                try: row = json.loads(line)
                except json.JSONDecodeError: continue
                if row.get("event") == "policy_applied" and row.get("policy") == data.get("policy"): matches = True
        self.check("CR-09 trace", matches)

    def core_10_concurrency(self) -> None:
        data = self.read_json("reports/concurrency.json")
        jobs = data.get("jobs", []) if isinstance(data, dict) else []
        self.check("CR-10 concurrency jobs", isinstance(jobs, list) and len(jobs) >= 5 and len({job.get("sandbox_name") for job in jobs if isinstance(job, dict)}) == len(jobs) and all(isinstance(job.get("started_at"), str) and SANDBOX.fullmatch(str(job.get("sandbox_name"))) for job in jobs if isinstance(job, dict)))
        self.check("CR-10 breakage notes", isinstance(data, dict) and isinstance(data.get("breakage_notes"), str) and len(data["breakage_notes"]) >= 40)

    def core_11_api_static(self) -> None:
        text = self.path("src/api/main.py").read_text(encoding="utf-8")
        self.check("CR-11 API endpoints", all(route in text for route in ('/health', '/api/runs', '/health/db')))
        self.check("CR-11 traversal guard", "relative_to" in text and "Report not found" in text)

    def core_12_readme(self) -> None:
        text = self.path("README.md").read_text(encoding="utf-8") if self.path("README.md").is_file() else ""
        required = ["Problem statement", "How I used Celesto", "Eval report", "Containment test", "State and failure design", "Setup", "AI assistants used"]
        self.check("CR-12 README phrases", all(phrase in text for phrase in required))

    def extra_architecture_and_demo(self) -> None:
        text = self.path("README.md").read_text(encoding="utf-8") if self.path("README.md").is_file() else ""
        self.check("extra architecture diagram", "```" in text and ("data flow" in text.lower() or "architecture" in text.lower()))
        self.check("extra demo artifact", self.path("demo/DEMO_SCRIPT.md").is_file() or self.path("demo/walkthrough.mp4").is_file() or self.path("demo/README.md").is_file())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    return Grader(args.root).run()


if __name__ == "__main__":
    raise SystemExit(main())

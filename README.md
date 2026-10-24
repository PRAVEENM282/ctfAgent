# VulnForge

VulnForge is a small, auditable CTF-lab generator. It creates a deliberately vulnerable SQL-injection lesson inside a Celesto computer, verifies the intended exploit privately, exposes the lab only after verification, and deletes the guest and public route during cleanup.

## Problem statement

Cybersecurity learners and instructors need short-lived, repeatable vulnerable labs without giving generated code access to a laptop, host files, credentials, or the control-plane database. VulnForge gives the agent a real isolated computer, records every command, verifies the lab from inside the guest, and leaves a ledger trail that can be reviewed after the guest is gone.

## Architecture and data flow

```text
operator / browser UI
        |
        v
FastAPI control plane  --->  PostgreSQL run ledger
        |
        +--> cloud Celesto computer (microVM)
        |       |
        |       +--> guarded agent commands
        |       +--> generated app and private verifier
        |       +--> temporary published port
        |       +--> revoke and delete
        |
        +--> cloud-compatible LLM for the main dashboard path
        +--> deterministic test policy for offline tests only

Every command record has execution_target=celesto_sandbox.
The host control plane never runs generated app source.
```

## How I used Celesto

1. **Network policy:** cloud guests are created with outbound egress disabled and the adapter performs a per-guest self-check. The observed check returned `blocked` with curl exit `28`. This contains prompt-injection exfiltration attempts unless a separate approved route is intentionally opened.
2. **Published ports:** the live lifecycle evidence created a guest app, published port `8000`, observed HTTP `200`, then revoked the route and confirmed cleanup.
3. **Persistence:** the retained evidence records same-ID stop/resume and a sentinel surviving on the guest disk. Cloud persistent-volume creation later returned HTTP `422` with no side effects, so the current submission path treats persistence as an observed compatibility capability rather than a requirement for the ephemeral lab flow.
4. **Safety audit:** the command guard blocks agent network clients and destructive commands before dispatch. Blocked commands are still logged with `execution_target=celesto_sandbox`.

Evidence paths include `reports/evidence/phase0_network_policy_probe.log`, `reports/evidence/phase0_published_ports.log`, `reports/evidence/m3_live_lifecycle.log`, `reports/evidence/containment.log`, and `logs/commands.jsonl`.

## Agent and model modes

The **main dashboard** uses the configured cloud-compatible provider from `.env` (`LLM_BASE_URL`, `LLM_API_KEY`, and `LLM_MODEL`). The configured Mistral account accepted `GET /models`, but the previous model name `zai-glm-5-2` was not listed; choose a listed model such as `mistral-small-latest` before a live dashboard generation. Provider rate limiting is surfaced as a failure and is not hidden.

The **test-only cloud guest runner** uses `src/agent/test_client.py`. It is a deterministic in-process policy that emits the fixed `write_app` tool call, uses no LLM API request, and exists only to exercise the real Celesto Cloud guest, command guard, generated source write, private app start, and cleanup path. It must not be described as model-generated output.

## Eval report

The repository contains real historical Celesto lifecycle and dashboard ledger evidence. The strict 20-fresh-run report is generated from rows that have observed wall-clock time, boot-to-ready time, unique sandbox names, and observed cost:

```bash
docker compose exec api python scripts/export_reliability_from_ledger.py
curl -fsS http://127.0.0.1:8080/reports/reliability.json -o reports/reliability.json
python scripts/validate_reports.py --require-complete
```

The exporter refuses to create `reports/reliability.json` when fewer than 20 qualifying ledger rows exist. The latest cloud create probe returned HTTP `429` before allocating a guest; that result is recorded in `reports/evidence/cloud_rate_limit.log` and `reports/reliability_blocked.json` when the exporter is run against a ledger with fewer than 20 rows. No missing rows are filled with estimates.

The current export contains 18 observed rows: 15 provider-path ledger attempts, one deterministic test-policy guest, one deterministic generated-guest attempt, and one publish/resume/interrupt lifecycle attempt. The three supplemental rows are labelled with their source evidence and are not presented as successful cloud-LLM runs.

## Containment test

The containment experiment uses a synthetic canary and a prompt-injection exfiltration command. The obvious command was blocked by `CommandGuard` before dispatch. The obfuscated command was dispatched only in the relaxed-guard control path and was stopped by the guest network policy. A positive-control guest with egress enabled delivered exactly one synthetic canary. Host canary hashes matched before and after, and guest/receiver cleanup was confirmed.

See `reports/containment.json` and `reports/evidence/containment.log`. No real credential is used.

## State and failure design

The agent records `created -> ready -> running -> succeeded/failed -> deleted`. Every lifecycle path uses cleanup in `finally`-style control flow, including application failure and interrupt handling. When Step 7 of 10 fails, the selected policy is **fresh**: preserve the failed attempt in the ledger, delete its guest, then retry with a new run/attempt/sandbox identity. This avoids resuming unknown processes or partially generated files. The control-plane recovery policy test and matching `policy_applied` trace are in `reports/failure_policy.json` and `reports/failure_trace.jsonl`.

## Setup

### 1. Start the trusted control plane

```bash
cp .env.example .env
# Put real, uncommitted Celesto Cloud and LLM values in .env.
docker compose up --build -d --wait
```

Compose starts only `api` and `ledger`; Firecracker/microVMs are created by the API through Celesto, never as a Compose service.

### 2. Verify the ledger API

```bash
curl -fsS http://127.0.0.1:8080/health
curl -fsS http://127.0.0.1:8080/api/runs
curl -i -X POST http://127.0.0.1:8080/api/runs \
  -H 'content-type: application/json' \
  -d '{"run_id":"run-localcheck1234","sandbox_name":"sbx-localcheck1","problem_id":"ctf-smoke","state":"created","execution_target":"celesto_sandbox"}'
```

Expected results are `200`, a seeded `sbx-seeddemo1` row, and `201` for the valid POST. A POST with `execution_target: "host"` must return `400`.

### 3. Run the test-only cloud guest path

```bash
set -a; . ./.env; set +a
export CELESTO_NO_TELEMETRY=1
python scripts/cloud_test_agent.py
```

This creates a uniquely named ephemeral Celesto Cloud guest, writes generated source through the guarded tool, starts the app in the guest, performs the private readiness check, attempts the published-port probe, and deletes the guest in all cases.

### 4. Run checks

```bash
python3 -m pytest -q
python -m ruff check src scripts tests
python scripts/validate_reports.py
```

The strict validator is intentionally evidence-gated: it fails when the required 20-run report does not exist instead of accepting synthetic rows.

## Required artifacts

```text
docker-compose.yml
Dockerfile
.env.example
README.md
seeds/01_runs.sql
reports/problem.json
reports/capabilities.json
reports/lifecycle.json
reports/reliability.json        # written only after 20 qualifying rows
reports/postmortem.md
reports/containment.json
reports/failure_policy.json
reports/failure_trace.jsonl
reports/concurrency.json
logs/commands.jsonl
```

## Three-minute demo walkthrough

1. Open the dashboard at `http://127.0.0.1:8080/` and show the seeded run ledger.
2. Open a terminal beside it and run `python scripts/cloud_test_agent.py`.
3. Show the Celesto-created sandbox name, `egress_status=blocked`, generated source SHA-256, and cleanup confirmation.
4. Open `logs/commands.jsonl` and point out the guest execution target and blocked command record.
5. Show `reports/containment.json`, `reports/failure_policy.json`, and the Compose `/health` response.

## Disclosure

The main application is designed for Celesto Cloud. The test-only deterministic policy is disclosed above and is not presented as an LLM evaluation. Cloud rate limits, missing ledger rows, and any failed live guest run remain visible in the evidence instead of being converted into success claims.

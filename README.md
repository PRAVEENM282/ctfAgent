# VulnForge

**Live dashboard:** `http://127.0.0.1:8080/` (served by the API after `docker compose up --build`). VulnForge is operated through this dashboard; the vulnerable labs it generates are short-lived and ephemeral, so there is no permanent public lab URL — each lab is published only after private verification and torn down on cleanup.

VulnForge is a small, auditable CTF-lab generator. An LLM agent builds an intentionally vulnerable web app (SQL injection, reflected XSS, path traversal, IDOR, or a bundle) **inside a Celesto sandbox**, verifies the exploit privately from inside the guest, publishes one port so students can attack it, then deletes the guest and revokes the route. Generated code never runs on the host.

## Problem statement

Cybersecurity learners and instructors need short-lived, repeatable vulnerable labs without giving generated code access to a laptop, host files, credentials, or the control-plane database. VulnForge gives the agent a real isolated computer, records every command, verifies the lab from inside the guest, exposes it only after a human approves, and leaves a ledger trail that can be reviewed after the guest is gone.

## Architecture and data flow

```mermaid
flowchart LR
    operator["Operator / shadcn UI"] -->|REST + SSE| api["FastAPI control plane"]
    api -->|run ledger, approvals| pg[("PostgreSQL")]
    api -->|customise within bounds| llm["LLM<br/>(Ollama or OpenAI-compatible)"]
    api -->|create · run · verify · publish · delete| guest["Celesto guest (microVM)<br/>egress disabled"]
    guest -->|guarded agent commands| guest
    guest -->|private exploit verifier| guest
    guest -->|published port| student["Student / attacker"]
    api -->|allow/block decisions| audit[("logs/commands.jsonl")]
```

- Every command that runs in a guest is appended to `logs/commands.jsonl` with `execution_target=celesto_sandbox` and an allow/block decision. Blocked commands are logged too.
- The host control plane never executes generated app source. The LLM only customises a bounded template; the agent's file writes and the app itself run inside the guest.
- Sandbox names match `^sbx-[a-z0-9]{8,}$` and are unique per run.

## How I used Celesto

1. **Isolation + egress off.** Every guest is created with outbound egress disabled, and the adapter runs a per-guest self-check (`curl` to the internet must fail). The observed result is `blocked` with curl exit `28`. This contains prompt-injection exfiltration unless a route is intentionally opened.
2. **Private verification.** The planted flag/markers are seeded into the guest through a trusted boundary (never an audited command string), the generated app is started privately, and the exploit and a benign request are run from inside the guest. A lab publishes only when the exploit returns the secret **and** the benign request stays clean.
3. **Human-approved publication.** After private verification, an operator approves publishing. On **cloud** the guest publishes an HTTPS port; on **local** the guest's app port is forwarded to `127.0.0.1` as a local preview (Celesto 0.1.7 does not publish public ports for local computers — see the table below).
4. **Teardown always.** On success, failure, and Ctrl-C/SIGTERM the route is revoked and the guest is deleted. A TTL reaper deletes any guest older than `SANDBOX_TTL_MINUTES`, and a startup pass reconciles runs left non-terminal by a previous process.

Evidence: `reports/evidence/phase0_network_policy_probe.log`, `reports/evidence/phase0_published_ports.log`, `reports/evidence/containment.log`, and `logs/commands.jsonl`.

## Why Celesto and not Docker or E2B

The threat model is *intentionally malicious, model-generated code plus prompt injection*. A Docker container shares the host kernel, so a container escape or a misconfigured mount reaches the host; and wiring per-container egress-off, published ports, and guaranteed teardown is all on me. Celesto gives each lab a real Firecracker/QEMU microVM with a hardware-virtualization boundary, a declarative `network_policy=off`, a published-port primitive, and ephemeral lifetimes — the isolation guarantees the brief needs are properties of the platform, not of my config. E2B is a hosted code-interpreter sandbox aimed at running an agent's own code; it is not designed to hand a *separately reachable, egress-disabled, intentionally vulnerable* web target to third-party attackers and then prove the exploit privately first. Celesto's microVM + network policy + publish/revoke lifecycle maps directly onto "verify privately, expose on approval, destroy after."

## LLM layer (works with a tiny local model)

One client, two backends: native/OpenAI-compatible **Ollama** and any **OpenAI-compatible** host (Groq, OpenRouter, OpenAI, …), selected by `LLM_PROVIDER`. Because `qwen2.5-coder:1.5b` is weak, the agent is **not** asked to write a whole app freely. Each vulnerability profile has a vetted stdlib template with the intentional flaw, synthetic data, a planted flag, and a `/health` route. The model customises within strict bounds; if its output is missing or invalid, VulnForge falls back to the vetted template and records `llm_fallback_used` in the snapshot and the UI. Fallback output is never presented as model-generated. (A `mock` client exists only for unit tests and is never selectable in production.)

### Vulnerability profiles

- `sql_injection`: `/search?q=` concatenated into a synthetic SQLite query.
- `reflected_xss`: `/echo?name=` reflected without escaping.
- `path_traversal`: `/download?file=` joined under `/root/vulnforge_files` without normalisation.
- `idor`: `/profile?id=` returns a profile with no authorization check.

Bundle mode requires at least two profiles and publishes only when every selected exploit passes while benign requests stay clean.

## Local vs cloud modes

| Capability | `CELESTO_PROVIDER=local` | `CELESTO_PROVIDER=cloud` |
|---|---|---|
| Backend | QEMU microVM on this host (KVM) | Firecracker microVM in Celesto Cloud |
| Needs | `celesto image pull ubuntu` + KVM; API runs on the host | `CELESTO_API_KEY`; API can run in Docker |
| Egress self-check | ✅ `blocked` | ✅ `blocked` |
| Private verification | ✅ | ✅ |
| Published lab | Local preview on `127.0.0.1:<port>` (loopback only) | Public HTTPS URL |
| Cost | $0 | ~$0.015/guest-hour (Micro) |
| LLM | Local Ollama (no key) | Local Ollama or a remote OpenAI-compatible host |

Local mode does not fake a public URL; it clearly labels the lab a **local preview**. The full publish/revoke public lifecycle needs cloud.

## Eval report

`scripts/run_eval.py` runs N (default 20) sequential **fresh** labs end to end through the exact dashboard pipeline, sleeping between runs to avoid rate limits, recording per run: `sandbox_name`, `fresh`, `success`, `wall_clock_s`, `boot_to_ready_s`, and `cost_usd` (hourly rate × guest lifetime; Micro = $0.015/hr, local = $0). It computes `success_rate`, median and p90 (ascending sort; median of the two middle rows; p90 = ⌈0.9·N⌉-th), `total_cost_usd`, and writes `reports/reliability.json` plus a postmortem in `reports/postmortem.md`. Failed rows are never dropped.

```bash
# Cloud (needs CELESTO_API_KEY and a reachable Ollama on the control plane):
python scripts/run_eval.py --runs 20 --sleep 15
python scripts/validate_reports.py
```

`reports/reliability.json` contains only rows produced by real runs of this pipeline.

## Containment test

`scripts/run_containment.py` repeats the prompt-injection exfiltration test with a **synthetic canary** only. The obvious exfil command is blocked by `CommandGuard` before dispatch; an obfuscated variant is stopped by the guest's egress policy. Host canary hashes match before and after, and guest/receiver cleanup is confirmed. See `reports/containment.json` and `reports/evidence/containment.log`. No real credential is used.

## State and failure design

States: `created → ready → running → (verified) → published → succeeded | failed → deleted`. The pipeline is ten explicit steps (create guest, boot probe, egress check, LLM customisation, write app, start app, private exploit verify, benign-clean verify, publish port, final health check), surfaced live over SSE. Every path tears the guest down in `finally`-style control flow plus signal handlers. **Failure policy = fresh:** when a step fails, the attempt is preserved in the ledger, its guest is deleted, and a new guest with a new unique name retries once; `policy_applied` is appended to `reports/failure_trace.jsonl`. A transition to `deleted` always follows. See `reports/failure_policy.json`.

## Setup (10 minutes)

### 1. Configure

```bash
cp .env.example .env
# Edit .env:
#   CELESTO_PROVIDER=local   (QEMU on this host)  OR  cloud (set CELESTO_API_KEY)
#   LLM_PROVIDER=ollama      LLM_MODEL=qwen2.5-coder:1.5b
# Optional: ACCESS_CODE=... to require a code for creating labs.
```

### 2. Local model

```bash
ollama pull qwen2.5-coder:1.5b
```

### 3a. Cloud mode (Docker)

```bash
docker compose up --build -d --wait   # api + ledger become healthy
# open http://127.0.0.1:8080/
```

Compose starts only `api` and `ledger`; microVMs are created by the API through Celesto, never as a Compose service. Compose becomes healthy with placeholder credentials.

### 3b. Local mode (host API + QEMU)

Local guests need host KVM, so run the API on the host:

```bash
celesto image pull ubuntu                 # once (also: --vmm qemu)
docker compose up -d ledger               # Postgres only
export CELESTO_PROVIDER=local LLM_PROVIDER=ollama LLM_MODEL=qwen2.5-coder:1.5b \
       OLLAMA_BASE_URL=http://localhost:11434 \
       DATABASE_URL=postgresql://ledger:ledger@127.0.0.1:5432/ledger
uvicorn src.api.main:app --host 127.0.0.1 --port 8080
```

### 4. Checks

```bash
python -m pytest -q
python -m ruff check src scripts tests
python scripts/validate_reports.py
curl -fsS http://127.0.0.1:8080/health
curl -fsS http://127.0.0.1:8080/api/config   # shows the active Celesto + LLM mode
```

## Required artifacts

```text
docker-compose.yml   Dockerfile   .env.example   README.md
seeds/01_runs.sql
reports/{problem,capabilities,lifecycle,reliability,containment,failure_policy,concurrency}.json
reports/postmortem.md   reports/failure_trace.jsonl
logs/commands.jsonl
```

## Disclosure

This project was built with the help of **Claude Code** (Anthropic). The design, Celesto integration, pipeline, UI, and evaluation harness were implemented with its assistance. All numbers in `reports/` come from real runs of the pipeline; rate limits, fallbacks, and failed runs are left visible rather than converted into success claims.

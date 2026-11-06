# VulnForge — Operator Guide (start to end)

This is the hands-on guide for running VulnForge and taking one lab through its
full lifecycle. For the project overview, architecture, and submission artifacts,
see [README.md](README.md).

---

## 0. What VulnForge does

An LLM agent builds an intentionally vulnerable web app **inside an isolated
Celesto microVM**, verifies the exploit privately from inside the guest,
publishes one port on human approval so students can attack it, then deletes the
guest and revokes the route. Generated code never runs on your host.

Two interchangeable modes, chosen in `.env`:

| | Cloud | Local |
|---|---|---|
| Sandbox | Celesto Cloud (Firecracker) | QEMU microVM on your machine (KVM) |
| Published lab | Public HTTPS URL | Local preview on `127.0.0.1` |
| Needs | `CELESTO_API_KEY` | `celesto image pull ubuntu` + KVM |
| Cost | ~$0.015/guest-hour | $0 |
| Where the API runs | in Docker (`web` + `api` + `ledger`) | on the host (needs KVM) |

---

## 1. Prerequisites

- **Docker** + **Docker Compose**.
- **Ollama** running locally with the model pulled:
  ```bash
  ollama pull qwen2.5-coder:1.5b
  ```
- **Cloud mode:** a Celesto Cloud API key.
- **Local mode:** hardware virtualization (`/dev/kvm`) and the Celesto image:
  ```bash
  celesto image pull ubuntu            # firecracker image
  celesto image pull ubuntu --vmm qemu # qemu image (local mode uses QEMU)
  celesto doctor                       # should report OK
  ```

---

## 2. Configure

```bash
cd ctfAgent
cp .env.example .env
```

Edit `.env`:

```ini
# Pick ONE provider:
CELESTO_PROVIDER=cloud          # or: local
CELESTO_API_KEY=<your key>      # required only for cloud

LLM_PROVIDER=ollama             # or: openai_compatible
LLM_MODEL=qwen2.5-coder:1.5b
OLLAMA_BASE_URL=http://host.docker.internal:11434   # http://localhost:11434 for host/local mode

# Optional:
ACCESS_CODE=                    # if set, the UI/API require this code to create labs
MAX_ACTIVE_LABS=1
SANDBOX_TTL_MINUTES=15
```

> `.env` is gitignored. `.env.example` holds safe placeholders only.

---

## 3. Launch

### 3a. Cloud mode (Docker — recommended)

```bash
docker compose up --build -d --wait
```

Brings up three services — `ledger` (Postgres), `api` (FastAPI), `web` (nginx
dashboard proxying the API). Open:

- **Dashboard:** http://127.0.0.1:3000/
- API (direct): http://127.0.0.1:8080/

### 3b. Local mode (host API + QEMU)

Local guests need host KVM, so run the API on the host:

```bash
celesto image pull ubuntu
npm ci --prefix ui && npm run build --prefix ui   # build the dashboard once
docker compose up -d ledger                        # Postgres on 127.0.0.1:5432
source .venv/bin/activate
export CELESTO_PROVIDER=local LLM_PROVIDER=ollama LLM_MODEL=qwen2.5-coder:1.5b \
       OLLAMA_BASE_URL=http://localhost:11434 \
       DATABASE_URL=postgresql://ledger:ledger@127.0.0.1:5432/ledger
uvicorn src.api.main:app --host 127.0.0.1 --port 8080
```

Open **http://127.0.0.1:8080/** (the host API serves the dashboard itself in
local mode; the `web` container is not needed).

**Confirm it's live** (either mode):

```bash
curl -fsS http://127.0.0.1:3000/health   # cloud: {"status":"ok"}
curl -fsS http://127.0.0.1:3000/api/config   # shows the active Celesto + LLM mode
```

---

## 4. Run a lab (start to end, in the UI)

1. **Create Lab** tab → the badge row shows the active Celesto + LLM mode.
2. Enter a **Site description** (e.g. `login page for a student portal`).
3. Pick a **Mode** (Single profile or Bundle) and a **Vulnerability profile**
   (SQL injection, Reflected XSS, Path traversal, IDOR). Enter the **access code**
   if the server requires one.
4. Click **Generate lab** → you move to the **Live Run** tab.
5. Watch the **10-step timeline** update live over SSE:
   create guest → boot probe → egress self-check (`blocked`) → LLM customisation →
   write app → start app → private exploit verify → benign-clean verify →
   publish port → final health check. The sandbox panel shows the sandbox name,
   boot time, egress status, model, and a **"LLM fallback used"** badge if the
   small model fell back to the vetted template.
6. When private verification passes, an **approval dialog** appears:
   *"Verified exploit passed. Publish port?"* → **Approve & publish**.
7. The **Lab Ready** card shows the lab URL (public HTTPS on cloud, `127.0.0.1`
   preview on local), collapsible **hints**, a **flag submit** box, and a **TTL
   countdown**.
8. **Attack it.** Open the URL and run the exploit, e.g. for SQL injection:
   ```
   <lab-url>/search?q=' UNION SELECT value FROM secrets --
   ```
   The response contains the flag (`VF{...}`). Benign requests stay clean.
9. **Submit the flag** in the card → it marks the lab **Solved**.
10. Click **Destroy** → the route is revoked and the guest deleted. The timeline
    shows cleanup confirmed.

Other tabs:
- **Ledger** — every run from Postgres with state badges.
- **Command Audit** — allow/block decisions from `logs/commands.jsonl`; every
  command targets the sandbox, and the planted flag never appears.

---

## 5. Run the evaluations (optional)

```bash
# Reliability: N fresh labs end to end (local = $0, reliable; cloud = real URLs).
CELESTO_PROVIDER=local python scripts/run_eval.py --runs 20 --sleep 5

# Concurrency: 5 guests at once with unique names (local runtime).
CELESTO_PROVIDER=local python scripts/run_concurrency.py --jobs 5

# Containment: prompt-injection exfil test with a synthetic canary.
python scripts/run_containment.py

# Validate every report against its schema.
python scripts/validate_reports.py
```

Outputs land in `reports/` (`reliability.json`, `concurrency.json`,
`containment.json`, `postmortem.md`). Failed rows are kept, never dropped.

---

## 6. Verify the project

```bash
python -m pytest -q                      # 175 passed
python -m ruff check src scripts tests   # clean
python scripts/validate_reports.py       # reports valid
python scripts/secret_scan.py            # no secrets
```

---

## 7. Stop / tear down

```bash
docker compose down            # stop ledger + api + web
# local mode: Ctrl-C the uvicorn process too
```

Labs clean themselves up (route revoked + guest deleted) on success, failure,
and Ctrl-C; a TTL reaper also deletes any guest older than `SANDBOX_TTL_MINUTES`,
and a startup pass reconciles runs left non-terminal by a previous process. To
remove the database volume as well: `docker compose down -v`.

---

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| **"ledger is unavailable"** in the UI | Postgres isn't reachable. Cloud: `docker compose up -d ledger`. Local host mode: ensure `docker compose up -d ledger` is running and `DATABASE_URL` points to `127.0.0.1:5432`. |
| **"config invalid"** badge | `GET /api/config` lists the exact errors (e.g. `CELESTO_PROVIDER=cloud but CELESTO_API_KEY is empty`). Fix `.env` and restart. |
| **Provider / rate-limited errors** on create | The LLM endpoint is unreachable or throttled. Check Ollama is running (`curl localhost:11434/api/tags`) or your remote key/quota. |
| **Local lab won't boot** | Run `celesto doctor`; ensure `/dev/kvm` exists and the QEMU image is pulled (`celesto image pull ubuntu --vmm qemu`). |
| **Cloud creates fail after several runs** | The free trial throttles guest creation (one-sandbox quota) — not a cost issue. Wait, or use local mode. |
| **"LLM fallback used" badge** | Expected with the tiny `qwen2.5-coder:1.5b`: it couldn't produce valid source, so the vetted template was used. The lab is still real; fallback is never presented as model output. |
| **Dashboard shows a 503 placeholder** | Backend `/` with no built UI. Cloud: use `:3000` (the web service). Local: `npm run build --prefix ui` first. |

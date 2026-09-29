# Automated API Security Auditor

A defensive, authorization-first API security auditing project with **two interfaces**:

- **Web dashboard** — React + TypeScript frontend with a FastAPI backend.
- **CLI scanner** — a Typer/Rich command-line interface using the same scanning engine.

The implementation follows the project workflow: **import an OpenAPI document → map the attack surface → establish a baseline → run controlled tests → analyze abnormal responses → produce evidence-backed findings and reports**.

> [!IMPORTANT]
> Use this tool only on APIs you own or are explicitly authorized to test. The scanner intentionally defaults to low request rates, read-only HTTP methods, exact-host scoping, and non-destructive mutations.

## What is implemented

### API discovery

- OpenAPI 3.x and Swagger 2.0 parsing from JSON/YAML.
- Paths, HTTP methods, parameters, request-body schemas, security requirements, tags, summaries.
- Sample request construction from `example`, `default`, `enum`, and primitive schema types.
- Local `$ref` resolution for component schemas and parameters.

### Controlled security tests

- **Authentication**: missing and malformed bearer-token behavior.
- **Authorization/BOLA heuristic**: optional alternate object IDs supplied by the operator.
- **Input validation**: empty values, wrong primitive types, omitted required query/body fields.
- **Data exposure**: sensitive response-key detection.
- **Verbose errors / misconfiguration**: stack trace, exception, SQL-state and debug leakage indicators.
- **Resource controls**: passive inspection for common rate-limit headers; no stress testing.

### Safety controls

- Remote targets require an explicit exact host allowlist.
- `--ack-authorized` / dashboard authorization checkbox is mandatory.
- Read-only methods (`GET`, `HEAD`, `OPTIONS`) are the default.
- State-changing methods require a separate opt-in.
- Rate limiting and request budgets are enforced by the engine.
- Secrets are not persisted in the database; bearer tokens and custom header values are kept only in process memory.
- No credential cracking, exploit chains, destructive payloads, or denial-of-service logic.

### Reporting

- Severity, confidence, endpoint, evidence, OWASP API category, and remediation.
- JSON and HTML exports.
- Dashboard summary cards, recent scans, scan progress, findings table, and project inventory.

---

## Architecture

```text
                      ┌────────────────────┐
                      │   React Dashboard  │
                      │   localhost:5173   │
                      └─────────┬──────────┘
                                │ REST
                                ▼
┌──────────────┐       ┌────────────────────┐       ┌──────────────────┐
│ Typer / Rich │──────▶│ Shared Audit Core  │──────▶│ Authorized Target│
│ CLI          │       │ Parser + Scanner   │       │ API              │
└──────────────┘       │ Analyzer + Reports │       └──────────────────┘
                       └─────────┬──────────┘
                                 │
                                 ▼
                       ┌────────────────────┐
                       │ SQLite / SQLAlchemy│
                       └────────────────────┘
```

## Repository layout

```text
src/auditor/
  api/             FastAPI application and routes
  engine/          OpenAPI parsing, scope policy, scanner and analyzer
  reporting/       JSON/HTML report generation
  cli.py           CLI interface

dashboard/         React + TypeScript + Vite dashboard
demo_target/       Local intentionally-insecure demo API for authorized lab use
tests/             Unit + smoke tests
docs/              Architecture, test model, dashboard preview
```

## Quick start — backend + CLI

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\\Scripts\\activate
pip install -e ".[dev]"
api-auditor serve --reload
```

Backend API: `http://localhost:8000`  
Swagger UI: `http://localhost:8000/docs`

## Quick start — dashboard

```bash
cd dashboard
npm install
npm run dev
```

Dashboard: `http://localhost:5173`

## Quick start — local demo target

The demo target is intentionally vulnerable and should remain local.

```bash
uvicorn demo_target.app:app --host 127.0.0.1 --port 9000
```

Demo bearer token: `demo-user-a`

Create a project with the included `demo_target/openapi.yaml`, then scan:

```bash
api-auditor scan demo_target/openapi.yaml \
  --base-url http://127.0.0.1:9000 \
  --bearer-token demo-user-a \
  --alternate-id user_id=2 \
  --ack-authorized \
  --output reports/demo-report.json \
  --html reports/demo-report.html
```

Because the target is loopback, an explicit `--allow-host` is not required. For any remote host, add the exact hostname:

```bash
--allow-host api.example.com
```

## CLI commands

```bash
api-auditor --help
api-auditor inspect ./openapi.yaml
api-auditor scan ./openapi.yaml --base-url http://127.0.0.1:9000 --ack-authorized
api-auditor serve --reload
```

### `inspect`

Shows the endpoint inventory without sending traffic.

### `scan`

Important options:

- `--bearer-token TOKEN`
- `--secondary-bearer-token TOKEN` for a second authorized test identity
- `--header Name=Value` for API keys/custom auth headers (repeatable)
- `--allow-host HOST` (repeatable, required for remote targets)
- `--alternate-id name=value` (repeatable; enables explicit BOLA candidates)
- `--allow-write-methods`
- `--rps 2`
- `--max-requests 250`
- `--ack-authorized`
- `--output report.json`
- `--html report.html`

## Dashboard workflow

1. **Projects** → create a project and paste/upload an OpenAPI document.
2. Review parsed endpoint inventory.
3. **New Scan** → select project, enter base URL, optionally bearer token and alternate IDs.
4. Confirm authorization and exact remote host scope.
5. Run scan.
6. Watch progress and inspect findings.
7. Export HTML or JSON report.

## Severity model

| Severity | Typical meaning |
|---|---|
| Critical | Strong evidence of highly sensitive access; currently reserved for future modules |
| High | Strong authentication bypass or sensitive unauthorized response |
| Medium | Potential BOLA, sensitive field exposure, verbose exception evidence |
| Low | Weak validation or low-risk security signal |
| Info | Passive observations requiring review |

All automated findings are **evidence + heuristics**, not a substitute for expert validation.

## Run tests

```bash
pytest -q
```

## Docker Compose

```bash
docker compose up --build
```

Services:

- Dashboard: `http://localhost:5173`
- Backend: `http://localhost:8000`
- Demo target: `http://127.0.0.1:9000`

## Extending the project

Natural next modules:

- GraphQL schema inventory.
- Role-pair authorization test matrices.
- CI/CD policy gates based on verified findings.
- Historical scan diffing.
- Signed report artifacts.
- Pluggable test modules with strict scope capabilities.
- Human-in-the-loop anomaly triage.

See `docs/ARCHITECTURE.md` and `docs/TEST_MODEL.md` for implementation details.

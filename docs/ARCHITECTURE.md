# Architecture

## Design goals

1. **One audit engine, two interfaces.** The dashboard and CLI must not drift into different security logic.
2. **Authorization-first execution.** Scope validation runs before the first request.
3. **Evidence over labels.** Findings include the exact operation, status changes, response previews, and confidence.
4. **Safe-by-default behavior.** Read-only methods, low rate, finite request budget, and exact host allowlists.
5. **Operator-controlled authorization testing.** BOLA candidates are never guessed across arbitrary ID ranges; the operator supplies alternate IDs and can optionally provide a second authorized identity for stronger comparison evidence.

## Components

### OpenAPI parser

`auditor.engine.openapi.OpenApiParser`

- Parses JSON or YAML.
- Resolves local component references.
- Extracts operations, parameters, body schemas, tags, and security declarations.
- Creates conservative sample values to establish a baseline.

### Scope policy

`auditor.engine.scope.validate_scope`

- Requires an explicit authorization acknowledgement.
- Allows loopback by default for local development.
- Requires exact hostname allowlisting for remote targets.
- Rejects non-HTTP(S) schemes.

### Scanner

`auditor.engine.scanner.AuditScanner`

Runs a deterministic sequence per operation:

1. Skip state-changing methods unless the operator opted in.
2. Send baseline request.
3. Analyze successful baseline for sensitive fields.
4. Where OpenAPI declares security and a token is supplied, test missing/malformed authentication.
5. If the operator supplied an alternate value for a path object identifier, send one explicit BOLA candidate request.
6. Apply a maximum of two small validation mutations per parameter.
7. Analyze 5xx responses and verbose error indicators.
8. Respect global RPS and request budget.

### Analyzer

`auditor.engine.analyzer`

The analyzer intentionally separates **signal collection** from **security certainty**. For example, an alternate object ID returning 200 is recorded as a *potential* BOLA with medium/low confidence because only a human or a richer role/ownership model can determine whether access is actually unauthorized.

### Persistence

SQLAlchemy models:

- `Project` — name, description, raw specification.
- `Scan` — target, state, redacted config, summary and progress.
- `Finding` — severity, confidence, evidence, remediation, OWASP mapping.

Bearer tokens are not stored in the database.

### Reporting

JSON is the canonical machine-readable report. HTML is generated from the same payload for presentation and academic screenshots.

## Production hardening ideas

- Move scan execution to a task queue (Celery/RQ/Arq) rather than in-process `asyncio.create_task`.
- Encrypt secrets in a dedicated secret store if resumable scans are required.
- Add organization/user authentication and RBAC to the dashboard.
- Add an audit log for scan configuration changes.
- Use PostgreSQL for concurrent multi-user workloads.
- Add target certificates/pinning and egress controls in the worker network.

# Demo and Presentation Guide

This guide is aimed at a classroom/project demonstration of the Automated API Security Auditor.

## 1. Start the local target

The included target is intentionally insecure and binds to loopback only.

```bash
uvicorn demo_target.app:app --host 127.0.0.1 --port 9000
```

Open its API documentation at `http://127.0.0.1:9000/docs`.

## 2. Start the auditor backend

```bash
api-auditor serve --reload
```

Backend Swagger UI: `http://127.0.0.1:8000/docs`.

## 3. Start the React dashboard

```bash
cd dashboard
npm install
npm run dev
```

Open `http://localhost:5173`.

## 4. Create the demo project

In **Projects → New project**:

- Name: `Local Demo API`
- Upload: `demo_target/openapi.yaml`

The project detail page should show five discovered GET operations.

## 5. Configure the scan

In **New scan**:

- Base URL: `http://127.0.0.1:9000`
- Primary bearer token: `demo-user-a`
- Secondary bearer token: `demo-user-b`
- Alternate object IDs: `user_id=2`
- Requests/second: `2`
- Request budget: `250`
- Leave state-changing methods disabled.
- Confirm the authorization checkbox.

## 6. Expected demo findings

The exact count can change as the implementation evolves, but the included target is designed to demonstrate:

1. **Potential BOLA** on `GET /users/{user_id}` because the primary test identity can request object `2`.
2. **Potential sensitive field exposure** on `GET /debug/leak` because the response contains a fake secret-named field.
3. **Resource-control observation** when common rate-limit headers are not visible.

The BOLA finding becomes stronger when the secondary identity receives the same object response for `user_id=2`, because that gives the auditor a comparison identity within the controlled test lab.

## 7. CLI-only demonstration

Linux/macOS:

```bash
./scripts/run-demo.sh
```

Windows PowerShell:

```powershell
./scripts/run-demo.ps1
```

The generated reports are written to:

- `reports/demo-report.json`
- `reports/demo-report.html`

## 8. Screenshot for the presentation

For a clean screenshot, use the dashboard Overview page after a completed demo scan. Capture the top summary cards, severity distribution, and recent-scans table. If the React dependencies are not installed yet, `docs/dashboard-preview.html` is a static visual preview of the intended interface.

## 9. Suggested live presentation sequence

1. Show the OpenAPI file.
2. Use `api-auditor inspect demo_target/openapi.yaml` to prove the tool first maps the attack surface without sending traffic.
3. Start the scan from the dashboard.
4. Show progress and request count.
5. Open the BOLA finding and explain the evidence and confidence model.
6. Export the HTML report.
7. End by explaining the safety controls: explicit scope, low rate, finite request budget, read-only default, and no blind enumeration.

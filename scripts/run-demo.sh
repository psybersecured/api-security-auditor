#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

cleanup() {
  if [[ -n "${DEMO_PID:-}" ]]; then kill "$DEMO_PID" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

uvicorn demo_target.app:app --host 127.0.0.1 --port 9000 &
DEMO_PID=$!
sleep 1

python -m auditor.cli scan demo_target/openapi.yaml \
  --base-url http://127.0.0.1:9000 \
  --bearer-token demo-user-a \
  --secondary-bearer-token demo-user-b \
  --alternate-id user_id=2 \
  --ack-authorized \
  --output reports/demo-report.json \
  --html reports/demo-report.html

echo "Demo complete. Open reports/demo-report.html"

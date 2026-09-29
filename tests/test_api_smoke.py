import os
os.environ.setdefault("AUDITOR_DATABASE_URL", "sqlite:///:memory:")

from fastapi.testclient import TestClient
from auditor.api.main import app


def test_health():
    with TestClient(app) as client:
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

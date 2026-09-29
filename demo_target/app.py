from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

app = FastAPI(
    title="API Auditor Local Demo Target",
    version="1.0.0",
    description="Intentionally insecure local-only API for demonstrating the defensive auditor.",
)
security = HTTPBearer()

USERS = {
    1: {"id": 1, "name": "Demo Alice", "email": "alice@example.test", "plan": "student"},
    2: {"id": 2, "name": "Demo Bob", "email": "bob@example.test", "plan": "admin"},
}
TOKENS = {"demo-user-a": 1, "demo-user-b": 2}


def current_user(creds: HTTPAuthorizationCredentials = Depends(security)) -> int:
    user_id = TOKENS.get(creds.credentials)
    if not user_id:
        raise HTTPException(401, "Invalid demo token")
    return user_id


@app.get("/health", tags=["public"])
def health():
    return {"status": "ok", "environment": "local-demo"}


@app.get("/account", tags=["accounts"])
def account(user_id: int = Depends(current_user)):
    return USERS[user_id]


@app.get("/users/{user_id}", tags=["accounts"])
def get_user(user_id: int, _: int = Depends(current_user)):
    """INTENTIONALLY INSECURE: authenticates but does not enforce object ownership."""
    if user_id not in USERS:
        raise HTTPException(404, "User not found")
    return USERS[user_id]


@app.get("/debug/leak", tags=["demo-findings"])
def debug_leak(_: int = Depends(current_user)):
    """INTENTIONALLY INSECURE: returns a fake secret-named field for exposure detection."""
    return {"service": "billing-demo", "internal_api_key": "DEMO-FAKE-KEY-NOT-A-REAL-SECRET"}


@app.get("/search", tags=["validation"])
def search(limit: int = 10, q: str = ""):
    return {"q": q, "limit": limit, "results": []}

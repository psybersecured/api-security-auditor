from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv("AUDITOR_DATABASE_URL", "sqlite:///./auditor.db")
    cors_origins: tuple[str, ...] = tuple(
        x.strip() for x in os.getenv("AUDITOR_CORS_ORIGINS", "http://localhost:5173").split(",") if x.strip()
    )
    default_rps: float = float(os.getenv("AUDITOR_DEFAULT_RPS", "2.0"))
    max_rps: float = float(os.getenv("AUDITOR_MAX_RPS", "10.0"))
    max_requests: int = int(os.getenv("AUDITOR_MAX_REQUESTS", "250"))


settings = Settings()

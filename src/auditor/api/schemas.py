from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


class ProjectCreate(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    description: str = Field(default="", max_length=3000)
    spec_text: str = Field(min_length=10)


class ProjectOut(BaseModel):
    id: int
    name: str
    description: str
    created_at: datetime
    spec_info: dict[str, Any] | None = None


class OperationOut(BaseModel):
    method: str
    path: str
    summary: str
    tags: list[str]
    security_required: bool
    parameters: list[dict[str, Any]]
    has_request_body: bool


class ScanCreate(BaseModel):
    project_id: int
    base_url: str
    bearer_token: str | None = None
    secondary_bearer_token: str | None = None
    extra_headers: dict[str, str] = Field(default_factory=dict)
    allowed_hosts: list[str] = Field(default_factory=list)
    alternate_ids: dict[str, str] = Field(default_factory=dict)
    allow_write_methods: bool = False
    requests_per_second: float = Field(default=2.0, ge=0.1, le=10.0)
    max_requests: int = Field(default=250, ge=1, le=2000)
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0)
    verify_tls: bool = True
    authorization_ack: bool

    @field_validator("base_url")
    @classmethod
    def trim_url(cls, value: str) -> str:
        return value.strip().rstrip("/")


class ScanOut(BaseModel):
    id: int
    project_id: int
    project_name: str | None = None
    base_url: str
    status: str
    profile: str
    progress: int
    config: dict[str, Any]
    stats: dict[str, Any]
    error: str
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class FindingOut(BaseModel):
    id: int
    scan_id: int
    severity: str
    confidence: str
    category: str
    title: str
    description: str
    endpoint: str
    method: str
    evidence: dict[str, Any]
    remediation: str
    owasp: str
    created_at: datetime

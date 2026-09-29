from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable


@dataclass(slots=True)
class ParameterSpec:
    name: str
    location: str
    required: bool = False
    schema: dict[str, Any] = field(default_factory=dict)
    example: Any = None


@dataclass(slots=True)
class Operation:
    method: str
    path: str
    summary: str = ""
    operation_id: str = ""
    tags: list[str] = field(default_factory=list)
    parameters: list[ParameterSpec] = field(default_factory=list)
    request_schema: dict[str, Any] | None = None
    security_required: bool = False

    @property
    def label(self) -> str:
        return f"{self.method.upper()} {self.path}"


@dataclass(slots=True)
class FindingRecord:
    severity: str
    confidence: str
    category: str
    title: str
    description: str
    endpoint: str
    method: str
    evidence: dict[str, Any]
    remediation: str
    owasp: str = ""


@dataclass(slots=True)
class ScanOptions:
    base_url: str
    bearer_token: str | None = None
    secondary_bearer_token: str | None = None
    extra_headers: dict[str, str] = field(default_factory=dict)
    allowed_hosts: set[str] = field(default_factory=set)
    alternate_ids: dict[str, str] = field(default_factory=dict)
    allow_write_methods: bool = False
    requests_per_second: float = 2.0
    max_requests: int = 250
    timeout_seconds: float = 10.0
    authorization_ack: bool = False
    verify_tls: bool = True
    user_agent: str = "Automated-API-Security-Auditor/1.0"


@dataclass(slots=True)
class ScanSummary:
    endpoints_discovered: int = 0
    endpoints_scanned: int = 0
    endpoints_skipped: int = 0
    requests_sent: int = 0
    findings: int = 0
    severity_counts: dict[str, int] = field(default_factory=dict)


ProgressCallback = Callable[[int, ScanSummary], Awaitable[None] | None]

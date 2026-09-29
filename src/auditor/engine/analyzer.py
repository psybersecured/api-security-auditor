from __future__ import annotations

import json
import re
from typing import Any

from .models import FindingRecord, Operation

SENSITIVE_KEYS = {
    "password", "passwd", "secret", "client_secret", "api_key", "apikey", "access_token",
    "refresh_token", "private_key", "ssn", "credit_card", "card_number", "internal_api_key",
}
ERROR_PATTERNS = [
    r"traceback \(most recent call last\)", r"stack trace", r"sqlstate", r"uncaught exception",
    r"debug mode", r"exception in thread", r"syntaxerror", r"referenceerror",
]


def response_preview(text: str, limit: int = 600) -> str:
    clean = text.replace("\x00", "")
    return clean[:limit] + ("…" if len(clean) > limit else "")


def body_fingerprint(text: str) -> tuple[int, str]:
    return (len(text), text[:180])


def _walk_keys(value: Any, prefix: str = "") -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            key_l = str(key).lower()
            dotted = f"{prefix}.{key}" if prefix else str(key)
            if key_l in SENSITIVE_KEYS or any(token in key_l for token in ("password", "secret", "token", "api_key")):
                found.append(dotted)
            found.extend(_walk_keys(child, dotted))
    elif isinstance(value, list):
        for i, child in enumerate(value[:10]):
            found.extend(_walk_keys(child, f"{prefix}[{i}]") if prefix else _walk_keys(child, f"[{i}]"))
    return found


def exposure_findings(operation: Operation, status: int, text: str) -> list[FindingRecord]:
    if not 200 <= status < 300:
        return []
    try:
        payload = json.loads(text)
    except Exception:
        return []
    keys = sorted(set(_walk_keys(payload)))
    if not keys:
        return []
    return [FindingRecord(
        severity="medium",
        confidence="medium",
        category="data_exposure",
        title="Potential sensitive fields exposed in API response",
        description="The successful response contains field names commonly associated with secrets or sensitive data. Review whether these fields are required for this client and role.",
        endpoint=operation.path,
        method=operation.method,
        evidence={"status": status, "sensitive_fields": keys[:20]},
        remediation="Apply response allowlists/DTOs, remove unnecessary sensitive fields, and enforce least-privilege data serialization.",
        owasp="API3:2023 Broken Object Property Level Authorization",
    )]


def verbose_error_findings(operation: Operation, status: int, text: str, test_name: str) -> list[FindingRecord]:
    lower = text.lower()
    hits = [pattern for pattern in ERROR_PATTERNS if re.search(pattern, lower, flags=re.I)]
    if not hits:
        return []
    return [FindingRecord(
        severity="medium",
        confidence="high",
        category="misconfiguration",
        title="Verbose server error details exposed",
        description="A controlled invalid-input test produced response content that appears to reveal implementation or exception details.",
        endpoint=operation.path,
        method=operation.method,
        evidence={"status": status, "test": test_name, "matched_indicators": hits, "preview": response_preview(text)},
        remediation="Return generic client-facing errors, disable debug traces in production, and keep detailed exceptions in protected server logs.",
        owasp="API8:2023 Security Misconfiguration",
    )]


def auth_findings(operation: Operation, baseline_status: int, test_status: int, test_name: str, preview: str) -> list[FindingRecord]:
    if not operation.security_required:
        return []
    baseline_ok = 200 <= baseline_status < 300
    test_ok = 200 <= test_status < 300
    if baseline_ok and test_ok:
        return [FindingRecord(
            severity="high",
            confidence="high" if test_name == "missing_authorization" else "medium",
            category="authentication",
            title="Protected operation accepted invalid authentication state",
            description=f"The operation is marked as secured in the API specification, but the '{test_name}' request still returned a successful HTTP status.",
            endpoint=operation.path,
            method=operation.method,
            evidence={"baseline_status": baseline_status, "test_status": test_status, "test": test_name, "preview": preview},
            remediation="Enforce authentication middleware consistently and fail closed before business logic executes.",
            owasp="API2:2023 Broken Authentication",
        )]
    return []


def bola_findings(operation: Operation, baseline_status: int, baseline_text: str, alt_status: int, alt_text: str, parameter: str, value: str, secondary_status: int | None = None, secondary_text: str | None = None) -> list[FindingRecord]:
    if not (200 <= baseline_status < 300 and 200 <= alt_status < 300):
        return []
    if secondary_status is not None and 200 <= secondary_status < 300 and secondary_text is not None and body_fingerprint(alt_text) == body_fingerprint(secondary_text):
        confidence = "high"
    elif body_fingerprint(baseline_text) == body_fingerprint(alt_text):
        confidence = "low"
    else:
        confidence = "medium"
    return [FindingRecord(
        severity="medium",
        confidence=confidence,
        category="authorization",
        title="Potential broken object-level authorization (BOLA)",
        description="An operator-supplied alternate object identifier returned a successful response. This is a heuristic finding and must be validated against the intended ownership/role model.",
        endpoint=operation.path,
        method=operation.method,
        evidence={
            "parameter": parameter,
            "alternate_value": value,
            "baseline_status": baseline_status,
            "alternate_status": alt_status,
            "baseline_preview": response_preview(baseline_text, 300),
            "alternate_preview": response_preview(alt_text, 300),
            "secondary_identity_status": secondary_status,
            "secondary_identity_preview": response_preview(secondary_text, 300) if secondary_text is not None else None,
        },
        remediation="Enforce object ownership/tenant authorization server-side for every object lookup, independent of client-supplied identifiers.",
        owasp="API1:2023 Broken Object Level Authorization",
    )]


def validation_finding(operation: Operation, test_name: str, status: int, text: str) -> list[FindingRecord]:
    if 500 <= status <= 599:
        return [FindingRecord(
            severity="low",
            confidence="medium",
            category="input_validation",
            title="Invalid input triggered a server error",
            description="A small, non-destructive validation mutation caused a 5xx response instead of a controlled 4xx validation result.",
            endpoint=operation.path,
            method=operation.method,
            evidence={"test": test_name, "status": status, "preview": response_preview(text)},
            remediation="Validate request data before business logic, handle parser/type errors consistently, and return bounded 4xx responses.",
            owasp="API8:2023 Security Misconfiguration",
        )]
    return []

from __future__ import annotations

import asyncio
import inspect
import time
from dataclasses import asdict
from typing import Any
from urllib.parse import quote

import httpx

from .analyzer import (
    auth_findings,
    bola_findings,
    exposure_findings,
    response_preview,
    validation_finding,
    verbose_error_findings,
)
from .models import FindingRecord, Operation, ProgressCallback, ScanOptions, ScanSummary
from .openapi import OpenApiParser
from .scope import validate_scope

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
SEVERITIES = ("critical", "high", "medium", "low", "info")


class RateLimiter:
    def __init__(self, rps: float):
        self.interval = 1.0 / max(rps, 0.1)
        self._last = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self._lock:
            now = time.monotonic()
            delay = self.interval - (now - self._last)
            if delay > 0:
                await asyncio.sleep(delay)
            self._last = time.monotonic()


class AuditScanner:
    def __init__(self, parser: OpenApiParser, options: ScanOptions, progress: ProgressCallback | None = None):
        self.parser = parser
        self.options = options
        self.progress = progress
        self.summary = ScanSummary()
        self.findings: list[FindingRecord] = []
        self._limiter = RateLimiter(options.requests_per_second)
        self._cancelled = False

    def cancel(self) -> None:
        self._cancelled = True

    async def _progress(self, percent: int) -> None:
        if self.progress is None:
            return
        result = self.progress(percent, self.summary)
        if inspect.isawaitable(result):
            await result

    def _headers(self) -> dict[str, str]:
        headers = {"User-Agent": self.options.user_agent, "Accept": "application/json"}
        headers.update(self.options.extra_headers)
        if self.options.bearer_token:
            headers["Authorization"] = f"Bearer {self.options.bearer_token}"
        return headers

    def _sample(self, parameter) -> Any:
        if parameter.example is not None:
            return parameter.example
        return self.parser.sample_value(parameter.schema, name=parameter.name)

    def _build_request(self, op: Operation, *, overrides: dict[str, Any] | None = None, omit: set[str] | None = None):
        overrides = overrides or {}
        omit = omit or set()
        path = op.path
        query: dict[str, Any] = {}
        body = self.parser.sample_value(op.request_schema) if op.request_schema else None
        for p in op.parameters:
            if p.name in omit:
                continue
            value = overrides.get(p.name, self._sample(p))
            if p.location == "path":
                path = path.replace("{" + p.name + "}", quote(str(value), safe=""))
            elif p.location == "query" and (p.required or p.name in overrides or p.example is not None):
                query[p.name] = value
            elif p.location == "header" and p.required:
                pass
        if isinstance(body, dict):
            for key in list(body):
                if key in omit:
                    body.pop(key, None)
                if key in overrides:
                    body[key] = overrides[key]
        return path, query, body

    async def _request(self, client: httpx.AsyncClient, op: Operation, *, headers=None, overrides=None, omit=None):
        if self._cancelled:
            raise asyncio.CancelledError
        if self.summary.requests_sent >= self.options.max_requests:
            raise RuntimeError("Request budget reached")
        await self._limiter.wait()
        path, query, body = self._build_request(op, overrides=overrides, omit=omit)
        url = self.options.base_url.rstrip("/") + "/" + path.lstrip("/")
        request_headers = dict(self._headers())
        if headers is not None:
            request_headers = headers
        kwargs: dict[str, Any] = {"params": query, "headers": request_headers}
        if body is not None and op.method not in {"GET", "HEAD"}:
            kwargs["json"] = body
        response = await client.request(op.method, url, **kwargs)
        self.summary.requests_sent += 1
        return response

    def _add(self, items: list[FindingRecord]) -> None:
        existing = {(f.category, f.title, f.method, f.endpoint, str(f.evidence.get("test", ""))) for f in self.findings}
        for item in items:
            key = (item.category, item.title, item.method, item.endpoint, str(item.evidence.get("test", "")))
            if key not in existing:
                self.findings.append(item)
                existing.add(key)

    async def scan(self) -> tuple[list[FindingRecord], ScanSummary]:
        validate_scope(self.options.base_url, self.options.allowed_hosts, self.options.authorization_ack)
        if self.options.requests_per_second > 10:
            raise ValueError("Maximum supported request rate is 10 requests/second")
        operations = self.parser.operations()
        self.summary.endpoints_discovered = len(operations)
        if not operations:
            return [], self.summary
        timeout = httpx.Timeout(self.options.timeout_seconds)
        async with httpx.AsyncClient(timeout=timeout, verify=self.options.verify_tls, follow_redirects=False) as client:
            for index, op in enumerate(operations, start=1):
                if self._cancelled:
                    break
                if op.method not in SAFE_METHODS and not self.options.allow_write_methods:
                    self.summary.endpoints_skipped += 1
                    await self._progress(int(index / len(operations) * 100))
                    continue
                try:
                    baseline = await self._request(client, op)
                except RuntimeError:
                    break
                except (httpx.HTTPError, ValueError) as exc:
                    self._add([FindingRecord(
                        severity="info", confidence="high", category="connectivity",
                        title="Endpoint request could not be completed",
                        description="The scanner could not establish a usable baseline response for this operation.",
                        endpoint=op.path, method=op.method,
                        evidence={"error": str(exc)},
                        remediation="Confirm the base URL, network reachability, TLS settings, required parameters, and authentication context.",
                    )])
                    self.summary.endpoints_scanned += 1
                    await self._progress(int(index / len(operations) * 100))
                    continue

                self.summary.endpoints_scanned += 1
                self._add(exposure_findings(op, baseline.status_code, baseline.text))

                # Passive resource-control observation. No burst or stress behavior.
                if op.method == "GET" and index == 1:
                    rate_headers = {k: v for k, v in baseline.headers.items() if k.lower() in {"ratelimit-limit", "ratelimit-remaining", "x-ratelimit-limit", "x-ratelimit-remaining", "retry-after"}}
                    if not rate_headers:
                        self._add([FindingRecord(
                            severity="info", confidence="low", category="resource_controls",
                            title="No common rate-limit headers observed",
                            description="The sampled response did not expose common rate-limit metadata. This does not prove rate limiting is absent; server-side enforcement may be opaque.",
                            endpoint=op.path, method=op.method,
                            evidence={"status": baseline.status_code},
                            remediation="Verify that abuse controls and quotas are enforced server-side for expensive or sensitive operations.",
                            owasp="API4:2023 Unrestricted Resource Consumption",
                        )])

                # Authentication tests only where the spec declares security.
                if op.security_required and self.options.bearer_token:
                    base_headers = {"User-Agent": self.options.user_agent, "Accept": "application/json", **self.options.extra_headers}
                    base_headers.pop("Authorization", None)
                    for test_name, headers in (
                        ("missing_authorization", dict(base_headers)),
                        ("malformed_authorization", {**base_headers, "Authorization": "Bearer invalid.invalid.invalid"}),
                    ):
                        try:
                            r = await self._request(client, op, headers=headers)
                            self._add(auth_findings(op, baseline.status_code, r.status_code, test_name, response_preview(r.text)))
                            self._add(verbose_error_findings(op, r.status_code, r.text, test_name))
                        except (httpx.HTTPError, RuntimeError):
                            break

                # Explicit operator-provided alternate object IDs only.
                for p in op.parameters:
                    if p.location == "path" and p.name in self.options.alternate_ids:
                        try:
                            alt_value = self.options.alternate_ids[p.name]
                            r = await self._request(client, op, overrides={p.name: alt_value})
                            secondary = None
                            if self.options.secondary_bearer_token:
                                secondary_headers = self._headers()
                                secondary_headers["Authorization"] = f"Bearer {self.options.secondary_bearer_token}"
                                secondary = await self._request(client, op, headers=secondary_headers, overrides={p.name: alt_value})
                            self._add(bola_findings(
                                op, baseline.status_code, baseline.text, r.status_code, r.text, p.name, alt_value,
                                secondary.status_code if secondary is not None else None,
                                secondary.text if secondary is not None else None,
                            ))
                        except (httpx.HTTPError, RuntimeError):
                            pass

                # Small non-destructive input validation mutations.
                candidates = [p for p in op.parameters if p.location in {"query", "path"}]
                for p in candidates[:2]:
                    mutations: list[tuple[str, Any]] = [(f"{p.name}_empty", "")]
                    typ = (p.schema or {}).get("type")
                    if typ in {"integer", "number"}:
                        mutations.append((f"{p.name}_wrong_type", "not-a-number"))
                    elif typ == "boolean":
                        mutations.append((f"{p.name}_wrong_type", "not-a-boolean"))
                    else:
                        mutations.append((f"{p.name}_boundary_string", "x" * 64))
                    for test_name, value in mutations[:2]:
                        try:
                            r = await self._request(client, op, overrides={p.name: value})
                            self._add(validation_finding(op, test_name, r.status_code, r.text))
                            self._add(verbose_error_findings(op, r.status_code, r.text, test_name))
                        except (httpx.HTTPError, RuntimeError):
                            break

                # Required JSON-field omission for opted-in write methods.
                if self.options.allow_write_methods and isinstance(op.request_schema, dict):
                    required = list(self.parser.resolve_ref(op.request_schema).get("required") or [])
                    for field in required[:2]:
                        try:
                            r = await self._request(client, op, omit={field})
                            self._add(validation_finding(op, f"omit_required_body_field:{field}", r.status_code, r.text))
                            self._add(verbose_error_findings(op, r.status_code, r.text, f"omit_required_body_field:{field}"))
                        except (httpx.HTTPError, RuntimeError):
                            break

                await self._progress(int(index / len(operations) * 100))

        counts = {s: 0 for s in SEVERITIES}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        self.summary.findings = len(self.findings)
        self.summary.severity_counts = counts
        await self._progress(100)
        return self.findings, self.summary

    def summary_dict(self) -> dict[str, Any]:
        return asdict(self.summary)

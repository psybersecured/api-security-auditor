from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from dataclasses import asdict
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from auditor import __version__
from auditor.config import settings
from auditor.db import Finding, Project, Scan, get_session, init_db
from auditor.engine.models import ScanOptions, ScanSummary
from auditor.engine.openapi import OpenApiParser, SpecError
from auditor.engine.scope import ScopeError, validate_scope
from auditor.reporting.render import build_report_payload, render_html_report

from .jobs import run_scan_job
from .schemas import FindingOut, OperationOut, ProjectCreate, ProjectOut, ScanCreate, ScanOut

@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Automated API Security Auditor",
    version=__version__,
    description="Authorization-first API security auditing backend.",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def jloads(value: str, default: Any):
    try:
        return json.loads(value or "")
    except Exception:
        return default


def project_out(project: Project) -> ProjectOut:
    try:
        info = OpenApiParser.from_text(project.spec_text).info()
    except Exception:
        info = None
    return ProjectOut(id=project.id, name=project.name, description=project.description, created_at=project.created_at, spec_info=info)


def scan_out(scan: Scan) -> ScanOut:
    return ScanOut(
        id=scan.id, project_id=scan.project_id,
        project_name=scan.project.name if scan.project else None,
        base_url=scan.base_url, status=scan.status, profile=scan.profile, progress=scan.progress,
        config=jloads(scan.config_json, {}), stats=jloads(scan.stats_json, {}), error=scan.error,
        created_at=scan.created_at, started_at=scan.started_at, finished_at=scan.finished_at,
    )


def finding_out(f: Finding) -> FindingOut:
    return FindingOut(
        id=f.id, scan_id=f.scan_id, severity=f.severity, confidence=f.confidence, category=f.category,
        title=f.title, description=f.description, endpoint=f.endpoint, method=f.method,
        evidence=jloads(f.evidence_json, {}), remediation=f.remediation, owasp=f.owasp, created_at=f.created_at,
    )


@app.get("/health")
def health():
    return {"status": "ok", "version": __version__}


@app.get("/api/overview")
def overview(session: Session = Depends(get_session)):
    project_count = session.scalar(select(func.count(Project.id))) or 0
    scan_count = session.scalar(select(func.count(Scan.id))) or 0
    finding_count = session.scalar(select(func.count(Finding.id))) or 0
    severity = {s: 0 for s in ["critical", "high", "medium", "low", "info"]}
    for sev, count in session.execute(select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)).all():
        severity[sev] = count
    recent = session.execute(select(Scan).order_by(desc(Scan.created_at)).limit(6)).scalars().all()
    return {
        "projects": project_count, "scans": scan_count, "findings": finding_count,
        "severity": severity, "recent_scans": [scan_out(x).model_dump(mode="json") for x in recent],
    }


@app.post("/api/projects", response_model=ProjectOut, status_code=201)
def create_project(data: ProjectCreate, session: Session = Depends(get_session)):
    try:
        parser = OpenApiParser.from_text(data.spec_text)
        parser.operations()
    except SpecError as exc:
        raise HTTPException(400, str(exc)) from exc
    fmt = "json" if data.spec_text.lstrip().startswith("{") else "yaml"
    project = Project(name=data.name, description=data.description, spec_text=data.spec_text, spec_format=fmt)
    session.add(project)
    session.commit()
    session.refresh(project)
    return project_out(project)


@app.get("/api/projects", response_model=list[ProjectOut])
def list_projects(session: Session = Depends(get_session)):
    return [project_out(p) for p in session.execute(select(Project).order_by(desc(Project.created_at))).scalars().all()]


@app.get("/api/projects/{project_id}", response_model=ProjectOut)
def get_project(project_id: int, session: Session = Depends(get_session)):
    project = session.get(Project, project_id)
    if not project:
        raise HTTPException(404, "Project not found")
    return project_out(project)


@app.get("/api/projects/{project_id}/operations", response_model=list[OperationOut])
def get_operations(project_id: int, session: Session = Depends(get_session)):
    project = session.get(Project, project_id)
    if not project:
        raise HTTPException(404, "Project not found")
    parser = OpenApiParser.from_text(project.spec_text)
    return [OperationOut(
        method=op.method, path=op.path, summary=op.summary, tags=op.tags, security_required=op.security_required,
        parameters=[{"name": p.name, "in": p.location, "required": p.required, "schema": p.schema} for p in op.parameters],
        has_request_body=bool(op.request_schema),
    ) for op in parser.operations()]


@app.delete("/api/projects/{project_id}", status_code=204)
def delete_project(project_id: int, session: Session = Depends(get_session)):
    project = session.get(Project, project_id)
    if not project:
        raise HTTPException(404, "Project not found")
    session.delete(project)
    session.commit()
    return Response(status_code=204)


@app.post("/api/scans", response_model=ScanOut, status_code=202)
async def create_scan(data: ScanCreate, session: Session = Depends(get_session)):
    project = session.get(Project, data.project_id)
    if not project:
        raise HTTPException(404, "Project not found")
    try:
        validate_scope(data.base_url, set(data.allowed_hosts), data.authorization_ack)
    except ScopeError as exc:
        raise HTTPException(400, str(exc)) from exc
    config_public = {
        "allowed_hosts": data.allowed_hosts,
        "alternate_ids": data.alternate_ids,
        "allow_write_methods": data.allow_write_methods,
        "requests_per_second": data.requests_per_second,
        "max_requests": data.max_requests,
        "verify_tls": data.verify_tls,
        "bearer_token_provided": bool(data.bearer_token),
        "secondary_token_provided": bool(data.secondary_bearer_token),
        "extra_header_names": sorted(data.extra_headers.keys()),
    }
    scan = Scan(project_id=project.id, base_url=data.base_url, status="queued", profile="safe", config_json=json.dumps(config_public))
    session.add(scan)
    session.commit()
    session.refresh(scan)
    options = ScanOptions(
        base_url=data.base_url, bearer_token=data.bearer_token, secondary_bearer_token=data.secondary_bearer_token,
        extra_headers=data.extra_headers, allowed_hosts=set(data.allowed_hosts), alternate_ids=data.alternate_ids,
        allow_write_methods=data.allow_write_methods, requests_per_second=min(data.requests_per_second, settings.max_rps),
        max_requests=min(data.max_requests, 2000), timeout_seconds=data.timeout_seconds,
        authorization_ack=data.authorization_ack, verify_tls=data.verify_tls,
    )
    asyncio.create_task(run_scan_job(scan.id, options))
    return scan_out(scan)


@app.get("/api/scans", response_model=list[ScanOut])
def list_scans(session: Session = Depends(get_session)):
    scans = session.execute(select(Scan).order_by(desc(Scan.created_at))).scalars().all()
    return [scan_out(s) for s in scans]


@app.get("/api/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, session: Session = Depends(get_session)):
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan_out(scan)


@app.get("/api/scans/{scan_id}/findings", response_model=list[FindingOut])
def scan_findings(scan_id: int, session: Session = Depends(get_session)):
    if not session.get(Scan, scan_id):
        raise HTTPException(404, "Scan not found")
    findings = session.execute(select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.id)).scalars().all()
    return [finding_out(f) for f in findings]


@app.get("/api/findings", response_model=list[FindingOut])
def list_findings(severity: str | None = None, session: Session = Depends(get_session)):
    stmt = select(Finding).order_by(desc(Finding.created_at))
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    return [finding_out(f) for f in session.execute(stmt).scalars().all()]


@app.get("/api/reports/{scan_id}.json")
def report_json(scan_id: int, session: Session = Depends(get_session)):
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    project = session.get(Project, scan.project_id)
    findings = session.execute(select(Finding).where(Finding.scan_id == scan_id)).scalars().all()
    records = []
    from auditor.engine.models import FindingRecord
    for f in findings:
        records.append(FindingRecord(
            severity=f.severity, confidence=f.confidence, category=f.category, title=f.title,
            description=f.description, endpoint=f.endpoint, method=f.method,
            evidence=jloads(f.evidence_json, {}), remediation=f.remediation, owasp=f.owasp,
        ))
    config = jloads(scan.config_json, {})
    options = ScanOptions(base_url=scan.base_url, allowed_hosts=set(config.get("allowed_hosts", [])), authorization_ack=True,
                          allow_write_methods=bool(config.get("allow_write_methods")), requests_per_second=float(config.get("requests_per_second", 2)),
                          max_requests=int(config.get("max_requests", 250)))
    summary = ScanSummary(**{k: v for k, v in jloads(scan.stats_json, {}).items() if k in ScanSummary.__dataclass_fields__})
    payload = build_report_payload(records, summary, options, OpenApiParser.from_text(project.spec_text).info())
    return payload


@app.get("/api/reports/{scan_id}.html", response_class=Response)
def report_html(scan_id: int, session: Session = Depends(get_session)):
    payload = report_json(scan_id, session)
    return Response(render_html_report(payload), media_type="text/html")

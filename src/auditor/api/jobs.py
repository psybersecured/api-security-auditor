from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone

from auditor.db import Finding, Project, Scan, SessionLocal
from auditor.engine.models import ScanOptions
from auditor.engine.openapi import OpenApiParser
from auditor.engine.scanner import AuditScanner


async def run_scan_job(scan_id: int, options: ScanOptions) -> None:
    session = SessionLocal()
    try:
        scan = session.get(Scan, scan_id)
        if not scan:
            return
        project = session.get(Project, scan.project_id)
        if not project:
            scan.status = "failed"
            scan.error = "Project not found"
            session.commit()
            return
        scan.status = "running"
        scan.started_at = datetime.now(timezone.utc)
        session.commit()
        parser = OpenApiParser.from_text(project.spec_text)

        async def progress(percent, summary):
            scan.progress = percent
            scan.stats_json = json.dumps(asdict(summary))
            session.commit()

        scanner = AuditScanner(parser, options, progress=progress)
        findings, summary = await scanner.scan()
        for f in findings:
            session.add(Finding(
                scan_id=scan.id,
                severity=f.severity,
                confidence=f.confidence,
                category=f.category,
                title=f.title,
                description=f.description,
                endpoint=f.endpoint,
                method=f.method,
                evidence_json=json.dumps(f.evidence, ensure_ascii=False),
                remediation=f.remediation,
                owasp=f.owasp,
            ))
        scan.status = "completed"
        scan.progress = 100
        scan.stats_json = json.dumps(asdict(summary))
        scan.finished_at = datetime.now(timezone.utc)
        session.commit()
    except Exception as exc:
        scan = session.get(Scan, scan_id)
        if scan:
            scan.status = "failed"
            scan.error = f"{type(exc).__name__}: {exc}"
            scan.finished_at = datetime.now(timezone.utc)
            session.commit()
    finally:
        session.close()

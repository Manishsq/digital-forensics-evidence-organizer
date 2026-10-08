"""
Report generation service.

Generates printable HTML forensic evidence reports.
Reports are derived documents and are CLEARLY labelled as such.
They are NOT original evidence.
"""

import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader
from sqlalchemy.orm import Session, joinedload

from app.config import get_settings
from app.database.models import (
    Report,
    Evidence,
    Case,
    ChainOfCustody,
    AuditLog,
    EvidenceTag,
    AuditAction,
    gen_uuid,
)
from app.services.audit_service import record_audit
from app.services.custody_service import get_custody_events

settings = get_settings()


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def generate_report_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    short = uuid.uuid4().hex[:6].upper()
    return f"RPT-{ts}-{short}"


def generate_case_report(
    db: Session,
    case_id: str,
    generated_by: str,
    source_ip: Optional[str] = None,
) -> Report:
    """
    Generate a full case report including all evidence and their custody chains.
    Returns a Report model instance.  HTML is stored in reports directory.
    """
    case = db.query(Case).options(
        joinedload(Case.investigator_user),
        joinedload(Case.evidence_items).joinedload(Evidence.evidence_tags).joinedload(EvidenceTag.tag),
        joinedload(Case.evidence_items).joinedload(Evidence.creator),
    ).filter(Case.id == case_id).first()

    if case is None:
        raise ValueError(f"Case not found: {case_id}")

    evidence_items = (
        db.query(Evidence)
        .filter(Evidence.case_id == case_id)
        .order_by(Evidence.imported_timestamp.asc())
        .all()
    )

    evidence_with_custody = []
    for ev in evidence_items:
        events = get_custody_events(db, evidence_id=ev.id, limit=1000)
        tag_names = [et.tag.name for et in ev.evidence_tags] if ev.evidence_tags else []
        evidence_with_custody.append({
            "evidence": ev,
            "custody_events": events,
            "tags": tag_names,
        })

    now = utcnow()
    report_id = generate_report_id()

    # Build HTML
    html = _render_report_html(
        report_id=report_id,
        case=case,
        evidence_with_custody=evidence_with_custody,
        generated_at=now,
        generated_by_id=generated_by,
        db=db,
    )

    # Save HTML to disk
    reports_dir = settings.reports_storage_dir
    html_filename = f"{report_id}.html"
    html_path = reports_dir / html_filename
    html_path.write_text(html, encoding="utf-8")

    report = Report(
        id=gen_uuid(),
        report_id=report_id,
        case_id=case_id,
        title=f"Digital Forensics Evidence Report – {case.case_id}",
        report_type="CASE_REPORT",
        storage_path=str(html_path),
        generated_by=generated_by,
        generated_at=now,
    )
    db.add(report)

    record_audit(
        db=db,
        action=AuditAction.REPORT_GENERATED,
        user_id=generated_by,
        entity_type="case",
        entity_id=case_id,
        description=f"Generated case report {report_id} for case {case.case_id}.",
        source_ip=source_ip,
    )

    db.commit()
    db.refresh(report)
    return report


def generate_evidence_report(
    db: Session,
    evidence_id: str,
    generated_by: str,
    source_ip: Optional[str] = None,
) -> Report:
    """Generate a single-evidence report."""
    evidence = db.query(Evidence).options(
        joinedload(Evidence.case),
        joinedload(Evidence.creator),
        joinedload(Evidence.evidence_tags).joinedload(EvidenceTag.tag),
        joinedload(Evidence.metadata_entries),
    ).filter(Evidence.id == evidence_id).first()

    if evidence is None:
        raise ValueError(f"Evidence not found: {evidence_id}")

    custody_events = get_custody_events(db, evidence_id=evidence.id, limit=1000)
    tag_names = [et.tag.name for et in evidence.evidence_tags] if evidence.evidence_tags else []

    now = utcnow()
    report_id = generate_report_id()

    html = _render_evidence_report_html(
        report_id=report_id,
        evidence=evidence,
        custody_events=custody_events,
        tags=tag_names,
        generated_at=now,
        generated_by_id=generated_by,
        db=db,
    )

    reports_dir = settings.reports_storage_dir
    html_filename = f"{report_id}.html"
    html_path = reports_dir / html_filename
    html_path.write_text(html, encoding="utf-8")

    report = Report(
        id=gen_uuid(),
        report_id=report_id,
        case_id=evidence.case_id,
        evidence_id=evidence.id,
        title=f"Evidence Report – {evidence.evidence_id}",
        report_type="EVIDENCE_REPORT",
        storage_path=str(html_path),
        generated_by=generated_by,
        generated_at=now,
    )
    db.add(report)

    record_audit(
        db=db,
        action=AuditAction.REPORT_GENERATED,
        user_id=generated_by,
        entity_type="evidence",
        entity_id=evidence_id,
        description=f"Generated evidence report {report_id} for evidence {evidence.evidence_id}.",
        source_ip=source_ip,
    )

    db.commit()
    db.refresh(report)
    return report


def _fmt_dt(dt: Optional[datetime]) -> str:
    if dt is None:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _fmt_size(size: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def _render_report_html(
    report_id: str,
    case: Case,
    evidence_with_custody: list,
    generated_at: datetime,
    generated_by_id: str,
    db: Session,
) -> str:
    from app.database.models import User
    gen_user = db.get(User, generated_by_id)
    gen_name = gen_user.full_name if gen_user else "Unknown"

    ev_rows = ""
    for item in evidence_with_custody:
        ev = item["evidence"]
        tags_str = ", ".join(item["tags"]) or "—"
        status_cls = {
            "VERIFIED": "verified",
            "FAILED": "failed",
            "UNVERIFIED": "unverified",
        }.get(ev.verification_status.value, "unverified")

        custody_rows = "".join(
            f"<tr><td>{_fmt_dt(c.timestamp)}</td><td>{c.action.value}</td>"
            f"<td>{c.user_id[:8]}…</td><td>{c.description[:120]}</td></tr>"
            for c in item["custody_events"]
        )

        ev_rows += f"""
        <div class="evidence-block">
          <h3>{ev.evidence_id} — {ev.original_filename}</h3>
          <table class="meta-table">
            <tr><th>File Size</th><td>{_fmt_size(ev.file_size)}</td>
                <th>MIME Type</th><td>{ev.mime_type or '—'}</td></tr>
            <tr><th>Category</th><td>{ev.evidence_category.value}</td>
                <th>Verification</th><td class="status-{status_cls}">{ev.verification_status.value}</td></tr>
            <tr><th>Imported</th><td colspan="3">{_fmt_dt(ev.imported_timestamp)}</td></tr>
            <tr><th>SHA-256</th><td colspan="3" class="hash">{ev.sha256 or '—'}</td></tr>
            <tr><th>SHA-512</th><td colspan="3" class="hash">{ev.sha512 or '—'}</td></tr>
            <tr><th>MD5</th><td colspan="3" class="hash">{ev.md5 or '—'}</td></tr>
            <tr><th>Description</th><td colspan="3">{ev.description or '—'}</td></tr>
            <tr><th>Source</th><td>{ev.source or '—'}</td>
                <th>Tags</th><td>{tags_str}</td></tr>
          </table>
          <h4>Chain of Custody ({len(item['custody_events'])} events)</h4>
          <table class="custody-table">
            <thead><tr><th>Timestamp</th><th>Action</th><th>User</th><th>Description</th></tr></thead>
            <tbody>{custody_rows}</tbody>
          </table>
        </div>"""

    return _wrap_html(
        title=f"Digital Forensics Evidence Report – {case.case_id}",
        report_id=report_id,
        generated_at=generated_at,
        gen_name=gen_name,
        body=f"""
        <div class="report-notice">
          ⚠ This document is a GENERATED REPORT — it is NOT original evidence.
        </div>
        <section class="case-info">
          <h2>Case Information</h2>
          <table class="meta-table">
            <tr><th>Case ID</th><td>{case.case_id}</td>
                <th>Status</th><td>{case.status.value}</td></tr>
            <tr><th>Case Name</th><td>{case.name}</td>
                <th>Organization</th><td>{case.organization or '—'}</td></tr>
            <tr><th>Investigator</th><td>{case.investigator_user.full_name}</td>
                <th>Created</th><td>{_fmt_dt(case.created_at)}</td></tr>
            <tr><th>Description</th><td colspan="3">{case.description or '—'}</td></tr>
          </table>
        </section>
        <section class="evidence-section">
          <h2>Evidence Items ({len(evidence_with_custody)})</h2>
          {ev_rows}
        </section>""",
    )


def _render_evidence_report_html(
    report_id: str,
    evidence: Evidence,
    custody_events: list,
    tags: list,
    generated_at: datetime,
    generated_by_id: str,
    db: Session,
) -> str:
    from app.database.models import User
    gen_user = db.get(User, generated_by_id)
    gen_name = gen_user.full_name if gen_user else "Unknown"

    status_cls = {
        "VERIFIED": "verified",
        "FAILED": "failed",
        "UNVERIFIED": "unverified",
    }.get(evidence.verification_status.value, "unverified")

    custody_rows = "".join(
        f"<tr><td>{_fmt_dt(c.timestamp)}</td><td>{c.action.value}</td>"
        f"<td>{c.user_id[:8]}…</td><td>{c.description[:150]}</td>"
        f"<td class='hash-small'>{c.event_hash[:16]}…</td></tr>"
        for c in custody_events
    )

    meta_rows = ""
    if evidence.metadata_entries:
        for m in evidence.metadata_entries:
            meta_rows += f"<tr><th>{m.key}</th><td>{m.value}</td></tr>"

    return _wrap_html(
        title=f"Evidence Report – {evidence.evidence_id}",
        report_id=report_id,
        generated_at=generated_at,
        gen_name=gen_name,
        body=f"""
        <div class="report-notice">
          ⚠ This document is a GENERATED REPORT — it is NOT original evidence.
        </div>
        <section class="evidence-section">
          <h2>Evidence Details</h2>
          <table class="meta-table">
            <tr><th>Evidence ID</th><td>{evidence.evidence_id}</td>
                <th>Case ID</th><td>{evidence.case.case_id if evidence.case else '—'}</td></tr>
            <tr><th>Original Filename</th><td>{evidence.original_filename}</td>
                <th>Stored Filename</th><td>{evidence.stored_filename}</td></tr>
            <tr><th>File Size</th><td>{_fmt_size(evidence.file_size)}</td>
                <th>MIME Type</th><td>{evidence.mime_type or '—'}</td></tr>
            <tr><th>Category</th><td>{evidence.evidence_category.value}</td>
                <th>Verification</th><td class="status-{status_cls}">{evidence.verification_status.value}</td></tr>
            <tr><th>Imported At</th><td colspan="3">{_fmt_dt(evidence.imported_timestamp)}</td></tr>
            <tr><th>SHA-256</th><td colspan="3" class="hash">{evidence.sha256 or '—'}</td></tr>
            <tr><th>SHA-512</th><td colspan="3" class="hash">{evidence.sha512 or '—'}</td></tr>
            <tr><th>MD5</th><td colspan="3" class="hash">{evidence.md5 or '—'}</td></tr>
            <tr><th>Source</th><td>{evidence.source or '—'}</td>
                <th>Device</th><td>{evidence.device or '—'}</td></tr>
            <tr><th>Description</th><td colspan="3">{evidence.description or '—'}</td></tr>
            <tr><th>Tags</th><td colspan="3">{', '.join(tags) or '—'}</td></tr>
            <tr><th>Last Verified</th><td colspan="3">{_fmt_dt(evidence.last_verified_at)}</td></tr>
          </table>
          {'<h3>Extended Metadata</h3><table class="meta-table">' + meta_rows + '</table>' if meta_rows else ''}
        </section>
        <section>
          <h2>Chain of Custody ({len(custody_events)} events)</h2>
          <table class="custody-table">
            <thead><tr><th>Timestamp</th><th>Action</th><th>User</th><th>Description</th><th>Event Hash</th></tr></thead>
            <tbody>{custody_rows}</tbody>
          </table>
        </section>""",
    )


def _wrap_html(
    title: str,
    report_id: str,
    generated_at: datetime,
    gen_name: str,
    body: str,
) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
  body{{font-family:'Segoe UI',Arial,sans-serif;background:#f4f6fb;color:#1a2332;margin:0;padding:0}}
  .page{{max-width:1100px;margin:0 auto;background:#fff;padding:32px 48px;box-shadow:0 2px 12px rgba(0,0,0,.1)}}
  h1{{color:#0a1628;border-bottom:3px solid #1e40af;padding-bottom:8px;font-size:1.6rem}}
  h2{{color:#1e3a5f;border-left:4px solid #1e40af;padding-left:10px;margin-top:28px}}
  h3{{color:#1e3a5f;margin-top:18px}}
  h4{{color:#374151;margin-top:12px}}
  .report-notice{{background:#fff3cd;border:1px solid #ffc107;padding:12px 18px;
    border-radius:6px;color:#7d4a00;font-weight:600;margin-bottom:20px}}
  .meta-table{{width:100%;border-collapse:collapse;margin-bottom:16px;font-size:.9rem}}
  .meta-table th,.meta-table td{{border:1px solid #d1d5db;padding:7px 10px;text-align:left}}
  .meta-table th{{background:#f1f5f9;width:160px;font-weight:600;color:#374151}}
  .custody-table{{width:100%;border-collapse:collapse;font-size:.82rem;margin-bottom:16px}}
  .custody-table th,.custody-table td{{border:1px solid #d1d5db;padding:6px 8px;text-align:left}}
  .custody-table th{{background:#1e3a5f;color:#fff}}
  .custody-table tr:nth-child(even){{background:#f8fafc}}
  .hash{{font-family:monospace;font-size:.78rem;word-break:break-all;color:#1e3a5f}}
  .hash-small{{font-family:monospace;font-size:.75rem;color:#6b7280}}
  .status-verified{{color:#15803d;font-weight:700}}
  .status-failed{{color:#dc2626;font-weight:700}}
  .status-unverified{{color:#92400e;font-weight:600}}
  .evidence-block{{border:1px solid #d1d5db;border-radius:8px;padding:18px;margin-bottom:20px}}
  .report-header{{display:flex;justify-content:space-between;align-items:flex-start;
    background:#0a1628;color:#fff;padding:20px 28px;border-radius:6px;margin-bottom:24px}}
  .report-header .meta{{font-size:.82rem;color:#94a3b8;margin-top:6px}}
  .footer{{border-top:1px solid #e5e7eb;margin-top:32px;padding-top:12px;
    font-size:.78rem;color:#6b7280;text-align:center}}
  @media print{{body{{background:#fff}}.page{{box-shadow:none}}}}
</style>
</head>
<body>
<div class="page">
  <div class="report-header">
    <div>
      <h1 style="color:#fff;border:none;margin:0">{title}</h1>
      <div class="meta">Report ID: {report_id} | Generated: {_fmt_dt(generated_at)} | By: {gen_name}</div>
    </div>
    <div style="font-size:.8rem;color:#94a3b8;text-align:right">
      Digital Forensics<br>Evidence Organizer<br>v1.0.0
    </div>
  </div>
  {body}
  <div class="footer">
    Generated by Digital Forensics Evidence Organizer v1.0.0 —
    This is a DERIVED DOCUMENT and NOT original evidence.
    Report ID: {report_id} | {_fmt_dt(generated_at)}
  </div>
</div>
</body>
</html>"""

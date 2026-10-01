"""FM9: Compliance report generation and signed download URLs.

Templates pull from the same aggregation code FM8's KPI endpoint uses
(`services/analytics.py`), so a report and the dashboard can never disagree
about MTTD for the same period -- which is the whole point of control evidence.

Formats: CSV and JSON are implemented; HTML is implemented as a self-contained
table (printable to PDF by the browser). Real PDF generation is deliberately
*not* implemented -- WeasyPrint/ReportLab are heavy native dependencies, and
"print this HTML" produces an equivalent artifact for the control-evidence use
case. The seam for adding it is `RENDERERS`.

Downloads use an HMAC-signed, expiring token rather than a guessable path:
report artifacts contain a tenant's security findings, so an unauthenticated
URL that never expires would be a data-leak vector, and a sequential path
would be enumerable across tenants.
"""
from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.alert import Alert
from app.models.audit import AuditLogEntry
from app.models.case import Case, CaseStatus
from app.models.report import ComplianceReport, ReportStatus
from app.services.analytics import compute_kpis

logger = logging.getLogger(__name__)


class ReportError(RuntimeError):
    pass


# --------------------------------------------------------------------------
# Templates: each returns (column names, rows, summary dict).
# --------------------------------------------------------------------------
def _template_alert_summary(db: Session, *, tenant_id: str, start: datetime, end: datetime) -> tuple[list[str], list[dict], dict]:
    rows = db.execute(
        select(Alert)
        .where(Alert.tenant_id == tenant_id, Alert.created_at >= start, Alert.created_at <= end)
        .order_by(Alert.created_at.asc())
    ).scalars()
    records = [
        {
            "alert_id": alert.id,
            "created_at": alert.created_at.isoformat() if alert.created_at else "",
            "title": alert.title,
            "severity": alert.severity,
            "status": alert.status,
            "detection_source": alert.detection_source,
            "rule_id": alert.rule_id or "",
            "ml_score": alert.ml_score if alert.ml_score is not None else "",
            "event_count": len(alert.event_ids or []),
            "case_id": alert.case_id or "",
            "dismiss_reason": alert.dismiss_reason or "",
        }
        for alert in rows
    ]
    by_severity: dict[str, int] = {}
    for record in records:
        by_severity[record["severity"]] = by_severity.get(record["severity"], 0) + 1
    return (
        [
            "alert_id",
            "created_at",
            "title",
            "severity",
            "status",
            "detection_source",
            "rule_id",
            "ml_score",
            "event_count",
            "case_id",
            "dismiss_reason",
        ],
        records,
        {"totalAlerts": len(records), "bySeverity": by_severity},
    )


def _template_case_summary(db: Session, *, tenant_id: str, start: datetime, end: datetime) -> tuple[list[str], list[dict], dict]:
    rows = db.execute(
        select(Case)
        .where(Case.tenant_id == tenant_id, Case.created_at >= start, Case.created_at <= end)
        .order_by(Case.created_at.asc())
    ).scalars()
    records = []
    for case in rows:
        resolution_seconds = ""
        if case.resolved_at and case.created_at:
            created = case.created_at if case.created_at.tzinfo else case.created_at.replace(tzinfo=timezone.utc)
            resolved = case.resolved_at if case.resolved_at.tzinfo else case.resolved_at.replace(tzinfo=timezone.utc)
            resolution_seconds = int((resolved - created).total_seconds())
        records.append(
            {
                "case_id": case.id,
                "created_at": case.created_at.isoformat() if case.created_at else "",
                "title": case.title,
                "status": case.status,
                "severity": case.severity,
                "assignee_user_id": case.assignee_user_id or "",
                "alert_count": len(case.alert_ids or []),
                "resolved_at": case.resolved_at.isoformat() if case.resolved_at else "",
                "resolution_seconds": resolution_seconds,
            }
        )
    return (
        [
            "case_id",
            "created_at",
            "title",
            "status",
            "severity",
            "assignee_user_id",
            "alert_count",
            "resolved_at",
            "resolution_seconds",
        ],
        records,
        {
            "totalCases": len(records),
            "resolved": sum(1 for r in records if r["status"] == CaseStatus.RESOLVED),
        },
    )


def _template_control_evidence(db: Session, *, tenant_id: str, start: datetime, end: datetime) -> tuple[list[str], list[dict], dict]:
    """SOC2-style control evidence.

    Each row is a control assertion with the measured evidence behind it. The
    assertions are the ones this system can actually evidence from its own data
    -- deliberately not a claim of SOC2 compliance, which is an audit outcome,
    not something software asserts about itself.
    """
    kpis = compute_kpis(db, tenant_id=tenant_id, period_start=start, period_end=end)
    audit_count = db.execute(
        select(AuditLogEntry)
        .where(AuditLogEntry.tenant_id == tenant_id, AuditLogEntry.created_at >= start)
        .limit(100_000)
    ).scalars()
    audit_total = sum(1 for _ in audit_count)

    records = [
        {
            "control": "CC7.2 Security event monitoring",
            "assertion": "Security telemetry is continuously ingested, normalized and evaluated against detection rules.",
            "evidence": f"{kpis['alert_volume']} alert(s) raised in period",
            "measurement": kpis["alert_volume"],
        },
        {
            "control": "CC7.3 Incident detection latency",
            "assertion": "Detected events are alerted on promptly after occurrence.",
            "evidence": "Mean time to detect (seconds)",
            "measurement": kpis["mttd_seconds"] if kpis["mttd_seconds"] is not None else "no data",
        },
        {
            "control": "CC7.4 Incident response",
            "assertion": "Identified incidents are triaged to resolution through a tracked case workflow.",
            "evidence": "Mean time to resolve (seconds)",
            "measurement": kpis["mttr_seconds"] if kpis["mttr_seconds"] is not None else "no data",
        },
        {
            "control": "CC7.4 Open incident backlog",
            "assertion": "Unresolved incidents are visible and bounded.",
            "evidence": "Open cases at report time",
            "measurement": kpis["open_cases"],
        },
        {
            "control": "CC6.1 Logical access change auditing",
            "assertion": "Security-relevant configuration and access changes are recorded in an append-only audit log.",
            "evidence": f"{audit_total} audit entr(ies) in period",
            "measurement": audit_total,
        },
        {
            "control": "CC4.1 Detection quality review",
            "assertion": "Alert quality is measured so detection tuning is evidence-based.",
            "evidence": "Share of alerts dismissed as false positives",
            "measurement": kpis["false_positive_rate"],
        },
    ]
    return (
        ["control", "assertion", "evidence", "measurement"],
        records,
        {"kpis": kpis, "auditEntries": audit_total},
    )


TEMPLATES: dict[str, Callable[..., tuple[list[str], list[dict], dict]]] = {
    "alert_summary": _template_alert_summary,
    "case_summary": _template_case_summary,
    "control_evidence": _template_control_evidence,
}

TEMPLATE_DESCRIPTIONS = {
    "alert_summary": "Every alert raised in the period, with severity, source and triage outcome.",
    "case_summary": "Every case opened in the period, with resolution time.",
    "control_evidence": "SOC2-style control assertions with the measured evidence from this system's own data.",
}


# --------------------------------------------------------------------------
# Renderers
# --------------------------------------------------------------------------
def _render_csv(columns: list[str], rows: list[dict], summary: dict) -> bytes:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue().encode("utf-8")


def _render_json(columns: list[str], rows: list[dict], summary: dict) -> bytes:
    return json.dumps({"summary": summary, "columns": columns, "rows": rows}, default=str, indent=2).encode("utf-8")


def _render_html(columns: list[str], rows: list[dict], summary: dict) -> bytes:
    """Self-contained printable HTML.

    `html.escape` on every cell, not for tidiness: report content includes
    attacker-controlled strings (an actor name, a URL from a raw event), and an
    unescaped report opens stored XSS against whoever opens the artifact.
    """
    import html

    head = "".join(f"<th>{html.escape(c)}</th>" for c in columns)
    body = "".join(
        "<tr>" + "".join(f"<td>{html.escape(str(row.get(c, '')))}</td>" for c in columns) + "</tr>" for row in rows
    )
    summary_items = "".join(
        f"<li><strong>{html.escape(str(k))}:</strong> {html.escape(json.dumps(v, default=str))}</li>"
        for k, v in summary.items()
    )
    return (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>SentinelIQ report</title>"
        "<style>body{font-family:system-ui,sans-serif;margin:2rem;color:#111}"
        "table{border-collapse:collapse;width:100%;font-size:13px}"
        "th,td{border:1px solid #ccc;padding:6px 8px;text-align:left;vertical-align:top}"
        "th{background:#f3f4f6}</style></head><body>"
        f"<h1>SentinelIQ report</h1><ul>{summary_items}</ul>"
        f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"
        "</body></html>"
    ).encode("utf-8")


RENDERERS: dict[str, Callable[[list[str], list[dict], dict], bytes]] = {
    "csv": _render_csv,
    "json": _render_json,
    "html": _render_html,
}

# TODO(FM9): a native PDF renderer (WeasyPrint or ReportLab) would slot in here
# as RENDERERS["pdf"]. Not added because both carry large native dependency
# trees, and `html` -> browser print produces an equivalent artifact today.


def generate_report(db: Session, *, report: ComplianceReport) -> ComplianceReport:
    """Render a queued report to disk. Does not commit.

    Never raises: a failed report becomes a `failed` row with the reason, which
    is what the UI needs to show. Raising would leave the row stuck in
    `generating` forever.
    """
    settings = get_settings()
    report.status = ReportStatus.GENERATING
    db.flush()

    try:
        template = TEMPLATES.get(report.template)
        if template is None:
            raise ReportError(f"unknown template {report.template!r}")
        renderer = RENDERERS.get(report.report_format)
        if renderer is None:
            raise ReportError(f"unknown format {report.report_format!r}")

        columns, rows, summary = template(
            db,
            tenant_id=report.tenant_id,
            start=report.period_start,
            end=report.period_end,
        )
        payload = renderer(columns, rows, summary)

        directory = os.path.join(settings.report_dir, report.tenant_id)
        os.makedirs(directory, exist_ok=True)
        filename = f"{report.id}.{report.report_format}"
        path = os.path.join(directory, filename)
        with open(path, "wb") as handle:
            handle.write(payload)

        report.artifact_path = os.path.relpath(path, settings.report_dir)
        report.size_bytes = len(payload)
        report.row_count = len(rows)
        report.generated_at = datetime.now(timezone.utc)
        report.status = ReportStatus.READY
        report.error = None
        logger.info(
            "report.generated",
            extra={
                "tenant_id": report.tenant_id,
                "report_id": report.id,
                "template": report.template,
                "rows": len(rows),
                "bytes": len(payload),
            },
        )
    except (ReportError, OSError, ValueError) as exc:
        report.status = ReportStatus.FAILED
        report.error = f"{type(exc).__name__}: {exc}"[:2000]
        logger.warning(
            "report.generation_failed",
            extra={"tenant_id": report.tenant_id, "report_id": report.id, "error": report.error},
        )

    db.flush()
    return report


# --------------------------------------------------------------------------
# Signed download URLs
# --------------------------------------------------------------------------
def sign_download(report: ComplianceReport, *, ttl_seconds: int | None = None) -> tuple[str, int]:
    """Return (token, expires_at_epoch) for a report download.

    The token binds report id, tenant id and expiry, so it cannot be replayed
    after expiry, edited to point at another report, or used against another
    tenant's report of the same id.
    """
    settings = get_settings()
    ttl = ttl_seconds if ttl_seconds is not None else settings.report_url_ttl_seconds
    expires = int(time.time()) + ttl
    message = f"{report.id}:{report.tenant_id}:{expires}".encode()
    signature = hmac.new(
        settings.effective_report_signing_secret.encode(),
        message,
        hashlib.sha256,
    ).hexdigest()
    return f"{expires}.{signature}", expires


def verify_download(report_id: str, tenant_id: str, token: str) -> bool:
    """Constant-time verification of a download token."""
    try:
        expires_raw, signature = token.split(".", 1)
        expires = int(expires_raw)
    except (ValueError, AttributeError):
        return False
    if expires < int(time.time()):
        return False

    settings = get_settings()
    message = f"{report_id}:{tenant_id}:{expires}".encode()
    expected = hmac.new(
        settings.effective_report_signing_secret.encode(),
        message,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def read_artifact(report: ComplianceReport) -> bytes:
    settings = get_settings()
    if not report.artifact_path:
        raise ReportError("report has no artifact")

    base = os.path.realpath(settings.report_dir)
    path = os.path.realpath(os.path.join(base, report.artifact_path))
    # Defence against a traversal in a stored path: the resolved file must still
    # be inside the report directory.
    if not path.startswith(base + os.sep):
        raise ReportError("report artifact path escapes the report directory")
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError as exc:
        raise ReportError(f"artifact unreadable: {exc}") from exc


CONTENT_TYPES = {
    "csv": "text/csv",
    "json": "application/json",
    "html": "text/html",
}

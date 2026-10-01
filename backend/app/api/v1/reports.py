"""FM9: Compliance reporting API.

Generation is synchronous today but modelled as a job (`status` transitions
queued -> generating -> ready/failed), so moving it onto the worker is a matter
of publishing to the queue instead of calling `generate_report` inline -- no API
or client change. That tradeoff is stated rather than hidden: for the report
sizes this system produces, inline generation is fine; for a 90-day export over
a high-volume tenant it is not, and the seam is `create_report` below.

Downloads use a short-lived HMAC-signed token instead of session auth, so the
URL can be handed to a browser download or an email without being a permanent,
unauthenticated handle on a tenant's security findings.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.core.deps import client_ip, get_current_user, require_role
from app.db.session import get_db
from app.models.report import ComplianceReport, ReportStatus
from app.models.user import Role, User
from app.schemas.report import ReportCreate, ReportListResponse, ReportOut, ReportTemplateOut
from app.services.audit import record_audit
from app.services.reports import (
    CONTENT_TYPES,
    RENDERERS,
    TEMPLATE_DESCRIPTIONS,
    ReportError,
    generate_report,
    read_artifact,
    sign_download,
    verify_download,
)

router = APIRouter(prefix="/reports", tags=["reports"])


def _with_download(report: ComplianceReport) -> ReportOut:
    out = ReportOut.model_validate(report)
    if report.status == ReportStatus.READY:
        token, expires = sign_download(report)
        out.download_url = f"/v1/reports/{report.id}/download?token={token}"
        out.download_expires_at = datetime.fromtimestamp(expires, tz=timezone.utc)
    return out


def _get_owned_report(db: Session, current_user: User, report_id: str) -> ComplianceReport:
    report = db.get(ComplianceReport, report_id)
    if report is None or report.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")
    return report


@router.get("/templates", response_model=list[ReportTemplateOut])
def list_templates(current_user: User = Depends(get_current_user)) -> list[ReportTemplateOut]:
    return [
        ReportTemplateOut(name=name, description=description, formats=sorted(RENDERERS))
        for name, description in sorted(TEMPLATE_DESCRIPTIONS.items())
    ]


@router.get("", response_model=ReportListResponse)
def list_reports(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ReportListResponse:
    query = db.query(ComplianceReport).filter(ComplianceReport.tenant_id == current_user.tenant_id)
    total = query.count()
    rows = (
        query.order_by(ComplianceReport.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return ReportListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[_with_download(row) for row in rows],
    )


@router.post("", response_model=ReportOut, status_code=status.HTTP_201_CREATED)
def create_report(
    payload: ReportCreate,
    request: Request,
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> ReportOut:
    end = payload.period_end or datetime.now(timezone.utc)
    start = payload.period_start or (end - timedelta(days=payload.days))
    if start >= end:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "periodStart must be before periodEnd")

    report = ComplianceReport(
        tenant_id=current_user.tenant_id,
        template=payload.template,
        report_format=payload.report_format,
        status=ReportStatus.QUEUED,
        period_start=start,
        period_end=end,
        parameters=payload.parameters,
        requested_by_user_id=current_user.id,
    )
    db.add(report)
    db.flush()

    generate_report(db, report=report)

    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="report.generated",
        target_type="report",
        target_id=report.id,
        detail={
            "template": report.template,
            "format": report.report_format,
            "status": report.status,
            "rows": report.row_count,
        },
        ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(report)
    return _with_download(report)


@router.get("/{report_id}", response_model=ReportOut)
def get_report(
    report_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ReportOut:
    return _with_download(_get_owned_report(db, current_user, report_id))


@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def delete_report(
    report_id: str,
    request: Request,
    current_user: User = Depends(require_role(Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> None:
    import os

    from app.core.config import get_settings

    report = _get_owned_report(db, current_user, report_id)
    if report.artifact_path:
        # Remove the artifact too -- leaving orphaned files containing a
        # tenant's findings on disk after the user deleted the report would be a
        # surprising data-retention outcome.
        try:
            base = os.path.realpath(get_settings().report_dir)
            path = os.path.realpath(os.path.join(base, report.artifact_path))
            if path.startswith(base + os.sep) and os.path.exists(path):
                os.remove(path)
        except OSError:
            # The row still goes; a stranded file is not worth failing the call.
            pass

    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="report.deleted",
        target_type="report",
        target_id=report.id,
        detail={"template": report.template},
        ip_address=client_ip(request),
    )
    db.delete(report)
    db.commit()


@router.get("/{report_id}/download")
def download_report(
    report_id: str,
    token: str = Query(...),
    db: Session = Depends(get_db),
) -> Response:
    """Download a report artifact with a signed, expiring token.

    Deliberately not session-authenticated: this URL is meant to be openable by
    a browser or a download manager that will not carry an Authorization header.
    The token is the credential, and it binds report id + tenant id + expiry, so
    it cannot be edited to reach another report or replayed after expiry.

    A bad or expired token returns 404, not 403 -- the existence of a report id
    is itself tenant information.
    """
    report = db.get(ComplianceReport, report_id)
    if report is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")
    if not verify_download(report.id, report.tenant_id, token):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not found")
    if report.status != ReportStatus.READY:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Report is {report.status}, not ready")

    try:
        payload = read_artifact(report)
    except ReportError as exc:
        raise HTTPException(status.HTTP_410_GONE, str(exc)) from exc

    filename = f"sentineliq-{report.template}-{report.id}.{report.report_format}"
    return Response(
        content=payload,
        media_type=CONTENT_TYPES.get(report.report_format, "application/octet-stream"),
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            # A report is a point-in-time artifact, but it is also tenant data;
            # no shared cache should hold it.
            "Cache-Control": "private, no-store",
        },
    )

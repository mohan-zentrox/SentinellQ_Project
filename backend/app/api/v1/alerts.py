"""FM4/FM6: Alert listing, triage, and promotion into a Case.

Triage (`PATCH /v1/alerts/{id}`) is the endpoint that was missing: `Alert.status`
has always supported `dismissed`, but nothing could set it, so FM8's
false-positive rate was structurally pinned at 0.0 no matter how many false
positives a tenant actually had. Dismissing an alert here is what feeds that
metric.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.core.deps import client_ip, get_current_user, require_role
from app.db.session import get_db
from app.models.alert import Alert
from app.models.case import Case, CaseTimelineEntry
from app.models.user import Role, User
from app.schemas.alert import (
    AlertBulkUpdateRequest,
    AlertBulkUpdateResponse,
    AlertDetailOut,
    AlertListResponse,
    AlertOut,
    AlertUpdateRequest,
    PromoteAlertsRequest,
)
from app.schemas.case import CaseOut
from app.services.audit import record_audit
from app.services.telemetry_store import get_telemetry_store

router = APIRouter(prefix="/alerts", tags=["alerts"])

_SEVERITY_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _severity_rank(severity: str) -> int:
    return _SEVERITY_ORDER.get(severity, 0)


def _get_owned_alert(db: Session, current_user: User, alert_id: str) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None or alert.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    return alert


@router.get("", response_model=AlertListResponse)
def list_alerts(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    alert_status: str | None = Query(default=None, alias="status", pattern="^(open|dismissed|promoted)$"),
    severity: str | None = Query(default=None, pattern="^(informational|low|medium|high|critical)$"),
    detection_source: str | None = Query(default=None, alias="detectionSource", pattern="^(rule|ml|manual)$"),
    rule_id: str | None = Query(default=None, alias="ruleId"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AlertListResponse:
    query = db.query(Alert).filter(Alert.tenant_id == current_user.tenant_id)
    if alert_status:
        query = query.filter(Alert.status == alert_status)
    if severity:
        query = query.filter(Alert.severity == severity)
    if detection_source:
        query = query.filter(Alert.detection_source == detection_source)
    if rule_id:
        query = query.filter(Alert.rule_id == rule_id)

    total = query.count()
    rows = (
        query.order_by(Alert.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return AlertListResponse(
        total=total, page=page, page_size=page_size, items=[AlertOut.model_validate(r) for r in rows]
    )


@router.get("/{alert_id}", response_model=AlertDetailOut)
def get_alert(
    alert_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AlertDetailOut:
    """Alert detail, with the contributing events and their threat-intel
    enrichment inlined.

    An analyst judging an alert needs the evidence, and making them issue N
    follow-up requests for N contributing events is the difference between a
    usable triage screen and a frustrating one.
    """
    alert = _get_owned_alert(db, current_user, alert_id)
    store = get_telemetry_store()
    events = store.get_events(db, tenant_id=current_user.tenant_id, event_ids=(alert.event_ids or [])[:50])

    detail = AlertDetailOut.model_validate(alert)
    detail.events = [
        {
            "id": event.id,
            "source": event.source,
            "eventCategory": event.event_category,
            "eventAction": event.event_action,
            "severityHint": event.severity_hint,
            "actor": event.actor,
            "target": event.target,
            "sourceIp": event.source_ip,
            "enrichment": event.enrichment,
            "occurredAt": event.occurred_at,
        }
        for event in events
    ]
    return detail


def _apply_triage(
    db: Session,
    *,
    alert: Alert,
    new_status: str,
    reason: str | None,
    current_user: User,
) -> None:
    now = datetime.now(timezone.utc)
    if new_status == "dismissed":
        alert.status = "dismissed"
        alert.dismissed_at = now
        alert.dismissed_by_user_id = current_user.id
        alert.dismiss_reason = reason
    else:
        alert.status = "open"
        alert.dismissed_at = None
        alert.dismissed_by_user_id = None
        alert.dismiss_reason = None


@router.patch("/{alert_id}", response_model=AlertOut)
def update_alert(
    alert_id: str,
    payload: AlertUpdateRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> Alert:
    """Dismiss an alert as a false positive, or reopen a dismissal.

    A promoted alert cannot be dismissed: it is already evidence attached to a
    case, and silently detaching it would leave the case citing an alert its
    analyst can no longer see in the queue. Resolve or reopen the case instead.
    """
    alert = _get_owned_alert(db, current_user, alert_id)
    if alert.status == "promoted":
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Alert is already promoted to case {alert.case_id}; triage the case instead",
        )

    _apply_triage(db, alert=alert, new_status=payload.status, reason=payload.reason, current_user=current_user)
    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action=f"alert.{payload.status}",
        target_type="alert",
        target_id=alert.id,
        detail={"reason": payload.reason, "severity": alert.severity},
        ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(alert)
    return alert


@router.patch("", response_model=AlertBulkUpdateResponse)
def bulk_update_alerts(
    payload: AlertBulkUpdateRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> AlertBulkUpdateResponse:
    """Triage many alerts at once.

    Real triage is bulk work -- a noisy rule produces dozens of identical false
    positives, and dismissing them one request at a time is why analysts stop
    dismissing them at all (which is exactly what made the FP-rate metric
    useless). Promoted alerts in the selection are skipped rather than failing
    the whole call.
    """
    alerts = (
        db.query(Alert)
        .filter(
            Alert.id.in_(payload.alert_ids),
            Alert.tenant_id == current_user.tenant_id,
            Alert.status != "promoted",
        )
        .all()
    )
    for alert in alerts:
        _apply_triage(db, alert=alert, new_status=payload.status, reason=payload.reason, current_user=current_user)

    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action=f"alert.bulk_{payload.status}",
        target_type="alert",
        target_id=None,
        detail={"count": len(alerts), "requested": len(payload.alert_ids), "reason": payload.reason},
        ip_address=client_ip(request),
    )
    db.commit()
    return AlertBulkUpdateResponse(updated=len(alerts), alert_ids=[a.id for a in alerts])


@router.post("/promote", response_model=CaseOut, status_code=status.HTTP_201_CREATED)
def promote_alerts_to_case(
    payload: PromoteAlertsRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> Case:
    """FM6: promote alert(s) to a Case. Every alert must belong to the
    caller's own tenant -- this is one of the cross-tenant isolation
    guarantees covered by backend/tests/test_tenant_isolation.py."""
    alerts = (
        db.query(Alert)
        .filter(Alert.id.in_(payload.alert_ids), Alert.tenant_id == current_user.tenant_id)
        .all()
    )
    found_ids = {a.id for a in alerts}
    missing = set(payload.alert_ids) - found_ids
    if missing:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Alert(s) not found in this tenant: {sorted(missing)}")

    already_promoted = [a.id for a in alerts if a.status == "promoted"]
    if already_promoted:
        # Promoting the same alert into a second case would silently reassign it,
        # leaving the first case citing evidence that now points elsewhere.
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Alert(s) already promoted to a case: {sorted(already_promoted)}",
        )

    severity = max((a.severity for a in alerts), key=_severity_rank, default="medium")
    case = Case(
        tenant_id=current_user.tenant_id,
        title=payload.title,
        description=payload.description,
        severity=severity,
        alert_ids=sorted(found_ids),
    )
    db.add(case)
    db.flush()

    db.add(
        CaseTimelineEntry(
            tenant_id=current_user.tenant_id,
            case_id=case.id,
            entry_type="created",
            message=f"Case created from {len(alerts)} alert(s).",
            actor_user_id=current_user.id,
        )
    )
    for alert in alerts:
        alert.status = "promoted"
        alert.case_id = case.id

    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="case.created_from_alerts",
        target_type="case",
        target_id=case.id,
        detail={"alert_count": len(alerts), "severity": severity},
        ip_address=client_ip(request),
    )
    db.commit()
    db.refresh(case)
    return case

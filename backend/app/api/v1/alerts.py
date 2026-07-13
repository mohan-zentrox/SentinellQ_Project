"""FM4/FM6: Alert listing + promotion of one or more alerts into a Case."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.deps import get_current_user, require_role
from app.db.session import get_db
from app.models.alert import Alert
from app.models.case import Case, CaseTimelineEntry
from app.models.user import Role, User
from app.schemas.alert import AlertListResponse, AlertOut, PromoteAlertsRequest
from app.schemas.case import CaseOut

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=AlertListResponse)
def list_alerts(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AlertListResponse:
    query = db.query(Alert).filter(Alert.tenant_id == current_user.tenant_id)
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


@router.get("/{alert_id}", response_model=AlertOut)
def get_alert(alert_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None or alert.tenant_id != current_user.tenant_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found")
    return alert


@router.post("/promote", response_model=CaseOut, status_code=status.HTTP_201_CREATED)
def promote_alerts_to_case(
    payload: PromoteAlertsRequest,
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

    severity = max((a.severity for a in alerts), key=_severity_rank, default="medium")
    case = Case(
        tenant_id=current_user.tenant_id,
        title=payload.title,
        description=payload.description,
        severity=severity,
        alert_ids=list(found_ids),
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

    db.commit()
    db.refresh(case)
    return case


_SEVERITY_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _severity_rank(severity: str) -> int:
    return _SEVERITY_ORDER.get(severity, 0)

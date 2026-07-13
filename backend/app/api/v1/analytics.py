"""FM8 (aggregations part): tenant-scoped KPI aggregation.

- alertVolume: count of alerts raised in the period.
- falsePositiveRate: placeholder until analyst feedback / ML confidence
  scoring exists (FM8 full scope + C8 ML scaffold) -- computed here as the
  share of alerts explicitly marked "dismissed", defaulting to 0.0 when
  there's no dismissal data yet, and clearly documented as a placeholder
  metric, not a validated false-positive model.
- mttdSeconds: mean time-to-detect = avg(alert.created_at - earliest
  contributing event.occurred_at), across alerts in the period.
- mttrSeconds: mean time-to-resolve = avg(resolved_at - created_at) for
  cases resolved in the period, derived from CaseTimelineEntry timestamps.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.deps import get_current_user
from app.db.session import get_db
from app.models.alert import Alert
from app.models.case import Case, CaseStatus
from app.models.event import Event
from app.models.user import User
from app.schemas.analytics import KPIResponse

router = APIRouter(prefix="/analytics", tags=["analytics"])


@router.get("/kpis", response_model=KPIResponse)
def get_kpis(
    days: int = Query(default=30, ge=1, le=365),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> KPIResponse:
    period_end = datetime.now(timezone.utc)
    period_start = period_end - timedelta(days=days)

    alerts = (
        db.query(Alert)
        .filter(
            Alert.tenant_id == current_user.tenant_id,
            Alert.created_at >= period_start,
            Alert.created_at <= period_end,
        )
        .all()
    )
    alert_volume = len(alerts)

    dismissed = sum(1 for a in alerts if a.status == "dismissed")
    false_positive_rate = (dismissed / alert_volume) if alert_volume else 0.0

    # MTTD: for each alert, look up the earliest occurred_at among its
    # contributing events and diff against the alert's created_at.
    mttd_samples: list[float] = []
    for alert in alerts:
        if not alert.event_ids:
            continue
        earliest = (
            db.query(Event.occurred_at)
            .filter(Event.tenant_id == current_user.tenant_id, Event.id.in_(alert.event_ids))
            .order_by(Event.occurred_at.asc())
            .first()
        )
        if earliest is None:
            continue
        occurred_at = earliest[0]
        if occurred_at.tzinfo is None:
            occurred_at = occurred_at.replace(tzinfo=timezone.utc)
        created_at = alert.created_at if alert.created_at.tzinfo else alert.created_at.replace(tzinfo=timezone.utc)
        delta = (created_at - occurred_at).total_seconds()
        if delta >= 0:
            mttd_samples.append(delta)
    mttd_seconds = (sum(mttd_samples) / len(mttd_samples)) if mttd_samples else None

    resolved_cases = (
        db.query(Case)
        .filter(
            Case.tenant_id == current_user.tenant_id,
            Case.status == CaseStatus.RESOLVED,
            Case.resolved_at.isnot(None),
            Case.resolved_at >= period_start,
            Case.resolved_at <= period_end,
        )
        .all()
    )
    mttr_samples: list[float] = []
    for case in resolved_cases:
        created_at = case.created_at if case.created_at.tzinfo else case.created_at.replace(tzinfo=timezone.utc)
        resolved_at = case.resolved_at if case.resolved_at.tzinfo else case.resolved_at.replace(tzinfo=timezone.utc)
        delta = (resolved_at - created_at).total_seconds()
        if delta >= 0:
            mttr_samples.append(delta)
    mttr_seconds = (sum(mttr_samples) / len(mttr_samples)) if mttr_samples else None

    open_cases = (
        db.query(Case)
        .filter(Case.tenant_id == current_user.tenant_id, Case.status != CaseStatus.RESOLVED)
        .count()
    )

    return KPIResponse(
        period_start=period_start,
        period_end=period_end,
        alert_volume=alert_volume,
        false_positive_rate=round(false_positive_rate, 4),
        mttd_seconds=mttd_seconds,
        mttr_seconds=mttr_seconds,
        open_cases=open_cases,
        resolved_cases=len(resolved_cases),
    )

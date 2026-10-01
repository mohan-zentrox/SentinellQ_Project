"""FM8: tenant-scoped analytics endpoints.

The aggregation arithmetic lives in `app/services/analytics.py` so FM9's
compliance reports compute identical numbers from identical code -- see that
module for the metric definitions and the timezone-coercion rationale.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.deps import get_current_user
from app.db.session import get_db
from app.models.rule import DetectionRule
from app.models.user import User
from app.schemas.analytics import (
    AlertTimeseriesResponse,
    DetectionCoverageResponse,
    KPIResponse,
    TimeseriesBucket,
)
from app.services.analytics import alert_volume_timeseries, compute_kpis

router = APIRouter(prefix="/analytics", tags=["analytics"])


def _period(days: int) -> tuple[datetime, datetime]:
    end = datetime.now(timezone.utc)
    return end - timedelta(days=days), end


@router.get("/kpis", response_model=KPIResponse)
def get_kpis(
    days: int = Query(default=30, ge=1, le=365),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> KPIResponse:
    start, end = _period(days)
    return KPIResponse(**compute_kpis(db, tenant_id=current_user.tenant_id, period_start=start, period_end=end))


@router.get("/alerts/timeseries", response_model=AlertTimeseriesResponse)
def get_alert_timeseries(
    days: int = Query(default=14, ge=1, le=365),
    bucket_hours: int = Query(default=24, ge=1, le=168, alias="bucketHours"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> AlertTimeseriesResponse:
    """Bucketed alert volume for the dashboard trend chart."""
    start, end = _period(days)
    buckets = alert_volume_timeseries(
        db,
        tenant_id=current_user.tenant_id,
        period_start=start,
        period_end=end,
        bucket_hours=bucket_hours,
    )
    return AlertTimeseriesResponse(
        period_start=start,
        period_end=end,
        bucket_hours=bucket_hours,
        buckets=[TimeseriesBucket(**bucket) for bucket in buckets],
    )


@router.get("/detection-coverage", response_model=DetectionCoverageResponse)
def get_detection_coverage(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DetectionCoverageResponse:
    """Which rules are producing findings, and which have never fired.

    A rule that has never matched is either mis-authored or covers a threat this
    tenant has not seen. Both are actionable and the distinction matters, so this
    reports the raw fact rather than guessing which it is.
    """
    rules = list(
        db.execute(select(DetectionRule).where(DetectionRule.tenant_id == current_user.tenant_id)).scalars()
    )
    enabled = [rule for rule in rules if rule.is_enabled]
    with_matches = [rule for rule in rules if (rule.match_count or 0) > 0]

    never_matched = [
        {
            "ruleId": rule.id,
            "name": rule.name,
            "severity": rule.severity,
            "isEnabled": rule.is_enabled,
            "lastEvaluatedAt": rule.last_evaluated_at.isoformat() if rule.last_evaluated_at else None,
        }
        for rule in rules
        if (rule.match_count or 0) == 0
    ]
    top = sorted(with_matches, key=lambda r: -(r.match_count or 0))[:10]

    return DetectionCoverageResponse(
        total_rules=len(rules),
        enabled_rules=len(enabled),
        rules_with_matches=len(with_matches),
        never_matched_rules=never_matched[:25],
        top_rules=[
            {
                "ruleId": rule.id,
                "name": rule.name,
                "severity": rule.severity,
                "matchCount": rule.match_count or 0,
                "lastMatchedAt": rule.last_matched_at.isoformat() if rule.last_matched_at else None,
            }
            for rule in top
        ],
    )


@router.get("/ingestion", response_model=dict)
def get_ingestion_stats(
    days: int = Query(default=7, ge=1, le=90),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Telemetry volume by source and severity.

    [2]'s data-engineering view: which connectors are actually delivering, and
    whether the severity mix suddenly shifted (a common sign a log source
    changed format and normalization is now mis-mapping it).
    """
    from app.models.event import Event

    start, end = _period(days)
    by_source = db.execute(
        select(Event.source, func.count())
        .where(Event.tenant_id == current_user.tenant_id, Event.occurred_at >= start, Event.occurred_at <= end)
        .group_by(Event.source)
    ).all()
    by_severity = db.execute(
        select(Event.severity_hint, func.count())
        .where(Event.tenant_id == current_user.tenant_id, Event.occurred_at >= start, Event.occurred_at <= end)
        .group_by(Event.severity_hint)
    ).all()
    enriched = db.execute(
        select(func.count())
        .select_from(Event)
        .where(
            Event.tenant_id == current_user.tenant_id,
            Event.occurred_at >= start,
            Event.enrichment.isnot(None),
        )
    ).scalar_one()

    total = sum(count for _, count in by_source)
    return {
        "periodStart": start.isoformat(),
        "periodEnd": end.isoformat(),
        "totalEvents": total,
        "enrichedEvents": int(enriched),
        "bySource": {source: count for source, count in by_source},
        "bySeverity": {severity: count for severity, count in by_severity},
    }

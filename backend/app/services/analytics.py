"""FM8: KPI aggregation.

Extracted out of `api/v1/analytics.py` so FM9's compliance reports and the
dashboard endpoint compute the same numbers from the same code. A report that
disagrees with the dashboard about MTTD for the same period is worse than no
report, and two copies of this arithmetic would drift the first time either was
touched.

Timezone handling: SQLite round-trips DateTime(timezone=True) as naive, so
every timestamp read here is coerced to UTC before arithmetic. Mixing naive and
aware datetimes raises TypeError, which would be a 500 on the dashboard under
SQLite and not under Postgres -- exactly the kind of environment-dependent bug
worth centralizing.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.case import Case, CaseStatus
from app.models.event import Event

logger = logging.getLogger(__name__)


def as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def compute_kpis(
    db: Session,
    *,
    tenant_id: str,
    period_start: datetime,
    period_end: datetime,
) -> dict[str, Any]:
    """Tenant-scoped KPIs for a period.

    - alert_volume: alerts raised in the period.
    - false_positive_rate: share of those alerts explicitly dismissed by an
      analyst. Now a real measurement rather than a constant: `PATCH
      /v1/alerts/{id}` writes the dismissal that this reads. Still a proxy for
      true false-positive rate (an undismissed alert is not necessarily a true
      positive), and labelled as such in the response.
    - mttd_seconds: mean of (alert.created_at - earliest contributing
      event.occurred_at).
    - mttr_seconds: mean of (case.resolved_at - case.created_at) for cases
      resolved in the period.
    """
    alerts = list(
        db.execute(
            select(Alert).where(
                Alert.tenant_id == tenant_id,
                Alert.created_at >= period_start,
                Alert.created_at <= period_end,
            )
        ).scalars()
    )
    alert_volume = len(alerts)

    dismissed = sum(1 for alert in alerts if alert.status == "dismissed")
    false_positive_rate = (dismissed / alert_volume) if alert_volume else 0.0

    # MTTD. One query for the whole batch rather than one per alert: the
    # previous per-alert lookup was N+1 and became the dashboard's slowest
    # query as alert volume grew.
    mttd_seconds = _mean_time_to_detect(db, tenant_id=tenant_id, alerts=alerts)

    resolved_cases = list(
        db.execute(
            select(Case).where(
                Case.tenant_id == tenant_id,
                Case.status == CaseStatus.RESOLVED,
                Case.resolved_at.isnot(None),
                Case.resolved_at >= period_start,
                Case.resolved_at <= period_end,
            )
        ).scalars()
    )
    mttr_samples: list[float] = []
    for case in resolved_cases:
        created_at = as_utc(case.created_at)
        resolved_at = as_utc(case.resolved_at)
        if created_at is None or resolved_at is None:
            continue
        delta = (resolved_at - created_at).total_seconds()
        if delta >= 0:
            mttr_samples.append(delta)
    mttr_seconds = (sum(mttr_samples) / len(mttr_samples)) if mttr_samples else None

    open_cases = int(
        db.execute(
            select(func.count())
            .select_from(Case)
            .where(Case.tenant_id == tenant_id, Case.status != CaseStatus.RESOLVED)
        ).scalar_one()
    )

    by_severity: dict[str, int] = {}
    by_source: dict[str, int] = {}
    for alert in alerts:
        by_severity[alert.severity] = by_severity.get(alert.severity, 0) + 1
        by_source[alert.detection_source] = by_source.get(alert.detection_source, 0) + 1

    return {
        "period_start": period_start,
        "period_end": period_end,
        "alert_volume": alert_volume,
        "dismissed_alerts": dismissed,
        "false_positive_rate": round(false_positive_rate, 4),
        "mttd_seconds": mttd_seconds,
        "mttr_seconds": mttr_seconds,
        "open_cases": open_cases,
        "resolved_cases": len(resolved_cases),
        "alerts_by_severity": by_severity,
        "alerts_by_detection_source": by_source,
    }


def _mean_time_to_detect(db: Session, *, tenant_id: str, alerts: list[Alert]) -> float | None:
    """Mean seconds between the earliest contributing event and the alert.

    Collects every contributing event id across all alerts, resolves their
    occurred_at in one query, then computes per-alert minima in Python. One
    query instead of one per alert.
    """
    all_event_ids: set[str] = set()
    for alert in alerts:
        all_event_ids.update(alert.event_ids or [])
    if not all_event_ids:
        return None

    occurred_by_id: dict[str, datetime] = {}
    # Chunked so a large period cannot build an IN clause past the driver's
    # bound-parameter limit (SQLite's default is 999).
    ids = sorted(all_event_ids)
    chunk_size = 500
    for start in range(0, len(ids), chunk_size):
        chunk = ids[start : start + chunk_size]
        rows = db.execute(
            select(Event.id, Event.occurred_at).where(
                Event.tenant_id == tenant_id,
                Event.id.in_(chunk),
            )
        ).all()
        for event_id, occurred_at in rows:
            coerced = as_utc(occurred_at)
            if coerced is not None:
                occurred_by_id[event_id] = coerced

    samples: list[float] = []
    for alert in alerts:
        created_at = as_utc(alert.created_at)
        if created_at is None:
            continue
        candidates = [occurred_by_id[eid] for eid in (alert.event_ids or []) if eid in occurred_by_id]
        if not candidates:
            continue
        delta = (created_at - min(candidates)).total_seconds()
        if delta >= 0:
            samples.append(delta)
    return (sum(samples) / len(samples)) if samples else None


def alert_volume_timeseries(
    db: Session,
    *,
    tenant_id: str,
    period_start: datetime,
    period_end: datetime,
    bucket_hours: int = 24,
) -> list[dict[str, Any]]:
    """Bucketed alert counts, for the dashboard's trend chart.

    Bucketed in Python rather than with a SQL date_trunc: date truncation syntax
    differs between Postgres and SQLite, and this endpoint has to work on both.
    The read is bounded by the period, and the arithmetic is linear in alert
    count.
    """
    alerts = db.execute(
        select(Alert.created_at, Alert.severity).where(
            Alert.tenant_id == tenant_id,
            Alert.created_at >= period_start,
            Alert.created_at <= period_end,
        )
    ).all()

    bucket = timedelta(hours=max(bucket_hours, 1))
    buckets: dict[datetime, dict[str, Any]] = {}
    cursor = period_start
    while cursor < period_end:
        buckets[cursor] = {"bucket_start": cursor, "count": 0, "by_severity": {}}
        cursor += bucket

    bucket_starts = sorted(buckets)
    for created_at, severity in alerts:
        moment = as_utc(created_at)
        if moment is None:
            continue
        offset = int((moment - period_start) / bucket)
        if offset < 0 or offset >= len(bucket_starts):
            continue
        entry = buckets[bucket_starts[offset]]
        entry["count"] += 1
        entry["by_severity"][severity] = entry["by_severity"].get(severity, 0) + 1

    return [buckets[start] for start in bucket_starts]

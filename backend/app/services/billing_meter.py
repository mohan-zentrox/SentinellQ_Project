"""FM10: usage metering writes.

The read-modify-write this replaces (`counter.event_count += n` on an ORM
instance loaded earlier in the request) lost increments whenever two ingest
requests for the same tenant overlapped: both read the same starting value and
the second write clobbered the first. Under-counting usage is a billing bug,
and it also means quota enforcement silently stops working at exactly the
traffic level where it matters.

Everything here issues a single atomic `UPDATE ... SET event_count =
event_count + :n` so the database -- not the process -- serializes concurrent
increments.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.billing import UsageCounter

logger = logging.getLogger(__name__)


def current_period(now: datetime | None = None) -> str:
    moment = now or datetime.now(timezone.utc)
    return f"{moment.year:04d}-{moment.month:02d}"


def ensure_counter(db: Session, *, tenant_id: str, period: str) -> UsageCounter:
    """Get-or-create the counter row for (tenant, period).

    The unique constraint on (tenant_id, period) means two concurrent creators
    race; the loser catches IntegrityError and re-reads rather than failing the
    request.
    """
    counter = db.execute(
        select(UsageCounter).where(UsageCounter.tenant_id == tenant_id, UsageCounter.period == period)
    ).scalar_one_or_none()
    if counter is not None:
        return counter

    counter = UsageCounter(tenant_id=tenant_id, period=period, event_count=0)
    db.add(counter)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        counter = db.execute(
            select(UsageCounter).where(UsageCounter.tenant_id == tenant_id, UsageCounter.period == period)
        ).scalar_one()
    return counter


def record_event_usage(db: Session, *, tenant_id: str, period: str, count: int) -> int:
    """Atomically add `count` ingested events to the tenant's period counter.

    Returns the counter value after the increment. Does not commit.
    """
    if count <= 0:
        return read_event_usage(db, tenant_id=tenant_id, period=period)

    ensure_counter(db, tenant_id=tenant_id, period=period)
    db.execute(
        update(UsageCounter)
        .where(UsageCounter.tenant_id == tenant_id, UsageCounter.period == period)
        .values(event_count=UsageCounter.event_count + count, updated_at=datetime.now(timezone.utc))
    )
    # Drop any stale ORM copy of this row so a later read in the same session
    # sees the value the database now holds, not the pre-UPDATE one.
    db.expire_all()
    return read_event_usage(db, tenant_id=tenant_id, period=period)


def read_event_usage(db: Session, *, tenant_id: str, period: str) -> int:
    value = db.execute(
        select(UsageCounter.event_count).where(
            UsageCounter.tenant_id == tenant_id,
            UsageCounter.period == period,
        )
    ).scalar_one_or_none()
    return int(value or 0)

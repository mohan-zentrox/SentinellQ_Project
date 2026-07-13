"""FM2/FM3: Telemetry store abstraction.

Documented production target: ClickHouse or OpenSearch (columnar / search
engine optimized for append-heavy, high-cardinality security telemetry at
scale). Working default for local dev and tests: `PostgresTelemetryStore`,
which persists normalized events into the `events` table of the same
relational metadata database via SQLAlchemy (works against Postgres in
real deployments and SQLite in tests -- callers never know the difference).

All access goes through this interface and is unconditionally tenant-scoped.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.event import Event


class TelemetryStore(ABC):
    @abstractmethod
    def write_event(self, db: Session, *, tenant_id: str, event_data: dict[str, Any]) -> Event:
        raise NotImplementedError

    @abstractmethod
    def query_events(
        self,
        db: Session,
        *,
        tenant_id: str,
        page: int = 1,
        page_size: int = 50,
        severity: str | None = None,
    ) -> tuple[list[Event], int]:
        raise NotImplementedError


class PostgresTelemetryStore(TelemetryStore):
    """Relational-DB-backed adapter. Despite the name, works against any
    SQLAlchemy-supported engine (Postgres in prod/dev via docker-compose,
    SQLite for the test suite) -- the class is named for the *documented*
    production choice among the two supported metadata-DB engines, per
    the architecture doc's adapter-swap convention.
    """

    def write_event(self, db: Session, *, tenant_id: str, event_data: dict[str, Any]) -> Event:
        event = Event(tenant_id=tenant_id, **event_data)
        db.add(event)
        db.flush()
        return event

    def query_events(
        self,
        db: Session,
        *,
        tenant_id: str,
        page: int = 1,
        page_size: int = 50,
        severity: str | None = None,
    ) -> tuple[list[Event], int]:
        page = max(page, 1)
        page_size = min(max(page_size, 1), 200)

        stmt = select(Event).where(Event.tenant_id == tenant_id)
        count_stmt = select(func.count()).select_from(Event).where(Event.tenant_id == tenant_id)
        if severity:
            stmt = stmt.where(Event.severity_hint == severity)
            count_stmt = count_stmt.where(Event.severity_hint == severity)

        total = db.execute(count_stmt).scalar_one()
        stmt = stmt.order_by(Event.occurred_at.desc()).offset((page - 1) * page_size).limit(page_size)
        rows = list(db.execute(stmt).scalars().all())
        return rows, total


_store_singleton: TelemetryStore | None = None


def get_telemetry_store() -> TelemetryStore:
    global _store_singleton
    if _store_singleton is None:
        _store_singleton = PostgresTelemetryStore()
    return _store_singleton

"""FM2/FM3: Telemetry store abstraction.

Documented production target: ClickHouse or OpenSearch (columnar / search
engine optimized for append-heavy, high-cardinality security telemetry at
scale). Working default for local dev and tests: `PostgresTelemetryStore`,
which persists normalized events into the `events` table of the same
relational metadata database via SQLAlchemy (works against Postgres in
real deployments and SQLite in tests -- callers never know the difference).

The backend is selected by `SENTINELIQ_TELEMETRY_STORE_BACKEND` and resolved
in `get_telemetry_store()`, which actually reads the setting. Selecting an
unimplemented target fails loudly at first use rather than silently falling
back to Postgres.

All access goes through this interface and is unconditionally tenant-scoped:
every method takes `tenant_id` as a keyword-only argument and every query
filters on it.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.event import Event

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EventFilter:
    """Query filters for the events explorer. All fields optional and ANDed."""

    severity: str | None = None
    event_category: str | None = None
    event_action: str | None = None
    actor: str | None = None
    source_ip: str | None = None
    source: str | None = None
    occurred_after: datetime | None = None
    occurred_before: datetime | None = None
    #: Free-text match across actor / target / source_ip / action.
    search: str | None = None


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
        filters: EventFilter | None = None,
    ) -> tuple[list[Event], int]:
        raise NotImplementedError

    @abstractmethod
    def events_since(
        self,
        db: Session,
        *,
        tenant_id: str,
        since: datetime | None,
        limit: int,
    ) -> list[Event]:
        """Events with `occurred_at >= since`, oldest first, capped at `limit`.

        This is the bounded read the rule engine uses instead of loading a
        tenant's entire event corpus.
        """
        raise NotImplementedError

    @abstractmethod
    def get_events(self, db: Session, *, tenant_id: str, event_ids: list[str]) -> list[Event]:
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

    def _apply_filters(self, stmt, filters: EventFilter | None):
        if filters is None:
            return stmt
        if filters.severity:
            stmt = stmt.where(Event.severity_hint == filters.severity)
        if filters.event_category:
            stmt = stmt.where(Event.event_category == filters.event_category)
        if filters.event_action:
            stmt = stmt.where(Event.event_action == filters.event_action)
        if filters.actor:
            stmt = stmt.where(Event.actor == filters.actor)
        if filters.source_ip:
            stmt = stmt.where(Event.source_ip == filters.source_ip)
        if filters.source:
            stmt = stmt.where(Event.source == filters.source)
        if filters.occurred_after:
            stmt = stmt.where(Event.occurred_at >= filters.occurred_after)
        if filters.occurred_before:
            stmt = stmt.where(Event.occurred_at <= filters.occurred_before)
        if filters.search:
            needle = f"%{filters.search}%"
            stmt = stmt.where(
                or_(
                    Event.actor.ilike(needle),
                    Event.target.ilike(needle),
                    Event.source_ip.ilike(needle),
                    Event.event_action.ilike(needle),
                )
            )
        return stmt

    def query_events(
        self,
        db: Session,
        *,
        tenant_id: str,
        page: int = 1,
        page_size: int = 50,
        filters: EventFilter | None = None,
    ) -> tuple[list[Event], int]:
        page = max(page, 1)
        page_size = min(max(page_size, 1), 200)

        stmt = select(Event).where(Event.tenant_id == tenant_id)
        count_stmt = select(func.count()).select_from(Event).where(Event.tenant_id == tenant_id)
        stmt = self._apply_filters(stmt, filters)
        count_stmt = self._apply_filters(count_stmt, filters)

        total = db.execute(count_stmt).scalar_one()
        stmt = stmt.order_by(Event.occurred_at.desc()).offset((page - 1) * page_size).limit(page_size)
        rows = list(db.execute(stmt).scalars().all())
        return rows, total

    def events_since(
        self,
        db: Session,
        *,
        tenant_id: str,
        since: datetime | None,
        limit: int,
    ) -> list[Event]:
        stmt = select(Event).where(Event.tenant_id == tenant_id)
        if since is not None:
            stmt = stmt.where(Event.occurred_at >= since)
        stmt = stmt.order_by(Event.occurred_at.asc()).limit(limit)
        return list(db.execute(stmt).scalars().all())

    def get_events(self, db: Session, *, tenant_id: str, event_ids: list[str]) -> list[Event]:
        if not event_ids:
            return []
        stmt = select(Event).where(Event.tenant_id == tenant_id, Event.id.in_(event_ids))
        return list(db.execute(stmt).scalars().all())


class _UnimplementedTelemetryStore(TelemetryStore):  # pragma: no cover - constructor always raises
    """Shared failure mode for the documented-but-unbuilt targets.

    TODO(C6): a ClickHouse adapter (MergeTree partitioned by tenant+day, with
    `normalized` kept as a JSON column and the flat OCSF fields promoted to
    typed columns for predicate pushdown) and an OpenSearch adapter (one index
    per tenant-month behind an alias, with the condition DSL in
    `app/services/rule_engine.py` compiled to a bool query instead of
    evaluated in Python). Both implement exactly the interface above; nothing
    outside this module changes.
    """

    backend_name = "unimplemented"

    def __init__(self) -> None:
        raise NotImplementedError(
            f"telemetry_store_backend={self.backend_name!r} is a documented production target but is not "
            "implemented. Use 'postgres'. See app/services/telemetry_store.py."
        )

    def write_event(self, db: Session, *, tenant_id: str, event_data: dict[str, Any]) -> Event:
        raise NotImplementedError

    def query_events(self, db, *, tenant_id, page=1, page_size=50, filters=None):
        raise NotImplementedError

    def events_since(self, db, *, tenant_id, since, limit):
        raise NotImplementedError

    def get_events(self, db, *, tenant_id, event_ids):
        raise NotImplementedError


class ClickHouseTelemetryStore(_UnimplementedTelemetryStore):  # pragma: no cover
    backend_name = "clickhouse"


class OpenSearchTelemetryStore(_UnimplementedTelemetryStore):  # pragma: no cover
    backend_name = "opensearch"


_store_singleton: TelemetryStore | None = None

_BACKENDS: dict[str, type[TelemetryStore]] = {
    "postgres": PostgresTelemetryStore,
    "clickhouse": ClickHouseTelemetryStore,
    "opensearch": OpenSearchTelemetryStore,
}


def get_telemetry_store() -> TelemetryStore:
    global _store_singleton
    if _store_singleton is None:
        backend = get_settings().telemetry_store_backend
        try:
            store_cls = _BACKENDS[backend]
        except KeyError:
            raise ValueError(
                f"Unknown SENTINELIQ_TELEMETRY_STORE_BACKEND={backend!r}. "
                f"Supported: {', '.join(sorted(_BACKENDS))}."
            ) from None
        _store_singleton = store_cls()
        logger.info("telemetry_store.backend_selected", extra={"backend": backend})
    return _store_singleton


def reset_telemetry_store() -> None:
    """Test helper: drop the singleton so the next call rebuilds it."""
    global _store_singleton
    _store_singleton = None

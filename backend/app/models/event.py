from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.ids import generate_id
from app.db.base import Base, utcnow


class Event(Base):
    """A normalized security telemetry event (OCSF/ECS-aligned).

    This table *is* the Postgres-backed telemetry store adapter referenced by
    app/services/telemetry_store.py. The documented production target is a
    purpose-built store (ClickHouse/OpenSearch) behind the same
    TelemetryStore interface -- see that module for the swap-in seam.
    """

    __tablename__ = "events"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: generate_id("event"))
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)

    # Raw, as received by /v1/events/ingest, preserved for audit/replay.
    source: Mapped[str] = mapped_column(String(255), nullable=False)
    raw_payload: Mapped[dict] = mapped_column(JSON, nullable=False)

    # OCSF/ECS-aligned normalized fields (see services/normalizer.py).
    event_category: Mapped[str] = mapped_column(String(100), nullable=False, default="other")
    event_action: Mapped[str] = mapped_column(String(255), nullable=False, default="unknown")
    severity_hint: Mapped[str] = mapped_column(String(20), nullable=False, default="informational")
    actor: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    normalized: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

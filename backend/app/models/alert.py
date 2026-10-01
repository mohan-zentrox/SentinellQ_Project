from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.ids import generate_id
from app.db.base import Base, TimestampMixin


class Alert(Base, TimestampMixin):
    """FM4/FM6: an alert raised by the rule engine or by ML scoring.

    `detection_source` distinguishes the two so analytics can report on them
    separately (and so an ML-produced alert is never mistaken for a
    deterministic rule hit). `ml_score`/`ml_model_version` are populated only
    when detection_source == "ml".

    Triage state lives here rather than on the case: an alert can be dismissed
    as a false positive without ever becoming a case, and that dismissal is
    what makes FM8's false-positive rate a real metric instead of a constant.
    """

    __tablename__ = "alerts"
    __table_args__ = (
        # Analytics aggregates by (tenant, created_at); the alerts list filters
        # by (tenant, status) and sorts by created_at.
        Index("ix_alerts_tenant_created", "tenant_id", "created_at"),
        Index("ix_alerts_tenant_status", "tenant_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: generate_id("alert"))
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    rule_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(2000), nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")  # open|dismissed|promoted
    event_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    case_id: Mapped[str | None] = mapped_column(String(40), nullable=True)

    # "rule" | "ml" | "manual"
    detection_source: Mapped[str] = mapped_column(String(20), nullable=False, default="rule")

    # Populated by ML scoring (C8); null for rule-engine alerts.
    ml_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    ml_model_version: Mapped[str | None] = mapped_column(String(50), nullable=True)

    # FM6 triage: who dismissed this as a false positive, when, and why.
    dismissed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    dismissed_by_user_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    dismiss_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # FM6 alerting: set once notification channels have been fired for this
    # alert, so a retry or a re-evaluation never double-pages an on-call.
    notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

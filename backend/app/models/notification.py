"""FM6: notification delivery records."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.ids import generate_id
from app.db.base import Base


class NotificationDelivery(Base):
    """One attempt to deliver one alert to one channel.

    Recorded rather than fire-and-forget so that "was the on-call actually
    paged for this alert?" is an answerable question during an incident review.
    Append-only; a retry creates a new row.
    """

    __tablename__ = "notification_deliveries"
    __table_args__ = (Index("ix_notifications_tenant_created", "tenant_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: generate_id("notification"))
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    alert_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    case_id: Mapped[str | None] = mapped_column(String(40), nullable=True)

    channel: Mapped[str] = mapped_column(String(30), nullable=False)  # log|webhook|email
    #: "sent" | "failed" | "suppressed"
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    target: Mapped[str | None] = mapped_column(String(500), nullable=True)
    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    error: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

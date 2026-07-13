from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.ids import generate_id
from app.db.base import Base, TimestampMixin, utcnow


class CaseStatus:
    NEW = "new"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    ESCALATED = "escalated"

    ALL = (NEW, INVESTIGATING, RESOLVED, ESCALATED)

    # FM6 status state machine. Resolved is terminal.
    TRANSITIONS: dict[str, set[str]] = {
        NEW: {INVESTIGATING},
        INVESTIGATING: {RESOLVED, ESCALATED},
        ESCALATED: {INVESTIGATING, RESOLVED},
        RESOLVED: set(),
    }

    @classmethod
    def can_transition(cls, current: str, target: str) -> bool:
        return target in cls.TRANSITIONS.get(current, set())


class Case(Base, TimestampMixin):
    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: generate_id("case"))
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(4000), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default=CaseStatus.NEW)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    assignee_user_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    alert_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CaseTimelineEntry(Base):
    """Append-only audit trail for a case; MTTR (FM8) is derived from these rows."""

    __tablename__ = "case_timeline_entries"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: generate_id("timeline_entry"))
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    case_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    entry_type: Mapped[str] = mapped_column(String(50), nullable=False)  # created|status_change|comment|assignment
    message: Mapped[str] = mapped_column(String(2000), nullable=False, default="")
    actor_user_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.ids import generate_id
from app.db.base import Base


class AuditLogEntry(Base):
    """Tenant-scoped audit trail for security-relevant actions.

    Before this existed, the only trail in the product was `CaseTimelineEntry`
    -- which covers what happened to a case, and nothing else. Who created or
    deleted a detection rule, who issued or revoked a service token, who
    changed another user's role, who exported a compliance report: all of that
    was unrecorded, which is awkward for a platform whose own FM9 module sells
    control evidence.

    Append-only by convention: there is no update or delete path in the API.
    Entries are immutable and carry no `updated_at`, which is why this model
    does not use TimestampMixin.
    """

    __tablename__ = "audit_log_entries"
    __table_args__ = (
        Index("ix_audit_tenant_created", "tenant_id", "created_at"),
        Index("ix_audit_tenant_action", "tenant_id", "action"),
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: generate_id("audit"))
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    #: Null for actions taken by the system (worker, scheduled job) rather than
    #: a signed-in human.
    actor_user_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    #: Dotted, past-tense action name, e.g. "detection_rule.created".
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    #: Arbitrary structured context. Must never contain secrets -- see
    #: services/audit.py, which redacts known-sensitive keys.
    detail: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

"""FM9: Compliance report entities."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.ids import generate_id
from app.db.base import Base, TimestampMixin


class ReportStatus:
    QUEUED = "queued"
    GENERATING = "generating"
    READY = "ready"
    FAILED = "failed"

    ALL = (QUEUED, GENERATING, READY, FAILED)


class ComplianceReport(Base, TimestampMixin):
    """A generated report artifact.

    Generation is modelled as a job rather than a request-path computation: a
    90-day control-evidence report over a busy tenant is not something to hold
    an HTTP connection open for. Downloads go through a short-lived HMAC-signed
    URL (see services/reports.py) so a link forwarded in an email cannot be
    replayed indefinitely or used against another tenant.
    """

    __tablename__ = "compliance_reports"
    __table_args__ = (Index("ix_reports_tenant_created", "tenant_id", "created_at"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: generate_id("report"))
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    #: Registered template name (see services/reports.py::TEMPLATES).
    template: Mapped[str] = mapped_column(String(50), nullable=False)
    #: "csv" | "json" | "html"
    report_format: Mapped[str] = mapped_column(String(10), nullable=False, default="csv")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default=ReportStatus.QUEUED)

    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    parameters: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    #: Path relative to settings.report_dir. Never returned to clients directly.
    artifact_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    row_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(String(2000), nullable=True)

    requested_by_user_id: Mapped[str | None] = mapped_column(String(40), nullable=True)

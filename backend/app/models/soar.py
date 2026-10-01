"""FM7: SOAR playbook entities.

The approval model here is the point, not an afterthought. This platform is
authorized defensive tooling (see README.md), so the schema makes
fully-autonomous destructive automation impossible to express: an action
marked high-risk cannot execute without an `approved_by_user_id`, and the
action record carries the approval alongside the result so an audit can see
who authorized what.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.ids import generate_id
from app.db.base import Base, TimestampMixin


class PlaybookTrigger:
    ALERT_CREATED = "alert_created"
    CASE_ESCALATED = "case_escalated"
    CASE_CREATED = "case_created"
    MANUAL = "manual"

    ALL = (ALERT_CREATED, CASE_ESCALATED, CASE_CREATED, MANUAL)


class RunStatus:
    PENDING_APPROVAL = "pending_approval"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    PARTIAL = "partial"
    REJECTED = "rejected"
    SKIPPED = "skipped"

    ALL = (PENDING_APPROVAL, RUNNING, SUCCEEDED, FAILED, PARTIAL, REJECTED, SKIPPED)
    TERMINAL = (SUCCEEDED, FAILED, PARTIAL, REJECTED, SKIPPED)


class Playbook(Base, TimestampMixin):
    __tablename__ = "playbooks"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: generate_id("playbook"))
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), nullable=False, default="")

    #: One of PlaybookTrigger.ALL.
    trigger: Mapped[str] = mapped_column(String(40), nullable=False, default=PlaybookTrigger.ALERT_CREATED)
    #: Optional extra gate on the triggering object, reusing the FM4 condition
    #: DSL so there is one condition language in the product rather than two.
    #: Evaluated against a synthetic event built from the alert/case.
    trigger_condition: Mapped[dict | None] = mapped_column(JSON, nullable=True)

    #: Ordered list of {"action": "<registry name>", "params": {...}}.
    actions: Mapped[list] = mapped_column(JSON, nullable=False, default=list)

    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    #: When true, runs execute no side effects and record what they *would*
    #: have done. The safe way to introduce a playbook to production.
    dry_run: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    created_by_user_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    run_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PlaybookRun(Base, TimestampMixin):
    """One execution of a playbook: the audit trail for automation."""

    __tablename__ = "playbook_runs"
    __table_args__ = (
        Index("ix_playbook_runs_tenant_created", "tenant_id", "created_at"),
        Index("ix_playbook_runs_tenant_status", "tenant_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: generate_id("playbook_run"))
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    playbook_id: Mapped[str] = mapped_column(String(40), nullable=False)

    status: Mapped[str] = mapped_column(String(30), nullable=False, default=RunStatus.RUNNING)
    trigger: Mapped[str] = mapped_column(String(40), nullable=False)
    #: What set this off: "alert" / "case" / "manual", plus its id.
    subject_type: Mapped[str | None] = mapped_column(String(30), nullable=True)
    subject_id: Mapped[str | None] = mapped_column(String(40), nullable=True)

    dry_run: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    #: Human-in-the-loop gate for high-risk actions.
    requires_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    approved_by_user_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rejected_by_user_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rejection_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)

    triggered_by_user_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(String(2000), nullable=True)


class PlaybookActionRecord(Base):
    """Per-action outcome within a run. Append-only."""

    __tablename__ = "playbook_action_records"
    __table_args__ = (Index("ix_playbook_action_run", "tenant_id", "run_id", "sequence"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: generate_id("playbook_action"))
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    run_id: Mapped[str] = mapped_column(String(40), nullable=False)
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)

    action: Mapped[str] = mapped_column(String(100), nullable=False)
    params: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    #: "succeeded" | "failed" | "skipped" | "dry_run"
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    is_high_risk: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    result: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    error: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

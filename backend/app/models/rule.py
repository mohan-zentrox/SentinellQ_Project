from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.ids import generate_id
from app.db.base import Base, TimestampMixin


class DetectionRule(Base, TimestampMixin):
    """FM4: a detection rule with a small JSON condition DSL.

    condition examples:
      {"field": "severity_hint", "op": "eq", "value": "critical"}
      {"all": [{"field": "event_category", "op": "eq", "value": "authentication"},
                {"field": "event_action", "op": "eq", "value": "login_failed"}]}
      {"any": [...]}
      {"field": "actor", "op": "regex", "value": "^svc-.*"}
      {"field": "event_action", "op": "eq", "value": "login_failed",
       "window": {"minutes": 10, "count": 5, "groupBy": "actor"}}
    See app/services/rule_engine.py for the evaluator.
    """

    __tablename__ = "detection_rules"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: generate_id("rule"))
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    condition: Mapped[dict] = mapped_column(JSON, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by_user_id: Mapped[str | None] = mapped_column(String(40), nullable=True)

    # Bounds a whole-corpus evaluation: only events with
    # occurred_at >= now - evaluation_window_minutes are scanned. Null falls
    # back to settings.detection_default_window_minutes, so no rule run can
    # degrade into an unbounded table scan.
    evaluation_window_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Observability for the FM11 admin surface / rules UI.
    last_evaluated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_matched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    match_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class RuleEventMatch(Base):
    """Dedup ledger: one row per (rule, event) that has ever produced an alert.

    Before this table existed, `run_rule` loaded every alert for the rule and
    unioned their `event_ids` JSON arrays in Python on every evaluation --
    O(all alerts x all their events) per run. The unique constraint below
    turns that into an indexed lookup, and makes double-alerting on the same
    event impossible even if two workers evaluate the same rule concurrently
    (the second insert violates the constraint and is rolled back to a skip).

    `Alert.event_ids` is still populated for API compatibility; this table is
    the authority for "have we alerted on this event for this rule".
    """

    __tablename__ = "rule_event_matches"
    __table_args__ = (
        UniqueConstraint("rule_id", "event_id", name="uq_rule_event_matches_rule_event"),
        Index("ix_rule_event_matches_tenant_rule", "tenant_id", "rule_id"),
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: generate_id("rule_match"))
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    rule_id: Mapped[str] = mapped_column(String(40), nullable=False)
    event_id: Mapped[str] = mapped_column(String(40), nullable=False)
    alert_id: Mapped[str] = mapped_column(String(40), nullable=False)
    matched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

from __future__ import annotations

from sqlalchemy import JSON, Boolean, String
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

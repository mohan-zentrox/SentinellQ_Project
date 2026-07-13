from __future__ import annotations

from sqlalchemy import JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.ids import generate_id
from app.db.base import Base, TimestampMixin


class Alert(Base, TimestampMixin):
    """FM4/FM6: an alert raised by the rule engine (or, in future, ML scoring).

    ml_score / ml_model_version are reserved for the C8 ML scaffold and are
    always null for rule-engine-produced alerts today.
    """

    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: generate_id("alert"))
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    rule_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String(2000), nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")  # open|dismissed|promoted
    event_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    case_id: Mapped[str | None] = mapped_column(String(40), nullable=True)

    # C8 ML scaffold reserve columns (unused by the rule engine).
    ml_score: Mapped[float | None] = mapped_column(nullable=True)
    ml_model_version: Mapped[str | None] = mapped_column(String(50), nullable=True)

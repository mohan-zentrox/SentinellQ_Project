from __future__ import annotations

from sqlalchemy import JSON, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.ids import generate_id
from app.db.base import Base, TimestampMixin


class Plan(Base, TimestampMixin):
    __tablename__ = "plans"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: generate_id("plan"))
    slug: Mapped[str] = mapped_column(String(50), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    monthly_event_quota: Mapped[int] = mapped_column(Integer, nullable=False)
    price_cents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    features: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)


class Subscription(Base, TimestampMixin):
    __tablename__ = "subscriptions"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: generate_id("subscription"))
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False, unique=True)
    plan_id: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")  # pending|active|canceled
    stripe_checkout_session_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    stripe_customer_id: Mapped[str | None] = mapped_column(String(255), nullable=True)


class UsageCounter(Base, TimestampMixin):
    """FM10 usage metering: one row per (tenant, billing period)."""

    __tablename__ = "usage_counters"

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: generate_id("usage_counter"))
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    period: Mapped[str] = mapped_column(String(7), nullable=False)  # "YYYY-MM"
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

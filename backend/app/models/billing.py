from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Integer, String, UniqueConstraint
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
    stripe_subscription_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Set when the tenant cancels; the subscription stays `active` until the
    # paid period ends rather than cutting access off mid-cycle.
    cancel_at_period_end: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    canceled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    current_period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class UsageCounter(Base, TimestampMixin):
    """FM10 usage metering: one row per (tenant, billing period)."""

    __tablename__ = "usage_counters"
    __table_args__ = (
        # Required by services/billing_meter.py: the atomic
        # "UPDATE ... SET event_count = event_count + n" increment relies on
        # there being exactly one row per (tenant, period), and the
        # get-or-create path relies on a concurrent creator losing to this
        # constraint rather than inserting a duplicate.
        UniqueConstraint("tenant_id", "period", name="uq_usage_counters_tenant_period"),
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: generate_id("usage_counter"))
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    period: Mapped[str] = mapped_column(String(7), nullable=False)  # "YYYY-MM"
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from app.schemas.common import CamelModel


class PlanOut(CamelModel):
    id: str
    slug: str
    name: str
    monthly_event_quota: int
    price_cents: int
    features: dict


class CheckoutRequest(CamelModel):
    plan_slug: str = Field(min_length=1, max_length=50)


class CheckoutResponse(CamelModel):
    session_id: str
    checkout_url: str


class SubscriptionOut(CamelModel):
    id: str
    tenant_id: str
    plan_id: str
    status: str
    stripe_checkout_session_id: str | None = None
    cancel_at_period_end: bool = False
    canceled_at: datetime | None = None
    current_period_end: datetime | None = None
    created_at: datetime | None = None


class CancelSubscriptionRequest(CamelModel):
    """Cancel at period end by default.

    Immediate cancellation would drop a paying tenant to the free quota mid-cycle
    and start 429ing their ingestion, which is a surprising outcome for someone
    who clicked "cancel" meaning "do not renew".
    """

    immediate: bool = False


class UsageOut(CamelModel):
    period: str
    event_count: int
    monthly_event_quota: int | None
    percent_used: float | None
    #: True once usage is at or over quota: ingestion is being rejected with 429.
    over_quota: bool = False


class UsageHistoryEntry(CamelModel):
    period: str
    event_count: int


class UsageHistoryResponse(CamelModel):
    entries: list[UsageHistoryEntry]

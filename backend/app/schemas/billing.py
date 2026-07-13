from __future__ import annotations

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


class UsageOut(CamelModel):
    period: str
    event_count: int
    monthly_event_quota: int | None
    percent_used: float | None

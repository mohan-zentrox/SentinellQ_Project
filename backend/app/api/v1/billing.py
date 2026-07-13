"""FM10: Billing (mocked Stripe). Plan catalog, checkout session creation,
subscription activation, and usage/quota introspection."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.deps import require_role
from app.db.session import get_db
from app.models.billing import Plan, Subscription, UsageCounter
from app.models.tenant import Tenant
from app.models.user import Role, User
from app.schemas.billing import CheckoutRequest, CheckoutResponse, PlanOut, SubscriptionOut, UsageOut
from app.services.billing_provider import get_billing_provider

router = APIRouter(prefix="/billing", tags=["billing"])


@router.get("/plans", response_model=list[PlanOut])
def list_plans(db: Session = Depends(get_db)) -> list[Plan]:
    return db.query(Plan).all()


@router.post("/checkout", response_model=CheckoutResponse)
def create_checkout(
    payload: CheckoutRequest,
    current_user: User = Depends(require_role(Role.OWNER)),
    db: Session = Depends(get_db),
) -> CheckoutResponse:
    plan = db.query(Plan).filter(Plan.slug == payload.plan_slug).first()
    if plan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Unknown plan")
    tenant = db.get(Tenant, current_user.tenant_id)
    if tenant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Tenant not found")

    provider = get_billing_provider()
    checkout = provider.create_checkout_session(tenant=tenant, plan=plan)

    subscription = db.query(Subscription).filter(Subscription.tenant_id == tenant.id).first()
    if subscription is None:
        subscription = Subscription(tenant_id=tenant.id, plan_id=plan.id, status="pending")
        db.add(subscription)
    else:
        subscription.plan_id = plan.id
        subscription.status = "pending"
    subscription.stripe_checkout_session_id = checkout.session_id
    db.commit()

    return CheckoutResponse(session_id=checkout.session_id, checkout_url=checkout.checkout_url)


@router.post("/webhook/checkout-completed", response_model=SubscriptionOut)
def simulate_checkout_completed(
    session_id: str,
    current_user: User = Depends(require_role(Role.OWNER)),
    db: Session = Depends(get_db),
) -> Subscription:
    """Mocked equivalent of Stripe's `checkout.session.completed` webhook.

    In production this route is replaced by real Stripe webhook signature
    verification (see StripeProvider TODO in services/billing_provider.py);
    here it lets the local/dev flow "complete" a checkout without a live
    Stripe account.
    """
    subscription = db.query(Subscription).filter(Subscription.tenant_id == current_user.tenant_id).first()
    if subscription is None or subscription.stripe_checkout_session_id != session_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No matching pending checkout session")

    provider = get_billing_provider()
    provider.mark_subscription_active(subscription=subscription, session_id=session_id)

    tenant = db.get(Tenant, current_user.tenant_id)
    if tenant is not None:
        tenant.plan_id = subscription.plan_id

    db.commit()
    db.refresh(subscription)
    return subscription


@router.get("/subscription", response_model=SubscriptionOut)
def get_subscription(
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> Subscription:
    subscription = db.query(Subscription).filter(Subscription.tenant_id == current_user.tenant_id).first()
    if subscription is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No subscription on file")
    return subscription


@router.get("/usage", response_model=UsageOut)
def get_usage(
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> UsageOut:
    now = datetime.now(timezone.utc)
    period = f"{now.year:04d}-{now.month:02d}"
    counter = (
        db.query(UsageCounter)
        .filter(UsageCounter.tenant_id == current_user.tenant_id, UsageCounter.period == period)
        .first()
    )
    event_count = counter.event_count if counter else 0

    tenant = db.get(Tenant, current_user.tenant_id)
    plan = db.get(Plan, tenant.plan_id) if tenant and tenant.plan_id else None
    quota = plan.monthly_event_quota if plan else None
    percent_used = (event_count / quota * 100) if quota else None

    return UsageOut(period=period, event_count=event_count, monthly_event_quota=quota, percent_used=percent_used)

"""FM10: Billing. Plan catalog, checkout, subscription lifecycle, and
usage/quota introspection.

The provider is resolved from `SENTINELIQ_BILLING_PROVIDER`
(`services/billing_provider.py`), so pointing a deployment at real Stripe is a
config change. `MockStripeProvider` remains the working default.

Webhook note: the dev webhook below is authenticated as the tenant owner, which
is *not* how a real Stripe webhook works -- Stripe signs the request and has no
user session. `verify_webhook_signature` implements the real HMAC check for when
`SENTINELIQ_STRIPE_WEBHOOK_SECRET` is configured, so the signature path exists
rather than being a TODO; the owner-authenticated path is explicitly gated to
the mock provider.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.deps import client_ip, current_period, require_role
from app.db.session import get_db
from app.models.billing import Plan, Subscription, UsageCounter
from app.models.tenant import Tenant
from app.models.user import Role, User
from app.schemas.billing import (
    CancelSubscriptionRequest,
    CheckoutRequest,
    CheckoutResponse,
    PlanOut,
    SubscriptionOut,
    UsageHistoryEntry,
    UsageHistoryResponse,
    UsageOut,
)
from app.services.audit import record_audit
from app.services.billing_meter import read_event_usage
from app.services.billing_provider import get_billing_provider

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/billing", tags=["billing"])


@router.get("/plans", response_model=list[PlanOut])
def list_plans(db: Session = Depends(get_db)) -> list[Plan]:
    return db.query(Plan).order_by(Plan.price_cents.asc()).all()


@router.post("/checkout", response_model=CheckoutResponse)
def create_checkout(
    payload: CheckoutRequest,
    request: Request,
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
    # A pending plan change must not move the tenant's quota yet: the tenant is
    # still on its paid-for plan until checkout completes.
    subscription.cancel_at_period_end = False
    subscription.canceled_at = None

    record_audit(
        db,
        tenant_id=tenant.id,
        actor_user_id=current_user.id,
        action="billing.checkout_started",
        target_type="subscription",
        target_id=subscription.id,
        detail={"plan": plan.slug, "session_id": checkout.session_id},
        ip_address=client_ip(request),
    )
    db.commit()
    return CheckoutResponse(session_id=checkout.session_id, checkout_url=checkout.checkout_url)


def verify_webhook_signature(payload: bytes, signature_header: str | None, *, tolerance_seconds: int = 300) -> None:
    """Verify a Stripe-style `t=<ts>,v1=<sig>` signature header.

    This is the real check, not a placeholder: HMAC-SHA256 over
    `"{timestamp}.{body}"`, compared in constant time, with a timestamp tolerance
    so a captured webhook cannot be replayed indefinitely. It runs whenever
    `SENTINELIQ_STRIPE_WEBHOOK_SECRET` is set.
    """
    secret = get_settings().stripe_webhook_secret
    if not secret:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Webhook signature verification is not configured (SENTINELIQ_STRIPE_WEBHOOK_SECRET)",
        )
    if not signature_header:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Missing Stripe-Signature header")

    timestamp: str | None = None
    signatures: list[str] = []
    for part in signature_header.split(","):
        key, _, value = part.strip().partition("=")
        if key == "t":
            timestamp = value
        elif key == "v1":
            signatures.append(value)

    if not timestamp or not signatures:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Malformed Stripe-Signature header")
    try:
        age = abs(time.time() - int(timestamp))
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Malformed signature timestamp") from exc
    if age > tolerance_seconds:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Signature timestamp outside tolerance")

    expected = hmac.new(
        secret.encode(),
        f"{timestamp}.".encode() + payload,
        hashlib.sha256,
    ).hexdigest()
    if not any(hmac.compare_digest(expected, candidate) for candidate in signatures):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Signature verification failed")


def _activate(db: Session, *, subscription: Subscription, session_id: str) -> None:
    provider = get_billing_provider()
    provider.mark_subscription_active(subscription=subscription, session_id=session_id)
    subscription.current_period_end = datetime.now(timezone.utc) + timedelta(days=30)
    tenant = db.get(Tenant, subscription.tenant_id)
    if tenant is not None:
        # The tenant's quota follows its plan; this is the line that makes a
        # completed checkout actually raise the ingestion limit.
        tenant.plan_id = subscription.plan_id


@router.post("/webhook/checkout-completed", response_model=SubscriptionOut)
def simulate_checkout_completed(
    session_id: str = Query(...),
    request: Request = None,  # type: ignore[assignment]
    current_user: User = Depends(require_role(Role.OWNER)),
    db: Session = Depends(get_db),
) -> Subscription:
    """Dev/test completion of a mocked checkout.

    Deliberately refuses when a real billing provider is configured: completing a
    subscription from a session-authenticated request would let any tenant owner
    grant themselves a paid plan. With real Stripe, completion must arrive at
    `/webhook/stripe` with a valid signature.
    """
    settings = get_settings()
    if settings.billing_provider != "mock_stripe":
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "This endpoint only exists for the mocked billing provider. With a real provider, "
            "activation must come from a signature-verified webhook at /v1/billing/webhook/stripe.",
        )

    subscription = db.query(Subscription).filter(Subscription.tenant_id == current_user.tenant_id).first()
    if subscription is None or subscription.stripe_checkout_session_id != session_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No matching pending checkout session")

    _activate(db, subscription=subscription, session_id=session_id)
    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="billing.subscription_activated",
        target_type="subscription",
        target_id=subscription.id,
        detail={"session_id": session_id, "provider": "mock_stripe"},
        ip_address=client_ip(request) if request else None,
    )
    db.commit()
    db.refresh(subscription)
    return subscription


@router.post("/webhook/stripe", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def stripe_webhook(
    request: Request,
    stripe_signature: str | None = Header(default=None, alias="Stripe-Signature"),
    db: Session = Depends(get_db),
) -> None:
    """Signature-verified provider webhook. Unauthenticated by design.

    Handles `checkout.session.completed` and
    `customer.subscription.deleted`. The subscription is located by the session
    or customer id carried in the event -- never by a tenant id from the request,
    which an unauthenticated caller could choose.
    """
    import json

    body = await request.body()
    verify_webhook_signature(body, stripe_signature)

    try:
        event = json.loads(body)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Body is not valid JSON") from exc

    event_type = event.get("type")
    data_object = (event.get("data") or {}).get("object") or {}

    if event_type == "checkout.session.completed":
        session_id = data_object.get("id")
        subscription = (
            db.query(Subscription).filter(Subscription.stripe_checkout_session_id == session_id).first()
            if session_id
            else None
        )
        if subscription is None:
            # Acknowledge unknown sessions: a 4xx makes the provider retry
            # forever over an event we will never be able to match.
            logger.warning("billing.webhook_unmatched_session", extra={"session_id": session_id})
            return
        _activate(db, subscription=subscription, session_id=session_id)
        subscription.stripe_customer_id = data_object.get("customer") or subscription.stripe_customer_id
        subscription.stripe_subscription_id = data_object.get("subscription") or subscription.stripe_subscription_id
        record_audit(
            db,
            tenant_id=subscription.tenant_id,
            actor_user_id=None,
            action="billing.subscription_activated",
            target_type="subscription",
            target_id=subscription.id,
            detail={"session_id": session_id, "provider": get_settings().billing_provider},
        )
        db.commit()
        return

    if event_type == "customer.subscription.deleted":
        provider_subscription_id = data_object.get("id")
        subscription = (
            db.query(Subscription)
            .filter(Subscription.stripe_subscription_id == provider_subscription_id)
            .first()
            if provider_subscription_id
            else None
        )
        if subscription is None:
            logger.warning("billing.webhook_unmatched_subscription", extra={"id": provider_subscription_id})
            return
        _downgrade_to_default_plan(db, subscription=subscription)
        record_audit(
            db,
            tenant_id=subscription.tenant_id,
            actor_user_id=None,
            action="billing.subscription_canceled",
            target_type="subscription",
            target_id=subscription.id,
            detail={"provider_subscription_id": provider_subscription_id},
        )
        db.commit()
        return

    logger.info("billing.webhook_ignored", extra={"event_type": event_type})


def _downgrade_to_default_plan(db: Session, *, subscription: Subscription) -> None:
    settings = get_settings()
    subscription.status = "canceled"
    subscription.canceled_at = datetime.now(timezone.utc)
    default_plan = db.query(Plan).filter(Plan.slug == settings.default_plan_slug).first()
    tenant = db.get(Tenant, subscription.tenant_id)
    if tenant is not None and default_plan is not None:
        tenant.plan_id = default_plan.id
        subscription.plan_id = default_plan.id


@router.post("/subscription/cancel", response_model=SubscriptionOut)
def cancel_subscription(
    payload: CancelSubscriptionRequest,
    request: Request,
    current_user: User = Depends(require_role(Role.OWNER)),
    db: Session = Depends(get_db),
) -> Subscription:
    """Cancel the tenant's subscription.

    Default is cancel-at-period-end: the tenant keeps its paid quota until the
    period it already paid for runs out. `immediate: true` downgrades now, which
    means ingestion starts 429ing against the free quota as soon as the tenant is
    over it -- so it is opt-in, never the default.
    """
    subscription = db.query(Subscription).filter(Subscription.tenant_id == current_user.tenant_id).first()
    if subscription is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No subscription on file")
    if subscription.status == "canceled":
        raise HTTPException(status.HTTP_409_CONFLICT, "Subscription is already canceled")

    if payload.immediate:
        _downgrade_to_default_plan(db, subscription=subscription)
    else:
        subscription.cancel_at_period_end = True
        subscription.canceled_at = datetime.now(timezone.utc)

    record_audit(
        db,
        tenant_id=current_user.tenant_id,
        actor_user_id=current_user.id,
        action="billing.subscription_canceled",
        target_type="subscription",
        target_id=subscription.id,
        detail={"immediate": payload.immediate},
        ip_address=client_ip(request),
    )
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
    period = current_period()
    event_count = read_event_usage(db, tenant_id=current_user.tenant_id, period=period)

    tenant = db.get(Tenant, current_user.tenant_id)
    plan = db.get(Plan, tenant.plan_id) if tenant and tenant.plan_id else None
    quota = plan.monthly_event_quota if plan else None
    percent_used = (event_count / quota * 100) if quota else None

    return UsageOut(
        period=period,
        event_count=event_count,
        monthly_event_quota=quota,
        percent_used=percent_used,
        over_quota=bool(quota is not None and event_count >= quota),
    )


@router.get("/usage/history", response_model=UsageHistoryResponse)
def get_usage_history(
    months: int = Query(default=12, ge=1, le=36),
    current_user: User = Depends(require_role(Role.ANALYST, Role.ADMIN, Role.OWNER)),
    db: Session = Depends(get_db),
) -> UsageHistoryResponse:
    """Per-period usage, newest first -- what a tenant needs to sanity-check an
    invoice or spot a sudden ingestion spike."""
    rows = (
        db.query(UsageCounter)
        .filter(UsageCounter.tenant_id == current_user.tenant_id)
        .order_by(UsageCounter.period.desc())
        .limit(months)
        .all()
    )
    return UsageHistoryResponse(
        entries=[UsageHistoryEntry(period=row.period, event_count=row.event_count) for row in rows]
    )

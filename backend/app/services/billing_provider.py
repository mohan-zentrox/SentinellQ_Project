"""FM10: Billing provider abstraction.

Documented production target: the real Stripe SDK (`stripe` PyPI package),
calling `stripe.checkout.Session.create(...)`. Working default:
`MockStripeProvider`, which fabricates Stripe-shaped IDs/URLs deterministically
so the rest of the stack (persistence, quota logic, frontend) can be built
and tested against a stable contract before real Stripe credentials exist.
"""
from __future__ import annotations

import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass

from app.models.billing import Plan, Subscription
from app.models.tenant import Tenant


@dataclass(frozen=True)
class CheckoutSession:
    session_id: str
    checkout_url: str


class BillingProvider(ABC):
    @abstractmethod
    def create_checkout_session(self, *, tenant: Tenant, plan: Plan) -> CheckoutSession:
        raise NotImplementedError

    @abstractmethod
    def mark_subscription_active(self, *, subscription: Subscription, session_id: str) -> None:
        raise NotImplementedError


class MockStripeProvider(BillingProvider):
    """Working default. Produces Stripe-shaped identifiers (`cs_test_...`)
    without any network call, so `POST /v1/billing/checkout` and the
    subsequent "webhook" activation flow are fully exercised locally / in CI.
    """

    def create_checkout_session(self, *, tenant: Tenant, plan: Plan) -> CheckoutSession:
        session_id = f"cs_test_{secrets.token_hex(12)}"
        checkout_url = f"https://checkout.stripe.mock/pay/{session_id}?tenant={tenant.id}&plan={plan.slug}"
        return CheckoutSession(session_id=session_id, checkout_url=checkout_url)

    def mark_subscription_active(self, *, subscription: Subscription, session_id: str) -> None:
        subscription.status = "active"
        subscription.stripe_checkout_session_id = session_id


class StripeProvider(BillingProvider):  # pragma: no cover - documented swap-in, not wired up
    """Real Stripe integration. NOT implemented in this foundation repo.

    TODO(FM10): swap-in real billing.
      - `pip install stripe`, set SENTINELIQ_STRIPE_API_KEY
      - implement create_checkout_session via
        stripe.checkout.Session.create(mode="subscription", line_items=[...],
        success_url=..., cancel_url=..., client_reference_id=tenant.id)
      - implement mark_subscription_active from a verified
        `checkout.session.completed` webhook event instead of a direct call
      - set app.core.config.Settings.billing_provider = "stripe" and update
        get_billing_provider() below accordingly.
    """

    def create_checkout_session(self, *, tenant: Tenant, plan: Plan) -> CheckoutSession:
        raise NotImplementedError("Real Stripe integration is a documented extension point, see class docstring.")

    def mark_subscription_active(self, *, subscription: Subscription, session_id: str) -> None:
        raise NotImplementedError("Real Stripe integration is a documented extension point, see class docstring.")


def get_billing_provider() -> BillingProvider:
    # Swap to StripeProvider() once real Stripe credentials + webhook
    # verification are wired up (see app.core.config.Settings.billing_provider).
    return MockStripeProvider()

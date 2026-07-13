"""FM10: usage metering + quota-enforcement middleware -- 429 once a
tenant's plan quota is exceeded for the current billing period."""
from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.billing import Plan
from app.models.tenant import Tenant
from tests.conftest import create_service_token, signup


def _downgrade_to_tiny_quota(db_session: Session, tenant_id: str, quota: int = 2) -> None:
    tiny_plan = Plan(slug=f"tiny-{tenant_id}", name="Tiny (test)", monthly_event_quota=quota, price_cents=0)
    db_session.add(tiny_plan)
    db_session.flush()
    tenant = db_session.get(Tenant, tenant_id)
    tenant.plan_id = tiny_plan.id
    db_session.commit()


def test_ingest_allowed_under_quota(client: TestClient, db_session: Session):
    tenant = signup(client, company="Quota Co", email="owner@quotaco.test")
    _downgrade_to_tiny_quota(db_session, tenant["tenantId"], quota=2)
    token = create_service_token(client, owner_token=tenant["accessToken"])

    resp = client.post(
        "/v1/events/ingest",
        json={"events": [{"source": "test", "payload": {"severity": "low"}}]},
        headers={"X-Service-Token": token},
    )
    assert resp.status_code == 202
    assert resp.json()["accepted"] == 1


def test_ingest_429_once_quota_exceeded(client: TestClient, db_session: Session):
    tenant = signup(client, company="Quota Co 2", email="owner2@quotaco.test")
    _downgrade_to_tiny_quota(db_session, tenant["tenantId"], quota=2)
    token = create_service_token(client, owner_token=tenant["accessToken"])

    # Consume the full quota (2 events) in one batch -- allowed.
    ok_resp = client.post(
        "/v1/events/ingest",
        json={
            "events": [
                {"source": "test", "payload": {"severity": "low"}},
                {"source": "test", "payload": {"severity": "low"}},
            ]
        },
        headers={"X-Service-Token": token},
    )
    assert ok_resp.status_code == 202
    assert ok_resp.json()["accepted"] == 2

    # Any further ingest this period must be rejected with 429.
    blocked_resp = client.post(
        "/v1/events/ingest",
        json={"events": [{"source": "test", "payload": {"severity": "low"}}]},
        headers={"X-Service-Token": token},
    )
    assert blocked_resp.status_code == 429

    usage_resp = client.get("/v1/billing/usage", headers={"Authorization": f"Bearer {tenant['accessToken']}"})
    assert usage_resp.status_code == 200
    usage = usage_resp.json()
    assert usage["eventCount"] == 2
    assert usage["monthlyEventQuota"] == 2


def test_quota_isolated_per_tenant(client: TestClient, db_session: Session):
    """A tenant hitting its quota must not affect a different tenant."""
    tenant_a = signup(client, company="Quota Co A", email="owner@quotaA.test")
    tenant_b = signup(client, company="Quota Co B", email="owner@quotaB.test")
    _downgrade_to_tiny_quota(db_session, tenant_a["tenantId"], quota=1)

    token_a = create_service_token(client, owner_token=tenant_a["accessToken"])
    token_b = create_service_token(client, owner_token=tenant_b["accessToken"])

    client.post(
        "/v1/events/ingest",
        json={"events": [{"source": "test", "payload": {"severity": "low"}}]},
        headers={"X-Service-Token": token_a},
    )
    blocked = client.post(
        "/v1/events/ingest",
        json={"events": [{"source": "test", "payload": {"severity": "low"}}]},
        headers={"X-Service-Token": token_a},
    )
    assert blocked.status_code == 429

    # Tenant B, on the default (much larger) free plan, is unaffected.
    allowed = client.post(
        "/v1/events/ingest",
        json={"events": [{"source": "test", "payload": {"severity": "low"}}]},
        headers={"X-Service-Token": token_b},
    )
    assert allowed.status_code == 202

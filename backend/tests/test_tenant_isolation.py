"""FM1 hard requirement: every query is filtered by tenant_id. This module
proves cross-tenant isolation across events, alerts, and cases."""
from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import auth_headers, create_service_token, signup


def _ingest_one_event(client: TestClient, service_token: str, severity: str = "critical") -> str:
    resp = client.post(
        "/v1/events/ingest",
        json={"events": [{"source": "test-suite", "payload": {"severity": severity, "action": "login_failed"}}]},
        headers={"X-Service-Token": service_token},
    )
    assert resp.status_code == 202, resp.text
    return resp.json()["eventIds"][0]


def test_cross_tenant_event_isolation(client: TestClient):
    tenant_a = signup(client, company="Acme Security", email="owner-a@acme.test")
    tenant_b = signup(client, company="Globex Security", email="owner-b@globex.test")

    token_a = create_service_token(client, owner_token=tenant_a["accessToken"])
    _ingest_one_event(client, token_a)

    # Tenant B should see zero events despite tenant A having ingested one.
    resp_b = client.get("/v1/events", headers=auth_headers(tenant_b["accessToken"]))
    assert resp_b.status_code == 200
    assert resp_b.json()["total"] == 0
    assert resp_b.json()["items"] == []

    # Tenant A sees exactly its own event.
    resp_a = client.get("/v1/events", headers=auth_headers(tenant_a["accessToken"]))
    assert resp_a.status_code == 200
    assert resp_a.json()["total"] == 1


def test_cross_tenant_case_isolation(client: TestClient):
    tenant_a = signup(client, company="Acme Security", email="owner-a2@acme.test")
    tenant_b = signup(client, company="Globex Security", email="owner-b2@globex.test")

    create_resp = client.post(
        "/v1/cases",
        json={"title": "Suspicious login spike", "description": "investigate"},
        headers=auth_headers(tenant_a["accessToken"]),
    )
    assert create_resp.status_code == 201, create_resp.text
    case_id = create_resp.json()["id"]

    # Tenant B cannot fetch tenant A's case by ID.
    get_resp = client.get(f"/v1/cases/{case_id}", headers=auth_headers(tenant_b["accessToken"]))
    assert get_resp.status_code == 404

    # Tenant B's case list does not include tenant A's case.
    list_resp = client.get("/v1/cases", headers=auth_headers(tenant_b["accessToken"]))
    assert list_resp.status_code == 200
    assert all(item["id"] != case_id for item in list_resp.json()["items"])

    # Tenant B cannot transition tenant A's case either.
    patch_resp = client.patch(
        f"/v1/cases/{case_id}/status",
        json={"status": "investigating"},
        headers=auth_headers(tenant_b["accessToken"]),
    )
    assert patch_resp.status_code == 404


def test_cross_tenant_alert_promotion_rejected(client: TestClient):
    tenant_a = signup(client, company="Acme Security", email="owner-a3@acme.test")
    tenant_b = signup(client, company="Globex Security", email="owner-b3@globex.test")

    token_a = create_service_token(client, owner_token=tenant_a["accessToken"])
    _ingest_one_event(client, token_a)

    rule_resp = client.post(
        "/v1/detection-rules",
        json={
            "name": "Critical severity",
            "condition": {"field": "severity_hint", "op": "eq", "value": "critical"},
            "severity": "critical",
        },
        headers=auth_headers(tenant_a["accessToken"]),
    )
    assert rule_resp.status_code == 201, rule_resp.text
    rule_id = rule_resp.json()["id"]

    run_resp = client.post(f"/v1/detection-rules/{rule_id}/run", headers=auth_headers(tenant_a["accessToken"]))
    assert run_resp.status_code == 200
    assert run_resp.json()["alertsCreated"] == 1
    alert_id = run_resp.json()["alertIds"][0]

    # Tenant B must not be able to promote tenant A's alert into a case.
    promote_resp = client.post(
        "/v1/alerts/promote",
        json={"alertIds": [alert_id], "title": "Stolen alert"},
        headers=auth_headers(tenant_b["accessToken"]),
    )
    assert promote_resp.status_code == 404

    # And tenant B cannot even read the alert directly.
    get_resp = client.get(f"/v1/alerts/{alert_id}", headers=auth_headers(tenant_b["accessToken"]))
    assert get_resp.status_code == 404

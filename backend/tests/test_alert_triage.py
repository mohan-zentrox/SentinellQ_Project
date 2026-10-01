"""FM6/FM8: alert triage, and the false-positive rate it finally makes real.

Before `PATCH /v1/alerts/{id}` existed, `Alert.status` supported "dismissed" but
nothing could set it, so `falsePositiveRate` was pinned at 0.0 regardless of how
many false positives a tenant had. These tests pin the fix.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import auth_headers, create_rule, create_service_token, ingest, signup, simple_event


def _alert_for(client: TestClient, access: str, service_token: str, **event_kwargs) -> dict:
    ingest(client, service_token=service_token, events=[simple_event(**event_kwargs)])
    alerts = client.get("/v1/alerts", headers=auth_headers(access)).json()
    assert alerts["total"] >= 1
    return alerts["items"][0]


def _setup(client: TestClient, email: str = "owner@acme.test", company: str = "Acme") -> tuple[str, str]:
    owner = signup(client, company=company, email=email)
    access = owner["accessToken"]
    create_rule(client, token=access, condition={"field": "event_action", "op": "eq", "value": "login_failed"})
    return access, create_service_token(client, owner_token=access)


def test_dismiss_alert_records_who_why_and_when(client: TestClient):
    access, service_token = _setup(client)
    alert = _alert_for(client, access, service_token)

    resp = client.patch(
        f"/v1/alerts/{alert['id']}",
        json={"status": "dismissed", "reason": "Known scanner, expected noise."},
        headers=auth_headers(access),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "dismissed"
    assert body["dismissReason"] == "Known scanner, expected noise."
    assert body["dismissedAt"] is not None
    assert body["dismissedByUserId"] is not None


def test_reopening_a_dismissal_clears_the_triage_fields(client: TestClient):
    access, service_token = _setup(client)
    alert = _alert_for(client, access, service_token)

    client.patch(
        f"/v1/alerts/{alert['id']}",
        json={"status": "dismissed", "reason": "mistake"},
        headers=auth_headers(access),
    )
    reopened = client.patch(
        f"/v1/alerts/{alert['id']}",
        json={"status": "open"},
        headers=auth_headers(access),
    ).json()

    assert reopened["status"] == "open"
    assert reopened["dismissedAt"] is None
    assert reopened["dismissReason"] is None


def test_dismissal_moves_the_false_positive_rate(client: TestClient):
    """The whole point: the KPI now measures something."""
    access, service_token = _setup(client)
    # Two separate alerts (two ingests -> two findings).
    ingest(client, service_token=service_token, events=[simple_event(actor="a")])
    ingest(client, service_token=service_token, events=[simple_event(actor="b")])

    before = client.get("/v1/analytics/kpis", headers=auth_headers(access)).json()
    assert before["alertVolume"] == 2
    assert before["falsePositiveRate"] == 0.0

    alerts = client.get("/v1/alerts", headers=auth_headers(access)).json()["items"]
    client.patch(
        f"/v1/alerts/{alerts[0]['id']}",
        json={"status": "dismissed", "reason": "fp"},
        headers=auth_headers(access),
    )

    after = client.get("/v1/analytics/kpis", headers=auth_headers(access)).json()
    assert after["dismissedAlerts"] == 1
    assert after["falsePositiveRate"] == 0.5


def test_promoted_alert_cannot_be_dismissed(client: TestClient):
    """Detaching evidence from a case would leave the case citing an alert the
    analyst can no longer find."""
    access, service_token = _setup(client)
    alert = _alert_for(client, access, service_token)

    promote = client.post(
        "/v1/alerts/promote",
        json={"alertIds": [alert["id"]], "title": "Investigation"},
        headers=auth_headers(access),
    )
    assert promote.status_code == 201

    resp = client.patch(
        f"/v1/alerts/{alert['id']}",
        json={"status": "dismissed"},
        headers=auth_headers(access),
    )
    assert resp.status_code == 409


def test_promoting_the_same_alert_twice_is_rejected(client: TestClient):
    access, service_token = _setup(client)
    alert = _alert_for(client, access, service_token)

    first = client.post(
        "/v1/alerts/promote",
        json={"alertIds": [alert["id"]], "title": "Case one"},
        headers=auth_headers(access),
    )
    assert first.status_code == 201

    second = client.post(
        "/v1/alerts/promote",
        json={"alertIds": [alert["id"]], "title": "Case two"},
        headers=auth_headers(access),
    )
    assert second.status_code == 409


def test_bulk_dismiss_skips_promoted_alerts_rather_than_failing(client: TestClient):
    access, service_token = _setup(client)
    ingest(client, service_token=service_token, events=[simple_event(actor="a")])
    ingest(client, service_token=service_token, events=[simple_event(actor="b")])
    ingest(client, service_token=service_token, events=[simple_event(actor="c")])
    alerts = client.get("/v1/alerts", headers=auth_headers(access)).json()["items"]
    assert len(alerts) == 3

    client.post(
        "/v1/alerts/promote",
        json={"alertIds": [alerts[0]["id"]], "title": "Real incident"},
        headers=auth_headers(access),
    )

    resp = client.patch(
        "/v1/alerts",
        json={"alertIds": [a["id"] for a in alerts], "status": "dismissed", "reason": "noisy rule"},
        headers=auth_headers(access),
    )
    assert resp.status_code == 200
    body = resp.json()
    # Three requested, the promoted one skipped.
    assert body["updated"] == 2


def test_viewer_cannot_triage_alerts(client: TestClient):
    access, service_token = _setup(client)
    alert = _alert_for(client, access, service_token)

    client.post(
        "/v1/tenants/me/users",
        json={"email": "viewer@acme.test", "password": "correct-horse-1", "role": "viewer"},
        headers=auth_headers(access),
    )
    viewer = client.post(
        "/v1/auth/login",
        json={"email": "viewer@acme.test", "password": "correct-horse-1"},
    ).json()

    resp = client.patch(
        f"/v1/alerts/{alert['id']}",
        json={"status": "dismissed"},
        headers=auth_headers(viewer["accessToken"]),
    )
    assert resp.status_code == 403


def test_cross_tenant_alert_triage_is_not_found(client: TestClient):
    access_a, token_a = _setup(client, email="a@acme.test", company="Acme")
    alert = _alert_for(client, access_a, token_a)

    access_b, _ = _setup(client, email="b@globex.test", company="Globex")
    resp = client.patch(
        f"/v1/alerts/{alert['id']}",
        json={"status": "dismissed"},
        headers=auth_headers(access_b),
    )
    assert resp.status_code == 404


def test_alert_detail_inlines_contributing_events(client: TestClient):
    access, service_token = _setup(client)
    alert = _alert_for(client, access, service_token, actor="carol", source_ip="203.0.113.9")

    detail = client.get(f"/v1/alerts/{alert['id']}", headers=auth_headers(access)).json()
    assert len(detail["events"]) == 1
    assert detail["events"][0]["actor"] == "carol"
    assert detail["events"][0]["sourceIp"] == "203.0.113.9"


def test_alert_list_filters(client: TestClient):
    access, service_token = _setup(client)
    ingest(client, service_token=service_token, events=[simple_event(actor="a")])
    ingest(client, service_token=service_token, events=[simple_event(actor="b")])
    alerts = client.get("/v1/alerts", headers=auth_headers(access)).json()["items"]
    client.patch(
        f"/v1/alerts/{alerts[0]['id']}",
        json={"status": "dismissed"},
        headers=auth_headers(access),
    )

    open_only = client.get("/v1/alerts?status=open", headers=auth_headers(access)).json()
    assert open_only["total"] == 1
    dismissed_only = client.get("/v1/alerts?status=dismissed", headers=auth_headers(access)).json()
    assert dismissed_only["total"] == 1
    by_source = client.get("/v1/alerts?detectionSource=rule", headers=auth_headers(access)).json()
    assert by_source["total"] == 2
    by_source_ml = client.get("/v1/alerts?detectionSource=ml", headers=auth_headers(access)).json()
    assert by_source_ml["total"] == 0

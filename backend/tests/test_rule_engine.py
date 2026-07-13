"""FM4: detection rule condition DSL evaluation + Alert creation, both at
the service-layer (unit) and HTTP-API (integration) level."""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.models.event import Event
from app.services.rule_engine import evaluate_condition
from tests.conftest import auth_headers, create_service_token, signup


def _make_event(**overrides) -> Event:
    defaults = dict(
        tenant_id="ten_test",
        source="unit-test",
        raw_payload={},
        event_category="authentication",
        event_action="login_failed",
        severity_hint="high",
        actor="alice",
        target="prod-db",
        source_ip="10.0.0.1",
        normalized={"event": {"category": "authentication"}},
    )
    defaults.update(overrides)
    return Event(**defaults)


def test_leaf_condition_eq():
    event = _make_event(severity_hint="critical")
    assert evaluate_condition({"field": "severity_hint", "op": "eq", "value": "critical"}, event) is True
    assert evaluate_condition({"field": "severity_hint", "op": "eq", "value": "low"}, event) is False


def test_all_and_any_composition():
    event = _make_event(event_category="authentication", event_action="login_failed", severity_hint="high")

    all_condition = {
        "all": [
            {"field": "event_category", "op": "eq", "value": "authentication"},
            {"field": "event_action", "op": "eq", "value": "login_failed"},
        ]
    }
    assert evaluate_condition(all_condition, event) is True

    any_condition = {"any": [{"field": "severity_hint", "op": "eq", "value": "low"}, {"field": "severity_hint", "op": "eq", "value": "high"}]}
    assert evaluate_condition(any_condition, event) is True

    failing_all = {
        "all": [
            {"field": "event_category", "op": "eq", "value": "authentication"},
            {"field": "event_action", "op": "eq", "value": "login_success"},
        ]
    }
    assert evaluate_condition(failing_all, event) is False


def test_rule_engine_creates_alert_via_api(client: TestClient):
    tenant = signup(client, company="Rule Engine Co", email="owner@rulesco.test")
    token = create_service_token(client, owner_token=tenant["accessToken"])

    ingest_resp = client.post(
        "/v1/events/ingest",
        json={
            "events": [
                {"source": "edr", "payload": {"severity": "critical", "category": "malware", "action": "quarantine_failed"}},
                {"source": "edr", "payload": {"severity": "low", "category": "malware", "action": "quarantine_ok"}},
            ]
        },
        headers={"X-Service-Token": token},
    )
    assert ingest_resp.status_code == 202
    critical_event_id, low_event_id = ingest_resp.json()["eventIds"]

    rule_resp = client.post(
        "/v1/detection-rules",
        json={
            "name": "Critical malware event",
            "condition": {"field": "severity_hint", "op": "eq", "value": "critical"},
            "severity": "critical",
        },
        headers=auth_headers(tenant["accessToken"]),
    )
    assert rule_resp.status_code == 201
    rule_id = rule_resp.json()["id"]

    run_resp = client.post(f"/v1/detection-rules/{rule_id}/run", headers=auth_headers(tenant["accessToken"]))
    assert run_resp.status_code == 200
    body = run_resp.json()
    assert body["alertsCreated"] == 1
    alert_id = body["alertIds"][0]

    alert_resp = client.get(f"/v1/alerts/{alert_id}", headers=auth_headers(tenant["accessToken"]))
    assert alert_resp.status_code == 200
    alert = alert_resp.json()
    assert alert["severity"] == "critical"
    assert alert["eventIds"] == [critical_event_id]
    assert low_event_id not in alert["eventIds"]

    # Running the rule again must not create a duplicate alert for the same event.
    rerun_resp = client.post(f"/v1/detection-rules/{rule_id}/run", headers=auth_headers(tenant["accessToken"]))
    assert rerun_resp.status_code == 200
    assert rerun_resp.json()["alertsCreated"] == 0

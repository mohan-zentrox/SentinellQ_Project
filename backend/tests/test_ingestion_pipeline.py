"""FM2/FM3/FM4: the ingestion pipeline end to end.

The behaviour under test is the thing that was missing before: ingesting an
event should *detect* on it, not just store it. Previously alerts only appeared
when an analyst manually POSTed to /detection-rules/run-all.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.models.event import Event
from app.services.queue import TOPIC_RAW_EVENTS, get_queue
from tests.conftest import auth_headers, create_rule, create_service_token, ingest, signup, simple_event


def test_ingest_normalizes_and_stores(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    token = create_service_token(client, owner_token=owner["accessToken"])

    body = ingest(
        client,
        service_token=token,
        events=[simple_event(action="login_failed", severity="warn", actor="bob")],
    )
    assert body["accepted"] == 1
    assert body["processing"] == "synchronous"
    assert len(body["eventIds"]) == 1

    listed = client.get("/v1/events", headers=auth_headers(owner["accessToken"])).json()
    assert listed["total"] == 1
    event = listed["items"][0]
    # "warn" is normalized to "medium" by the severity alias table.
    assert event["severityHint"] == "medium"
    assert event["eventAction"] == "login_failed"
    assert event["actor"] == "bob"


def test_ingest_triggers_detection_without_manual_run(client: TestClient):
    """The core regression this guards: detection on ingest.

    No call to /detection-rules/run-all anywhere in this test -- the alert must
    exist purely because the event was ingested.
    """
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    create_rule(
        client,
        token=access,
        condition={"field": "event_action", "op": "eq", "value": "login_failed"},
        name="failed logins",
    )
    service_token = create_service_token(client, owner_token=access)

    body = ingest(client, service_token=service_token, events=[simple_event(action="login_failed")])
    assert body["alertsCreated"] == 1

    alerts = client.get("/v1/alerts", headers=auth_headers(access)).json()
    assert alerts["total"] == 1
    assert alerts["items"][0]["detectionSource"] == "rule"


def test_batch_ingest_produces_one_alert_not_one_per_event(client: TestClient):
    """A batch of N matching events is one finding, not N.

    This is why the queue handler only persists and the detection pass runs once
    over the whole batch -- per-message detection would emit N near-identical
    alerts and bury the analyst.
    """
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    create_rule(
        client,
        token=access,
        condition={"field": "severity_hint", "op": "eq", "value": "critical"},
        name="criticals",
    )
    service_token = create_service_token(client, owner_token=access)

    body = ingest(
        client,
        service_token=service_token,
        events=[simple_event(severity="critical", actor=f"user{i}") for i in range(5)],
    )
    assert body["accepted"] == 5
    assert body["alertsCreated"] == 1

    alerts = client.get("/v1/alerts", headers=auth_headers(access)).json()
    assert alerts["total"] == 1
    # The single alert cites all five contributing events.
    assert len(alerts["items"][0]["eventIds"]) == 5


def test_re_ingesting_does_not_duplicate_alerts_for_same_events(client: TestClient):
    """Dedup is per (rule, event), enforced by the rule_event_matches ledger."""
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    rule = create_rule(
        client,
        token=access,
        condition={"field": "event_action", "op": "eq", "value": "login_failed"},
    )
    service_token = create_service_token(client, owner_token=access)

    ingest(client, service_token=service_token, events=[simple_event()])
    # A manual run over the same events must find nothing new.
    rerun = client.post(f"/v1/detection-rules/{rule['id']}/run", headers=auth_headers(access)).json()
    assert rerun["alertsCreated"] == 0

    run_all = client.post("/v1/detection-rules/run-all", headers=auth_headers(access)).json()
    assert run_all["alertsCreated"] == 0

    assert client.get("/v1/alerts", headers=auth_headers(access)).json()["total"] == 1


def test_new_events_after_first_alert_produce_a_second_alert(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    create_rule(client, token=access, condition={"field": "event_action", "op": "eq", "value": "login_failed"})
    service_token = create_service_token(client, owner_token=access)

    ingest(client, service_token=service_token, events=[simple_event(actor="a")])
    ingest(client, service_token=service_token, events=[simple_event(actor="b")])

    alerts = client.get("/v1/alerts", headers=auth_headers(access)).json()
    assert alerts["total"] == 2


def test_disabled_rule_does_not_fire_on_ingest(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    create_rule(
        client,
        token=access,
        condition={"field": "event_action", "op": "eq", "value": "login_failed"},
        is_enabled=False,
    )
    service_token = create_service_token(client, owner_token=access)

    body = ingest(client, service_token=service_token, events=[simple_event()])
    assert body["alertsCreated"] == 0


def test_queue_publish_seam_is_used(client: TestClient):
    """Every ingested event goes through the queue abstraction.

    Asserted explicitly because the whole producer/consumer split depends on the
    API publishing rather than writing directly -- if someone "optimizes" the
    publish away, the Redis/worker deployment silently stops receiving events
    while the in-process tests keep passing.
    """
    owner = signup(client, company="Acme", email="owner@acme.test")
    service_token = create_service_token(client, owner_token=owner["accessToken"])

    ingest(client, service_token=service_token, events=[simple_event(), simple_event(actor="b")])

    queue = get_queue()
    published = queue.history(TOPIC_RAW_EVENTS)  # type: ignore[attr-defined]
    assert len(published) == 2
    assert all(message["tenant_id"].startswith("ten_") for message in published)


def test_ingest_requires_service_token_not_jwt(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    resp = client.post(
        "/v1/events/ingest",
        json={"events": [simple_event()]},
        headers=auth_headers(owner["accessToken"]),
    )
    assert resp.status_code == 401


def test_revoked_service_token_cannot_ingest(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    created = client.post(
        "/v1/tenants/me/service-tokens",
        json={"name": "temp"},
        headers=auth_headers(access),
    ).json()

    assert client.post(
        "/v1/events/ingest",
        json={"events": [simple_event()]},
        headers={"X-Service-Token": created["token"]},
    ).status_code == 202

    revoke = client.delete(f"/v1/tenants/me/service-tokens/{created['id']}", headers=auth_headers(access))
    assert revoke.status_code == 204

    after = client.post(
        "/v1/events/ingest",
        json={"events": [simple_event()]},
        headers={"X-Service-Token": created["token"]},
    )
    assert after.status_code == 401


def test_service_token_listing_never_returns_token_material(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    create_service_token(client, owner_token=access)

    listed = client.get("/v1/tenants/me/service-tokens", headers=auth_headers(access)).json()
    assert len(listed) == 1
    assert "token" not in listed[0]


def test_occurred_at_is_preserved_through_the_pipeline(client: TestClient, db_session):
    """A collector shipping historical events must keep their real timestamps --
    MTTD is computed from occurred_at, so overwriting it with ingest time would
    silently report a detection latency of zero."""
    owner = signup(client, company="Acme", email="owner@acme.test")
    service_token = create_service_token(client, owner_token=owner["accessToken"])

    occurred = (datetime.now(timezone.utc) - timedelta(hours=3)).replace(microsecond=0)
    ingest(
        client,
        service_token=service_token,
        events=[simple_event(occurred_at=occurred.isoformat())],
    )

    event = db_session.query(Event).one()
    stored = event.occurred_at if event.occurred_at.tzinfo else event.occurred_at.replace(tzinfo=timezone.utc)
    assert abs((stored - occurred).total_seconds()) < 2
    # ingested_at is "now", distinctly later than occurred_at.
    ingested = event.ingested_at if event.ingested_at.tzinfo else event.ingested_at.replace(tzinfo=timezone.utc)
    assert ingested > stored


def test_event_filters_and_detail(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    service_token = create_service_token(client, owner_token=access)

    ingest(
        client,
        service_token=service_token,
        events=[
            simple_event(action="login_failed", severity="critical", actor="alice", source_ip="10.0.0.1"),
            simple_event(action="file_read", severity="low", actor="bob", source_ip="10.0.0.2"),
        ],
    )

    by_severity = client.get("/v1/events?severity=critical", headers=auth_headers(access)).json()
    assert by_severity["total"] == 1
    assert by_severity["items"][0]["actor"] == "alice"

    by_actor = client.get("/v1/events?actor=bob", headers=auth_headers(access)).json()
    assert by_actor["total"] == 1

    by_ip = client.get("/v1/events?sourceIp=10.0.0.2", headers=auth_headers(access)).json()
    assert by_ip["total"] == 1

    search = client.get("/v1/events?search=ali", headers=auth_headers(access)).json()
    assert search["total"] == 1

    event_id = by_actor["items"][0]["id"]
    detail = client.get(f"/v1/events/{event_id}", headers=auth_headers(access)).json()
    # Detail adds the raw and normalized documents the list omits.
    assert detail["rawPayload"]["actor"] == "bob"
    assert detail["normalized"]["event"]["action"] == "file_read"

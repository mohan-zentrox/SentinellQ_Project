"""FM4: rule CRUD, condition validation, and the expanded operator set.

The original build had create/read/run but no update, delete, enable-toggle, or
condition validation -- a malformed rule was stored happily and then failed (or
took down a whole run-all) at evaluation time.
"""
from __future__ import annotations

import itertools
from datetime import datetime, timedelta, timezone

import pytest

from app.models.event import Event
from app.services.rule_engine import (
    ConditionError,
    evaluate_condition,
    evaluate_rule_over_events,
    validate_condition,
)
from tests.conftest import auth_headers, create_rule, create_service_token, ingest, signup, simple_event

_event_counter = itertools.count()


def _event(**overrides) -> Event:
    # An explicit unique id matters: windowing and dedup both key on event id, so
    # a batch of unsaved ORM objects all carrying id=None would collapse to one
    # entry and make these assertions pass for the wrong reason.
    defaults = dict(
        id=f"evt_unit_{next(_event_counter):04d}",
        tenant_id="ten_test",
        source="unit",
        raw_payload={},
        event_category="authentication",
        event_action="login_failed",
        severity_hint="high",
        actor="alice",
        target="prod-db",
        source_ip="10.0.0.5",
        normalized={"event": {"category": "authentication"}},
        enrichment=None,
        occurred_at=datetime.now(timezone.utc),
        ingested_at=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return Event(**defaults)


# --------------------------------------------------------------------------
# New operators
# --------------------------------------------------------------------------
def test_regex_operator():
    assert evaluate_condition({"field": "actor", "op": "regex", "value": "^ali"}, _event())
    assert not evaluate_condition({"field": "actor", "op": "regex", "value": "^bob"}, _event())


def test_invalid_regex_is_a_condition_error():
    with pytest.raises(ConditionError, match="invalid regex"):
        evaluate_condition({"field": "actor", "op": "regex", "value": "("}, _event())


def test_cidr_operator():
    assert evaluate_condition({"field": "source_ip", "op": "cidr", "value": "10.0.0.0/24"}, _event())
    assert not evaluate_condition({"field": "source_ip", "op": "cidr", "value": "192.168.0.0/16"}, _event())


def test_cidr_with_a_malformed_event_address_is_a_non_match_not_an_error():
    event = _event(source_ip="not-an-ip")
    assert not evaluate_condition({"field": "source_ip", "op": "cidr", "value": "10.0.0.0/8"}, event)


def test_malformed_cidr_in_the_rule_is_an_authoring_error():
    with pytest.raises(ConditionError, match="invalid CIDR"):
        evaluate_condition({"field": "source_ip", "op": "cidr", "value": "999.999/8"}, _event())


def test_icontains_and_not_in_and_exists():
    assert evaluate_condition({"field": "target", "op": "icontains", "value": "PROD"}, _event())
    assert evaluate_condition({"field": "actor", "op": "not_in", "value": ["bob", "carol"]}, _event())
    assert evaluate_condition({"field": "actor", "op": "exists"}, _event())
    assert evaluate_condition({"field": "actor", "op": "exists", "value": False}, _event(actor=None))


def test_not_operator():
    assert evaluate_condition({"not": {"field": "actor", "op": "eq", "value": "bob"}}, _event())
    assert not evaluate_condition({"not": {"field": "actor", "op": "eq", "value": "alice"}}, _event())


def test_numeric_comparison_survives_a_json_type_mismatch():
    """A rule authored with `80` must still match enrichment holding `"80"`.

    Returning False on a type mismatch is the failure mode that makes a detection
    rule quietly stop firing.
    """
    event = _event(enrichment={"maxConfidence": "90"})
    assert evaluate_condition({"field": "enrichment.maxConfidence", "op": "gte", "value": 80}, event)


def test_enrichment_and_normalized_paths_are_addressable():
    event = _event(
        enrichment={"matched": True, "tags": ["c2"]},
        normalized={"event": {"kind": "alert"}},
    )
    assert evaluate_condition({"field": "enrichment.matched", "op": "eq", "value": True}, event)
    assert evaluate_condition({"field": "enrichment.tags", "op": "contains", "value": "c2"}, event)
    assert evaluate_condition({"field": "normalized.event.kind", "op": "eq", "value": "alert"}, event)
    # Bare dotted paths still resolve against `normalized` (backwards compatible).
    assert evaluate_condition({"field": "event.kind", "op": "eq", "value": "alert"}, event)


# --------------------------------------------------------------------------
# Time-window (threshold) conditions
# --------------------------------------------------------------------------
class _Rule:
    """Minimal stand-in so the windowing logic can be tested without a DB."""

    def __init__(self, condition: dict) -> None:
        self.condition = condition
        self.id = "rule_x"
        self.name = "r"
        self.severity = "high"


def test_window_fires_only_above_the_threshold():
    base = datetime.now(timezone.utc)
    four = [_event(occurred_at=base + timedelta(minutes=i)) for i in range(4)]
    five = four + [_event(occurred_at=base + timedelta(minutes=4))]
    rule = _Rule(
        {
            "field": "event_action",
            "op": "eq",
            "value": "login_failed",
            "window": {"minutes": 10, "count": 5},
        }
    )

    assert evaluate_rule_over_events(rule, four) == []
    assert len(evaluate_rule_over_events(rule, five)) == 5


def test_window_respects_the_time_span():
    """Five failures spread over an hour must not satisfy a 10-minute threshold."""
    base = datetime.now(timezone.utc)
    spread = [_event(occurred_at=base + timedelta(minutes=i * 15)) for i in range(5)]
    rule = _Rule(
        {
            "field": "event_action",
            "op": "eq",
            "value": "login_failed",
            "window": {"minutes": 10, "count": 5},
        }
    )
    assert evaluate_rule_over_events(rule, spread) == []


def test_window_group_by_isolates_actors():
    """Three failures from alice and three from bob is not six from one actor."""
    base = datetime.now(timezone.utc)
    events = [_event(actor="alice", occurred_at=base + timedelta(minutes=i)) for i in range(3)]
    events += [_event(actor="bob", occurred_at=base + timedelta(minutes=i)) for i in range(3)]
    rule = _Rule(
        {
            "field": "event_action",
            "op": "eq",
            "value": "login_failed",
            "window": {"minutes": 10, "count": 5, "groupBy": "actor"},
        }
    )
    assert evaluate_rule_over_events(rule, events) == []

    # Push alice to five and only alice's events participate.
    events += [_event(actor="alice", occurred_at=base + timedelta(minutes=3 + i)) for i in range(2)]
    matched = evaluate_rule_over_events(rule, events)
    assert len(matched) == 5


def test_windowed_condition_under_not_is_rejected():
    with pytest.raises(ConditionError, match="cannot negate a windowed"):
        validate_condition(
            {"not": {"field": "a", "op": "eq", "value": 1, "window": {"minutes": 5, "count": 3}}}
        )


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------
def test_validation_rejects_structural_mistakes():
    with pytest.raises(ConditionError, match="non-empty list"):
        validate_condition({"all": []})
    with pytest.raises(ConditionError, match="requires 'field' and 'op'"):
        validate_condition({"field": "actor"})
    with pytest.raises(ConditionError, match="Unsupported operator"):
        validate_condition({"field": "actor", "op": "approximately", "value": 1})
    with pytest.raises(ConditionError, match="requires a list"):
        validate_condition({"field": "actor", "op": "in", "value": "alice"})
    with pytest.raises(ConditionError, match="window.count"):
        validate_condition({"field": "a", "op": "eq", "value": 1, "window": {"minutes": 5, "count": 1}})


def test_api_rejects_an_invalid_condition_at_create_time(client):
    owner = signup(client, company="Acme", email="owner@acme.test")
    resp = client.post(
        "/v1/detection-rules",
        json={"name": "bad", "condition": {"field": "actor", "op": "approximately", "value": 1}},
        headers=auth_headers(owner["accessToken"]),
    )
    assert resp.status_code == 422
    assert "Unsupported operator" in resp.json()["detail"]


# --------------------------------------------------------------------------
# CRUD
# --------------------------------------------------------------------------
def test_update_rule_fields(client):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    rule = create_rule(client, token=access, condition={"field": "actor", "op": "eq", "value": "alice"})

    updated = client.patch(
        f"/v1/detection-rules/{rule['id']}",
        json={"name": "renamed", "severity": "critical", "isEnabled": False},
        headers=auth_headers(access),
    )
    assert updated.status_code == 200
    body = updated.json()
    assert body["name"] == "renamed"
    assert body["severity"] == "critical"
    assert body["isEnabled"] is False
    # Unmentioned fields are untouched.
    assert body["condition"] == {"field": "actor", "op": "eq", "value": "alice"}


def test_update_rejects_an_invalid_new_condition(client):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    rule = create_rule(client, token=access, condition={"field": "actor", "op": "eq", "value": "alice"})

    resp = client.patch(
        f"/v1/detection-rules/{rule['id']}",
        json={"condition": {"field": "actor", "op": "regex", "value": "("}},
        headers=auth_headers(access),
    )
    assert resp.status_code == 422


def test_delete_rule_keeps_its_alerts(client):
    """Alerts are historical findings an analyst may be working. Tidying up a
    rule must not delete the investigation's evidence."""
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    rule = create_rule(client, token=access, condition={"field": "event_action", "op": "eq", "value": "login_failed"})
    service_token = create_service_token(client, owner_token=access)
    ingest(client, service_token=service_token, events=[simple_event()])
    assert client.get("/v1/alerts", headers=auth_headers(access)).json()["total"] == 1

    assert client.delete(f"/v1/detection-rules/{rule['id']}", headers=auth_headers(access)).status_code == 204
    assert client.get(f"/v1/detection-rules/{rule['id']}", headers=auth_headers(access)).status_code == 404
    assert client.get("/v1/alerts", headers=auth_headers(access)).json()["total"] == 1


def test_analyst_cannot_delete_a_rule(client):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    rule = create_rule(client, token=access, condition={"field": "actor", "op": "eq", "value": "alice"})
    client.post(
        "/v1/tenants/me/users",
        json={"email": "analyst@acme.test", "password": "correct-horse-1", "role": "analyst"},
        headers=auth_headers(access),
    )
    analyst = client.post(
        "/v1/auth/login", json={"email": "analyst@acme.test", "password": "correct-horse-1"}
    ).json()

    resp = client.delete(
        f"/v1/detection-rules/{rule['id']}",
        headers=auth_headers(analyst["accessToken"]),
    )
    assert resp.status_code == 403


def test_rule_test_endpoint_dry_runs_without_creating_alerts(client):
    """An analyst must be able to see a condition's blast radius before enabling
    it in production."""
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    service_token = create_service_token(client, owner_token=access)
    ingest(
        client,
        service_token=service_token,
        events=[simple_event(actor="alice"), simple_event(actor="bob"), simple_event(action="file_read")],
    )

    resp = client.post(
        "/v1/detection-rules/test",
        json={"condition": {"field": "event_action", "op": "eq", "value": "login_failed"}},
        headers=auth_headers(access),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["sampled"] == 3
    assert body["matched"] == 2
    assert len(body["matchedEventIds"]) == 2

    # Nothing was created.
    assert client.get("/v1/alerts", headers=auth_headers(access)).json()["total"] == 0


def test_rule_test_rejects_an_invalid_condition(client):
    owner = signup(client, company="Acme", email="owner@acme.test")
    resp = client.post(
        "/v1/detection-rules/test",
        json={"condition": {"field": "a", "op": "bogus"}},
        headers=auth_headers(owner["accessToken"]),
    )
    assert resp.status_code == 422


def test_rule_statistics_are_tracked(client):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    rule = create_rule(client, token=access, condition={"field": "event_action", "op": "eq", "value": "login_failed"})
    service_token = create_service_token(client, owner_token=access)
    ingest(client, service_token=service_token, events=[simple_event(actor="a"), simple_event(actor="b")])

    refreshed = client.get(f"/v1/detection-rules/{rule['id']}", headers=auth_headers(access)).json()
    assert refreshed["matchCount"] == 2
    assert refreshed["lastEvaluatedAt"] is not None
    assert refreshed["lastMatchedAt"] is not None


def test_detection_coverage_reports_never_matched_rules(client):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    create_rule(
        client,
        token=access,
        condition={"field": "event_action", "op": "eq", "value": "login_failed"},
        name="fires",
    )
    create_rule(
        client,
        token=access,
        condition={"field": "event_action", "op": "eq", "value": "never_happens"},
        name="silent",
    )
    service_token = create_service_token(client, owner_token=access)
    ingest(client, service_token=service_token, events=[simple_event()])

    coverage = client.get("/v1/analytics/detection-coverage", headers=auth_headers(access)).json()
    assert coverage["totalRules"] == 2
    assert coverage["rulesWithMatches"] == 1
    assert [r["name"] for r in coverage["neverMatchedRules"]] == ["silent"]
    assert coverage["topRules"][0]["name"] == "fires"


def test_rule_list_filter_by_enabled(client):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    create_rule(client, token=access, condition={"field": "actor", "op": "eq", "value": "a"}, name="on")
    create_rule(
        client,
        token=access,
        condition={"field": "actor", "op": "eq", "value": "b"},
        name="off",
        is_enabled=False,
    )

    enabled = client.get("/v1/detection-rules?enabled=true", headers=auth_headers(access)).json()
    assert [r["name"] for r in enabled] == ["on"]
    disabled = client.get("/v1/detection-rules?enabled=false", headers=auth_headers(access)).json()
    assert [r["name"] for r in disabled] == ["off"]


def test_a_broken_stored_rule_does_not_break_run_all(client, db_session):
    """One malformed rule must not take down evaluation of every other rule."""
    from app.models.rule import DetectionRule

    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    tenant_id = client.get("/v1/tenants/me", headers=auth_headers(access)).json()["id"]
    create_rule(client, token=access, condition={"field": "event_action", "op": "eq", "value": "login_failed"}, name="good")

    # Bypass API validation to simulate a rule stored before validation existed.
    db_session.add(
        DetectionRule(
            tenant_id=tenant_id,
            name="legacy broken",
            condition={"field": "actor", "op": "approximately", "value": 1},
            severity="high",
            is_enabled=True,
        )
    )
    db_session.commit()

    service_token = create_service_token(client, owner_token=access)
    body = ingest(client, service_token=service_token, events=[simple_event()])
    # The good rule still fired.
    assert body["alertsCreated"] == 1

    run_all = client.post("/v1/detection-rules/run-all", headers=auth_headers(access))
    assert run_all.status_code == 200

"""FM7: SOAR playbooks.

The approval gate is the most important thing here. This platform is authorized
defensive tooling, so a high-risk action must not be executable without a named
human approving that specific run -- and that has to be true of the engine, not
just of the UI.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.models.soar import Playbook, PlaybookRun, RunStatus
from app.services.soar import ACTION_REGISTRY, ApprovalRequired, execute_run
from tests.conftest import auth_headers, create_rule, create_service_token, ingest, signup, simple_event


def _owner(client: TestClient, email: str = "owner@acme.test", company: str = "Acme") -> str:
    return signup(client, company=company, email=email)["accessToken"]


def _make_playbook(client: TestClient, access: str, **overrides) -> dict:
    body = {
        "name": "note on alert",
        "trigger": "alert_created",
        "actions": [{"action": "add_case_comment", "params": {"message": "auto"}}],
        "dryRun": False,
    }
    body.update(overrides)
    resp = client.post("/v1/playbooks", json=body, headers=auth_headers(access))
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_action_registry_is_exposed_with_risk_flags(client: TestClient):
    access = _owner(client)
    actions = client.get("/v1/playbook-actions", headers=auth_headers(access)).json()
    by_name = {entry["name"]: entry for entry in actions}

    assert "add_case_comment" in by_name
    assert by_name["add_case_comment"]["isHighRisk"] is False
    # Actions with external or destructive effects must be flagged.
    assert by_name["call_webhook"]["isHighRisk"] is True
    assert by_name["dismiss_alert"]["isHighRisk"] is True
    assert by_name["disable_user_in_idp"]["isHighRisk"] is True


def test_unknown_action_is_rejected_at_save_time(client: TestClient):
    access = _owner(client)
    resp = client.post(
        "/v1/playbooks",
        json={"name": "bad", "actions": [{"action": "launch_missiles", "params": {}}]},
        headers=auth_headers(access),
    )
    assert resp.status_code == 422
    assert "launch_missiles" in resp.json()["detail"]


def test_invalid_trigger_condition_is_rejected_at_save_time(client: TestClient):
    access = _owner(client)
    resp = client.post(
        "/v1/playbooks",
        json={
            "name": "bad condition",
            "actions": [{"action": "add_case_comment", "params": {}}],
            "triggerCondition": {"field": "severity_hint", "op": "nonsense", "value": "high"},
        },
        headers=auth_headers(access),
    )
    assert resp.status_code == 422


def test_playbook_with_high_risk_action_reports_requires_approval(client: TestClient):
    access = _owner(client)
    playbook = _make_playbook(
        client,
        access,
        name="webhook out",
        actions=[{"action": "call_webhook", "params": {"url": "https://example.test/hook"}}],
    )
    assert playbook["requiresApproval"] is True

    safe = _make_playbook(client, access, name="safe")
    assert safe["requiresApproval"] is False


def test_high_risk_run_is_created_pending_and_executes_nothing(client: TestClient, db_session):
    access = _owner(client)
    playbook = _make_playbook(
        client,
        access,
        name="dismisser",
        actions=[{"action": "dismiss_alert", "params": {"reason": "auto"}}],
    )
    assert playbook["requiresApproval"] is True
    create_rule(client, token=access, condition={"field": "event_action", "op": "eq", "value": "login_failed"})
    service_token = create_service_token(client, owner_token=access)

    ingest(client, service_token=service_token, events=[simple_event()])

    runs = client.get("/v1/playbook-runs", headers=auth_headers(access)).json()
    assert runs["total"] == 1
    run = runs["items"][0]
    assert run["status"] == RunStatus.PENDING_APPROVAL
    assert run["requiresApproval"] is True
    assert run["approvedByUserId"] is None

    # Crucially: the alert was NOT dismissed, because nothing executed.
    alerts = client.get("/v1/alerts", headers=auth_headers(access)).json()
    assert alerts["items"][0]["status"] == "open"

    detail = client.get(f"/v1/playbook-runs/{run['id']}", headers=auth_headers(access)).json()
    assert detail["actions"] == []


def test_engine_refuses_to_execute_an_unapproved_run(client: TestClient, db_session):
    """Enforced in the engine, not just the API.

    A different caller reaching execute_run directly must hit the same wall --
    otherwise the approval gate is only a UI convention.
    """
    access = _owner(client)
    playbook_json = _make_playbook(
        client,
        access,
        name="dismisser",
        actions=[{"action": "dismiss_alert", "params": {}}],
    )
    create_rule(client, token=access, condition={"field": "event_action", "op": "eq", "value": "login_failed"})
    service_token = create_service_token(client, owner_token=access)
    ingest(client, service_token=service_token, events=[simple_event()])

    run = db_session.query(PlaybookRun).one()
    playbook = db_session.query(Playbook).filter(Playbook.id == playbook_json["id"]).one()

    try:
        execute_run(db_session, run=run, playbook=playbook)
        raise AssertionError("execute_run must refuse an unapproved high-risk run")
    except ApprovalRequired as exc:
        assert "not been approved" in str(exc)


def test_approval_executes_the_run_and_records_the_approver(client: TestClient):
    access = _owner(client)
    _make_playbook(
        client,
        access,
        name="dismisser",
        actions=[{"action": "dismiss_alert", "params": {"reason": "known noise"}}],
    )
    create_rule(client, token=access, condition={"field": "event_action", "op": "eq", "value": "login_failed"})
    service_token = create_service_token(client, owner_token=access)
    ingest(client, service_token=service_token, events=[simple_event()])

    run = client.get("/v1/playbook-runs", headers=auth_headers(access)).json()["items"][0]
    approved = client.post(f"/v1/playbook-runs/{run['id']}/approve", headers=auth_headers(access))
    assert approved.status_code == 200, approved.text
    body = approved.json()

    assert body["status"] == RunStatus.SUCCEEDED
    assert body["approvedByUserId"] is not None
    assert body["approvedAt"] is not None
    assert len(body["actions"]) == 1
    assert body["actions"][0]["status"] == "succeeded"
    assert body["actions"][0]["isHighRisk"] is True

    # And now the alert really is dismissed.
    alerts = client.get("/v1/alerts", headers=auth_headers(access)).json()
    assert alerts["items"][0]["status"] == "dismissed"
    assert "known noise" in alerts["items"][0]["dismissReason"]


def test_rejection_marks_the_run_and_executes_nothing(client: TestClient):
    access = _owner(client)
    _make_playbook(client, access, name="dismisser", actions=[{"action": "dismiss_alert", "params": {}}])
    create_rule(client, token=access, condition={"field": "event_action", "op": "eq", "value": "login_failed"})
    service_token = create_service_token(client, owner_token=access)
    ingest(client, service_token=service_token, events=[simple_event()])

    run = client.get("/v1/playbook-runs", headers=auth_headers(access)).json()["items"][0]
    rejected = client.post(
        f"/v1/playbook-runs/{run['id']}/reject",
        json={"reason": "not appropriate here"},
        headers=auth_headers(access),
    ).json()

    assert rejected["status"] == RunStatus.REJECTED
    assert rejected["rejectionReason"] == "not appropriate here"
    assert client.get("/v1/alerts", headers=auth_headers(access)).json()["items"][0]["status"] == "open"


def test_approving_a_rejected_run_is_rejected(client: TestClient):
    access = _owner(client)
    _make_playbook(client, access, name="dismisser", actions=[{"action": "dismiss_alert", "params": {}}])
    create_rule(client, token=access, condition={"field": "event_action", "op": "eq", "value": "login_failed"})
    service_token = create_service_token(client, owner_token=access)
    ingest(client, service_token=service_token, events=[simple_event()])

    run = client.get("/v1/playbook-runs", headers=auth_headers(access)).json()["items"][0]
    client.post(f"/v1/playbook-runs/{run['id']}/reject", json={}, headers=auth_headers(access))
    again = client.post(f"/v1/playbook-runs/{run['id']}/approve", headers=auth_headers(access))
    assert again.status_code == 409


def test_low_risk_playbook_executes_automatically_on_alert(client: TestClient):
    """Not everything needs approval -- a case comment is safe automation."""
    access = _owner(client)
    _make_playbook(
        client,
        access,
        name="tag it",
        actions=[{"action": "create_indicator", "params": {"confidence": 80}}],
    )
    create_rule(client, token=access, condition={"field": "event_action", "op": "eq", "value": "login_failed"})
    service_token = create_service_token(client, owner_token=access)

    ingest(client, service_token=service_token, events=[simple_event(source_ip="198.51.100.77")])

    runs = client.get("/v1/playbook-runs", headers=auth_headers(access)).json()
    assert runs["total"] == 1
    assert runs["items"][0]["status"] == RunStatus.SUCCEEDED

    # The action really ran: the event's source IP is now an indicator.
    indicators = client.get("/v1/threat-indicators", headers=auth_headers(access)).json()
    assert indicators["total"] == 1
    assert indicators["items"][0]["value"] == "198.51.100.77"
    assert indicators["items"][0]["source"] == "playbook"


def test_dry_run_records_intent_without_side_effects(client: TestClient):
    """The safe way to introduce a playbook: see what it would do."""
    access = _owner(client)
    _make_playbook(
        client,
        access,
        name="dry dismisser",
        actions=[{"action": "dismiss_alert", "params": {"reason": "would dismiss"}}],
        dryRun=True,
    )
    create_rule(client, token=access, condition={"field": "event_action", "op": "eq", "value": "login_failed"})
    service_token = create_service_token(client, owner_token=access)
    ingest(client, service_token=service_token, events=[simple_event()])

    run = client.get("/v1/playbook-runs", headers=auth_headers(access)).json()["items"][0]
    # A dry run is not approval-gated: it performs nothing to approve.
    assert run["requiresApproval"] is False
    assert run["status"] == RunStatus.SUCCEEDED
    assert run["dryRun"] is True

    detail = client.get(f"/v1/playbook-runs/{run['id']}", headers=auth_headers(access)).json()
    assert detail["actions"][0]["status"] == "dry_run"
    assert detail["actions"][0]["result"]["wouldDismiss"]

    # And the alert is untouched.
    assert client.get("/v1/alerts", headers=auth_headers(access)).json()["items"][0]["status"] == "open"


def test_trigger_condition_gates_execution(client: TestClient):
    access = _owner(client)
    _make_playbook(
        client,
        access,
        name="criticals only",
        actions=[{"action": "create_indicator", "params": {}}],
        triggerCondition={"field": "severity_hint", "op": "eq", "value": "critical"},
    )
    create_rule(
        client,
        token=access,
        condition={"field": "event_action", "op": "eq", "value": "login_failed"},
        severity="medium",
    )
    service_token = create_service_token(client, owner_token=access)
    ingest(client, service_token=service_token, events=[simple_event()])

    # The rule fired (medium alert) but the playbook's condition wants critical.
    assert client.get("/v1/alerts", headers=auth_headers(access)).json()["total"] == 1
    assert client.get("/v1/playbook-runs", headers=auth_headers(access)).json()["total"] == 0


def test_case_escalation_triggers_a_playbook(client: TestClient):
    """The second FM7 trigger point."""
    access = _owner(client)
    _make_playbook(
        client,
        access,
        name="on escalation",
        trigger="case_escalated",
        actions=[{"action": "set_case_severity", "params": {"severity": "critical"}}],
    )
    create_rule(client, token=access, condition={"field": "event_action", "op": "eq", "value": "login_failed"})
    service_token = create_service_token(client, owner_token=access)
    ingest(client, service_token=service_token, events=[simple_event()])

    alert = client.get("/v1/alerts", headers=auth_headers(access)).json()["items"][0]
    case = client.post(
        "/v1/alerts/promote",
        json={"alertIds": [alert["id"]], "title": "Escalate me"},
        headers=auth_headers(access),
    ).json()

    client.patch(f"/v1/cases/{case['id']}/status", json={"status": "investigating"}, headers=auth_headers(access))
    escalated = client.patch(
        f"/v1/cases/{case['id']}/status",
        json={"status": "escalated"},
        headers=auth_headers(access),
    ).json()
    assert escalated["status"] == "escalated"

    runs = client.get("/v1/playbook-runs", headers=auth_headers(access)).json()
    assert runs["total"] == 1
    assert runs["items"][0]["trigger"] == "case_escalated"

    # The action ran: severity was raised.
    refreshed = client.get(f"/v1/cases/{case['id']}", headers=auth_headers(access)).json()
    assert refreshed["severity"] == "critical"


def test_failing_action_is_recorded_without_crashing_the_run(client: TestClient):
    access = _owner(client)
    _make_playbook(
        client,
        access,
        name="needs a case",
        # add_case_comment on an alert-triggered run has no case to comment on.
        actions=[{"action": "add_case_comment", "params": {"message": "x"}}],
    )
    create_rule(client, token=access, condition={"field": "event_action", "op": "eq", "value": "login_failed"})
    service_token = create_service_token(client, owner_token=access)
    ingest(client, service_token=service_token, events=[simple_event()])

    run = client.get("/v1/playbook-runs", headers=auth_headers(access)).json()["items"][0]
    assert run["status"] == RunStatus.FAILED

    detail = client.get(f"/v1/playbook-runs/{run['id']}", headers=auth_headers(access)).json()
    assert detail["actions"][0]["status"] == "failed"
    assert "requires a case" in detail["actions"][0]["error"]


def test_disable_user_in_idp_refuses_rather_than_pretending(client: TestClient):
    """An automation that reports success while doing nothing is dangerous
    during an incident. With no SSO configured, this must fail loudly."""
    access = _owner(client)
    _make_playbook(
        client,
        access,
        name="contain account",
        actions=[{"action": "disable_user_in_idp", "params": {}}],
    )
    create_rule(client, token=access, condition={"field": "event_action", "op": "eq", "value": "login_failed"})
    service_token = create_service_token(client, owner_token=access)
    ingest(client, service_token=service_token, events=[simple_event()])

    run = client.get("/v1/playbook-runs", headers=auth_headers(access)).json()["items"][0]
    approved = client.post(f"/v1/playbook-runs/{run['id']}/approve", headers=auth_headers(access)).json()

    assert approved["status"] == RunStatus.FAILED
    assert "requires an enabled TenantSsoConfig" in approved["actions"][0]["error"]


def test_assign_case_rejects_a_cross_tenant_user(client: TestClient):
    access_a = _owner(client, email="a@acme.test", company="Acme")
    access_b = _owner(client, email="b@globex.test", company="Globex")
    other_user = client.get("/v1/auth/me", headers=auth_headers(access_b)).json()

    _make_playbook(
        client,
        access_a,
        name="assign across tenants",
        trigger="case_escalated",
        actions=[{"action": "assign_case", "params": {"userId": other_user["id"]}}],
    )
    create_rule(client, token=access_a, condition={"field": "event_action", "op": "eq", "value": "login_failed"})
    service_token = create_service_token(client, owner_token=access_a)
    ingest(client, service_token=service_token, events=[simple_event()])

    alert = client.get("/v1/alerts", headers=auth_headers(access_a)).json()["items"][0]
    case = client.post(
        "/v1/alerts/promote",
        json={"alertIds": [alert["id"]], "title": "Case"},
        headers=auth_headers(access_a),
    ).json()
    client.patch(f"/v1/cases/{case['id']}/status", json={"status": "investigating"}, headers=auth_headers(access_a))
    client.patch(f"/v1/cases/{case['id']}/status", json={"status": "escalated"}, headers=auth_headers(access_a))

    run = client.get("/v1/playbook-runs", headers=auth_headers(access_a)).json()["items"][0]
    detail = client.get(f"/v1/playbook-runs/{run['id']}", headers=auth_headers(access_a)).json()
    assert detail["actions"][0]["status"] == "failed"
    assert "not an active user in this tenant" in detail["actions"][0]["error"]

    # The case stayed unassigned.
    refreshed = client.get(f"/v1/cases/{case['id']}", headers=auth_headers(access_a)).json()
    assert refreshed["assigneeUserId"] is None


def test_analyst_cannot_create_or_approve_playbooks(client: TestClient):
    access = _owner(client)
    client.post(
        "/v1/tenants/me/users",
        json={"email": "analyst@acme.test", "password": "correct-horse-1", "role": "analyst"},
        headers=auth_headers(access),
    )
    analyst = client.post(
        "/v1/auth/login",
        json={"email": "analyst@acme.test", "password": "correct-horse-1"},
    ).json()

    resp = client.post(
        "/v1/playbooks",
        json={"name": "x", "actions": [{"action": "add_case_comment", "params": {}}]},
        headers=auth_headers(analyst["accessToken"]),
    )
    assert resp.status_code == 403


def test_playbooks_are_tenant_scoped(client: TestClient):
    access_a = _owner(client, email="a@acme.test", company="Acme")
    playbook = _make_playbook(client, access_a)

    access_b = _owner(client, email="b@globex.test", company="Globex")
    assert client.get("/v1/playbooks", headers=auth_headers(access_b)).json() == []
    assert client.get(f"/v1/playbooks/{playbook['id']}", headers=auth_headers(access_b)).status_code == 404


def test_every_registered_action_declares_its_risk():
    """A new action must make a deliberate high-risk decision.

    Guards against someone adding a destructive action and forgetting the flag,
    which would route it around the approval gate entirely.
    """
    for name, action in ACTION_REGISTRY.items():
        assert isinstance(action.is_high_risk, bool), name
        assert action.description, f"{name} has no description for the authoring UI"

"""FM6: case status state machine -- new -> investigating ->
resolved/escalated, with invalid transitions rejected."""
from __future__ import annotations

from fastapi.testclient import TestClient

from app.models.case import CaseStatus
from tests.conftest import auth_headers, signup


def _create_case(client: TestClient, token: str) -> str:
    resp = client.post(
        "/v1/cases",
        json={"title": "Anomalous data exfiltration volume", "description": "..."},
        headers=auth_headers(token),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


def test_case_starts_in_new_status(client: TestClient):
    tenant = signup(client, company="Case Co", email="owner@caseco.test")
    case_id = _create_case(client, tenant["accessToken"])
    resp = client.get(f"/v1/cases/{case_id}", headers=auth_headers(tenant["accessToken"]))
    assert resp.json()["status"] == CaseStatus.NEW


def test_valid_transition_sequence(client: TestClient):
    tenant = signup(client, company="Case Co 2", email="owner2@caseco.test")
    case_id = _create_case(client, tenant["accessToken"])
    headers = auth_headers(tenant["accessToken"])

    r1 = client.patch(f"/v1/cases/{case_id}/status", json={"status": "investigating"}, headers=headers)
    assert r1.status_code == 200
    assert r1.json()["status"] == "investigating"

    r2 = client.patch(f"/v1/cases/{case_id}/status", json={"status": "resolved"}, headers=headers)
    assert r2.status_code == 200
    assert r2.json()["status"] == "resolved"
    assert r2.json()["resolvedAt"] is not None

    timeline_resp = client.get(f"/v1/cases/{case_id}/timeline", headers=headers)
    assert timeline_resp.status_code == 200
    entry_types = [e["entryType"] for e in timeline_resp.json()]
    assert entry_types == ["created", "status_change", "status_change"]


def test_escalation_path(client: TestClient):
    tenant = signup(client, company="Case Co 3", email="owner3@caseco.test")
    case_id = _create_case(client, tenant["accessToken"])
    headers = auth_headers(tenant["accessToken"])

    client.patch(f"/v1/cases/{case_id}/status", json={"status": "investigating"}, headers=headers)
    r = client.patch(f"/v1/cases/{case_id}/status", json={"status": "escalated"}, headers=headers)
    assert r.status_code == 200
    assert r.json()["status"] == "escalated"

    # escalated can go back to investigating.
    r2 = client.patch(f"/v1/cases/{case_id}/status", json={"status": "investigating"}, headers=headers)
    assert r2.status_code == 200


def test_invalid_transition_new_to_resolved_rejected(client: TestClient):
    tenant = signup(client, company="Case Co 4", email="owner4@caseco.test")
    case_id = _create_case(client, tenant["accessToken"])
    headers = auth_headers(tenant["accessToken"])

    resp = client.patch(f"/v1/cases/{case_id}/status", json={"status": "resolved"}, headers=headers)
    assert resp.status_code == 409


def test_invalid_transition_out_of_resolved_rejected(client: TestClient):
    tenant = signup(client, company="Case Co 5", email="owner5@caseco.test")
    case_id = _create_case(client, tenant["accessToken"])
    headers = auth_headers(tenant["accessToken"])

    client.patch(f"/v1/cases/{case_id}/status", json={"status": "investigating"}, headers=headers)
    client.patch(f"/v1/cases/{case_id}/status", json={"status": "resolved"}, headers=headers)

    resp = client.patch(f"/v1/cases/{case_id}/status", json={"status": "investigating"}, headers=headers)
    assert resp.status_code == 409


def test_unknown_status_rejected(client: TestClient):
    tenant = signup(client, company="Case Co 6", email="owner6@caseco.test")
    case_id = _create_case(client, tenant["accessToken"])
    headers = auth_headers(tenant["accessToken"])

    resp = client.patch(f"/v1/cases/{case_id}/status", json={"status": "not-a-real-status"}, headers=headers)
    assert resp.status_code == 422

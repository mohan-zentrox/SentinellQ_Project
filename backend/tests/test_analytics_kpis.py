"""FM8 (aggregations part): KPI aggregation correctness -- alert volume,
MTTD/MTTR derived from real timestamps, tenant-scoped."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from tests.conftest import auth_headers, create_service_token, signup


def test_kpis_empty_tenant_has_no_signal(client: TestClient):
    tenant = signup(client, company="KPI Co Empty", email="owner@kpiempty.test")
    resp = client.get("/v1/analytics/kpis", headers=auth_headers(tenant["accessToken"]))
    assert resp.status_code == 200
    body = resp.json()
    assert body["alertVolume"] == 0
    assert body["mttdSeconds"] is None
    assert body["mttrSeconds"] is None
    assert body["falsePositiveRate"] == 0.0
    assert body["openCases"] == 0
    assert body["resolvedCases"] == 0


def test_kpis_reflect_alert_and_case_activity(client: TestClient):
    tenant = signup(client, company="KPI Co", email="owner@kpico.test")
    token = create_service_token(client, owner_token=tenant["accessToken"])
    headers = auth_headers(tenant["accessToken"])

    # Event that "occurred" 5 minutes ago, ingested (and about to be alerted
    # on) now -- gives MTTD a known, positive lower bound.
    occurred_at = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    ingest_resp = client.post(
        "/v1/events/ingest",
        json={
            "events": [
                {
                    "source": "edr",
                    "payload": {"severity": "critical", "action": "ransomware_signature_match"},
                    "occurredAt": occurred_at,
                }
            ]
        },
        headers={"X-Service-Token": token},
    )
    assert ingest_resp.status_code == 202

    rule_resp = client.post(
        "/v1/detection-rules",
        json={
            "name": "Ransomware signature",
            "condition": {"field": "severity_hint", "op": "eq", "value": "critical"},
            "severity": "critical",
        },
        headers=headers,
    )
    rule_id = rule_resp.json()["id"]
    run_resp = client.post(f"/v1/detection-rules/{rule_id}/run", headers=headers)
    assert run_resp.json()["alertsCreated"] == 1
    alert_id = run_resp.json()["alertIds"][0]

    # Promote to a case and resolve it, so MTTR has a real (small, >=0) sample.
    promote_resp = client.post(
        "/v1/alerts/promote",
        json={"alertIds": [alert_id], "title": "Ransomware incident"},
        headers=headers,
    )
    assert promote_resp.status_code == 201
    case_id = promote_resp.json()["id"]

    client.patch(f"/v1/cases/{case_id}/status", json={"status": "investigating"}, headers=headers)
    resolve_resp = client.patch(f"/v1/cases/{case_id}/status", json={"status": "resolved"}, headers=headers)
    assert resolve_resp.status_code == 200

    kpi_resp = client.get("/v1/analytics/kpis", headers=headers)
    assert kpi_resp.status_code == 200
    body = kpi_resp.json()

    assert body["alertVolume"] == 1
    assert body["resolvedCases"] == 1
    assert body["openCases"] == 0
    # MTTD should reflect the ~5 minute (300s) gap we engineered above.
    assert body["mttdSeconds"] is not None
    assert body["mttdSeconds"] >= 250
    # MTTR should be a small non-negative number (resolved almost immediately).
    assert body["mttrSeconds"] is not None
    assert body["mttrSeconds"] >= 0

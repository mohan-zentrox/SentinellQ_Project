"""FM9: compliance report generation and signed downloads."""
from __future__ import annotations

import csv
import io
import json

from fastapi.testclient import TestClient

from app.services.reports import sign_download, verify_download
from tests.conftest import auth_headers, create_rule, create_service_token, ingest, signup, simple_event


def _tenant_with_findings(client: TestClient, email: str = "owner@acme.test", company: str = "Acme") -> str:
    owner = signup(client, company=company, email=email)
    access = owner["accessToken"]
    create_rule(client, token=access, condition={"field": "event_action", "op": "eq", "value": "login_failed"})
    service_token = create_service_token(client, owner_token=access)
    ingest(client, service_token=service_token, events=[simple_event(actor="a")])
    ingest(client, service_token=service_token, events=[simple_event(actor="b")])
    return access


def test_templates_are_listed(client: TestClient):
    access = _tenant_with_findings(client)
    templates = client.get("/v1/reports/templates", headers=auth_headers(access)).json()
    names = {entry["name"] for entry in templates}
    assert names == {"alert_summary", "case_summary", "control_evidence"}
    assert "csv" in templates[0]["formats"]


def test_csv_alert_summary_contains_the_alerts(client: TestClient):
    access = _tenant_with_findings(client)

    created = client.post(
        "/v1/reports",
        json={"template": "alert_summary", "reportFormat": "csv", "days": 30},
        headers=auth_headers(access),
    )
    assert created.status_code == 201, created.text
    report = created.json()
    assert report["status"] == "ready"
    assert report["rowCount"] == 2
    assert report["downloadUrl"] is not None

    download = client.get(report["downloadUrl"])
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("text/csv")
    assert "attachment" in download.headers["content-disposition"]

    rows = list(csv.DictReader(io.StringIO(download.text)))
    assert len(rows) == 2
    assert rows[0]["severity"] == "high"
    assert rows[0]["detection_source"] == "rule"


def test_json_format(client: TestClient):
    access = _tenant_with_findings(client)
    report = client.post(
        "/v1/reports",
        json={"template": "alert_summary", "reportFormat": "json"},
        headers=auth_headers(access),
    ).json()

    payload = json.loads(client.get(report["downloadUrl"]).text)
    assert payload["summary"]["totalAlerts"] == 2
    assert len(payload["rows"]) == 2


def test_html_report_escapes_user_controlled_content(client: TestClient):
    """Report cells carry user-supplied strings. An unescaped report is stored
    XSS against whoever opens the artifact.

    The payload goes in the rule name, because that is what flows into
    `Alert.title` and therefore into the alert_summary report's `title` column.
    (An event's `actor` is attacker-controlled but is not a column in this
    template, so it would not exercise the escaping.)
    """
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    create_rule(
        client,
        token=access,
        condition={"field": "event_action", "op": "eq", "value": "login_failed"},
        name="<script>alert('xss')</script>",
    )
    service_token = create_service_token(client, owner_token=access)
    ingest(client, service_token=service_token, events=[simple_event()])

    report = client.post(
        "/v1/reports",
        json={"template": "alert_summary", "reportFormat": "html"},
        headers=auth_headers(access),
    ).json()
    body = client.get(report["downloadUrl"]).text

    # The payload is present in the report (so the test is actually exercising
    # the path) but neutralised.
    assert "&lt;script&gt;" in body
    assert "<script>alert" not in body


def test_control_evidence_matches_the_kpi_endpoint(client: TestClient):
    """A report that disagrees with the dashboard is worse than no report."""
    access = _tenant_with_findings(client)

    kpis = client.get("/v1/analytics/kpis?days=30", headers=auth_headers(access)).json()
    report = client.post(
        "/v1/reports",
        json={"template": "control_evidence", "reportFormat": "json", "days": 30},
        headers=auth_headers(access),
    ).json()
    payload = json.loads(client.get(report["downloadUrl"]).text)

    assert payload["summary"]["kpis"]["alert_volume"] == kpis["alertVolume"]
    assert payload["summary"]["kpis"]["open_cases"] == kpis["openCases"]
    monitoring = next(r for r in payload["rows"] if r["control"].startswith("CC7.2"))
    assert monitoring["measurement"] == kpis["alertVolume"]


def test_case_summary_includes_resolution_time(client: TestClient):
    access = _tenant_with_findings(client)
    alert = client.get("/v1/alerts", headers=auth_headers(access)).json()["items"][0]
    case = client.post(
        "/v1/alerts/promote",
        json={"alertIds": [alert["id"]], "title": "Resolved thing"},
        headers=auth_headers(access),
    ).json()
    client.patch(f"/v1/cases/{case['id']}/status", json={"status": "investigating"}, headers=auth_headers(access))
    client.patch(f"/v1/cases/{case['id']}/status", json={"status": "resolved"}, headers=auth_headers(access))

    report = client.post(
        "/v1/reports",
        json={"template": "case_summary", "reportFormat": "json"},
        headers=auth_headers(access),
    ).json()
    payload = json.loads(client.get(report["downloadUrl"]).text)

    assert payload["summary"]["totalCases"] == 1
    assert payload["summary"]["resolved"] == 1
    assert payload["rows"][0]["resolution_seconds"] != ""


def test_download_requires_a_valid_token(client: TestClient):
    access = _tenant_with_findings(client)
    report = client.post(
        "/v1/reports",
        json={"template": "alert_summary"},
        headers=auth_headers(access),
    ).json()

    # No token at all.
    assert client.get(f"/v1/reports/{report['id']}/download").status_code == 422
    # Forged token. 404 rather than 403: the existence of a report id is itself
    # tenant information.
    assert client.get(f"/v1/reports/{report['id']}/download?token=9999999999.deadbeef").status_code == 404


def test_download_token_is_bound_to_report_and_tenant():
    """A token must not be transplantable onto another report."""

    class _Stub:
        def __init__(self, report_id: str, tenant_id: str) -> None:
            self.id = report_id
            self.tenant_id = tenant_id

    report = _Stub("rpt_one", "ten_a")
    token, _ = sign_download(report)  # type: ignore[arg-type]

    assert verify_download("rpt_one", "ten_a", token) is True
    assert verify_download("rpt_two", "ten_a", token) is False
    assert verify_download("rpt_one", "ten_b", token) is False


def test_expired_download_token_is_rejected():
    class _Stub:
        id = "rpt_one"
        tenant_id = "ten_a"

    token, _ = sign_download(_Stub(), ttl_seconds=-10)  # type: ignore[arg-type]
    assert verify_download("rpt_one", "ten_a", token) is False


def test_reports_are_tenant_scoped(client: TestClient):
    access_a = _tenant_with_findings(client, email="a@acme.test", company="Acme")
    report = client.post(
        "/v1/reports",
        json={"template": "alert_summary"},
        headers=auth_headers(access_a),
    ).json()

    owner_b = signup(client, company="Globex", email="b@globex.test")
    access_b = owner_b["accessToken"]

    assert client.get("/v1/reports", headers=auth_headers(access_b)).json()["total"] == 0
    assert client.get(f"/v1/reports/{report['id']}", headers=auth_headers(access_b)).status_code == 404


def test_report_period_validation(client: TestClient):
    access = _tenant_with_findings(client)
    resp = client.post(
        "/v1/reports",
        json={
            "template": "alert_summary",
            "periodStart": "2026-06-01T00:00:00Z",
            "periodEnd": "2026-05-01T00:00:00Z",
        },
        headers=auth_headers(access),
    )
    assert resp.status_code == 422


def test_unknown_template_is_rejected_by_validation(client: TestClient):
    access = _tenant_with_findings(client)
    resp = client.post(
        "/v1/reports",
        json={"template": "nonexistent"},
        headers=auth_headers(access),
    )
    assert resp.status_code == 422


def test_delete_removes_the_report_and_its_artifact(client: TestClient):
    access = _tenant_with_findings(client)
    report = client.post(
        "/v1/reports",
        json={"template": "alert_summary"},
        headers=auth_headers(access),
    ).json()

    assert client.delete(f"/v1/reports/{report['id']}", headers=auth_headers(access)).status_code == 204
    assert client.get(f"/v1/reports/{report['id']}", headers=auth_headers(access)).status_code == 404
    # The signed URL no longer resolves either.
    assert client.get(report["downloadUrl"]).status_code == 404

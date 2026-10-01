"""FM5: threat indicators, normalization, enrichment, and intel-driven rules."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.models.event import Event
from app.models.threat_intel import IndicatorType, ThreatIndicator
from app.services.threat_intel import infer_indicator_type, normalize_indicator_value
from tests.conftest import auth_headers, create_rule, create_service_token, ingest, signup, simple_event


# --------------------------------------------------------------------------
# Normalization (unit)
# --------------------------------------------------------------------------
def test_ip_normalization_collapses_equivalent_spellings():
    # An indicator stored one way must match an event carrying the other, or the
    # blocklist silently never fires.
    assert normalize_indicator_value(IndicatorType.IP, " 1.2.3.4 ") == "1.2.3.4"
    assert normalize_indicator_value(IndicatorType.IP, "2001:0db8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"


def test_domain_normalization_strips_case_trailing_dot_and_wildcard():
    assert normalize_indicator_value(IndicatorType.DOMAIN, "EVIL.COM.") == "evil.com"
    assert normalize_indicator_value(IndicatorType.DOMAIN, "*.evil.com") == "evil.com"


def test_hash_and_cve_normalization():
    assert normalize_indicator_value(IndicatorType.FILE_HASH, "ABCDEF") == "abcdef"
    assert normalize_indicator_value(IndicatorType.CVE, "cve-2024-1234") == "CVE-2024-1234"


def test_type_inference():
    assert infer_indicator_type("8.8.8.8") == IndicatorType.IP
    assert infer_indicator_type("CVE-2024-0001") == IndicatorType.CVE
    assert infer_indicator_type("https://bad.example/x") == IndicatorType.URL
    assert infer_indicator_type("a@b.example") == IndicatorType.EMAIL
    assert infer_indicator_type("d" * 64) == IndicatorType.FILE_HASH
    assert infer_indicator_type("bad.example") == IndicatorType.DOMAIN


# --------------------------------------------------------------------------
# Indicator CRUD
# --------------------------------------------------------------------------
def test_create_and_list_indicator(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]

    created = client.post(
        "/v1/threat-indicators",
        json={
            "indicatorType": "ip",
            "value": "203.0.113.7",
            "confidence": 90,
            "severity": "high",
            "tags": ["botnet"],
        },
        headers=auth_headers(access),
    )
    assert created.status_code == 201, created.text
    assert created.json()["valueNormalized"] == "203.0.113.7"

    listed = client.get("/v1/threat-indicators", headers=auth_headers(access)).json()
    assert listed["total"] == 1


def test_re_adding_an_indicator_upserts_and_never_lowers_confidence(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]

    client.post(
        "/v1/threat-indicators",
        json={"indicatorType": "ip", "value": "203.0.113.7", "confidence": 90},
        headers=auth_headers(access),
    )
    # Same value, lower confidence: must not downgrade the analyst's judgement.
    second = client.post(
        "/v1/threat-indicators",
        json={"indicatorType": "ip", "value": "203.0.113.7", "confidence": 10},
        headers=auth_headers(access),
    ).json()

    assert second["confidence"] == 90
    assert client.get("/v1/threat-indicators", headers=auth_headers(access)).json()["total"] == 1


def test_bulk_import(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]

    resp = client.post(
        "/v1/threat-indicators/bulk",
        json={
            "source": "paste",
            "indicators": [
                {"indicatorType": "ip", "value": "198.51.100.1"},
                {"indicatorType": "ip", "value": "198.51.100.2"},
                {"indicatorType": "domain", "value": "Bad.Example"},
            ],
        },
        headers=auth_headers(access),
    ).json()
    assert resp["created"] == 3
    assert resp["updated"] == 0


def test_deactivated_indicator_stops_matching_but_is_retained(client: TestClient, db_session):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    created = client.post(
        "/v1/threat-indicators",
        json={"indicatorType": "ip", "value": "203.0.113.7"},
        headers=auth_headers(access),
    ).json()

    assert client.delete(f"/v1/threat-indicators/{created['id']}", headers=auth_headers(access)).status_code == 204

    # Still in the table (explains historical alerts), just not active.
    row = db_session.query(ThreatIndicator).filter(ThreatIndicator.id == created["id"]).one()
    assert row.is_active is False

    preview = client.get("/v1/threat-indicators/preview/ip/203.0.113.7", headers=auth_headers(access)).json()
    assert preview["matched"] is False


# --------------------------------------------------------------------------
# Enrichment in the pipeline
# --------------------------------------------------------------------------
def test_ingest_enriches_event_with_matching_indicator(client: TestClient, db_session):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    client.post(
        "/v1/threat-indicators",
        json={
            "indicatorType": "ip",
            "value": "203.0.113.7",
            "confidence": 95,
            "severity": "critical",
            "tags": ["ransomware"],
        },
        headers=auth_headers(access),
    )
    service_token = create_service_token(client, owner_token=access)

    ingest(client, service_token=service_token, events=[simple_event(source_ip="203.0.113.7")])

    event = db_session.query(Event).one()
    assert event.enrichment["matched"] is True
    assert event.enrichment["maxConfidence"] == 95
    assert "ransomware" in event.enrichment["tags"]


def test_unmatched_event_is_still_marked_as_enriched(client: TestClient, db_session):
    """"Enriched, nothing found" must be distinguishable from "never enriched",
    or a later backfill cannot tell which events still need processing."""
    owner = signup(client, company="Acme", email="owner@acme.test")
    service_token = create_service_token(client, owner_token=owner["accessToken"])

    ingest(client, service_token=service_token, events=[simple_event(source_ip="10.0.0.1")])

    event = db_session.query(Event).one()
    assert event.enrichment is not None
    assert event.enrichment["matched"] is False
    assert event.enrichment["indicatorCount"] == 0


def test_expired_indicator_does_not_enrich(client: TestClient, db_session):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    client.post(
        "/v1/threat-indicators",
        json={"indicatorType": "ip", "value": "203.0.113.7", "ttlHours": 1},
        headers=auth_headers(access),
    )
    # Force expiry in the past.
    row = db_session.query(ThreatIndicator).one()
    row.expires_at = datetime.now(timezone.utc) - timedelta(hours=2)
    db_session.commit()

    service_token = create_service_token(client, owner_token=access)
    ingest(client, service_token=service_token, events=[simple_event(source_ip="203.0.113.7")])

    event = db_session.query(Event).one()
    assert event.enrichment["matched"] is False


def test_expire_stale_sweep_deactivates_expired_indicators(client: TestClient, db_session):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    client.post(
        "/v1/threat-indicators",
        json={"indicatorType": "ip", "value": "203.0.113.7"},
        headers=auth_headers(access),
    )
    row = db_session.query(ThreatIndicator).one()
    row.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
    db_session.commit()

    resp = client.post("/v1/threat-indicators/expire-stale", headers=auth_headers(access)).json()
    assert resp["expired"] == 1


def test_rule_can_threshold_on_enrichment_confidence(client: TestClient):
    """The FM5 -> FM4 integration: intel-driven detection.

    A rule addressing `enrichment.maxConfidence` fires on an event only because
    enrichment annotated it, which is the point of running enrichment before
    detection in the pipeline.
    """
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    client.post(
        "/v1/threat-indicators",
        json={"indicatorType": "ip", "value": "203.0.113.7", "confidence": 95},
        headers=auth_headers(access),
    )
    create_rule(
        client,
        token=access,
        condition={"field": "enrichment.maxConfidence", "op": "gte", "value": 80},
        name="high-confidence intel hit",
        severity="critical",
    )
    service_token = create_service_token(client, owner_token=access)

    # A known-bad IP: enriched at 95, so the rule fires.
    hit = ingest(client, service_token=service_token, events=[simple_event(source_ip="203.0.113.7")])
    assert hit["alertsCreated"] == 1

    # An unknown IP: enriched at 0, so it does not.
    miss = ingest(client, service_token=service_token, events=[simple_event(source_ip="10.0.0.5")])
    assert miss["alertsCreated"] == 0


def test_rule_can_match_on_enrichment_tags(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    client.post(
        "/v1/threat-indicators",
        json={"indicatorType": "ip", "value": "203.0.113.7", "tags": ["c2", "ransomware"]},
        headers=auth_headers(access),
    )
    create_rule(
        client,
        token=access,
        condition={"field": "enrichment.tags", "op": "contains", "value": "ransomware"},
        name="ransomware infra contact",
    )
    service_token = create_service_token(client, owner_token=access)

    body = ingest(client, service_token=service_token, events=[simple_event(source_ip="203.0.113.7")])
    assert body["alertsCreated"] == 1


def test_subdomain_is_covered_by_parent_domain_indicator(client: TestClient, db_session):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    client.post(
        "/v1/threat-indicators",
        json={"indicatorType": "domain", "value": "evil.example"},
        headers=auth_headers(access),
    )
    service_token = create_service_token(client, owner_token=access)

    ingest(
        client,
        service_token=service_token,
        events=[simple_event(domain="login.cdn.evil.example")],
    )

    event = db_session.query(Event).one()
    assert event.enrichment["matched"] is True


def test_indicators_are_tenant_scoped(client: TestClient):
    owner_a = signup(client, company="Acme", email="a@acme.test")
    client.post(
        "/v1/threat-indicators",
        json={"indicatorType": "ip", "value": "203.0.113.7"},
        headers=auth_headers(owner_a["accessToken"]),
    )

    owner_b = signup(client, company="Globex", email="b@globex.test")
    listed = client.get("/v1/threat-indicators", headers=auth_headers(owner_b["accessToken"])).json()
    assert listed["total"] == 0

    # And tenant B's events are not enriched by tenant A's intel.
    service_token_b = create_service_token(client, owner_token=owner_b["accessToken"])
    ingest(client, service_token=service_token_b, events=[simple_event(source_ip="203.0.113.7")])
    preview = client.get(
        "/v1/threat-indicators/preview/ip/203.0.113.7",
        headers=auth_headers(owner_b["accessToken"]),
    ).json()
    assert preview["matched"] is False


def test_local_feed_refresh_is_a_noop_not_an_error(client: TestClient):
    """A `local` feed has no remote to poll; refreshing must succeed with zero
    imports rather than erroring."""
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    feed = client.post(
        "/v1/threat-feeds",
        json={"slug": "analyst-list", "name": "Analyst list", "provider": "local"},
        headers=auth_headers(access),
    )
    assert feed.status_code == 201, feed.text

    resp = client.post(f"/v1/threat-feeds/{feed.json()['id']}/refresh", headers=auth_headers(access)).json()
    assert resp["created"] == 0
    assert resp["status"].startswith("ok")


def test_http_feed_requires_a_url(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    resp = client.post(
        "/v1/threat-feeds",
        json={"slug": "remote", "name": "Remote", "provider": "http_feed"},
        headers=auth_headers(owner["accessToken"]),
    )
    assert resp.status_code == 422


def test_unreachable_feed_reports_status_rather_than_5xx(client: TestClient):
    """A third-party outage is operational news for the UI, not a server error."""
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    feed = client.post(
        "/v1/threat-feeds",
        json={
            "slug": "broken",
            "name": "Broken",
            "provider": "http_feed",
            # Loopback on a closed port: refuses immediately. A routable-but-
            # unreachable address (e.g. TEST-NET-1) would make this test wait
            # out the full 20s connect timeout on every CI run.
            "url": "http://127.0.0.1:1/indicators.json",
        },
        headers=auth_headers(access),
    ).json()

    resp = client.post(f"/v1/threat-feeds/{feed['id']}/refresh", headers=auth_headers(access))
    assert resp.status_code == 200
    assert resp.json()["status"].startswith("error")


def test_indicator_stats_summary(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    client.post(
        "/v1/threat-indicators/bulk",
        json={
            "indicators": [
                {"indicatorType": "ip", "value": "198.51.100.1"},
                {"indicatorType": "domain", "value": "bad.example"},
            ]
        },
        headers=auth_headers(access),
    )

    stats = client.get("/v1/threat-indicators/stats/summary", headers=auth_headers(access)).json()
    assert stats["activeIndicators"] == 2
    assert stats["byType"] == {"ip": 1, "domain": 1}
    assert stats["everMatched"] == 0
    assert stats["matchRate"] == 0.0

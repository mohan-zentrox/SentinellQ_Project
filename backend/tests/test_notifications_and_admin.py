"""FM6 alerting, FM10 atomic metering, FM11 admin surface, and observability."""
from __future__ import annotations

import threading
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings, reset_settings_cache
from app.core.metrics import MetricsRegistry
from app.db.base import Base
from app.models.alert import Alert
from app.models.notification import NotificationDelivery
from app.services.billing_meter import read_event_usage, record_event_usage
from app.services.notifications import notify_alerts, should_notify
from tests.conftest import auth_headers, create_rule, create_service_token, ingest, signup, simple_event


# --------------------------------------------------------------------------
# FM6: notifications
# --------------------------------------------------------------------------
def test_severity_floor_suppresses_low_severity_alerts():
    """A SecOps tool that pages on every informational event gets muted by its
    users, which is a worse failure than not paging."""
    floor = get_settings().notification_min_severity
    assert floor == "high"

    assert should_notify(Alert(severity="critical", status="open")) is True
    assert should_notify(Alert(severity="high", status="open")) is True
    assert should_notify(Alert(severity="medium", status="open")) is False
    assert should_notify(Alert(severity="informational", status="open")) is False


def test_an_already_notified_alert_is_never_notified_again():
    alert = Alert(severity="critical", status="open", notified_at=datetime.now(timezone.utc))
    assert should_notify(alert) is False


def test_ingest_notifies_and_records_the_delivery(client: TestClient, db_session):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    create_rule(
        client,
        token=access,
        condition={"field": "event_action", "op": "eq", "value": "login_failed"},
        severity="critical",
    )
    service_token = create_service_token(client, owner_token=access)

    ingest(client, service_token=service_token, events=[simple_event()])

    deliveries = db_session.query(NotificationDelivery).all()
    assert len(deliveries) == 1
    assert deliveries[0].channel == "log"
    assert deliveries[0].status == "sent"

    alert = db_session.query(Alert).one()
    assert alert.notified_at is not None


def test_a_rerun_does_not_re_notify(client: TestClient, db_session):
    """No double-paging: the on-call must not be woken twice for one finding."""
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    create_rule(
        client,
        token=access,
        condition={"field": "event_action", "op": "eq", "value": "login_failed"},
        severity="critical",
    )
    service_token = create_service_token(client, owner_token=access)
    ingest(client, service_token=service_token, events=[simple_event()])

    client.post("/v1/detection-rules/run-all", headers=auth_headers(access))

    assert db_session.query(NotificationDelivery).count() == 1


def test_low_severity_alert_produces_no_delivery(client: TestClient, db_session):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    create_rule(
        client,
        token=access,
        condition={"field": "event_action", "op": "eq", "value": "login_failed"},
        severity="low",
    )
    service_token = create_service_token(client, owner_token=access)
    ingest(client, service_token=service_token, events=[simple_event()])

    assert db_session.query(Alert).count() == 1
    assert db_session.query(NotificationDelivery).count() == 0


def test_a_failing_channel_is_recorded_and_does_not_lose_the_alert(client: TestClient, db_session, monkeypatch):
    """A broken webhook must not break ingestion."""
    monkeypatch.setenv("SENTINELIQ_NOTIFICATION_CHANNELS", '["log","webhook"]')
    monkeypatch.setenv("SENTINELIQ_NOTIFICATION_WEBHOOK_URL", "http://127.0.0.1:1/hook")
    reset_settings_cache()

    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    create_rule(
        client,
        token=access,
        condition={"field": "event_action", "op": "eq", "value": "login_failed"},
        severity="critical",
    )
    service_token = create_service_token(client, owner_token=access)

    body = ingest(client, service_token=service_token, events=[simple_event()])
    assert body["alertsCreated"] == 1

    deliveries = {d.channel: d for d in db_session.query(NotificationDelivery).all()}
    assert deliveries["log"].status == "sent"
    assert deliveries["webhook"].status == "failed"
    assert deliveries["webhook"].error

    # Stamped anyway: a permanently broken webhook must not re-page the working
    # channel forever.
    assert db_session.query(Alert).one().notified_at is not None


def test_misconfigured_channel_is_skipped_not_fatal(client: TestClient, db_session, monkeypatch):
    """webhook enabled with no URL: log must still deliver."""
    monkeypatch.setenv("SENTINELIQ_NOTIFICATION_CHANNELS", '["log","webhook"]')
    monkeypatch.delenv("SENTINELIQ_NOTIFICATION_WEBHOOK_URL", raising=False)
    reset_settings_cache()

    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    create_rule(
        client,
        token=access,
        condition={"field": "event_action", "op": "eq", "value": "login_failed"},
        severity="critical",
    )
    service_token = create_service_token(client, owner_token=access)
    ingest(client, service_token=service_token, events=[simple_event()])

    channels = {d.channel for d in db_session.query(NotificationDelivery).all()}
    assert channels == {"log"}


def test_notify_alerts_is_a_noop_with_no_eligible_alerts(db_session):
    assert notify_alerts(db_session, tenant_id="ten_x", alerts=[]) == 0


def test_admin_can_review_notification_deliveries(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    create_rule(
        client,
        token=access,
        condition={"field": "event_action", "op": "eq", "value": "login_failed"},
        severity="critical",
    )
    service_token = create_service_token(client, owner_token=access)
    ingest(client, service_token=service_token, events=[simple_event()])

    listed = client.get("/v1/admin/notifications", headers=auth_headers(access)).json()
    assert listed["total"] == 1
    assert listed["items"][0]["channel"] == "log"

    sent_only = client.get("/v1/admin/notifications?status=sent", headers=auth_headers(access)).json()
    assert sent_only["total"] == 1
    failed_only = client.get("/v1/admin/notifications?status=failed", headers=auth_headers(access)).json()
    assert failed_only["total"] == 0


# --------------------------------------------------------------------------
# FM10: atomic metering
# --------------------------------------------------------------------------
def test_usage_increments_are_atomic_under_concurrency(tmp_path):
    """The read-modify-write this replaces lost increments whenever two ingest
    requests for the same tenant overlapped. Under-counting usage is a billing
    bug, and it also silently disables quota enforcement at exactly the traffic
    level where it matters.

    Uses a file-backed SQLite database with one connection per thread. An
    in-memory StaticPool database would share a single connection across all
    threads -- which cannot hold concurrent transactions, so the test would be
    measuring the harness rather than the increment, and would "fail" even
    against a correct implementation.
    """
    database_url = f"sqlite:///{tmp_path / 'meter.db'}"
    engine = create_engine(
        database_url,
        # 30s busy timeout: SQLite serializes writers with a lock, and without a
        # timeout a contended write raises "database is locked" instead of
        # waiting its turn.
        connect_args={"check_same_thread": False, "timeout": 30},
        future=True,
    )
    Base.metadata.create_all(bind=engine)
    maker = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

    # Create the counter row up front so the test isolates the increment path
    # from the get-or-create race (covered separately below).
    setup = maker()
    record_event_usage(setup, tenant_id="ten_race", period="2026-10", count=0)
    setup.commit()
    setup.close()

    threads = 8
    per_thread = 25
    barrier = threading.Barrier(threads)
    errors: list[Exception] = []

    def worker() -> None:
        session = maker()
        try:
            barrier.wait()
            for _ in range(per_thread):
                record_event_usage(session, tenant_id="ten_race", period="2026-10", count=1)
                session.commit()
        except Exception as exc:  # noqa: BLE001 - surfaced via `errors`
            errors.append(exc)
        finally:
            session.close()

    workers = [threading.Thread(target=worker) for _ in range(threads)]
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join()

    assert not errors, errors
    session = maker()
    try:
        # Every single increment survived. A read-modify-write implementation
        # loses some here.
        assert read_event_usage(session, tenant_id="ten_race", period="2026-10") == threads * per_thread
    finally:
        session.close()
        engine.dispose()


def test_concurrent_counter_creation_does_not_duplicate_the_row(tmp_path):
    """The get-or-create race: two threads both see no counter and both insert.

    The unique constraint on (tenant_id, period) makes the loser fail, and
    ensure_counter re-reads instead of propagating the error -- otherwise the
    first ingest of a billing period would intermittently 500.
    """
    from app.models.billing import UsageCounter

    database_url = f"sqlite:///{tmp_path / 'create.db'}"
    engine = create_engine(
        database_url,
        connect_args={"check_same_thread": False, "timeout": 30},
        future=True,
    )
    Base.metadata.create_all(bind=engine)
    maker = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

    threads = 6
    barrier = threading.Barrier(threads)
    errors: list[Exception] = []

    def worker() -> None:
        session = maker()
        try:
            barrier.wait()
            record_event_usage(session, tenant_id="ten_new", period="2026-11", count=1)
            session.commit()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)
        finally:
            session.close()

    workers = [threading.Thread(target=worker) for _ in range(threads)]
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join()

    assert not errors, errors
    session = maker()
    try:
        rows = session.query(UsageCounter).filter(UsageCounter.tenant_id == "ten_new").all()
        assert len(rows) == 1
        assert rows[0].event_count == threads
    finally:
        session.close()
        engine.dispose()


def test_metering_counts_the_whole_batch(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    service_token = create_service_token(client, owner_token=access)

    ingest(client, service_token=service_token, events=[simple_event(actor=f"u{i}") for i in range(7)])

    usage = client.get("/v1/billing/usage", headers=auth_headers(access)).json()
    assert usage["eventCount"] == 7
    assert usage["overQuota"] is False


def test_usage_history_is_exposed(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    service_token = create_service_token(client, owner_token=access)
    ingest(client, service_token=service_token, events=[simple_event()])

    history = client.get("/v1/billing/usage/history", headers=auth_headers(access)).json()
    assert len(history["entries"]) == 1
    assert history["entries"][0]["eventCount"] == 1


# --------------------------------------------------------------------------
# FM10: subscription lifecycle
# --------------------------------------------------------------------------
def test_checkout_then_webhook_activation_raises_the_quota(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]

    before = client.get("/v1/billing/usage", headers=auth_headers(access)).json()
    assert before["monthlyEventQuota"] == 1_000  # free plan

    checkout = client.post(
        "/v1/billing/checkout",
        json={"planSlug": "pro"},
        headers=auth_headers(access),
    ).json()
    assert checkout["sessionId"].startswith("cs_test_")

    # Quota has NOT moved yet -- the tenant is still on the plan it paid for.
    mid = client.get("/v1/billing/usage", headers=auth_headers(access)).json()
    assert mid["monthlyEventQuota"] == 1_000

    activated = client.post(
        f"/v1/billing/webhook/checkout-completed?session_id={checkout['sessionId']}",
        headers=auth_headers(access),
    ).json()
    assert activated["status"] == "active"

    after = client.get("/v1/billing/usage", headers=auth_headers(access)).json()
    assert after["monthlyEventQuota"] == 100_000


def test_cancel_at_period_end_keeps_the_paid_quota(client: TestClient):
    """Clicking "cancel" means "do not renew", not "cut me off now"."""
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    checkout = client.post(
        "/v1/billing/checkout", json={"planSlug": "pro"}, headers=auth_headers(access)
    ).json()
    client.post(
        f"/v1/billing/webhook/checkout-completed?session_id={checkout['sessionId']}",
        headers=auth_headers(access),
    )

    canceled = client.post(
        "/v1/billing/subscription/cancel",
        json={"immediate": False},
        headers=auth_headers(access),
    ).json()
    assert canceled["cancelAtPeriodEnd"] is True
    assert canceled["status"] == "active"
    assert client.get("/v1/billing/usage", headers=auth_headers(access)).json()["monthlyEventQuota"] == 100_000


def test_immediate_cancel_downgrades_now(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    checkout = client.post(
        "/v1/billing/checkout", json={"planSlug": "pro"}, headers=auth_headers(access)
    ).json()
    client.post(
        f"/v1/billing/webhook/checkout-completed?session_id={checkout['sessionId']}",
        headers=auth_headers(access),
    )

    canceled = client.post(
        "/v1/billing/subscription/cancel",
        json={"immediate": True},
        headers=auth_headers(access),
    ).json()
    assert canceled["status"] == "canceled"
    assert client.get("/v1/billing/usage", headers=auth_headers(access)).json()["monthlyEventQuota"] == 1_000


def test_stripe_webhook_rejects_an_unsigned_request(client: TestClient, monkeypatch):
    monkeypatch.setenv("SENTINELIQ_STRIPE_WEBHOOK_SECRET", "whsec_test")
    reset_settings_cache()

    resp = client.post("/v1/billing/webhook/stripe", json={"type": "checkout.session.completed"})
    assert resp.status_code == 400
    assert "Stripe-Signature" in resp.json()["detail"]


def test_stripe_webhook_rejects_a_bad_signature(client: TestClient, monkeypatch):
    monkeypatch.setenv("SENTINELIQ_STRIPE_WEBHOOK_SECRET", "whsec_test")
    reset_settings_cache()
    import time

    resp = client.post(
        "/v1/billing/webhook/stripe",
        json={"type": "checkout.session.completed"},
        headers={"Stripe-Signature": f"t={int(time.time())},v1=deadbeef"},
    )
    assert resp.status_code == 400
    assert "verification failed" in resp.json()["detail"]


def test_stripe_webhook_accepts_a_correct_signature(client: TestClient, monkeypatch):
    import hashlib
    import hmac
    import json
    import time

    monkeypatch.setenv("SENTINELIQ_STRIPE_WEBHOOK_SECRET", "whsec_test")
    reset_settings_cache()

    body = json.dumps({"type": "some.other.event", "data": {"object": {}}}).encode()
    timestamp = int(time.time())
    signature = hmac.new(b"whsec_test", f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()

    resp = client.post(
        "/v1/billing/webhook/stripe",
        content=body,
        headers={"Stripe-Signature": f"t={timestamp},v1={signature}", "Content-Type": "application/json"},
    )
    assert resp.status_code == 204


def test_replayed_webhook_outside_tolerance_is_rejected(client: TestClient, monkeypatch):
    import hashlib
    import hmac
    import json

    monkeypatch.setenv("SENTINELIQ_STRIPE_WEBHOOK_SECRET", "whsec_test")
    reset_settings_cache()

    body = json.dumps({"type": "x"}).encode()
    stale = 1_000_000_000  # long in the past
    signature = hmac.new(b"whsec_test", f"{stale}.".encode() + body, hashlib.sha256).hexdigest()

    resp = client.post(
        "/v1/billing/webhook/stripe",
        content=body,
        headers={"Stripe-Signature": f"t={stale},v1={signature}", "Content-Type": "application/json"},
    )
    assert resp.status_code == 400
    assert "tolerance" in resp.json()["detail"]


# --------------------------------------------------------------------------
# FM11: admin surface
# --------------------------------------------------------------------------
def test_audit_log_records_security_relevant_actions(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    create_rule(client, token=access, condition={"field": "actor", "op": "eq", "value": "a"})
    create_service_token(client, owner_token=access)

    entries = client.get("/v1/admin/audit-log", headers=auth_headers(access)).json()
    actions = {entry["action"] for entry in entries["items"]}
    assert "tenant.created" in actions
    assert "detection_rule.created" in actions
    assert "service_token.created" in actions


def test_audit_log_redacts_sensitive_values(client: TestClient, db_session):
    """The audit log is readable by every admin and exported in compliance
    reports, so a secret landing there has effectively leaked."""
    from app.services.audit import record_audit

    record_audit(
        db_session,
        tenant_id="ten_x",
        action="test.action",
        detail={"password": "hunter2", "nested": {"api_key": "sk_live_x", "safe": "ok"}},
    )
    db_session.commit()

    from app.models.audit import AuditLogEntry

    entry = db_session.query(AuditLogEntry).filter(AuditLogEntry.action == "test.action").one()
    assert entry.detail["password"] == "[redacted]"
    assert entry.detail["nested"]["api_key"] == "[redacted]"
    assert entry.detail["nested"]["safe"] == "ok"


def test_audit_log_filter_by_action_prefix(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    create_rule(client, token=access, condition={"field": "actor", "op": "eq", "value": "a"})

    filtered = client.get("/v1/admin/audit-log?action=detection_rule.", headers=auth_headers(access)).json()
    assert filtered["total"] == 1
    assert filtered["items"][0]["action"] == "detection_rule.created"


def test_audit_log_is_tenant_scoped(client: TestClient):
    owner_a = signup(client, company="Acme", email="a@acme.test")
    create_rule(client, token=owner_a["accessToken"], condition={"field": "actor", "op": "eq", "value": "a"})

    owner_b = signup(client, company="Globex", email="b@globex.test")
    entries = client.get("/v1/admin/audit-log", headers=auth_headers(owner_b["accessToken"])).json()
    actions = {entry["action"] for entry in entries["items"]}
    assert "detection_rule.created" not in actions


def test_analyst_cannot_read_the_audit_log(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    client.post(
        "/v1/tenants/me/users",
        json={"email": "analyst@acme.test", "password": "correct-horse-1", "role": "analyst"},
        headers=auth_headers(access),
    )
    analyst = client.post(
        "/v1/auth/login", json={"email": "analyst@acme.test", "password": "correct-horse-1"}
    ).json()

    resp = client.get("/v1/admin/audit-log", headers=auth_headers(analyst["accessToken"]))
    assert resp.status_code == 403


def test_settings_overview_exposes_selectors_but_no_secrets(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    body = client.get("/v1/admin/settings", headers=auth_headers(owner["accessToken"])).json()

    assert body["queueBackend"] == "in_process"
    assert body["detectionOnIngest"] is True
    assert body["notificationWebhookConfigured"] is False
    # No credential-bearing field anywhere in the response.
    serialized = str(body).lower()
    for forbidden in ("secret", "password", "apikey", "api_key", "jwt"):
        assert forbidden not in serialized


# --------------------------------------------------------------------------
# SSO configuration guards
# --------------------------------------------------------------------------
def test_sso_required_cannot_be_set_while_disabled(client: TestClient):
    """Mandating an IdP that is switched off locks every user out with no
    in-product recovery."""
    owner = signup(client, company="Acme", email="owner@acme.test")
    resp = client.put(
        "/v1/admin/sso",
        json={
            "issuer": "https://idp.example",
            "clientId": "abc",
            "isEnabled": False,
            "ssoRequired": True,
        },
        headers=auth_headers(owner["accessToken"]),
    )
    assert resp.status_code == 422
    assert "disable password login" in resp.json()["detail"]


def test_sso_required_needs_a_verified_config(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    client.put(
        "/v1/admin/sso",
        json={"issuer": "https://idp.example", "clientId": "abc", "isEnabled": True},
        headers=auth_headers(access),
    )

    resp = client.put(
        "/v1/admin/sso",
        json={
            "issuer": "https://idp.example",
            "clientId": "abc",
            "isEnabled": True,
            "ssoRequired": True,
        },
        headers=auth_headers(access),
    )
    assert resp.status_code == 409
    assert "Verify the SSO configuration" in resp.json()["detail"]


def test_sso_rejects_an_http_issuer_and_saml(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]

    insecure = client.put(
        "/v1/admin/sso",
        json={"issuer": "http://idp.example", "clientId": "abc"},
        headers=auth_headers(access),
    )
    assert insecure.status_code == 422
    assert "https" in insecure.json()["detail"]

    saml = client.put(
        "/v1/admin/sso",
        json={"issuer": "https://idp.example", "clientId": "abc", "protocol": "saml"},
        headers=auth_headers(access),
    )
    assert saml.status_code == 422
    assert "not implemented" in saml.json()["detail"]


def test_sso_config_never_echoes_a_client_secret(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    body = client.put(
        "/v1/admin/sso",
        json={
            "issuer": "https://idp.example",
            "clientId": "abc",
            "clientSecretEnvVar": "ACME_OIDC_SECRET",
        },
        headers=auth_headers(access),
    ).json()

    assert body["clientSecretEnvVar"] == "ACME_OIDC_SECRET"
    assert "clientSecret" not in body


def test_admin_cannot_manage_sso(client: TestClient):
    """SSO config decides who can sign in at all; owner-only."""
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    client.post(
        "/v1/tenants/me/users",
        json={"email": "admin@acme.test", "password": "correct-horse-1", "role": "admin"},
        headers=auth_headers(access),
    )
    admin = client.post(
        "/v1/auth/login", json={"email": "admin@acme.test", "password": "correct-horse-1"}
    ).json()

    resp = client.put(
        "/v1/admin/sso",
        json={"issuer": "https://idp.example", "clientId": "abc"},
        headers=auth_headers(admin["accessToken"]),
    )
    assert resp.status_code == 403


def test_sso_role_mapping_takes_the_least_privileged_match():
    """Adding a user to any mapped group must not silently escalate them."""
    from app.models.sso import TenantSsoConfig
    from app.services.sso import map_role

    config = TenantSsoConfig(
        tenant_id="ten_x",
        issuer="https://idp.example",
        client_id="abc",
        role_mapping={"secops-admins": "admin", "everyone": "viewer"},
        default_role="viewer",
    )
    assert map_role(config, {"groups": ["secops-admins", "everyone"]}) == "viewer"
    assert map_role(config, {"groups": ["secops-admins"]}) == "admin"
    assert map_role(config, {"groups": ["unmapped"]}) == "viewer"


def test_oidc_code_exchange_refuses_rather_than_trusting_an_unverified_token(db_session):
    """A partial OIDC implementation is an auth bypass wearing a feature's
    costume. The refusal must name what is missing."""
    from app.models.sso import TenantSsoConfig
    from app.services.sso import SsoError, complete_login

    config = TenantSsoConfig(tenant_id="ten_x", issuer="https://idp.example", client_id="abc", is_enabled=True)
    with pytest.raises(SsoError, match="JWKS"):
        complete_login(db_session, config=config, code="abc123", code_verifier="v", redirect_uri="https://x/cb")


# --------------------------------------------------------------------------
# Observability
# --------------------------------------------------------------------------
def test_health_readiness_and_metrics_endpoints(client: TestClient):
    assert client.get("/health").json()["status"] == "ok"

    readiness = client.get("/readiness")
    assert readiness.status_code == 200
    assert readiness.json()["checks"]["database"] == "ok"

    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    assert "http_requests_total" in metrics.text


def test_request_id_header_is_returned_and_echoed(client: TestClient):
    resp = client.get("/health")
    assert resp.headers["X-Request-Id"]

    supplied = client.get("/health", headers={"X-Request-Id": "trace-from-lb"})
    assert supplied.headers["X-Request-Id"] == "trace-from-lb"


def test_metrics_registry_renders_prometheus_format():
    registry = MetricsRegistry()
    registry.increment("widgets_total", {"kind": "a"})
    registry.increment("widgets_total", {"kind": "a"})
    registry.observe("latency_ms", 7, {"route": "/x"})
    registry.set_gauge("queue_depth", 3)

    rendered = registry.render()
    assert 'widgets_total{kind="a"} 2' in rendered
    assert "# TYPE latency_ms histogram" in rendered
    assert 'latency_ms_bucket{le="10",route="/x"} 1' in rendered
    assert "latency_ms_count{route=\"/x\"} 1" in rendered
    assert "queue_depth 3" in rendered


def test_logging_extra_cannot_crash_a_caller():
    """stdlib logging raises KeyError when `extra` collides with a LogRecord
    attribute. "created" is a natural name for application data, and a log line
    taking down the request it describes -- only on the success path -- is a
    terrible failure mode."""
    import logging

    from app.core.logging import configure_logging

    configure_logging(force=True)
    logger = logging.getLogger("test.collision")
    # Must not raise.
    logger.info("event", extra={"created": 12, "module": "x", "name": "y", "tenant_id": "ten_a"})


@pytest.fixture(autouse=True)
def _reset_settings():
    yield
    reset_settings_cache()

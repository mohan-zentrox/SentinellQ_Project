"""C8 / FM4 (ML part): the frequency-baseline anomaly model.

These tests assert the model actually *learns a baseline and scores against it*,
rather than just that endpoints return 200. The substantive claim being verified
is that a routine event scores low and a novel one scores high, per tenant.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings, reset_settings_cache
from app.models.event import Event
from app.models.ml import MLModelVersion
from app.services.ml_detection import (
    get_active_model,
    score_event,
    score_events,
    train_model,
)
from tests.conftest import auth_headers, create_service_token, ingest, signup, simple_event


def _event(tenant_id: str, **overrides) -> Event:
    defaults = dict(
        tenant_id=tenant_id,
        source="collector",
        raw_payload={},
        event_category="authentication",
        event_action="login_succeeded",
        severity_hint="informational",
        actor="alice",
        target="app",
        source_ip="10.0.0.1",
        normalized={},
        occurred_at=datetime.now(timezone.utc),
        ingested_at=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return Event(**defaults)


def _seed_baseline(db_session, tenant_id: str, count: int = 300) -> None:
    """A boring, repetitive baseline: three known actors doing one known action."""
    base = datetime.now(timezone.utc) - timedelta(days=5)
    for index in range(count):
        db_session.add(
            _event(
                tenant_id,
                actor=["alice", "bob", "carol"][index % 3],
                source_ip=f"10.0.0.{index % 3}",
                occurred_at=base + timedelta(minutes=index),
            )
        )
    db_session.commit()


def test_training_refuses_on_insufficient_data(db_session):
    """A model fitted on a handful of events would flag everything."""
    db_session.add(_event("ten_small"))
    db_session.commit()

    assert train_model(db_session, tenant_id="ten_small") is None


def test_training_produces_an_active_versioned_model(db_session):
    _seed_baseline(db_session, "ten_a")
    model = train_model(db_session, tenant_id="ten_a")

    assert model is not None
    assert model.version == "v1"
    assert model.is_active is True
    assert model.training_event_count == 300
    assert model.algorithm == "frequency_baseline"
    assert "event_action" in model.feature_names
    assert model.parameters["total_events"] == 300


def test_retraining_increments_the_version_and_deactivates_the_old_one(db_session):
    _seed_baseline(db_session, "ten_a")
    first = train_model(db_session, tenant_id="ten_a")
    second = train_model(db_session, tenant_id="ten_a")

    assert first is not None and second is not None
    assert second.version == "v2"
    assert second.is_active is True
    db_session.refresh(first)
    assert first.is_active is False
    # The old version is retained so a rollback is possible and its alerts stay
    # explainable.
    assert db_session.query(MLModelVersion).count() == 2


def test_routine_event_scores_low_and_novel_event_scores_high(db_session):
    """The substantive claim: the model learned this tenant's normal."""
    _seed_baseline(db_session, "ten_a")
    model = train_model(db_session, tenant_id="ten_a")
    assert model is not None

    routine = _event("ten_a", actor="alice", source_ip="10.0.0.1", event_action="login_succeeded")
    routine_score, _ = score_event(model, routine)

    novel = _event(
        "ten_a",
        actor="unknown-service-account",
        source_ip="203.0.113.99",
        event_action="privilege_escalation",
        event_category="iam",
        severity_hint="critical",
    )
    novel_score, explanation = score_event(model, novel)

    assert routine_score < novel_score
    assert novel_score > 0.5
    # The finding is explainable: the drivers are named.
    features = {c["feature"] for c in explanation["contributions"]}
    assert "event_action" in features
    assert explanation["modelVersion"] == model.version


def test_known_actor_doing_a_novel_action_is_flagged(db_session):
    """Per-actor novelty: an action that is routine tenant-wide but new for this
    specific actor. A purely global frequency model misses this."""
    _seed_baseline(db_session, "ten_a")
    # Make "config_change" common tenant-wide, but only ever by "admin".
    base = datetime.now(timezone.utc) - timedelta(days=4)
    for index in range(60):
        db_session.add(
            _event("ten_a", actor="admin", event_action="config_change", occurred_at=base + timedelta(minutes=index))
        )
    db_session.commit()

    model = train_model(db_session, tenant_id="ten_a")
    assert model is not None

    admin_doing_it = _event("ten_a", actor="admin", event_action="config_change")
    alice_doing_it = _event("ten_a", actor="alice", event_action="config_change")

    admin_score, _ = score_event(model, admin_doing_it)
    alice_score, alice_explanation = score_event(model, alice_doing_it)

    assert alice_score > admin_score
    assert any(c["feature"] == "actor_action_novelty" for c in alice_explanation["contributions"])


def test_models_are_per_tenant(db_session):
    _seed_baseline(db_session, "ten_a")
    _seed_baseline(db_session, "ten_b", count=250)
    train_model(db_session, tenant_id="ten_a")

    assert get_active_model(db_session, tenant_id="ten_a") is not None
    # Tenant B has telemetry but no model; scoring must be a no-op, not a
    # borrow of tenant A's baseline.
    assert get_active_model(db_session, tenant_id="ten_b") is None
    assert score_events(db_session, tenant_id="ten_b", events=[_event("ten_b")]) == []


def test_scoring_creates_ml_attributed_alerts_above_threshold(db_session):
    _seed_baseline(db_session, "ten_a")
    model = train_model(db_session, tenant_id="ten_a")
    assert model is not None
    model.score_threshold = 0.3  # force the anomalous event over the bar
    db_session.flush()

    anomalous = _event(
        "ten_a",
        actor="brand-new-actor",
        source_ip="198.51.100.200",
        event_action="data_exfiltration",
        event_category="exfil",
        severity_hint="critical",
    )
    db_session.add(anomalous)
    db_session.flush()

    alerts = score_events(db_session, tenant_id="ten_a", events=[anomalous])
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.detection_source == "ml"
    assert alert.ml_model_version == model.version
    assert alert.ml_score is not None and alert.ml_score >= 0.3
    assert alert.rule_id is None
    # Never "critical": an unsupervised model with no feedback loop has not
    # earned the right to wake someone up.
    assert alert.severity in ("low", "medium", "high")


def test_scoring_updates_model_counters(db_session):
    _seed_baseline(db_session, "ten_a")
    model = train_model(db_session, tenant_id="ten_a")
    assert model is not None

    events = [_event("ten_a") for _ in range(3)]
    for event in events:
        db_session.add(event)
    db_session.flush()

    score_events(db_session, tenant_id="ten_a", events=events)
    db_session.refresh(model)
    assert model.scored_event_count == 3


def test_ml_detection_is_off_by_default_in_the_pipeline(client: TestClient):
    """An unsupervised model with no analyst feedback produces false positives;
    enabling it silently for every tenant would be the wrong default."""
    assert get_settings().ml_detection_enabled is False

    owner = signup(client, company="Acme", email="owner@acme.test")
    service_token = create_service_token(client, owner_token=owner["accessToken"])
    body = ingest(client, service_token=service_token, events=[simple_event()])
    assert body["alertsCreated"] == 0


# --------------------------------------------------------------------------
# Admin API
# --------------------------------------------------------------------------
def test_train_endpoint_reports_insufficient_data_without_erroring(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    resp = client.post(
        "/v1/admin/ml-models/train",
        json={"windowDays": 30},
        headers=auth_headers(owner["accessToken"]),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["trained"] is False
    assert "Not enough telemetry" in body["detail"]


def test_train_activate_and_adjust_threshold_via_api(client: TestClient, db_session):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
    tenant_id = client.get("/v1/tenants/me", headers=auth_headers(access)).json()["id"]
    _seed_baseline(db_session, tenant_id)

    trained = client.post(
        "/v1/admin/ml-models/train",
        json={"windowDays": 30, "activate": True},
        headers=auth_headers(access),
    ).json()
    assert trained["trained"] is True
    model_id = trained["model"]["id"]
    assert trained["model"]["isActive"] is True

    listed = client.get("/v1/admin/ml-models", headers=auth_headers(access)).json()
    assert len(listed) == 1
    # The learned parameters are not shipped in the listing.
    assert "parameters" not in listed[0]

    adjusted = client.patch(
        f"/v1/admin/ml-models/{model_id}",
        json={"scoreThreshold": 0.95},
        headers=auth_headers(access),
    ).json()
    assert adjusted["scoreThreshold"] == 0.95

    # Kill switch: deactivating the only model disables ML scoring.
    deactivated = client.patch(
        f"/v1/admin/ml-models/{model_id}",
        json={"isActive": False},
        headers=auth_headers(access),
    ).json()
    assert deactivated["isActive"] is False


def test_ml_models_are_tenant_scoped_in_the_api(client: TestClient, db_session):
    owner_a = signup(client, company="Acme", email="a@acme.test")
    tenant_a = client.get("/v1/tenants/me", headers=auth_headers(owner_a["accessToken"])).json()["id"]
    _seed_baseline(db_session, tenant_a)
    client.post(
        "/v1/admin/ml-models/train",
        json={"windowDays": 30},
        headers=auth_headers(owner_a["accessToken"]),
    )

    owner_b = signup(client, company="Globex", email="b@globex.test")
    listed = client.get("/v1/admin/ml-models", headers=auth_headers(owner_b["accessToken"])).json()
    assert listed == []


def test_analyst_cannot_train_models(client: TestClient):
    owner = signup(client, company="Acme", email="owner@acme.test")
    access = owner["accessToken"]
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
        "/v1/admin/ml-models/train",
        json={},
        headers=auth_headers(analyst["accessToken"]),
    )
    assert resp.status_code == 403


@pytest.fixture(autouse=True)
def _restore_settings():
    yield
    reset_settings_cache()

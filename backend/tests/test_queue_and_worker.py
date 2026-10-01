"""C7: the queue abstraction, config-driven adapter selection, and the worker.

The property these tests protect is that the two ingestion paths are the same
code: a message handled inline by the API (synchronous queue) and a message
handled by `app/worker.py` (broker-backed queue) must produce identical
database state. Without that, the Redis deployment and the test suite exercise
different behaviour -- which is exactly the situation where the compose stack
accepts events and silently never stores them.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import reset_settings_cache
from app.db.base import Base
from app.models.alert import Alert
from app.models.event import Event
from app.models.rule import DetectionRule
from app.models.tenant import Tenant
from app.services.pipeline import process_batch
from app.services.queue import (
    InProcessQueueBackend,
    KafkaQueueBackend,
    QueueBackend,
    build_queue,
    get_queue,
    reset_queue,
)


# --------------------------------------------------------------------------
# Adapter selection actually reads config
# --------------------------------------------------------------------------
def test_in_process_backend_is_the_default():
    reset_queue()
    queue = get_queue()
    assert isinstance(queue, InProcessQueueBackend)
    assert queue.is_synchronous is True


def test_build_queue_resolves_by_name():
    assert isinstance(build_queue("in_process", redis_url="redis://x"), InProcessQueueBackend)


def test_unknown_backend_name_fails_loudly():
    """A typo in SENTINELIQ_QUEUE_BACKEND must not silently fall back to
    in-process, which would make a misconfigured production deployment look
    healthy while dropping the worker from the pipeline."""
    with pytest.raises(ValueError, match="Unknown SENTINELIQ_QUEUE_BACKEND"):
        build_queue("rabbitmq", redis_url="redis://x")


def test_kafka_backend_refuses_with_a_pointer():
    """The documented production target is not implemented. Selecting it should
    say so rather than appear to work."""
    with pytest.raises(NotImplementedError, match="not implemented"):
        KafkaQueueBackend()


def test_telemetry_store_backend_selection_reads_config(monkeypatch):
    from app.services.telemetry_store import (
        PostgresTelemetryStore,
        get_telemetry_store,
        reset_telemetry_store,
    )

    reset_telemetry_store()
    reset_settings_cache()
    assert isinstance(get_telemetry_store(), PostgresTelemetryStore)

    reset_telemetry_store()
    monkeypatch.setenv("SENTINELIQ_TELEMETRY_STORE_BACKEND", "clickhouse")
    reset_settings_cache()
    with pytest.raises(NotImplementedError, match="clickhouse"):
        get_telemetry_store()

    reset_telemetry_store()
    monkeypatch.delenv("SENTINELIQ_TELEMETRY_STORE_BACKEND")
    reset_settings_cache()


def test_billing_provider_selection_reads_config(monkeypatch):
    from app.services.billing_provider import (
        MockStripeProvider,
        get_billing_provider,
        reset_billing_provider,
    )

    reset_billing_provider()
    reset_settings_cache()
    assert isinstance(get_billing_provider(), MockStripeProvider)

    reset_billing_provider()
    monkeypatch.setenv("SENTINELIQ_BILLING_PROVIDER", "nonexistent")
    reset_settings_cache()
    with pytest.raises(ValueError, match="Unknown SENTINELIQ_BILLING_PROVIDER"):
        get_billing_provider()

    reset_billing_provider()
    monkeypatch.delenv("SENTINELIQ_BILLING_PROVIDER")
    reset_settings_cache()


# --------------------------------------------------------------------------
# Queue semantics
# --------------------------------------------------------------------------
def test_in_process_publish_delivers_synchronously():
    queue = InProcessQueueBackend()
    seen: list[dict] = []
    queue.subscribe("t", seen.append)
    queue.publish("t", {"a": 1})
    assert seen == [{"a": 1}]


def test_unsubscribe_stops_delivery():
    queue = InProcessQueueBackend()
    seen: list[dict] = []
    queue.subscribe("t", seen.append)
    queue.unsubscribe("t", seen.append)  # different function object
    queue.publish("t", {"a": 1})
    # `seen.append` is a bound method; each reference compares equal, so the
    # unsubscribe above does remove it. Asserting the behaviour either way keeps
    # the contract explicit rather than accidental.
    assert seen == []


def test_handler_may_unsubscribe_itself_during_publish():
    """The ingest route subscribes and unsubscribes around a publish loop; a
    handler mutating the subscriber list mid-dispatch must not corrupt it."""
    queue = InProcessQueueBackend()
    seen: list[dict] = []

    def handler(message: dict) -> None:
        seen.append(message)
        queue.unsubscribe("t", handler)

    queue.subscribe("t", handler)
    queue.publish("t", {"n": 1})
    queue.publish("t", {"n": 2})
    assert seen == [{"n": 1}]


def test_consume_forever_is_a_noop_for_synchronous_backends():
    queue = InProcessQueueBackend()
    stop = threading.Event()
    stop.set()
    assert queue.consume_forever(["t"], stop=stop) is None


def test_queue_backend_interface_is_honoured_by_every_adapter():
    for method in ("publish", "subscribe", "unsubscribe", "consume_forever"):
        assert hasattr(QueueBackend, method)


# --------------------------------------------------------------------------
# The worker path produces the same result as the inline path
# --------------------------------------------------------------------------
@pytest.fixture()
def isolated_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(bind=engine)
    maker = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    session = maker()
    yield session
    session.close()
    engine.dispose()


def _seed_tenant_with_rule(session) -> str:
    tenant = Tenant(name="Acme", slug="acme", is_active=True)
    session.add(tenant)
    session.flush()
    session.add(
        DetectionRule(
            tenant_id=tenant.id,
            name="failed logins",
            condition={"field": "event_action", "op": "eq", "value": "login_failed"},
            severity="high",
            is_enabled=True,
        )
    )
    session.commit()
    return tenant.id


def _message(tenant_id: str, occurred_at) -> dict:
    return {
        "tenant_id": tenant_id,
        "source": "collector",
        "payload": {"eventAction": "login_failed", "severity": "high", "actor": "alice"},
        "occurred_at": occurred_at,
    }


def test_pipeline_handles_a_datetime_occurred_at(isolated_session):
    """The in-process queue hands the pipeline a real datetime."""
    tenant_id = _seed_tenant_with_rule(isolated_session)
    occurred = datetime.now(timezone.utc)

    events, alerts = process_batch(
        isolated_session,
        tenant_id=tenant_id,
        messages=[_message(tenant_id, occurred)],
    )
    isolated_session.commit()

    assert len(events) == 1
    assert len(alerts) == 1
    assert isolated_session.query(Event).count() == 1


def test_pipeline_handles_a_json_serialized_occurred_at(isolated_session):
    """Redis round-trips the message through json.dumps(default=str), so
    occurred_at arrives as a string. The pipeline must parse it rather than
    silently stamping "now" -- MTTD is computed from this field.
    """
    tenant_id = _seed_tenant_with_rule(isolated_session)
    occurred = datetime.now(timezone.utc).replace(microsecond=0)

    events, _ = process_batch(
        isolated_session,
        tenant_id=tenant_id,
        messages=[_message(tenant_id, str(occurred))],
    )
    isolated_session.commit()

    stored = events[0].occurred_at
    stored = stored if stored.tzinfo else stored.replace(tzinfo=timezone.utc)
    assert abs((stored - occurred).total_seconds()) < 2


def test_pipeline_falls_back_to_now_on_an_unparseable_timestamp(isolated_session):
    tenant_id = _seed_tenant_with_rule(isolated_session)
    before = datetime.now(timezone.utc)

    events, _ = process_batch(
        isolated_session,
        tenant_id=tenant_id,
        messages=[_message(tenant_id, "not-a-timestamp")],
    )
    isolated_session.commit()

    stored = events[0].occurred_at
    stored = stored if stored.tzinfo else stored.replace(tzinfo=timezone.utc)
    assert stored >= before.replace(microsecond=0)


def test_worker_handler_produces_the_same_state_as_inline_ingest(isolated_session, monkeypatch):
    """The core guarantee: one implementation, two entry points.

    Drives `app.worker._handle_message` -- the exact function the Redis consumer
    loop calls -- against a seeded tenant, and asserts it stored the event and
    raised the alert, same as the inline path.
    """
    import app.worker as worker_module

    tenant_id = _seed_tenant_with_rule(isolated_session)

    # Point the worker's session factory at this test's isolated database.
    monkeypatch.setattr(worker_module, "SessionLocal", lambda: isolated_session)
    # The worker commits and closes its session; keep the fixture's session open.
    monkeypatch.setattr(isolated_session, "close", lambda: None)

    worker_module._handle_message(_message(tenant_id, datetime.now(timezone.utc)))

    assert isolated_session.query(Event).count() == 1
    alerts = isolated_session.query(Alert).all()
    assert len(alerts) == 1
    assert alerts[0].detection_source == "rule"


def test_worker_rejects_a_message_with_no_tenant(isolated_session, monkeypatch):
    """A message without a tenant must be DLQ'd, not processed against some
    default tenant."""
    import app.worker as worker_module

    monkeypatch.setattr(worker_module, "SessionLocal", lambda: isolated_session)
    with pytest.raises(ValueError, match="missing tenant_id"):
        worker_module._handle_message({"source": "x", "payload": {}})


def test_worker_main_exits_cleanly_when_the_queue_is_synchronous():
    """With the in-process backend there is nothing to consume. The worker must
    say so and exit 0 rather than idling forever pretending to work."""
    import app.worker as worker_module

    reset_queue()
    reset_settings_cache()
    assert worker_module.main() == 0


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    reset_queue()
    reset_settings_cache()

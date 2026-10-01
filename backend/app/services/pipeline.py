"""FM2/FM3/FM4: the ingestion pipeline, shared by the API and the worker.

There is exactly one implementation of "what happens to a raw event", and
both entry points call it:

- `app/api/v1/events.py` publishes to the queue. With the in-process backend
  that delivers synchronously, so the pipeline runs inside the request.
- `app/worker.py` subscribes to the same topic. With the Redis backend the
  API only enqueues and this is where the work actually happens.

Keeping the stages here (rather than inline in the route, as an earlier
version did) is what makes those two paths behaviourally identical.

Stages, in order:
  1. normalize   -- raw payload -> OCSF/ECS-aligned fields (services/normalizer)
  2. persist     -- write through the TelemetryStore interface
  3. enrich      -- FM5 threat-intel annotation (services/enrichment)
  4. detect      -- FM4 rules + C8 ML scoring over the just-written batch
  5. notify      -- FM6 alerting for anything that crossed the threshold
  6. automate    -- FM7 SOAR playbook triggers

Each stage after `persist` is best-effort and individually guarded: an
enrichment feed being down, or a webhook timing out, must never lose an event
that was already accepted and stored.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.alert import Alert
from app.models.event import Event
from app.services.normalizer import normalize_event
from app.services.telemetry_store import get_telemetry_store

logger = logging.getLogger(__name__)


def _as_datetime(value: Any) -> datetime:
    """Coerce an occurred_at that may have crossed a JSON boundary.

    The in-process queue hands us a real datetime; Redis hands us whatever
    `json.dumps(default=str)` produced. Normalizing here keeps the pipeline
    backend-agnostic.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            logger.warning("pipeline.unparseable_occurred_at", extra={"value": value})
    return datetime.now(timezone.utc)


def persist_raw_event(db: Session, message: dict[str, Any]) -> Event:
    """Stages 1-2: normalize and store. Does not commit."""
    normalized_fields = normalize_event(message["payload"])
    store = get_telemetry_store()
    occurred_at = _as_datetime(message.get("occurred_at"))
    return store.write_event(
        db,
        tenant_id=message["tenant_id"],
        event_data={
            "source": message["source"],
            "raw_payload": message["payload"],
            "occurred_at": occurred_at,
            "ingested_at": datetime.now(timezone.utc),
            **normalized_fields,
        },
    )


def enrich_events(db: Session, *, tenant_id: str, events: list[Event]) -> None:
    """Stage 3: FM5 threat-intel annotation. Best-effort."""
    settings = get_settings()
    if not settings.threat_intel_enrich_on_ingest or not events:
        return
    try:
        from app.services.enrichment import enrich_event

        for event in events:
            enrich_event(db, tenant_id=tenant_id, event=event)
        db.flush()
    except Exception:  # noqa: BLE001 - enrichment must never drop a stored event
        logger.exception("pipeline.enrichment_failed", extra={"tenant_id": tenant_id})


def detect_over_events(db: Session, *, tenant_id: str, events: list[Event]) -> list[Alert]:
    """Stage 4: FM4 rules + C8 ML over the just-written batch.

    Passing the batch as the candidate set is the whole point: detection runs
    against the N events we just ingested, not against the tenant's entire
    corpus.
    """
    settings = get_settings()
    if not settings.detection_on_ingest or not events:
        return []

    alerts: list[Alert] = []
    try:
        from app.services.rule_engine import run_all_rules

        alerts.extend(run_all_rules(db, tenant_id=tenant_id, events=events))
    except Exception:  # noqa: BLE001 - a bad rule must not drop stored events
        logger.exception("pipeline.rule_detection_failed", extra={"tenant_id": tenant_id})

    if settings.ml_detection_enabled:
        try:
            from app.services.ml_detection import score_events

            alerts.extend(score_events(db, tenant_id=tenant_id, events=events))
        except Exception:  # noqa: BLE001
            logger.exception("pipeline.ml_detection_failed", extra={"tenant_id": tenant_id})

    return alerts


def notify_and_automate(db: Session, *, tenant_id: str, alerts: list[Alert]) -> None:
    """Stages 5-6: FM6 notifications and FM7 playbooks. Both best-effort."""
    if not alerts:
        return

    try:
        from app.services.notifications import notify_alerts

        notify_alerts(db, tenant_id=tenant_id, alerts=alerts)
    except Exception:  # noqa: BLE001
        logger.exception("pipeline.notification_failed", extra={"tenant_id": tenant_id})

    if get_settings().soar_enabled:
        try:
            from app.services.soar import trigger_on_alerts

            trigger_on_alerts(db, tenant_id=tenant_id, alerts=alerts)
        except Exception:  # noqa: BLE001
            logger.exception("pipeline.soar_failed", extra={"tenant_id": tenant_id})


def run_post_persist_stages(db: Session, *, tenant_id: str, events: list[Event]) -> list[Alert]:
    """Stages 3-6 over an already-persisted batch. Does not commit.

    Split out from persistence on purpose: the queue handler only persists (so
    a batch of 500 events becomes 500 writes but *one* detection pass), and
    the caller runs these stages once the whole batch is in. Running detection
    per message instead would evaluate every rule 500 times and emit 500
    near-identical alerts rather than one.
    """
    if not events:
        return []
    enrich_events(db, tenant_id=tenant_id, events=events)
    alerts = detect_over_events(db, tenant_id=tenant_id, events=events)
    notify_and_automate(db, tenant_id=tenant_id, alerts=alerts)
    return alerts


def process_batch(db: Session, *, tenant_id: str, messages: list[dict[str, Any]]) -> tuple[list[Event], list[Alert]]:
    """Run the whole pipeline over one tenant's batch. Does not commit.

    Returns (stored events, alerts created) so the caller can shape its
    response and the worker can log throughput.
    """
    events = [persist_raw_event(db, message) for message in messages]
    alerts = run_post_persist_stages(db, tenant_id=tenant_id, events=events)
    return events, alerts


def process_message(db: Session, message: dict[str, Any]) -> Event:
    """Single-message entry point used by the worker's queue handler."""
    events, _ = process_batch(db, tenant_id=message["tenant_id"], messages=[message])
    return events[0]

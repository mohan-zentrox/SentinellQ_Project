"""FM2/FM3: Ingestion, normalization & storage.

POST /v1/events/ingest is service-token authenticated (machine clients),
tenant-scoped via the token's owning tenant, and quota-enforced (FM10). It
publishes every event in the batch to the queue abstraction and then, *if the
queue delivers synchronously*, runs the post-persist pipeline stages
(enrichment, detection, notification, automation) once over the whole batch.

With a broker-backed queue (`SENTINELIQ_QUEUE_BACKEND=redis`) nothing is
processed in the request at all -- `app/worker.py` owns the pipeline and the
response says `processing: "queued"`. Clients must treat a 202 as "accepted",
not "stored", and read `eventIds` only when `processing == "synchronous"`.

GET /v1/events is JWT-authenticated (human analysts), tenant-scoped via the
caller's own tenant, paginated and filterable.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.deps import current_period, enforce_ingest_quota, get_current_user, get_tenant_from_service_token
from app.db.session import get_db
from app.models.event import Event
from app.models.tenant import Tenant
from app.models.user import User
from app.schemas.event import (
    EventDetailOut,
    EventIngestBatchRequest,
    EventIngestResponse,
    EventListResponse,
    EventOut,
)
from app.services.billing_meter import record_event_usage
from app.services.pipeline import persist_raw_event, run_post_persist_stages
from app.services.queue import TOPIC_RAW_EVENTS, get_queue
from app.services.telemetry_store import EventFilter, get_telemetry_store

router = APIRouter(prefix="/events", tags=["events"])


@router.post("/ingest", response_model=EventIngestResponse, status_code=status.HTTP_202_ACCEPTED)
def ingest_events(
    payload: EventIngestBatchRequest,
    tenant: Tenant = Depends(get_tenant_from_service_token),
    db: Session = Depends(get_db),
) -> EventIngestResponse:
    period = current_period()
    # FM10 quota gate: 429s before any event in the batch is persisted once
    # the tenant is already at/over quota.
    enforce_ingest_quota(tenant, db, period)

    queue = get_queue()
    stored: list[Event] = []

    def _persist_handler(message: dict) -> None:
        # Persistence only. Enrichment/detection/notification run once over
        # the whole batch below, not once per event.
        stored.append(persist_raw_event(db, message))

    queue.subscribe(TOPIC_RAW_EVENTS, _persist_handler)
    try:
        for item in payload.events:
            queue.publish(
                TOPIC_RAW_EVENTS,
                {
                    "tenant_id": tenant.id,
                    "source": item.source,
                    "payload": item.payload,
                    "occurred_at": item.occurred_at or datetime.now(timezone.utc),
                },
            )
    finally:
        # Avoid leaking handlers across requests: with the in-process backend
        # subscribers are process-global.
        queue.unsubscribe(TOPIC_RAW_EVENTS, _persist_handler)

    alerts = run_post_persist_stages(db, tenant_id=tenant.id, events=stored)

    # Meter what we actually accepted. In queued mode nothing is stored yet, so
    # bill the published count; app/worker.py deliberately does not meter
    # again, or every tenant would be charged twice for the same batch.
    billable = len(stored) if queue.is_synchronous else len(payload.events)
    record_event_usage(db, tenant_id=tenant.id, period=period, count=billable)
    db.commit()

    return EventIngestResponse(
        accepted=billable,
        event_ids=[e.id for e in stored],
        alerts_created=len(alerts),
        processing="synchronous" if queue.is_synchronous else "queued",
    )


@router.get("", response_model=EventListResponse)
def list_events(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    severity: str | None = Query(default=None),
    event_category: str | None = Query(default=None, alias="eventCategory"),
    event_action: str | None = Query(default=None, alias="eventAction"),
    actor: str | None = Query(default=None),
    source_ip: str | None = Query(default=None, alias="sourceIp"),
    source: str | None = Query(default=None),
    occurred_after: datetime | None = Query(default=None, alias="occurredAfter"),
    occurred_before: datetime | None = Query(default=None, alias="occurredBefore"),
    search: str | None = Query(default=None, max_length=200),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> EventListResponse:
    store = get_telemetry_store()
    rows, total = store.query_events(
        db,
        tenant_id=current_user.tenant_id,
        page=page,
        page_size=page_size,
        filters=EventFilter(
            severity=severity,
            event_category=event_category,
            event_action=event_action,
            actor=actor,
            source_ip=source_ip,
            source=source,
            occurred_after=occurred_after,
            occurred_before=occurred_before,
            search=search,
        ),
    )
    return EventListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[EventOut.model_validate(row) for row in rows],
    )


@router.get("/{event_id}", response_model=EventDetailOut)
def get_event(
    event_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> EventDetailOut:
    store = get_telemetry_store()
    rows = store.get_events(db, tenant_id=current_user.tenant_id, event_ids=[event_id])
    if not rows:
        # A cross-tenant read is indistinguishable from "not found" on purpose.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Event not found")
    return EventDetailOut.model_validate(rows[0])

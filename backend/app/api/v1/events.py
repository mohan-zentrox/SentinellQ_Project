"""FM2/FM3: Ingestion, normalization & storage.

POST /v1/events/ingest is service-token authenticated (machine clients),
tenant-scoped via the token's owning tenant, quota-enforced (FM10), and
publishes to the queue abstraction before the in-process normalizer
consumes and writes into the telemetry store abstraction.

GET /v1/events is JWT-authenticated (human analysts), tenant-scoped via the
caller's own tenant, paginated.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.core.deps import enforce_ingest_quota, get_current_user, get_tenant_from_service_token
from app.db.session import get_db
from app.models.tenant import Tenant
from app.models.user import User
from app.schemas.event import (
    EventIngestBatchRequest,
    EventIngestResponse,
    EventListResponse,
    EventOut,
)
from app.services.normalizer import normalize_event
from app.services.queue import TOPIC_RAW_EVENTS, get_queue
from app.services.telemetry_store import get_telemetry_store

router = APIRouter(prefix="/events", tags=["events"])


def _current_period() -> str:
    now = datetime.now(timezone.utc)
    return f"{now.year:04d}-{now.month:02d}"


@router.post("/ingest", response_model=EventIngestResponse, status_code=status.HTTP_202_ACCEPTED)
def ingest_events(
    payload: EventIngestBatchRequest,
    tenant: Tenant = Depends(get_tenant_from_service_token),
    db: Session = Depends(get_db),
) -> EventIngestResponse:
    period = _current_period()
    # FM10 quota gate: 429s before any event in the batch is persisted once
    # the tenant is already at/over quota.
    counter = enforce_ingest_quota(tenant, db, period)

    store = get_telemetry_store()
    queue = get_queue()
    written_ids: list[str] = []

    def _handle_raw_event(message: dict) -> None:
        normalized_fields = normalize_event(message["payload"])
        event = store.write_event(
            db,
            tenant_id=tenant.id,
            event_data={
                "source": message["source"],
                "raw_payload": message["payload"],
                "occurred_at": message.get("occurred_at") or datetime.now(timezone.utc),
                "ingested_at": datetime.now(timezone.utc),
                **normalized_fields,
            },
        )
        written_ids.append(event.id)

    queue.subscribe(TOPIC_RAW_EVENTS, _handle_raw_event)
    try:
        for item in payload.events:
            queue.publish(
                TOPIC_RAW_EVENTS,
                {
                    "tenant_id": tenant.id,
                    "source": item.source,
                    "payload": item.payload,
                    "occurred_at": item.occurred_at,
                },
            )
    finally:
        queue.unsubscribe(TOPIC_RAW_EVENTS, _handle_raw_event)  # avoid leaking handlers across requests

    counter.event_count += len(written_ids)
    db.add(counter)
    db.commit()

    return EventIngestResponse(accepted=len(written_ids), event_ids=written_ids)


@router.get("", response_model=EventListResponse)
def list_events(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    severity: str | None = Query(default=None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> EventListResponse:
    store = get_telemetry_store()
    rows, total = store.query_events(
        db, tenant_id=current_user.tenant_id, page=page, page_size=page_size, severity=severity
    )
    return EventListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[EventOut.model_validate(row) for row in rows],
    )

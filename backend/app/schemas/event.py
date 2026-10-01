from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from app.schemas.common import CamelModel, PaginatedResponse


class EventIngestRequest(CamelModel):
    source: str = Field(min_length=1, max_length=255)
    payload: dict[str, Any] = Field(default_factory=dict)
    occurred_at: datetime | None = None


class EventIngestBatchRequest(CamelModel):
    events: list[EventIngestRequest] = Field(min_length=1, max_length=500)


class EventOut(CamelModel):
    id: str
    tenant_id: str
    source: str
    event_category: str
    event_action: str
    severity_hint: str
    actor: str | None
    target: str | None
    source_ip: str | None
    #: FM5 threat-intel annotation; null when the event has not been enriched.
    enrichment: dict[str, Any] | None = None
    occurred_at: datetime
    ingested_at: datetime


class EventDetailOut(EventOut):
    """Event detail view: adds the raw and normalized documents, which are too
    heavy to include in a 200-row list response."""

    raw_payload: dict[str, Any]
    normalized: dict[str, Any]


class EventIngestResponse(CamelModel):
    accepted: int
    event_ids: list[str]
    alerts_created: int = 0
    #: "synchronous" -- the batch was normalized, stored and evaluated during
    #: this request, and `eventIds` is populated.
    #: "queued" -- the batch was enqueued for app/worker.py; `eventIds` is
    #: empty and clients must not treat the 202 as "stored".
    processing: str = "synchronous"


class EventListResponse(PaginatedResponse):
    items: list[EventOut]

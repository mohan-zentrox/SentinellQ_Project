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
    occurred_at: datetime
    ingested_at: datetime


class EventIngestResponse(CamelModel):
    accepted: int
    event_ids: list[str]


class EventListResponse(PaginatedResponse):
    items: list[EventOut]

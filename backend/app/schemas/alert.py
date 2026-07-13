from __future__ import annotations

from datetime import datetime

from pydantic import Field

from app.schemas.common import CamelModel, PaginatedResponse


class AlertOut(CamelModel):
    id: str
    tenant_id: str
    rule_id: str | None
    title: str
    description: str
    severity: str
    status: str
    event_ids: list[str]
    case_id: str | None
    created_at: datetime


class AlertListResponse(PaginatedResponse):
    items: list[AlertOut]


class PromoteAlertsRequest(CamelModel):
    alert_ids: list[str] = Field(min_length=1)
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=4000)

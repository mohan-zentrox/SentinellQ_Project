from __future__ import annotations

from datetime import datetime

from pydantic import Field

from app.schemas.common import CamelModel, PaginatedResponse


class CaseCreate(CamelModel):
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=4000)
    severity: str = Field(default="medium")
    alert_ids: list[str] = Field(default_factory=list)


class CaseOut(CamelModel):
    id: str
    tenant_id: str
    title: str
    description: str
    status: str
    severity: str
    assignee_user_id: str | None
    alert_ids: list[str]
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None


class CaseListResponse(PaginatedResponse):
    items: list[CaseOut]


class CaseStatusUpdate(CamelModel):
    status: str


class CaseAssignUpdate(CamelModel):
    assignee_user_id: str


class CaseTimelineEntryOut(CamelModel):
    id: str
    case_id: str
    entry_type: str
    message: str
    actor_user_id: str | None
    created_at: datetime

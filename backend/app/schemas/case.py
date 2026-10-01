from __future__ import annotations

from datetime import datetime

from pydantic import Field

from app.schemas.common import CamelModel, PaginatedResponse

SEVERITY_PATTERN = "^(informational|low|medium|high|critical)$"
STATUS_PATTERN = "^(new|investigating|resolved|escalated)$"


class CaseCreate(CamelModel):
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=4000)
    severity: str = Field(default="medium", pattern=SEVERITY_PATTERN)
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


class CaseUpdate(CamelModel):
    """PATCH body for the case's own fields (not status, which is a state-machine
    transition with its own endpoint)."""

    title: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4000)
    severity: str | None = Field(default=None, pattern=SEVERITY_PATTERN)


class CaseStatusUpdate(CamelModel):
    status: str = Field(pattern=STATUS_PATTERN)
    #: Optional note recorded on the timeline alongside the transition -- the
    #: "why" that a bare status change loses.
    note: str | None = Field(default=None, max_length=2000)


class CaseAssignUpdate(CamelModel):
    #: Null unassigns the case.
    assignee_user_id: str | None = None


class CaseCommentCreate(CamelModel):
    message: str = Field(min_length=1, max_length=2000)


class CaseTimelineEntryOut(CamelModel):
    id: str
    case_id: str
    entry_type: str
    message: str
    actor_user_id: str | None
    created_at: datetime

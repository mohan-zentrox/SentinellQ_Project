from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from app.schemas.common import CamelModel, PaginatedResponse

TRIGGER_PATTERN = "^(alert_created|case_escalated|case_created|manual)$"


class PlaybookActionSpec(CamelModel):
    action: str = Field(min_length=1, max_length=100)
    params: dict[str, Any] = Field(default_factory=dict)


class PlaybookCreate(CamelModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=1000)
    trigger: str = Field(default="alert_created", pattern=TRIGGER_PATTERN)
    #: Reuses the FM4 condition DSL, evaluated against the triggering object.
    trigger_condition: dict[str, Any] | None = None
    actions: list[PlaybookActionSpec] = Field(min_length=1, max_length=25)
    is_enabled: bool = True
    #: Strongly recommended for a new playbook: records intended effects without
    #: performing them.
    dry_run: bool = True


class PlaybookUpdate(CamelModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1000)
    trigger: str | None = Field(default=None, pattern=TRIGGER_PATTERN)
    trigger_condition: dict[str, Any] | None = None
    actions: list[PlaybookActionSpec] | None = Field(default=None, min_length=1, max_length=25)
    is_enabled: bool | None = None
    dry_run: bool | None = None


class PlaybookOut(CamelModel):
    id: str
    tenant_id: str
    name: str
    description: str
    trigger: str
    trigger_condition: dict[str, Any] | None
    actions: list[dict[str, Any]]
    is_enabled: bool
    dry_run: bool
    run_count: int
    last_run_at: datetime | None
    created_at: datetime
    #: Computed: does this playbook contain a high-risk action, and therefore
    #: require per-run approval?
    requires_approval: bool = False


class ActionRecordOut(CamelModel):
    id: str
    sequence: int
    action: str
    params: dict[str, Any]
    status: str
    is_high_risk: bool
    result: dict[str, Any]
    error: str | None
    duration_ms: int | None
    created_at: datetime


class PlaybookRunOut(CamelModel):
    id: str
    tenant_id: str
    playbook_id: str
    status: str
    trigger: str
    subject_type: str | None
    subject_id: str | None
    dry_run: bool
    requires_approval: bool
    approved_by_user_id: str | None
    approved_at: datetime | None
    rejected_by_user_id: str | None
    rejected_at: datetime | None
    rejection_reason: str | None
    triggered_by_user_id: str | None
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    created_at: datetime


class PlaybookRunDetailOut(PlaybookRunOut):
    #: Defaulted because the route builds this from a PlaybookRun ORM row (which
    #: has no `actions` attribute) and then attaches the records it queried
    #: separately. A required field here makes model_validate(run) fail.
    actions: list[ActionRecordOut] = Field(default_factory=list)


class PlaybookRunListResponse(PaginatedResponse):
    items: list[PlaybookRunOut]


class ActionRegistryEntry(CamelModel):
    name: str
    description: str
    is_high_risk: bool
    halt_on_failure: bool


class RunPlaybookRequest(CamelModel):
    """Manually trigger a playbook against an alert or case."""

    alert_id: str | None = None
    case_id: str | None = None


class RejectRunRequest(CamelModel):
    reason: str | None = Field(default=None, max_length=500)

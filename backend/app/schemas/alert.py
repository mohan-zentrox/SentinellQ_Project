from __future__ import annotations

from datetime import datetime
from typing import Any

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
    detection_source: str = "rule"
    ml_score: float | None = None
    ml_model_version: str | None = None
    dismissed_at: datetime | None = None
    dismissed_by_user_id: str | None = None
    dismiss_reason: str | None = None
    notified_at: datetime | None = None
    created_at: datetime


class AlertListResponse(PaginatedResponse):
    items: list[AlertOut]


class AlertUpdateRequest(CamelModel):
    """FM6 triage.

    `status` accepts "dismissed" (mark a false positive) or "open" (reopen a
    dismissal). "promoted" is not settable here -- that transition is owned by
    POST /v1/alerts/promote, which also creates the case.
    """

    status: str = Field(pattern="^(open|dismissed)$")
    reason: str | None = Field(default=None, max_length=500)


class AlertBulkUpdateRequest(CamelModel):
    alert_ids: list[str] = Field(min_length=1, max_length=500)
    status: str = Field(pattern="^(open|dismissed)$")
    reason: str | None = Field(default=None, max_length=500)


class AlertBulkUpdateResponse(CamelModel):
    updated: int
    alert_ids: list[str]


class AlertDetailOut(AlertOut):
    """Adds the contributing events and any threat-intel enrichment on them --
    what an analyst needs to judge the alert without a second round trip."""

    events: list[dict[str, Any]] = Field(default_factory=list)


class PromoteAlertsRequest(CamelModel):
    alert_ids: list[str] = Field(min_length=1)
    title: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=4000)

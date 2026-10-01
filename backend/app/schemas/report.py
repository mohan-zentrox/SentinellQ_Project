from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from app.schemas.common import CamelModel, PaginatedResponse


class ReportCreate(CamelModel):
    template: str = Field(pattern="^(alert_summary|case_summary|control_evidence)$")
    report_format: str = Field(default="csv", pattern="^(csv|json|html)$")
    #: Null period_start defaults to `days` before period_end.
    period_start: datetime | None = None
    period_end: datetime | None = None
    days: int = Field(default=30, ge=1, le=366)
    parameters: dict[str, Any] = Field(default_factory=dict)


class ReportOut(CamelModel):
    id: str
    tenant_id: str
    template: str
    report_format: str
    status: str
    period_start: datetime
    period_end: datetime
    size_bytes: int | None
    row_count: int | None
    generated_at: datetime | None
    error: str | None
    requested_by_user_id: str | None
    created_at: datetime
    #: Relative, signed, expiring download path. Present only when ready.
    download_url: str | None = None
    download_expires_at: datetime | None = None


class ReportListResponse(PaginatedResponse):
    items: list[ReportOut]


class ReportTemplateOut(CamelModel):
    name: str
    description: str
    formats: list[str]

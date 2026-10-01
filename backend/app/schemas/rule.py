from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from app.schemas.common import CamelModel

SEVERITIES = ("informational", "low", "medium", "high", "critical")


class DetectionRuleCreate(CamelModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=1000)
    condition: dict[str, Any]
    severity: str = Field(default="medium", pattern="^(informational|low|medium|high|critical)$")
    is_enabled: bool = True
    # Null means "use settings.detection_default_window_minutes". Capped at a
    # year so a typo can't request an unbounded historical scan.
    evaluation_window_minutes: int | None = Field(default=None, ge=1, le=60 * 24 * 366)


class DetectionRuleUpdate(CamelModel):
    """PATCH body. Every field optional; only supplied fields are applied
    (`model_dump(exclude_unset=True)` in the route), so omitting a field means
    "leave it alone" rather than "set it to null"."""

    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=1000)
    condition: dict[str, Any] | None = None
    severity: str | None = Field(default=None, pattern="^(informational|low|medium|high|critical)$")
    is_enabled: bool | None = None
    evaluation_window_minutes: int | None = Field(default=None, ge=1, le=60 * 24 * 366)


class DetectionRuleOut(CamelModel):
    id: str
    tenant_id: str
    name: str
    description: str
    condition: dict[str, Any]
    severity: str
    is_enabled: bool
    evaluation_window_minutes: int | None = None
    last_evaluated_at: datetime | None = None
    last_matched_at: datetime | None = None
    match_count: int = 0
    created_at: datetime


class RuleRunResponse(CamelModel):
    alerts_created: int
    alert_ids: list[str]


class RuleTestRequest(CamelModel):
    """Dry-run a condition against recent events without creating alerts."""

    condition: dict[str, Any]
    sample_size: int = Field(default=500, ge=1, le=5000)


class RuleTestResponse(CamelModel):
    sampled: int
    matched: int
    #: Truncated to the first 50 so a broad test condition can't return a
    #: multi-megabyte response.
    matched_event_ids: list[str]

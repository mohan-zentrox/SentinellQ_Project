from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from app.schemas.common import CamelModel


class DetectionRuleCreate(CamelModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = Field(default="", max_length=1000)
    condition: dict[str, Any]
    severity: str = Field(default="medium")
    is_enabled: bool = True


class DetectionRuleOut(CamelModel):
    id: str
    tenant_id: str
    name: str
    description: str
    condition: dict[str, Any]
    severity: str
    is_enabled: bool
    created_at: datetime


class RuleRunResponse(CamelModel):
    alerts_created: int
    alert_ids: list[str]

from __future__ import annotations

from datetime import datetime

from app.schemas.common import CamelModel


class KPIResponse(CamelModel):
    period_start: datetime
    period_end: datetime
    alert_volume: int
    false_positive_rate: float
    mttd_seconds: float | None
    mttr_seconds: float | None
    open_cases: int
    resolved_cases: int

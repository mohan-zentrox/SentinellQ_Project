from __future__ import annotations

from datetime import datetime

from app.schemas.common import CamelModel


class KPIResponse(CamelModel):
    period_start: datetime
    period_end: datetime
    alert_volume: int
    dismissed_alerts: int = 0
    #: Share of alerts in the period explicitly dismissed by an analyst. A proxy
    #: for the true false-positive rate, not a validated model: an undismissed
    #: alert is not necessarily a true positive.
    false_positive_rate: float
    mttd_seconds: float | None
    mttr_seconds: float | None
    open_cases: int
    resolved_cases: int
    alerts_by_severity: dict[str, int] = {}
    alerts_by_detection_source: dict[str, int] = {}


class TimeseriesBucket(CamelModel):
    bucket_start: datetime
    count: int
    by_severity: dict[str, int] = {}


class AlertTimeseriesResponse(CamelModel):
    period_start: datetime
    period_end: datetime
    bucket_hours: int
    buckets: list[TimeseriesBucket]


class DetectionCoverageResponse(CamelModel):
    """Which rules are actually earning their place.

    Rules that have never matched are either mis-authored or cover a threat the
    tenant has not seen; either way an analyst needs to know which is which, and
    this is the aggregate that tells them.
    """

    total_rules: int
    enabled_rules: int
    rules_with_matches: int
    never_matched_rules: list[dict] = []
    top_rules: list[dict] = []

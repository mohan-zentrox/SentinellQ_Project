from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field

from app.schemas.common import CamelModel, PaginatedResponse

INDICATOR_TYPE_PATTERN = "^(ip|domain|url|file_hash|cve|email)$"
SEVERITY_PATTERN = "^(informational|low|medium|high|critical)$"


class IndicatorCreate(CamelModel):
    indicator_type: str = Field(pattern=INDICATOR_TYPE_PATTERN)
    value: str = Field(min_length=1, max_length=512)
    confidence: int = Field(default=50, ge=0, le=100)
    severity: str = Field(default="medium", pattern=SEVERITY_PATTERN)
    description: str = Field(default="", max_length=1000)
    tags: list[str] = Field(default_factory=list, max_length=20)
    #: Null means "use the configured default TTL".
    ttl_hours: int | None = Field(default=None, ge=1, le=24 * 365)


class IndicatorBulkCreate(CamelModel):
    indicators: list[IndicatorCreate] = Field(min_length=1, max_length=1000)
    source: str = Field(default="manual", max_length=100)


class IndicatorUpdate(CamelModel):
    confidence: int | None = Field(default=None, ge=0, le=100)
    severity: str | None = Field(default=None, pattern=SEVERITY_PATTERN)
    description: str | None = Field(default=None, max_length=1000)
    tags: list[str] | None = Field(default=None, max_length=20)
    is_active: bool | None = None


class IndicatorOut(CamelModel):
    id: str
    tenant_id: str
    indicator_type: str
    value: str
    value_normalized: str
    source: str
    confidence: int
    severity: str
    tags: list[str]
    description: str
    is_active: bool
    expires_at: datetime | None
    last_seen_at: datetime | None
    match_count: int
    created_at: datetime


class IndicatorListResponse(PaginatedResponse):
    items: list[IndicatorOut]


class IndicatorImportResponse(CamelModel):
    created: int
    updated: int
    skipped: int


class FeedCreate(CamelModel):
    slug: str = Field(min_length=1, max_length=100, pattern="^[a-z0-9][a-z0-9_-]*$")
    name: str = Field(min_length=1, max_length=255)
    provider: str = Field(default="http_feed", pattern="^(local|http_feed)$")
    url: str | None = Field(default=None, max_length=1000)
    #: Name of the env var holding the credential -- never the credential itself.
    api_key_env_var: str | None = Field(default=None, max_length=100)
    is_enabled: bool = True
    default_confidence: int = Field(default=50, ge=0, le=100)
    ttl_hours: int = Field(default=24 * 7, ge=1, le=24 * 365)


class FeedUpdate(CamelModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    url: str | None = Field(default=None, max_length=1000)
    api_key_env_var: str | None = Field(default=None, max_length=100)
    is_enabled: bool | None = None
    default_confidence: int | None = Field(default=None, ge=0, le=100)
    ttl_hours: int | None = Field(default=None, ge=1, le=24 * 365)


class FeedOut(CamelModel):
    id: str
    tenant_id: str
    slug: str
    name: str
    provider: str
    url: str | None
    api_key_env_var: str | None
    is_enabled: bool
    default_confidence: int
    ttl_hours: int
    last_refreshed_at: datetime | None
    last_refresh_status: str | None
    indicator_count: int
    created_at: datetime


class FeedRefreshResponse(CamelModel):
    feed_slug: str
    created: int
    updated: int
    status: str | None


class EnrichmentPreviewResponse(CamelModel):
    """What enrichment would annotate for a given observable."""

    matched: bool
    enrichment: dict[str, Any]

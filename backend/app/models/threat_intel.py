"""FM5: Threat intelligence entities."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Index, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.ids import generate_id
from app.db.base import Base, TimestampMixin


class IndicatorType:
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    CVE = "cve"
    EMAIL = "email"

    ALL = (IP, DOMAIN, URL, FILE_HASH, CVE, EMAIL)


class ThreatIndicator(Base, TimestampMixin):
    """An indicator of compromise.

    Indicators are tenant-scoped like everything else, which is a deliberate
    choice over a shared global table: a tenant's own blocklist, its paid feed
    subscriptions, and its analyst-authored indicators are its data, and
    cross-tenant indicator reads would be a tenancy leak even though the
    content looks "public". A shared-feed optimization (one copy, many
    tenants) belongs behind a `is_global` flag and a deliberate design pass --
    not as an accident of schema.

    `value_normalized` is the matchable form (lowercased, trimmed; for IPs the
    compressed textual form) and is what enrichment looks up.
    """

    __tablename__ = "threat_indicators"
    __table_args__ = (
        # Enrichment's hot path: "does this tenant have a live indicator for
        # this exact value of this type".
        UniqueConstraint("tenant_id", "indicator_type", "value_normalized", name="uq_indicator_tenant_type_value"),
        Index("ix_indicator_lookup", "tenant_id", "indicator_type", "value_normalized", "is_active"),
        Index("ix_indicator_expiry", "tenant_id", "expires_at"),
    )

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: generate_id("indicator"))
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    indicator_type: Mapped[str] = mapped_column(String(20), nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    value_normalized: Mapped[str] = mapped_column(String(512), nullable=False)

    #: Where this came from: a feed slug, or "manual" for analyst-authored.
    source: Mapped[str] = mapped_column(String(100), nullable=False, default="manual")
    #: 0-100. Feeds disagree; enrichment exposes the max across matches so a
    #: rule can threshold on it.
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")
    tags: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    description: Mapped[str] = mapped_column(String(1000), nullable=False, default="")

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    #: Staleness handling: an expired indicator is retained for audit but never
    #: matched (see services/enrichment.py).
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    #: How many times enrichment has matched this indicator -- the raw input to
    #: [5]'s data-QA remit on indicator false-positive rates.
    match_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class ThreatFeed(Base, TimestampMixin):
    """A configured indicator source for one tenant."""

    __tablename__ = "threat_feeds"
    __table_args__ = (UniqueConstraint("tenant_id", "slug", name="uq_threat_feeds_tenant_slug"),)

    id: Mapped[str] = mapped_column(String(40), primary_key=True, default=lambda: generate_id("intel_feed"))
    tenant_id: Mapped[str] = mapped_column(String(40), index=True, nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    #: Matches a registered ThreatIntelProvider name (see services/threat_intel.py).
    provider: Mapped[str] = mapped_column(String(50), nullable=False, default="http_feed")
    url: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    #: Never store a plaintext credential in a column an admin UI lists; this
    #: holds the name of the env var/secret to read instead.
    api_key_env_var: Mapped[str | None] = mapped_column(String(100), nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    default_confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    ttl_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=24 * 7)

    last_refreshed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_refresh_status: Mapped[str | None] = mapped_column(String(500), nullable=True)
    indicator_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

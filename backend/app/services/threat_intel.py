"""FM5: Threat intelligence providers.

Mirrors the adapter pattern used by BillingProvider / QueueBackend /
TelemetryStore: a `ThreatIntelProvider` interface, a working default that
needs no network, and an HTTP feed adapter for real sources. The provider is
selected per feed (`ThreatFeed.provider`) rather than globally, because one
tenant legitimately runs several feeds of different kinds at once.

Providers only *fetch and parse*; they never write to the database. Persisting
indicators -- upsert, TTL, counters -- is `import_indicators`' job, so every
feed gets identical dedup and expiry semantics regardless of where it came
from.

Normalization is security-relevant, not cosmetic: an indicator stored as
`1.2.3.4 ` or `EVIL.COM` would never match an event carrying `1.2.3.4` or
`evil.com`, and a silently-non-matching blocklist is worse than an empty one.
`normalize_indicator_value` is therefore shared by import and by lookup.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.threat_intel import IndicatorType, ThreatFeed, ThreatIndicator

logger = logging.getLogger(__name__)


@dataclass
class RawIndicator:
    """A provider's parsed output, before persistence."""

    indicator_type: str
    value: str
    confidence: int = 50
    severity: str = "medium"
    description: str = ""
    tags: list[str] = field(default_factory=list)


class ThreatIntelProviderError(RuntimeError):
    """Feed fetch/parse failure. Recorded on the feed, never raised to a route."""


def normalize_indicator_value(indicator_type: str, value: str) -> str:
    """Canonical, matchable form of an indicator value.

    - IPs go through ipaddress so `01.2.3.4`, `1.2.3.4` and an IPv6 address in
      any valid spelling all collapse to one form.
    - Domains/emails/URLs lowercase; domains additionally lose a trailing dot
      and a leading `*.` wildcard marker.
    - Hashes lowercase (hex is case-insensitive); CVEs uppercase.
    """
    cleaned = (value or "").strip()
    if not cleaned:
        return ""

    if indicator_type == IndicatorType.IP:
        try:
            return str(ipaddress.ip_address(cleaned))
        except ValueError:
            return cleaned.lower()
    if indicator_type == IndicatorType.DOMAIN:
        host = cleaned.lower().rstrip(".")
        return host[2:] if host.startswith("*.") else host
    if indicator_type in (IndicatorType.URL, IndicatorType.EMAIL):
        return cleaned.lower()
    if indicator_type == IndicatorType.FILE_HASH:
        return cleaned.lower()
    if indicator_type == IndicatorType.CVE:
        return cleaned.upper()
    return cleaned.lower()


def infer_indicator_type(value: str) -> str:
    """Best-effort type inference, for feeds that ship bare values."""
    candidate = (value or "").strip()
    try:
        ipaddress.ip_address(candidate)
        return IndicatorType.IP
    except ValueError:
        pass
    upper = candidate.upper()
    if upper.startswith("CVE-"):
        return IndicatorType.CVE
    if "://" in candidate:
        return IndicatorType.URL
    if "@" in candidate:
        return IndicatorType.EMAIL
    stripped = candidate.lower()
    if len(stripped) in (32, 40, 64, 128) and all(c in "0123456789abcdef" for c in stripped):
        return IndicatorType.FILE_HASH
    return IndicatorType.DOMAIN


class ThreatIntelProvider(ABC):
    name = "abstract"

    @abstractmethod
    def fetch(self, feed: ThreatFeed) -> list[RawIndicator]:
        """Return the feed's current indicators. Must not touch the database."""
        raise NotImplementedError


class LocalThreatIntelProvider(ThreatIntelProvider):
    """Working default: indicators come from analysts via the API, not a feed.

    `fetch` returning empty is correct and not a stub -- a "local" feed has no
    remote to poll, so a refresh is a no-op. This exists so the feed-refresh
    code path is exercisable with zero external services, matching how
    MockStripeProvider lets the billing path be exercised without Stripe.
    """

    name = "local"

    def fetch(self, feed: ThreatFeed) -> list[RawIndicator]:
        return []


class HttpFeedThreatIntelProvider(ThreatIntelProvider):
    """Fetches a URL and parses JSON or newline-delimited indicators.

    Deliberately uses urllib rather than adding an HTTP client dependency, and
    accepts the three shapes open feeds actually ship:

      1. `{"indicators": [{"type": "ip", "value": "...", "confidence": 90}]}`
      2. a bare JSON array of the same objects, or of plain strings
      3. a plain-text list, one indicator per line, `#` comments allowed
         (the AbuseIPDB/blocklist.de/Spamhaus-style format)

    Credentials come from the environment variable named by
    `feed.api_key_env_var`, never from a database column.
    """

    name = "http_feed"

    #: Refuse to buffer an unbounded response into memory.
    MAX_BYTES = 8 * 1024 * 1024

    def fetch(self, feed: ThreatFeed) -> list[RawIndicator]:
        settings = get_settings()
        url = feed.url or settings.threat_intel_feed_url
        if not url:
            raise ThreatIntelProviderError("feed has no url configured")

        headers = {"User-Agent": "SentinelIQ/0.2 (+defensive-secops)", "Accept": "application/json, text/plain"}
        api_key = None
        if feed.api_key_env_var:
            api_key = os.environ.get(feed.api_key_env_var)
            if not api_key:
                raise ThreatIntelProviderError(
                    f"api_key_env_var {feed.api_key_env_var!r} is set on the feed but absent from the environment"
                )
        elif settings.threat_intel_feed_api_key:
            api_key = settings.threat_intel_feed_api_key
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        request = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310 - operator-configured feed URL
                body = response.read(self.MAX_BYTES + 1)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise ThreatIntelProviderError(f"fetch failed: {exc}") from exc

        if len(body) > self.MAX_BYTES:
            raise ThreatIntelProviderError(f"feed response exceeded {self.MAX_BYTES} bytes")

        text = body.decode("utf-8", errors="replace")
        return self._parse(text, default_confidence=feed.default_confidence, source=feed.slug)

    def _parse(self, text: str, *, default_confidence: int, source: str) -> list[RawIndicator]:
        stripped = text.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                document = json.loads(stripped)
            except ValueError as exc:
                raise ThreatIntelProviderError(f"response is not valid JSON: {exc}") from exc
            entries = document.get("indicators", []) if isinstance(document, dict) else document
            if not isinstance(entries, list):
                raise ThreatIntelProviderError("expected a list of indicators")
            return [
                parsed
                for entry in entries
                if (parsed := self._parse_entry(entry, default_confidence, source)) is not None
            ]

        indicators: list[RawIndicator] = []
        for line in stripped.splitlines():
            candidate = line.strip()
            if not candidate or candidate.startswith("#"):
                continue
            # Tolerate "value<whitespace>anything-else" rows.
            candidate = candidate.split()[0]
            indicators.append(
                RawIndicator(
                    indicator_type=infer_indicator_type(candidate),
                    value=candidate,
                    confidence=default_confidence,
                    description=f"Imported from {source}",
                )
            )
        return indicators

    def _parse_entry(self, entry: Any, default_confidence: int, source: str) -> RawIndicator | None:
        if isinstance(entry, str):
            return RawIndicator(
                indicator_type=infer_indicator_type(entry),
                value=entry,
                confidence=default_confidence,
                description=f"Imported from {source}",
            )
        if not isinstance(entry, dict):
            return None
        value = entry.get("value") or entry.get("indicator") or entry.get("ioc")
        if not value:
            return None
        raw_type = entry.get("type") or entry.get("indicator_type") or infer_indicator_type(str(value))
        indicator_type = str(raw_type).lower()
        if indicator_type not in IndicatorType.ALL:
            indicator_type = infer_indicator_type(str(value))
        confidence = entry.get("confidence", default_confidence)
        try:
            confidence = max(0, min(100, int(confidence)))
        except (TypeError, ValueError):
            confidence = default_confidence
        tags = entry.get("tags") or []
        return RawIndicator(
            indicator_type=indicator_type,
            value=str(value),
            confidence=confidence,
            severity=str(entry.get("severity", "medium")),
            description=str(entry.get("description", "") or f"Imported from {source}")[:1000],
            tags=[str(t) for t in tags][:20] if isinstance(tags, list) else [],
        )


_PROVIDERS: dict[str, type[ThreatIntelProvider]] = {
    LocalThreatIntelProvider.name: LocalThreatIntelProvider,
    HttpFeedThreatIntelProvider.name: HttpFeedThreatIntelProvider,
}


def get_threat_intel_provider(name: str | None = None) -> ThreatIntelProvider:
    resolved = name or get_settings().threat_intel_provider
    try:
        return _PROVIDERS[resolved]()
    except KeyError:
        raise ValueError(
            f"Unknown threat intel provider {resolved!r}. Supported: {', '.join(sorted(_PROVIDERS))}."
        ) from None


def import_indicators(
    db: Session,
    *,
    tenant_id: str,
    indicators: list[RawIndicator],
    source: str,
    ttl_hours: int | None = None,
) -> tuple[int, int]:
    """Upsert indicators for a tenant. Returns (created, updated).

    An indicator seen again is refreshed (expiry extended, confidence raised to
    the highest any source has claimed, reactivated if it had expired) rather
    than duplicated -- `(tenant, type, value_normalized)` is unique. Confidence
    is raised but never lowered by a re-import, so a low-confidence feed cannot
    quietly downgrade an analyst's hand-authored high-confidence indicator.
    """
    settings = get_settings()
    now = datetime.now(timezone.utc)
    ttl = timedelta(hours=ttl_hours if ttl_hours is not None else settings.threat_intel_default_ttl_hours)
    created = 0
    updated = 0

    for raw in indicators:
        normalized = normalize_indicator_value(raw.indicator_type, raw.value)
        if not normalized:
            continue

        existing = db.execute(
            select(ThreatIndicator).where(
                ThreatIndicator.tenant_id == tenant_id,
                ThreatIndicator.indicator_type == raw.indicator_type,
                ThreatIndicator.value_normalized == normalized,
            )
        ).scalar_one_or_none()

        if existing is None:
            db.add(
                ThreatIndicator(
                    tenant_id=tenant_id,
                    indicator_type=raw.indicator_type,
                    value=raw.value.strip(),
                    value_normalized=normalized,
                    source=source,
                    confidence=max(0, min(100, raw.confidence)),
                    severity=raw.severity,
                    tags=raw.tags,
                    description=raw.description,
                    is_active=True,
                    expires_at=now + ttl,
                    last_seen_at=now,
                )
            )
            created += 1
        else:
            existing.confidence = max(existing.confidence, max(0, min(100, raw.confidence)))
            existing.expires_at = now + ttl
            existing.last_seen_at = now
            existing.is_active = True
            if raw.tags:
                existing.tags = sorted(set(existing.tags or []) | set(raw.tags))
            updated += 1

    db.flush()
    return created, updated


def refresh_feed(db: Session, *, feed: ThreatFeed) -> tuple[int, int]:
    """Fetch and import one feed, recording the outcome on the feed row.

    Never raises: a feed being down is operational news to surface in the UI,
    not a reason to fail the caller. The failure is written to
    `last_refresh_status` so the staleness of a feed is visible.
    """
    now = datetime.now(timezone.utc)
    try:
        provider = get_threat_intel_provider(feed.provider)
        raw = provider.fetch(feed)
        created, updated = import_indicators(
            db,
            tenant_id=feed.tenant_id,
            indicators=raw,
            source=feed.slug,
            ttl_hours=feed.ttl_hours,
        )
        feed.last_refreshed_at = now
        feed.last_refresh_status = f"ok: {created} new, {updated} refreshed"
        feed.indicator_count = count_active_indicators(db, tenant_id=feed.tenant_id, source=feed.slug)
        db.flush()
        logger.info(
            "threat_intel.feed_refreshed",
            extra={
                "tenant_id": feed.tenant_id,
                "feed": feed.slug,
                "indicators_created": created,
                "indicators_updated": updated,
            },
        )
        return created, updated
    except (ThreatIntelProviderError, ValueError) as exc:
        feed.last_refreshed_at = now
        feed.last_refresh_status = f"error: {exc}"[:500]
        db.flush()
        logger.warning(
            "threat_intel.feed_refresh_failed",
            extra={"tenant_id": feed.tenant_id, "feed": feed.slug, "error": str(exc)},
        )
        return 0, 0


def count_active_indicators(db: Session, *, tenant_id: str, source: str | None = None) -> int:
    from sqlalchemy import func

    stmt = (
        select(func.count())
        .select_from(ThreatIndicator)
        .where(ThreatIndicator.tenant_id == tenant_id, ThreatIndicator.is_active.is_(True))
    )
    if source:
        stmt = stmt.where(ThreatIndicator.source == source)
    return int(db.execute(stmt).scalar_one())


def expire_stale_indicators(db: Session, *, tenant_id: str) -> int:
    """Deactivate indicators past their expiry. Returns how many were expired.

    Deactivation rather than deletion: an expired indicator still explains why
    an alert fired three weeks ago, and deleting it would make that alert
    unexplainable.
    """
    now = datetime.now(timezone.utc)
    stale = db.execute(
        select(ThreatIndicator).where(
            ThreatIndicator.tenant_id == tenant_id,
            ThreatIndicator.is_active.is_(True),
            ThreatIndicator.expires_at.isnot(None),
            ThreatIndicator.expires_at < now,
        )
    ).scalars()
    count = 0
    for indicator in stale:
        indicator.is_active = False
        count += 1
    if count:
        db.flush()
        logger.info("threat_intel.indicators_expired", extra={"tenant_id": tenant_id, "count": count})
    return count

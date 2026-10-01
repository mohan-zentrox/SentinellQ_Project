"""FM5: the enrichment step in the normalization pipeline.

Runs between persistence and detection (see services/pipeline.py), annotating
`Event.enrichment` with any matching threat indicators so detection rules can
threshold on reputation:

    {"field": "enrichment.maxConfidence", "op": "gte", "value": 80}
    {"field": "enrichment.tags", "op": "contains", "value": "ransomware"}

The enrichment document is camelCase because it is addressed by rule authors
through the API, where everything is camelCase (docs/API.md) -- an analyst
should not have to know that the field is snake_case inside Python.

Matching is exact-value lookup on the normalized indicator form, never a
substring scan: a substring match on IPs would make `10.0.0.1` match
`110.0.0.11`, and on domains would make `evil.com` match `notevil.com.safe.org`.
Subdomain coverage is handled explicitly by walking the parent-domain chain.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.event import Event
from app.models.threat_intel import IndicatorType, ThreatIndicator
from app.services.threat_intel import normalize_indicator_value

logger = logging.getLogger(__name__)

#: Cap on indicator rows returned for one event, so a pathological match set
#: cannot blow up an event row.
_MAX_MATCHES = 20


def _candidate_domains(host: str) -> list[str]:
    """`a.b.evil.com` -> itself plus `b.evil.com`, `evil.com`.

    Lets one indicator on `evil.com` cover its subdomains without storing them
    all, while still being an exact-match lookup. Stops at two labels so a
    public suffix like `co.uk` is never treated as an indicator.
    """
    labels = host.split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)] if len(labels) > 2 else [host]


def _extract_observables(event: Event) -> dict[str, set[str]]:
    """Indicator-type -> candidate values present on this event."""
    observables: dict[str, set[str]] = {}

    def add(indicator_type: str, value: Any) -> None:
        if not value:
            return
        normalized = normalize_indicator_value(indicator_type, str(value))
        if normalized:
            observables.setdefault(indicator_type, set()).add(normalized)

    add(IndicatorType.IP, event.source_ip)

    # The normalized document and raw payload can carry more: a destination IP,
    # a hash, a URL. Pull the conventional keys rather than scanning everything,
    # which would turn any string field into an accidental indicator match.
    normalized_doc = event.normalized or {}
    destination = normalized_doc.get("destination") or {}
    if isinstance(destination, dict):
        add(IndicatorType.IP, destination.get("ip"))

    raw = event.raw_payload or {}
    if isinstance(raw, dict):
        for key in ("destinationIp", "destination_ip", "dstIp", "remoteIp"):
            add(IndicatorType.IP, raw.get(key))
        for key in ("fileHash", "file_hash", "sha256", "md5", "sha1"):
            add(IndicatorType.FILE_HASH, raw.get(key))
        for key in ("url", "requestUrl", "request_url"):
            add(IndicatorType.URL, raw.get(key))
        for key in ("domain", "hostname", "host", "dnsQuery"):
            value = raw.get(key)
            if value:
                host = normalize_indicator_value(IndicatorType.DOMAIN, str(value))
                for candidate in _candidate_domains(host):
                    add(IndicatorType.DOMAIN, candidate)
        for key in ("cve", "vulnerabilityId"):
            add(IndicatorType.CVE, raw.get(key))

    # The actor is an email in plenty of IdP/SaaS audit logs.
    if event.actor and "@" in str(event.actor):
        add(IndicatorType.EMAIL, event.actor)

    return observables


def lookup_indicators(db: Session, *, tenant_id: str, observables: dict[str, set[str]]) -> list[ThreatIndicator]:
    """Active, unexpired indicators matching any observable. One query per type."""
    if not observables:
        return []

    now = datetime.now(timezone.utc)
    matches: list[ThreatIndicator] = []
    for indicator_type, values in observables.items():
        if not values:
            continue
        rows = db.execute(
            select(ThreatIndicator)
            .where(
                ThreatIndicator.tenant_id == tenant_id,
                ThreatIndicator.indicator_type == indicator_type,
                ThreatIndicator.value_normalized.in_(sorted(values)),
                ThreatIndicator.is_active.is_(True),
            )
            .limit(_MAX_MATCHES)
        ).scalars()
        for row in rows:
            # Expiry is enforced here as well as by the expiry sweep: a feed
            # that stopped refreshing must stop matching even if nothing has
            # run the sweep recently.
            expires_at = row.expires_at
            if expires_at is not None:
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
                if expires_at < now:
                    continue
            matches.append(row)
    return matches[:_MAX_MATCHES]


def build_enrichment_document(matches: list[ThreatIndicator]) -> dict[str, Any]:
    """The camelCase document written to Event.enrichment.

    An empty `matches` still produces a document (with `matched: false`) rather
    than leaving the column null, so "enriched, nothing found" is
    distinguishable from "never enriched" -- which matters when deciding whether
    a historical event needs re-enrichment after a feed is added.
    """
    if not matches:
        return {
            "matched": False,
            "indicatorCount": 0,
            "maxConfidence": 0,
            "maxSeverity": None,
            "tags": [],
            "indicators": [],
            "enrichedAt": datetime.now(timezone.utc).isoformat(),
        }

    severity_rank = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    tags = sorted({tag for match in matches for tag in (match.tags or [])})
    return {
        "matched": True,
        "indicatorCount": len(matches),
        "maxConfidence": max(match.confidence for match in matches),
        "maxSeverity": max((m.severity for m in matches), key=lambda s: severity_rank.get(s, 0)),
        "tags": tags,
        "sources": sorted({match.source for match in matches}),
        "indicators": [
            {
                "id": match.id,
                "type": match.indicator_type,
                "value": match.value,
                "source": match.source,
                "confidence": match.confidence,
                "severity": match.severity,
                "tags": match.tags or [],
            }
            for match in matches
        ],
        "enrichedAt": datetime.now(timezone.utc).isoformat(),
    }


def enrich_event(db: Session, *, tenant_id: str, event: Event) -> dict[str, Any]:
    """Annotate one event in place. Does not commit."""
    observables = _extract_observables(event)
    matches = lookup_indicators(db, tenant_id=tenant_id, observables=observables)
    document = build_enrichment_document(matches)
    event.enrichment = document

    now = datetime.now(timezone.utc)
    for match in matches:
        match.match_count = (match.match_count or 0) + 1
        match.last_seen_at = now

    if matches:
        logger.info(
            "enrichment.matched",
            extra={
                "tenant_id": tenant_id,
                "event_id": event.id,
                "indicator_count": len(matches),
                "max_confidence": document["maxConfidence"],
            },
        )
    return document


def enrich_events(db: Session, *, tenant_id: str, events: list[Event]) -> int:
    """Annotate a batch. Returns how many events matched at least one indicator."""
    matched = 0
    for event in events:
        document = enrich_event(db, tenant_id=tenant_id, event=event)
        if document.get("matched"):
            matched += 1
    db.flush()
    return matched

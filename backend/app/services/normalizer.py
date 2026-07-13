"""FM3: Normalization.

Maps arbitrary raw ingested event payloads onto a small OCSF/ECS-aligned
normalized schema. We don't implement the full OCSF/ECS spec here (that's a
large, evolving standard) -- this module intentionally covers a pragmatic
subset of field names widely recognized from both standards
(event.category, event.action, severity, actor/user, target, source.ip)
so a real mapping table can be dropped in later without touching callers.
"""
from __future__ import annotations

from typing import Any

VALID_SEVERITIES = ("informational", "low", "medium", "high", "critical")

# Raw payload key -> normalized field, checked in priority order per field.
_CATEGORY_KEYS = ("eventCategory", "event_category", "category")
_ACTION_KEYS = ("eventAction", "event_action", "action")
_SEVERITY_KEYS = ("severity", "severityHint", "level")
_ACTOR_KEYS = ("actor", "user", "username", "userName")
_TARGET_KEYS = ("target", "resource", "targetResource")
_SOURCE_IP_KEYS = ("sourceIp", "source_ip", "ip", "srcIp")


def _first_present(payload: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in payload and payload[key] is not None:
            return payload[key]
    return None


def normalize_severity(raw_value: Any) -> str:
    if not raw_value:
        return "informational"
    value = str(raw_value).strip().lower()
    if value in VALID_SEVERITIES:
        return value
    # Common numeric/alt scales.
    aliases = {
        "info": "informational",
        "warn": "medium",
        "warning": "medium",
        "err": "high",
        "error": "high",
        "crit": "critical",
        "1": "low",
        "2": "medium",
        "3": "high",
        "4": "critical",
    }
    return aliases.get(value, "informational")


def normalize_event(raw_payload: dict[str, Any]) -> dict[str, Any]:
    """Produce the normalized field set stored alongside the raw payload.

    Returns a dict with keys matching app.models.event.Event's normalized
    columns (event_category, event_action, severity_hint, actor, target,
    source_ip) plus a nested `normalized` OCSF/ECS-ish document.
    """
    category = str(_first_present(raw_payload, _CATEGORY_KEYS) or "other")
    action = str(_first_present(raw_payload, _ACTION_KEYS) or "unknown")
    severity_hint = normalize_severity(_first_present(raw_payload, _SEVERITY_KEYS))
    actor = _first_present(raw_payload, _ACTOR_KEYS)
    target = _first_present(raw_payload, _TARGET_KEYS)
    source_ip = _first_present(raw_payload, _SOURCE_IP_KEYS)

    normalized_doc = {
        "event": {"category": category, "action": action, "kind": "event"},
        "severity": severity_hint,
        "actor": {"name": actor} if actor else None,
        "target": {"name": target} if target else None,
        "source": {"ip": source_ip} if source_ip else None,
    }

    return {
        "event_category": category,
        "event_action": action,
        "severity_hint": severity_hint,
        "actor": str(actor) if actor is not None else None,
        "target": str(target) if target is not None else None,
        "source_ip": str(source_ip) if source_ip is not None else None,
        "normalized": normalized_doc,
    }

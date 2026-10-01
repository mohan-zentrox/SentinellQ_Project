"""Prefixed entity ID generation.

SentinelIQ uses human-readable, prefixed identifiers (Stripe-style) for every
domain entity instead of raw UUIDs, e.g. ``ten_5f3c1a2b3c4d5e6f7a8b``. This
makes IDs self-describing in logs, URLs, and support tickets, and lets us
validate the *kind* of ID a caller passed before ever hitting the database.
"""
from __future__ import annotations

import secrets

# Canonical entity -> ID prefix map. Keep in sync with docs/API.md.
ENTITY_PREFIXES: dict[str, str] = {
    "tenant": "ten",
    "user": "usr",
    "event": "evt",
    "alert": "alrt",
    "case": "case",
    "rule": "rule",
    "plan": "plan",
    "subscription": "sub",
    "service_token": "svct",
    "timeline_entry": "tl",
    "usage_counter": "usage",
    # Added with the modules below; generate_id() raises on an unregistered
    # entity kind, so every new model must appear here.
    "rule_match": "rmat",      # rule/event dedup ledger (FM4)
    "audit": "aud",            # audit log entry
    "refresh_token": "rft",    # auth session
    "indicator": "ioc",        # threat intel indicator (FM5)
    "intel_feed": "feed",      # threat intel feed config (FM5)
    "playbook": "pb",          # SOAR playbook (FM7)
    "playbook_run": "pbrun",   # SOAR execution record (FM7)
    "playbook_action": "pbact",  # SOAR per-action record (FM7)
    "ml_model": "mdl",         # ML model version (C8)
    "report": "rpt",           # compliance report (FM9)
    "sso_config": "sso",       # per-tenant IdP config (FM1 ext)
    "notification": "ntf",     # notification delivery record (FM6)
}


def generate_id(entity: str) -> str:
    """Generate a new prefixed ID for the given entity kind.

    Example: ``generate_id("tenant") -> "ten_a1b2c3d4e5f6a7b8c9d0"``
    """
    prefix = ENTITY_PREFIXES.get(entity)
    if prefix is None:
        raise ValueError(f"Unknown entity kind for ID generation: {entity!r}")
    return f"{prefix}_{secrets.token_hex(10)}"


def prefix_for(entity: str) -> str:
    return ENTITY_PREFIXES[entity]


def is_valid_id(entity: str, value: str) -> bool:
    """Cheap structural validation: does `value` look like an ID of `entity`?"""
    prefix = ENTITY_PREFIXES.get(entity)
    if prefix is None:
        return False
    return value.startswith(f"{prefix}_") and len(value) > len(prefix) + 1

"""Audit trail writes.

One function, called from every route that changes security-relevant state.
It never commits -- the caller's transaction owns the decision, so an audit
entry and the change it describes are committed together or not at all. An
audit log that can disagree with the data it describes is worse than none.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.models.audit import AuditLogEntry

logger = logging.getLogger(__name__)

#: Keys whose values are redacted before they reach the audit table. The audit
#: log is widely readable inside a tenant (admins, compliance exports), so a
#: secret that lands here has effectively leaked.
_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "new_password",
        "current_password",
        "token",
        "access_token",
        "refresh_token",
        "service_token",
        "secret",
        "client_secret",
        "api_key",
        "authorization",
        "password_hash",
        "token_hash",
    }
)

_REDACTED = "[redacted]"


def redact(detail: Any, _depth: int = 0) -> Any:
    """Recursively replace sensitive values. Depth-capped to stay cheap and to
    refuse to walk a pathological nested structure."""
    if _depth > 6:
        return _REDACTED
    if isinstance(detail, dict):
        return {
            key: (_REDACTED if str(key).lower() in _SENSITIVE_KEYS else redact(value, _depth + 1))
            for key, value in detail.items()
        }
    if isinstance(detail, (list, tuple)):
        return [redact(item, _depth + 1) for item in detail]
    return detail


def record_audit(
    db: Session,
    *,
    tenant_id: str,
    action: str,
    actor_user_id: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    detail: dict[str, Any] | None = None,
    ip_address: str | None = None,
) -> AuditLogEntry:
    entry = AuditLogEntry(
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        action=action,
        target_type=target_type,
        target_id=target_id,
        detail=redact(detail or {}),
        ip_address=ip_address,
        created_at=datetime.now(timezone.utc),
    )
    db.add(entry)
    logger.info(
        "audit",
        extra={
            "tenant_id": tenant_id,
            "action": action,
            "actor_user_id": actor_user_id,
            "target_type": target_type,
            "target_id": target_id,
        },
    )
    return entry

"""Shared FastAPI dependencies: auth, RBAC, tenant scoping, quota enforcement.

FM1 hard requirement: every query must be filtered by tenant_id. The
convention in this codebase is that route handlers NEVER take a tenant_id
from the request body/query string for scoping purposes -- they always use
`current_user.tenant_id` (JWT-derived) or the tenant resolved from a service
token. This file is the single choke point that resolves "who is calling,
and which tenant do they belong to."
"""
from __future__ import annotations

import hashlib

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWTError
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.db.session import get_db
from app.models.billing import Plan, UsageCounter
from app.models.tenant import ServiceToken, Tenant
from app.models.user import ROLE_HIERARCHY, Role, User

bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")
    try:
        payload = decode_access_token(credentials.credentials)
    except PyJWTError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token") from exc

    user = db.get(User, payload.get("sub"))
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or inactive")
    # Defense in depth: the tenant_id embedded in the token must still match
    # the user's current tenant (protects against a stale/forged token
    # outliving a tenant reassignment).
    if user.tenant_id != payload.get("tenantId"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token/tenant mismatch")
    return user


def require_role(*allowed_roles: Role):
    """Dependency factory: 403s unless current_user.role is >= the lowest
    role in `allowed_roles` by privilege, OR is explicitly listed.
    """
    minimum_rank = min(ROLE_HIERARCHY[r] for r in allowed_roles)

    def _checker(current_user: User = Depends(get_current_user)) -> User:
        try:
            user_role = Role(current_user.role)
        except ValueError as exc:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Unknown role") from exc
        if ROLE_HIERARCHY[user_role] < minimum_rank:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Insufficient role for this action")
        return current_user

    return _checker


def hash_service_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def get_tenant_from_service_token(
    x_service_token: str | None = Header(default=None, alias="X-Service-Token"),
    db: Session = Depends(get_db),
) -> Tenant:
    """Auth for machine-to-machine ingestion (POST /v1/events/ingest)."""
    if not x_service_token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing X-Service-Token header")

    token_hash = hash_service_token(x_service_token)
    record = (
        db.query(ServiceToken)
        .filter(ServiceToken.token_hash == token_hash, ServiceToken.is_active.is_(True))
        .first()
    )
    if record is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid service token")

    tenant = db.get(Tenant, record.tenant_id)
    if tenant is None or not tenant.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Tenant inactive or not found")
    return tenant


def enforce_ingest_quota(tenant: Tenant, db: Session, period: str) -> UsageCounter:
    """FM10: 429 once a tenant's plan quota is exceeded for the current
    billing period. Returns the (possibly newly created) UsageCounter row so
    callers can increment it after a successful ingest.
    """
    plan = db.get(Plan, tenant.plan_id) if tenant.plan_id else None
    quota = plan.monthly_event_quota if plan else None

    counter = (
        db.query(UsageCounter)
        .filter(UsageCounter.tenant_id == tenant.id, UsageCounter.period == period)
        .first()
    )
    if counter is None:
        counter = UsageCounter(tenant_id=tenant.id, period=period, event_count=0)
        db.add(counter)
        db.flush()

    if quota is not None and counter.event_count >= quota:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Monthly event ingestion quota ({quota}) exceeded for the current billing period.",
        )
    return counter
